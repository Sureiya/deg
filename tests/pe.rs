//! End-to-end tests for PE-aware build artifacts.
//!
//! These tests build a synthetic PE32 image in memory (DOS header, COFF
//! header, optional header, `.text` + `.rdata` sections), write it into
//! `target/test-tmp`, and run the real `deg` binary against a model that
//! addresses it by virtual address.

use deg::sha256::sha256_hex;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

/// A minimal PE32 image (image base 0x400000):
/// * `.text`  RVA 0x1000 → VA 0x401000, raw offset 0x200, 0x200 bytes
///   (NOPs, executable);
/// * `.rdata` RVA 0x2000 → VA 0x402000, raw offset 0x400, 0x200 bytes of raw
///   data of which 0x100 are mapped; the first five bytes are `41 42 43 44
///   45`.
fn synthetic_pe32() -> Vec<u8> {
    let mut bytes = vec![0u8; 0x600];
    bytes[0] = b'M';
    bytes[1] = b'Z';
    bytes[0x3C..0x40].copy_from_slice(&0x80u32.to_le_bytes());
    bytes[0x80..0x84].copy_from_slice(b"PE\0\0");
    let coff = 0x84;
    bytes[coff..coff + 2].copy_from_slice(&0x14Cu16.to_le_bytes()); // Machine: i386
    bytes[coff + 2..coff + 4].copy_from_slice(&2u16.to_le_bytes()); // NumberOfSections
    bytes[coff + 16..coff + 18].copy_from_slice(&0xE0u16.to_le_bytes()); // SizeOfOptionalHeader
    bytes[coff + 18..coff + 20].copy_from_slice(&0x0102u16.to_le_bytes()); // Characteristics
    let opt = coff + 20;
    bytes[opt..opt + 2].copy_from_slice(&0x10Bu16.to_le_bytes()); // Magic: PE32
    bytes[opt + 28..opt + 32].copy_from_slice(&0x400000u32.to_le_bytes()); // ImageBase
    bytes[opt + 32..opt + 36].copy_from_slice(&0x1000u32.to_le_bytes()); // SectionAlignment
    bytes[opt + 36..opt + 40].copy_from_slice(&0x200u32.to_le_bytes()); // FileAlignment
    let table = opt + 0xE0;
    // .text
    bytes[table..table + 8].copy_from_slice(b".text\0\0\0");
    bytes[table + 8..table + 12].copy_from_slice(&0x200u32.to_le_bytes()); // VirtualSize
    bytes[table + 12..table + 16].copy_from_slice(&0x1000u32.to_le_bytes()); // VirtualAddress
    bytes[table + 16..table + 20].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    bytes[table + 20..table + 24].copy_from_slice(&0x200u32.to_le_bytes()); // PointerToRawData
    bytes[table + 36..table + 40].copy_from_slice(&0x6000_0020u32.to_le_bytes()); // CODE | EXECUTE | READ
                                                                                  // .rdata
    bytes[table + 40..table + 48].copy_from_slice(b".rdata\0\0");
    bytes[table + 48..table + 52].copy_from_slice(&0x100u32.to_le_bytes()); // VirtualSize
    bytes[table + 52..table + 56].copy_from_slice(&0x2000u32.to_le_bytes()); // VirtualAddress
    bytes[table + 56..table + 60].copy_from_slice(&0x200u32.to_le_bytes()); // SizeOfRawData
    bytes[table + 60..table + 64].copy_from_slice(&0x400u32.to_le_bytes()); // PointerToRawData
    bytes[table + 76..table + 80].copy_from_slice(&0x4000_0040u32.to_le_bytes()); // INITIALIZED_DATA | READ
    bytes[0x200..0x400].fill(0x90);
    bytes[0x400..0x405].copy_from_slice(b"ABCDE");
    bytes
}

fn run(args: &[&str]) -> Output {
    Command::new(env!("CARGO_BIN_EXE_deg"))
        .args(args)
        .current_dir(env!("CARGO_MANIFEST_DIR"))
        .output()
        .expect("failed to run deg")
}

fn stdout(o: &Output) -> String {
    String::from_utf8_lossy(&o.stdout).to_string()
}

fn stderr(o: &Output) -> String {
    String::from_utf8_lossy(&o.stderr).to_string()
}

fn tmp_dir() -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
    fs::create_dir_all(&d).unwrap();
    d
}

/// Write the synthetic PE and return its path and digest.
fn write_pe(name: &str) -> (PathBuf, String) {
    let dir = tmp_dir().join("pe");
    fs::create_dir_all(&dir).unwrap();
    let bytes = synthetic_pe32();
    let path = dir.join(format!("{name}.exe"));
    fs::write(&path, &bytes).unwrap();
    (path, sha256_hex(&bytes))
}

fn model_with(build_extra: &str, evidence: &str) -> String {
    format!("{build_extra}\n{evidence}\n")
}

#[test]
fn pe_build_scans_rdata_and_reads_rdata_bytes() {
    let (path, sha) = write_pe("pe32");
    let build = format!(
        "build pe1 = binary({:?}, sha256: {:?}, arch: x86_64, format: pe);",
        path.display().to_string(),
        sha
    );
    // No `text:` override and no `load:`: everything is resolved through the
    // PE section table, addressed by image-base virtual address.
    let model = model_with(
        &build,
        r#"
        ev e_scan := scan(pe1, ".rdata", "41 42 43 44 45");
        ev e_bytes := bytes(pe1, at: 0x402000, expect: "4142434445");
        "#,
    );
    let model_path = tmp_dir().join("pe-check.dg");
    fs::write(&model_path, &model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap(), "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let json = deg::json::parse(&stdout(&out)).unwrap();
    assert_eq!(json.get("ok").unwrap().as_bool(), Some(true));
    let evidence = json.get("evidence").unwrap().as_arr().unwrap();
    assert_eq!(evidence.len(), 2);
    for ev in evidence {
        assert_eq!(ev.get("ok").unwrap().as_bool(), Some(true));
    }
    let scan = evidence
        .iter()
        .find(|e| e.get("name").and_then(|v| v.as_str()) == Some("e_scan"))
        .unwrap();
    assert_eq!(scan.get("kind").and_then(|v| v.as_str()), Some("scan"));
    // The hit is reported as an image-base virtual address.
    let hit0 = scan
        .get("details")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .find(|d| d.get("key").and_then(|v| v.as_str()) == Some("hit_0"))
        .and_then(|d| d.get("value").and_then(|v| v.as_str()))
        .unwrap()
        .to_string();
    assert_eq!(hit0, "0x402000");
    let bytes = evidence
        .iter()
        .find(|e| e.get("name").and_then(|v| v.as_str()) == Some("e_bytes"))
        .unwrap();
    assert_eq!(bytes.get("kind").and_then(|v| v.as_str()), Some("bytes"));
}

#[test]
fn pe_build_maps_text_scans_through_the_section_table() {
    let (path, sha) = write_pe("pe32-text");
    let build = format!(
        "build pe1 = binary({:?}, sha256: {:?}, arch: x86_64, format: pe);",
        path.display().to_string(),
        sha
    );
    // .text is 0x200 NOPs starting at VA 0x1000 (file offset 0x200).
    let model = model_with(
        &build,
        r#"
        ev e_nops := scan(pe1, ".text", "90 90 90 90") |> unique;
        "#,
    );
    let model_path = tmp_dir().join("pe-text.dg");
    fs::write(&model_path, &model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap()]);
    // 0x200 NOPs match the pattern many times; `|> unique` must fail.
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("unique"), "{}", stdout(&out));
}

#[test]
fn pe_build_rejects_a_va_outside_all_sections() {
    let (path, sha) = write_pe("pe32-oob");
    let build = format!(
        "build pe1 = binary({:?}, sha256: {:?}, arch: x86_64, format: pe);",
        path.display().to_string(),
        sha
    );
    let model = model_with(
        &build,
        r#"
        ev e_oob := bytes(pe1, at: 0x405000, expect: "00");
        "#,
    );
    let model_path = tmp_dir().join("pe-oob.dg");
    fs::write(&model_path, &model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("outside"), "{}", stdout(&out));
}

#[test]
fn pe_build_rejects_a_bare_rva_below_the_image_base() {
    let (path, sha) = write_pe("pe32-rva");
    let build = format!(
        "build pe1 = binary({:?}, sha256: {:?}, arch: x86_64, format: pe);",
        path.display().to_string(),
        sha
    );
    // 0x2000 is .rdata's RVA, not an address: PE builds are addressed by
    // image-base virtual addresses (image_base 0x400000), so this is below
    // the image base and outside every section.
    let model = model_with(
        &build,
        r#"
        ev e_rva := bytes(pe1, at: 0x2000, expect: "00");
        "#,
    );
    let model_path = tmp_dir().join("pe-rva.dg");
    fs::write(&model_path, &model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("outside"), "{}", stdout(&out));
}

#[test]
fn pe_build_rejects_a_text_override_spanning_sections() {
    let (path, sha) = write_pe("pe32-span");
    // A declared `text:` range crossing from .text into .rdata must not be
    // sliced across the inter-section file padding.
    let build = format!(
        "build pe1 = binary({:?}, sha256: {:?}, arch: x86_64, format: pe, text: 0x401100..0x402100);",
        path.display().to_string(),
        sha
    );
    let model = model_with(
        &build,
        r#"
        fn f in pe1 at 0x401100;
        ev e_dec := decode(pe1, f, count: 8);
        "#,
    );
    let model_path = tmp_dir().join("pe-span.dg");
    fs::write(&model_path, &model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(
        stdout(&out).contains("spans multiple sections"),
        "{}",
        stdout(&out)
    );
}

#[test]
fn pe_build_rejects_an_unknown_section_name() {
    let (path, sha) = write_pe("pe32-nosect");
    let build = format!(
        "build pe1 = binary({:?}, sha256: {:?}, arch: x86_64, format: pe);",
        path.display().to_string(),
        sha
    );
    let model = model_with(
        &build,
        r#"
        ev e_scan := scan(pe1, ".data", "41 42 43 44 45");
        "#,
    );
    let model_path = tmp_dir().join("pe-nosect.dg");
    fs::write(&model_path, &model).unwrap();
    // Validation should reject the section name before evaluation runs.
    let out = run(&["check", model_path.to_str().unwrap()]);
    assert!(!out.status.success());
    let errs = format!("{}{}", stdout(&out), stderr(&out));
    assert!(errs.contains("no PE section"), "{errs}");
}

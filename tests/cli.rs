//! End-to-end tests for the `deg` binary. These exercise the checked-in
//! examples, not mocks: the kernel parses real bytes, pcaps, and datasets.

use deg::json::parse as parse_json;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

const B1_SHA: &str = "470de64c4b572ec064a0e14e1831017dea5c6204f24383f0bc31b9cd474beca6";

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

/// Copy a model into target/test-tmp and make fixture paths absolute so the
/// copy still sees the same content-addressed artifacts.
fn temp_model(name: &str, src: &str, transforms: &[(&str, &str)]) -> PathBuf {
    let fixtures = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures");
    let prefix = format!("\"{}/", fixtures.display());
    let mut text = src.replace("\"../fixtures/", &prefix);
    for (a, b) in transforms {
        text = text.replace(a, b);
    }
    let path = tmp_dir().join(format!("{name}.dg"));
    fs::write(&path, text).unwrap();
    path
}

#[test]
fn position_example_checks_and_seals() {
    let out = run(&["check", "examples/position/model.dg"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("kernel: OK"), "{text}");
    assert!(text.contains("P_reads_vec3_z"));
    assert!(text.contains("deterministic"));
    assert!(text.contains("C_loot_uniform"));
    assert!(text.contains("conflicts   1 (0 unresolved)"), "{text}");

    let lock = tmp_dir().join("position.lock.json");
    let _ = fs::remove_file(&lock);
    let out = run(&[
        "seal",
        "examples/position/model.dg",
        "--out",
        lock.to_str().unwrap(),
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let json = parse_json(&fs::read_to_string(&lock).unwrap()).unwrap();
    assert_eq!(
        json.get("model").unwrap().as_str(),
        Some("examples/position/model.dg")
    );
    let sealed = json.get("sealed").unwrap().as_arr().unwrap();
    assert!(sealed
        .iter()
        .any(|c| c.get("name").and_then(|v| v.as_str()) == Some("P_reads_vec3_z")));
    assert!(sealed
        .iter()
        .any(|c| c.get("name").and_then(|v| v.as_str()) == Some("P_anchor_exact")));
    let hyps = json.get("hypotheses").unwrap().as_arr().unwrap();
    assert!(hyps
        .iter()
        .any(|c| c.get("name").and_then(|v| v.as_str()) == Some("C_predictable")));
    let arts = json.get("artifacts").unwrap().as_arr().unwrap();
    assert!(arts
        .iter()
        .all(|a| a.get("verified").unwrap().as_bool() == Some(true)));
}

#[test]
fn tight_timing_claim_is_rejected() {
    let src = fs::read_to_string("examples/timing/model.dg").unwrap();
    let path = temp_model("timing-tight", &src, &[("± 0.05ms", "± 0.0001ms")]);
    let out = run(&["check", path.to_str().unwrap()]);
    assert!(
        !out.status.success(),
        "expected failure, stdout: {}",
        stdout(&out)
    );
    let text = stdout(&out);
    assert!(
        text.contains("differs from claimed") || text.contains("tighter than"),
        "{text}"
    );
}

#[test]
fn tampered_artifact_is_rejected() {
    let dir = tmp_dir().join("tampered");
    fs::create_dir_all(&dir).unwrap();
    let mut bytes = fs::read("examples/fixtures/game-b1.bin").unwrap();
    let mid = bytes.len() / 2;
    bytes[mid] ^= 0xff;
    let path = dir.join("game-b1.bin");
    fs::write(&path, &bytes).unwrap();
    let model = format!(
        "build b1 = binary({:?}, sha256: {:?}, arch: x86_64, load: 0x140000000, text: 0x140001000..0x140001400);\n",
        path.display().to_string(),
        B1_SHA
    );
    let model_path = tmp_dir().join("tampered.dg");
    fs::write(&model_path, model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap()]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("digest mismatch"), "{}", stdout(&out));
}

fn strip_conflict_block(src: &str) -> String {
    let Some(start) = src.find("conflict C_loot") else {
        return src.to_string();
    };
    let Some(rel_end) = src[start..].find(";\n") else {
        return src.to_string();
    };
    let mut out = String::new();
    out.push_str(&src[..start]);
    out.push_str("// conflict block removed by test\n");
    out.push_str(&src[start + rel_end + 2..]);
    out
}

#[test]
fn unresolved_conflict_blocks_seal() {
    let src = fs::read_to_string("examples/loot/model.dg").unwrap();
    let src = strip_conflict_block(&src);
    let path = temp_model("loot-no-conflict", &src, &[]);
    let check = run(&["check", path.to_str().unwrap()]);
    assert!(check.status.success(), "{}", stdout(&check));
    assert!(stdout(&check).contains("UNRESOLVED"));

    let seal = run(&[
        "seal",
        path.to_str().unwrap(),
        "--out",
        "target/test-tmp/nope.lock.json",
    ]);
    assert!(!seal.status.success());
    assert!(
        stderr(&seal).contains("unresolved conflict"),
        "{}",
        stderr(&seal)
    );
}

#[test]
fn underpowered_uniform_claim_is_a_hypothesis() {
    let src = fs::read_to_string("examples/loot/model.dg").unwrap();
    let src = strip_conflict_block(&src);
    let path = temp_model(
        "loot-underpowered",
        &src,
        &[("delta: 0.02", "delta: 0.001")],
    );
    let out = run(&["check", path.to_str().unwrap()]);
    assert!(out.status.success(), "{}", stdout(&out));
    assert!(stdout(&out).contains("underpowered"), "{}", stdout(&out));
}

#[test]
fn port_reports_rebases_and_drops() {
    let out = run(&["port", "examples/port/model.dg", "--to", "b2", "--json"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let json = parse_json(&stdout(&out)).unwrap();
    assert_eq!(json.get("target").unwrap().as_str(), Some("b2"));
    let maps = json.get("mappings").unwrap().as_arr().unwrap();
    assert_eq!(maps.len(), 2);
    let claims = json.get("claims").unwrap().as_arr().unwrap();
    let reads = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("P_reads"))
        .unwrap();
    assert_eq!(
        reads.get("action").and_then(|v| v.as_str()),
        Some("rebased")
    );
    assert_eq!(
        reads.get("status").and_then(|v| v.as_str()),
        Some("demoted")
    );
    let algo = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("P_algo"))
        .unwrap();
    assert_eq!(algo.get("status").and_then(|v| v.as_str()), Some("stale"));
    assert!(!json
        .get("obligations")
        .unwrap()
        .as_arr()
        .unwrap()
        .is_empty());
}

#[test]
fn explain_prints_the_derivation() {
    let out = run(&["explain", "examples/position/model.dg", "P_reads_vec3_z"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("derivation:"), "{text}");
    assert!(text.contains("reader_reads_struct_field"), "{text}");
    assert!(text.contains("scan_unique(e_anchor)"), "{text}");
}

#[test]
fn json_check_output_parses() {
    let out = run(&["check", "examples/position/model.dg", "--json"]);
    assert!(out.status.success());
    let json = parse_json(&stdout(&out)).unwrap();
    assert_eq!(json.get("ok").unwrap().as_bool(), Some(true));
    let claims = json.get("claims").unwrap().as_arr().unwrap();
    let reads = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("P_reads_vec3_z"))
        .unwrap();
    assert_eq!(reads.get("status").and_then(|v| v.as_str()), Some("sealed"));
    assert_eq!(
        reads.get("strength").and_then(|v| v.as_str()),
        Some("deterministic")
    );
}

#[test]
fn stdlib_is_inspectable() {
    let out = run(&["stdlib"]);
    assert!(out.status.success());
    let text = stdout(&out);
    assert!(text.contains("reader_reads_struct_field"));
    assert!(text.contains("mt19937_identified"));
    assert!(text.contains("recovery_witness"));
}

#[test]
fn extensions_command_lists_registered_kinds() {
    let out = run(&["extensions"]);
    assert!(out.status.success());
    // The core binary registers no compiled-in evidence extensions.
    assert_eq!(stdout(&out).trim(), "");
}

#[test]
fn strict_check_rejects_hypotheses() {
    let out = run(&["check", "examples/position/model.dg", "--strict"]);
    assert!(!out.status.success());
    assert!(stdout(&out).contains("seal: blocked"), "{}", stdout(&out));
}

#[test]
fn strict_seal_refuses_hypotheses() {
    let out = run(&[
        "seal",
        "examples/position/model.dg",
        "--strict",
        "--out",
        "target/test-tmp/strict.lock.json",
    ]);
    assert!(!out.status.success());
    assert!(stderr(&out).contains("only hypotheses"), "{}", stderr(&out));
}

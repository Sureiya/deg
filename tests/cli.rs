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
fn explain_mermaid_prints_a_flowchart() {
    let out = run(&[
        "explain",
        "examples/position/model.dg",
        "P_reads_vec3_z",
        "--mermaid",
    ]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("```mermaid"), "{text}");
    assert!(text.contains("flowchart TD"), "{text}");
    assert!(
        text.contains(
            "reads(read_position, Vec3.z)<br/>deterministic<br/>rule reader_reads_struct_field"
        ),
        "{text}"
    );
    assert!(text.contains("-->|evidence e_anchor|"), "{text}");
    assert!(text.contains("-->|definition|"), "{text}");
}

#[test]
fn explain_mermaid_and_json_are_mutually_exclusive() {
    let out = run(&[
        "explain",
        "examples/position/model.dg",
        "P_reads_vec3_z",
        "--mermaid",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("mutually exclusive"),
        "{}",
        stderr(&out)
    );
}

#[test]
fn port_markdown_renders_the_report() {
    let out = run(&["port", "examples/port/model.dg", "--to", "b2", "--markdown"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(
        text.contains("# DeG port report — `examples/port/model.dg` → `b2`"),
        "{text}"
    );
    assert!(text.contains("## Mappings"), "{text}");
    assert!(text.contains("## Claims"), "{text}");
    assert!(text.contains("## New obligations"), "{text}");
    assert!(text.contains("## Warnings"), "{text}");
    assert!(
        text.contains(
            "| `P_reads` | `b1` | rebased | demoted | deterministic → heuristic | ported strength heuristic is below the seal threshold deterministic; re-discharge obligations |"
        ),
        "{text}"
    );
    assert!(text.contains("[blocks seal]"), "{text}");
}

#[test]
fn port_markdown_and_json_are_mutually_exclusive() {
    let out = run(&[
        "port",
        "examples/port/model.dg",
        "--to",
        "b2",
        "--markdown",
        "--json",
    ]);
    assert_eq!(out.status.code(), Some(2));
    assert!(
        stderr(&out).contains("mutually exclusive"),
        "{}",
        stderr(&out)
    );
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

// ── samples evidence and mean claims ──────────────────────────────────────

#[test]
fn stats_example_checks_mean_claims() {
    let out = run(&["check", "examples/stats/model.dg"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("C_club_mean"), "{text}");
    assert!(text.contains("provisional"), "{text}");
    assert!(text.contains("mean(club) ~ 42"), "{text}");
    assert!(text.contains("underpowered"), "{text}");
}

#[test]
fn tight_mean_tolerance_is_rejected() {
    let src = fs::read_to_string("examples/stats/model.dg").unwrap();
    // 0.2 is inside the measured |mean - 42| (0.13) but far tighter than the
    // evidence CI (0.36): the kernel must reject it.
    let path = temp_model("stats-tight", &src, &[("± 1.2", "± 0.2")]);
    let out = run(&["check", path.to_str().unwrap()]);
    assert!(!out.status.success(), "stdout: {}", stdout(&out));
    assert!(stdout(&out).contains("tighter than"), "{}", stdout(&out));
}

// ── coverage claims ───────────────────────────────────────────────────────

#[test]
fn coverage_example_checks_three_outcomes() {
    let out = run(&["check", "examples/coverage/model.dg"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("C_cov "), "{text}");
    assert!(text.contains("5/5 covered; missing: none"), "{text}");
    assert!(
        text.contains("covered 5/82; dataset fully covered but the target is not met"),
        "{text}"
    );
    assert!(text.contains("covered 5/6; missing: 0x6"), "{text}");
    let out = run(&["check", "examples/coverage/model.dg", "--json"]);
    assert!(out.status.success());
    let json = parse_json(&stdout(&out)).unwrap();
    let claims = json.get("claims").unwrap().as_arr().unwrap();
    let cov = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("C_cov"))
        .unwrap();
    assert_eq!(cov.get("covered").and_then(|v| v.as_u64()), Some(5));
    assert_eq!(cov.get("target").and_then(|v| v.as_u64()), Some(5));
    assert_eq!(cov.get("status").and_then(|v| v.as_str()), Some("sealed"));
    let cov6 = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("C_cov6"))
        .unwrap();
    let missing = cov6.get("missing").and_then(|v| v.as_arr()).unwrap();
    assert_eq!(missing.len(), 1);
    // Large ids must survive JSON as decimal strings, not floats.
    assert_eq!(missing[0].as_str(), Some("6"));
    assert_eq!(
        cov6.get("status").and_then(|v| v.as_str()),
        Some("hypothesis")
    );
}

// ── generic conflicts and decisions ───────────────────────────────────────

#[test]
fn conflicts_example_resolves_prefer_and_decision() {
    let out = run(&["check", "examples/conflicts/model.dg"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("conflicts   2 (0 unresolved)"), "{text}");
    assert!(text.contains("demoted by conflict C_v"), "{text}");
    assert!(text.contains("demoted by conflict C_dec"), "{text}");
    assert!(text.contains("decisions   1 (1 ok)"), "{text}");
}

#[test]
fn decision_digest_mismatch_breaks_resolution_and_seal() {
    let src = fs::read_to_string("examples/conflicts/model.dg").unwrap();
    let path = temp_model(
        "conflicts-bad-decision",
        &src,
        &[(
            "8ceafe95256a677ca37f121f1ca9b10f49db72482d85b0fa19210fce8c4b06b6",
            "0000000000000000000000000000000000000000000000000000000000000000",
        )],
    );
    // The decision path is relative to the model directory, so mirror the
    // real decision file there; only the declared digest is wrong.
    let dec_dir = tmp_dir().join("decisions");
    fs::create_dir_all(&dec_dir).unwrap();
    fs::copy(
        "examples/conflicts/decisions/prefer_d.txt",
        dec_dir.join("prefer_d.txt"),
    )
    .unwrap();
    let check = run(&["check", path.to_str().unwrap()]);
    assert!(!check.status.success());
    let text = stdout(&check);
    assert!(text.contains("decision D_cd: digest mismatch"), "{text}");
    assert!(text.contains("UNRESOLVED"), "{text}");

    let seal = run(&[
        "seal",
        path.to_str().unwrap(),
        "--out",
        "target/test-tmp/bad-decision.lock.json",
    ]);
    assert!(!seal.status.success());
    assert!(
        stderr(&seal).contains("digest mismatch"),
        "{}",
        stderr(&seal)
    );
}

#[test]
fn decision_file_written_by_the_test_resolves_a_conflict() {
    use deg::sha256::sha256_hex;
    // The decision file is written next to the temp model; the digest is
    // computed with deg's own sha256 module.
    let dir = tmp_dir().join("decision-resolve");
    fs::create_dir_all(&dir).unwrap();
    let decision = b"Decision: prefer P_b over P_a\nSigner: test-runner\n";
    fs::write(dir.join("decision.txt"), decision).unwrap();
    let sha = sha256_hex(decision);

    let src = r#"
        build b1 = binary("{b1}", sha256: "470de64c4b572ec064a0e14e1831017dea5c6204f24383f0bc31b9cd474beca6", arch: x86_64, load: 0x140000000, text: 0x140001000..0x140001400);
        dump ids_bin = dump("{ids}", sha256: "74f81fe167d99b4cb41d6d0ccda82278caee9f3e2f25d5e5a3936ff3dcec60d0", base: 0, build: b1);
        ev e_b1 := bytes(ids_bin, at: 0, expect: "01");
        ev e_b2 := bytes(ids_bin, at: 1, expect: "02");
        rule version_1: version(1) if bytes_ok(?e, 0x0);
        rule version_2: version(2) if bytes_ok(?e, 0x1);
        proof P_a : version(1) in b1 { evidence e_b1; rules version_1; }
        proof P_b : version(2) in b1 { evidence e_b2; rules version_2; }
        decision D := decision("decision.txt", sha256: "{sha}", prefer: P_b, over: P_a, signer: "test-runner");
        conflict C : P_a vs P_b decision D reason "resolved by the test decision";
    "#
    .replace(
        "{b1}",
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/fixtures/game-b1.bin")
            .display()
            .to_string(),
    )
    .replace(
        "{ids}",
        &Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("examples/fixtures/ids.bin")
            .display()
            .to_string(),
    )
    .replace("{sha}", &sha);
    let model = dir.join("model.dg");
    fs::write(&model, src).unwrap();
    let out = run(&["check", model.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("0 unresolved"), "{text}");
    assert!(text.contains("demoted by conflict C"), "{text}");
    assert!(text.contains("via decision D"), "{text}");
}

// ── generalized refutation ────────────────────────────────────────────────

#[test]
fn generalized_refutation_marks_matching_claims_refuted() {
    let dir = tmp_dir().join("refute-general");
    fs::create_dir_all(&dir).unwrap();
    let b1 = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/game-b1.bin");
    let b1_path = b1.display().to_string();
    let b1_sha = "470de64c4b572ec064a0e14e1831017dea5c6204f24383f0bc31b9cd474beca6";
    let certs = dir.join("certs");
    fs::create_dir_all(&certs).unwrap();
    fs::write(
        certs.join("pred.json"),
        format!(
            "{{\"kind\": \"pred\", \"build\": \"{b1_sha}\", \"tool\": \"test\", \
             \"facts\": [{{\"rel\": \"pred_ev\", \"args\": [\"e_pred\", 1, \"x\"]}}]}}\n"
        ),
    )
    .unwrap();
    fs::write(
        certs.join("contra.json"),
        format!(
            "{{\"kind\": \"contradicts\", \"build\": \"{b1_sha}\", \"tool\": \"test\", \
             \"facts\": [{{\"rel\": \"contradicts\", \"args\": [\"e_contra\", \"pred\", [1, \"x\"]]}}]}}\n"
        ),
    )
    .unwrap();
    let src = format!(
        r#"
        pragma seal_threshold = observational;
        build b1 = binary("{b1_path}", sha256: "{b1_sha}", arch: x86_64, load: 0x140000000, text: 0x140001000..0x140001400);
        ev e_pred := external("certs/pred.json", kind: pred, build: b1);
        ev e_contra := external("certs/contra.json", kind: contradicts, build: b1);
        rule r_pred: pred(?n, ?s) if pred_ev(?e, ?n, ?s);
        proof P_pred : pred(1, x) in b1 {{ evidence e_pred; rules r_pred; }}
        refute R_pred : pred(1, x) in b1 by e_contra;
        "#
    );
    let model = dir.join("model.dg");
    fs::write(&model, src).unwrap();

    let out = run(&["check", model.to_str().unwrap(), "--json"]);
    // The refutation marks P_pred refuted, which is a hard error, so the
    // exit code is 1 — but the JSON report still shows the refutation sealed.
    let json = parse_json(&stdout(&out)).unwrap();
    let claims = json.get("claims").unwrap().as_arr().unwrap();
    let refute = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("R_pred"))
        .unwrap();
    assert_eq!(
        refute.get("status").and_then(|v| v.as_str()),
        Some("sealed")
    );
    assert_eq!(
        refute.get("strength").and_then(|v| v.as_str()),
        Some("observational")
    );
    let pred = claims
        .iter()
        .find(|c| c.get("name").and_then(|v| v.as_str()) == Some("P_pred"))
        .unwrap();
    assert_eq!(pred.get("status").and_then(|v| v.as_str()), Some("refuted"));
    assert!(json
        .get("errors")
        .unwrap()
        .as_arr()
        .unwrap()
        .iter()
        .any(|e| e.as_str().unwrap_or("").contains("refuted by R_pred")));
}

#[test]
fn refute_example_checks() {
    let out = run(&["check", "examples/refute/model.dg"]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("R_can_predict"), "{text}");
    assert!(text.contains("observational"), "{text}");
    // The contradiction comes from Observational external evidence, so the
    // refutation is a recorded hypothesis, not a seal.
    assert!(text.contains("hypothesis"), "{text}");
    assert!(
        text.contains("the contradiction is recorded but cannot seal"),
        "{text}"
    );
}

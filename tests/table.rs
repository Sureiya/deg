//! Tests for the `table` evidence kind: unit-style evaluator checks through
//! the library API plus an end-to-end `deg check` against the checked-in
//! `opcodes-sample.csv` fixture.

use deg::artifact::ArtifactSet;
use deg::evidence::{self, EvalCtx, EvidenceOutcome};
use deg::parser::parse_model;
use deg::semantic::ModelIndex;
use deg::sha256::sha256_hex;
use deg::value::Value;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::{Command, Output};

fn tmp_dir() -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
    fs::create_dir_all(&d).unwrap();
    d
}

/// Evaluate one `table` evidence declaration over an in-memory dataset:
/// writes the dataset (and a small build artifact) to target/test-tmp and
/// runs the library pipeline. `name` must be unique per test because tests
/// run in parallel.
fn evaluate_table(
    name: &str,
    evidence: &str,
    dataset_content: &str,
) -> (ModelIndex, ArtifactSet, EvidenceOutcome) {
    let dir = tmp_dir().join("table");
    fs::create_dir_all(&dir).unwrap();
    let bin_path = dir.join(format!("{name}.bin"));
    fs::write(&bin_path, b"table test build bytes").unwrap();
    let ds_path = dir.join(format!("{name}.csv"));
    fs::write(&ds_path, dataset_content).unwrap();
    let src = format!(
        "build b1 = binary({:?}, sha256: {:?}, arch: x86_64, load: 0x400000);\n\
         dataset ds = dataset({:?}, sha256: {:?}, build: b1);\n{evidence}\n",
        bin_path.display().to_string(),
        sha256_hex(b"table test build bytes"),
        ds_path.display().to_string(),
        sha256_hex(dataset_content.as_bytes()),
    );
    let model = parse_model("table-test.dg", &src).unwrap();
    let index = ModelIndex::new(&model).unwrap();
    let artifacts = ArtifactSet::load(&model, None);
    let ctx = EvalCtx {
        index: &index,
        artifacts: &artifacts,
    };
    let outcome = evidence::evaluate(&ctx, &index.evidence["e"]);
    (index, artifacts, outcome)
}

fn rows_of(outcome: &EvidenceOutcome) -> Vec<&[Value]> {
    outcome
        .facts
        .iter()
        .filter(|(rel, args)| rel == "row" && args.len() == 3)
        .map(|(_, args)| args[2].as_list().unwrap())
        .collect()
}

fn fact_has(outcome: &EvidenceOutcome, rel: &str, args: &[Value]) -> bool {
    outcome.facts.iter().any(|(r, a)| r == rel && a == args)
}

#[test]
fn csv_with_header_skips_the_header_and_parses_cells() {
    let (_i, _a, outcome) = evaluate_table(
        "csv-header",
        r#"ev e := table(ds, has_header: true);"#,
        "# comment line\nname,value\nnop,0x90\nret,7\nmov,ABC\n",
    );
    assert!(outcome.ok, "{}", outcome.error.as_deref().unwrap_or(""));
    assert_eq!(outcome.kind, "table");
    assert_eq!(outcome.strength.as_str(), "deterministic");
    let rows = rows_of(&outcome);
    assert_eq!(rows.len(), 3);
    // Header skipped; 0x90 is a hex integer, 7 decimal, ABC a symbol.
    assert_eq!(
        rows[0],
        &vec![Value::sym("nop"), Value::Int(0x90)],
        "rows: {rows:?}"
    );
    assert_eq!(rows[1], &vec![Value::sym("ret"), Value::Int(7)]);
    assert_eq!(rows[2], &vec![Value::sym("mov"), Value::sym("ABC")]);
    assert!(fact_has(
        &outcome,
        "table_rows",
        &[Value::sym("e"), Value::Int(3)]
    ));
    assert!(fact_has(
        &outcome,
        "table_cols",
        &[Value::sym("e"), Value::Int(2)]
    ));
    assert!(fact_has(
        &outcome,
        "row",
        &[
            Value::sym("e"),
            Value::Int(0),
            Value::list(vec![Value::sym("nop"), Value::Int(0x90)]),
        ]
    ));
    // Header cells are kept in the details.
    assert!(outcome
        .details
        .iter()
        .any(|(k, v)| k == "header_col_0" && v == "name"));
    assert!(outcome
        .details
        .iter()
        .any(|(k, v)| k == "header_col_1" && v == "value"));
    assert!(outcome.summary.contains("3 rows x 2 cols"));
    assert!(outcome.summary.contains("ds"));
}

#[test]
fn ws_format_splits_on_whitespace() {
    let (_i, _a, outcome) = evaluate_table(
        "ws-format",
        r#"ev e := table(ds, format: "ws");"#,
        "a  1  b\n2 c 3\n",
    );
    assert!(outcome.ok);
    let rows = rows_of(&outcome);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        &vec![Value::sym("a"), Value::Int(1), Value::sym("b")]
    );
    assert_eq!(
        rows[1],
        &vec![Value::Int(2), Value::sym("c"), Value::Int(3)]
    );
    assert!(fact_has(
        &outcome,
        "table_cols",
        &[Value::sym("e"), Value::Int(3)]
    ));
}

#[test]
fn tsv_format_splits_on_tabs() {
    let (_i, _a, outcome) = evaluate_table(
        "tsv-format",
        r#"ev e := table(ds, format: "tsv");"#,
        "a\t1\tb\n2\t3\tc\n",
    );
    assert!(outcome.ok);
    let rows = rows_of(&outcome);
    assert_eq!(rows.len(), 2);
    assert_eq!(
        rows[0],
        &vec![Value::sym("a"), Value::Int(1), Value::sym("b")]
    );
}

#[test]
fn hex_like_cells_become_ints_and_other_strings_stay_symbols() {
    let (_i, _a, outcome) = evaluate_table(
        "hex-cells",
        r#"ev e := table(ds);"#,
        "0x1F,0X10,-5,1.5,empty,,tag\n",
    );
    assert!(outcome.ok, "{}", outcome.error.as_deref().unwrap_or(""));
    let rows = rows_of(&outcome);
    assert_eq!(rows.len(), 1);
    assert_eq!(
        rows[0],
        &vec![
            Value::Int(31),
            Value::Int(16),
            Value::Int(-5),
            Value::sym("1.5"),
            Value::sym("empty"),
            // An empty cell is an empty symbol, not a missing cell.
            Value::sym(""),
            Value::sym("tag"),
        ]
    );
}

#[test]
fn empty_cells_are_preserved() {
    let (_i, _a, outcome) = evaluate_table("empty-cells", r#"ev e := table(ds);"#, "a,,c\n");
    assert!(outcome.ok);
    let rows = rows_of(&outcome);
    assert_eq!(
        rows[0],
        &vec![Value::sym("a"), Value::sym(""), Value::sym("c")]
    );
}

#[test]
fn inconsistent_column_counts_fail() {
    let (_i, _a, outcome) = evaluate_table("ragged-rows", r#"ev e := table(ds);"#, "1,2\n3,4,5\n");
    assert!(!outcome.ok);
    assert!(
        outcome
            .error
            .as_deref()
            .unwrap_or("")
            .contains("inconsistent column count"),
        "{}",
        outcome.error.as_deref().unwrap_or("")
    );
}

#[test]
fn empty_dataset_still_reports_zero_rows() {
    let (_i, _a, outcome) = evaluate_table(
        "only-comment",
        r#"ev e := table(ds);"#,
        "# only a comment\n",
    );
    assert!(outcome.ok);
    assert!(fact_has(
        &outcome,
        "table_rows",
        &[Value::sym("e"), Value::Int(0)]
    ));
    assert!(fact_has(
        &outcome,
        "table_cols",
        &[Value::sym("e"), Value::Int(0)]
    ));
}

#[test]
fn unknown_dataset_is_a_validation_error() {
    let dir = tmp_dir().join("table");
    fs::create_dir_all(&dir).unwrap();
    let src = r#"
        build b1 = binary("b.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64);
        ev e := table(ds_missing);
    "#;
    let model = parse_model("t.dg", src).unwrap();
    let errs = ModelIndex::new(&model).unwrap_err();
    assert!(
        errs.iter()
            .any(|e| e.contains("unknown dataset `ds_missing`")),
        "{errs:?}"
    );
}

// ── end-to-end: row facts drive a proof through `contains` ────────────────

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

#[test]
fn fixture_table_drives_a_proof_with_row_and_contains() {
    let fixture =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/fixtures/opcodes-sample.csv");
    let content = fs::read_to_string(&fixture).unwrap();
    let sha = sha256_hex(content.as_bytes());
    let dir = tmp_dir().join("table");
    fs::create_dir_all(&dir).unwrap();
    let bin_path = dir.join("bin.bin");
    fs::write(&bin_path, b"table test build bytes").unwrap();
    let model = format!(
        "build b1 = binary({:?}, sha256: {:?}, arch: x86_64, load: 0x400000);\n\
         dataset ds_ops = dataset({:?}, sha256: {:?}, build: b1);\n\
         ev e_ops := table(ds_ops, has_header: true);\n\
         rule known_op:\n\
         \x20 known_op(?op) if\n\
         \x20   row(?e, ?i, ?cells) and\n\
         \x20   contains(?cells, ?op);\n\
         proof P_known_nop : known_op(0x90) in b1 {{\n\
         \x20 evidence e_ops;\n\
         \x20 rules known_op;\n\
         }}\n",
        bin_path.display().to_string(),
        sha256_hex(b"table test build bytes"),
        fixture.display().to_string(),
        sha,
    );
    let model_path = tmp_dir().join("table-fixture.dg");
    fs::write(&model_path, &model).unwrap();
    let out = run(&["check", model_path.to_str().unwrap()]);
    assert!(out.status.success(), "stderr: {}", stderr(&out));
    let text = stdout(&out);
    assert!(text.contains("P_known_nop"), "{text}");
    assert!(text.contains("sealed"), "{text}");
    assert!(text.contains("deterministic"), "{text}");
}

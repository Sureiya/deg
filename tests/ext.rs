//! Integration tests for the compiled-in evidence extension registry.
//!
//! These exercise the library path (parse → ModelIndex::new → ArtifactSet::load
//! → kernel::check) exactly as `deg check` does, with a fake extension
//! registered at startup.

use deg::artifact::ArtifactSet;
use deg::ast::EvidenceDecl;
use deg::evidence::EvidenceOutcome;
use deg::ext::{self, Extension};
use deg::kernel::{self, ClaimStatus};
use deg::parser::parse_model;
use deg::semantic::ModelIndex;
use deg::sha256::sha256_hex;
use deg::strength::Strength;
use deg::value::Value;
use std::fs;
use std::path::{Path, PathBuf};

/// A fake extension evaluator: emits a single `ext_ok(e)` fact at
/// Deterministic strength and ignores its arguments.
fn fake_eval(
    _index: &ModelIndex,
    _artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "faketest",
        Strength::Deterministic,
        "fake extension evaluated",
    );
    out.fact("ext_ok", vec![Value::sym(&decl.name)]);
    let argc = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => args.positional.len() + args.named.len(),
        _ => 0,
    };
    out.detail("argc", argc.to_string());
    Ok(out)
}

fn tmp_dir() -> PathBuf {
    let d = Path::new(env!("CARGO_MANIFEST_DIR")).join("target/test-tmp");
    fs::create_dir_all(&d).unwrap();
    d
}

/// Write a tiny artifact and return `(path, sha256)` so a model can declare a
/// verified build without checked-in fixtures.
fn write_artifact(name: &str) -> (PathBuf, String) {
    let dir = tmp_dir().join("ext");
    fs::create_dir_all(&dir).unwrap();
    let bytes = format!("{name} artifact bytes").into_bytes();
    let path = dir.join(format!("{name}.bin"));
    fs::write(&path, &bytes).unwrap();
    (path, sha256_hex(&bytes))
}

fn check_model(name: &str, evidence: &str) -> (ModelIndex, ArtifactSet, kernel::CheckReport) {
    let (path, sha) = write_artifact(name);
    let src = format!(
        "build b1 = binary({:?}, sha256: {:?}, arch: x86_64, load: 0x400000);\n{evidence}\n",
        path.display().to_string(),
        sha
    );
    let model = parse_model(&format!("{name}.dg"), &src).unwrap();
    let index = ModelIndex::new(&model).unwrap();
    let artifacts = ArtifactSet::load(&model, None);
    let report = kernel::check(&index, &artifacts);
    (index, artifacts, report)
}

#[test]
fn registered_extension_seals_a_proof() {
    ext::register(
        "ext_it_faketest",
        Extension {
            eval: fake_eval,
            build: None,
            describe: "fake integration-test extension",
        },
    )
    .unwrap();

    let (_index, _artifacts, report) = check_model(
        "ext-sealed",
        r#"
        ev e := ext_it_faketest(x, n: 3);
        proof P : ext_ok(e) in b1 { evidence e; }
        "#,
    );
    assert!(report.ok, "errors: {:?}", report.errors);
    let claim = report.claim("P").expect("proof P is in the report");
    assert_eq!(claim.status, ClaimStatus::Sealed);
    assert_eq!(claim.strength, Some(Strength::Deterministic));
    assert!(claim.support.contains("e"));
}

#[test]
fn extension_build_hook_is_checked() {
    // A fake extension whose evidence is bound to the build named by its
    // first positional argument.
    fn bound_build(index: &ModelIndex, ev: &EvidenceDecl) -> Option<String> {
        let _ = index;
        match &ev.kind {
            deg::ast::EvidenceKind::Extension { args, .. } => args.positional_string(0),
            _ => None,
        }
    }

    ext::register(
        "ext_it_bound",
        Extension {
            eval: fake_eval,
            build: Some(bound_build),
            describe: "build-bound fake",
        },
    )
    .unwrap();

    // Evidence bound to a build that does not exist: validation must reject it.
    let (path, sha) = write_artifact("ext-bound");
    let src = format!(
        "build b1 = binary({:?}, sha256: {:?}, arch: x86_64, load: 0x400000);\n\
         ev e := ext_it_bound(nope);\n",
        path.display().to_string(),
        sha
    );
    let model = parse_model("ext-bound.dg", &src).unwrap();
    let errs = ModelIndex::new(&model).unwrap_err();
    assert!(
        errs.iter().any(|e| e.contains("unknown build `nope`")),
        "{errs:?}"
    );
}

#[test]
fn unregistered_extension_fails_evaluation() {
    let (_index, _artifacts, report) = check_model(
        "ext-unregistered",
        r#"
        ev e := ext_it_never_registered(x);
        "#,
    );
    assert!(!report.ok);
    let outcome = report.evidence.get("e").expect("evidence e evaluated");
    assert!(!outcome.ok);
    let error = outcome.error.as_deref().unwrap_or("");
    assert!(
        error.contains("not registered") && error.contains("ext_it_never_registered"),
        "{error}"
    );
    assert!(
        error.contains("registered:"),
        "error should list the registered kinds: {error}"
    );
}

#[test]
fn duplicate_registration_errors_in_this_process() {
    // Register a kind unique to this test twice; the second registration must
    // be rejected.
    let kind = "ext_it_dup";
    ext::register(
        kind,
        Extension {
            eval: fake_eval,
            build: None,
            describe: "first registration",
        },
    )
    .unwrap();
    let err = ext::register(
        kind,
        Extension {
            eval: fake_eval,
            build: None,
            describe: "duplicate registration",
        },
    );
    assert!(err.is_err());
}

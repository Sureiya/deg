//! Compiled-in evidence extension registry.
//!
//! DeG's core evidence primitives (scan, bytes, decode, …) are fixed. Domain
//! crates (for example a game adapter) may *compile in* additional evidence
//! kinds that ship inside a trusted binary. There is no runtime loading: an
//! extension is a function pointer registered at startup, reviewed and built
//! exactly like the core evaluators it sits next to.
//!
//! Registration is global and append-only. Duplicate kinds are an error so a
//! binary can never silently replace an evaluator.

use crate::artifact::ArtifactSet;
use crate::ast::EvidenceDecl;
use crate::evidence::EvidenceOutcome;
use crate::semantic::ModelIndex;
use std::collections::BTreeMap;
use std::sync::{Mutex, OnceLock};

/// An extension evaluator: computes the evidence outcome from the model index
/// and the loaded artifacts. It must follow the same strength rules as the
/// core primitives (see `docs/extensions.md`).
pub type ExtensionEval =
    fn(&ModelIndex, &ArtifactSet, &EvidenceDecl) -> Result<EvidenceOutcome, String>;

pub struct Extension {
    pub eval: ExtensionEval,
    /// Optionally resolves the build this evidence is bound to, so proofs can
    /// be checked to live in the right build.
    pub build: Option<fn(&ModelIndex, &EvidenceDecl) -> Option<String>>,
    /// A short human-readable description shown in documentation/tools.
    pub describe: &'static str,
}

/// The registry. `OnceLock` fixes initialization; the `Mutex` layer lets
/// `register` append after the first use, and extensions are `Box::leak`ed so
/// `get` can return `&'static Extension` (the registry lives for the whole
/// process, so this is deliberate, not a leak in practice).
static REGISTRY: OnceLock<Mutex<BTreeMap<&'static str, &'static Extension>>> = OnceLock::new();

/// Register an evidence kind. Errors when the kind is already registered.
pub fn register(kind: &'static str, ext: Extension) -> Result<(), String> {
    let registry = REGISTRY.get_or_init(|| Mutex::new(BTreeMap::new()));
    let mut map = registry
        .lock()
        .map_err(|_| "extension registry is poisoned".to_string())?;
    if map.contains_key(kind) {
        return Err(format!("evidence extension `{kind}` is already registered"));
    }
    map.insert(kind, Box::leak(Box::new(ext)));
    Ok(())
}

/// Look up a registered extension by kind name.
pub fn get(kind: &str) -> Option<&'static Extension> {
    let registry = REGISTRY.get()?;
    let map = registry.lock().ok()?;
    map.get(kind).copied()
}

/// All registered kind names, sorted.
pub fn registered() -> Vec<&'static str> {
    match REGISTRY.get() {
        Some(registry) => registry
            .lock()
            .map(|map| map.keys().copied().collect())
            .unwrap_or_default(),
        None => Vec::new(),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn dummy_eval(
        _: &ModelIndex,
        _: &ArtifactSet,
        _: &EvidenceDecl,
    ) -> Result<EvidenceOutcome, String> {
        Err("not called".into())
    }

    #[test]
    fn duplicate_registration_is_rejected() {
        let kind = "ext_unit_duplicate";
        register(
            kind,
            Extension {
                eval: dummy_eval,
                build: None,
                describe: "unit test",
            },
        )
        .unwrap();
        let dup = register(
            kind,
            Extension {
                eval: dummy_eval,
                build: None,
                describe: "duplicate",
            },
        );
        assert!(dup.is_err());
        assert_eq!(get(kind).map(|e| e.describe), Some("unit test"));
        assert!(registered().contains(&kind));
    }

    #[test]
    fn unknown_kinds_are_not_registered() {
        assert!(get("ext_unit_never_registered").is_none());
        assert!(!registered().contains(&"ext_unit_never_registered"));
    }

    #[test]
    fn registration_is_sorted() {
        register(
            "ext_unit_zeta",
            Extension {
                eval: dummy_eval,
                build: None,
                describe: "z",
            },
        )
        .unwrap();
        register(
            "ext_unit_alpha",
            Extension {
                eval: dummy_eval,
                build: None,
                describe: "a",
            },
        )
        .unwrap();
        let kinds = registered();
        let pos_a = kinds.iter().position(|k| *k == "ext_unit_alpha").unwrap();
        let pos_z = kinds.iter().position(|k| *k == "ext_unit_zeta").unwrap();
        assert!(pos_a < pos_z);
    }
}

//! Patch porting.
//!
//! `deg port` never silently keeps a claim. It re-runs what it can against the
//! target build, re-anchors unique byte patterns, structurally rebases functions
//! when a `port { rebase ... }` rule is declared, and *demotes or marks stale*
//! everything else. Statistical evidence needs a new capture; a recovery
//! witness needs a new observed dataset. The output is a port report plus
//! generated obligations, not a rewritten model.

use crate::artifact::ArtifactSet;
use crate::ast::*;
use crate::evidence::{self, EvalCtx, EvidenceOutcome};
use crate::facts::{self, FactStore};
use crate::json::Json;
use crate::kernel::{self, CheckReport, ClaimKind, ClaimResult, ClaimStatus};
use crate::semantic::ModelIndex;
use crate::strength::Strength;
use crate::value::{Lit, Value};
use crate::x86;
use std::collections::{BTreeMap, BTreeSet};

#[derive(Debug, Clone)]
pub struct Mapping {
    pub name: String,
    pub kind: String,
    pub old_addr: u64,
    pub new_addr: u64,
    pub similarity: f64,
    pub how: String,
}

#[derive(Debug, Clone)]
pub struct PortClaim {
    pub name: String,
    pub kind: String,
    pub source_build: String,
    pub action: String,
    pub status: String,
    pub old_strength: Option<Strength>,
    pub new_strength: Option<Strength>,
    pub note: Option<String>,
}

#[derive(Debug, Clone)]
pub struct PortObligation {
    pub name: String,
    pub goal: String,
    pub priority: String,
    pub blocks_seal: bool,
    pub reason: String,
}

#[derive(Debug, Clone)]
pub struct PortReport {
    pub target: String,
    pub mappings: Vec<Mapping>,
    pub claims: Vec<PortClaim>,
    pub obligations: Vec<PortObligation>,
    pub warnings: Vec<String>,
    pub errors: Vec<String>,
}

/// Port every claim from other builds to `target`. `source` is the check
/// report of the model itself, which provides each claim's strength in its
/// source build (the "old" half of the report's old → new strength column).
pub fn port(
    index: &ModelIndex,
    artifacts: &ArtifactSet,
    target: &str,
    source: &CheckReport,
) -> PortReport {
    let old_strengths: BTreeMap<&str, Option<Strength>> = source
        .claims
        .iter()
        .map(|c| (c.name.as_str(), c.strength))
        .collect();
    port_inner(index, artifacts, target, &old_strengths)
}

fn port_inner(
    index: &ModelIndex,
    artifacts: &ArtifactSet,
    target: &str,
    old_strengths: &BTreeMap<&str, Option<Strength>>,
) -> PortReport {
    let mut report = PortReport {
        target: target.to_string(),
        mappings: Vec::new(),
        claims: Vec::new(),
        obligations: Vec::new(),
        warnings: Vec::new(),
        errors: Vec::new(),
    };
    if !index.builds.contains_key(target) {
        report
            .errors
            .push(format!("unknown target build `{target}`"));
        return report;
    }
    if !artifacts.is_verified(target) {
        report.errors.push(format!(
            "target build `{target}` is not a verified artifact"
        ));
        return report;
    }

    // Port declarations are grouped by (from, to).
    let mut rebase_rules: Vec<(String, PortRule, String)> = Vec::new();
    let mut drops: BTreeSet<String> = BTreeSet::new();
    let mut revalidate: BTreeMap<String, String> = BTreeMap::new();
    let mut sources: BTreeSet<String> = BTreeSet::new();
    for p in &index.ports {
        if p.to != target {
            continue;
        }
        sources.insert(p.from.clone());
        for r in &p.rules {
            match r {
                PortRule::Rebase {
                    target,
                    window,
                    min_similarity,
                } => rebase_rules.push((
                    p.from.clone(),
                    PortRule::Rebase {
                        target: target.clone(),
                        window: *window,
                        min_similarity: *min_similarity,
                    },
                    target.clone(),
                )),
                PortRule::Drop { target } => {
                    drops.insert(target.clone());
                }
                PortRule::Revalidate { evidence, with } => {
                    revalidate.insert(evidence.clone(), with.clone());
                }
            }
        }
    }

    // Explicit structural rebases.
    let mut mappings: BTreeMap<String, Mapping> = BTreeMap::new();
    for (from, rule, _) in &rebase_rules {
        let PortRule::Rebase {
            target: name,
            window,
            min_similarity,
        } = rule
        else {
            continue;
        };
        if from != target {
            // Only map objects from the source build.
            let object_build = index
                .fns
                .get(name)
                .map(|f| f.build.clone())
                .or_else(|| index.rngs.get(name).map(|r| r.build.clone()));
            if object_build.as_deref() != Some(from.as_str()) {
                continue;
            }
        }
        let old = match (index.fns.get(name), index.rngs.get(name)) {
            (Some(f), _) => Some((f.addr, "fn")),
            (_, Some(r)) => Some((r.addr, "rng")),
            _ => None,
        };
        let Some((old_addr, kind)) = old else {
            report.warnings.push(format!(
                "port rebase target `{name}` is not a function or rng"
            ));
            continue;
        };
        match structural_rebase(artifacts, from, target, old_addr, *window, *min_similarity) {
            Ok((new_addr, score)) => {
                report.warnings.push(format!(
                    "rebased {kind} `{name}` {old_addr:#x} -> {new_addr:#x} (similarity {score:.2})"
                ));
                mappings.insert(
                    name.clone(),
                    Mapping {
                        name: name.clone(),
                        kind: kind.to_string(),
                        old_addr,
                        new_addr,
                        similarity: score,
                        how: "structural_similarity".into(),
                    },
                );
            }
            Err(e) => report.warnings.push(format!("rebase `{name}` failed: {e}")),
        }
    }

    // Source definitions are reused except for the objects we rebased.
    let mut source_builds: BTreeSet<String> = index
        .proofs
        .values()
        .map(|p| p.build.clone())
        .chain(index.claims.values().map(|c| c.build.clone()))
        .filter(|b| b != target)
        .collect();
    source_builds.extend(sources);
    if source_builds.is_empty() {
        report
            .warnings
            .push("no claims from another build to port".into());
        return report;
    }

    // Port relational proofs.
    let mut ported_results: Vec<ClaimResult> = Vec::new();
    for proof in index.proofs.values() {
        if proof.build == target {
            continue;
        }
        let result = port_proof(
            index,
            artifacts,
            proof,
            target,
            &mappings,
            &drops,
            &revalidate,
            &mut report,
        );
        report.claims.push(PortClaim {
            name: proof.name.clone(),
            kind: "proof".into(),
            source_build: proof.build.clone(),
            action: result.0.clone(),
            status: result.1.clone(),
            old_strength: old_strengths.get(proof.name.as_str()).copied().flatten(),
            new_strength: result.2,
            note: result.3.clone(),
        });
        if let Some(cr) = result.4 {
            ported_results.push(cr);
        }
    }

    // Direct measurement claims are build/capture-bound. Without an explicit
    // revalidation for a target capture they go stale, never silently kept.
    for claim in index.claims.values() {
        if claim.build == target {
            continue;
        }
        let is_direct = matches!(claim.body, ClaimBody::Direct { .. });
        if !is_direct {
            continue;
        }
        let ev_name = match &claim.body {
            ClaimBody::Direct { evidence, .. } => evidence,
            _ => unreachable!(),
        };
        let status = if revalidate.contains_key(ev_name) {
            // Statistical re-checking with a new capture is a v0.2 feature; even
            // with a replacement, report it as needing re-derivation.
            "stale"
        } else {
            "stale"
        };
        let note = if revalidate.contains_key(ev_name) {
            format!(
                "revalidation artifact {} is declared; re-run the measurement against it",
                revalidate[ev_name]
            )
        } else {
            format!(
                "{} is bound to {}; statistical evidence does not transfer across patches",
                ev_name, claim.build
            )
        };
        report.claims.push(PortClaim {
            name: claim.name.clone(),
            kind: claim.head.kind().to_string(),
            source_build: claim.build.clone(),
            action: "stale".into(),
            status: status.into(),
            old_strength: old_strengths.get(claim.name.as_str()).copied().flatten(),
            new_strength: None,
            note: Some(note.clone()),
        });
        report.obligations.push(PortObligation {
            name: format!("port:{}:revalidate", claim.name),
            goal: format!("revalidate({}, target: {target})", claim.name),
            priority: "high".into(),
            blocks_seal: true,
            reason: note.clone(),
        });
        ported_results.push(ClaimResult {
            name: claim.name.clone(),
            kind: match claim.head {
                ClaimHead::Period { .. } => ClaimKind::Period,
                ClaimHead::Uniform { .. } => ClaimKind::Uniform,
                ClaimHead::Mean { .. } => ClaimKind::Mean,
                ClaimHead::Coverage { .. } => ClaimKind::Coverage,
                ClaimHead::Rel(_) => ClaimKind::Derived,
            },
            build: target.to_string(),
            goal: claim.head.display(),
            goal_key: None,
            status: ClaimStatus::Stale,
            strength: None,
            support: BTreeSet::new(),
            premises: Vec::new(),
            bottleneck: None,
            note: Some(note),
            error: None,
            provisional_until: claim.provisional_until.clone(),
            conflict_with: Vec::new(),
            refuted_by: None,
            measured: None,
            coverage: None,
        });
    }

    // Derived claims are recomputed from the ported statuses.
    let mut pending: Vec<&ClaimDecl> = index
        .claims
        .values()
        .filter(|c| matches!(c.body, ClaimBody::Derived { .. }) && c.build != target)
        .collect();
    let mut progress = true;
    while progress {
        progress = false;
        let mut still = Vec::new();
        for claim in pending {
            let refs = match &claim.body {
                ClaimBody::Derived { from } => from,
                _ => unreachable!(),
            };
            if refs
                .iter()
                .all(|r| ported_results.iter().any(|c| &c.name == r))
            {
                let result = kernel::check_derived_claim(index, claim, &ported_results);
                let status = match result.status {
                    ClaimStatus::Sealed => "ported",
                    ClaimStatus::Provisional => "provisional",
                    ClaimStatus::Hypothesis => "demoted",
                    ClaimStatus::Failed
                        if result.error.as_deref().unwrap_or("").contains("stale") =>
                    {
                        "stale"
                    }
                    _ => "stale",
                };
                report.claims.push(PortClaim {
                    name: claim.name.clone(),
                    kind: "derived".into(),
                    source_build: claim.build.clone(),
                    action: status.into(),
                    status: status.into(),
                    old_strength: old_strengths.get(claim.name.as_str()).copied().flatten(),
                    new_strength: result.strength,
                    note: result.note.clone().or(result.error.clone()),
                });
                if status == "stale" {
                    report.obligations.push(PortObligation {
                        name: format!("port:{}:premises", claim.name),
                        goal: format!("revalidate({}, target: {target})", claim.name),
                        priority: "high".into(),
                        blocks_seal: true,
                        reason: result
                            .error
                            .clone()
                            .unwrap_or_else(|| "a premise is stale or failed".into()),
                    });
                }
                ported_results.push(result);
                progress = true;
            } else {
                still.push(claim);
            }
        }
        pending = still;
    }
    for claim in pending {
        report.claims.push(PortClaim {
            name: claim.name.clone(),
            kind: "derived".into(),
            source_build: claim.build.clone(),
            action: "stale".into(),
            status: "stale".into(),
            old_strength: None,
            new_strength: None,
            note: Some("unresolved premises after porting".into()),
        });
    }

    // Deduplicate generated obligations.
    let mut seen = BTreeSet::new();
    report.obligations.retain(|o| seen.insert(o.name.clone()));
    report.claims.sort_by(|a, b| {
        (a.source_build.as_str(), a.name.as_str()).cmp(&(b.source_build.as_str(), b.name.as_str()))
    });
    report.mappings = mappings.into_values().collect();
    report
}

#[allow(clippy::too_many_arguments)]
fn port_proof(
    index: &ModelIndex,
    artifacts: &ArtifactSet,
    proof: &ProofDecl,
    target: &str,
    mappings: &BTreeMap<String, Mapping>,
    drops: &BTreeSet<String>,
    revalidate: &BTreeMap<String, String>,
    report: &mut PortReport,
) -> (
    String,
    String,
    Option<Strength>,
    Option<String>,
    Option<ClaimResult>,
) {
    let mut inferred = mappings.clone();
    let mut ported: BTreeMap<String, EvidenceOutcome> = BTreeMap::new();
    let mut stale: Vec<String> = Vec::new();

    // Pass 1: scans. They can re-anchor functions by unique byte pattern.
    for ev_name in &proof.evidence {
        let Some(decl) = index.evidence.get(ev_name) else {
            stale.push(format!("unknown evidence `{ev_name}`"));
            continue;
        };
        if drops.contains(ev_name) {
            stale.push(format!("evidence `{ev_name}` is dropped by the port block"));
            continue;
        }
        if let EvidenceKind::Scan { .. } = &decl.kind {
            match port_scan(index, artifacts, decl, target) {
                Ok(out) => {
                    // Infer a function mapping from a unique re-anchored scan.
                    {
                        let source_out = evidence::evaluate(&EvalCtx { index, artifacts }, decl);
                        let source_addr = source_out
                            .facts
                            .iter()
                            .find(|(rel, args)| rel == "scan_hit" && args.len() == 2)
                            .and_then(|(_, args)| args[1].as_u64());
                        let new_addr = out
                            .facts
                            .iter()
                            .find(|(rel, args)| rel == "scan_hit" && args.len() == 2)
                            .and_then(|(_, args)| args[1].as_u64());
                        if let (Some(old), Some(new)) = (source_addr, new_addr) {
                            if let Some(f) = index
                                .fns
                                .values()
                                .find(|f| f.build == proof.build && f.addr == old)
                            {
                                inferred.entry(f.name.clone()).or_insert(Mapping {
                                    name: f.name.clone(),
                                    kind: "fn".into(),
                                    old_addr: old,
                                    new_addr: new,
                                    similarity: 1.0,
                                    how: "scan_reanchor".into(),
                                });
                            }
                        }
                    }
                    ported.insert(ev_name.clone(), out);
                }
                Err(e) => {
                    {
                        let src = evidence::evaluate(&EvalCtx { index, artifacts }, decl);
                        let old_hit = src
                            .facts
                            .iter()
                            .find(|(rel, args)| rel == "scan_hit" && args.len() == 2)
                            .and_then(|(_, args)| args[1].as_u64());
                        if let Some(old) = old_hit {
                            let found = mappings.values().find(|m| m.old_addr == old).cloned();
                            if let Some(m) = found {
                                let out = rebased_scan_outcome(decl, &m);
                                inferred.entry(m.name.clone()).or_insert(m);
                                ported.insert(ev_name.clone(), out);
                                continue;
                            }
                        }
                    }
                    stale.push(format!("scan `{ev_name}`: {e}"))
                }
            }
        }
    }

    // Pass 2: everything else, using inferred mappings.
    for ev_name in &proof.evidence {
        if ported.contains_key(ev_name) || stale.iter().any(|s| s.contains(ev_name)) {
            continue;
        }
        let Some(decl) = index.evidence.get(ev_name) else {
            continue;
        };
        if drops.contains(ev_name) {
            stale.push(format!("evidence `{ev_name}` is dropped by the port block"));
            continue;
        }
        match port_evidence(
            index, artifacts, decl, target, &inferred, revalidate, report,
        ) {
            Ok(out) => {
                ported.insert(ev_name.clone(), out);
            }
            Err(e) => stale.push(format!("`{ev_name}`: {e}")),
        }
    }

    if !stale.is_empty() {
        let note = format!("stale: {}", stale.join("; "));
        report.obligations.push(PortObligation {
            name: format!("port:{}:revalidate", proof.name),
            goal: format!("revalidate({}, target: {target})", proof.name),
            priority: "high".into(),
            blocks_seal: true,
            reason: note.clone(),
        });
        return ("stale".into(), "stale".into(), None, Some(note), None);
    }

    // Rebuild a fact store against the target: target definitions first, then
    // mapped definitions, then source definitions (skipped where mapped), then
    // ported evidence.
    let mut store = FactStore::new();
    for (rel, args) in index.definitions(target) {
        store.insert_definition(&rel, args);
    }
    for m in inferred.values() {
        match m.kind.as_str() {
            "fn" => {
                store.insert_definition(
                    "fn_addr",
                    vec![Value::sym(&m.name), Value::Int(m.new_addr as i128)],
                );
                store.insert_definition("fn_label", vec![Value::sym(&m.name), Value::sym(&m.name)]);
            }
            "rng" => {
                store.insert_definition(
                    "rng_addr",
                    vec![Value::sym(&m.name), Value::Int(m.new_addr as i128)],
                );
            }
            _ => {}
        }
    }
    for (rel, args) in index.definitions(&proof.build) {
        store.insert_definition(&rel, args);
    }
    for (name, out) in &ported {
        if !out.ok {
            continue;
        }
        for (rel, args) in &out.facts {
            store.insert_evidence(rel, args.clone(), out.strength, name);
        }
    }

    let all_rules = index.all_rules().unwrap_or_default();
    let rule_map: BTreeMap<&str, &RuleDecl> =
        all_rules.iter().map(|r| (r.name.as_str(), r)).collect();
    let mut selected = Vec::new();
    for name in &proof.rules {
        if let Some(r) = rule_map.get(name.as_str()) {
            selected.push((*r).clone());
        }
    }
    let compiled = match facts::compile_rules(&selected) {
        Ok(c) => c,
        Err(e) => return ("failed".into(), "failed".into(), None, Some(e), None),
    };
    if let Err(e) = facts::fixpoint(&mut store, &compiled) {
        return ("failed".into(), "failed".into(), None, Some(e), None);
    }
    let goal = normalize_atom(index, &proof.goal);
    let key = match facts::ground_key(&goal) {
        Ok(k) => k,
        Err(e) => return ("failed".into(), "failed".into(), None, Some(e), None),
    };
    let used_objects = referenced_objects(index, proof);
    let used_rebase = inferred.values().any(|m| {
        used_objects.contains(&m.name)
            && matches!(m.how.as_str(), "structural_similarity" | "scan_reanchor")
    });
    match store.get(&key) {
        Some(info) if !info.support.is_empty() => {
            let strength = info.strength;
            let threshold = index.seal_threshold();
            let status = if strength >= threshold {
                "ported"
            } else {
                "demoted"
            };
            let note = if status == "demoted" {
                Some(format!(
                    "ported strength {strength} is below the seal threshold {threshold}; re-discharge obligations"
                ))
            } else if used_rebase {
                Some("re-anchored against the target build".into())
            } else {
                None
            };
            if used_rebase {
                for m in inferred
                    .values()
                    .filter(|m| m.how == "structural_similarity" && used_objects.contains(&m.name))
                {
                    report.obligations.push(PortObligation {
                        name: format!("port:{}:unique:{}", proof.name, m.name),
                        goal: format!("unique({target}, {:#x})", m.new_addr),
                        priority: "high".into(),
                        blocks_seal: true,
                        reason: format!(
                            "rebased `{}` by structural similarity only ({:.2})",
                            m.name, m.similarity
                        ),
                    });
                }
            }
            let mut cr = ClaimResult {
                name: proof.name.clone(),
                kind: ClaimKind::Proof,
                build: target.to_string(),
                goal: goal.display(),
                goal_key: Some(key),
                status: if strength >= threshold {
                    ClaimStatus::Sealed
                } else {
                    ClaimStatus::Hypothesis
                },
                strength: Some(strength),
                support: info.support.clone(),
                premises: Vec::new(),
                bottleneck: None,
                note: note.clone(),
                error: None,
                provisional_until: None,
                conflict_with: Vec::new(),
                refuted_by: None,
                measured: None,
                coverage: None,
            };
            if proof.expect.map(|e| strength < e).unwrap_or(false) {
                cr.status = ClaimStatus::Failed;
                cr.error = Some("ported strength is below the declared expect".into());
            }
            (
                if used_rebase { "rebased" } else { "reused" }.into(),
                status.into(),
                Some(strength),
                note,
                Some(cr),
            )
        }
        Some(_) => {
            let note = "goal derived only from model definitions in the target".to_string();
            report.obligations.push(PortObligation {
                name: format!("port:{}:evidence", proof.name),
                goal: format!("reanchor({}, target: {target})", proof.name),
                priority: "high".into(),
                blocks_seal: true,
                reason: note.clone(),
            });
            ("failed".into(), "failed".into(), None, Some(note), None)
        }
        None => {
            let note = format!(
                "could not re-derive {} against {target}; re-anchor or re-validate",
                key.display()
            );
            report.obligations.push(PortObligation {
                name: format!("port:{}:reanchor", proof.name),
                goal: format!("reanchor({}, target: {target})", proof.name),
                priority: "high".into(),
                blocks_seal: true,
                reason: note.clone(),
            });
            ("failed".into(), "failed".into(), None, Some(note), None)
        }
    }
}

fn port_scan(
    index: &ModelIndex,
    artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
    target: &str,
) -> Result<EvidenceOutcome, String> {
    let EvidenceKind::Scan {
        pattern, section, ..
    } = &decl.kind
    else {
        return Err("not a scan".into());
    };
    if section != ".text" {
        return Err(format!("unsupported scan section `{section}`"));
    }
    let mut cloned = decl.clone();
    cloned.kind = EvidenceKind::Scan {
        build: target.to_string(),
        section: section.clone(),
        pattern: pattern.clone(),
    };
    let ctx = EvalCtx { index, artifacts };
    let out = evidence::evaluate(&ctx, &cloned);
    if out.ok {
        return Ok(out);
    }
    // Structural fallback by address mapping is handled by the caller's
    // scan-reanchor inference; without a unique hit there is nothing to infer.
    Err(out.error.unwrap_or_else(|| "scan did not match".into()))
}

fn port_evidence(
    index: &ModelIndex,
    artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
    target: &str,
    mappings: &BTreeMap<String, Mapping>,
    revalidate: &BTreeMap<String, String>,
    _report: &mut PortReport,
) -> Result<EvidenceOutcome, String> {
    let ctx = EvalCtx { index, artifacts };
    match &decl.kind {
        EvidenceKind::Scan { .. } => port_scan(index, artifacts, decl, target),
        EvidenceKind::Bytes {
            artifact,
            at,
            expect,
        } => {
            if index.builds.contains_key(artifact) {
                let mut cloned = decl.clone();
                cloned.kind = EvidenceKind::Bytes {
                    artifact: target.to_string(),
                    at: *at,
                    expect: expect.clone(),
                };
                let out = evidence::evaluate(&ctx, &cloned);
                if out.ok {
                    Ok(out)
                } else {
                    Err(out.error.unwrap_or_else(|| "bytes differ".into()))
                }
            } else {
                Err(format!(
                    "artifact `{artifact}` is a dump and is build-bound"
                ))
            }
        }
        EvidenceKind::Decode { func, count, .. } => {
            let old = index
                .fns
                .get(func)
                .ok_or_else(|| format!("unknown fn `{func}`"))?;
            let new_addr = mappings.get(func).map(|m| m.new_addr).unwrap_or(old.addr);
            decode_outcome(artifacts, target, &decl.name, func, new_addr, *count)
        }
        EvidenceKind::Constants {
            at,
            window,
            values,
            unique,
            ..
        } => {
            let old_addr = index.resolve_addr_target(at)?;
            let mapped = match at {
                Target::Ref(r) => mappings.get(&index.norm(r)).map(|m| m.new_addr),
                Target::Addr(_) => None,
            };
            let addr = mapped.unwrap_or(old_addr);
            constants_outcome(artifacts, target, addr, *window, values, *unique, decl)
        }
        EvidenceKind::Modulo { func, modulus, .. } => {
            let old = index
                .fns
                .get(func)
                .ok_or_else(|| format!("unknown fn `{func}`"))?;
            let addr = mappings.get(func).map(|m| m.new_addr).unwrap_or(old.addr);
            modulo_outcome(artifacts, target, func, addr, *modulus, decl)
        }
        EvidenceKind::Recovery { observed, .. } => {
            let replacement = revalidate
                .get(&decl.name)
                .ok_or_else(|| {
                    format!(
                        "recovery witness needs a new observed dataset; add `revalidate {} with <dataset>`",
                        decl.name
                    )
                })?;
            let mut cloned = decl.clone();
            if let EvidenceKind::Recovery { observed: o, .. } = &mut cloned.kind {
                let _ = observed;
                *o = replacement.clone();
            }
            let out = evidence::evaluate(&ctx, &cloned);
            if out.ok {
                Ok(out)
            } else {
                Err(out.error.unwrap_or_else(|| "recovery failed".into()))
            }
        }
        EvidenceKind::Rate { .. } | EvidenceKind::Sample { .. } => {
            let replacement = revalidate.get(&decl.name).ok_or_else(|| {
                format!(
                    "statistical evidence requires a target capture; add `revalidate {} with <capture>`",
                    decl.name
                )
            })?;
            let mut cloned = decl.clone();
            match &mut cloned.kind {
                EvidenceKind::Rate { capture, .. } => *capture = replacement.clone(),
                EvidenceKind::Sample { capture, .. } => *capture = replacement.clone(),
                _ => {}
            }
            let out = evidence::evaluate(&ctx, &cloned);
            if out.ok {
                Ok(out)
            } else {
                Err(out.error.unwrap_or_else(|| "measurement failed".into()))
            }
        }
        EvidenceKind::Samples { .. } => {
            Err("samples evidence is dataset-bound and not build-specific; re-declare it for the target if needed".into())
        }
        EvidenceKind::External { .. } => {
            Err("external certificate is build-bound; re-issue it for the target".into())
        }
        EvidenceKind::Symbols { .. } => {
            Err("symbol store is build-bound; provide a target store".into())
        }
        EvidenceKind::Absence { .. } => {
            Err("absence certificate is build- and time-scoped; re-issue it".into())
        }
        EvidenceKind::Table { .. } => {
            Err("table evidence is dataset-bound; revalidate it against a target dataset".into())
        }
        EvidenceKind::Extension { .. } => Err(
            "extension evidence cannot be ported automatically; re-derive it for the target build"
                .into(),
        ),
    }
}

fn decode_outcome(
    artifacts: &ArtifactSet,
    target: &str,
    ev: &str,
    func: &str,
    addr: u64,
    count: usize,
) -> Result<EvidenceOutcome, String> {
    let (start, text) = artifacts.text_bytes(target)?;
    let off = addr
        .checked_sub(start)
        .ok_or_else(|| format!("{addr:#x} is below .text"))? as usize;
    if off >= text.len() {
        return Err(format!("{addr:#x} is outside .text"));
    }
    let decoded = x86::decode(&text[off..], addr, count);
    if decoded.insns.is_empty() {
        return Err(format!("no instructions decoded at {addr:#x}"));
    }
    let strength = if decoded.complete {
        Strength::Deterministic
    } else {
        Strength::Heuristic
    };
    let mut out = EvidenceOutcome::new(
        ev,
        "decode",
        strength,
        format!(
            "{} instruction(s) at {addr:#x} in {target}",
            decoded.insns.len()
        ),
    );
    out.fact(
        "insn_count",
        vec![Value::sym(ev), Value::Int(decoded.insns.len() as i128)],
    );
    if decoded.complete {
        out.fact("decode_complete", vec![Value::sym(ev)]);
    } else {
        out.fact("decode_partial", vec![Value::sym(ev)]);
    }
    let mut loads: BTreeMap<u8, BTreeSet<i64>> = BTreeMap::new();
    let mut stores: BTreeMap<u8, BTreeSet<i64>> = BTreeMap::new();
    for insn in &decoded.insns {
        if let Some(m) = &insn.mem {
            if m.base.is_none() || m.rip_relative || m.disp < 0 {
                continue;
            }
            if !matches!(m.width, 1 | 2 | 4 | 8 | 16) {
                continue;
            }
            if m.write {
                stores.entry(m.width).or_default().insert(m.disp);
            } else {
                loads.entry(m.width).or_default().insert(m.disp);
            }
        }
    }
    for (width, offs) in &loads {
        let list = offs.iter().map(|o| Value::Int(*o as i128)).collect();
        out.fact(
            "loads_set",
            vec![
                Value::sym(ev),
                Value::sym(func),
                Value::list(list),
                Value::Int(*width as i128),
            ],
        );
    }
    for (width, offs) in &stores {
        let list = offs.iter().map(|o| Value::Int(*o as i128)).collect();
        out.fact(
            "stores_set",
            vec![
                Value::sym(ev),
                Value::sym(func),
                Value::list(list),
                Value::Int(*width as i128),
            ],
        );
    }
    Ok(out)
}

fn constants_outcome(
    artifacts: &ArtifactSet,
    target: &str,
    addr: u64,
    window: u64,
    values: &[u32],
    unique_requested: bool,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    let (start, text) = artifacts.text_bytes(target)?;
    let off = addr
        .checked_sub(start)
        .ok_or_else(|| format!("{addr:#x} is below .text"))? as usize;
    if off + window as usize > text.len() {
        return Err(format!("window {addr:#x}+{window:#x} runs past .text"));
    }
    let bytes = &text[off..off + window as usize];
    let mut counts = Vec::new();
    for v in values {
        let pat = v.to_le_bytes();
        let count = bytes.windows(4).filter(|w| *w == pat).count();
        if count == 0 {
            return Err(format!("constant {v:#x} missing in the target window"));
        }
        counts.push((*v, count));
    }
    let unique = counts.iter().all(|(_, c)| *c == 1);
    if unique_requested && !unique {
        return Err("constants are not unique in the target window".into());
    }
    let strength = if unique {
        Strength::Deterministic
    } else {
        Strength::Heuristic
    };
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "constants",
        strength,
        format!("constants re-checked at {addr:#x} in {target}"),
    );
    out.fact(
        "constants_window",
        vec![
            Value::sym(&decl.name),
            Value::Int(addr as i128),
            Value::Int(window as i128),
        ],
    );
    for (v, c) in counts {
        out.fact(
            "constant_present",
            vec![Value::sym(&decl.name), Value::Int(v as i128)],
        );
        out.fact(
            "constant_count",
            vec![
                Value::sym(&decl.name),
                Value::Int(v as i128),
                Value::Int(c as i128),
            ],
        );
    }
    if unique {
        out.fact("constants_unique", vec![Value::sym(&decl.name)]);
    }
    Ok(out)
}

fn modulo_outcome(
    artifacts: &ArtifactSet,
    target: &str,
    func: &str,
    addr: u64,
    modulus: u64,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    let (start, text) = artifacts.text_bytes(target)?;
    let off = addr
        .checked_sub(start)
        .ok_or_else(|| format!("{addr:#x} is below .text"))? as usize;
    if off >= text.len() {
        return Err(format!("{addr:#x} is outside .text"));
    }
    let decoded = x86::decode(&text[off..], addr, 64);
    for (i, insn) in decoded.insns.iter().enumerate() {
        let Some(div_reg) = insn.div_reg else {
            continue;
        };
        let imm = decoded.insns[..i]
            .iter()
            .rev()
            .find(|prev| prev.mov_reg == Some(div_reg))
            .and_then(|prev| prev.imm);
        if imm == Some(modulus as i64) {
            let mut out = EvidenceOutcome::new(
                &decl.name,
                "modulo",
                Strength::Deterministic,
                format!("literal div by {modulus} at {:#x} in {target}", insn.addr),
            );
            out.fact(
                "modulo_op",
                vec![
                    Value::sym(&decl.name),
                    Value::sym(func),
                    Value::Int(modulus as i128),
                ],
            );
            out.fact(
                "modulo_site",
                vec![Value::sym(&decl.name), Value::Int(insn.addr as i128)],
            );
            return Ok(out);
        }
    }
    Err(format!(
        "literal div by {modulus} not found in the target function `{func}`"
    ))
}

fn referenced_objects(index: &ModelIndex, proof: &ProofDecl) -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for term in &proof.goal.args {
        if let Term::Lit(Lit::Sym(s)) = term {
            let n = index.norm(s);
            if index.fns.contains_key(&n) || index.rngs.contains_key(&n) {
                out.insert(n);
            }
        }
    }
    for ev_name in &proof.evidence {
        if let Some(ev) = index.evidence.get(ev_name) {
            match &ev.kind {
                EvidenceKind::Decode { func, .. } | EvidenceKind::Modulo { func, .. } => {
                    out.insert(func.clone());
                }
                EvidenceKind::Constants {
                    at: Target::Ref(r), ..
                } => {
                    out.insert(index.norm(r));
                }
                EvidenceKind::Recovery { rng, .. } => {
                    out.insert(rng.clone());
                }
                _ => {}
            }
        }
    }
    out
}

fn rebased_scan_outcome(decl: &EvidenceDecl, mapping: &Mapping) -> EvidenceOutcome {
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "scan",
        Strength::Heuristic,
        format!(
            "pattern disappeared; rebased to {:#x} by structural similarity ({:.2})",
            mapping.new_addr, mapping.similarity
        ),
    );
    out.fact(
        "scan_hit",
        vec![Value::sym(&decl.name), Value::Int(mapping.new_addr as i128)],
    );
    out.fact("scan_count", vec![Value::sym(&decl.name), Value::Int(1)]);
    // Synthetic uniqueness: deliberately strength Heuristic, never
    // Deterministic, and paired with a port obligation.
    out.fact("scan_unique", vec![Value::sym(&decl.name)]);
    out.detail("rebased_to", format!("{:#x}", mapping.new_addr));
    out.detail("similarity", format!("{:.3}", mapping.similarity));
    out.detail("obligation", "prove uniqueness in the target build");
    out
}

fn structural_rebase(
    artifacts: &ArtifactSet,
    from: &str,
    to: &str,
    old_addr: u64,
    window: u64,
    min_similarity: f64,
) -> Result<(u64, f64), String> {
    let (from_start, from_text) = artifacts.text_bytes(from)?;
    let (to_start, to_text) = artifacts.text_bytes(to)?;
    let off = old_addr
        .checked_sub(from_start)
        .ok_or_else(|| format!("{old_addr:#x} is below .text"))? as usize;
    if off >= from_text.len() {
        return Err(format!("{old_addr:#x} is outside .text"));
    }
    let len = (window as usize).min(from_text.len() - off).max(16);
    let source = &from_text[off..(off + len).min(from_text.len())];
    let mut best: Option<(usize, f64)> = None;
    for pos in 0..=to_text.len().saturating_sub(len) {
        let target = &to_text[pos..pos + len];
        let score = lcs_ratio(source, target);
        if best.map(|(_, b)| score > b).unwrap_or(true) {
            best = Some((pos, score));
        }
    }
    match best {
        Some((pos, score)) if score >= min_similarity => Ok((to_start + pos as u64, score)),
        Some((pos, score)) => Err(format!(
            "best candidate {:#x} scored {score:.2}, below min {min_similarity:.2}",
            to_start + pos as u64
        )),
        None => Err("target .text is too small".into()),
    }
}

fn lcs_ratio(a: &[u8], b: &[u8]) -> f64 {
    if a.is_empty() || b.is_empty() {
        return 0.0;
    }
    let mut prev = vec![0usize; b.len() + 1];
    let mut cur = vec![0usize; b.len() + 1];
    for &ca in a {
        for (j, &cb) in b.iter().enumerate() {
            cur[j + 1] = if ca == cb {
                prev[j] + 1
            } else {
                prev[j + 1].max(cur[j])
            };
        }
        std::mem::swap(&mut prev, &mut cur);
        for v in cur.iter_mut() {
            *v = 0;
        }
    }
    prev[b.len()] as f64 / a.len().max(b.len()) as f64
}

fn normalize_atom(index: &ModelIndex, atom: &Atom) -> Atom {
    let mut out = atom.clone();
    for term in &mut out.args {
        if let Term::Lit(Lit::Sym(s)) = term {
            *s = index.norm(s);
        }
    }
    out
}

pub fn print_port(report: &PortReport) {
    println!("deg port -> {}", report.target);
    println!("  mappings: {}", report.mappings.len());
    for m in &report.mappings {
        println!(
            "    {:<10} {:<24} {:#x} -> {:#x}  ({:.2}, {})",
            m.kind, m.name, m.old_addr, m.new_addr, m.similarity, m.how
        );
    }
    println!("\nclaims:");
    for c in &report.claims {
        println!(
            "  {:<28} {:<10} {:<8} {:<8} {}",
            c.name,
            c.source_build,
            c.action,
            c.status,
            c.new_strength
                .map(|s| s.as_str().to_string())
                .unwrap_or_else(|| "-".into())
        );
        if let Some(n) = &c.note {
            println!("      {n}");
        }
    }
    if !report.obligations.is_empty() {
        println!("\nnew obligations:");
        for o in &report.obligations {
            println!(
                "  {:<40} {}{}",
                o.name,
                o.goal,
                if o.blocks_seal { " [blocks seal]" } else { "" }
            );
        }
    }
    if !report.warnings.is_empty() {
        println!("\nwarnings:");
        for w in &report.warnings {
            println!("  ! {w}");
        }
    }
    if !report.errors.is_empty() {
        println!("\nerrors:");
        for e in &report.errors {
            println!("  ✗ {e}");
        }
    }
}

/// Render the port report as a GitHub-ready Markdown document. The report
/// structures are already in deterministic order, so the tables are stable.
pub fn port_markdown(report: &PortReport, model: &str) -> String {
    let mut out = String::new();
    out.push_str(&format!(
        "# DeG port report — `{model}` → `{}`\n\n",
        report.target
    ));

    out.push_str("## Mappings\n\n| Kind | Name | Old | New | Similarity | How |\n|---|---|---|---|---|---|\n");
    for m in &report.mappings {
        out.push_str(&format!(
            "| {} | `{}` | `{:#x}` | `{:#x}` | {:.2} | {} |\n",
            m.kind, m.name, m.old_addr, m.new_addr, m.similarity, m.how
        ));
    }
    out.push('\n');

    out.push_str("## Claims\n\n| Claim | Source build | Action | Status | Strength | Notes |\n|---|---|---|---|---|---|\n");
    for c in &report.claims {
        let strength = match (c.old_strength, c.new_strength) {
            (Some(o), Some(n)) => format!("{} → {}", o.as_str(), n.as_str()),
            (Some(o), None) => o.as_str().to_string(),
            (None, Some(n)) => n.as_str().to_string(),
            (None, None) => "-".into(),
        };
        let note = c.note.as_deref().unwrap_or("").replace('|', "\\|");
        out.push_str(&format!(
            "| `{}` | `{}` | {} | {} | {} | {} |\n",
            c.name, c.source_build, c.action, c.status, strength, note
        ));
    }
    out.push('\n');

    out.push_str("## New obligations\n\n");
    if report.obligations.is_empty() {
        out.push_str("_None._\n\n");
    } else {
        for o in &report.obligations {
            out.push_str(&format!(
                "- `{}` — `{}` ({}){}\n",
                o.name,
                o.goal,
                o.reason.replace('|', "\\|"),
                if o.blocks_seal { " [blocks seal]" } else { "" }
            ));
        }
        out.push('\n');
    }

    if !report.warnings.is_empty() {
        out.push_str("## Warnings\n\n");
        for w in &report.warnings {
            out.push_str(&format!("- {w}\n"));
        }
        out.push('\n');
    }
    if !report.errors.is_empty() {
        out.push_str("## Errors\n\n");
        for e in &report.errors {
            out.push_str(&format!("- {e}\n"));
        }
        out.push('\n');
    }
    out.push_str("---\n\n_Generated by DeG. Strength is computed, never asserted._\n");
    out
}

pub fn port_json(report: &PortReport) -> Json {
    let mut root = BTreeMap::new();
    root.insert("target".into(), Json::Str(report.target.clone()));
    root.insert(
        "mappings".into(),
        Json::Arr(
            report
                .mappings
                .iter()
                .map(|m| {
                    let mut o = BTreeMap::new();
                    o.insert("name".into(), Json::Str(m.name.clone()));
                    o.insert("kind".into(), Json::Str(m.kind.clone()));
                    o.insert("old".into(), Json::Num(m.old_addr as f64));
                    o.insert("new".into(), Json::Num(m.new_addr as f64));
                    o.insert("similarity".into(), Json::Num(m.similarity));
                    o.insert("how".into(), Json::Str(m.how.clone()));
                    Json::Obj(o)
                })
                .collect(),
        ),
    );
    root.insert(
        "claims".into(),
        Json::Arr(
            report
                .claims
                .iter()
                .map(|c| {
                    let mut o = BTreeMap::new();
                    o.insert("name".into(), Json::Str(c.name.clone()));
                    o.insert("kind".into(), Json::Str(c.kind.clone()));
                    o.insert("source_build".into(), Json::Str(c.source_build.clone()));
                    o.insert("action".into(), Json::Str(c.action.clone()));
                    o.insert("status".into(), Json::Str(c.status.clone()));
                    o.insert(
                        "old_strength".into(),
                        Json::Str(
                            c.old_strength
                                .map(|s| s.as_str().to_string())
                                .unwrap_or_else(|| "-".into()),
                        ),
                    );
                    o.insert(
                        "new_strength".into(),
                        Json::Str(
                            c.new_strength
                                .map(|s| s.as_str().to_string())
                                .unwrap_or_else(|| "-".into()),
                        ),
                    );
                    if let Some(n) = &c.note {
                        o.insert("note".into(), Json::Str(n.clone()));
                    }
                    Json::Obj(o)
                })
                .collect(),
        ),
    );
    root.insert(
        "obligations".into(),
        Json::Arr(
            report
                .obligations
                .iter()
                .map(|o| {
                    let mut m = BTreeMap::new();
                    m.insert("name".into(), Json::Str(o.name.clone()));
                    m.insert("goal".into(), Json::Str(o.goal.clone()));
                    m.insert("priority".into(), Json::Str(o.priority.clone()));
                    m.insert("blocks_seal".into(), Json::Bool(o.blocks_seal));
                    m.insert("reason".into(), Json::Str(o.reason.clone()));
                    Json::Obj(m)
                })
                .collect(),
        ),
    );
    root.insert(
        "warnings".into(),
        Json::Arr(report.warnings.iter().cloned().map(Json::Str).collect()),
    );
    root.insert(
        "errors".into(),
        Json::Arr(report.errors.iter().cloned().map(Json::Str).collect()),
    );
    Json::Obj(root)
}

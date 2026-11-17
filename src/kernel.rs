//! The DeG checking kernel.
//!
//! The kernel is deliberately small in trust surface: it verifies artifacts,
//! replays evidence, applies user-visible rules, propagates the strength
//! lattice, detects conflicts, and accounts for obligations. Expensive or
//! unverified analyses can only enter as external evidence capped at
//! `Observational`.

use crate::artifact::ArtifactSet;
use crate::ast::*;
use crate::evidence::{self, EvalCtx, EvidenceOutcome, Measured};
use crate::facts::{self, FactKey, FactStore};
use crate::json::Json;
use crate::semantic::ModelIndex;
use crate::stats;
use crate::strength::Strength;
use crate::value::{Lit, Value};
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;
use std::time::{SystemTime, UNIX_EPOCH};

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimKind {
    Proof,
    Period,
    Uniform,
    Mean,
    Coverage,
    Derived,
    Refute,
}

impl ClaimKind {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimKind::Proof => "proof",
            ClaimKind::Period => "period",
            ClaimKind::Uniform => "uniform",
            ClaimKind::Mean => "mean",
            ClaimKind::Coverage => "coverage",
            ClaimKind::Derived => "derived",
            ClaimKind::Refute => "refutation",
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ClaimStatus {
    Sealed,
    Provisional,
    Hypothesis,
    Open,
    Failed,
    Refuted,
    Stale,
}

impl ClaimStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ClaimStatus::Sealed => "sealed",
            ClaimStatus::Provisional => "provisional",
            ClaimStatus::Hypothesis => "hypothesis",
            ClaimStatus::Open => "open",
            ClaimStatus::Failed => "failed",
            ClaimStatus::Refuted => "refuted",
            ClaimStatus::Stale => "stale",
        }
    }

    pub fn usable(self) -> bool {
        matches!(self, ClaimStatus::Sealed | ClaimStatus::Provisional)
    }
}

#[derive(Debug, Clone)]
pub struct ClaimResult {
    pub name: String,
    pub kind: ClaimKind,
    pub build: String,
    pub goal: String,
    pub goal_key: Option<FactKey>,
    pub status: ClaimStatus,
    pub strength: Option<Strength>,
    pub support: BTreeSet<String>,
    pub premises: Vec<String>,
    pub bottleneck: Option<String>,
    pub note: Option<String>,
    pub error: Option<String>,
    pub provisional_until: Option<String>,
    pub conflict_with: Vec<String>,
    pub refuted_by: Option<String>,
    pub measured: Option<String>,
    pub coverage: Option<CoverageStats>,
}

/// Structured result of a coverage claim, mirrored into JSON and the lock.
#[derive(Debug, Clone)]
pub struct CoverageStats {
    pub covered: u64,
    pub target: u64,
    pub missing: Vec<i128>,
}

impl ClaimResult {
    fn base(name: &str, kind: ClaimKind, build: &str, goal: String) -> ClaimResult {
        ClaimResult {
            name: name.to_string(),
            kind,
            build: build.to_string(),
            goal,
            goal_key: None,
            status: ClaimStatus::Open,
            strength: None,
            support: BTreeSet::new(),
            premises: Vec::new(),
            bottleneck: None,
            note: None,
            error: None,
            provisional_until: None,
            conflict_with: Vec::new(),
            refuted_by: None,
            measured: None,
            coverage: None,
        }
    }
}

#[derive(Debug, Clone)]
pub struct ObligationResult {
    pub name: String,
    pub goal: String,
    pub priority: Priority,
    pub blocks_seal: bool,
    pub status: ObligationStatus,
    pub resolved_by: Option<String>,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ObligationStatus {
    Open,
    Resolved,
}

impl ObligationStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            ObligationStatus::Open => "open",
            ObligationStatus::Resolved => "resolved",
        }
    }
}

#[derive(Debug, Clone)]
pub struct ConflictResult {
    pub name: String,
    pub left: String,
    pub right: String,
    pub preferred: Option<String>,
    pub demoted: Option<String>,
    pub reason: Option<String>,
    pub decision: Option<String>,
    pub resolved: bool,
}

/// A hash-verified human decision file. `ok` is true only when the file was
/// readable and its digest matched the declaration; a failed decision cannot
/// resolve a conflict.
#[derive(Debug, Clone)]
pub struct DecisionResult {
    pub name: String,
    pub sha256: String,
    pub ok: bool,
    pub signer: Option<String>,
    pub prefer: String,
    pub over: String,
}

#[derive(Debug, Clone)]
pub struct DefinitionAudit {
    pub kind: String,
    pub name: String,
    pub build: String,
    pub justified: bool,
    pub justification: Option<String>,
}

#[derive(Debug, Clone)]
pub struct ArtifactStatus {
    pub name: String,
    pub kind: String,
    pub path: String,
    pub declared_sha256: String,
    pub actual_sha256: String,
    pub verified: bool,
    pub error: Option<String>,
}

#[derive(Debug, Clone)]
pub struct CheckReport {
    pub ok: bool,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
    pub artifacts: Vec<ArtifactStatus>,
    pub evidence: BTreeMap<String, EvidenceOutcome>,
    pub claims: Vec<ClaimResult>,
    pub obligations: Vec<ObligationResult>,
    pub conflicts: Vec<ConflictResult>,
    pub decisions: Vec<DecisionResult>,
    pub definitions: Vec<DefinitionAudit>,
    pub proof_stores: BTreeMap<String, FactStore>,
    pub seal_threshold: Strength,
}

impl CheckReport {
    pub fn claim(&self, name: &str) -> Option<&ClaimResult> {
        self.claims.iter().find(|c| c.name == name)
    }

    pub fn sealed_count(&self) -> usize {
        self.claims
            .iter()
            .filter(|c| matches!(c.status, ClaimStatus::Sealed | ClaimStatus::Provisional))
            .count()
    }

    pub fn hypotheses(&self) -> Vec<&ClaimResult> {
        self.claims
            .iter()
            .filter(|c| c.status == ClaimStatus::Hypothesis)
            .collect()
    }

    pub fn open_blocking_obligations(&self) -> Vec<&ObligationResult> {
        self.obligations
            .iter()
            .filter(|o| o.blocks_seal && o.status == ObligationStatus::Open)
            .collect()
    }

    pub fn unresolved_conflicts(&self) -> Vec<&ConflictResult> {
        self.conflicts.iter().filter(|c| !c.resolved).collect()
    }

    pub fn seal_ready(&self) -> Result<(), Vec<String>> {
        let mut errors = self.errors.clone();
        for o in self.open_blocking_obligations() {
            errors.push(format!(
                "obligation {} is open and blocks seal: {}",
                o.name, o.goal
            ));
        }
        for c in self.unresolved_conflicts() {
            errors.push(format!(
                "unresolved conflict {} between {} and {}",
                c.name, c.left, c.right
            ));
        }
        for claim in &self.claims {
            match claim.status {
                ClaimStatus::Sealed | ClaimStatus::Provisional => {}
                ClaimStatus::Hypothesis => errors.push(format!(
                    "claim {} is only a hypothesis ({}); use --allow-hypotheses to record it without sealing",
                    claim.name,
                    claim
                        .strength
                        .map(|s| s.as_str())
                        .unwrap_or("unknown strength")
                )),
                _ => errors.push(format!(
                    "claim {} is {} and cannot be sealed",
                    claim.name,
                    claim.status.as_str()
                )),
            }
        }
        if errors.is_empty() {
            Ok(())
        } else {
            Err(errors)
        }
    }
}

pub fn check(index: &ModelIndex, artifacts: &ArtifactSet) -> CheckReport {
    let mut errors = Vec::new();
    let mut warnings = Vec::new();
    errors.extend(artifacts.errors.iter().cloned());

    let artifact_status = artifacts
        .items
        .values()
        .map(|a| ArtifactStatus {
            name: a.decl.name().to_string(),
            kind: a.decl.kind().to_string(),
            path: a.resolved_path.display().to_string(),
            declared_sha256: a.decl.declared_sha().to_string(),
            actual_sha256: a.actual_sha256.clone(),
            verified: a.verified,
            error: a.load_error.clone(),
        })
        .collect::<Vec<_>>();

    let ctx = EvalCtx { index, artifacts };
    let evidence_outcomes = evidence::evaluate_all(&ctx);
    for (name, outcome) in &evidence_outcomes {
        if !outcome.ok {
            errors.push(format!(
                "evidence {name} failed: {}",
                outcome
                    .error
                    .clone()
                    .unwrap_or_else(|| "unknown error".into())
            ));
        }
    }

    // Decisions are hash-pinned files: verify them before conflicts are
    // resolved, since a digest mismatch makes a decision unusable.
    let decisions = verify_decisions(index, artifacts, &mut errors);

    let all_rules = match index.all_rules() {
        Ok(r) => r,
        Err(e) => {
            errors.extend(e);
            Vec::new()
        }
    };
    let rule_map: BTreeMap<&str, &RuleDecl> =
        all_rules.iter().map(|r| (r.name.as_str(), r)).collect();

    let mut claims = Vec::new();
    let mut proof_stores = BTreeMap::new();

    // 1. Relational proofs.
    for proof in index.proofs.values() {
        let result = check_proof(
            index,
            proof,
            &evidence_outcomes,
            &rule_map,
            &mut proof_stores,
            &mut errors,
        );
        claims.push(result);
    }

    // 2. Direct certificate claims.
    for claim in index.claims.values() {
        if let ClaimBody::Direct { .. } = &claim.body {
            let result = check_direct_claim(index, claim, &evidence_outcomes);
            if result.status == ClaimStatus::Failed {
                errors.push(format!(
                    "claim {} failed: {}",
                    result.name,
                    result.error.clone().unwrap_or_default()
                ));
            }
            claims.push(result);
        }
    }

    // 3. Refutations (they can invalidate proofs before conflicts/derived
    // claims are resolved).
    for refute in &index.refutes {
        let result = check_refute(index, refute, &evidence_outcomes);
        if result.status == ClaimStatus::Failed {
            errors.push(format!(
                "refutation {} failed: {}",
                result.name,
                result.error.clone().unwrap_or_default()
            ));
        }
        // Mark the target claim, if present.
        if result.status == ClaimStatus::Sealed {
            if let Some(key) = &result.goal_key {
                for c in claims.iter_mut() {
                    if c.goal_key.as_ref() == Some(key)
                        && matches!(
                            c.status,
                            ClaimStatus::Sealed
                                | ClaimStatus::Provisional
                                | ClaimStatus::Hypothesis
                        )
                    {
                        c.status = ClaimStatus::Refuted;
                        c.refuted_by = Some(result.name.clone());
                        c.note = Some(format!(
                            "refuted by {}: the simulation witness contradicts this claim",
                            result.name
                        ));
                    }
                }
            }
        }
        claims.push(result);
    }

    for c in claims.iter().filter(|c| c.status == ClaimStatus::Refuted) {
        errors.push(format!(
            "claim {} was refuted{}",
            c.name,
            c.refuted_by
                .as_ref()
                .map(|r| format!(" by {r}"))
                .unwrap_or_default()
        ));
    }

    // 4. Conflicts between active claims (generic pairs, and the uniform-vs-
    // biased auto-detection), resolved by `prefer` or a verified `decision`.
    let conflicts = resolve_conflicts(index, &mut claims, &mut warnings, &decisions);

    // 5. Derived and coverage claims, after base claims and demotions.
    let mut pending: Vec<&ClaimDecl> = index
        .claims
        .values()
        .filter(|c| {
            matches!(
                c.body,
                ClaimBody::Derived { .. } | ClaimBody::Coverage { .. }
            )
        })
        .collect();
    let mut made_progress = true;
    while made_progress {
        made_progress = false;
        let mut still = Vec::new();
        for claim in pending {
            let refs = match &claim.body {
                ClaimBody::Derived { from } | ClaimBody::Coverage { from } => from,
                _ => unreachable!(),
            };
            if refs.iter().all(|r| claims.iter().any(|c| &c.name == r)) {
                let result = match &claim.body {
                    ClaimBody::Derived { .. } => check_derived_claim(index, claim, &claims),
                    ClaimBody::Coverage { .. } => {
                        check_coverage_claim(index, claim, &claims, artifacts)
                    }
                    _ => unreachable!(),
                };
                if result.status == ClaimStatus::Failed {
                    errors.push(format!(
                        "claim {} failed: {}",
                        result.name,
                        result.error.clone().unwrap_or_default()
                    ));
                }
                claims.push(result);
                made_progress = true;
            } else {
                still.push(claim);
            }
        }
        pending = still;
    }
    for claim in pending {
        errors.push(format!("claim {} has unresolved premises", claim.name));
    }

    // 6. Obligations.
    let obligations = check_obligations(index, &claims);

    // 7. Definition audit.
    let definitions = audit_definitions(index, &claims);

    let mut seen = BTreeSet::new();
    claims.retain(|c| seen.insert(c.name.clone()));
    claims.sort_by(|a, b| a.name.cmp(&b.name));

    let ok = errors.is_empty();
    CheckReport {
        ok,
        errors,
        warnings,
        artifacts: artifact_status,
        evidence: evidence_outcomes,
        claims,
        obligations,
        conflicts,
        decisions,
        definitions,
        proof_stores,
        seal_threshold: index.seal_threshold(),
    }
}

fn check_proof(
    index: &ModelIndex,
    proof: &ProofDecl,
    outcomes: &BTreeMap<String, EvidenceOutcome>,
    rule_map: &BTreeMap<&str, &RuleDecl>,
    proof_stores: &mut BTreeMap<String, FactStore>,
    errors: &mut Vec<String>,
) -> ClaimResult {
    let goal_norm = normalize_atom(index, &proof.goal);
    let goal_display = goal_norm.display();
    let mut result = ClaimResult::base(&proof.name, ClaimKind::Proof, &proof.build, goal_display);
    result.strength = None;

    let mut store = FactStore::new();
    for (rel, args) in index.definitions(&proof.build) {
        store.insert_definition(&rel, args);
    }

    let mut failed_evidence = false;
    for ev_name in &proof.evidence {
        let Some(outcome) = outcomes.get(ev_name) else {
            result.error = Some(format!("evidence `{ev_name}` was not evaluated"));
            failed_evidence = true;
            continue;
        };
        if !outcome.ok {
            result.error = Some(format!(
                "evidence `{ev_name}` failed: {}",
                outcome.error.clone().unwrap_or_default()
            ));
            failed_evidence = true;
            continue;
        }
        for (rel, args) in &outcome.facts {
            store.insert_evidence(rel, args.clone(), outcome.strength, ev_name);
        }
        result.support.insert(ev_name.clone());
    }
    if failed_evidence {
        result.status = ClaimStatus::Failed;
        errors.push(format!(
            "proof {} failed: {}",
            proof.name,
            result.error.clone().unwrap_or_default()
        ));
        proof_stores.insert(proof.name.clone(), store);
        return result;
    }

    let mut selected: Vec<RuleDecl> = Vec::new();
    for name in &proof.rules {
        if let Some(rule) = rule_map.get(name.as_str()) {
            selected.push((*rule).clone());
        } else {
            result.status = ClaimStatus::Failed;
            result.error = Some(format!("unknown rule `{name}`"));
            errors.push(format!(
                "proof {} failed: unknown rule `{name}`",
                proof.name
            ));
            proof_stores.insert(proof.name.clone(), store);
            return result;
        }
    }
    let compiled = match facts::compile_rules(&selected) {
        Ok(c) => c,
        Err(e) => {
            result.status = ClaimStatus::Failed;
            result.error = Some(e.clone());
            errors.push(format!("proof {} failed: {e}", proof.name));
            proof_stores.insert(proof.name.clone(), store);
            return result;
        }
    };
    if let Err(e) = facts::fixpoint(&mut store, &compiled) {
        result.status = ClaimStatus::Failed;
        result.error = Some(e.clone());
        errors.push(format!("proof {} failed: {e}", proof.name));
        proof_stores.insert(proof.name.clone(), store);
        return result;
    }

    let key = match facts::ground_key(&goal_norm) {
        Ok(k) => k,
        Err(e) => {
            result.status = ClaimStatus::Failed;
            result.error = Some(e.clone());
            errors.push(format!("proof {} failed: {e}", proof.name));
            proof_stores.insert(proof.name.clone(), store);
            return result;
        }
    };
    result.goal_key = Some(key.clone());

    match store.get(&key) {
        Some(info) => {
            if info.support.is_empty() {
                result.status = ClaimStatus::Hypothesis;
                result.strength = Some(Strength::Speculative);
                result.error = Some(
                    "goal is derived only from model definitions; no evidence supports it".into(),
                );
                result.note = Some("definition-only derivation cannot seal".into());
            } else {
                result.support = info.support.clone();
                result.strength = Some(info.strength);
                if let Some(expect) = proof.expect {
                    if info.strength < expect {
                        result.status = ClaimStatus::Failed;
                        result.error = Some(format!(
                            "proof strength {} is below the required {}",
                            info.strength, expect
                        ));
                    }
                }
                if result.status != ClaimStatus::Failed {
                    let (status, _) =
                        seal_status(info.strength, index.seal_threshold(), None, None);
                    result.status = status;
                    if status == ClaimStatus::Hypothesis {
                        result.note = Some(format!(
                            "strength {} is below the seal threshold {}",
                            info.strength,
                            index.seal_threshold()
                        ));
                    }
                }
            }
        }
        None => {
            result.status = ClaimStatus::Failed;
            let mut related: Vec<String> = store
                .relation(&key.rel)
                .iter()
                .take(8)
                .map(|(k, i)| format!("{} [{}]", k.display(), i.strength))
                .collect();
            if related.is_empty() {
                related.push("(no facts of that relation were derived)".into());
            }
            result.error = Some(format!(
                "could not derive {}; available {} facts: {}",
                key.display(),
                key.rel,
                related.join("; ")
            ));
            errors.push(format!(
                "proof {} failed: {}",
                proof.name,
                result.error.clone().unwrap_or_default()
            ));
        }
    }

    proof_stores.insert(proof.name.clone(), store);
    result
}

fn check_direct_claim(
    index: &ModelIndex,
    claim: &ClaimDecl,
    outcomes: &BTreeMap<String, EvidenceOutcome>,
) -> ClaimResult {
    let kind = match &claim.head {
        ClaimHead::Period { .. } => ClaimKind::Period,
        ClaimHead::Uniform { .. } => ClaimKind::Uniform,
        ClaimHead::Mean { .. } => ClaimKind::Mean,
        ClaimHead::Coverage { .. } => ClaimKind::Coverage,
        ClaimHead::Rel(_) => ClaimKind::Derived,
    };
    let mut result = ClaimResult::base(&claim.name, kind, &claim.build, claim.head.display());
    result.provisional_until = claim.provisional_until.clone();

    let (ev_name, requires) = match &claim.body {
        ClaimBody::Direct { evidence, requires } => (evidence, requires),
        _ => {
            result.status = ClaimStatus::Failed;
            result.error = Some("measurement claim has no `by <evidence>` body".into());
            return result;
        }
    };
    let Some(outcome) = outcomes.get(ev_name) else {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!("unknown evidence `{ev_name}`"));
        return result;
    };
    if !outcome.ok {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!(
            "evidence `{ev_name}` failed: {}",
            outcome.error.clone().unwrap_or_default()
        ));
        return result;
    }
    result.support.insert(ev_name.clone());

    let Some(decl) = index.evidence.get(ev_name) else {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!("unknown evidence `{ev_name}`"));
        return result;
    };

    match &claim.head {
        ClaimHead::Period {
            clock,
            stream,
            period_us,
            eps_us,
        } => {
            let (meas_period, meas_ci, coverage, samples, stationary) = match &outcome.measured {
                Some(Measured::Rate {
                    period_us,
                    ci_us,
                    coverage_us,
                    samples,
                    stationary,
                    opcode,
                    clock: ev_clock,
                }) => {
                    if opcode != stream {
                        result.status = ClaimStatus::Failed;
                        result.error = Some(format!(
                            "evidence stream is {opcode:#06x}, claim is {stream:#06x}"
                        ));
                        return result;
                    }
                    if let Some(c) = ev_clock {
                        if c != clock {
                            result.status = ClaimStatus::Failed;
                            result.error = Some(format!(
                                "evidence clock `{c}` does not match claim clock `{clock}`"
                            ));
                            return result;
                        }
                    }
                    (*period_us, *ci_us, *coverage_us, *samples, *stationary)
                }
                _ => {
                    result.status = ClaimStatus::Failed;
                    result.error = Some("period claim requires `rate(...)` evidence".into());
                    return result;
                }
            };
            if let EvidenceKind::Rate { capture, .. } = &decl.kind {
                if claim.during.as_deref() != Some(capture.as_str()) {
                    result.status = ClaimStatus::Failed;
                    result.error = Some(format!(
                        "period claim must be `during {capture}` to match its evidence"
                    ));
                    return result;
                }
            }
            let req = Requirements::from(requires.as_slice());
            let z = stats::normal_quantile(1.0 - (1.0 - req.confidence) / 2.0);
            let ci = meas_ci * z / 1.96;
            if req.samples > 0 && samples < req.samples {
                result.status = ClaimStatus::Hypothesis;
                result.note = Some(format!(
                    "only {samples} samples; requirement is {}",
                    req.samples
                ));
                result.strength = Some(Strength::Heuristic);
                result.measured = Some(format!(
                    "period={meas_period:.1}us ci={ci:.1}us coverage={coverage}us samples={samples}"
                ));
                return result;
            }
            if req.coverage > 0 && coverage < req.coverage {
                result.status = ClaimStatus::Hypothesis;
                result.note = Some(format!(
                    "coverage {coverage}us is below the required {}us",
                    req.coverage
                ));
                result.strength = Some(Strength::Heuristic);
                result.measured = Some(format!(
                    "period={meas_period:.1}us ci={ci:.1}us coverage={coverage}us samples={samples}"
                ));
                return result;
            }
            if (meas_period - *period_us as f64).abs() > *eps_us as f64 {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "measured period {meas_period:.3}us differs from claimed {period_us}us by more than {eps_us}us"
                ));
                result.measured = Some(format!(
                    "period={meas_period:.1}us ci={ci:.1}us coverage={coverage}us samples={samples}"
                ));
                return result;
            }
            if ci > *eps_us as f64 {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "claimed tolerance {eps_us}us is tighter than the evidence CI ±{ci:.1}us"
                ));
                result.measured = Some(format!(
                    "period={meas_period:.1}us ci={ci:.1}us coverage={coverage}us samples={samples}"
                ));
                return result;
            }
            result.measured = Some(format!(
                "period={meas_period:.3}us ci95={ci:.3}us coverage={coverage}us samples={samples}"
            ));
            if !stationary {
                result.strength = Some(Strength::Heuristic);
                result.status = ClaimStatus::Hypothesis;
                result.note = Some("the rate evidence failed the stationarity check".into());
                return result;
            }
            result.strength = Some(Strength::Observational);
            let (status, note) = seal_status(
                Strength::Observational,
                index.seal_threshold(),
                claim.provisional_until.as_deref(),
                None,
            );
            result.status = status;
            result.note = note;
        }
        ClaimHead::Uniform { dist, bins } => {
            let (counts, n, coverage) = match &outcome.measured {
                Some(Measured::Sample {
                    counts,
                    n,
                    coverage_us,
                    opcode: _,
                    field: _,
                    width: _,
                }) => (counts.clone(), *n, *coverage_us),
                _ => {
                    result.status = ClaimStatus::Failed;
                    result.error = Some("uniform claim requires `sample(...)` evidence".into());
                    return result;
                }
            };
            if let EvidenceKind::Sample { capture, .. } = &decl.kind {
                if claim.during.as_deref() != Some(capture.as_str()) {
                    result.status = ClaimStatus::Failed;
                    result.error = Some(format!(
                        "uniform claim must be `during {capture}` to match its evidence"
                    ));
                    return result;
                }
            }
            let d = match index.dists.get(dist) {
                Some(d) => d,
                None => {
                    result.status = ClaimStatus::Failed;
                    result.error = Some(format!("unknown distribution `{dist}`"));
                    return result;
                }
            };
            if d.bins != *bins {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "distribution `{dist}` declares {} bins, claim uses {bins}",
                    d.bins
                ));
                return result;
            }
            let k = *bins as usize;
            let mut padded = vec![0u64; k];
            for (i, c) in counts.iter().enumerate() {
                if i >= k {
                    if *c > 0 {
                        result.status = ClaimStatus::Failed;
                        result.error =
                            Some(format!("sample value {i} is outside the claimed {k} bins"));
                        return result;
                    }
                } else {
                    padded[i] = *c;
                }
            }
            let (stat, df, p) = stats::chi2_uniform(&padded);
            let req = Requirements::from(requires.as_slice());
            result.measured = Some(format!(
                "n={n} coverage={coverage}us chi2={stat:.3} df={df:.0} p={p:.3e}"
            ));
            if req.samples > 0 && n < req.samples {
                result.status = ClaimStatus::Hypothesis;
                result.strength = Some(Strength::Observational);
                result.note = Some(format!("only {n} samples; requirement is {}", req.samples));
                return result;
            }
            if req.coverage > 0 && coverage < req.coverage {
                result.status = ClaimStatus::Hypothesis;
                result.strength = Some(Strength::Observational);
                result.note = Some(format!(
                    "coverage {coverage}us is below the required {}us",
                    req.coverage
                ));
                return result;
            }
            if p < req.alpha {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "uniformity rejected: p={p:.3e} < alpha={:.3e}",
                    req.alpha
                ));
                return result;
            }
            let delta = req.delta.unwrap_or(0.01);
            if let Some(power) = req.power {
                let required = stats::required_samples(1.0 / k as f64, delta, req.alpha, power);
                let achieved = stats::achieved_power(1.0 / k as f64, delta, req.alpha, n as f64);
                result.measured = Some(format!(
                    "n={n} coverage={coverage}us chi2={stat:.3} df={df:.0} p={p:.3e} required_n={required:.0} power={achieved:.3}"
                ));
                if (n as f64) < required {
                    result.status = ClaimStatus::Hypothesis;
                    result.strength = Some(Strength::Observational);
                    result.note = Some(format!(
                        "underpowered: n={n}, required n≈{required:.0} to detect delta={delta} at alpha={:.1e}, power={power}",
                        req.alpha
                    ));
                    return result;
                }
            }
            result.strength = Some(Strength::Observational);
            let (status, note) = seal_status(
                Strength::Observational,
                index.seal_threshold(),
                claim.provisional_until.as_deref(),
                None,
            );
            result.status = status;
            result.note = note;
        }
        ClaimHead::Mean { metric, value, eps } => {
            let group = match &outcome.measured {
                Some(Measured::Samples { groups }) => match groups.get(metric) {
                    Some(g) => g.clone(),
                    None => {
                        result.status = ClaimStatus::Failed;
                        let available: Vec<&str> = groups.keys().map(String::as_str).collect();
                        result.error = Some(format!(
                            "samples evidence `{ev_name}` has no group `{metric}`; available: {}",
                            if available.is_empty() {
                                "(none)".to_string()
                            } else {
                                available
                                    .iter()
                                    .map(|g| format!("`{g}`"))
                                    .collect::<Vec<_>>()
                                    .join(", ")
                            }
                        ));
                        return result;
                    }
                },
                _ => {
                    result.status = ClaimStatus::Failed;
                    result.error = Some("mean claim requires `samples(...)` evidence".into());
                    return result;
                }
            };
            let req = Requirements::from(requires.as_slice());
            let n = group.n;
            result.measured = Some(format!(
                "n={n} mean={:.3} median={:.3} sd={:.3} ci95={:.3}",
                group.mean, group.median, group.sd, group.ci95
            ));
            if req.samples > 0 && n < req.samples {
                result.status = ClaimStatus::Hypothesis;
                result.strength = Some(Strength::Observational);
                result.note = Some(format!("only {n} samples; requirement is {}", req.samples));
                return result;
            }
            if (group.mean - *value).abs() > *eps {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "measured mean {:.3} differs from claimed {value} by more than {eps}",
                    group.mean
                ));
                return result;
            }
            // Rescale the 95% CI to the requested confidence.
            let z = stats::normal_quantile(1.0 - (1.0 - req.confidence) / 2.0);
            let ci = group.ci95 * z / 1.96;
            if ci > *eps {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "claimed tolerance {eps} is tighter than the evidence CI ±{ci:.3}"
                ));
                return result;
            }
            // Power/delta when declared: alpha is fixed at 0.05 for mean
            // claims in v0.1 (there is no alpha requirement syntax for them).
            if let Some(delta) = req.delta {
                if let Some(power) = req.power {
                    let z_alpha = stats::normal_quantile(1.0 - 0.05 / 2.0);
                    let z_power = stats::normal_quantile(power);
                    let required_n = ((z_alpha + z_power) * group.sd / delta).powi(2);
                    if (n as f64) < required_n {
                        result.status = ClaimStatus::Hypothesis;
                        result.strength = Some(Strength::Observational);
                        result.note = Some(format!(
                            "underpowered: n={n}, required n≈{required_n:.0} to detect delta={delta} at power={power}"
                        ));
                        return result;
                    }
                }
            }
            result.strength = Some(Strength::Observational);
            let (status, note) = seal_status(
                Strength::Observational,
                index.seal_threshold(),
                claim.provisional_until.as_deref(),
                None,
            );
            result.status = status;
            result.note = note;
        }
        ClaimHead::Coverage { .. } => {
            result.status = ClaimStatus::Failed;
            result.error =
                Some("coverage claims must use `from <claim,...>`, not `by <evidence>`".into());
        }
        ClaimHead::Rel(_) => {
            result.status = ClaimStatus::Failed;
            result.error =
                Some("relational goals must use `proof`, not a direct `claim ... by`".into());
        }
    }
    result
}

pub fn check_derived_claim(
    index: &ModelIndex,
    claim: &ClaimDecl,
    claims: &[ClaimResult],
) -> ClaimResult {
    let mut result = ClaimResult::base(
        &claim.name,
        ClaimKind::Derived,
        &claim.build,
        claim.head.display(),
    );
    result.provisional_until = claim.provisional_until.clone();
    let refs = match &claim.body {
        ClaimBody::Derived { from } => from,
        _ => {
            result.status = ClaimStatus::Failed;
            result.error = Some("not a derived claim".into());
            return result;
        }
    };
    let mut premises = Vec::new();
    for r in refs {
        match claims.iter().find(|c| &c.name == r) {
            Some(c) => premises.push(c),
            None => {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!("unknown premise `{r}`"));
                return result;
            }
        }
    }

    let hard = premises.iter().find(|c| {
        matches!(
            c.status,
            ClaimStatus::Failed | ClaimStatus::Open | ClaimStatus::Refuted | ClaimStatus::Stale
        )
    });
    if let Some(bad) = hard {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!("premise `{}` is {}", bad.name, bad.status.as_str()));
        result.premises = refs.clone();
        return result;
    }

    let mut min_strength = Strength::Exact;
    let mut bottleneck = None;
    let mut provisional_until: Option<String> = None;
    let mut any_hypothesis = false;
    let mut all_provisional = true;
    for p in &premises {
        let s = p.strength.unwrap_or(Strength::Speculative);
        if s < min_strength {
            min_strength = s;
            bottleneck = Some(p.name.clone());
        } else if bottleneck.is_none() {
            bottleneck = Some(p.name.clone());
        }
        if p.status == ClaimStatus::Hypothesis {
            any_hypothesis = true;
        }
        if p.status != ClaimStatus::Provisional {
            all_provisional = false;
        }
        if p.status == ClaimStatus::Provisional {
            if let Some(exp) = &p.provisional_until {
                provisional_until = match provisional_until {
                    None => Some(exp.clone()),
                    Some(cur) => {
                        if date_key(exp) < date_key(&cur) {
                            Some(exp.clone())
                        } else {
                            Some(cur)
                        }
                    }
                };
            }
        }
    }
    result.strength = Some(min_strength);
    result.premises = refs.clone();
    result.support = refs.iter().cloned().collect();
    result.bottleneck = bottleneck;
    result.provisional_until = provisional_until.clone().or(result.provisional_until);

    if let ClaimHead::Rel(atom) = &claim.head {
        let norm = normalize_atom(index, atom);
        if let Ok(key) = facts::ground_key(&norm) {
            result.goal_key = Some(key);
        }
    }

    if any_hypothesis {
        result.status = ClaimStatus::Hypothesis;
        result.note = Some("at least one premise is only a hypothesis".into());
        return result;
    }
    if min_strength < index.seal_threshold() {
        if provisional_until.is_some() && min_strength >= Strength::Observational {
            result.status = ClaimStatus::Provisional;
            result.note = Some(format!(
                "provisional via premise{}; expires {}{}",
                if premises.len() > 1 { "s" } else { "" },
                provisional_until.clone().unwrap_or_else(|| "never".into()),
                provisional_until
                    .as_deref()
                    .map(|d| if provisional_expired(d) {
                        " (EXPIRED)"
                    } else {
                        ""
                    })
                    .unwrap_or("")
            ));
            if provisional_until
                .as_deref()
                .map(provisional_expired)
                .unwrap_or(false)
            {
                result.status = ClaimStatus::Hypothesis;
                result.note = Some("provisional premise has expired".into());
            }
        } else {
            result.status = ClaimStatus::Hypothesis;
            result.note = Some(format!(
                "minimum premise strength {min_strength} is below the seal threshold {}",
                index.seal_threshold()
            ));
        }
        return result;
    }
    result.status = if all_provisional {
        ClaimStatus::Provisional
    } else {
        ClaimStatus::Sealed
    };
    result
}

/// Verify every declared decision file: resolve the path against the model
/// directory (absolute paths are allowed), read the bytes, and compare the
/// SHA-256 to the declared digest. A missing file or a digest mismatch is a
/// hard error and makes the decision unusable for conflict resolution.
fn verify_decisions(
    index: &ModelIndex,
    artifacts: &ArtifactSet,
    errors: &mut Vec<String>,
) -> Vec<DecisionResult> {
    let mut out = Vec::new();
    for (name, d) in &index.decisions {
        let p = Path::new(&d.path);
        let full = if p.is_absolute() {
            p.to_path_buf()
        } else {
            artifacts.model_dir.join(p)
        };
        let (sha256, ok) = match fs::read(&full) {
            Ok(bytes) => {
                let actual = crate::sha256::sha256_hex(&bytes);
                let ok = actual.eq_ignore_ascii_case(&d.sha256);
                if !ok {
                    errors.push(format!(
                        "decision {name}: digest mismatch (declared {}, actual {actual})",
                        d.sha256.to_ascii_lowercase()
                    ));
                }
                (actual, ok)
            }
            Err(e) => {
                errors.push(format!(
                    "decision {name}: cannot read {}: {e}",
                    full.display()
                ));
                (String::new(), false)
            }
        };
        out.push(DecisionResult {
            name: name.clone(),
            sha256,
            ok,
            signer: d.signer.clone(),
            prefer: d.prefer.clone(),
            over: d.over.clone(),
        });
    }
    out
}

/// Check a coverage claim: how many IDs of a locked dataset are covered by
/// sealed claims of one relation family.
///
/// DeG is not the count authority — the dataset fixes the universe of IDs and
/// each premise must be a sealed/provisional ground claim whose first
/// argument is an ID from the dataset. The claim seals when every dataset ID
/// is covered and the number of covered IDs equals the declared target.
fn check_coverage_claim(
    index: &ModelIndex,
    claim: &ClaimDecl,
    claims: &[ClaimResult],
    artifacts: &ArtifactSet,
) -> ClaimResult {
    let (dataset_name, target) = match &claim.head {
        ClaimHead::Coverage { dataset, target } => (dataset.clone(), *target),
        _ => {
            let mut result = ClaimResult::base(
                &claim.name,
                ClaimKind::Coverage,
                &claim.build,
                claim.head.display(),
            );
            result.status = ClaimStatus::Failed;
            result.error = Some("not a coverage claim".into());
            return result;
        }
    };
    let mut result = ClaimResult::base(
        &claim.name,
        ClaimKind::Coverage,
        &claim.build,
        claim.head.display(),
    );
    result.provisional_until = claim.provisional_until.clone();
    let refs = match &claim.body {
        ClaimBody::Coverage { from } => from.clone(),
        _ => {
            result.status = ClaimStatus::Failed;
            result.error = Some("coverage claim has no `from <claim,...>` body".into());
            return result;
        }
    };

    // The universe of IDs: one integer per line, hex `0x…` allowed, blank
    // lines and `#` comments ignored. Duplicates count once.
    let text = match artifacts.dataset_text(&dataset_name) {
        Ok(t) => t,
        Err(e) => {
            result.status = ClaimStatus::Failed;
            result.error = Some(e);
            return result;
        }
    };
    let mut ids = BTreeSet::new();
    let mut duplicates = 0usize;
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("").trim();
        if line.is_empty() {
            continue;
        }
        let id = match parse_dataset_id(line) {
            Some(v) => v,
            None => {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!(
                    "dataset `{dataset_name}` contains an invalid id {line:?}"
                ));
                return result;
            }
        };
        if !ids.insert(id) {
            duplicates += 1;
        }
    }
    if ids.is_empty() {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!("dataset `{dataset_name}` contains no ids"));
        return result;
    }

    let mut premises = Vec::new();
    for r in &refs {
        match claims.iter().find(|c| &c.name == r) {
            Some(c) => premises.push(c),
            None => {
                result.status = ClaimStatus::Failed;
                result.error = Some(format!("unknown premise `{r}`"));
                return result;
            }
        }
    }

    // Every premise must be a sealed/provisional claim with a ground goal;
    // the first premise's relation defines the family.
    let mut min_strength = Strength::Exact;
    let mut bottleneck = None;
    let mut covered: BTreeSet<i128> = BTreeSet::new();
    let mut family: Option<String> = None;
    let mut all_provisional = true;
    let mut provisional_until: Option<String> = None;
    for p in &premises {
        if !p.status.usable() {
            result.status = ClaimStatus::Failed;
            result.error = Some(format!("premise `{}` is {}", p.name, p.status.as_str()));
            result.premises = refs.clone();
            return result;
        }
        let Some(key) = &p.goal_key else {
            result.status = ClaimStatus::Failed;
            result.error = Some(format!("premise `{}` has no ground goal", p.name));
            result.premises = refs.clone();
            return result;
        };
        match &family {
            None => family = Some(key.rel.clone()),
            Some(f) => {
                if f != &key.rel {
                    result.status = ClaimStatus::Failed;
                    result.error = Some(format!(
                        "premise `{}` proves `{}`, but the family is `{}`",
                        p.name, key.rel, f
                    ));
                    result.premises = refs.clone();
                    return result;
                }
            }
        }
        let Some(Value::Int(id)) = key.args.first() else {
            result.status = ClaimStatus::Failed;
            result.error = Some(format!(
                "premise `{}` goal {} has no integer first argument",
                p.name,
                key.display()
            ));
            result.premises = refs.clone();
            return result;
        };
        if !ids.contains(id) {
            result.status = ClaimStatus::Failed;
            result.error = Some(format!(
                "claim `{}` covers id {id} not in dataset `{dataset_name}`",
                p.name
            ));
            result.premises = refs.clone();
            return result;
        }
        covered.insert(*id);
        let s = p.strength.unwrap_or(Strength::Speculative);
        if s < min_strength {
            min_strength = s;
            bottleneck = Some(p.name.clone());
        } else if bottleneck.is_none() {
            bottleneck = Some(p.name.clone());
        }
        if p.status != ClaimStatus::Provisional {
            all_provisional = false;
        } else if let Some(exp) = &p.provisional_until {
            provisional_until = match provisional_until {
                None => Some(exp.clone()),
                Some(cur) => {
                    if date_key(exp) < date_key(&cur) {
                        Some(exp.clone())
                    } else {
                        Some(cur)
                    }
                }
            };
        }
    }

    result.strength = Some(min_strength);
    result.premises = refs.clone();
    result.support = refs.iter().cloned().collect();
    result.bottleneck = bottleneck;
    result.provisional_until = provisional_until.clone().or(result.provisional_until);
    result.measured = Some(format!(
        "dataset {dataset_name}: {} distinct id(s), {duplicates} duplicate(s) deduplicated",
        ids.len()
    ));

    let missing: Vec<i128> = ids
        .iter()
        .filter(|i| !covered.contains(i))
        .copied()
        .collect();
    let covered_n = covered.len() as u64;
    result.coverage = Some(CoverageStats {
        covered: covered_n,
        target,
        missing: missing.clone(),
    });

    if !missing.is_empty() {
        result.status = ClaimStatus::Hypothesis;
        result.note = Some(format!(
            "covered {covered_n}/{target}; missing: {}",
            format_missing_ids(&missing)
        ));
        return result;
    }
    if covered_n != target {
        result.status = ClaimStatus::Hypothesis;
        result.note = Some(format!("covered {covered_n}/{target} (target not met)"));
        return result;
    }
    if min_strength < index.seal_threshold() {
        if provisional_until.is_some() && min_strength >= Strength::Observational {
            result.status = ClaimStatus::Provisional;
            result.note = Some(format!(
                "provisional via premise{}; expires {}{}",
                if premises.len() > 1 { "s" } else { "" },
                provisional_until.clone().unwrap_or_else(|| "never".into()),
                provisional_until
                    .as_deref()
                    .map(|d| if provisional_expired(d) {
                        " (EXPIRED)"
                    } else {
                        ""
                    })
                    .unwrap_or("")
            ));
            if provisional_until
                .as_deref()
                .map(provisional_expired)
                .unwrap_or(false)
            {
                result.status = ClaimStatus::Hypothesis;
                result.note = Some("provisional premise has expired".into());
            }
        } else {
            result.status = ClaimStatus::Hypothesis;
            result.note = Some(format!(
                "minimum premise strength {min_strength} is below the seal threshold {}",
                index.seal_threshold()
            ));
        }
        return result;
    }
    result.status = if all_provisional {
        ClaimStatus::Provisional
    } else {
        ClaimStatus::Sealed
    };
    result
}

/// Parse one dataset id: decimal or `0x…` hex, non-negative.
fn parse_dataset_id(s: &str) -> Option<i128> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok().map(|v| v as i128)
    } else {
        s.parse().ok()
    }
}

/// Render missing ids compactly: up to 32 as hex, then "+K more".
fn format_missing_ids(missing: &[i128]) -> String {
    const LIMIT: usize = 32;
    let shown: Vec<String> = missing
        .iter()
        .take(LIMIT)
        .map(|id| format!("{id:#x}"))
        .collect();
    if missing.len() > LIMIT {
        format!("{}, +{} more", shown.join(", "), missing.len() - LIMIT)
    } else {
        shown.join(", ")
    }
}

fn check_refute(
    index: &ModelIndex,
    refute: &RefuteDecl,
    outcomes: &BTreeMap<String, EvidenceOutcome>,
) -> ClaimResult {
    let norm = normalize_atom(index, &refute.goal);
    let mut result = ClaimResult::base(
        &refute.name,
        ClaimKind::Refute,
        &refute.build,
        norm.display(),
    );
    result.support.insert(refute.evidence.clone());
    let key = match facts::ground_key(&norm) {
        Ok(k) => k,
        Err(e) => {
            result.status = ClaimStatus::Failed;
            result.error = Some(e);
            return result;
        }
    };
    result.goal_key = Some(key.clone());
    let Some(outcome) = outcomes.get(&refute.evidence) else {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!("unknown evidence `{}`", refute.evidence));
        return result;
    };
    if !outcome.ok {
        result.status = ClaimStatus::Failed;
        result.error = Some(format!(
            "evidence `{}` failed: {}",
            refute.evidence,
            outcome.error.clone().unwrap_or_default()
        ));
        return result;
    }
    if key.rel == "algo" && key.args.len() == 2 {
        // RNG path: a `sim_fail` fact from recovery evidence contradicts the
        // declared algorithm.
        let rng = &key.args[0];
        let algo = &key.args[1];
        let contradicts = outcome.facts.iter().any(|(rel, args)| {
            rel == "sim_fail" && args.len() == 3 && &args[1] == rng && &args[2] == algo
        });
        if contradicts {
            result.status = ClaimStatus::Sealed;
            result.strength = Some(Strength::Deterministic);
            result.note = Some("the simulation witness contradicts the goal".into());
        } else {
            result.status = ClaimStatus::Failed;
            result.error =
                Some("evidence does not contain a `sim_fail` fact matching this goal".into());
        }
        return result;
    }

    // General path: any ground goal can be refuted when the evidence carries
    // a `contradicts(ev, rel, [args…])` fact whose relation and argument
    // list equal the goal's. Core primitives may emit it in future;
    // extensions can emit it through external certificate facts today.
    let mut available: Vec<String> = Vec::new();
    for (rel, args) in &outcome.facts {
        if rel != "contradicts" || args.len() != 3 {
            continue;
        }
        let (Some(Value::Sym(ev)), Some(Value::Sym(rel_name)), Some(Value::List(vals))) =
            (args.first(), args.get(1), args.get(2))
        else {
            continue;
        };
        let shown = format!(
            "contradicts({ev}, {rel_name}, [{}])",
            vals.iter()
                .map(Value::display)
                .collect::<Vec<_>>()
                .join(", ")
        );
        if rel_name == &key.rel && *vals == key.args {
            result.status = ClaimStatus::Sealed;
            // The evidence emitted the mismatch as a checked fact, so the
            // refutation is never stronger than that evidence.
            result.strength = Some(outcome.strength.min(Strength::Deterministic));
            result.note =
                Some("the evidence carries a `contradicts` fact matching the goal".into());
            return result;
        }
        available.push(shown);
    }
    result.status = ClaimStatus::Failed;
    result.error = Some(if available.is_empty() {
        "evidence does not contain a `contradicts` fact matching this goal".into()
    } else {
        format!(
            "evidence does not contain a `contradicts` fact matching this goal; available: {}",
            available.join("; ")
        )
    });
    result
}

fn resolve_conflicts(
    index: &ModelIndex,
    claims: &mut [ClaimResult],
    warnings: &mut Vec<String>,
    decisions: &[DecisionResult],
) -> Vec<ConflictResult> {
    let mut out = Vec::new();

    // A claim is "active" when it is Sealed, Provisional, or Hypothesis;
    // only active claims take part in conflicts.
    fn active(claims: &[ClaimResult], name: &str) -> bool {
        claims
            .iter()
            .find(|c| c.name == name)
            .map(|c| {
                matches!(
                    c.status,
                    ClaimStatus::Sealed | ClaimStatus::Provisional | ClaimStatus::Hypothesis
                )
            })
            .unwrap_or(false)
    }

    // Resolve a declared pair via `prefer` or a verified `decision`. Returns
    // the name to prefer, or None when the conflict cannot be resolved.
    let resolution = |d: &ConflictDecl| -> Option<String> {
        if let Some(p) = &d.prefer {
            return Some(p.clone());
        }
        if let Some(dname) = &d.decision {
            let decision = decisions.iter().find(|r| &r.name == dname && r.ok)?;
            if (decision.prefer == d.left && decision.over == d.right)
                || (decision.prefer == d.right && decision.over == d.left)
            {
                return Some(decision.prefer.clone());
            }
        }
        None
    };

    // (b) Generic conflicts: any declared pair whose sides are two active
    // claims conflicts, regardless of claim heads. This covers the
    // uniform/biased pairs when a declaration names them, and any other pair
    // the researcher declares.
    for d in &index.conflicts {
        if !active(claims, &d.left) || !active(claims, &d.right) {
            // (c) A declaration that does not name two active claims is a
            // warning, exactly as before.
            warnings.push(format!(
                "conflict declaration `{}` does not match two active claims",
                d.name
            ));
            continue;
        }
        match resolution(d) {
            Some(pref) => {
                let demoted = if pref == d.left { &d.right } else { &d.left };
                if let Some(c) = claims.iter_mut().find(|c| &c.name == demoted) {
                    if matches!(c.status, ClaimStatus::Sealed | ClaimStatus::Provisional) {
                        c.status = ClaimStatus::Hypothesis;
                        c.note = Some(format!(
                            "demoted by conflict {}{}",
                            d.name,
                            d.reason
                                .as_ref()
                                .map(|r| format!(": {r}"))
                                .unwrap_or_default()
                        ));
                        c.conflict_with.push(pref.clone());
                    }
                }
                out.push(ConflictResult {
                    name: d.name.clone(),
                    left: d.left.clone(),
                    right: d.right.clone(),
                    preferred: Some(pref),
                    demoted: Some(demoted.clone()),
                    reason: d.reason.clone(),
                    decision: d.decision.clone(),
                    resolved: true,
                });
            }
            None => {
                out.push(ConflictResult {
                    name: d.name.clone(),
                    left: d.left.clone(),
                    right: d.right.clone(),
                    preferred: None,
                    demoted: None,
                    reason: d.reason.clone(),
                    decision: d.decision.clone(),
                    resolved: false,
                });
                match (&d.prefer, &d.decision) {
                    (None, None) => warnings.push(format!(
                        "conflict between `{}` and `{}` has no `prefer` clause",
                        d.left, d.right
                    )),
                    (_, Some(dname)) => warnings.push(format!(
                        "decision `{dname}` does not resolve conflict `{}` between `{}` and `{}`",
                        d.name, d.left, d.right
                    )),
                    _ => {}
                }
            }
        }
    }

    // (a) Auto-detected uniform/biased pairs that no declaration names.
    let mut uniform: Vec<(String, String)> = Vec::new();
    let mut biased: Vec<(String, String)> = Vec::new();
    for c in claims.iter() {
        if let Some(ClaimHead::Uniform { dist, .. }) = index.claims.get(&c.name).map(|d| &d.head) {
            uniform.push((c.name.clone(), dist.clone()));
        }
        if let Some(key) = &c.goal_key {
            if key.rel == "biased" {
                if let Some(Value::Sym(dist)) = key.args.first() {
                    biased.push((c.name.clone(), dist.clone()));
                }
            }
        }
    }
    for (u_name, u_dist) in &uniform {
        for (b_name, b_dist) in &biased {
            if u_dist != b_dist || u_name == b_name {
                continue;
            }
            if !active(claims, u_name) || !active(claims, b_name) {
                continue;
            }
            let declared = index.conflicts.iter().any(|d| {
                (d.left == *u_name && d.right == *b_name)
                    || (d.left == *b_name && d.right == *u_name)
            });
            if declared {
                continue;
            }
            out.push(ConflictResult {
                name: format!("auto:{u_name}~{b_name}"),
                left: u_name.clone(),
                right: b_name.clone(),
                preferred: None,
                demoted: None,
                reason: None,
                decision: None,
                resolved: false,
            });
            warnings.push(format!(
                "uniform `{u_name}` and biased `{b_name}` conflict; declare a `conflict` block with `prefer`"
            ));
        }
    }
    out
}

fn check_obligations(index: &ModelIndex, claims: &[ClaimResult]) -> Vec<ObligationResult> {
    #[derive(Clone)]
    struct Spec {
        atom: Atom,
        priority: Priority,
        blocks_seal: bool,
        resolved_by: Option<String>,
        span: crate::lexer::Span,
    }
    let mut specs: BTreeMap<String, Spec> = BTreeMap::new();
    for o in &index.obligations {
        if o.atom.name == "resolved" {
            continue;
        }
        specs.insert(
            o.name.clone(),
            Spec {
                atom: o.atom.clone(),
                priority: o.priority,
                blocks_seal: o.blocks_seal,
                resolved_by: o.resolved_by.clone(),
                span: o.span,
            },
        );
    }
    for o in &index.obligations {
        if let Some(r) = &o.resolved_by {
            if let Some(spec) = specs.get_mut(&o.name) {
                spec.resolved_by = Some(r.clone());
            }
        }
    }
    let mut out = Vec::new();
    for (name, spec) in specs {
        let norm = normalize_atom(index, &spec.atom);
        let goal = norm.display();
        let key = facts::ground_key(&norm).ok();
        let mut resolved_by = None;
        if let Some(r) = &spec.resolved_by {
            if let Some(c) = claims.iter().find(|c| &c.name == r) {
                if c.status.usable() {
                    resolved_by = Some(r.clone());
                }
            }
        }
        if resolved_by.is_none() {
            if let Some(k) = &key {
                resolved_by = claims
                    .iter()
                    .find(|c| c.status.usable() && c.goal_key.as_ref() == Some(k))
                    .map(|c| c.name.clone());
            }
        }
        let _ = spec.span;
        out.push(ObligationResult {
            name,
            goal,
            priority: spec.priority,
            blocks_seal: spec.blocks_seal,
            status: if resolved_by.is_some() {
                ObligationStatus::Resolved
            } else {
                ObligationStatus::Open
            },
            resolved_by,
        });
    }
    out
}

fn audit_definitions(index: &ModelIndex, claims: &[ClaimResult]) -> Vec<DefinitionAudit> {
    let mut out = Vec::new();
    let sealed =
        |pred: &dyn Fn(&ClaimResult) -> bool| claims.iter().find(|c| c.status.usable() && pred(c));
    for f in index.fns.values() {
        let just = sealed(&|c| {
            c.goal_key
                .as_ref()
                .map(|k| {
                    (k.rel == "anchored"
                        && k.args.first().map(|v| v.as_str()) == Some(Some(&f.name)))
                        || (k.rel == "defined"
                            && k.args.first().and_then(|v| v.as_str()) == Some("fn")
                            && k.args.get(1).and_then(|v| v.as_str()) == Some(&f.name))
                })
                .unwrap_or(false)
        });
        out.push(DefinitionAudit {
            kind: "fn".into(),
            name: f.name.clone(),
            build: f.build.clone(),
            justified: just.is_some(),
            justification: just.map(|c| c.name.clone()),
        });
    }
    for s in index.structs.values() {
        let just = sealed(&|c| {
            c.goal_key
                .as_ref()
                .map(|k| {
                    (k.rel == "layout_exact"
                        && k.args.first().and_then(|v| v.as_str()) == Some(&s.name))
                        || (k.rel == "defined"
                            && k.args.first().and_then(|v| v.as_str()) == Some("struct")
                            && k.args.get(1).and_then(|v| v.as_str()) == Some(&s.name))
                })
                .unwrap_or(false)
        });
        out.push(DefinitionAudit {
            kind: "struct".into(),
            name: s.name.clone(),
            build: s.build.clone(),
            justified: just.is_some(),
            justification: just.map(|c| c.name.clone()),
        });
    }
    for r in index.rngs.values() {
        let just = sealed(&|c| {
            c.goal_key
                .as_ref()
                .map(|k| {
                    k.rel == "algo" && k.args.first().and_then(|v| v.as_str()) == Some(&r.name)
                })
                .unwrap_or(false)
        });
        out.push(DefinitionAudit {
            kind: "rng".into(),
            name: r.name.clone(),
            build: r.build.clone(),
            justified: just.is_some(),
            justification: just.map(|c| c.name.clone()),
        });
    }
    for p in index.packets.values() {
        out.push(DefinitionAudit {
            kind: "packet".into(),
            name: p.name.clone(),
            build: p.build.clone(),
            justified: false,
            justification: None,
        });
    }
    for d in index.dists.values() {
        out.push(DefinitionAudit {
            kind: "dist".into(),
            name: d.name.clone(),
            build: d.build.clone(),
            justified: false,
            justification: None,
        });
    }
    out.sort_by(|a, b| (a.kind.as_str(), a.name.as_str()).cmp(&(b.kind.as_str(), b.name.as_str())));
    out
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

#[derive(Debug, Clone, Copy)]
struct Requirements {
    coverage: u64,
    alpha: f64,
    power: Option<f64>,
    delta: Option<f64>,
    confidence: f64,
    samples: u64,
}

impl From<&[Requirement]> for Requirements {
    fn from(reqs: &[Requirement]) -> Requirements {
        let mut out = Requirements {
            coverage: 0,
            alpha: 0.05,
            power: None,
            delta: None,
            confidence: 0.95,
            samples: 0,
        };
        for r in reqs {
            match r {
                Requirement::CoverageAtLeast(us) => out.coverage = *us,
                Requirement::Alpha(a) => out.alpha = *a,
                Requirement::Power(p) => out.power = Some(*p),
                Requirement::Delta(d) => out.delta = Some(*d),
                Requirement::ConfidenceAtLeast(c) => out.confidence = *c,
                Requirement::SamplesAtLeast(n) => out.samples = *n,
            }
        }
        out
    }
}

fn seal_status(
    strength: Strength,
    threshold: Strength,
    provisional_until: Option<&str>,
    note: Option<String>,
) -> (ClaimStatus, Option<String>) {
    if strength >= threshold {
        return (ClaimStatus::Sealed, note);
    }
    if let Some(until) = provisional_until {
        if strength >= Strength::Observational {
            if provisional_expired(until) {
                return (
                    ClaimStatus::Hypothesis,
                    Some(format!("provisional window ended {until}")),
                );
            }
            return (
                ClaimStatus::Provisional,
                Some(format!("provisional until {until}")),
            );
        }
    }
    (
        ClaimStatus::Hypothesis,
        Some(format!(
            "strength {strength} is below the seal threshold {threshold}"
        )),
    )
}

pub fn provisional_expired(date: &str) -> bool {
    let Some(d) = parse_date_days(date) else {
        return true;
    };
    d < today_days()
}

fn parse_date_days(s: &str) -> Option<i64> {
    let mut parts = s.split('-');
    let y: i64 = parts.next()?.parse().ok()?;
    let m: i64 = parts.next()?.parse().ok()?;
    let d: i64 = parts.next()?.parse().ok()?;
    if parts.next().is_some() || !(1..=12).contains(&m) || !(1..=31).contains(&d) {
        return None;
    }
    // Howard Hinnant's civil-from-days inverse.
    let y = if m <= 2 { y - 1 } else { y };
    let era = (if y >= 0 { y } else { y - 399 }) / 400;
    let yoe = y - era * 400;
    let mp = (m + 9) % 12;
    let doy = (153 * mp + 2) / 5 + d - 1;
    let doe = yoe * 365 + yoe / 4 - yoe / 100 + doy;
    Some(era * 146_097 + doe - 719_468)
}

fn date_key(s: &str) -> i64 {
    parse_date_days(s).unwrap_or(i64::MAX)
}

fn today_days() -> i64 {
    let secs = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .map(|d| d.as_secs())
        .unwrap_or(0);
    (secs / 86_400) as i64
}

/* ── lock files ─────────────────────────────────────────────────────────── */

pub fn lock_json(index: &ModelIndex, artifacts: &ArtifactSet, report: &CheckReport) -> Json {
    let mut root = BTreeMap::new();
    root.insert(
        "deg_version".into(),
        Json::Str(env!("CARGO_PKG_VERSION").into()),
    );
    root.insert("model".into(), Json::Str(index.path.clone()));
    root.insert(
        "seal_threshold".into(),
        Json::Str(report.seal_threshold.as_str().into()),
    );

    let mut arts = Vec::new();
    for a in &report.artifacts {
        let mut m = BTreeMap::new();
        m.insert("name".into(), Json::Str(a.name.clone()));
        m.insert("kind".into(), Json::Str(a.kind.clone()));
        m.insert("path".into(), Json::Str(a.path.clone()));
        m.insert("sha256".into(), Json::Str(a.actual_sha256.clone()));
        m.insert("verified".into(), Json::Bool(a.verified));
        arts.push(Json::Obj(m));
    }
    root.insert("artifacts".into(), Json::Arr(arts));

    let mut sealed = Vec::new();
    let mut hypotheses = Vec::new();
    for c in &report.claims {
        let mut m = BTreeMap::new();
        m.insert("name".into(), Json::Str(c.name.clone()));
        m.insert("kind".into(), Json::Str(c.kind.as_str().into()));
        m.insert("goal".into(), Json::Str(c.goal.clone()));
        m.insert(
            "strength".into(),
            Json::Str(
                c.strength
                    .map(|s| s.as_str().to_string())
                    .unwrap_or_else(|| "unknown".into()),
            ),
        );
        m.insert(
            "support".into(),
            Json::Arr(c.support.iter().cloned().map(Json::Str).collect()),
        );
        if let Some(until) = &c.provisional_until {
            m.insert("provisional_until".into(), Json::Str(until.clone()));
        }
        if let Some(cov) = &c.coverage {
            m.insert("covered".into(), Json::Num(cov.covered as f64));
            m.insert("target".into(), Json::Num(cov.target as f64));
            m.insert(
                "missing".into(),
                Json::Arr(cov.missing.iter().map(|id| Json::Num(*id as f64)).collect()),
            );
        }
        match c.status {
            ClaimStatus::Sealed | ClaimStatus::Provisional => {
                m.insert("status".into(), Json::Str(c.status.as_str().into()));
                sealed.push(Json::Obj(m));
            }
            _ => {
                m.insert("status".into(), Json::Str(c.status.as_str().into()));
                if let Some(note) = &c.note {
                    m.insert("note".into(), Json::Str(note.clone()));
                }
                hypotheses.push(Json::Obj(m));
            }
        }
    }
    root.insert("sealed".into(), Json::Arr(sealed));
    root.insert("hypotheses".into(), Json::Arr(hypotheses));

    let mut obls = Vec::new();
    for o in &report.obligations {
        let mut m = BTreeMap::new();
        m.insert("name".into(), Json::Str(o.name.clone()));
        m.insert("goal".into(), Json::Str(o.goal.clone()));
        m.insert("priority".into(), Json::Str(o.priority.as_str().into()));
        m.insert("blocks_seal".into(), Json::Bool(o.blocks_seal));
        m.insert("status".into(), Json::Str(o.status.as_str().into()));
        if let Some(r) = &o.resolved_by {
            m.insert("resolved_by".into(), Json::Str(r.clone()));
        }
        obls.push(Json::Obj(m));
    }
    root.insert("obligations".into(), Json::Arr(obls));

    let mut cons = Vec::new();
    for c in &report.conflicts {
        let mut m = BTreeMap::new();
        m.insert("name".into(), Json::Str(c.name.clone()));
        m.insert("left".into(), Json::Str(c.left.clone()));
        m.insert("right".into(), Json::Str(c.right.clone()));
        m.insert("resolved".into(), Json::Bool(c.resolved));
        if let Some(p) = &c.preferred {
            m.insert("preferred".into(), Json::Str(p.clone()));
        }
        if let Some(d) = &c.demoted {
            m.insert("demoted".into(), Json::Str(d.clone()));
        }
        if let Some(d) = &c.decision {
            m.insert("decision".into(), Json::Str(d.clone()));
        }
        cons.push(Json::Obj(m));
    }
    root.insert("conflicts".into(), Json::Arr(cons));

    let mut decs = Vec::new();
    for d in &report.decisions {
        let mut m = BTreeMap::new();
        m.insert("name".into(), Json::Str(d.name.clone()));
        m.insert("sha256".into(), Json::Str(d.sha256.clone()));
        m.insert("ok".into(), Json::Bool(d.ok));
        m.insert("prefer".into(), Json::Str(d.prefer.clone()));
        m.insert("over".into(), Json::Str(d.over.clone()));
        if let Some(s) = &d.signer {
            m.insert("signer".into(), Json::Str(s.clone()));
        }
        decs.push(Json::Obj(m));
    }
    root.insert("decisions".into(), Json::Arr(decs));

    let mut defs = Vec::new();
    for d in &report.definitions {
        let mut m = BTreeMap::new();
        m.insert("kind".into(), Json::Str(d.kind.clone()));
        m.insert("name".into(), Json::Str(d.name.clone()));
        m.insert("build".into(), Json::Str(d.build.clone()));
        m.insert("justified".into(), Json::Bool(d.justified));
        if let Some(j) = &d.justification {
            m.insert("justification".into(), Json::Str(j.clone()));
        }
        defs.push(Json::Obj(m));
    }
    root.insert("definitions".into(), Json::Arr(defs));

    root.insert(
        "artifact_count".into(),
        Json::Num(artifacts.items.len() as f64),
    );
    Json::Obj(root)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::evidence::{EvidenceOutcome, GroupStats};
    use crate::lexer::Span;

    fn empty_index() -> ModelIndex {
        ModelIndex {
            path: "test.dg".into(),
            builds: BTreeMap::new(),
            captures: BTreeMap::new(),
            dumps: BTreeMap::new(),
            datasets: BTreeMap::new(),
            clocks: BTreeMap::new(),
            structs: BTreeMap::new(),
            packets: BTreeMap::new(),
            fns: BTreeMap::new(),
            rngs: BTreeMap::new(),
            dists: BTreeMap::new(),
            evidence: BTreeMap::new(),
            rules: BTreeMap::new(),
            proofs: BTreeMap::new(),
            claims: BTreeMap::new(),
            conflicts: Vec::new(),
            decisions: BTreeMap::new(),
            obligations: Vec::new(),
            refutes: Vec::new(),
            ports: Vec::new(),
            pragmas: BTreeMap::new(),
            build_names: BTreeSet::new(),
            stdlib_rule_names: BTreeSet::new(),
        }
    }

    fn span() -> Span {
        Span::new(1, 1, 0)
    }

    fn mean_claim(metric: &str, value: f64, eps: f64, requires: Vec<Requirement>) -> ClaimDecl {
        ClaimDecl {
            name: "C".into(),
            head: ClaimHead::Mean {
                metric: metric.into(),
                value,
                eps,
            },
            build: "b1".into(),
            during: None,
            body: ClaimBody::Direct {
                evidence: "e".into(),
                requires,
            },
            provisional_until: Some("2099-12-31".into()),
            span: span(),
        }
    }

    fn samples_outcome(groups: BTreeMap<String, GroupStats>) -> BTreeMap<String, EvidenceOutcome> {
        let mut out = EvidenceOutcome::new("e", "samples", Strength::Observational, "ok");
        out.measured = Some(Measured::Samples { groups });
        let mut map = BTreeMap::new();
        map.insert("e".to_string(), out);
        map
    }

    fn samples_evidence_index() -> ModelIndex {
        let mut index = empty_index();
        index.evidence.insert(
            "e".into(),
            EvidenceDecl {
                name: "e".into(),
                kind: EvidenceKind::Samples {
                    dataset: "ds".into(),
                    value_col: 0,
                    group_col: Some(1),
                    delim: "csv".into(),
                },
                modifiers: Vec::new(),
                span: span(),
            },
        );
        index
    }

    #[test]
    fn mean_claim_passes_and_stays_observational() {
        let index = samples_evidence_index();
        let groups = BTreeMap::from([(
            "club".to_string(),
            GroupStats {
                n: 240,
                mean: 42.0,
                median: 42.0,
                sd: 2.0,
                ci95: 0.25,
            },
        )]);
        let claim = mean_claim(
            "club",
            42.0,
            1.2,
            vec![
                Requirement::SamplesAtLeast(200),
                Requirement::ConfidenceAtLeast(0.95),
                Requirement::Power(0.8),
                Requirement::Delta(2.0),
            ],
        );
        let result = check_direct_claim(&index, &claim, &samples_outcome(groups));
        assert_eq!(result.status, ClaimStatus::Provisional, "{:?}", result);
        assert_eq!(result.strength, Some(Strength::Observational));
    }

    #[test]
    fn mean_claim_fails_on_unknown_group() {
        let index = samples_evidence_index();
        let groups = BTreeMap::from([(
            "club".to_string(),
            GroupStats {
                n: 240,
                mean: 42.0,
                median: 42.0,
                sd: 2.0,
                ci95: 0.25,
            },
        )]);
        let claim = mean_claim("sword", 42.0, 1.2, vec![]);
        let result = check_direct_claim(&index, &claim, &samples_outcome(groups));
        assert_eq!(result.status, ClaimStatus::Failed);
        assert!(result.error.unwrap().contains("no group `sword`"));
    }

    #[test]
    fn mean_claim_fails_when_tolerance_is_tighter_than_ci() {
        let index = samples_evidence_index();
        let groups = BTreeMap::from([(
            "club".to_string(),
            GroupStats {
                n: 240,
                mean: 42.0,
                median: 42.0,
                sd: 2.0,
                ci95: 0.5,
            },
        )]);
        let claim = mean_claim("club", 42.0, 0.1, vec![]);
        let result = check_direct_claim(&index, &claim, &samples_outcome(groups));
        assert_eq!(result.status, ClaimStatus::Failed);
        assert!(result.error.unwrap().contains("tighter than"));
    }

    #[test]
    fn mean_claim_is_underpowered_hypothesis_for_tiny_delta() {
        let index = samples_evidence_index();
        let groups = BTreeMap::from([(
            "club".to_string(),
            GroupStats {
                n: 120,
                mean: 42.0,
                median: 42.0,
                sd: 2.0,
                ci95: 0.36,
            },
        )]);
        let claim = mean_claim(
            "club",
            42.0,
            2.0,
            vec![Requirement::Power(0.8), Requirement::Delta(0.001)],
        );
        let result = check_direct_claim(&index, &claim, &samples_outcome(groups));
        assert_eq!(result.status, ClaimStatus::Hypothesis);
        assert!(result.note.unwrap().contains("underpowered"));
        assert_eq!(result.strength, Some(Strength::Observational));
    }

    fn refute_decl(goal: Atom) -> RefuteDecl {
        RefuteDecl {
            name: "R".into(),
            goal,
            build: "b1".into(),
            evidence: "e".into(),
            span: span(),
        }
    }

    #[test]
    fn refute_seals_on_matching_contradicts_fact() {
        let index = empty_index();
        let refute = refute_decl(Atom {
            name: "can_predict".into(),
            args: vec![Term::Lit(Lit::Sym("conn_7".into()))],
            span: span(),
        });
        let mut out = EvidenceOutcome::new("e", "external", Strength::Observational, "ok");
        out.fact(
            "contradicts",
            vec![
                Value::sym("e"),
                Value::sym("can_predict"),
                Value::list(vec![Value::sym("conn_7")]),
            ],
        );
        let mut outcomes = BTreeMap::new();
        outcomes.insert("e".to_string(), out);
        let result = check_refute(&index, &refute, &outcomes);
        assert_eq!(result.status, ClaimStatus::Sealed, "{result:?}");
        assert_eq!(
            result.strength,
            Some(Strength::Observational),
            "external contradicts facts stay Observational"
        );
    }

    #[test]
    fn refute_fails_and_lists_available_contradicts_facts() {
        let index = empty_index();
        let refute = refute_decl(Atom {
            name: "can_predict".into(),
            args: vec![Term::Lit(Lit::Sym("conn_7".into()))],
            span: span(),
        });
        let mut out = EvidenceOutcome::new("e", "external", Strength::Observational, "ok");
        out.fact(
            "contradicts",
            vec![
                Value::sym("e"),
                Value::sym("can_predict"),
                Value::list(vec![Value::sym("conn_9")]),
            ],
        );
        let mut outcomes = BTreeMap::new();
        outcomes.insert("e".to_string(), out);
        let result = check_refute(&index, &refute, &outcomes);
        assert_eq!(result.status, ClaimStatus::Failed);
        let err = result.error.unwrap();
        assert!(
            err.contains("available: contradicts(e, can_predict, [conn_9])"),
            "{err}"
        );
    }

    #[test]
    fn refute_rng_path_is_unchanged() {
        let index = empty_index();
        let refute = refute_decl(Atom {
            name: "algo".into(),
            args: vec![
                Term::Lit(Lit::Sym("r".into())),
                Term::Lit(Lit::Sym("XORSHIFT128".into())),
            ],
            span: span(),
        });
        let mut out = EvidenceOutcome::new("e", "recovery", Strength::Deterministic, "mismatch");
        out.fact(
            "sim_fail",
            vec![Value::sym("e"), Value::sym("r"), Value::sym("XORSHIFT128")],
        );
        let mut outcomes = BTreeMap::new();
        outcomes.insert("e".to_string(), out);
        let result = check_refute(&index, &refute, &outcomes);
        assert_eq!(result.status, ClaimStatus::Sealed);
        assert_eq!(result.strength, Some(Strength::Deterministic));
    }

    #[test]
    fn dataset_id_parsing_and_missing_id_formatting() {
        assert_eq!(parse_dataset_id("42"), Some(42));
        assert_eq!(parse_dataset_id("0x2a"), Some(42));
        assert_eq!(parse_dataset_id("0X2A"), Some(42));
        assert_eq!(parse_dataset_id("nope"), None);
        assert_eq!(format_missing_ids(&[0x79]), "0x79");
        let many: Vec<i128> = (0..40).collect();
        let shown = format_missing_ids(&many);
        assert!(shown.contains("+8 more"), "{shown}");
        assert!(shown.contains("0x1f"), "{shown}");
        assert!(!shown.contains("0x20"), "{shown}");
    }
}

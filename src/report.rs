//! Human and machine renderings of a check result.

use crate::facts::{FactInfo, FactKey, FactStore};
use crate::json::Json;
use crate::kernel::{
    CheckReport, ClaimKind, ClaimResult, ClaimStatus, CoverageStats, ObligationStatus,
};
use crate::semantic::ModelIndex;
use std::collections::{BTreeMap, BTreeSet};

pub fn print_check(report: &CheckReport, model: &str, strict: bool) {
    println!("deg check {model}");
    println!(
        "  artifacts   {} ({} verified)",
        report.artifacts.len(),
        report.artifacts.iter().filter(|a| a.verified).count()
    );
    let ev_ok = report.evidence.values().filter(|e| e.ok).count();
    println!("  evidence    {} ({} ok)", report.evidence.len(), ev_ok);
    let sealed = report
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Sealed)
        .count();
    let provisional = report
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Provisional)
        .count();
    let hypotheses = report
        .claims
        .iter()
        .filter(|c| c.status == ClaimStatus::Hypothesis)
        .count();
    let failed = report
        .claims
        .iter()
        .filter(|c| matches!(c.status, ClaimStatus::Failed | ClaimStatus::Refuted))
        .count();
    println!(
        "  claims      {sealed} sealed, {provisional} provisional, {hypotheses} hypothesis, {failed} failed/refuted"
    );
    let open = report
        .obligations
        .iter()
        .filter(|o| o.status == ObligationStatus::Open)
        .count();
    println!("  obligations {open} open");
    println!(
        "  conflicts   {} ({} unresolved)",
        report.conflicts.len(),
        report.unresolved_conflicts().len()
    );
    println!(
        "  decisions   {} ({} ok)",
        report.decisions.len(),
        report.decisions.iter().filter(|d| d.ok).count()
    );
    println!("  threshold   {}", report.seal_threshold);

    if !report.errors.is_empty() {
        println!("\nerrors:");
        for e in &report.errors {
            println!("  ✗ {e}");
        }
    }
    if !report.warnings.is_empty() {
        println!("\nwarnings:");
        for w in &report.warnings {
            println!("  ! {w}");
        }
    }

    println!("\nclaims:");
    for c in &report.claims {
        let strength = c
            .strength
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "-".into());
        let marker = match c.status {
            ClaimStatus::Sealed => "✓",
            ClaimStatus::Provisional => "◐",
            ClaimStatus::Hypothesis => "?",
            ClaimStatus::Failed | ClaimStatus::Refuted => "✗",
            _ => "·",
        };
        println!(
            "  {marker} {:<28} {:<12} {:<14} {}",
            c.name,
            c.status.as_str(),
            strength,
            c.goal
        );
        if let Some(note) = &c.note {
            println!("      note: {note}");
        }
        if let Some(err) = &c.error {
            if c.status == ClaimStatus::Failed {
                println!("      error: {err}");
            }
        }
        if let Some(b) = &c.bottleneck {
            println!("      bottleneck: {b}");
        }
        if let Some(cov) = &c.coverage {
            if cov.missing.is_empty() {
                println!(
                    "      coverage: {}/{} covered; missing: none",
                    cov.covered, cov.target
                );
            } else {
                let shown: Vec<String> = cov
                    .missing
                    .iter()
                    .take(32)
                    .map(|id| format!("{id:#x}"))
                    .collect();
                let mut line = format!(
                    "      coverage: {}/{} covered; missing: {}",
                    cov.covered,
                    cov.target,
                    shown.join(", ")
                );
                if cov.missing.len() > 32 {
                    line.push_str(&format!(", +{} more", cov.missing.len() - 32));
                }
                println!("{line}");
            }
        }
    }

    if !report.obligations.is_empty() {
        println!("\nobligations:");
        for o in &report.obligations {
            println!(
                "  {:<24} {:<9} {}{}",
                o.name,
                o.status.as_str(),
                o.goal,
                if o.blocks_seal { " [blocks seal]" } else { "" }
            );
        }
    }
    if !report.conflicts.is_empty() {
        println!("\nconflicts:");
        for c in &report.conflicts {
            let source = c
                .decision
                .as_ref()
                .map(|d| format!(" via decision {d}"))
                .unwrap_or_default();
            println!(
                "  {:<24} {} vs {}{}{}",
                c.name,
                c.left,
                c.right,
                if c.resolved {
                    format!(
                        " => prefer {}{}",
                        c.preferred.clone().unwrap_or_default(),
                        c.demoted
                            .as_ref()
                            .map(|d| format!(", demoted {d}"))
                            .unwrap_or_default()
                    )
                } else {
                    " [UNRESOLVED]".into()
                },
                source
            );
        }
    }
    if !report.decisions.is_empty() {
        println!("\ndecisions:");
        for d in &report.decisions {
            let digest = if d.sha256.is_empty() {
                "(unreadable)".to_string()
            } else {
                d.sha256.clone()
            };
            println!(
                "  {:<24} prefer {} over {} sha256:{} {}{}",
                d.name,
                d.prefer,
                d.over,
                digest,
                if d.ok { "ok" } else { "MISMATCH" },
                d.signer
                    .as_ref()
                    .map(|s| format!(" (signed by {s})"))
                    .unwrap_or_default()
            );
        }
    }

    println!(
        "\n{}",
        if report.ok {
            "kernel: OK"
        } else {
            "kernel: ERRORS"
        }
    );
    if strict {
        match report.seal_ready() {
            Ok(()) => println!("seal: ready"),
            Err(errs) => {
                println!("seal: blocked ({} reason(s))", errs.len());
                for e in errs {
                    println!("  - {e}");
                }
            }
        }
    }
}

pub fn report_json(report: &CheckReport, index: &ModelIndex) -> Json {
    let mut root = BTreeMap::new();
    root.insert("model".into(), Json::Str(index.path.clone()));
    root.insert("ok".into(), Json::Bool(report.ok));
    root.insert(
        "seal_threshold".into(),
        Json::Str(report.seal_threshold.as_str().into()),
    );
    root.insert(
        "errors".into(),
        Json::Arr(report.errors.iter().cloned().map(Json::Str).collect()),
    );
    root.insert(
        "warnings".into(),
        Json::Arr(report.warnings.iter().cloned().map(Json::Str).collect()),
    );

    let arts = report
        .artifacts
        .iter()
        .map(|a| {
            let mut m = BTreeMap::new();
            m.insert("name".into(), Json::Str(a.name.clone()));
            m.insert("kind".into(), Json::Str(a.kind.clone()));
            m.insert("path".into(), Json::Str(a.path.clone()));
            m.insert("sha256".into(), Json::Str(a.actual_sha256.clone()));
            m.insert("verified".into(), Json::Bool(a.verified));
            if let Some(e) = &a.error {
                m.insert("error".into(), Json::Str(e.clone()));
            }
            Json::Obj(m)
        })
        .collect();
    root.insert("artifacts".into(), Json::Arr(arts));

    let evs = report
        .evidence
        .values()
        .map(|e| {
            let mut m = BTreeMap::new();
            m.insert("name".into(), Json::Str(e.name.clone()));
            m.insert("kind".into(), Json::Str(e.kind.clone()));
            m.insert("ok".into(), Json::Bool(e.ok));
            m.insert("strength".into(), Json::Str(e.strength.as_str().into()));
            m.insert("summary".into(), Json::Str(e.summary.clone()));
            if let Some(err) = &e.error {
                m.insert("error".into(), Json::Str(err.clone()));
            }
            let details = e
                .details
                .iter()
                .map(|(k, v)| {
                    let mut d = BTreeMap::new();
                    d.insert("key".into(), Json::Str(k.clone()));
                    d.insert("value".into(), Json::Str(v.clone()));
                    Json::Obj(d)
                })
                .collect();
            m.insert("details".into(), Json::Arr(details));
            Json::Obj(m)
        })
        .collect();
    root.insert("evidence".into(), Json::Arr(evs));

    let claims = report
        .claims
        .iter()
        .map(|c| {
            let mut m = BTreeMap::new();
            m.insert("name".into(), Json::Str(c.name.clone()));
            m.insert("kind".into(), Json::Str(c.kind.as_str().into()));
            m.insert("goal".into(), Json::Str(c.goal.clone()));
            m.insert("status".into(), Json::Str(c.status.as_str().into()));
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
            if let Some(n) = &c.note {
                m.insert("note".into(), Json::Str(n.clone()));
            }
            if let Some(e) = &c.error {
                m.insert("error".into(), Json::Str(e.clone()));
            }
            if let Some(b) = &c.bottleneck {
                m.insert("bottleneck".into(), Json::Str(b.clone()));
            }
            if !c.premises.is_empty() {
                m.insert(
                    "premises".into(),
                    Json::Arr(c.premises.iter().cloned().map(Json::Str).collect()),
                );
            }
            if let Some(u) = &c.provisional_until {
                m.insert("provisional_until".into(), Json::Str(u.clone()));
            }
            if let Some(meas) = &c.measured {
                m.insert("measured".into(), Json::Str(meas.clone()));
            }
            if let Some(cov) = &c.coverage {
                m.insert("covered".into(), Json::Num(cov.covered as f64));
                m.insert("target".into(), Json::Num(cov.target as f64));
                m.insert(
                    "missing".into(),
                    Json::Arr(
                        cov.missing
                            .iter()
                            .map(|id| Json::Str(id.to_string()))
                            .collect(),
                    ),
                );
            }
            Json::Obj(m)
        })
        .collect();
    root.insert("claims".into(), Json::Arr(claims));

    let obls = report
        .obligations
        .iter()
        .map(|o| {
            let mut m = BTreeMap::new();
            m.insert("name".into(), Json::Str(o.name.clone()));
            m.insert("goal".into(), Json::Str(o.goal.clone()));
            m.insert("priority".into(), Json::Str(o.priority.as_str().into()));
            m.insert("status".into(), Json::Str(o.status.as_str().into()));
            m.insert("blocks_seal".into(), Json::Bool(o.blocks_seal));
            if let Some(r) = &o.resolved_by {
                m.insert("resolved_by".into(), Json::Str(r.clone()));
            }
            Json::Obj(m)
        })
        .collect();
    root.insert("obligations".into(), Json::Arr(obls));

    let conflicts = report
        .conflicts
        .iter()
        .map(|c| {
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
            if let Some(r) = &c.reason {
                m.insert("reason".into(), Json::Str(r.clone()));
            }
            if let Some(d) = &c.decision {
                m.insert("decision".into(), Json::Str(d.clone()));
            }
            Json::Obj(m)
        })
        .collect();
    root.insert("conflicts".into(), Json::Arr(conflicts));

    let decisions = report
        .decisions
        .iter()
        .map(|d| {
            let mut m = BTreeMap::new();
            m.insert("name".into(), Json::Str(d.name.clone()));
            m.insert("sha256".into(), Json::Str(d.sha256.clone()));
            m.insert("ok".into(), Json::Bool(d.ok));
            m.insert("prefer".into(), Json::Str(d.prefer.clone()));
            m.insert("over".into(), Json::Str(d.over.clone()));
            if let Some(s) = &d.signer {
                m.insert("signer".into(), Json::Str(s.clone()));
            }
            Json::Obj(m)
        })
        .collect();
    root.insert("decisions".into(), Json::Arr(decisions));

    let defs = report
        .definitions
        .iter()
        .map(|d| {
            let mut m = BTreeMap::new();
            m.insert("kind".into(), Json::Str(d.kind.clone()));
            m.insert("name".into(), Json::Str(d.name.clone()));
            m.insert("build".into(), Json::Str(d.build.clone()));
            m.insert("justified".into(), Json::Bool(d.justified));
            if let Some(j) = &d.justification {
                m.insert("justification".into(), Json::Str(j.clone()));
            }
            Json::Obj(m)
        })
        .collect();
    root.insert("definitions".into(), Json::Arr(defs));

    Json::Obj(root)
}

pub fn markdown(report: &CheckReport, index: &ModelIndex) -> String {
    let mut out = String::new();
    out.push_str(&format!("# DeG report — `{}`\n\n", index.path));
    out.push_str(&format!(
        "Seal threshold: **{}**. Kernel: **{}**.\n\n",
        report.seal_threshold,
        if report.ok { "OK" } else { "ERRORS" }
    ));

    out.push_str("## Artifacts\n\n| Artifact | Kind | SHA-256 | Verified |\n|---|---|---|---|\n");
    for a in &report.artifacts {
        out.push_str(&format!(
            "| `{}` | {} | `{}` | {} |\n",
            a.name,
            a.kind,
            a.actual_sha256,
            if a.verified { "✓" } else { "✗" }
        ));
    }
    out.push('\n');

    out.push_str("## Evidence\n\n| Evidence | Kind | Strength | Result |\n|---|---|---|---|\n");
    for e in report.evidence.values() {
        out.push_str(&format!(
            "| `{}` | {} | {} | {} |\n",
            e.name,
            e.kind,
            e.strength,
            if e.ok {
                e.summary.clone()
            } else {
                format!("FAILED: {}", e.error.clone().unwrap_or_default())
            }
        ));
    }
    out.push('\n');

    out.push_str("## Claims\n\n| Claim | Status | Strength | Goal | Support / bottleneck |\n|---|---|---|---|---|\n");
    for c in &report.claims {
        let support = if let Some(b) = &c.bottleneck {
            format!("bottleneck `{b}`")
        } else if !c.premises.is_empty() {
            c.premises
                .iter()
                .map(|p| format!("`{p}`"))
                .collect::<Vec<_>>()
                .join(", ")
        } else {
            c.support
                .iter()
                .map(|s| format!("`{s}`"))
                .collect::<Vec<_>>()
                .join(", ")
        };
        out.push_str(&format!(
            "| `{}` | {} | {} | `{}` | {} |\n",
            c.name,
            c.status.as_str(),
            c.strength
                .map(|s| s.as_str().to_string())
                .unwrap_or_else(|| "-".into()),
            c.goal.replace('|', "\\|"),
            support
        ));
        if let Some(note) = &c.note {
            out.push_str(&format!("| | | | *{}* | |\n", note.replace('|', "\\|")));
        }
        if let Some(cov) = &c.coverage {
            let missing = if cov.missing.is_empty() {
                "none".to_string()
            } else {
                let shown: Vec<String> = cov
                    .missing
                    .iter()
                    .take(32)
                    .map(|id| format!("{id:#x}"))
                    .collect();
                let mut s = shown.join(", ");
                if cov.missing.len() > 32 {
                    s.push_str(&format!(", +{} more", cov.missing.len() - 32));
                }
                s
            };
            out.push_str(&format!(
                "| | | | *coverage: {}/{} covered; missing: {}* | |\n",
                cov.covered,
                cov.target,
                missing.replace('|', "\\|")
            ));
        }
    }
    out.push('\n');

    if !report.conflicts.is_empty() {
        out.push_str("## Conflicts\n\n");
        for c in &report.conflicts {
            out.push_str(&format!(
                "- **{}**: `{}` vs `{}` — {}{}\n",
                c.name,
                c.left,
                c.right,
                if c.resolved {
                    format!(
                        "prefer `{}`{}{}",
                        c.preferred.clone().unwrap_or_default(),
                        c.reason
                            .as_ref()
                            .map(|r| format!("; {r}"))
                            .unwrap_or_default(),
                        c.demoted
                            .as_ref()
                            .map(|d| format!("; demoted `{d}`"))
                            .unwrap_or_default()
                    )
                } else {
                    "UNRESOLVED".into()
                },
                c.decision
                    .as_ref()
                    .map(|d| format!(" (via decision `{d}`)"))
                    .unwrap_or_default()
            ));
        }
        out.push('\n');
    }

    if !report.decisions.is_empty() {
        out.push_str("## Decisions\n\n| Decision | Prefers | Over | SHA-256 | Verified |\n|---|---|---|---|---|\n");
        for d in &report.decisions {
            out.push_str(&format!(
                "| `{}` | `{}` | `{}` | `{}` | {} |\n",
                d.name,
                d.prefer,
                d.over,
                d.sha256,
                if d.ok { "✓" } else { "✗" }
            ));
        }
        out.push('\n');
    }

    out.push_str("## Obligations\n\n");
    if report.obligations.is_empty() {
        out.push_str("_None._\n\n");
    } else {
        for o in &report.obligations {
            out.push_str(&format!(
                "- `{}` **{}** — {} (priority {}, {})\n",
                o.name,
                o.goal,
                o.status.as_str(),
                o.priority.as_str(),
                if o.blocks_seal {
                    "blocks seal"
                } else {
                    "non-blocking"
                }
            ));
        }
        out.push('\n');
    }

    out.push_str("## Definitions (model assumptions)\n\n| Definition | Kind | Build | Justified |\n|---|---|---|---|\n");
    for d in &report.definitions {
        out.push_str(&format!(
            "| `{}` | {} | `{}` | {}{} |\n",
            d.name,
            d.kind,
            d.build,
            if d.justified { "✓" } else { "—" },
            d.justification
                .as_ref()
                .map(|j| format!(" (`{j}`)"))
                .unwrap_or_default()
        ));
    }
    out.push('\n');

    if !report.errors.is_empty() {
        out.push_str("## Errors\n\n");
        for e in &report.errors {
            out.push_str(&format!("- {e}\n"));
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
    out.push_str("---\n\n_Generated by DeG. Strength is computed, never asserted._\n");
    out
}

pub fn explain(report: &CheckReport, claim_name: &str) {
    let Some(claim) = report.claim(claim_name) else {
        eprintln!("no claim named `{claim_name}`");
        return;
    };
    println!("claim {}", claim.name);
    println!("  goal        {}", claim.goal);
    println!("  kind        {}", claim.kind.as_str());
    println!("  status      {}", claim.status.as_str());
    println!(
        "  strength    {}",
        claim
            .strength
            .map(|s| s.as_str().to_string())
            .unwrap_or_else(|| "unknown".into())
    );
    if let Some(b) = &claim.bottleneck {
        println!("  bottleneck  {b}");
    }
    if let Some(note) = &claim.note {
        println!("  note        {note}");
    }
    if let Some(err) = &claim.error {
        println!("  error       {err}");
    }
    if let Some(meas) = &claim.measured {
        println!("  measured    {meas}");
    }
    println!("  support     {}", {
        let mut s: Vec<String> = claim.support.iter().cloned().collect();
        s.sort();
        if s.is_empty() {
            "-".into()
        } else {
            s.join(", ")
        }
    });
    if !claim.premises.is_empty() {
        println!("  premises    {}", claim.premises.join(", "));
    }

    if let Some(store) = report.proof_stores.get(&claim.name) {
        if let Some(key) = &claim.goal_key {
            println!("\nderivation:");
            print_fact(store, key, 2, &mut Vec::new());
        }
        println!("\nevidence:");
        for ev in &claim.support {
            if let Some(o) = report.evidence.get(ev) {
                println!("  {} ({}): {} [{}]", o.name, o.kind, o.summary, o.strength);
                for (k, v) in &o.details {
                    println!("      {k}: {v}");
                }
                if let Some(err) = &o.error {
                    println!("      error: {err}");
                }
            }
        }
    }
}

fn print_fact(store: &FactStore, key: &FactKey, indent: usize, seen: &mut Vec<FactKey>) {
    let pad = " ".repeat(indent);
    if seen.contains(key) {
        println!("{pad}{} (cycle)", key.display());
        return;
    }
    seen.push(key.clone());
    match store.get(key) {
        None => println!("{pad}{} (not in store)", key.display()),
        Some(info) => {
            let origin = match &info.origin {
                crate::facts::FactOrigin::Definition => "definition".to_string(),
                crate::facts::FactOrigin::Evidence(e) => format!("evidence {e}"),
                crate::facts::FactOrigin::Rule(r) => format!("rule {r}"),
            };
            println!("{pad}{}  [{} via {}]", key.display(), info.strength, origin);
            for p in &info.parents {
                print_fact(store, p, indent + 4, seen);
            }
        }
    }
    seen.pop();
}

// ── Mermaid flowchart rendering ───────────────────────────────────────────

/// Render a claim's explanation as a GitHub-renderable Mermaid flowchart
/// (fenced `mermaid` block). Returns `None` when the claim does not exist.
///
/// * relational proofs: one node per fact of the derivation tree, edges from
///   each fact to its premises labeled with the premise's origin (`rule …`,
///   `evidence …`, `definition`); the goal node carries its own origin;
/// * derived claims: the claim plus one node per premise, edges labeled with
///   the premise name, the bottleneck in the claim node;
/// * certificate claims (period/uniform/mean/coverage): a single node with the
///   measured/coverage text;
/// * failed claims without a derivation: a single node with status and error.
pub fn mermaid(report: &CheckReport, claim_name: &str) -> Option<String> {
    let claim = report.claim(claim_name)?;
    let mut out = String::new();
    out.push_str("```mermaid\nflowchart TD\n");
    match claim.kind {
        ClaimKind::Proof => mermaid_proof(report, claim, &mut out),
        ClaimKind::Derived => mermaid_derived(report, claim, &mut out),
        ClaimKind::Period | ClaimKind::Uniform | ClaimKind::Mean | ClaimKind::Coverage => {
            mermaid_direct(claim, &mut out)
        }
        ClaimKind::Refute => mermaid_single(claim, &mut out),
    }
    out.push_str("```\n");
    Some(out)
}

/// A fact tree in a relational proof: the goal node at the top, an edge from
/// each fact to each premise. Every edge is labeled with the *premise's*
/// origin — `rule <name>` for derived premises, `evidence <name>` for
/// evidence leaves, `definition` for definition leaves — and the goal node
/// carries its own origin on a third line.
fn mermaid_proof(report: &CheckReport, claim: &ClaimResult, out: &mut String) {
    let derivable = report
        .proof_stores
        .get(&claim.name)
        .zip(claim.goal_key.as_ref())
        .is_some_and(|(store, key)| store.get(key).is_some());
    if !derivable {
        mermaid_single(claim, out);
        return;
    }
    let mut em = Emitter::new();
    let store = report.proof_stores.get(&claim.name).expect("checked above");
    let key = claim.goal_key.as_ref().expect("checked above");
    let info = store.get(key).expect("checked above");
    let id = em.id();
    em.node(
        &id,
        &format!(
            "{}<br/>{}<br/>{}",
            key.display(),
            info.strength.as_str(),
            origin_label(info)
        ),
    );
    em.ids.insert(key.clone(), id.clone());
    let mut parents = info.parents.clone();
    parents.sort();
    for p in &parents {
        em.fact(store, p, Some(&id));
    }
    out.push_str(&em.out);
}

fn mermaid_derived(report: &CheckReport, claim: &ClaimResult, out: &mut String) {
    let mut em = Emitter::new();
    let id = em.id();
    let mut text = format!("{}<br/>{}", claim.goal, strength_text(claim));
    if let Some(b) = &claim.bottleneck {
        text.push_str(&format!("<br/>bottleneck {b}"));
    }
    em.node(&id, &text);
    for premise in &claim.premises {
        let pid = em.id();
        let ptext = match report.claim(premise) {
            Some(p) => format!("{}<br/>{}", p.goal, strength_text(p)),
            None => format!("{premise}<br/>unknown"),
        };
        em.node(&pid, &ptext);
        em.edge(&id, &pid, premise);
    }
    out.push_str(&em.out);
}

fn mermaid_direct(claim: &ClaimResult, out: &mut String) {
    let mut em = Emitter::new();
    let id = em.id();
    let mut text = format!("{}<br/>{}", claim.goal, strength_text(claim));
    if let Some(m) = &claim.measured {
        text.push_str(&format!("<br/>{m}"));
    }
    if let Some(c) = &claim.coverage {
        text.push_str(&format!("<br/>{}", coverage_text(c)));
    }
    em.node(&id, &text);
    out.push_str(&em.out);
}

/// Failed claims without a derivation: the status and the (truncated) error.
fn mermaid_single(claim: &ClaimResult, out: &mut String) {
    let mut em = Emitter::new();
    let id = em.id();
    let mut text = format!("{}<br/>{}", claim.goal, strength_text(claim));
    if let Some(err) = &claim.error {
        text.push_str(&format!("<br/>{}", truncate(err, 120)));
    }
    em.node(&id, &text);
    out.push_str(&em.out);
}

fn strength_text(claim: &ClaimResult) -> String {
    let status = claim.status.as_str();
    match claim.strength {
        Some(s) => format!("{status} · {s}"),
        None => status.to_string(),
    }
}

fn coverage_text(cov: &CoverageStats) -> String {
    if cov.missing.is_empty() {
        format!(
            "coverage: {}/{} covered; missing: none",
            cov.covered, cov.target
        )
    } else {
        let shown: Vec<String> = cov
            .missing
            .iter()
            .take(32)
            .map(|id| format!("{id:#x}"))
            .collect();
        let mut line = format!(
            "coverage: {}/{} covered; missing: {}",
            cov.covered,
            cov.target,
            shown.join(", ")
        );
        if cov.missing.len() > 32 {
            line.push_str(&format!(", +{} more", cov.missing.len() - 32));
        }
        line
    }
}

/// Truncate to `limit` characters for node text; mark the cut honestly.
fn truncate(s: &str, limit: usize) -> String {
    if s.chars().count() <= limit {
        s.to_string()
    } else {
        let cut: String = s.chars().take(limit).collect();
        format!("{cut}…")
    }
}

/// Sanitize node/label text for Mermaid: quotes and backticks would break the
/// quoted node syntax, so they are replaced.
fn mermaid_escape(s: &str) -> String {
    s.replace(['"', '`'], "'")
}

fn origin_label(info: &FactInfo) -> String {
    match &info.origin {
        crate::facts::FactOrigin::Definition => "definition".to_string(),
        crate::facts::FactOrigin::Evidence(e) => format!("evidence {e}"),
        crate::facts::FactOrigin::Rule(r) => format!("rule {r}"),
    }
}

/// Accumulates mermaid nodes and edges. Node ids are `n0`, `n1`, … assigned in
/// traversal order, so the output is deterministic as long as the traversal is
/// (parents are sorted before recursing).
struct Emitter {
    out: String,
    next: usize,
    ids: BTreeMap<FactKey, String>,
    edges: BTreeSet<(String, String)>,
}

impl Emitter {
    fn new() -> Emitter {
        Emitter {
            out: String::new(),
            next: 0,
            ids: BTreeMap::new(),
            edges: BTreeSet::new(),
        }
    }

    fn id(&mut self) -> String {
        let id = format!("n{}", self.next);
        self.next += 1;
        id
    }

    fn node(&mut self, id: &str, text: &str) {
        self.out
            .push_str(&format!("    {id}[\"{}\"]\n", mermaid_escape(text)));
    }

    fn edge(&mut self, from: &str, to: &str, label: &str) {
        if self.edges.insert((from.to_string(), to.to_string())) {
            self.out
                .push_str(&format!("    {from} -->|{}| {to}\n", mermaid_escape(label)));
        }
    }

    /// Emit the fact and its premises, pre-order. The premise list is sorted
    /// so the ids and edges are deterministic. Cycles are guarded by the id
    /// map: a revisited fact already has a node id and is not re-expanded
    /// (the text derivation prints `(cycle)` for the same case).
    fn fact(&mut self, store: &FactStore, key: &FactKey, from: Option<&str>) -> String {
        let fresh = !self.ids.contains_key(key);
        let id = if fresh {
            let id = self.id();
            match store.get(key) {
                None => self.node(&id, &format!("{}<br/>(not in store)", key.display())),
                Some(info) => self.node(
                    &id,
                    &format!("{}<br/>{}", key.display(), info.strength.as_str()),
                ),
            }
            self.ids.insert(key.clone(), id.clone());
            id
        } else {
            self.ids.get(key).expect("contains_key checked").clone()
        };
        if let (Some(from_id), Some(info)) = (from, store.get(key)) {
            self.edge(from_id, &id, &origin_label(info));
        }
        if fresh {
            if let Some(info) = store.get(key) {
                let mut parents = info.parents.clone();
                parents.sort();
                for p in &parents {
                    self.fact(store, p, Some(&id));
                }
            }
        }
        id
    }
}

pub fn artifacts_json(report: &CheckReport) -> Json {
    Json::Arr(
        report
            .artifacts
            .iter()
            .map(|a| {
                let mut m = BTreeMap::new();
                m.insert("name".into(), Json::Str(a.name.clone()));
                m.insert("kind".into(), Json::Str(a.kind.clone()));
                m.insert("path".into(), Json::Str(a.path.clone()));
                m.insert("sha256".into(), Json::Str(a.actual_sha256.clone()));
                m.insert("verified".into(), Json::Bool(a.verified));
                Json::Obj(m)
            })
            .collect(),
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts;
    use crate::parser::parse_model;
    use crate::strength::Strength;
    use std::collections::BTreeSet;

    fn rule(src: &str) -> crate::ast::RuleDecl {
        let m = parse_model("<test>", src).unwrap();
        match m.items.into_iter().next().unwrap() {
            crate::ast::Item::Rule(r) => r,
            _ => panic!("not a rule"),
        }
    }

    /// A proof claim whose fact store derives `goal` from two parents: an
    /// evidence fact (via a rule) and a definition fact.
    fn proof_report() -> CheckReport {
        let r_root = rule("rule reader_rule: goal() if mid() and def();");
        let r_mid = rule("rule helper_rule: mid() if base();");
        let mut store = FactStore::new();
        store.insert_definition("def", vec![]);
        store.insert_evidence("base", vec![], Strength::Deterministic, "e_shape");
        facts::fixpoint(&mut store, &facts::compile_rules(&[r_root, r_mid]).unwrap()).unwrap();
        let key = facts::ground_key(&crate::ast::Atom {
            name: "goal".into(),
            args: vec![],
            span: crate::lexer::Span::new(1, 1, 0),
        })
        .unwrap();
        let claim = ClaimResult {
            name: "P".into(),
            kind: ClaimKind::Proof,
            build: "b1".into(),
            goal: key.display(),
            goal_key: Some(key.clone()),
            status: ClaimStatus::Sealed,
            strength: Some(Strength::Deterministic),
            support: BTreeSet::from(["e_shape".to_string()]),
            premises: vec![],
            bottleneck: None,
            note: None,
            error: None,
            provisional_until: None,
            conflict_with: vec![],
            refuted_by: None,
            measured: None,
            coverage: None,
        };
        CheckReport {
            ok: true,
            errors: vec![],
            warnings: vec![],
            artifacts: vec![],
            evidence: BTreeMap::new(),
            claims: vec![claim],
            obligations: vec![],
            conflicts: vec![],
            decisions: vec![],
            definitions: vec![],
            proof_stores: BTreeMap::from([("P".to_string(), store)]),
            seal_threshold: Strength::Deterministic,
        }
    }

    #[test]
    fn mermaid_proof_tree_has_rule_and_evidence_edges() {
        let report = proof_report();
        let m = mermaid(&report, "P").expect("claim exists");
        assert!(m.contains("flowchart TD"), "{m}");
        // The goal node carries its own rule; every premise edge is labeled
        // with the premise's origin.
        assert!(
            m.contains("goal()<br/>deterministic<br/>rule reader_rule"),
            "{m}"
        );
        assert!(m.contains("-->|rule helper_rule|"), "{m}");
        assert!(m.contains("-->|evidence e_shape|"), "{m}");
        assert!(m.contains("-->|definition|"), "{m}");
        assert!(m.contains("base()<br/>deterministic"), "{m}");
        assert!(m.contains("def()<br/>exact"), "{m}");
    }

    #[test]
    fn mermaid_proof_tree_node_ids_are_traversal_ordered() {
        let report = proof_report();
        let m = mermaid(&report, "P").expect("claim exists");
        // Root is n0; the two premises follow in sorted order, and the only
        // grandparent (base) comes last.
        assert!(
            m.contains("    n0[\"goal()<br/>deterministic<br/>rule reader_rule\"]"),
            "{m}"
        );
        assert!(m.contains("    n1[\"def()<br/>exact\"]"), "{m}");
        assert!(m.contains("    n2[\"mid()<br/>deterministic\"]"), "{m}");
        assert!(m.contains("    n3[\"base()<br/>deterministic\"]"), "{m}");
        assert!(m.contains("    n0 -->|definition| n1"), "{m}");
        assert!(m.contains("    n0 -->|rule helper_rule| n2"), "{m}");
        assert!(m.contains("    n2 -->|evidence e_shape| n3"), "{m}");
    }

    #[test]
    fn mermaid_derived_claim_lists_premises_and_bottleneck() {
        let prem = ClaimResult {
            name: "P_observable".into(),
            kind: ClaimKind::Proof,
            build: "b1".into(),
            goal: "outputs_observable(conn_7, c1)".into(),
            goal_key: None,
            status: ClaimStatus::Hypothesis,
            strength: Some(Strength::Observational),
            support: BTreeSet::new(),
            premises: vec![],
            bottleneck: None,
            note: None,
            error: None,
            provisional_until: None,
            conflict_with: vec![],
            refuted_by: None,
            measured: None,
            coverage: None,
        };
        let derived = ClaimResult {
            name: "C_predictable".into(),
            kind: ClaimKind::Derived,
            build: "b1".into(),
            goal: "predictable(srv_rng, conn_7, 32)".into(),
            goal_key: None,
            status: ClaimStatus::Hypothesis,
            strength: Some(Strength::Observational),
            support: BTreeSet::new(),
            premises: vec!["P_observable".to_string()],
            bottleneck: Some("P_observable".to_string()),
            note: Some("at least one premise is only a hypothesis".into()),
            error: None,
            provisional_until: None,
            conflict_with: vec![],
            refuted_by: None,
            measured: None,
            coverage: None,
        };
        let report = CheckReport {
            ok: true,
            errors: vec![],
            warnings: vec![],
            artifacts: vec![],
            evidence: BTreeMap::new(),
            claims: vec![prem, derived],
            obligations: vec![],
            conflicts: vec![],
            decisions: vec![],
            definitions: vec![],
            proof_stores: BTreeMap::new(),
            seal_threshold: Strength::Deterministic,
        };
        let m = mermaid(&report, "C_predictable").expect("claim exists");
        assert!(m.contains("flowchart TD"), "{m}");
        assert!(m.contains("bottleneck P_observable"), "{m}");
        assert!(m.contains("-->|P_observable|"), "{m}");
        assert!(m.contains("outputs_observable(conn_7, c1)<br/>"), "{m}");
    }

    #[test]
    fn mermaid_failed_claim_truncates_the_error() {
        let failed = ClaimResult {
            name: "P_bad".into(),
            kind: ClaimKind::Proof,
            build: "b1".into(),
            goal: "reads(read_position, Vec3.z)".into(),
            goal_key: None,
            status: ClaimStatus::Failed,
            strength: None,
            support: BTreeSet::new(),
            premises: vec![],
            bottleneck: None,
            note: None,
            error: Some(format!(
                "could not derive {}; {}",
                "reads(read_position, Vec3.z)",
                "x".repeat(200)
            )),
            provisional_until: None,
            conflict_with: vec![],
            refuted_by: None,
            measured: None,
            coverage: None,
        };
        let report = CheckReport {
            ok: false,
            errors: vec!["claim P_bad failed: …".into()],
            warnings: vec![],
            artifacts: vec![],
            evidence: BTreeMap::new(),
            claims: vec![failed],
            obligations: vec![],
            conflicts: vec![],
            decisions: vec![],
            definitions: vec![],
            proof_stores: BTreeMap::new(),
            seal_threshold: Strength::Deterministic,
        };
        let m = mermaid(&report, "P_bad").expect("claim exists");
        assert!(m.contains("flowchart TD"), "{m}");
        assert!(m.contains("<br/>failed"), "{m}");
        assert!(m.contains("…"), "{m}");
        // No edges for a single failed node.
        assert!(!m.contains("-->"), "{m}");
    }

    #[test]
    fn mermaid_direct_claim_shows_measured_text() {
        let direct = ClaimResult {
            name: "C_tick".into(),
            kind: ClaimKind::Period,
            build: "b1".into(),
            goal: "period(srv_tick, stream:0x01f4) ~ 15625us +- 50us".into(),
            goal_key: None,
            status: ClaimStatus::Provisional,
            strength: Some(Strength::Observational),
            support: BTreeSet::new(),
            premises: vec![],
            bottleneck: None,
            note: Some("provisional until 2099-12-31".into()),
            error: None,
            provisional_until: Some("2099-12-31".into()),
            conflict_with: vec![],
            refuted_by: None,
            measured: Some("period=15625.0us ci95=5.2us coverage=60000000us samples=9000".into()),
            coverage: None,
        };
        let report = CheckReport {
            ok: true,
            errors: vec![],
            warnings: vec![],
            artifacts: vec![],
            evidence: BTreeMap::new(),
            claims: vec![direct],
            obligations: vec![],
            conflicts: vec![],
            decisions: vec![],
            definitions: vec![],
            proof_stores: BTreeMap::new(),
            seal_threshold: Strength::Deterministic,
        };
        let m = mermaid(&report, "C_tick").expect("claim exists");
        assert!(m.contains("flowchart TD"), "{m}");
        assert!(m.contains("period=15625.0us"), "{m}");
        assert!(m.contains("provisional · observational"), "{m}");
        assert!(!m.contains("-->"), "{m}");
    }

    #[test]
    fn mermaid_unknown_claim_is_none() {
        let report = proof_report();
        assert!(mermaid(&report, "nope").is_none());
    }

    #[test]
    fn mermaid_escape_replaces_quotes_and_backticks() {
        let s = mermaid_escape("a \"quoted\" `tick` text");
        assert_eq!(s, "a 'quoted' 'tick' text");
    }

    #[test]
    fn truncate_marks_the_cut() {
        assert_eq!(truncate("short", 120), "short");
        let long = "x".repeat(200);
        let t = truncate(&long, 120);
        assert_eq!(t.chars().count(), 121);
        assert!(t.ends_with('…'));
    }

    #[test]
    fn strength_text_combines_status_and_strength() {
        let c = ClaimResult {
            name: "P".into(),
            kind: ClaimKind::Proof,
            build: "b1".into(),
            goal: "g()".into(),
            goal_key: None,
            status: ClaimStatus::Sealed,
            strength: Some(Strength::Deterministic),
            support: BTreeSet::new(),
            premises: vec![],
            bottleneck: None,
            note: None,
            error: None,
            provisional_until: None,
            conflict_with: vec![],
            refuted_by: None,
            measured: None,
            coverage: None,
        };
        assert_eq!(strength_text(&c), "sealed · deterministic");
    }
}

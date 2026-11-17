//! Human and machine renderings of a check result.

use crate::facts::{FactKey, FactStore};
use crate::json::Json;
use crate::kernel::{CheckReport, ClaimStatus, ObligationStatus};
use crate::semantic::ModelIndex;
use std::collections::BTreeMap;

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
            println!(
                "  {:<24} prefer {} over {} sha256:{} {}{}",
                d.name,
                d.prefer,
                d.over,
                d.sha256,
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
                    Json::Arr(cov.missing.iter().map(|id| Json::Num(*id as f64)).collect()),
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

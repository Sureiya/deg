//! Evidence evaluation.
//!
//! Every fact in a proof comes from one of these evaluators. The evaluator
//! either re-checks an artifact itself (scan, bytes, decode, constants, modulo,
//! recovery, rate, sample) or admits an external certificate at a capped
//! strength (external, absence). External certificates are never promoted to
//! `Deterministic`: the kernel did not perform the analysis.

use crate::artifact::ArtifactSet;
use crate::ast::{EvidenceDecl, EvidenceKind, RngAlgo, Target};
use crate::json::Json;
use crate::pcap;
use crate::prng::{self, Projection};
use crate::semantic::ModelIndex;
use crate::stats;
use crate::strength::Strength;
use crate::value::{parse_hex_bytes, Value};
use crate::x86;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::Path;

#[derive(Debug, Clone)]
pub enum Measured {
    Rate {
        period_us: f64,
        ci_us: f64,
        coverage_us: u64,
        samples: u64,
        stationary: bool,
        opcode: u16,
        clock: Option<String>,
    },
    Sample {
        counts: Vec<u64>,
        n: u64,
        coverage_us: u64,
        opcode: u16,
        field: usize,
        width: usize,
    },
    Recovery {
        algo: String,
        matched: usize,
        horizon: usize,
        index: u64,
        failed_at: Option<usize>,
        projection: String,
    },
    Samples {
        groups: BTreeMap<String, GroupStats>,
    },
}

/// Per-group descriptive statistics of a `samples` dataset.
#[derive(Debug, Clone)]
pub struct GroupStats {
    pub n: u64,
    pub mean: f64,
    pub median: f64,
    pub sd: f64,
    pub ci95: f64,
}

#[derive(Debug, Clone)]
pub struct EvidenceOutcome {
    pub name: String,
    pub kind: String,
    pub ok: bool,
    pub strength: Strength,
    pub facts: Vec<(String, Vec<Value>)>,
    pub summary: String,
    pub details: Vec<(String, String)>,
    pub error: Option<String>,
    pub measured: Option<Measured>,
}

impl EvidenceOutcome {
    fn failed(name: &str, kind: &str, msg: impl Into<String>) -> EvidenceOutcome {
        EvidenceOutcome {
            name: name.to_string(),
            kind: kind.to_string(),
            ok: false,
            strength: Strength::Speculative,
            facts: Vec::new(),
            summary: "failed".into(),
            details: Vec::new(),
            error: Some(msg.into()),
            measured: None,
        }
    }

    pub fn new(
        name: &str,
        kind: &str,
        strength: Strength,
        summary: impl Into<String>,
    ) -> EvidenceOutcome {
        EvidenceOutcome {
            name: name.to_string(),
            kind: kind.to_string(),
            ok: true,
            strength,
            facts: Vec::new(),
            summary: summary.into(),
            details: Vec::new(),
            error: None,
            measured: None,
        }
    }

    pub fn fact(&mut self, rel: &str, args: Vec<Value>) {
        self.facts.push((rel.to_string(), args));
    }

    pub fn detail(&mut self, key: &str, value: impl Into<String>) {
        self.details.push((key.to_string(), value.into()));
    }
}

pub struct EvalCtx<'a> {
    pub index: &'a ModelIndex,
    pub artifacts: &'a ArtifactSet,
}

pub fn evaluate_all(ctx: &EvalCtx<'_>) -> BTreeMap<String, EvidenceOutcome> {
    let mut out = BTreeMap::new();
    for (name, decl) in &ctx.index.evidence {
        let outcome = evaluate(ctx, decl);
        out.insert(name.clone(), outcome);
    }
    out
}

pub fn evaluate(ctx: &EvalCtx<'_>, decl: &EvidenceDecl) -> EvidenceOutcome {
    let result = if let EvidenceKind::Extension { kind, .. } = &decl.kind {
        // Compiled-in extension kinds (see `ext`) are dispatched through the
        // registry; unregistered kinds fail here with the list of what a
        // build of this binary knows.
        match crate::ext::get(kind) {
            Some(ext) => (ext.eval)(ctx.index, ctx.artifacts, decl),
            None => Err(format!(
                "evidence kind `{kind}` is not registered; registered: {:?}",
                crate::ext::registered()
            )),
        }
    } else {
        match &decl.kind {
            EvidenceKind::Scan {
                build,
                section,
                pattern,
            } => eval_scan(ctx, decl, build, section, pattern),
            EvidenceKind::Bytes {
                artifact,
                at,
                expect,
            } => eval_bytes(ctx, decl, artifact, *at, expect),
            EvidenceKind::Decode { build, func, count } => {
                eval_decode(ctx, decl, build, func, *count)
            }
            EvidenceKind::Constants {
                build,
                at,
                window,
                values,
                unique,
            } => eval_constants(ctx, decl, build, at, *window, values, *unique),
            EvidenceKind::Modulo {
                build,
                func,
                modulus,
            } => eval_modulo(ctx, decl, build, func, *modulus),
            EvidenceKind::Recovery {
                rng,
                algo,
                state,
                index,
                observed,
                projection,
            } => eval_recovery(
                ctx,
                decl,
                rng,
                algo.as_ref(),
                state,
                *index,
                observed,
                projection,
            ),
            EvidenceKind::Rate {
                capture,
                opcode,
                clock,
            } => eval_rate(ctx, decl, capture, *opcode, clock.as_deref()),
            EvidenceKind::Sample {
                capture,
                opcode,
                field,
                width,
                big_endian,
            } => eval_sample(ctx, decl, capture, *opcode, *field, *width, *big_endian),
            EvidenceKind::External { path, kind, build } => {
                eval_external(ctx, decl, path, kind, build)
            }
            EvidenceKind::Samples {
                dataset,
                value_col,
                group_col,
                delim,
            } => eval_samples(ctx, decl, dataset, *value_col, *group_col, delim),
            EvidenceKind::Symbols { build, path } => eval_symbols(ctx, decl, build, path),
            EvidenceKind::Absence {
                path,
                build,
                scope,
                during,
            } => eval_absence(ctx, decl, path, build, scope, during),
            EvidenceKind::Table {
                dataset,
                format,
                has_header,
            } => eval_table(ctx, decl, dataset, format, *has_header),
            EvidenceKind::Extension { .. } => {
                unreachable!("extension evidence is handled above")
            }
        }
    };
    result.unwrap_or_else(|e| EvidenceOutcome::failed(&decl.name, decl.kind.name(), e))
}

fn eval_scan(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    build: &str,
    section: &str,
    pattern: &str,
) -> Result<EvidenceOutcome, String> {
    if !ctx.artifacts.is_verified(build) {
        return Err(format!("build `{build}` is not a verified artifact"));
    }
    let hits = ctx.artifacts.scan_build(build, section, pattern)?;
    if hits.is_empty() {
        return Err(format!(
            "pattern {pattern:?} matched nothing in {build} section {section:?}"
        ));
    }
    let unique_requested = decl.unique();
    if unique_requested && hits.len() != 1 {
        return Err(format!(
            "pattern matched {} times in {build} section {section:?}; `|> unique` requires exactly one",
            hits.len()
        ));
    }
    let unique = hits.len() == 1 && unique_requested;
    let strength = if unique {
        Strength::Deterministic
    } else {
        Strength::Heuristic
    };
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "scan",
        strength,
        if unique {
            format!("unique match in {section} at {:#x}", hits[0])
        } else {
            format!(
                "{} match(es) in {section}; uniqueness not proven",
                hits.len()
            )
        },
    );
    for hit in &hits {
        out.fact(
            "scan_hit",
            vec![Value::sym(&decl.name), Value::Int(*hit as i128)],
        );
    }
    out.fact(
        "scan_count",
        vec![Value::sym(&decl.name), Value::Int(hits.len() as i128)],
    );
    if unique {
        out.fact("scan_unique", vec![Value::sym(&decl.name)]);
    }
    out.detail("section", section);
    out.detail("pattern", pattern);
    out.detail("matches", hits.len().to_string());
    for (i, hit) in hits.iter().enumerate().take(8) {
        out.detail(&format!("hit_{i}"), format!("{hit:#x}"));
    }
    Ok(out)
}

fn eval_bytes(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    artifact: &str,
    at: u64,
    expect: &str,
) -> Result<EvidenceOutcome, String> {
    let expected = parse_hex_bytes(expect)?;
    if expected.is_empty() {
        return Err("expected byte string is empty".into());
    }
    let actual = ctx.artifacts.read_addr(artifact, at, expected.len())?;
    if actual != expected {
        let first = actual
            .iter()
            .zip(&expected)
            .position(|(a, b)| a != b)
            .unwrap_or(0);
        return Err(format!(
            "byte mismatch at {:#x}: expected {:02x}, found {:02x}",
            at + first as u64,
            expected[first],
            actual[first]
        ));
    }
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "bytes",
        Strength::Deterministic,
        format!("{} bytes match at {at:#x}", expected.len()),
    );
    out.fact(
        "bytes_ok",
        vec![Value::sym(&decl.name), Value::Int(at as i128)],
    );
    out.fact(
        "bytes_at",
        vec![Value::sym(&decl.name), Value::Int(at as i128)],
    );
    out.detail("bytes", expected.len().to_string());
    Ok(out)
}

fn eval_decode(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    build: &str,
    func: &str,
    count: usize,
) -> Result<EvidenceOutcome, String> {
    let f = ctx
        .index
        .fns
        .get(func)
        .ok_or_else(|| format!("unknown function `{func}`"))?;
    if f.build != build {
        return Err(format!("function `{func}` is not in build `{build}`"));
    }
    if !ctx.artifacts.is_verified(build) {
        return Err(format!("build `{build}` is not a verified artifact"));
    }
    let (text_start, text) = ctx.artifacts.text_bytes(build)?;
    if f.addr < text_start {
        return Err(format!("function address {:#x} is below .text", f.addr));
    }
    let off = (f.addr - text_start) as usize;
    if off >= text.len() {
        return Err(format!("function address {:#x} is outside .text", f.addr));
    }
    let decoded = x86::decode(&text[off..], f.addr, count);
    if decoded.insns.is_empty() {
        return Err(format!(
            "no instructions decoded at {:#x}: {}",
            f.addr,
            decoded
                .stop_reason
                .unwrap_or_else(|| "unknown error".into())
        ));
    }

    let strength = if decoded.complete {
        Strength::Deterministic
    } else {
        Strength::Heuristic
    };
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "decode",
        strength,
        format!(
            "{} instruction(s) at {:#x}{}",
            decoded.insns.len(),
            f.addr,
            if decoded.complete { "" } else { " (partial)" }
        ),
    );
    out.fact(
        "insn_count",
        vec![
            Value::sym(&decl.name),
            Value::Int(decoded.insns.len() as i128),
        ],
    );
    if decoded.complete {
        out.fact("decode_complete", vec![Value::sym(&decl.name)]);
    } else {
        out.fact("decode_partial", vec![Value::sym(&decl.name)]);
        if let Some(reason) = &decoded.stop_reason {
            out.fact(
                "decode_error",
                vec![Value::sym(&decl.name), Value::str(reason.clone())],
            );
            out.detail("decode_stop", reason.clone());
        }
    }

    let mut loads: BTreeMap<u8, BTreeSet<i64>> = BTreeMap::new();
    let mut stores: BTreeMap<u8, BTreeSet<i64>> = BTreeMap::new();
    for insn in &decoded.insns {
        if let Some(m) = &insn.mem {
            if m.base.is_none() || m.rip_relative {
                continue;
            }
            if m.disp < 0 {
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
        let list = offs
            .iter()
            .map(|o| Value::Int(*o as i128))
            .collect::<Vec<_>>();
        out.fact(
            "loads_set",
            vec![
                Value::sym(&decl.name),
                Value::sym(func),
                Value::list(list.clone()),
                Value::Int(*width as i128),
            ],
        );
        if *width == 4 {
            out.fact(
                "loads_f32",
                vec![Value::sym(&decl.name), Value::sym(func), Value::list(list)],
            );
        }
        out.detail(
            &format!("loads_w{width}"),
            offs.iter()
                .map(|o| format!("{o:+}"))
                .collect::<Vec<_>>()
                .join(","),
        );
    }
    for (width, offs) in &stores {
        let list = offs
            .iter()
            .map(|o| Value::Int(*o as i128))
            .collect::<Vec<_>>();
        out.fact(
            "stores_set",
            vec![
                Value::sym(&decl.name),
                Value::sym(func),
                Value::list(list),
                Value::Int(*width as i128),
            ],
        );
    }
    out.detail(
        "instructions",
        decoded
            .insns
            .iter()
            .map(|i| i.mnemonic.clone())
            .collect::<Vec<_>>()
            .join(" "),
    );
    Ok(out)
}

fn eval_constants(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    build: &str,
    at: &Target,
    window: u64,
    values: &[u32],
    unique_requested: bool,
) -> Result<EvidenceOutcome, String> {
    let addr = ctx.index.resolve_addr_target(at)?;
    if !ctx.artifacts.is_verified(build) {
        return Err(format!("build `{build}` is not a verified artifact"));
    }
    let (text_start, text) = ctx.artifacts.text_bytes(build)?;
    if addr < text_start {
        return Err(format!("constant window {addr:#x} is below .text"));
    }
    let off = (addr - text_start) as usize;
    if off >= text.len() {
        return Err(format!("constant window {addr:#x} is outside .text"));
    }
    if off + window as usize > text.len() {
        return Err(format!(
            "constant window {addr:#x}+{window:#x} runs past .text"
        ));
    }
    let bytes = &text[off..off + window as usize];
    let mut counts = Vec::new();
    for v in values {
        let pat = v.to_le_bytes();
        let count = bytes
            .windows(pat.len())
            .filter(|w| *w == pat.as_slice())
            .count();
        if count == 0 {
            return Err(format!(
                "constant {v:#x} not found in {addr:#x}+{window:#x}"
            ));
        }
        counts.push((*v, count));
    }
    let unique = counts.iter().all(|(_, c)| *c == 1);
    if unique_requested && !unique {
        return Err(format!(
            "constants are not unique in the window: {:?}",
            counts
                .iter()
                .map(|(v, c)| format!("{v:#x} x{c}"))
                .collect::<Vec<_>>()
        ));
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
        format!(
            "{} constant(s) in {addr:#x}+{window:#x}{}",
            values.len(),
            if unique { " (unique)" } else { "" }
        ),
    );
    out.fact(
        "constants_window",
        vec![
            Value::sym(&decl.name),
            Value::Int(addr as i128),
            Value::Int(window as i128),
        ],
    );
    for (v, c) in &counts {
        out.fact(
            "constant_present",
            vec![Value::sym(&decl.name), Value::Int(*v as i128)],
        );
        out.fact(
            "constant_count",
            vec![
                Value::sym(&decl.name),
                Value::Int(*v as i128),
                Value::Int(*c as i128),
            ],
        );
        out.detail(&format!("const_{v:08X}"), format!("x{c}"));
    }
    if unique {
        out.fact("constants_unique", vec![Value::sym(&decl.name)]);
    }
    Ok(out)
}

fn eval_modulo(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    build: &str,
    func: &str,
    modulus: u64,
) -> Result<EvidenceOutcome, String> {
    let f = ctx
        .index
        .fns
        .get(func)
        .ok_or_else(|| format!("unknown function `{func}`"))?;
    if f.build != build {
        return Err(format!("function `{func}` is not in build `{build}`"));
    }
    let (text_start, text) = ctx.artifacts.text_bytes(build)?;
    let off = f
        .addr
        .checked_sub(text_start)
        .ok_or_else(|| format!("function address {:#x} is below .text", f.addr))?
        as usize;
    if off >= text.len() {
        return Err(format!("function address {:#x} is outside .text", f.addr));
    }
    let decoded = x86::decode(&text[off..], f.addr, 64);
    for (i, insn) in decoded.insns.iter().enumerate() {
        let Some(div_reg) = insn.div_reg else {
            continue;
        };
        // Find the nearest preceding `mov reg, imm`.
        let mut imm = None;
        for prev in decoded.insns[..i].iter().rev() {
            if prev.mov_reg == Some(div_reg) {
                imm = prev.imm;
                break;
            }
        }
        if let Some(v) = imm {
            if v >= 0 && v as u64 == modulus {
                let mut out = EvidenceOutcome::new(
                    &decl.name,
                    "modulo",
                    Strength::Deterministic,
                    format!("literal div by {modulus} at {:#x}", insn.addr),
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
                out.detail("site", format!("{:#x}", insn.addr));
                out.detail("divisor_register", format!("r{div_reg}"));
                return Ok(out);
            }
        }
    }
    Err(format!(
        "no literal `div` by {modulus} found in the first {} instruction(s) of `{func}`",
        decoded.insns.len()
    ))
}

#[allow(clippy::too_many_arguments)]
fn eval_recovery(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    rng: &str,
    explicit_algo: Option<&RngAlgo>,
    state_name: &str,
    index: u64,
    observed_name: &str,
    projection_name: &str,
) -> Result<EvidenceOutcome, String> {
    let r = ctx
        .index
        .rngs
        .get(rng)
        .ok_or_else(|| format!("unknown rng `{rng}`"))?;
    let algo = match explicit_algo {
        Some(RngAlgo::Other(s)) if s == "LCG" => match &r.algo {
            RngAlgo::Lcg { .. } => r.algo.clone(),
            _ => {
                return Err(
                    "recovery says LCG but the rng declaration has no LCG parameters".into(),
                )
            }
        },
        Some(a) => a.clone(),
        None => r.algo.clone(),
    };
    let projection = Projection::parse(projection_name)
        .ok_or_else(|| format!("unknown projection `{projection_name}`"))?;

    let state_text = ctx.artifacts.dataset_text(state_name)?;
    let state = parse_words(&state_text)?;
    let observed_text = ctx.artifacts.dataset_text(observed_name)?;
    let observed = parse_words(&observed_text)?;
    if observed.is_empty() {
        return Err("observed dataset is empty".into());
    }
    let simulated = prng::simulate(&algo, &state, index, observed.len())?;

    let mut matched = 0usize;
    let mut failed_at = None;
    for (i, (sim, obs)) in simulated.iter().zip(&observed).enumerate() {
        let projected = projection.apply(*sim);
        if projected == *obs {
            matched += 1;
        } else {
            failed_at = Some(i);
            break;
        }
    }

    let mut out;
    if let Some(i) = failed_at {
        out = EvidenceOutcome::new(
            &decl.name,
            "recovery",
            Strength::Deterministic,
            format!("simulation mismatch at sample {i}"),
        );
        out.fact(
            "sim_fail",
            vec![
                Value::sym(&decl.name),
                Value::sym(rng),
                Value::sym(algo.canonical()),
            ],
        );
        out.fact(
            "sim_mismatch_at",
            vec![Value::sym(&decl.name), Value::Int(i as i128)],
        );
        out.fact(
            "sim_matches",
            vec![Value::sym(&decl.name), Value::Int(matched as i128)],
        );
        out.detail("mismatch_at", i.to_string());
        out.detail("matched", matched.to_string());
    } else {
        let strength = if observed.len() >= 2 {
            Strength::Deterministic
        } else {
            Strength::Heuristic
        };
        out = EvidenceOutcome::new(
            &decl.name,
            "recovery",
            strength,
            format!(
                "{} output(s) reproduced by {} simulation",
                observed.len(),
                algo
            ),
        );
        out.fact(
            "recovery_ok",
            vec![
                Value::sym(&decl.name),
                Value::sym(rng),
                Value::Int(index as i128),
            ],
        );
        out.fact(
            "recovery_horizon",
            vec![Value::sym(&decl.name), Value::Int(observed.len() as i128)],
        );
        out.fact(
            "recovery_algo",
            vec![Value::sym(&decl.name), Value::sym(algo.canonical())],
        );
        out.fact(
            "sim_matches",
            vec![Value::sym(&decl.name), Value::Int(observed.len() as i128)],
        );
        out.detail("simulated", observed.len().to_string());
    }
    out.detail("algo", algo.as_str());
    out.detail("projection", projection.as_str());
    out.detail("index", index.to_string());
    out.detail("state_words", state.len().to_string());
    out.measured = Some(Measured::Recovery {
        algo: algo.canonical(),
        matched,
        horizon: observed.len(),
        index,
        failed_at,
        projection: projection.as_str().to_string(),
    });
    Ok(out)
}

fn eval_rate(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    capture: &str,
    opcode: u16,
    clock: Option<&str>,
) -> Result<EvidenceOutcome, String> {
    let bytes = ctx.artifacts.capture_bytes(capture)?;
    let packets = pcap::parse_pcap(bytes)?;
    let filtered = pcap::filter_opcode(&packets, opcode);
    if filtered.len() < 3 {
        return Err(format!(
            "capture `{capture}` has only {} packet(s) with opcode {opcode:#06x}; need at least 3",
            filtered.len()
        ));
    }
    let mut timestamps: Vec<u64> = filtered.iter().map(|p| p.ts_us).collect();
    timestamps.sort_unstable();
    let mut deltas: Vec<f64> = Vec::new();
    for w in timestamps.windows(2) {
        let d = w[1].saturating_sub(w[0]) as f64;
        if d > 0.0 {
            deltas.push(d);
        }
    }
    if deltas.len() < 2 {
        return Err("not enough distinct timestamps to estimate a period".into());
    }
    let period = stats::median(&deltas);
    let se = stats::median_se(&deltas);
    let ci = 1.96 * se;
    let coverage = timestamps.last().unwrap() - timestamps.first().unwrap();

    let mid = deltas.len() / 2;
    let m1 = stats::median(&deltas[..mid]);
    let m2 = stats::median(&deltas[mid..]);
    let max_mad =
        stats::mad(&deltas).max(stats::mad(&deltas[..mid]).max(stats::mad(&deltas[mid..])));
    let threshold = (period * 0.05).max(3.0 * max_mad / ((deltas.len() as f64 / 2.0).sqrt()));
    let stationary = (m1 - m2).abs() <= threshold;

    let strength = if stationary {
        Strength::Observational
    } else {
        Strength::Heuristic
    };
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "rate",
        strength,
        format!(
            "median period {period:.1}us over {} packets ({coverage}us){}",
            filtered.len(),
            if stationary { "" } else { ", nonstationary" }
        ),
    );
    out.fact(
        "rate_period_us",
        vec![Value::sym(&decl.name), Value::Int(period.round() as i128)],
    );
    out.fact(
        "rate_ci_us",
        vec![Value::sym(&decl.name), Value::Int(ci.round() as i128)],
    );
    out.fact(
        "rate_coverage_us",
        vec![Value::sym(&decl.name), Value::Int(coverage as i128)],
    );
    out.fact(
        "rate_samples",
        vec![Value::sym(&decl.name), Value::Int(filtered.len() as i128)],
    );
    out.fact(
        "rate_opcode",
        vec![Value::sym(&decl.name), Value::Int(opcode as i128)],
    );
    out.fact(
        "rate_stream",
        vec![Value::sym(&decl.name), Value::Int(opcode as i128)],
    );
    if stationary {
        out.fact("rate_stationary", vec![Value::sym(&decl.name)]);
    } else {
        out.fact("rate_nonstationary", vec![Value::sym(&decl.name)]);
    }
    if let Some(clock) = clock {
        out.fact(
            "rate_clock",
            vec![Value::sym(&decl.name), Value::sym(clock)],
        );
    }
    out.detail("period_us", format!("{period:.3}"));
    out.detail("ci95_us", format!("{ci:.3}"));
    out.detail("coverage_us", coverage.to_string());
    out.detail("samples", filtered.len().to_string());
    out.detail("stationary", stationary.to_string());
    if !stationary {
        out.detail("split_medians_us", format!("{m1:.1} vs {m2:.1}"));
    }
    out.measured = Some(Measured::Rate {
        period_us: period,
        ci_us: ci,
        coverage_us: coverage,
        samples: filtered.len() as u64,
        stationary,
        opcode,
        clock: clock.map(str::to_string),
    });
    Ok(out)
}

fn eval_sample(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    capture: &str,
    opcode: u16,
    field: usize,
    width: usize,
    big_endian: bool,
) -> Result<EvidenceOutcome, String> {
    let bytes = ctx.artifacts.capture_bytes(capture)?;
    let packets = pcap::parse_pcap(bytes)?;
    let filtered = pcap::filter_opcode(&packets, opcode);
    if filtered.is_empty() {
        return Err(format!(
            "capture `{capture}` has no packets with opcode {opcode:#06x}"
        ));
    }
    let mut values = Vec::new();
    let mut skipped = 0usize;
    let mut timestamps = Vec::new();
    for p in &filtered {
        let end = field + width;
        if p.payload.len() < end {
            skipped += 1;
            continue;
        }
        let slice = &p.payload[field..end];
        let mut v = 0u64;
        for (i, b) in slice.iter().enumerate() {
            let shift = if big_endian {
                (width - 1 - i) * 8
            } else {
                i * 8
            };
            v |= (*b as u64) << shift;
        }
        values.push(v);
        timestamps.push(p.ts_us);
    }
    if values.len() < 2 {
        return Err(format!(
            "sample evidence extracted only {} value(s) from `{capture}`",
            values.len()
        ));
    }
    let max = *values.iter().max().unwrap();
    if max > 65_535 {
        return Err(format!(
            "sample value {max} is too large for a binned distribution (max 65535)"
        ));
    }
    let mut counts = vec![0u64; max as usize + 1];
    for v in &values {
        counts[*v as usize] += 1;
    }
    timestamps.sort_unstable();
    let coverage = timestamps.last().unwrap() - timestamps.first().unwrap();
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "sample",
        Strength::Observational,
        format!(
            "{} sample(s) with opcode {opcode:#06x}, field {field} width {width}, {} observed bin(s)",
            values.len(),
            counts.len()
        ),
    );
    out.fact(
        "sample_n",
        vec![Value::sym(&decl.name), Value::Int(values.len() as i128)],
    );
    out.fact(
        "sample_opcode",
        vec![Value::sym(&decl.name), Value::Int(opcode as i128)],
    );
    out.fact(
        "sample_stream",
        vec![Value::sym(&decl.name), Value::Int(opcode as i128)],
    );
    out.fact(
        "sample_obs_bins",
        vec![Value::sym(&decl.name), Value::Int(counts.len() as i128)],
    );
    out.fact(
        "sample_coverage_us",
        vec![Value::sym(&decl.name), Value::Int(coverage as i128)],
    );
    out.fact(
        "sample_counts",
        vec![
            Value::sym(&decl.name),
            Value::list(counts.iter().map(|c| Value::Int(*c as i128)).collect()),
        ],
    );
    out.detail("samples", values.len().to_string());
    out.detail("skipped", skipped.to_string());
    out.detail("coverage_us", coverage.to_string());
    out.detail("observed_max", max.to_string());
    out.measured = Some(Measured::Sample {
        counts,
        n: values.len() as u64,
        coverage_us: coverage,
        opcode,
        field,
        width,
    });
    Ok(out)
}

/// Evaluate a `samples(ds, value: …, group: …, delim: …)` evidence term:
/// numeric samples from a content-addressed dataset, summarized per group.
///
/// The dataset rows are split on the declared delimiter; blank lines and
/// `#` comments are skipped and cells are trimmed. The value cell is parsed
/// as a float and the optional group cell names the group. When no group
/// column is declared, all values form a single group named `""`.
///
/// Statistics (mean, median, sample sd with an n-1 denominator, and a 95%
/// CI half-width of `1.96·sd/√n`) are emitted as milli-scaled integers so
/// rules and reports can consume them. The strength is Observational.
fn eval_samples(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    dataset: &str,
    value_col: usize,
    group_col: Option<usize>,
    delim: &str,
) -> Result<EvidenceOutcome, String> {
    let text = ctx.artifacts.dataset_text(dataset)?;
    let mut grouped: BTreeMap<String, Vec<f64>> = BTreeMap::new();
    for (row_no, line) in text.lines().enumerate() {
        let line = line.split('#').next().unwrap_or("");
        let line = line.trim();
        if line.is_empty() {
            continue;
        }
        let cells = split_row(line, delim);
        let value_cell = cells
            .get(value_col)
            .ok_or_else(|| format!("row {} has no value column {}", row_no + 1, value_col))?;
        let value: f64 = value_cell
            .parse()
            .map_err(|_| format!("row {} value {:?} is not a number", row_no + 1, value_cell))?;
        if !value.is_finite() {
            return Err(format!(
                "row {} value {:?} is not finite",
                row_no + 1,
                value_cell
            ));
        }
        let group = match group_col {
            Some(g) => cells
                .get(g)
                .ok_or_else(|| format!("row {} has no group column {g}", row_no + 1))?
                .to_string(),
            None => String::new(),
        };
        grouped.entry(group).or_default().push(value);
    }
    if grouped.is_empty() {
        return Err(format!("dataset `{dataset}` contains no sample rows"));
    }

    let mut groups = BTreeMap::new();
    for (name, values) in &grouped {
        let n = values.len() as u64;
        let mean = stats::mean(values);
        let median = stats::median(values);
        let (sd, ci95) = if n >= 2 {
            let sd = stats::sample_sd(values);
            (sd, 1.96 * sd / (n as f64).sqrt())
        } else {
            (0.0, 0.0)
        };
        groups.insert(
            name.clone(),
            GroupStats {
                n,
                mean,
                median,
                sd,
                ci95,
            },
        );
    }

    let total: u64 = grouped.values().map(|v| v.len() as u64).sum();
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "samples",
        Strength::Observational,
        format!("{} group(s), {total} total samples", groups.len()),
    );
    for (name, g) in &groups {
        out.fact(
            "samples_group",
            vec![Value::sym(&decl.name), Value::sym(name)],
        );
        out.fact(
            "samples_n",
            vec![
                Value::sym(&decl.name),
                Value::sym(name),
                Value::Int(g.n as i128),
            ],
        );
        out.fact(
            "samples_mean_milli",
            vec![
                Value::sym(&decl.name),
                Value::sym(name),
                Value::Int((g.mean * 1000.0).round() as i128),
            ],
        );
        out.fact(
            "samples_median_milli",
            vec![
                Value::sym(&decl.name),
                Value::sym(name),
                Value::Int((g.median * 1000.0).round() as i128),
            ],
        );
        out.fact(
            "samples_sd_milli",
            vec![
                Value::sym(&decl.name),
                Value::sym(name),
                Value::Int((g.sd * 1000.0).round() as i128),
            ],
        );
        out.fact(
            "samples_ci_milli",
            vec![
                Value::sym(&decl.name),
                Value::sym(name),
                Value::Int((g.ci95 * 1000.0).round() as i128),
            ],
        );
        out.detail(
            &format!("group_{name}"),
            format!(
                "n={} mean={:.3} median={:.3} sd={:.3} ci95={:.3}",
                g.n, g.mean, g.median, g.sd, g.ci95
            ),
        );
        if g.n < 2 {
            out.detail(
                &format!("group_{name}_ci"),
                "only one sample; the 95% CI half-width is 0",
            );
        }
    }
    out.measured = Some(Measured::Samples { groups });
    Ok(out)
}

fn eval_external(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    path: &str,
    kind: &str,
    build: &str,
) -> Result<EvidenceOutcome, String> {
    let cert = read_cert(ctx, path)?;
    let json = crate::json::parse(&cert)?;
    check_cert_build(ctx, &json, build)?;
    if let Some(k) = json.get("kind").and_then(Json::as_str) {
        if k != kind {
            return Err(format!(
                "certificate kind is `{k}`, evidence expects `{kind}`"
            ));
        }
    }
    let tool = json.get("tool").and_then(Json::as_str).unwrap_or("unknown");
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "external",
        Strength::Observational,
        format!("{kind} certificate from {tool}"),
    );
    out.detail("certificate", path);
    out.detail("tool", tool);

    match kind {
        "accesses" => {
            let arr = json
                .get("accesses")
                .and_then(Json::as_arr)
                .ok_or("accesses certificate lacks an `accesses` array")?;
            for a in arr {
                let fn_name = a
                    .get("fn")
                    .and_then(Json::as_str)
                    .ok_or("access.fn missing")?;
                let struct_name = a.get("struct").and_then(Json::as_str).unwrap_or("");
                let off = a
                    .get("offset")
                    .and_then(Json::as_u64)
                    .ok_or("access.offset missing")?;
                let width = a.get("width").and_then(Json::as_u64).unwrap_or(4);
                let mode = a.get("mode").and_then(Json::as_str).unwrap_or("read");
                out.fact(
                    "access",
                    vec![
                        Value::sym(&decl.name),
                        Value::sym(fn_name),
                        Value::sym(struct_name),
                        Value::Int(off as i128),
                        Value::Int(width as i128),
                        Value::sym(mode),
                    ],
                );
            }
            out.detail("accesses", arr.len().to_string());
        }
        "trace" => {
            let value = json.get("trace").ok_or("trace certificate lacks `trace`")?;
            let traces: Vec<&Json> = match value {
                Json::Arr(items) => items.iter().collect(),
                _ => vec![value],
            };
            for t in &traces {
                let from = t
                    .get("from")
                    .and_then(Json::as_str)
                    .ok_or("trace.from missing")?;
                let to = t
                    .get("to")
                    .and_then(Json::as_str)
                    .ok_or("trace.to missing")?;
                out.fact(
                    "trace",
                    vec![Value::sym(&decl.name), Value::sym(from), Value::sym(to)],
                );
            }
            out.detail("traces", traces.len().to_string());
        }
        "absence" => {
            let a = json
                .get("absence")
                .ok_or("absence certificate lacks `absence`")?;
            let scope = a.get("scope").and_then(Json::as_str).unwrap_or(".text");
            let start = a.get("window_start_us").and_then(Json::as_u64).unwrap_or(0);
            let end = a.get("window_end_us").and_then(Json::as_u64).unwrap_or(0);
            if let Some(writes) = a.get("writes").and_then(Json::as_arr) {
                if !writes.is_empty() {
                    return Err(format!(
                        "absence certificate lists {} write(s); it contradicts the claim",
                        writes.len()
                    ));
                }
            }
            out.fact(
                "absence_ok",
                vec![
                    Value::sym(&decl.name),
                    Value::sym(scope),
                    Value::Int(start as i128),
                    Value::Int(end as i128),
                ],
            );
            if let Some(field) = a.get("field").and_then(Json::as_str) {
                out.fact(
                    "absence_field",
                    vec![
                        Value::sym(&decl.name),
                        Value::sym(field),
                        Value::sym(scope),
                        Value::Int(start as i128),
                        Value::Int(end as i128),
                    ],
                );
            }
            out.detail("scope", scope.to_string());
        }
        "observability" => {
            let o = json
                .get("observability")
                .ok_or("observability certificate lacks `observability`")?;
            let conn = o
                .get("connection")
                .and_then(Json::as_str)
                .unwrap_or("unknown");
            let window = o.get("window").and_then(Json::as_str).unwrap_or("unknown");
            out.fact(
                "observability",
                vec![Value::sym(&decl.name), Value::sym(conn), Value::sym(window)],
            );
            out.detail("connection", conn.to_string());
        }
        _ => {
            if let Some(facts) = json.get("facts").and_then(Json::as_arr) {
                for f in facts {
                    let rel = f
                        .get("rel")
                        .and_then(Json::as_str)
                        .ok_or("generic fact.rel missing")?;
                    let args = f
                        .get("args")
                        .and_then(Json::as_arr)
                        .ok_or("generic fact.args missing")?;
                    let mut vals = Vec::new();
                    for a in args {
                        vals.push(json_value(a)?);
                    }
                    out.fact(rel, vals);
                }
                out.detail("facts", facts.len().to_string());
            } else {
                return Err(format!(
                    "external certificate kind `{kind}` has no recognized payload"
                ));
            }
        }
    }
    Ok(out)
}

fn eval_symbols(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    build: &str,
    path: &str,
) -> Result<EvidenceOutcome, String> {
    let text = read_cert(ctx, path)?;
    let json = crate::json::parse(&text)?;
    check_cert_build(ctx, &json, build)?;
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "symbols",
        Strength::Exact,
        "symbol store matched the build digest",
    );
    out.detail("store", path);

    let mut symbols = 0usize;
    if let Some(map) = json.get("symbols").and_then(Json::as_obj) {
        for (name, val) in map {
            let addr = val
                .as_u64()
                .or_else(|| val.as_str().and_then(parse_u64))
                .ok_or_else(|| format!("symbol `{name}` has an invalid address"))?;
            if ctx.artifacts.file_offset(build, addr).is_none() {
                return Err(format!(
                    "symbol `{name}` address {addr:#x} is outside the build image"
                ));
            }
            out.fact(
                "symbol_addr",
                vec![
                    Value::sym(&decl.name),
                    Value::sym(name),
                    Value::Int(addr as i128),
                ],
            );
            out.fact(
                "symbol_name",
                vec![
                    Value::sym(&decl.name),
                    Value::Int(addr as i128),
                    Value::sym(name),
                ],
            );
            symbols += 1;
        }
    }
    out.detail("symbols", symbols.to_string());

    let mut types = 0usize;
    let mut matches = 0usize;
    if let Some(map) = json.get("types").and_then(Json::as_obj) {
        for (name, val) in map {
            types += 1;
            let Some(st) = ctx.index.structs.get(name) else {
                out.fact(
                    "sym_struct_mismatch",
                    vec![Value::sym(&decl.name), Value::sym(name)],
                );
                out.detail(
                    &format!("type_{name}"),
                    "no matching model struct".to_string(),
                );
                continue;
            };
            let mut mismatch: Option<String> = None;
            let size = val.get("size").and_then(Json::as_u64).unwrap_or(0);
            let align = val.get("align").and_then(Json::as_u64).unwrap_or(0);
            if size != st.size {
                mismatch = Some(format!("size {} != model {}", size, st.size));
            } else if align != st.align {
                mismatch = Some(format!("align {} != model {}", align, st.align));
            } else if let Some(fields) = val.get("fields").and_then(Json::as_arr) {
                if fields.len() != st.fields.len() {
                    mismatch = Some("field count differs".into());
                } else {
                    for (f, model_field) in fields.iter().zip(&st.fields) {
                        let jname = f.get("name").and_then(Json::as_str).unwrap_or("");
                        let joff = f.get("offset").and_then(Json::as_u64).unwrap_or(u64::MAX);
                        let jtype = f.get("type").and_then(Json::as_str).unwrap_or("");
                        if jname != model_field.name
                            || joff != model_field.offset
                            || jtype != model_field.ty.display().as_str()
                        {
                            mismatch = Some(format!(
                                "field {} does not match {} @ {:#x}",
                                jname, model_field.name, model_field.offset
                            ));
                            break;
                        }
                    }
                }
            } else {
                mismatch = Some("type has no fields".into());
            }
            if let Some(reason) = mismatch {
                out.fact(
                    "sym_struct_mismatch",
                    vec![Value::sym(&decl.name), Value::sym(name)],
                );
                out.detail(&format!("type_{name}"), reason);
            } else {
                out.fact(
                    "sym_struct_match",
                    vec![Value::sym(&decl.name), Value::sym(name)],
                );
                matches += 1;
            }
        }
    }
    out.detail("types", types.to_string());
    out.detail("type_matches", matches.to_string());
    if symbols == 0 && types == 0 {
        return Err("symbol store contains no symbols or types".into());
    }
    Ok(out)
}

fn eval_absence(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    path: &str,
    build: &str,
    scope: &str,
    during: &str,
) -> Result<EvidenceOutcome, String> {
    let text = read_cert(ctx, path)?;
    let json = crate::json::parse(&text)?;
    check_cert_build(ctx, &json, build)?;
    let a = json
        .get("absence")
        .ok_or("absence certificate lacks `absence`")?;
    if let Some(writes) = a.get("writes").and_then(Json::as_arr) {
        if !writes.is_empty() {
            return Err(format!(
                "absence certificate lists {} write(s); it contradicts the claim",
                writes.len()
            ));
        }
    }
    let (text_start, text_end) = ctx.artifacts.text_range(build)?;
    let (start, end) = parse_scope(scope, text_start, text_end)?;
    if start < text_start || end > text_end || start >= end {
        return Err(format!(
            "absence scope {start:#x}..{end:#x} is outside .text {text_start:#x}..{text_end:#x}"
        ));
    }
    let capture_bytes = ctx.artifacts.capture_bytes(during)?;
    let packets = pcap::parse_pcap(capture_bytes)?;
    let span = pcap::span_us(&packets);
    let w_start = a.get("window_start_us").and_then(Json::as_u64).unwrap_or(0);
    let w_end = a.get("window_end_us").and_then(Json::as_u64).unwrap_or(0);
    if w_start > w_end || w_end > span {
        return Err(format!(
            "absence window {w_start}..{w_end}us is not inside capture `{during}` span 0..{span}us"
        ));
    }
    let tool = json.get("tool").and_then(Json::as_str).unwrap_or("unknown");
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "absence",
        Strength::Observational,
        format!("audited absence over {start:#x}..{end:#x} during {w_start}..{w_end}us"),
    );
    out.fact(
        "absence_ok",
        vec![
            Value::sym(&decl.name),
            Value::sym(scope),
            Value::Int(start as i128),
            Value::Int(end as i128),
        ],
    );
    if let Some(field) = a.get("field").and_then(Json::as_str) {
        out.fact(
            "absence_field",
            vec![
                Value::sym(&decl.name),
                Value::sym(field),
                Value::sym(scope),
                Value::Int(start as i128),
                Value::Int(end as i128),
            ],
        );
        out.detail("field", field.to_string());
    }
    out.detail("tool", tool);
    out.detail("scope", format!("{start:#x}..{end:#x}"));
    out.detail("window_us", format!("{w_start}..{w_end}"));
    Ok(out)
}

fn eval_table(
    ctx: &EvalCtx<'_>,
    decl: &EvidenceDecl,
    dataset: &str,
    format: &str,
    has_header: bool,
) -> Result<EvidenceOutcome, String> {
    let text = ctx.artifacts.dataset_text(dataset)?;
    let mut rows: Vec<Vec<Value>> = Vec::new();
    let mut header: Vec<String> = Vec::new();
    let mut cols: Option<usize> = None;
    let mut header_seen = false;
    for line in text.lines() {
        let line = line.trim();
        if line.is_empty() || line.starts_with('#') {
            continue;
        }
        if has_header && !header_seen {
            header = split_row(line, format);
            header_seen = true;
            continue;
        }
        let cells: Vec<Value> = split_row(line, format)
            .into_iter()
            .map(|c| parse_table_cell(&c))
            .collect();
        match cols {
            None => cols = Some(cells.len()),
            Some(n) if n != cells.len() => {
                return Err(format!(
                    "dataset `{dataset}` has an inconsistent column count at row {}: expected {n} column(s), found {}",
                    rows.len(),
                    cells.len()
                ))
            }
            Some(_) => {}
        }
        rows.push(cells);
    }
    let cols = cols.unwrap_or(0);

    let mut out = EvidenceOutcome::new(
        &decl.name,
        "table",
        Strength::Deterministic,
        format!("{} rows x {} cols from {dataset}", rows.len(), cols),
    );
    for (i, cells) in rows.iter().enumerate() {
        out.fact(
            "row",
            vec![
                Value::sym(&decl.name),
                Value::Int(i as i128),
                Value::list(cells.clone()),
            ],
        );
    }
    out.fact(
        "table_rows",
        vec![Value::sym(&decl.name), Value::Int(rows.len() as i128)],
    );
    out.fact(
        "table_cols",
        vec![Value::sym(&decl.name), Value::Int(cols as i128)],
    );
    out.detail("dataset", dataset);
    out.detail("format", format);
    for (i, cell) in header.iter().enumerate() {
        out.detail(&format!("header_col_{i}"), cell);
    }
    Ok(out)
}

/// Split one data line into cells on the declared delimiter. `csv` splits on
/// commas, `tsv` on tabs, `ws` on any whitespace run. Cells are trimmed;
/// quoted cells are not supported (keep tables delimiter-simple).
fn split_row(line: &str, delim: &str) -> Vec<String> {
    match delim {
        "tsv" => line.split('\t').map(|c| c.trim().to_string()).collect(),
        "ws" => line.split_whitespace().map(str::to_string).collect(),
        _ => line.split(',').map(|c| c.trim().to_string()).collect(),
    }
}

/// Parse one table cell into a fact value: empty → `Sym("")`; `0x…` → Int via
/// hex; decimal integer → Int; anything else → Sym.
fn parse_table_cell(cell: &str) -> Value {
    if cell.is_empty() {
        return Value::sym("");
    }
    if let Some(hex) = cell.strip_prefix("0x").or_else(|| cell.strip_prefix("0X")) {
        if let Ok(n) = u64::from_str_radix(hex, 16) {
            return Value::Int(n as i128);
        }
    }
    if let Ok(n) = cell.parse::<i128>() {
        return Value::Int(n);
    }
    Value::sym(cell)
}

fn check_cert_build(ctx: &EvalCtx<'_>, json: &Json, build: &str) -> Result<(), String> {
    let declared = ctx
        .artifacts
        .get(build)
        .ok_or_else(|| format!("unknown build `{build}`"))?;
    if !declared.verified {
        return Err(format!("build `{build}` is not a verified artifact"));
    }
    let cert_build = json
        .get("build")
        .and_then(Json::as_str)
        .ok_or("certificate lacks a `build` digest")?;
    if !cert_build.eq_ignore_ascii_case(&declared.actual_sha256) {
        return Err(format!(
            "certificate build digest {cert_build} does not match `{build}` ({})",
            declared.actual_sha256
        ));
    }
    Ok(())
}

fn read_cert(ctx: &EvalCtx<'_>, path: &str) -> Result<String, String> {
    let p = Path::new(path);
    let full = if p.is_absolute() {
        p.to_path_buf()
    } else {
        ctx.artifacts.model_dir.join(p)
    };
    fs::read_to_string(&full)
        .map_err(|e| format!("cannot read certificate {}: {e}", full.display()))
}

fn json_value(v: &Json) -> Result<Value, String> {
    match v {
        Json::Null => Ok(Value::sym("null")),
        Json::Bool(b) => Ok(Value::Bool(*b)),
        Json::Num(n) => Ok(Value::Int(*n as i128)),
        Json::Str(s) => Ok(Value::sym(s.clone())),
        Json::Arr(items) => {
            let mut out = Vec::new();
            for item in items {
                out.push(json_value(item)?);
            }
            Ok(Value::list(out))
        }
        Json::Obj(_) => Err("nested objects are not valid fact arguments".into()),
    }
}

fn parse_words(text: &str) -> Result<Vec<u64>, String> {
    let mut out = Vec::new();
    for line in text.lines() {
        let line = line.split('#').next().unwrap_or("");
        for tok in line.split(|c: char| c.is_whitespace() || c == ',' || c == ';') {
            if tok.is_empty() {
                continue;
            }
            let v = parse_u64(tok).ok_or_else(|| format!("invalid integer {tok:?} in dataset"))?;
            out.push(v);
        }
    }
    if out.is_empty() {
        return Err("dataset contains no integers".into());
    }
    Ok(out)
}

fn parse_u64(s: &str) -> Option<u64> {
    let s = s.trim();
    if let Some(hex) = s.strip_prefix("0x").or_else(|| s.strip_prefix("0X")) {
        u64::from_str_radix(hex, 16).ok()
    } else {
        s.parse().ok()
    }
}

fn parse_scope(scope: &str, text_start: u64, text_end: u64) -> Result<(u64, u64), String> {
    let s = scope.trim();
    if s == ".text" || s == "text" || s == "*.text" {
        return Ok((text_start, text_end));
    }
    let (a, b) = s
        .split_once("..")
        .ok_or_else(|| format!("scope must be `.text` or `start..end`, got {scope:?}"))?;
    let start = parse_u64(a).ok_or_else(|| format!("invalid scope start {a:?}"))?;
    let end = parse_u64(b).ok_or_else(|| format!("invalid scope end {b:?}"))?;
    Ok((start, end))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::artifact::{ArtifactDecl, ArtifactSet, LoadedArtifact};
    use crate::ast::DatasetDecl;
    use crate::lexer::Span;
    use crate::semantic::ModelIndex;
    use std::path::PathBuf;

    #[test]
    fn split_row_handles_all_delimiters() {
        assert_eq!(split_row("1.5, club", "csv"), vec!["1.5", "club"]);
        assert_eq!(split_row("1.5\tclub", "tsv"), vec!["1.5", "club"]);
        assert_eq!(split_row("  1.5  club ", "ws"), vec!["1.5", "club"]);
        assert_eq!(split_row(" 1.5 , club , ", "csv"), vec!["1.5", "club", ""]);
    }

    #[test]
    fn group_stats_are_computed_correctly() {
        let values = vec![1.0, 2.0, 3.0, 4.0];
        let n = values.len() as u64;
        let mean = stats::mean(&values);
        let median = stats::median(&values);
        let sd = stats::sample_sd(&values);
        let ci95 = 1.96 * sd / (n as f64).sqrt();
        let g = GroupStats {
            n,
            mean,
            median,
            sd,
            ci95,
        };
        assert_eq!(g.n, 4);
        assert!((g.mean - 2.5).abs() < 1e-12);
        assert!((g.median - 2.5).abs() < 1e-12);
        assert!((g.sd - 1.2909944487358056).abs() < 1e-12);
        assert!((g.ci95 - 1.96 * 1.2909944487358056 / 2.0).abs() < 1e-12);
    }

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    /// Evaluate a `samples` evidence term against an inline dataset so the
    /// real evaluator path (not just the helpers) is exercised. Failures are
    /// reported through the outcome's `ok`/`error` fields, like in `check`.
    fn eval_samples_inline(text: &str) -> EvidenceOutcome {
        let model = crate::parser::parse_model(
            "t.dg",
            &format!(
                "build b = binary(\"g.bin\", sha256: \"{SHA}\", arch: x86_64);\n\
                 dataset ds = dataset(\"s.csv\", sha256: \"{SHA}\", build: b);\n\
                 ev e := samples(ds, value: 0);\n"
            ),
        )
        .unwrap();
        let index = ModelIndex::new(&model).unwrap();
        let decl = index.evidence.get("e").unwrap().clone();
        let artifacts = ArtifactSet {
            model_dir: PathBuf::from("."),
            items: BTreeMap::from([(
                "ds".to_string(),
                LoadedArtifact {
                    decl: ArtifactDecl::Dataset(DatasetDecl {
                        name: "ds".into(),
                        path: "s.csv".into(),
                        sha256: SHA.into(),
                        build: Some("b".into()),
                        from: None,
                        span: Span::new(1, 1, 0),
                    }),
                    resolved_path: PathBuf::from("s.csv"),
                    bytes: text.as_bytes().to_vec(),
                    actual_sha256: SHA.into(),
                    verified: true,
                    load_error: None,
                },
            )]),
            errors: Vec::new(),
            pe_cache: std::cell::RefCell::new(BTreeMap::new()),
        };
        let ctx = EvalCtx {
            index: &index,
            artifacts: &artifacts,
        };
        evaluate(&ctx, &decl)
    }

    #[test]
    fn samples_evidence_evaluates_inline_dataset() {
        let out = eval_samples_inline("1.0\n2.0\n3.0\n");
        assert!(out.ok, "{:?}", out.error);
        assert_eq!(out.kind, "samples");
        match &out.measured {
            Some(Measured::Samples { groups }) => {
                let g = &groups[""];
                assert_eq!(g.n, 3);
                assert!((g.mean - 2.0).abs() < 1e-12);
            }
            other => panic!("wrong measured: {other:?}"),
        }
    }

    #[test]
    fn samples_evidence_rejects_non_finite_values() {
        for bad in ["1.0\nnan\n", "1.0\ninf\n", "1.0\n-inf\n"] {
            let out = eval_samples_inline(bad);
            assert!(!out.ok, "{bad}");
            let err = out.error.unwrap();
            assert!(err.contains("is not finite"), "{err}");
        }
    }

    #[test]
    fn samples_evidence_rejects_non_numeric_values() {
        let out = eval_samples_inline("1.0\ntwelve\n");
        assert!(!out.ok);
        let err = out.error.unwrap();
        assert!(err.contains("is not a number"), "{err}");
    }
}

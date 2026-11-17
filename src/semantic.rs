//! Model indexing, reference resolution, and static validation.
//!
//! Definitions (struct layouts, function addresses, RNG sites) become ground
//! facts tagged as *model assumptions*. They are audited in reports and never
//! count as evidence support: a proof made only of definitions cannot seal.

use crate::ast::*;
use crate::facts::compile_rules;
use crate::stdlib::stdlib_rules;
use crate::strength::Strength;
use crate::value::{Lit, Value};
use std::collections::{BTreeMap, BTreeSet, HashSet};

#[derive(Debug, Clone)]
pub struct ModelIndex {
    pub path: String,
    pub builds: BTreeMap<String, BuildDecl>,
    pub captures: BTreeMap<String, CaptureDecl>,
    pub dumps: BTreeMap<String, DumpDecl>,
    pub datasets: BTreeMap<String, DatasetDecl>,
    pub clocks: BTreeMap<String, ClockDecl>,
    pub structs: BTreeMap<String, StructDecl>,
    pub packets: BTreeMap<String, PacketDecl>,
    pub fns: BTreeMap<String, FnDecl>,
    pub rngs: BTreeMap<String, RngDecl>,
    pub dists: BTreeMap<String, DistDecl>,
    pub evidence: BTreeMap<String, EvidenceDecl>,
    pub rules: BTreeMap<String, RuleDecl>,
    pub proofs: BTreeMap<String, ProofDecl>,
    pub claims: BTreeMap<String, ClaimDecl>,
    pub conflicts: Vec<ConflictDecl>,
    pub decisions: BTreeMap<String, DecisionDecl>,
    pub obligations: Vec<ObligationDecl>,
    pub refutes: Vec<RefuteDecl>,
    pub ports: Vec<PortDecl>,
    pub pragmas: BTreeMap<String, Lit>,
    pub build_names: BTreeSet<String>,
    pub stdlib_rule_names: BTreeSet<String>,
}

impl ModelIndex {
    pub fn new(model: &Model) -> Result<ModelIndex, Vec<String>> {
        let mut errors = Vec::new();
        let mut index = ModelIndex {
            path: model.path.clone(),
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
        };

        for item in &model.items {
            match item {
                Item::Pragma(p) => {
                    if index
                        .pragmas
                        .insert(p.key.clone(), p.value.clone())
                        .is_some()
                    {
                        errors.push(format!("duplicate pragma `{}`", p.key));
                    }
                }
                Item::Build(d) => {
                    dup(&mut index.builds, &d.name, "build", &mut errors, d.clone());
                    index.build_names.insert(d.name.clone());
                }
                Item::Capture(d) => dup(
                    &mut index.captures,
                    &d.name,
                    "capture",
                    &mut errors,
                    d.clone(),
                ),
                Item::Dump(d) => dup(&mut index.dumps, &d.name, "dump", &mut errors, d.clone()),
                Item::Dataset(d) => dup(
                    &mut index.datasets,
                    &d.name,
                    "dataset",
                    &mut errors,
                    d.clone(),
                ),
                Item::Clock(d) => dup(&mut index.clocks, &d.name, "clock", &mut errors, d.clone()),
                Item::Struct(d) => dup(
                    &mut index.structs,
                    &d.name,
                    "struct",
                    &mut errors,
                    d.clone(),
                ),
                Item::Packet(d) => dup(
                    &mut index.packets,
                    &d.name,
                    "packet",
                    &mut errors,
                    d.clone(),
                ),
                Item::Fn(d) => dup(&mut index.fns, &d.name, "fn", &mut errors, d.clone()),
                Item::Rng(d) => dup(&mut index.rngs, &d.name, "rng", &mut errors, d.clone()),
                Item::Dist(d) => dup(&mut index.dists, &d.name, "dist", &mut errors, d.clone()),
                Item::Evidence(d) => dup(
                    &mut index.evidence,
                    &d.name,
                    "evidence",
                    &mut errors,
                    d.clone(),
                ),
                Item::Rule(d) => dup(&mut index.rules, &d.name, "rule", &mut errors, d.clone()),
                Item::Proof(d) => dup(&mut index.proofs, &d.name, "proof", &mut errors, d.clone()),
                Item::Claim(d) => dup(&mut index.claims, &d.name, "claim", &mut errors, d.clone()),
                Item::Conflict(d) => index.conflicts.push(d.clone()),
                Item::Decision(d) => dup(
                    &mut index.decisions,
                    &d.name,
                    "decision",
                    &mut errors,
                    d.clone(),
                ),
                Item::Obligation(d) => index.obligations.push(d.clone()),
                Item::Refute(d) => index.refutes.push(d.clone()),
                Item::Port(d) => index.ports.push(d.clone()),
                Item::Relate(_) => {}
            }
        }

        // Standard library rules are namespaced separately and may not be
        // overridden by user rules.
        match stdlib_rules() {
            Ok(rules) => {
                for r in rules {
                    index.stdlib_rule_names.insert(r.name.clone());
                }
            }
            Err(e) => errors.push(format!("internal error: stdlib: {e}")),
        }
        for name in index.rules.keys() {
            if index.stdlib_rule_names.contains(name) {
                errors.push(format!("rule `{name}` collides with the standard library"));
            }
        }

        // Resolve and validate declarations.
        index.validate_declarations(&mut errors);
        index.validate_evidence(&mut errors);
        index.validate_proofs_and_claims(&mut errors);
        index.validate_conflicts_and_obligations(&mut errors);
        index.validate_ports(&mut errors);

        if errors.is_empty() {
            Ok(index)
        } else {
            Err(errors)
        }
    }

    pub fn norm(&self, s: &str) -> String {
        if let Some((head, rest)) = s.split_once('.') {
            if self.build_names.contains(head) {
                return rest.to_string();
            }
        }
        s.to_string()
    }

    pub fn seal_threshold(&self) -> Strength {
        self.pragmas
            .get("seal_threshold")
            .and_then(|l| match l {
                Lit::Sym(s) | Lit::Str(s) => Strength::parse(s),
                _ => None,
            })
            .unwrap_or(Strength::Deterministic)
    }

    pub fn field_width(&self, _owner: &str, field: &FieldDecl) -> Option<u64> {
        match &field.ty {
            FieldTy::Scalar(t) => Some(t.width()),
            FieldTy::Named(name) => self.structs.get(name).map(|s| s.size),
        }
    }

    /// Ground definition facts for one build, in the order rules see them.
    pub fn definitions(&self, build: &str) -> Vec<(String, Vec<Value>)> {
        let mut out = Vec::new();
        let mut push = |rel: &str, args: Vec<Value>| out.push((rel.to_string(), args));

        for s in self.structs.values().filter(|s| s.build == build) {
            push(
                "owner_kind",
                vec![Value::sym(&s.name), Value::sym("struct")],
            );
            push(
                "struct_size",
                vec![Value::sym(&s.name), Value::Int(s.size as i128)],
            );
            push(
                "struct_align",
                vec![Value::sym(&s.name), Value::Int(s.align as i128)],
            );
            for f in &s.fields {
                let field_ref = format!("{}.{}", s.name, f.name);
                push(
                    "field_owner",
                    vec![Value::sym(&field_ref), Value::sym(&s.name)],
                );
                push(
                    "field_offset",
                    vec![Value::sym(&field_ref), Value::Int(f.offset as i128)],
                );
                if let Some(w) = self.field_width(&s.name, f) {
                    push(
                        "field_width",
                        vec![Value::sym(&field_ref), Value::Int(w as i128)],
                    );
                }
                push(
                    "field_type",
                    vec![Value::sym(&field_ref), Value::sym(f.ty.display())],
                );
            }
        }

        for p in self.packets.values().filter(|p| p.build == build) {
            push(
                "owner_kind",
                vec![Value::sym(&p.name), Value::sym("packet")],
            );
            push(
                "packet_size",
                vec![Value::sym(&p.name), Value::Int(p.size as i128)],
            );
            for f in &p.fields {
                let field_ref = format!("{}.{}", p.name, f.name);
                push(
                    "field_owner",
                    vec![Value::sym(&field_ref), Value::sym(&p.name)],
                );
                push(
                    "field_offset",
                    vec![Value::sym(&field_ref), Value::Int(f.offset as i128)],
                );
                if let Some(w) = self.field_width(&p.name, f) {
                    push(
                        "field_width",
                        vec![Value::sym(&field_ref), Value::Int(w as i128)],
                    );
                }
                push(
                    "field_type",
                    vec![Value::sym(&field_ref), Value::sym(f.ty.display())],
                );
                if let Some(c) = f.constant {
                    push(
                        "packet_field_constant",
                        vec![Value::sym(&field_ref), Value::Int(c)],
                    );
                    push("packet_opcode", vec![Value::sym(&p.name), Value::Int(c)]);
                }
            }
        }

        for f in self.fns.values().filter(|f| f.build == build) {
            push(
                "fn_addr",
                vec![Value::sym(&f.name), Value::Int(f.addr as i128)],
            );
            push("fn_label", vec![Value::sym(&f.name), Value::sym(&f.name)]);
        }

        for r in self.rngs.values().filter(|r| r.build == build) {
            push(
                "rng_addr",
                vec![Value::sym(&r.name), Value::Int(r.addr as i128)],
            );
            push(
                "rng_algo_decl",
                vec![Value::sym(&r.name), Value::sym(r.algo.canonical())],
            );
            push(
                "rng_algo_full",
                vec![Value::sym(&r.name), Value::sym(r.algo.as_str())],
            );
            if let Some(seed) = &r.seed {
                push(
                    "rng_seed",
                    vec![Value::sym(&r.name), Value::sym(seed.clone())],
                );
            }
            if let Some(scope) = &r.scope {
                push(
                    "rng_scope",
                    vec![Value::sym(&r.name), Value::sym(scope.clone())],
                );
            }
        }

        for d in self.dists.values().filter(|d| d.build == build) {
            push("dist_rng", vec![Value::sym(&d.name), Value::sym(&d.rng)]);
            push("dist_site", vec![Value::sym(&d.name), Value::sym(&d.site)]);
            push(
                "dist_bins",
                vec![Value::sym(&d.name), Value::Int(d.bins as i128)],
            );
        }

        for c in self
            .clocks
            .values()
            .filter(|c| c.build.as_deref().map(|b| b == build).unwrap_or(true))
        {
            push("clock_decl", vec![Value::sym(&c.name), Value::sym(&c.kind)]);
            if let Some(hz) = c.hz {
                push(
                    "clock_hz_milli",
                    vec![
                        Value::sym(&c.name),
                        Value::Int((hz * 1000.0).round() as i128),
                    ],
                );
            }
        }

        out
    }

    pub fn all_rules(&self) -> Result<Vec<RuleDecl>, Vec<String>> {
        let mut rules = stdlib_rules().map_err(|e| vec![format!("stdlib: {e}")])?;
        rules.extend(self.rules.values().cloned());
        compile_rules(&rules)
            .map(|_| rules)
            .map_err(|e| vec![format!("rule definition: {e}")])
    }

    pub fn evidence_build(&self, ev: &EvidenceDecl) -> Option<String> {
        match &ev.kind {
            EvidenceKind::Scan { build, .. }
            | EvidenceKind::Decode { build, .. }
            | EvidenceKind::Constants { build, .. }
            | EvidenceKind::Modulo { build, .. }
            | EvidenceKind::External { build, .. }
            | EvidenceKind::Symbols { build, .. }
            | EvidenceKind::Absence { build, .. } => Some(build.clone()),
            EvidenceKind::Bytes { artifact, .. } => {
                if let Some(b) = self.builds.get(artifact) {
                    Some(b.name.clone())
                } else if let Some(d) = self.dumps.get(artifact) {
                    d.build.clone()
                } else {
                    None
                }
            }
            EvidenceKind::Recovery { rng, .. } => self.rngs.get(rng).map(|r| r.build.clone()),
            EvidenceKind::Rate { capture, .. } | EvidenceKind::Sample { capture, .. } => {
                self.captures.get(capture).and_then(|c| c.build.clone())
            }
            EvidenceKind::Samples { dataset, .. } => {
                self.datasets.get(dataset).and_then(|d| d.build.clone())
            }
        }
    }

    pub fn resolve_addr_target(&self, target: &Target) -> Result<u64, String> {
        match target {
            Target::Addr(a) => Ok(*a),
            Target::Ref(r) => {
                let r = self.norm(r);
                if let Some(f) = self.fns.get(&r) {
                    Ok(f.addr)
                } else if let Some(rng) = self.rngs.get(&r) {
                    Ok(rng.addr)
                } else {
                    Err(format!("`{r}` is not a function or rng with an address"))
                }
            }
        }
    }

    fn validate_declarations(&self, errors: &mut Vec<String>) {
        for b in self.builds.values() {
            if let Some((start, end)) = b.text {
                if start >= end {
                    errors.push(format!(
                        "build `{}` has an empty or inverted text range {start:#x}..{end:#x}",
                        b.name
                    ));
                }
            }
        }
        for c in self.captures.values() {
            if let Some(b) = &c.build {
                if !self.builds.contains_key(b) {
                    errors.push(format!(
                        "capture `{}` refers to unknown build `{b}`",
                        c.name
                    ));
                }
            }
        }
        for d in self.dumps.values() {
            if let Some(b) = &d.build {
                if !self.builds.contains_key(b) {
                    errors.push(format!("dump `{}` refers to unknown build `{b}`", d.name));
                }
            }
        }
        for d in self.datasets.values() {
            if let Some(b) = &d.build {
                if !self.builds.contains_key(b) {
                    errors.push(format!(
                        "dataset `{}` refers to unknown build `{b}`",
                        d.name
                    ));
                }
            }
            if let Some(from) = &d.from {
                if !self.captures.contains_key(from) {
                    errors.push(format!(
                        "dataset `{}` refers to unknown capture `{from}`",
                        d.name
                    ));
                }
            }
        }
        for c in self.clocks.values() {
            if let Some(b) = &c.build {
                if !self.builds.contains_key(b) {
                    errors.push(format!("clock `{}` refers to unknown build `{b}`", c.name));
                }
            }
            if let Some(hz) = c.hz {
                if !(hz.is_finite() && hz > 0.0) {
                    errors.push(format!("clock `{}` has an invalid hz {hz}", c.name));
                }
            }
        }

        for s in self.structs.values() {
            if !self.builds.contains_key(&s.build) {
                errors.push(format!(
                    "struct `{}` refers to unknown build `{}`",
                    s.name, s.build
                ));
            }
            if s.size == 0 {
                errors.push(format!("struct `{}` has size 0", s.name));
            }
            if s.align == 0 || !s.align.is_power_of_two() {
                errors.push(format!(
                    "struct `{}` has non-power-of-two align {}",
                    s.name, s.align
                ));
            }
            self.validate_fields(&s.name, &s.fields, s.size, errors, &s.build);
        }
        for p in self.packets.values() {
            if !self.builds.contains_key(&p.build) {
                errors.push(format!(
                    "packet `{}` refers to unknown build `{}`",
                    p.name, p.build
                ));
            }
            if p.size == 0 {
                errors.push(format!("packet `{}` has size 0", p.name));
            }
            self.validate_fields(&p.name, &p.fields, p.size, errors, &p.build);
            if !p.fields.iter().any(|f| f.constant.is_some()) {
                errors.push(format!(
                    "packet `{}` has no constant field; at least one opcode/discriminator is required",
                    p.name
                ));
            }
        }

        for f in self.fns.values() {
            if !self.builds.contains_key(&f.build) {
                errors.push(format!(
                    "fn `{}` refers to unknown build `{}`",
                    f.name, f.build
                ));
            }
            if f.addr == 0 {
                errors.push(format!("fn `{}` has address 0", f.name));
            }
        }
        for r in self.rngs.values() {
            if !self.builds.contains_key(&r.build) {
                errors.push(format!(
                    "rng `{}` refers to unknown build `{}`",
                    r.name, r.build
                ));
            }
            if matches!(r.algo, RngAlgo::Other(_)) {
                errors.push(format!(
                    "rng `{}` uses an algorithm without a simulation backend: {}",
                    r.name, r.algo
                ));
            }
        }
        for d in self.dists.values() {
            if !self.builds.contains_key(&d.build) {
                errors.push(format!(
                    "dist `{}` refers to unknown build `{}`",
                    d.name, d.build
                ));
            }
            if !self.rngs.contains_key(&d.rng) {
                errors.push(format!(
                    "dist `{}` refers to unknown rng `{}`",
                    d.name, d.rng
                ));
            }
            if !self.fns.contains_key(&d.site) {
                errors.push(format!(
                    "dist `{}` refers to unknown fn `{}`",
                    d.name, d.site
                ));
            }
            if d.bins < 2 {
                errors.push(format!("dist `{}` needs at least 2 bins", d.name));
            }
        }
    }

    fn validate_fields(
        &self,
        owner: &str,
        fields: &[FieldDecl],
        size: u64,
        errors: &mut Vec<String>,
        build: &str,
    ) {
        for (i, f) in fields.iter().enumerate() {
            if let FieldTy::Named(name) = &f.ty {
                match self.structs.get(name) {
                    Some(s) if s.build == build => {}
                    Some(_) => errors.push(format!(
                        "field `{owner}.{}` references struct `{name}` from a different build",
                        f.name
                    )),
                    None => errors.push(format!(
                        "field `{owner}.{}` references unknown struct `{name}`",
                        f.name
                    )),
                }
            }
            let Some(w) = self.field_width(owner, f) else {
                if let FieldTy::Scalar(Ty::Bytes) = &f.ty {
                    continue;
                }
                continue;
            };
            if w == 0 {
                continue;
            }
            if f.offset + w > size {
                errors.push(format!(
                    "field `{owner}.{}` ends at {:#x}, beyond size {size:#x}",
                    f.name,
                    f.offset + w
                ));
            }
            for (_j, g) in fields.iter().enumerate().skip(i + 1) {
                let Some(w2) = self.field_width(owner, g) else {
                    continue;
                };
                if w2 == 0 {
                    continue;
                }
                let a0 = f.offset;
                let a1 = f.offset + w;
                let b0 = g.offset;
                let b1 = g.offset + w2;
                if a0 < b1 && b0 < a1 {
                    errors.push(format!(
                        "fields `{owner}.{}` and `{owner}.{}` overlap",
                        f.name, g.name
                    ));
                }
            }
        }
        if let Some(last) = fields.iter().map(|f| f.offset).max() {
            if last >= size && !fields.is_empty() {
                errors.push(format!(
                    "field offset {last:#x} is not below {owner} size {size:#x}"
                ));
            }
        }
    }

    fn validate_evidence(&self, errors: &mut Vec<String>) {
        for ev in self.evidence.values() {
            match &ev.kind {
                EvidenceKind::Scan {
                    build,
                    section,
                    pattern,
                } => {
                    self.need_build(build, &ev.name, errors);
                    if !self.builds.contains_key(build) {
                        continue;
                    }
                    if section != ".text" {
                        errors.push(format!(
                            "evidence `{}`: only .text scans are supported (got {section:?})",
                            ev.name
                        ));
                    }
                    if let Err(e) = crate::value::parse_byte_pattern(pattern) {
                        errors.push(format!("evidence `{}`: {e}", ev.name));
                    }
                }
                EvidenceKind::Bytes {
                    artifact, expect, ..
                } => {
                    if !self.builds.contains_key(artifact) && !self.dumps.contains_key(artifact) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown build/dump `{artifact}`",
                            ev.name
                        ));
                    }
                    if let Err(e) = crate::value::parse_hex_bytes(expect) {
                        errors.push(format!("evidence `{}`: {e}", ev.name));
                    }
                }
                EvidenceKind::Decode { build, func, count } => {
                    self.need_build(build, &ev.name, errors);
                    if !self.fns.contains_key(func) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown fn `{func}`",
                            ev.name
                        ));
                    }
                    if *count == 0 || *count > 4096 {
                        errors.push(format!("evidence `{}` has an unreasonable count", ev.name));
                    }
                }
                EvidenceKind::Constants {
                    build,
                    at,
                    window,
                    values,
                    ..
                } => {
                    self.need_build(build, &ev.name, errors);
                    if let Err(e) = self.resolve_addr_target(at) {
                        errors.push(format!("evidence `{}`: {e}", ev.name));
                    }
                    if *window == 0 || *window > 1 << 20 {
                        errors.push(format!(
                            "evidence `{}`: constants window must be 1..1MiB",
                            ev.name
                        ));
                    }
                    if values.is_empty() {
                        errors.push(format!("evidence `{}`: no constants requested", ev.name));
                    }
                }
                EvidenceKind::Modulo {
                    build,
                    func,
                    modulus,
                } => {
                    self.need_build(build, &ev.name, errors);
                    if !self.fns.contains_key(func) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown fn `{func}`",
                            ev.name
                        ));
                    }
                    if *modulus == 0 {
                        errors.push(format!("evidence `{}`: modulus must be non-zero", ev.name));
                    }
                }
                EvidenceKind::Recovery {
                    rng,
                    state,
                    observed,
                    projection,
                    ..
                } => {
                    if !self.rngs.contains_key(rng) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown rng `{rng}`",
                            ev.name
                        ));
                    }
                    if !self.datasets.contains_key(state) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown dataset `{state}`",
                            ev.name
                        ));
                    }
                    if !self.datasets.contains_key(observed) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown dataset `{observed}`",
                            ev.name
                        ));
                    }
                    if crate::prng::Projection::parse(projection).is_none() {
                        errors.push(format!(
                            "evidence `{}`: unknown projection `{projection}`",
                            ev.name
                        ));
                    }
                }
                EvidenceKind::Rate { capture, clock, .. } => {
                    if !self.captures.contains_key(capture) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown capture `{capture}`",
                            ev.name
                        ));
                    }
                    if let Some(clock) = clock {
                        if !self.clocks.contains_key(clock) {
                            errors.push(format!(
                                "evidence `{}` refers to unknown clock `{clock}`",
                                ev.name
                            ));
                        }
                    }
                }
                EvidenceKind::Sample { capture, .. } => {
                    if !self.captures.contains_key(capture) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown capture `{capture}`",
                            ev.name
                        ));
                    }
                }
                EvidenceKind::External { build, .. } => {
                    self.need_build(build, &ev.name, errors);
                }
                EvidenceKind::Samples {
                    dataset,
                    value_col,
                    group_col,
                    ..
                } => {
                    if !self.datasets.contains_key(dataset) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown dataset `{dataset}`",
                            ev.name
                        ));
                    }
                    if let Some(g) = group_col {
                        if g == value_col {
                            errors.push(format!(
                                "evidence `{}`: group column equals value column ({g})",
                                ev.name
                            ));
                        }
                    }
                }
                EvidenceKind::Symbols { build, .. } => {
                    self.need_build(build, &ev.name, errors);
                }
                EvidenceKind::Absence {
                    build,
                    during,
                    scope,
                    ..
                } => {
                    self.need_build(build, &ev.name, errors);
                    if !self.captures.contains_key(during) {
                        errors.push(format!(
                            "evidence `{}` refers to unknown capture `{during}`",
                            ev.name
                        ));
                    }
                    if scope.trim().is_empty() {
                        errors.push(format!("evidence `{}`: empty absence scope", ev.name));
                    }
                }
            }
        }
    }

    fn need_build(&self, build: &str, ev: &str, errors: &mut Vec<String>) {
        if !self.builds.contains_key(build) {
            errors.push(format!("evidence `{ev}` refers to unknown build `{build}`"));
        }
    }

    fn validate_proofs_and_claims(&self, errors: &mut Vec<String>) {
        for name in self.proofs.keys() {
            if self.claims.contains_key(name) {
                errors.push(format!("`{name}` is declared as both a proof and a claim"));
            }
        }
        for proof in self.proofs.values() {
            if !self.builds.contains_key(&proof.build) {
                errors.push(format!(
                    "proof `{}` refers to unknown build `{}`",
                    proof.name, proof.build
                ));
            }
            if proof.evidence.is_empty() {
                errors.push(format!(
                    "proof `{}` lists no evidence; definitions alone cannot prove anything",
                    proof.name
                ));
            }
            for e in &proof.evidence {
                match self.evidence.get(e) {
                    None => errors.push(format!(
                        "proof `{}` refers to unknown evidence `{e}`",
                        proof.name
                    )),
                    Some(ev) => {
                        if let Some(b) = self.evidence_build(ev) {
                            if b != proof.build {
                                errors.push(format!(
                                    "proof `{}` (build {}) uses evidence `{e}` from build {b}",
                                    proof.name, proof.build
                                ));
                            }
                        }
                    }
                }
            }
            for r in &proof.rules {
                if !self.rules.contains_key(r) && !self.stdlib_rule_names.contains(r) {
                    errors.push(format!(
                        "proof `{}` refers to unknown rule `{r}`",
                        proof.name
                    ));
                }
            }
        }

        for claim in self.claims.values() {
            if !self.builds.contains_key(&claim.build) {
                errors.push(format!(
                    "claim `{}` refers to unknown build `{}`",
                    claim.name, claim.build
                ));
            }
            if let Some(c) = &claim.during {
                if !self.captures.contains_key(c) {
                    errors.push(format!(
                        "claim `{}` refers to unknown capture `{c}`",
                        claim.name
                    ));
                }
            }
            match &claim.head {
                ClaimHead::Period { clock, .. } => {
                    if !self.clocks.contains_key(clock) {
                        errors.push(format!(
                            "claim `{}` refers to unknown clock `{clock}`",
                            claim.name
                        ));
                    }
                    if claim.during.is_none() {
                        errors.push(format!(
                            "claim `{}`: a period claim needs `during <capture>`",
                            claim.name
                        ));
                    }
                }
                ClaimHead::Uniform { dist, .. } => {
                    if !self.dists.contains_key(dist) {
                        errors.push(format!(
                            "claim `{}` refers to unknown distribution `{dist}`",
                            claim.name
                        ));
                    }
                    if claim.during.is_none() {
                        errors.push(format!(
                            "claim `{}`: a uniformity claim needs `during <capture>`",
                            claim.name
                        ));
                    }
                }
                ClaimHead::Mean { .. } => {
                    if !matches!(claim.body, ClaimBody::Direct { .. }) {
                        errors.push(format!(
                            "claim `{}`: a mean claim needs `by <samples evidence>`",
                            claim.name
                        ));
                    }
                }
                ClaimHead::Coverage { dataset, .. } => {
                    if !self.datasets.contains_key(dataset) {
                        errors.push(format!(
                            "claim `{}` refers to unknown dataset `{dataset}`",
                            claim.name
                        ));
                    }
                    if !matches!(claim.body, ClaimBody::Coverage { .. }) {
                        errors.push(format!(
                            "claim `{}`: a coverage claim needs `from <claim,...>`",
                            claim.name
                        ));
                    }
                }
                ClaimHead::Rel(_) => {}
            }
            match &claim.body {
                ClaimBody::Direct { evidence, .. } => {
                    if !self.evidence.contains_key(evidence) {
                        errors.push(format!(
                            "claim `{}` refers to unknown evidence `{evidence}`",
                            claim.name
                        ));
                    }
                }
                ClaimBody::Derived { from } | ClaimBody::Coverage { from } => {
                    if from.is_empty() {
                        errors.push(format!("claim `{}` has no premises", claim.name));
                    }
                    for f in from {
                        if !self.proofs.contains_key(f) && !self.claims.contains_key(f) {
                            errors.push(format!(
                                "claim `{}` refers to unknown premise `{f}`",
                                claim.name
                            ));
                        }
                    }
                }
            }
        }

        // Derived-claim cycles.
        let mut visiting = HashSet::new();
        let mut done = HashSet::new();
        for name in self.claims.keys() {
            self.visit_claim(name, &mut visiting, &mut done, errors);
        }
    }

    fn visit_claim(
        &self,
        name: &str,
        visiting: &mut HashSet<String>,
        done: &mut HashSet<String>,
        errors: &mut Vec<String>,
    ) {
        if done.contains(name) {
            return;
        }
        if !visiting.insert(name.to_string()) {
            errors.push(format!("derived claim cycle involving `{name}`"));
            return;
        }
        if let Some(claim) = self.claims.get(name) {
            if let ClaimBody::Derived { from } | ClaimBody::Coverage { from } = &claim.body {
                for f in from {
                    if self.claims.contains_key(f) {
                        self.visit_claim(f, visiting, done, errors);
                    }
                }
            }
        }
        visiting.remove(name);
        done.insert(name.to_string());
    }

    fn validate_conflicts_and_obligations(&self, errors: &mut Vec<String>) {
        for c in &self.conflicts {
            let known = |n: &str| self.proofs.contains_key(n) || self.claims.contains_key(n);
            if !known(&c.left) {
                errors.push(format!(
                    "conflict `{}` refers to unknown claim `{}`",
                    c.name, c.left
                ));
            }
            if !known(&c.right) {
                errors.push(format!(
                    "conflict `{}` refers to unknown claim `{}`",
                    c.name, c.right
                ));
            }
            if let Some(p) = &c.prefer {
                if p != &c.left && p != &c.right {
                    errors.push(format!(
                        "conflict `{}` prefers `{p}`, which is not one of its sides",
                        c.name
                    ));
                }
            }
            if let Some(d) = &c.decision {
                if !self.decisions.contains_key(d) {
                    errors.push(format!(
                        "conflict `{}` refers to unknown decision `{d}`",
                        c.name
                    ));
                }
            }
        }
        for d in self.decisions.values() {
            let known = |n: &str| self.proofs.contains_key(n) || self.claims.contains_key(n);
            if !known(&d.prefer) {
                errors.push(format!(
                    "decision `{}` prefers unknown claim `{}`",
                    d.name, d.prefer
                ));
            }
            if !known(&d.over) {
                errors.push(format!(
                    "decision `{}` overrides unknown claim `{}`",
                    d.name, d.over
                ));
            }
            if d.prefer == d.over {
                errors.push(format!(
                    "decision `{}` prefers and overrides the same claim `{}`",
                    d.name, d.prefer
                ));
            }
        }
        for o in &self.obligations {
            if let Some(r) = &o.resolved_by {
                if !self.proofs.contains_key(r) && !self.claims.contains_key(r) {
                    errors.push(format!(
                        "obligation `{}` is resolved by unknown claim `{r}`",
                        o.name
                    ));
                }
            }
        }
        for r in &self.refutes {
            if !self.builds.contains_key(&r.build) {
                errors.push(format!(
                    "refute `{}` refers to unknown build `{}`",
                    r.name, r.build
                ));
            }
            if !self.evidence.contains_key(&r.evidence) {
                errors.push(format!(
                    "refute `{}` refers to unknown evidence `{}`",
                    r.name, r.evidence
                ));
            }
        }
    }

    fn validate_ports(&self, errors: &mut Vec<String>) {
        for p in &self.ports {
            if !self.builds.contains_key(&p.from) {
                errors.push(format!("port refers to unknown build `{}`", p.from));
            }
            if !self.builds.contains_key(&p.to) {
                errors.push(format!("port refers to unknown build `{}`", p.to));
            }
            for r in &p.rules {
                match r {
                    PortRule::Rebase { target, .. } => {
                        if !self.fns.contains_key(target) && !self.rngs.contains_key(target) {
                            errors.push(format!(
                                "port rebase target `{target}` is not a function or rng"
                            ));
                        }
                    }
                    PortRule::Drop { target } => {
                        if !self.evidence.contains_key(target)
                            && !self.proofs.contains_key(target)
                            && !self.claims.contains_key(target)
                        {
                            errors.push(format!("port drop target `{target}` is unknown"));
                        }
                    }
                    PortRule::Revalidate { evidence, with } => {
                        if !self.evidence.contains_key(evidence) {
                            errors.push(format!(
                                "port revalidate refers to unknown evidence `{evidence}`"
                            ));
                        }
                        if !self.captures.contains_key(with) && !self.datasets.contains_key(with) {
                            errors.push(format!(
                                "port revalidate refers to unknown capture/dataset `{with}`"
                            ));
                        }
                    }
                }
            }
        }
    }
}

fn dup<T: Clone>(
    map: &mut BTreeMap<String, T>,
    name: &str,
    kind: &str,
    errors: &mut Vec<String>,
    value: T,
) {
    if map.insert(name.to_string(), value).is_some() {
        errors.push(format!("duplicate {kind} `{name}`"));
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::parser::parse_model;

    const SRC: &str = r#"
        build b1 = binary("g.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64, load: 0x140000000, text: 0x140001000..0x140001400);
        struct Vec3 in b1 { x: f32 @ 0; y: f32 @ 4; z: f32 @ 8; } size 12 align 4;
        packet P in b1 { op: u16 @ 0 = 0x1F4; pos: Vec3 @ 2; } size 14;
        fn f in b1 at 0x140001000;
        rng r in b1 at 0x140001100 { algo: MT19937; seed: time; scope: per_server; }
        dist D in b1 { rng: r; site: f; bins: 12; }
        capture c1 = capture("c.pcap", sha256: "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb", build: b1);
        ev e := scan(b1, ".text", "F3 0F 10 47 ??") |> unique;
        rule myrule: reads(?f, ?x) if loads_set(?e, ?f, ?o, 4) and field_owner(?x, ?f);
        proof p: reads(f, Vec3.z) in b1 { evidence e; rules myrule; }
        claim c: uniform(D, bins: 12) in b1 during c1 by e require alpha: 1e-4;
    "#;

    #[test]
    fn indexes_and_validates() {
        let m = parse_model("t.dg", SRC).unwrap();
        let idx = ModelIndex::new(&m).unwrap();
        assert_eq!(idx.structs.len(), 1);
        assert_eq!(
            idx.field_width("Vec3", &idx.structs["Vec3"].fields[2]),
            Some(4)
        );
        assert!(idx.stdlib_rule_names.contains("reader_reads_struct_field"));
    }

    #[test]
    fn rejects_overlapping_fields() {
        let src = r#"
            build b1 = binary("g.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64);
            struct S in b1 { a: u32 @ 0; b: u32 @ 2; } size 8 align 4;
        "#;
        let m = parse_model("t.dg", src).unwrap();
        let errs = ModelIndex::new(&m).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("overlap")));
    }

    #[test]
    fn rejects_stdlib_rule_shadowing() {
        let src = r#"
            build b1 = binary("g.bin", sha256: "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", arch: x86_64);
            rule reader_reads_struct_field: x(?a) if y(?a);
        "#;
        let m = parse_model("t.dg", src).unwrap();
        let errs = ModelIndex::new(&m).unwrap_err();
        assert!(errs.iter().any(|e| e.contains("collides")));
    }

    const SHA: &str = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa";

    #[test]
    fn samples_evidence_validates_dataset_and_columns() {
        let src = format!(
            r#"
            build b1 = binary("g.bin", sha256: "{SHA}", arch: x86_64);
            dataset ds = dataset("s.csv", sha256: "{SHA}", build: b1);
            ev e := samples(ds, value: 1, group: 1);
            ev e2 := samples(missing, value: 0);
            "#
        );
        let m = parse_model("t.dg", &src).unwrap();
        let errs = ModelIndex::new(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("group column equals value column")),
            "{errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("refers to unknown dataset `missing`")),
            "{errs:?}"
        );
    }

    #[test]
    fn coverage_claim_validates_dataset_and_body() {
        let src = format!(
            r#"
            build b1 = binary("g.bin", sha256: "{SHA}", arch: x86_64);
            dataset ds = dataset("ids.txt", sha256: "{SHA}", build: b1);
            claim C : coverage(ds, target: 5) in b1 by e;
            claim C2 : coverage(missing, target: 5) in b1 from P;
            "#
        );
        let m = parse_model("t.dg", &src).unwrap();
        let errs = ModelIndex::new(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("a coverage claim needs `from")),
            "{errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("refers to unknown dataset `missing`")),
            "{errs:?}"
        );
    }

    #[test]
    fn samples_evidence_build_follows_dataset_binding() {
        let src = format!(
            r#"
            build b1 = binary("g.bin", sha256: "{SHA}", arch: x86_64);
            dataset ds = dataset("s.csv", sha256: "{SHA}", build: b1);
            dataset ds2 = dataset("s2.csv", sha256: "{SHA}");
            ev e := samples(ds, value: 0);
            ev e2 := samples(ds2, value: 0);
            "#
        );
        let m = parse_model("t.dg", &src).unwrap();
        let idx = ModelIndex::new(&m).unwrap();
        assert_eq!(
            idx.evidence_build(&idx.evidence["e"]).as_deref(),
            Some("b1")
        );
        assert_eq!(idx.evidence_build(&idx.evidence["e2"]), None);
    }

    #[test]
    fn proof_using_cross_build_samples_evidence_is_rejected() {
        let src = format!(
            r#"
            build b1 = binary("g.bin", sha256: "{SHA}", arch: x86_64);
            build b2 = binary("h.bin", sha256: "{SHA}", arch: x86_64);
            dataset ds = dataset("s.csv", sha256: "{SHA}", build: b1);
            ev e := samples(ds, value: 0);
            rule r: x(1) if samples_group(?e, ?g);
            proof P : x(1) in b2 {{ evidence e; rules r; }}
            "#
        );
        let m = parse_model("t.dg", &src).unwrap();
        let errs = ModelIndex::new(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("uses evidence `e` from build b1")),
            "{errs:?}"
        );
    }

    #[test]
    fn decisions_and_conflict_references_are_validated() {
        let src = format!(
            r#"
            build b1 = binary("g.bin", sha256: "{SHA}", arch: x86_64);
            decision D := decision("d.txt", sha256: "{SHA}", prefer: P_a, over: P_b, signer: "x");
            decision D2 := decision("d2.txt", sha256: "{SHA}", prefer: P_a, over: P_a);
            conflict C : P_a vs P_b decision D;
            conflict C2 : P_a vs P_b decision NOPE;
            "#
        );
        let m = parse_model("t.dg", &src).unwrap();
        let errs = ModelIndex::new(&m).unwrap_err();
        assert!(
            errs.iter()
                .any(|e| e.contains("prefers unknown claim `P_a`")),
            "{errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("prefers and overrides the same claim")),
            "{errs:?}"
        );
        assert!(
            errs.iter()
                .any(|e| e.contains("refers to unknown decision `NOPE`")),
            "{errs:?}"
        );
    }
}

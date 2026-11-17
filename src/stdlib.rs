//! The standard rule library.
//!
//! Rules are ordinary DeG rules: they are printed in `deg stdlib`, auditable,
//! and only applied when a proof names them. Definitions (struct layouts,
//! function addresses, RNG sites) are *model assumptions*; rules that turn an
//! assumption into a claim are marked with an explicit cap where appropriate.

use crate::ast::{Item, RuleDecl};
use crate::parser::parse_model;

pub const STDLIB: &str = r#"
// ── function and field relationships ──────────────────────────────────────

// A struct field is read by f when f is anchored by a unique scan and its
// decoded 32-bit loads include the field's offset. This is deterministic
// *relative to the model's declared calling convention*: the kernel checks the
// bytes, the rule library encodes the ABI assumption.
rule reader_reads_struct_field:
  reads(?f, ?field) if
    fn_addr(?f, ?a) and
    scan_hit(?e, ?a) and scan_unique(?e) and
    field_owner(?field, ?owner) and owner_kind(?owner, "struct") and
    field_offset(?field, ?o) and
    loads_set(?e2, ?f, ?offs, 4) and
    contains(?offs, ?o);

rule writer_writes_struct_field:
  writes(?f, ?field) if
    fn_addr(?f, ?a) and
    scan_hit(?e, ?a) and scan_unique(?e) and
    field_owner(?field, ?owner) and owner_kind(?owner, "struct") and
    field_offset(?field, ?o) and
    stores_set(?e2, ?f, ?offs, 4) and
    contains(?offs, ?o);

// Packet fields require a dataflow certificate because the payload base is not
// recoverable from a single function's arithmetic. External evidence caps this
// at Observational.
rule packet_reader_traced:
  reads(?f, ?pf) if
    trace(?e, ?pf, ?f) and
    field_owner(?pf, ?p) and owner_kind(?p, "packet");

// ── RNG ────────────────────────────────────────────────────────────────────

// MT19937 announces itself with these three constants. Uniqueness in the
// declared window is checked by `constants(...) |> unique`.
rule mt19937_identified:
  algo(?r, "MT19937") if
    rng_addr(?r, ?a) and
    constants_window(?e, ?a, ?w) and
    constant_present(?e, 0x9908B0DF) and
    constant_present(?e, 0x9D2C5680) and
    constant_present(?e, 0xEFC60000) and
    constants_unique(?e);

// The model's own `algo:` field is a hypothesis, not a proof. This rule is
// deliberately capped at Heuristic; it lets exploratory models record an
// unproved algorithm choice without letting it seal.
rule algo_hypothesis cap heuristic:
  algo(?r, ?a) if rng_algo_decl(?r, ?a);

// A recovery witness re-checked by forward simulation, with at least two
// observed outputs.
rule recovery_witness:
  recovered(?r, ?i, ?h) if
    recovery_ok(?e, ?r, ?i) and
    recovery_horizon(?e, ?h) and
    ge(?h, 2);

// A literal `div` by a constant is a deterministic modular-bias witness.
rule modular_bias:
  biased(?d, ?m) if
    dist_site(?d, ?f) and
    fn_addr(?f, ?a) and
    scan_hit(?e, ?a) and scan_unique(?e) and
    modulo_op(?e2, ?f, ?m);

// ── exact anchors (symbol store) ──────────────────────────────────────────

rule exact_anchor:
  anchored(?f) if
    symbol_addr(?e, ?name, ?a) and
    fn_addr(?f, ?a) and fn_label(?f, ?name);

rule exact_layout:
  layout_exact(?s) if
    sym_struct_match(?e, ?s);

// ── audited absence and observability ─────────────────────────────────────

rule field_absent:
  absent_field(?field, ?scope, ?start, ?end) if
    absence_field(?e, ?field, ?scope, ?start, ?end);

rule observable_outputs:
  outputs_observable(?conn, ?window) if
    observability(?e, ?conn, ?window);

// ── refutation ─────────────────────────────────────────────────────────────

rule refuted_algo:
  refuted(?r, ?a) if
    sim_fail(?e, ?r, ?a);

// ── definitions ────────────────────────────────────────────────────────────

rule fn_defined:
  defined("fn", ?f) if
    fn_addr(?f, ?a) and scan_hit(?e, ?a) and scan_unique(?e);
"#;

pub fn stdlib_rules() -> Result<Vec<RuleDecl>, String> {
    let model = parse_model("<stdlib>", STDLIB)?;
    let mut rules = Vec::new();
    for item in model.items {
        if let Item::Rule(r) = item {
            rules.push(r);
        }
    }
    Ok(rules)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::facts::compile_rules;

    #[test]
    fn stdlib_parses_and_compiles() {
        let rules = stdlib_rules().unwrap();
        assert!(rules.len() >= 10);
        compile_rules(&rules).unwrap();
    }
}

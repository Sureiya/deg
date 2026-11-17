//! Ground facts, a small Datalog engine, and strength/provenance propagation.
//!
//! The engine is deliberately first-order and negation-free. Negation is only
//! ever admitted through *positive evidence of absence* (an audited external
//! certificate), because open-world negation over unbounded artifacts is how
//! reverse-engineering claims go wrong.
//!
//! Strength propagation is maximin: a derivation is as strong as its weakest
//! premise, capped by the rule's declared cap. When several derivations exist,
//! the strongest wins; ties keep the first derivation for stable explanations.

use crate::ast::{Atom, RuleDecl, Term};
use crate::strength::Strength;
use crate::value::Lit;
use crate::value::Value;
use std::collections::{BTreeMap, BTreeSet};

pub type Binding = BTreeMap<String, Value>;

#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord)]
pub struct FactKey {
    pub rel: String,
    pub args: Vec<Value>,
}

impl FactKey {
    pub fn new(rel: impl Into<String>, args: Vec<Value>) -> FactKey {
        FactKey {
            rel: rel.into(),
            args,
        }
    }

    pub fn display(&self) -> String {
        let args: Vec<String> = self.args.iter().map(Value::display).collect();
        format!("{}({})", self.rel, args.join(", "))
    }
}

#[derive(Debug, Clone)]
pub enum FactOrigin {
    Definition,
    Evidence(String),
    Rule(String),
}

#[derive(Debug, Clone)]
pub struct FactInfo {
    pub strength: Strength,
    pub support: BTreeSet<String>,
    pub origin: FactOrigin,
    pub parents: Vec<FactKey>,
}

impl FactInfo {
    pub fn is_definition(&self) -> bool {
        matches!(self.origin, FactOrigin::Definition)
    }
}

#[derive(Debug, Clone, Default)]
pub struct FactStore {
    facts: BTreeMap<FactKey, FactInfo>,
    by_rel: BTreeMap<String, Vec<FactKey>>,
}

impl FactStore {
    pub fn new() -> FactStore {
        FactStore::default()
    }

    pub fn len(&self) -> usize {
        self.facts.len()
    }

    pub fn is_empty(&self) -> bool {
        self.facts.is_empty()
    }

    pub fn get(&self, key: &FactKey) -> Option<&FactInfo> {
        self.facts.get(key)
    }

    pub fn contains(&self, key: &FactKey) -> bool {
        self.facts.contains_key(key)
    }

    pub fn relation(&self, rel: &str) -> Vec<(FactKey, FactInfo)> {
        match self.by_rel.get(rel) {
            Some(keys) => keys
                .iter()
                .filter_map(|k| self.facts.get(k).map(|i| (k.clone(), i.clone())))
                .collect(),
            None => Vec::new(),
        }
    }

    pub fn iter(&self) -> impl Iterator<Item = (&FactKey, &FactInfo)> {
        self.facts.iter()
    }

    pub fn insert_definition(&mut self, rel: &str, args: Vec<Value>) {
        let key = FactKey::new(rel, args);
        if self.facts.contains_key(&key) {
            return;
        }
        self.by_rel
            .entry(key.rel.clone())
            .or_default()
            .push(key.clone());
        self.facts.insert(
            key,
            FactInfo {
                strength: Strength::Exact,
                support: BTreeSet::new(),
                origin: FactOrigin::Definition,
                parents: Vec::new(),
            },
        );
    }

    pub fn insert_evidence(
        &mut self,
        rel: &str,
        args: Vec<Value>,
        strength: Strength,
        evidence: &str,
    ) {
        let key = FactKey::new(rel, args);
        let mut support = BTreeSet::new();
        support.insert(evidence.to_string());
        let exists = self.facts.contains_key(&key);
        if let Some(existing) = self.facts.get(&key) {
            if !existing.is_definition() && existing.strength >= strength {
                return;
            }
        }
        if !exists {
            self.by_rel
                .entry(key.rel.clone())
                .or_default()
                .push(key.clone());
        }
        self.facts.insert(
            key,
            FactInfo {
                strength,
                support,
                origin: FactOrigin::Evidence(evidence.to_string()),
                parents: Vec::new(),
            },
        );
    }

    fn insert_derived(
        &mut self,
        key: FactKey,
        strength: Strength,
        support: BTreeSet<String>,
        parents: Vec<FactKey>,
        rule: &str,
    ) -> bool {
        if let Some(existing) = self.facts.get(&key) {
            let existing_definition = existing.is_definition();
            if !existing_definition && existing.strength >= strength {
                return false;
            }
            if existing_definition && support.is_empty() {
                return false;
            }
        } else {
            self.by_rel
                .entry(key.rel.clone())
                .or_default()
                .push(key.clone());
        }
        self.facts.insert(
            key,
            FactInfo {
                strength,
                support,
                origin: FactOrigin::Rule(rule.to_string()),
                parents,
            },
        );
        true
    }
}

#[derive(Debug, Clone)]
pub struct CompiledRule {
    pub decl: RuleDecl,
}

pub fn compile_rules(rules: &[RuleDecl]) -> Result<Vec<CompiledRule>, String> {
    let mut out = Vec::new();
    let mut names = BTreeSet::new();
    for rule in rules {
        if !names.insert(rule.name.clone()) {
            return Err(format!("duplicate rule `{}`", rule.name));
        }
        if is_builtin(&rule.head.name) {
            return Err(format!(
                "rule `{}` uses builtin `{}` as its head relation",
                rule.name, rule.head.name
            ));
        }
        let mut body_vars = BTreeSet::new();
        let mut has_relation = false;
        for atom in &rule.body {
            for term in &atom.args {
                if let Term::Var(v) = term {
                    body_vars.insert(v.clone());
                }
                if let Term::Lit(Lit::Float(_)) = term {
                    return Err(format!(
                        "rule `{}` uses a float literal, which is not a fact value",
                        rule.name
                    ));
                }
            }
            if !is_builtin(&atom.name) {
                has_relation = true;
            }
        }
        if !has_relation {
            return Err(format!(
                "rule `{}` has no relational premise; tautological rules are not allowed",
                rule.name
            ));
        }
        for term in &rule.head.args {
            if let Term::Var(v) = term {
                if !body_vars.contains(v) {
                    return Err(format!(
                        "rule `{}` head variable ?{} is not bound by its body",
                        rule.name, v
                    ));
                }
            }
        }
        out.push(CompiledRule { decl: rule.clone() });
    }
    Ok(out)
}

pub fn instantiate_atom(atom: &Atom, binding: &Binding) -> Result<Vec<Value>, String> {
    let mut args = Vec::new();
    for term in &atom.args {
        match term {
            Term::Var(v) => {
                let val = binding
                    .get(v)
                    .ok_or_else(|| format!("unbound variable ?{v}"))?;
                args.push(val.clone());
            }
            Term::Lit(lit) => args.push(
                lit.to_value()
                    .map_err(|e| format!("cannot instantiate {}: {e}", lit.display()))?,
            ),
        }
    }
    Ok(args)
}

pub fn ground_key(atom: &Atom) -> Result<FactKey, String> {
    let mut args = Vec::new();
    for term in &atom.args {
        match term {
            Term::Var(v) => return Err(format!("goal contains unbound variable ?{v}")),
            Term::Lit(lit) => args.push(lit.to_value()?),
        }
    }
    Ok(FactKey::new(atom.name.clone(), args))
}

fn unify_term(term: &Term, value: &Value, binding: &Binding) -> Option<Binding> {
    match term {
        Term::Var(v) => match binding.get(v) {
            Some(bound) if bound == value => Some(binding.clone()),
            Some(_) => None,
            None => {
                let mut b = binding.clone();
                b.insert(v.clone(), value.clone());
                Some(b)
            }
        },
        Term::Lit(lit) => match lit.to_value() {
            Ok(v) if &v == value => Some(binding.clone()),
            _ => None,
        },
    }
}

fn unify_atom(atom: &Atom, args: &[Value], binding: &Binding) -> Option<Binding> {
    if atom.args.len() != args.len() {
        return None;
    }
    let mut b = binding.clone();
    for (term, value) in atom.args.iter().zip(args) {
        b = unify_term(term, value, &b)?;
    }
    Some(b)
}

/// Apply all rules to fixpoint. `store` already contains definitions and
/// evidence facts; derived facts are added until no fact improves.
pub fn fixpoint(store: &mut FactStore, rules: &[CompiledRule]) -> Result<(), String> {
    const MAX_FACTS: usize = 250_000;
    const MAX_ROUNDS: usize = 2_000;
    for round in 0..MAX_ROUNDS {
        let mut additions = Vec::new();
        for rule in rules {
            derive_rule(store, rule, &mut additions)?;
        }
        let mut changed = false;
        for (key, strength, support, parents, rule_name) in additions {
            if store.insert_derived(key, strength, support, parents, &rule_name) {
                changed = true;
            }
            if store.len() > MAX_FACTS {
                return Err(format!(
                    "fact store exceeded {MAX_FACTS} facts while applying rules (round {round})"
                ));
            }
        }
        if !changed {
            return Ok(());
        }
    }
    Err(format!(
        "rule fixpoint did not converge after {MAX_ROUNDS} rounds"
    ))
}

type Addition = (FactKey, Strength, BTreeSet<String>, Vec<FactKey>, String);

fn derive_rule(
    store: &FactStore,
    rule: &CompiledRule,
    additions: &mut Vec<Addition>,
) -> Result<(), String> {
    let mut premises: Vec<(FactKey, FactInfo)> = Vec::new();
    let binding = Binding::new();
    walk_body(store, rule, 0, binding, &mut premises, additions)
}

fn walk_body(
    store: &FactStore,
    rule: &CompiledRule,
    index: usize,
    binding: Binding,
    premises: &mut Vec<(FactKey, FactInfo)>,
    additions: &mut Vec<Addition>,
) -> Result<(), String> {
    if index == rule.decl.body.len() {
        let args = instantiate_atom(&rule.decl.head, &binding)
            .map_err(|e| format!("rule `{}`: {e}", rule.decl.name))?;
        let mut strength = rule.decl.cap.unwrap_or(Strength::Exact);
        let mut support = BTreeSet::new();
        let mut parents = Vec::new();
        for (key, info) in premises.iter() {
            strength = strength.meet(info.strength);
            support.extend(info.support.iter().cloned());
            parents.push(key.clone());
        }
        additions.push((
            FactKey::new(rule.decl.head.name.clone(), args),
            strength,
            support,
            parents,
            rule.decl.name.clone(),
        ));
        return Ok(());
    }

    let atom = &rule.decl.body[index];
    if is_builtin(&atom.name) {
        let bindings =
            eval_builtin(atom, &binding).map_err(|e| format!("rule `{}`: {e}", rule.decl.name))?;
        for b in bindings {
            walk_body(store, rule, index + 1, b, premises, additions)?;
        }
        return Ok(());
    }

    for (key, info) in store.relation(&atom.name) {
        if let Some(b) = unify_atom(atom, &key.args, &binding) {
            premises.push((key, info));
            walk_body(store, rule, index + 1, b, premises, additions)?;
            premises.pop();
        }
    }
    Ok(())
}

fn eval_builtin(atom: &Atom, binding: &Binding) -> Result<Vec<Binding>, String> {
    let arity_err = || {
        format!(
            "builtin `{}` called with {} argument(s)",
            atom.name,
            atom.args.len()
        )
    };
    let resolve = |term: &Term| -> Option<Value> {
        match term {
            Term::Var(v) => binding.get(v).cloned(),
            Term::Lit(l) => l.to_value().ok(),
        }
    };
    let get = |i: usize| resolve(&atom.args[i]);

    match atom.name.as_str() {
        "eq" => {
            if atom.args.len() != 2 {
                return Err(arity_err());
            }
            match (get(0), get(1)) {
                (Some(a), Some(b)) => Ok(if a == b {
                    vec![binding.clone()]
                } else {
                    vec![]
                }),
                (Some(a), None) => bind_term(&atom.args[1], a, binding),
                (None, Some(b)) => bind_term(&atom.args[0], b, binding),
                (None, None) => Err("eq requires at least one bound argument".into()),
            }
        }
        "contains" | "member" => {
            if atom.args.len() != 2 {
                return Err(arity_err());
            }
            let list = get(0).ok_or("contains requires a bound list")?;
            let items = list
                .as_list()
                .ok_or("contains requires a list as its first argument")?;
            let elem = get(1);
            let mut out = Vec::new();
            for item in items {
                match &elem {
                    Some(v) if v == item => out.push(binding.clone()),
                    Some(_) => {}
                    None => {
                        for b in bind_term(&atom.args[1], item.clone(), binding)? {
                            out.push(b);
                        }
                    }
                }
            }
            out.dedup();
            Ok(out)
        }
        "len" => {
            if atom.args.len() != 2 {
                return Err(arity_err());
            }
            let list = get(0).ok_or("len requires a bound list")?;
            let items = list.as_list().ok_or("len requires a list")?;
            bind_term(&atom.args[1], Value::Int(items.len() as i128), binding)
        }
        "lt" | "le" | "gt" | "ge" => {
            if atom.args.len() != 2 {
                return Err(arity_err());
            }
            let a = get(0)
                .and_then(|v| v.as_int())
                .ok_or("comparison needs a bound number")?;
            let b = get(1)
                .and_then(|v| v.as_int())
                .ok_or("comparison needs a bound number")?;
            let ok = match atom.name.as_str() {
                "lt" => a < b,
                "le" => a <= b,
                "gt" => a > b,
                "ge" => a >= b,
                _ => unreachable!(),
            };
            Ok(if ok { vec![binding.clone()] } else { vec![] })
        }
        "add" | "sub" | "mul" | "div" => {
            if atom.args.len() != 3 {
                return Err(arity_err());
            }
            let a = get(0).and_then(|v| v.as_int());
            let b = get(1).and_then(|v| v.as_int());
            let c = get(2).and_then(|v| v.as_int());
            let op = |x: i128, y: i128| -> Result<i128, String> {
                match atom.name.as_str() {
                    "add" => Ok(x + y),
                    "sub" => Ok(x - y),
                    "mul" => Ok(x * y),
                    "div" => {
                        if y == 0 {
                            Err("division by zero".into())
                        } else {
                            Ok(x / y)
                        }
                    }
                    _ => unreachable!(),
                }
            };
            match (a, b, c) {
                (Some(x), Some(y), _) => bind_term(&atom.args[2], Value::Int(op(x, y)?), binding),
                (Some(x), None, Some(z)) => {
                    // z = x op y
                    let y = match atom.name.as_str() {
                        "add" => z - x,
                        "sub" => x - z,
                        "mul" => {
                            if x == 0 {
                                return Err("cannot invert multiplication by zero".into());
                            }
                            z / x
                        }
                        "div" => {
                            if z == 0 {
                                return Err("cannot invert division by zero".into());
                            }
                            x / z
                        }
                        _ => unreachable!(),
                    };
                    bind_term(&atom.args[1], Value::Int(y), binding)
                }
                (None, Some(y), Some(z)) => {
                    let x = match atom.name.as_str() {
                        "add" => z - y,
                        "sub" => z + y,
                        "mul" => {
                            if y == 0 {
                                return Err("cannot invert multiplication by zero".into());
                            }
                            z / y
                        }
                        "div" => z * y,
                        _ => unreachable!(),
                    };
                    bind_term(&atom.args[0], Value::Int(x), binding)
                }
                _ => Err(format!(
                    "builtin `{}` needs at least two bound arguments",
                    atom.name
                )),
            }
        }
        "abs_diff" => {
            if atom.args.len() != 3 {
                return Err(arity_err());
            }
            let a = get(0)
                .and_then(|v| v.as_int())
                .ok_or("abs_diff needs bound numbers")?;
            let b = get(1)
                .and_then(|v| v.as_int())
                .ok_or("abs_diff needs bound numbers")?;
            bind_term(&atom.args[2], Value::Int((a - b).abs()), binding)
        }
        "min" | "max" => {
            if atom.args.len() != 3 {
                return Err(arity_err());
            }
            let a = get(0)
                .and_then(|v| v.as_int())
                .ok_or("min/max needs bound numbers")?;
            let b = get(1)
                .and_then(|v| v.as_int())
                .ok_or("min/max needs bound numbers")?;
            let v = if atom.name == "min" {
                a.min(b)
            } else {
                a.max(b)
            };
            bind_term(&atom.args[2], Value::Int(v), binding)
        }
        "within" => {
            if atom.args.len() != 3 {
                return Err(arity_err());
            }
            let a = get(0)
                .and_then(|v| v.as_int())
                .ok_or("within needs bound numbers")?;
            let b = get(1)
                .and_then(|v| v.as_int())
                .ok_or("within needs bound numbers")?;
            let tol = get(2)
                .and_then(|v| v.as_int())
                .ok_or("within needs a bound tolerance")?;
            Ok(if (a - b).abs() <= tol {
                vec![binding.clone()]
            } else {
                vec![]
            })
        }
        other => Err(format!("unknown builtin `{other}`")),
    }
}

fn bind_term(term: &Term, value: Value, binding: &Binding) -> Result<Vec<Binding>, String> {
    match term {
        Term::Var(v) => {
            if let Some(bound) = binding.get(v) {
                Ok(if *bound == value {
                    vec![binding.clone()]
                } else {
                    Vec::new()
                })
            } else {
                let mut b = binding.clone();
                b.insert(v.clone(), value);
                Ok(vec![b])
            }
        }
        Term::Lit(lit) => {
            let v = lit.to_value()?;
            Ok(if v == value {
                vec![binding.clone()]
            } else {
                Vec::new()
            })
        }
    }
}

pub fn is_builtin(name: &str) -> bool {
    matches!(
        name,
        "eq" | "contains"
            | "member"
            | "len"
            | "lt"
            | "le"
            | "gt"
            | "ge"
            | "add"
            | "sub"
            | "mul"
            | "div"
            | "abs_diff"
            | "min"
            | "max"
            | "within"
    )
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::lexer::Span;
    use crate::parser::parse_model;

    fn rule(src: &str) -> RuleDecl {
        let m = parse_model("<test>", src).unwrap();
        match m.items.into_iter().next().unwrap() {
            crate::ast::Item::Rule(r) => r,
            _ => panic!("not a rule"),
        }
    }

    fn fact(rel: &str, args: Vec<Value>) -> FactKey {
        FactKey::new(rel, args)
    }

    #[test]
    fn derives_with_join_and_strength() {
        let r = rule(
            "rule reads_field: reads(?f, ?field) if field_offset(?field, ?o) and loads(?f, ?offs, 4) and contains(?offs, ?o);",
        );
        let rules = compile_rules(&[r]).unwrap();
        let mut store = FactStore::new();
        store.insert_definition("field_offset", vec![Value::sym("Vec3.z"), Value::Int(8)]);
        store.insert_evidence(
            "loads",
            vec![
                Value::sym("read_position"),
                Value::list(vec![Value::Int(0), Value::Int(8)]),
                Value::Int(4),
            ],
            Strength::Deterministic,
            "e_shape",
        );
        store.insert_definition(
            "fn_addr",
            vec![Value::sym("read_position"), Value::Int(0x1000)],
        );
        fixpoint(&mut store, &rules).unwrap();
        let key = fact(
            "reads",
            vec![Value::sym("read_position"), Value::sym("Vec3.z")],
        );
        let info = store.get(&key).expect("fact was not derived");
        assert_eq!(info.strength, Strength::Deterministic);
        assert!(info.support.contains("e_shape"));
    }

    #[test]
    fn rule_cap_caps_the_conclusion() {
        let r = rule(
            "rule weak cap heuristic: reads(?f, ?x) if loads(?f, ?offs, 4) and field_offset(?x, ?y);",
        );
        let rules = compile_rules(&[r]).unwrap();
        let mut store = FactStore::new();
        store.insert_evidence(
            "loads",
            vec![
                Value::sym("f"),
                Value::list(vec![Value::Int(0)]),
                Value::Int(4),
            ],
            Strength::Exact,
            "e",
        );
        store.insert_definition("field_offset", vec![Value::sym("Vec3.z"), Value::Int(8)]);
        fixpoint(&mut store, &rules).unwrap();
        let info = store
            .iter()
            .find(|(k, _)| k.rel == "reads")
            .map(|(_, i)| i)
            .expect("reads should derive");
        assert_eq!(info.strength, Strength::Heuristic);
    }

    #[test]
    fn rejects_unbound_head_variables() {
        let r = rule("rule bad: reads(?f, ?o) if loads(?f, ?offs, 4);");
        assert!(compile_rules(&[r]).is_err());
    }

    #[test]
    fn definitions_do_not_count_as_evidence() {
        let r = rule("rule d: reads(?o, ?x) if field_offset(?o, ?x);");
        let rules = compile_rules(&[r]).unwrap();
        let mut store = FactStore::new();
        store.insert_definition("field_offset", vec![Value::sym("Vec3.z"), Value::Int(8)]);
        fixpoint(&mut store, &rules).unwrap();
        let info = store
            .iter()
            .find(|(k, _)| k.rel == "reads")
            .map(|(_, i)| i)
            .unwrap();
        assert!(info.support.is_empty());
    }

    #[test]
    fn unification_handles_repeated_variables() {
        let r = rule("rule same: p(?x) if q(?x, ?x);");
        let rules = compile_rules(&[r]).unwrap();
        let mut store = FactStore::new();
        store.insert_evidence(
            "q",
            vec![Value::Int(1), Value::Int(2)],
            Strength::Exact,
            "e",
        );
        store.insert_evidence(
            "q",
            vec![Value::Int(3), Value::Int(3)],
            Strength::Exact,
            "e",
        );
        fixpoint(&mut store, &rules).unwrap();
        assert!(store.contains(&fact("p", vec![Value::Int(3)])));
        assert!(!store.contains(&fact("p", vec![Value::Int(1)])));
    }

    #[test]
    fn no_rule_means_no_derivation() {
        let mut store = FactStore::new();
        store.insert_evidence("loads", vec![Value::Int(1)], Strength::Exact, "e");
        fixpoint(&mut store, &[]).unwrap();
        assert!(!store.contains(&fact("reads", vec![Value::Int(1)])));
        let _ = Span::new(1, 1, 0);
    }
}

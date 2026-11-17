# DeG — semantics

This document states the checking judgments implemented by `deg`. It is
deliberately small: a finite fact set, a negation-free rule language, a
five-point strength lattice, and a partial port relation. The implementation is
in `src/facts.rs` and `src/kernel.rs`.

## 1. Notation

| Symbol | Meaning |
|---|---|
| `A` | the set of declared artifacts, each with a SHA-256 digest |
| `H(a)` | the digest computed from the bytes of artifact `a` |
| `E` | an evidence declaration and its evaluation |
| `F` | a set of ground facts |
| `R` | the set of rules named by a proof |
| `s` | a strength in the lattice |
| `σ(f)` | the evidence support set of fact `f` |
| `D(f)` | the set of derivations of `f` in the closure |
| `⊓` | lattice meet (minimum) |
| `⊔` | lattice join (maximum) |

Fact keys are `(relation, value list)`. Values are integers, booleans, symbols
(including model references), strings-as-symbols, byte strings, lists, and
microsecond durations. Floating-point values are not facts; measurements are
integers, and statistics are computed in `stats`.

## 2. Artifact and evidence judgments

### 2.1 Artifact verification

```
A ⊢ a : H(a)        if sha256(bytes(a)) = H(a)
```

The kernel loads every declared artifact and computes SHA-256. If the digest
does not match, the artifact is marked unverified, a hard error is recorded, and
no evidence may use it. The digest is the only path from a model to bytes.
Symbol stores and external certificate files are *inputs* rather than declared
artifacts in v0.1; a certificate must carry the build digest, and a symbol store
must match it, but the files themselves are not signed or content-addressed.

### 2.2 Evidence evaluation

```
A; E ⇓ (F_E, s_E, cert_E)
```

`F_E` is a finite set of ground facts, `s_E` is the strength the evaluator
assigns to all of them, and `cert_E` is the audit detail printed by `deg
explain`/`deg report` (addresses, counts, windows, decoded instructions,
simulation results). Evaluation is deterministic for a fixed artifact set and
declaration.

The strength assignment is fixed per primitive:

| Primitive | `s_E` |
|---|---|
| `scan`, unique | `Deterministic` |
| `scan`, not unique | `Heuristic` |
| `bytes`, exact | `Deterministic` |
| `decode`, complete subset | `Deterministic` |
| `decode`, partial | `Heuristic` |
| `constants`, all unique | `Deterministic` |
| `constants`, present not unique | `Heuristic` |
| `modulo`, found | `Deterministic` |
| `recovery`, ≥2 matching outputs | `Deterministic` |
| `recovery`, 1 matching output | `Heuristic` |
| `recovery`, mismatch | `Deterministic` (a `sim_fail` observation) |
| `rate`, stationary | `Observational` |
| `rate`, nonstationary | `Heuristic` |
| `sample` | `Observational` |
| `samples` | `Observational` |
| `symbols`, build and type match | `Exact` (store is a trusted input) |
| `external` | `Observational` |
| `absence` | `Observational` |

A failed evaluator produces no facts. Failures are hard errors in `deg check`
when the evidence is declared, even if unused; a model with a broken evidence
term has a broken audit trail.

The **external cap** is a kernel invariant, not a convention:

> If `f ∈ F_E` comes only from an `external` or `absence` evaluator, then
> `s(f) ≤ Observational`.

The same invariant holds for statistical evidence:

> If `f` comes only from `rate`, `sample`, or `samples` evaluators, then
> `s(f) ≤ Observational`.

## 3. Fact closure

A rule is a Horn clause without negation:

```
h(?x, ?y) ← b1(…) ∧ b2(…) ∧ … ∧ g(…)
```

where `g` is a built-in. A substitution `θ` grounds the variables. Applying a
rule at `θ` derives `hθ` with premises `b_iθ` and built-in side conditions.

The closure `F*` is the least fixpoint of the rules `R` over the initial facts
`F0 = definitions ∪ evidence`. The implementation iterates rounds until no fact
improves; a derivation with a lower or equal strength than the existing fact is
not inserted again.

Definitions and evidence are the only initial facts. There is no built-in fact
that asserts a code property; a user rule may only derive from what is present.

**Termination.** The value universe is finite for a fixed model and artifact
set (model refs, addresses reachable from evidence, constants in evidence).
Rules can generate integer arithmetic values in principle; the implementation
caps the store at 250,000 facts and 2,000 rounds and reports an error rather
than looping. The language deliberately excludes function symbols that would
make the Herbrand universe infinite.

## 4. Strength algebra

Let `s0(f)` be `s_E` for an evidence fact, `Exact` for a definition, and
undefined otherwise. The strength of a derived fact is the **maximin**:

```
s(f) = max over derivations d ∈ D(f) of
         min( cap(rule(d)), min over premises p ∈ prem(d) of s(p) )
```

and the support is the union of the supports of the premises:

```
σ(f) = ∪_{p ∈ prem(d)} σ(p)
```

Definitions have `σ = ∅`. A fact derived only from definitions therefore has
`σ = ∅`; the kernel reports it as a hypothesis and refuses to seal it. This is
the formal content of “definitions are assumptions.”

Properties:

1. **Monotonicity.** Adding evidence or rules cannot decrease `s(f)` or remove
   a fact from `F*`. Removing evidence can. (The implementation's fixpoint is
   monotone in this sense; conflict demotion is a separate post-pass and does
   not change `s`.)
2. **Weakest-link.** For every derivation, `s(f)` is at most the minimum of its
   premise strengths and the rule cap.
3. **Cap inheritance.** If a rule has `cap = Heuristic`, every conclusion is at
   most `Heuristic`. If a premise is Observational (external/statistical), the
   conclusion is at most Observational, even if the rule says `Exact`.
4. **Support locality.** `σ(f)` contains only evidence names; definitions never
   appear in a support set. The seal manifest can therefore replay the exact
   evidence set for a sealed claim.

The lattice operations are `meet = min` and `join = max` on the five-point
chain `Speculative < Heuristic < Observational < Deterministic < Exact`. The
`⊓`/`⊔` notation above is only suggestive; the implementation uses `min`/`max`.

## 5. Proof judgment

A proof declaration is:

```
proof P : φ in b {
  evidence e1, …, en;
  rules    r1, …, rk;
  [expect >= s_min;]
}
```

Define:

```
E_P = { e_i }                     (named evidence)
R_P = { r_j }                     (named rules)
F0  = definitions(b) ∪ ⋃_{e ∈ E_P} F_e
F*  = lfp(R_P, F0)
```

The proof is **accepted at strength `s`** if:

1. every `e ∈ E_P` evaluated successfully;
2. the goal `φ` is ground and `φ ∈ F*`;
3. `σ(φ) ≠ ∅` (some evidence supports it);
4. if `expect` is present, `s(φ) ≥ s_min`.

Otherwise the proof fails with the available facts of the goal relation. The
kernel does not search for other rules or evidence.

A proof is **sealed** when `s(φ) ≥ seal_threshold` and the claim is not demoted
by a conflict. Otherwise it is a **hypothesis** (or provisional if it came from
a provisional chain; proofs themselves do not have provisional syntax in v0.1).

## 6. Certificate claims

Certificate claims are not Datalog proofs. They are checked procedures over the
`Measured` payload of one evidence term.

### 6.1 Period

Given evidence `rate` with measured `(period, ci95, coverage, n, stationary)`,
claim `period(clock, stream) ~ T ± ε during c by e` checks:

```
opcode(e) = stream
clock(e) = clock                    (when the evidence declares one)
capture(e) = c
|period - T| ≤ ε
ε ≥ ci(confidence)                  (the claim is not tighter than the evidence)
coverage ≥ coverage_required
n ≥ samples_required
stationary = true
```

If all hold, the claim is **Observational** (never higher). Nonstationarity
demotes it to Heuristic and makes it a hypothesis. A value mismatch or a
tolerance tighter than the CI is a hard failure. `confidence` rescales the 95%
CI via the normal quantile `z = Φ⁻¹(1 − (1−c)/2)`; the default is 0.95.

The kernel does **not** prove the period of the game clock. It proves that the
hashed capture's filtered UDP timestamps have a median and CI consistent with
the claim, and that the estimator's coverage/stationarity requirements hold.

### 6.2 Uniformity

Given `sample` counts over `k = bins` categories, `n = Σ counts`, the kernel:

1. checks the evidence capture is the claim's `during`;
2. checks the distribution declaration's `bins` equals `k`;
3. rejects any observed value `≥ k` (a value outside the claimed support);
4. pads missing categories with zero counts and computes
   `χ² = Σ (o_i − n/k)² / (n/k)`, `df = k − 1`;
5. computes `p = Q(df/2, χ²/2)` (regularized upper incomplete gamma);
6. rejects uniformity if `p < alpha` (default 0.05);
7. if `power` and `delta` are declared, computes the conservative
   worst-bin sample size
   `n* = ⌈(z_{1−α/2}√(p0(1−p0)) + z_{power}√(p1(1−p1)))² / (p1−p0)²⌉`
   with `p0 = 1/k`, `p1 = p0 + delta`, and marks the claim underpowered if
   `n < n*` (a hypothesis, not a hard failure);
8. checks coverage/sample requirements.

The result is **Observational**. There is no code path from a p-value to a
higher strength. A uniform claim is not a proof of uniformity; it is a
procedure-checked failure to reject. This is the statistical asymmetry encoded
in the kernel.

### 6.3 Mean

`samples` evidence over a verified dataset with a value column (and an
optional group column) produces, per group `g`:

```
n_g = |{ rows with group g }|
mean_g = Σ x / n_g
median_g, sd_g (n-1 denominator, n ≥ 2)
ci95_g = 1.96 · sd_g / √n_g          (0 when n = 1, with a detail note)
```

These are emitted as facts `samples_group(e, g)`, `samples_n(e, g, n)`, and
`*_milli(e, g, v)` facts for the mean/median/sd/CI (milli-scaled rounded
integers), plus a `Measured::Samples` payload. The evidence strength is
`Observational`.

A claim `mean(m) ~ μ ± ε` (where `m` is a group symbol, or `""` for a
group-less evidence term) checks, for the group named `m`:

```
|mean_m − μ| ≤ ε
ε ≥ ci95_m · Φ⁻¹(1 − (1−c)/2) / 1.96        (confidence c, default 0.95)
n_m ≥ samples_required                       (when declared)
n_m ≥ ((z_{1−0.05/2} + z_power) · sd_m / δ)² (when power/δ declared)
```

`alpha` is fixed at 0.05 for mean claims in v0.1; there is no alpha
requirement syntax for them. A mean mismatch or a tolerance tighter than the
evidence CI is a hard failure; a sample shortfall or an underpowered test is a
hypothesis. The result strength is `Observational`; sealing follows the
provisional-until rules of the other statistical claims.

## 7. Coverage claims

A claim `coverage(ds, target: T) from P₁, …, Pₖ` is a counting judgment over a
locked dataset, in which the kernel never invents the universe:

```
ids(ds)       = distinct integers in ds (hex 0x… allowed; blank/# ignored)
F(P₁)         = rel of P₁'s ground goal          (the relation family)
covered       = { arg₀(Pᵢ) : ∀i }                (each must be ∈ ids(ds))
missing       = ids(ds) \ covered
```

Every premise must be Sealed or Provisional with a ground goal, and every
premise must share the family relation and cover an ID from the dataset. The
claim is:

- **Failed** if a premise is failed/refuted/stale/open/hypothesis (named in
  the error), lacks a ground goal, leaves the family, or covers an ID outside
  the dataset;
- **Hypothesis** if `missing ≠ ∅` (“covered N/T; missing: …”, up to 32 IDs
  named) or if `|covered| ≠ T` (“covered N/T; dataset fully covered but the
  target is not met”);
- **Sealed** (or Provisional, propagating premise expiries) when
  `covered ⊇ ids(ds)` and `|covered| = T`.

The strength is `⊓` of the premise strengths; the weakest premise is the
bottleneck. `covered`, `target`, and `missing` are recorded in the JSON report
and the lock.

## 8. Decisions

A `decision D := decision(path, sha256: h, prefer: A, over: B, signer: s)` is a
content-addressed human judgment:

```
D ok        if sha256(bytes(resolve(path))) = h      (case-insensitive)
```

A missing file or digest mismatch is a hard error and `D` is not usable.
Decisions do not emit facts; they are recorded in the report and lock.

## 9. Conflicts

A conflict exists when two *active* claims (Sealed, Provisional, or Hypothesis)
are declared conflicting, or when the kernel auto-detects a uniform/biased pair
over the same distribution.

A `conflict` declaration `conflict C : A vs B [prefer P | decision D] [reason
"…"]` resolves the conflict by demoting the non-preferred side to Hypothesis.
The preferred side is `prefer P` (one of the sides), or — when the declaration
names a decision — `D.prefer` if `D` is ok and `{D.prefer, D.over}` equals the
conflict's sides in some order. The demotion changes the claim's **status**,
not its computed strength: the proof may still be a valid procedure, but it is
not treated as a sealed model fact when the resolution says otherwise. An
undeclared pair (or a declaration that cannot be resolved) is unresolved; it is
a warning in `deg check` and a hard blocker in `deg seal`.

The choice of preference is not made by the kernel. The researcher records the
reason (or a hash-pinned decision file); the kernel records the resolution and
the demotion.

## 10. Obligations

An obligation `O : φ priority p [blocks seal]` is resolved if:

- a declaration `obligation O resolved by C;` names a claim `C` with status
  Sealed or Provisional, or
- a claim with the same ground goal `φ` is Sealed or Provisional.

Otherwise it is open. If `blocks_seal` is set, an open obligation prevents
`deg seal`. Obligations do not affect proof strength; they are the accounting
of what is not proved.

## 11. Refutation

A refutation `refute R : algo(rng, A) by e` requires the evidence `e` to emit
`sim_fail(e, rng, A)`. Since `sim_fail` is a deterministic observation of a
mismatch, the refutation is sealed at Deterministic. Any claim with the same
ground goal is marked Refuted. A refutation is not negated Datalog: it is a
positive fact about a mismatch, which is why it does not require general
negation.

Any other ground goal `φ = rel(v₁, …, vₙ)` is refuted when the evidence emits

```
contradicts(e, rel, [v₁, …, vₙ])
```

with the goal's relation and argument list. The refutation is recorded at
`min(s_E, Deterministic)`: core primitives may emit `contradicts` at their own
strength in the future, while extensions can emit it today through an external
certificate's generic `facts` array (capped at Observational). When that
strength is below the seal threshold the contradiction is **recorded as a
hypothesis** with the note “strength … is below the seal threshold …; the
contradiction is recorded but cannot seal” — it never seals, exactly like any
other weak claim. A refutation whose evidence carries no matching
`contradicts` fact fails, listing the `contradicts` facts that were available.
A sealed refutation marks any claim with the same ground goal Refuted.

## 12. Port judgment

Porting is a partial relation

```
port(A_b1, A_b2, P) ⇓ (status, s', obligations)
```

For each claim/proof `P` from the source build:

1. **Re-anchor.** Re-run a scan evidence against the target. If the pattern is
   still unique, the evidence is Deterministic at the new address.
2. **Rebase.** If a scan fails and a `rebase` rule maps an old function/rng
   address to a target address by structural similarity, synthesize a
   **Heuristic** scan hit and a `unique(target, addr)` obligation. A rebase
   never produces Deterministic.
3. **Replay.** Re-run decode/constants/modulo/bytes evidence against the target
   at the mapped address. A complete decode remains Deterministic; a missing
   constant fails.
4. **Re-simulate.** A recovery witness is re-run against a target observed
   dataset only if the port block declares `revalidate … with …`. A mismatch
   fails the proof loudly.
5. **Statistical staleness.** `rate`/`sample` claims from another build are
   stale unless a replacement capture is explicitly declared; v0.1 still marks
   them stale for manual re-derivation.
6. **Recompute derived claims.** A derived claim is recomputed from the ported
   premises; a stale premise yields a stale derived claim.
7. **Report.** Every claim is `ported`, `demoted`, `stale`, `failed`, or
   `unchanged`. The model source is not rewritten.

The port relation is intentionally not a theorem-preserving compilation. It is
a report that tells you which obligations must be discharged before the target
model can be sealed again.

## 13. Seal judgment

`deg seal` writes a lock only if:

```
for every artifact a: H(a) = declared(a)
for every decision d: sha256(bytes(d)) = declared(d)
for every claim c:
  c is Sealed, or Provisional with a future expiry
  and (c is a hypothesis only if --strict is not given)
for every blocking obligation: resolved
for every conflict: resolved by a prefer clause or a verified decision
```

`--strict` additionally requires every claim to be Sealed or Provisional; by
default hypotheses are recorded in the lock under `"hypotheses"` with their
status and note. This is the “seal what you can, honestly” policy.

The lock is deterministic: it contains no timestamps other than the declared
provisional expiry, and all maps are sorted. The artifact digests and claim
support sets make it reproducible.

## 14. Soundness and its limits

The kernel's guarantee, stated without overclaiming:

> If `deg check` reports a claim as sealed at strength `s`, then the claim is
> the conclusion of the named rules applied to facts emitted by the named
> evidence evaluators, each of which replayed against a verified artifact, and
> `s` is a lower bound on the maximin strength of that derivation. If the claim
> is certificate-based, the kernel checked the stated statistical procedure
> against the measured samples.

It is **not** a guarantee that:

- the model is the only interpretation of the game;
- an external certificate (trace, absence, observability) is true — only that
  it is bound to the build digest and capped at Observational;
- a statistical claim holds beyond its capture window;
- a definition (layout, function address, RNG site) is the ground truth — it is
  an assumption audited in the lock;
- a user rule is sound for the real binary — rules are part of the trusted
  specification of that model.

Those limitations are the reason the strength lattice, support sets,
bottlenecks, obligations, and external caps exist. The kernel's job is not to
remove uncertainty; it is to make uncertainty **explicit, comparable, and
reproducible**.

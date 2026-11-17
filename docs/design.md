# DeG — design

> Status: **v0.1 working kernel + deliberate prototype**. This document is the
> language design. The implementation matrix is at the end; anything labelled
> *designed, not implemented* has no code path yet and is called out honestly.

## 1. The problem

Reverse engineering a live game produces claims:

- `Player.position` is a `Vec3` at RVA `0x140012345`;
- opcode `0x1F4` carries authoritative position;
- the loot RNG is MT19937 seeded with `time()`;
- the server never validates the client's movement rate;
- an attacker who observes 32 rolls can predict the next one.

Today those claims live in notes, IDA renames, scripts, and forum posts. They
are not reproducible, their evidence is not auditable, and they silently rot at
every patch. Worse, the confidence of a claim is usually implicit: a byte
pattern that happens to match once is treated like a PDB symbol.

DeG makes the claim, the evidence, the derivation, the confidence, and the
patch history **first-class artifacts**.

The one-sentence pitch:

> DeG is a Datalog-with-certificates where struct layouts, packet formats, and
> trust boundaries are claims that must be re-derived from hashed artifacts,
> and where “the patch broke my offsets” is a compile error with a suggested
> fix, not a weekend of work.

## 2. Goals and non-goals

### Goals

1. **Artifact-grounded.** Every claim bottoms out in bytes of a binary, a packet
   capture, a memory dump, or a content-addressed derived dataset — never prose.
2. **Sound by construction, honest about uncertainty.** A byte scan is not a
   proof. The language has a real strength lattice and refuses to seal a model
   on evidence below its declared threshold.
3. **Version-scoped.** Nothing is true “in general”; things are true in a
   **build**. Patches are a first-class operation.
4. **Small trusted kernel.** Expensive analyses (disassembly, dataflow, SMT,
   algebraic state recovery) run outside the kernel and must emit certificates
   the kernel can re-check or cap.
5. **Security claims are in scope.** Trust-boundary reasoning is the point of
   most game reverse engineering; the language expresses it, not a footnote.
6. **Auditable.** A seal is a lock file listing every artifact digest, claim,
   strength, support set, definition assumption, obligation, and conflict
   resolution.

### Non-goals

- DeG is **not a decompiler, symbolic executor, or packet parser generator**.
  It consumes their results as evidence.
- It does **not** decide whether a packet field is “fun” or “visible to the
  player”; it checks structural, control-flow, timing, and cryptographic claims.
- It does **not** attempt a general-purpose logic. Quantifiers beyond
  scope-limited absence are deliberately excluded; the kernel must stay
  decidable and small.
- It is **not a live cheat or injector**. It reasons about artifacts.

## 3. Architecture and trust model

```
┌──────────────────────────────────────────────────────────────┐
│ SEAL / PORT   model.lock.json · port report · obligations    │
├──────────────────────────────────────────────────────────────┤
│ CLAIMS        relational proofs · certificate claims ·       │
│               derived security claims · conflicts · refutes  │
├──────────────────────────────────────────────────────────────┤
│ FACTS + RULES ground atoms · maximin strength · provenance   │
├──────────────────────────────────────────────────────────────┤
│ EVIDENCE      scans · bytes · decode · constants · modulo ·  │
│               simulation · rate · sample · certificates      │
├──────────────────────────────────────────────────────────────┤
│ ARTIFACTS     binaries · pcaps · dumps · datasets (SHA-256)  │
└──────────────────────────────────────────────────────────────┘
```

There are two trust boundaries:

1. **Artifact boundary.** Every artifact is addressed by SHA-256. If the digest
   does not match, no evidence is replayed against it. Derived datasets (for
   example, “64 MT outputs observed from connection 7”) are themselves
   artifacts and carry a provenance edge to the capture they came from.
2. **Kernel boundary.** The kernel implements a fixed set of evidence
   primitives. Everything else enters as an **external certificate**. The kernel
   checks the certificate's schema and build binding, but not its analysis, so
   external evidence is capped at `Observational`.

Rules are part of the trusted specification. A proof names the rules it uses,
and `deg stdlib` prints the standard library. A user rule is an explicit,
auditable axiom of that model, not an invisible tactic. The kernel never
searches for “some rule that makes the goal true”; it applies exactly the rules
the proof names.

### Definitions are assumptions, not theorems

A model declaration introduces **definitional facts**:

```dg
struct Vec3 in b1 { x: f32 @ 0; y: f32 @ 4; z: f32 @ 8; } size 12 align 4;
fn read_position in b1 at 0x140001000;
```

These facts (`field_offset(Vec3.z, 8)`, `fn_addr(read_position, 0x140001000)`)
are needed to state claims, but they are not evidence. They are recorded as
**Exact assumptions** for the purpose of combining strengths, and the report
audits which definitions have a justification (`layout_exact(Vec3)`,
`anchored(read_position)`, `algo(srv_rng, MT19937)`) and which do not. A proof
whose support set contains **no evidence** cannot seal, even if its goal follows
from definitions alone.

This is the honest compromise: a layout declaration is not magically a proof of
the layout, but the language does not pretend the declaration is invisible
either. The seal manifest lists every assumption and its justification status.

## 4. Artifacts

```dg
build b1 = binary("../fixtures/game-b1.bin",
  sha256: "470d…", arch: x86_64,
  load: 0x140000000, text: 0x140001000..0x140001400);

capture c1 = capture("../fixtures/session-b1.pcap",
  sha256: "c9c0…", build: b1);

dataset ds_state = dataset("../fixtures/mt-state-b1.txt",
  sha256: "c306…", build: b1);
```

- **build** — a raw image with a virtual load base and an optional `.text`
  virtual range. Scans operate on the declared range; `bytes`/`decode` map
  virtual addresses to file offsets.
- **capture** — a pcap (Ethernet or raw IPv4, UDP). `rate` and `sample` read
  timestamps and payload fields from it.
- **dump** — a raw memory image with a virtual base, for `bytes` evidence.
- **dataset** — a content-addressed text file (integers, one or more per line).
  Used for RNG state/output witnesses and as a place to commit derived samples.
  A dataset may declare `from: c1` to record provenance.

Virtual addresses are used throughout. For a build with `load = L`, the file
offset of virtual address `v` is `v - L`; the `.text` range is virtual. This
keeps model files readable (`0x140001000`) without requiring PE/ELF parsing in
the kernel.

## 5. Evidence

An evidence declaration is named, evaluated once, and produces ground facts plus
a **strength computed by the kernel**:

```dg
ev e_anchor := scan(b1, ".text", "48 B8 44 65 47 21 62 31 00 00") |> unique;
ev e_shape  := decode(b1, read_position, count: 8);
ev e_recover := recovery(srv_rng, state: ds_state, index: 624, observed: ds_obs);
```

### Evidence primitives (implemented)

| Evidence | Certificate / check | Strength |
|---|---|---|
| `scan(build, ".text", pattern)` | byte-pattern sweep; `\|> unique` requires exactly one hit over the whole declared section | Deterministic if unique, else Heuristic |
| `bytes(artifact, at, expect)` | exact bytes at a virtual address in a hashed build/dump | Deterministic |
| `decode(build, fn, count)` | narrow x86-64 decoder: scalar/SSE loads and stores, small integer idioms; emits `loads_set`/`stores_set` by width and offset | Deterministic if the whole requested window decoded, else Heuristic |
| `constants(build, at, window, values)` | each constant present, counts derived from bytes; `\|> unique` requires one occurrence each | Deterministic if unique, else Heuristic |
| `modulo(build, fn, modulus)` | literal `mov reg, imm; …; div reg` in the function; emits `modulo_op` | Deterministic |
| `recovery(rng, state, index, observed, projection)` | forward-simulates LCG / xorshift32 / xorshift128 / MT19937 from a witness state, compares outputs (optionally projected bits) to a hashed dataset | Deterministic (Heuristic for a single output) |
| `rate(capture, opcode, clock)` | pcap timestamps, median inter-arrival, MAD-based CI, coverage, split-half stationarity | Observational (Heuristic if nonstationary) |
| `sample(capture, opcode, field, width, endian)` | payload field extraction, histogram, coverage | Observational |
| `symbols(build, store)` | store build digest must match; symbols and PDB-like types compared exactly to the model | Exact |
| `external(path, kind, build)` | certificate schema + build digest; **analysis not re-run** | Observational |
| `absence(path, build, scope, during)` | audited absence certificate: scope inside `.text`, time window inside the capture, no listed writes | Observational |

The x86 decoder is deliberately narrow. Anything outside its subset makes the
evidence **partial** and caps it at Heuristic. This is better than a fake
disassembler: a real disassembler can still be used, but it enters as an
external certificate capped at Observational.

External certificate kinds in v0.1: `trace` (from packet field to function),
`accesses` (field accesses), `absence`, `observability` (connection/window),
and a generic `facts` array. The kernel checks the `build` digest and the shape,
not the truth of the analysis. A future version can add a verified checker for a
specific dataflow engine and promote *that* certificate class.

### Negative evidence

The kernel has no general negation. “No other function writes to this field” is
only expressible as a scope-limited **absence certificate**:

```dg
ev e_absence := absence("absence.json", build: b1, scope: ".text", during: c1);
proof P_absence : absent_field(S2C_Position.pos, ".text", 0x140001000, 0x140001400) in b1 {
  evidence e_absence;
  rules field_absent;
}
```

The certificate must name the address scope and the time window. A timeless
absence claim is not expressible. The evidence remains Observational because the
kernel did not run the analysis; the audit trail is the certificate, the build
digest, and the scope/window check.

## 6. Strength

```
Speculative  <  Heuristic  <  Observational  <  Deterministic  <  Exact
```

- **Speculative** — human intuition or a definition-only derivation.
- **Heuristic** — a byte pattern matched once without a uniqueness proof; a
  partial decode; a nonstationary rate estimate; an explicit rule cap.
- **Observational** — sampled behavior or an external analysis. “No
  counterexample in this window” lives here, never higher.
- **Deterministic** — the kernel re-derived the fact from bytes/code: a unique
  scan, exact bytes, a complete decode, a literal `div`, a forward simulation.
- **Exact** — a cryptographic/identity anchor: the build digest appears in a
  trusted symbol store and the symbol/type matches.

Strength is computed by the kernel. The surface language has no syntax for
“trust me, this is Deterministic.”

### Maximin propagation

A derivation is only as strong as its weakest premise, capped by the rule's
declared cap:

```
strength(fact) = max over derivations d of
                   min( min over premises p of strength(p), cap(rule(d)) )
```

- Definitions contribute Exact *for the min* but carry an empty evidence
  support set. If the goal's support set is empty, the proof cannot seal.
- If several derivations exist, the strongest wins; ties keep the first for
  stable explanations.
- Statistical evidence is created at Observational and every statistical rule
  caps at Observational. There is no path from a flat histogram to
  Deterministic.
- External evidence is created at Observational and every rule that consumes it
  inherits that cap.

The current implementation computes this over a finite fact set by fixpoint.
The formal statement is in [semantics](semantics.md#4-strength-algebra).

### The bottleneck is reported

Derived claims never average their premises. The result is the minimum, and the
report names the premise that produced it:

```
C_predictable  hypothesis  observational
  bottleneck: P_observable
C_tamperable   hypothesis  observational
  bottleneck: P_reads_packet_pos
```

That is what a security report actually needs: “the proof is gated on whether
`conn_7` outputs are client-visible, obligation O7.”

## 7. Facts and rules

Facts are ground typed atoms. The vocabulary is open: rules and claims can use
any relation name. Model declarations emit a core vocabulary:

| Relation | Meaning |
|---|---|
| `fn_addr(fn, addr)`, `fn_label(fn, name)` | function definition |
| `field_owner(field, owner)`, `field_offset(field, off)`, `field_width(field, w)`, `field_type(field, ty)` | layout |
| `owner_kind(owner, "struct" \| "packet")`, `struct_size`, `struct_align`, `packet_size`, `packet_opcode` | owner metadata |
| `rng_addr`, `rng_algo_decl`, `rng_algo_full`, `rng_seed`, `rng_scope` | RNG definition |
| `dist_rng`, `dist_site`, `dist_bins` | distribution definition |
| `clock_decl`, `clock_hz_milli` | clock definition |

Evidence emits relations such as `scan_hit`, `scan_unique`, `loads_set`,
`stores_set`, `modulo_op`, `recovery_ok`, `recovery_horizon`, `sim_fail`,
`constant_present`, `rate_period_us`, `sample_counts`, `symbol_addr`,
`trace`, `absence_field`, `observability`.

Rules are Datalog-flavored and **negation-free**:

```dg
rule reader_reads_struct_field:
  reads(?f, ?field) if
    fn_addr(?f, ?a) and
    scan_hit(?e, ?a) and scan_unique(?e) and
    field_owner(?field, ?owner) and owner_kind(?owner, "struct") and
    field_offset(?field, ?o) and
    loads_set(?e2, ?f, ?offs, 4) and
    contains(?offs, ?o);
```

- Variables are prefixed with `?`. Bare identifiers are symbols/refs.
- Body atoms are ordered. Relation atoms bind variables; built-ins require
  their inputs to be bound by that point (`contains`, `eq`, `len`, `lt/le/gt/ge`,
  `add/sub/mul/div`, `abs_diff`, `min/max`, `within`).
- A rule may declare `cap heuristic:` (or any strength) before the colon.
- Every head variable must be bound by the body; tautological rules (no
  relational premise) are rejected.
- There is no negation. Use an audited absence certificate instead.

The standard library includes the rules used by the examples:
`reader_reads_struct_field`, `writer_writes_struct_field`,
`packet_reader_traced`, `mt19937_identified`, `algo_hypothesis`,
`recovery_witness`, `modular_bias`, `exact_anchor`, `exact_layout`,
`field_absent`, `observable_outputs`, `refuted_algo`, and `fn_defined`.

`deg stdlib` prints the exact source the kernel parses.

## 8. Proofs

A proof names a ground goal, a build, the evidence it is allowed to use, and
the rules it is allowed to apply:

```dg
proof P_reads_vec3_z : reads(read_position, Vec3.z) in b1 {
  evidence e_anchor, e_shape;
  rules reader_reads_struct_field;
}
```

The kernel:

1. verifies the artifacts and evaluates the named evidence;
2. loads the definitional facts for the proof's build;
3. inserts the evidence facts with their computed strengths;
4. applies only the named rules to fixpoint;
5. looks up the goal;
6. reports the strength, the evidence support, and the derivation tree.

There is no proof search outside the named rules. A proof that cannot derive the
goal fails with the available facts of that relation, so the researcher can see
what premise was missing.

Optional `expect >= exact;` turns “I expect this to be exact” into a hard check.
A proof whose strength is below the seal threshold becomes a **hypothesis**,
not an error; `deg seal --strict` can refuse to write a lock with hypotheses.

## 9. Claims

### 9.1 Certificate claims

Measurements are checked by the kernel against a specific evidence result:

```dg
claim C_tick : period(srv_tick, stream: 0x01F4) ~ 15.625ms ± 0.05ms in b1
  during c1 provisional until "2099-12-31"
  by e_tick require coverage >= 60s, confidence >= 0.95;

claim C_uniform : uniform(LootTable, bins: 12) in b1 during c1
  provisional until "2099-12-31"
  by e_loot require alpha: 1e-4, power: 0.999, delta: 0.02, coverage >= 100s;
```

For a period claim the kernel re-checks:

- the evidence is `rate(...)` for the same opcode/clock/capture;
- the measured median is within the claimed tolerance;
- the claimed tolerance is not tighter than the evidence CI at the requested
  confidence;
- coverage and sample requirements;
- the split-half stationarity check.

For a uniform claim it re-checks:

- the evidence is `sample(...)` for the same capture;
- the distribution has the claimed number of bins;
- no sample falls outside the bins;
- the chi-square p-value is at least `alpha` (failure to reject);
- if `power`/`delta` are given, the sample count is at least the conservative
  required size for the stated alternative.

A statistical claim is **always Observational**. The kernel certifies the
*procedure*, not the world: “observed for 100 seconds” is not “proved forever.”
The claim can be sealed only provisionally, with an expiry date, or at a lowered
threshold with eyes open.

### 9.2 Composed claims

Security claims are compositions of other claims:

```dg
claim C_tamperable : tamperable(Player.position) in b1
  provisional until "2099-12-31"
  from P_reads_packet_pos, P_absence, P_observable;

claim C_predictable : predictable(srv_rng, conn_7, 32) in b1
  from P_algo, P_recovered, P_observable;
```

The result inherits the **minimum** strength. If a premise is a hypothesis or
stale, the derived claim cannot be stronger. The report identifies the weakest
premise as the bottleneck. A provisional premise propagates its expiry to the
derived claim. There is no special “security multiplier”; trust-boundary claims
are exactly as strong as their weakest conjunct.

### 9.3 Conflicts

A uniform sample and a code-derived bias can both be “proved” while disagreeing:

```dg
conflict C_loot : C_uniform vs P_biased
  prefer P_biased
  reason "a 12k histogram cannot resolve a 2^-32 modular bias";
```

The kernel detects uniform/biased pairs over the same distribution. A conflict
declaration with `prefer` resolves it by **demoting** the non-preferred claim to
hypothesis and recording the conflict, preference, reason, and demotion in the
seal manifest. An undeclared conflict is reported unresolved and blocks
`deg seal`. The lattice is never averaged: the code proof of `% 12` bias wins
over a statistical failure to reject uniformity, because they are not the same
kind of claim.

### 9.4 Refutation

A refutation is a successful observation that kills a hypothesis:

```dg
refute R_not_xorshift : algo(srv_rng, XORSHIFT128) in b1 by e_xs_refute;
```

`recovery` evidence emits `sim_fail(rng, algo)` when the forward simulation
mismatches the observed dataset. The kernel checks that the refutation goal is
`algo(rng, ALGO)` and that the evidence contains the matching `sim_fail` fact.
A refutation is sealed at Deterministic (the mismatch is a byte-level fact) and
marks any claim with the same goal as `refuted`. Refutation is first-class
because eliminating wrong models is often the real work.

### 9.5 Obligations

Not everything is proved. Obligations are live, auditable gaps:

```dg
obligation O_layout : layout_exact(Vec3) priority: medium blocks: seal;
obligation O_recheck_rate : period_stable(srv_tick) priority: low;
```

An obligation is resolved by a sealed claim with the same ground atom, or by
`obligation O … resolved by <claim>;`. A blocking obligation that remains open
prevents sealing. A non-blocking obligation appears in the report and lock.

## 10. Sealing

`deg seal model.dg` writes a deterministic JSON lock:

```json
{
  "deg_version": "0.1.0",
  "model": "examples/position/model.dg",
  "seal_threshold": "deterministic",
  "artifacts": [{ "name": "b1", "sha256": "470d…", "verified": true }],
  "sealed": [{ "name": "P_reads_vec3_z", "strength": "deterministic", … }],
  "hypotheses": [{ "name": "C_predictable", "status": "hypothesis", … }],
  "obligations": [{ "name": "O_recheck_rate", "status": "open", … }],
  "conflicts": [{ "name": "C_loot", "preferred": "P_biased", "demoted": "C_uniform" }],
  "definitions": [{ "kind": "struct", "name": "Vec3", "justified": true, … }]
}
```

The lock is the shareable artifact. It contains no wall-clock timestamps, so it
is reproducible. `deg seal` by default records hypotheses honestly; `--strict`
refuses to write a lock unless every claim seals. Sealing refuses on:

- artifact digest mismatch;
- failed evidence, failed proof, failed measurement, or a refuted claim;
- an open blocking obligation;
- an unresolved conflict.

A claim at Observational can be sealed **provisionally** with
`provisional until "YYYY-MM-DD"`. The lock records the expiry; an expired
provisional claim is reported as a hypothesis and is not silently kept.

## 11. Timing

Timing is not cosmetic in games: tick rates, rate limits, cooldowns, replay
windows, lag compensation, speed hacks, and TOCTOU are all temporal. The design
adds:

### Clocks and time scopes

```dg
clock srv_tick = server_clock(b1, hz: 64, epoch: match_start, monotone: true);
clock cap_ts   = capture_clock(c1, source: kernel, resolution: us);
relate cli_frame ~ srv_tick within 50ms;
```

Every temporal claim is interpreted in a named clock. Cross-clock conversion is
a proof obligation with inherited strength. In v0.1, clocks and the declared clock on `rate` are parsed and identity-checked,
and `relate` is parsed; actual cross-clock conversion and `relate` enforcement
are **designed, not implemented**. The pcap timestamps are the clock
used for the rate measurement.

### Deductive vs statistical timing

Two kinds of temporal claim must not be mixed:

- **Code-derived** — “the guard is `now - last_cast >= 0x1C9C380` ticks.” A
  disassembly/dataflow certificate can make this Deterministic.
- **Capture-derived** — “the tick period is 15.625 ms ± 0.03 ms.” This is an
  estimate, always Observational, with coverage and a CI.

The kernel checks the statistical *procedure* against the samples (n, coverage,
CI, stationarity), not the claim “forever.”

### Time-scoped absence

```dg
exhaustive_writes(S2C_Position.pos, scope: ".text", during: c1.window)
```

An absence claim must declare both an address scope and a time scope. A timeless
“nothing writes here” is not expressible. In v0.1, absence enters through an
audited external certificate (`absence(...)`), because the kernel does not have
a sound dataflow analysis.

### Nonstationarity

`rate` splits the inter-arrival samples and compares the halves. A significant
shift demotes the evidence to Heuristic and marks the claim a hypothesis. The
design’s open problem is deliberate timing obfuscation (jitter, randomized
ticks); v0.1 reports nonstationarity rather than pretending the estimator is
robust to it.

## 12. RNG

RNG is the best case for a certificate language because the kernel can
**re-check a witness by simulation**:

```dg
rng srv_rng in b1 at 0x140001200 {
  algo: MT19937;
  seed: from(time_seconds@boot);
  scope: per_server_process;
}

ev e_mt_consts := constants(b1, at: srv_rng, window: 64,
  values: [0x9908B0DF, 0x9D2C5680, 0xEFC60000]) |> unique;

ev e_recover := recovery(srv_rng, state: ds_state, index: 624, observed: ds_obs);

proof P_algo : algo(srv_rng, MT19937) in b1 {
  evidence e_mt_anchor, e_mt_consts;
  rules mt19937_identified;
}

proof P_recovered : recovered(srv_rng, 624, 64) in b1 {
  evidence e_recover;
  rules recovery_witness;
}
```

- **Algorithm identification** uses constant-structure evidence at the RNG site,
  not a global “the binary contains MT constants somewhere.” The window,
  uniqueness, and site are explicit.
- **State recovery** is expensive and outside the kernel (LCG linear algebra,
  MT untempering, GF(2) solving). The tactic emits
  `(algorithm, state, index, observed projection)`. The kernel runs the PRNG
  forward and compares outputs byte-for-byte. The discovery may be heuristic;
  the **certificate is Deterministic**.
- **Projections** (`full32`, `high8`, `high16`, `low8`, `low16`) handle games
  that expose only some bits of each draw.
- **A mismatch is a refutation**, not a failure of the evidence. `sim_fail`
  is a deterministic observation and can kill a competing algorithm via
  `refute`.

### The distribution asymmetry

> You can **prove bias** from code. You can never **prove uniformity** from
> samples.

A `next() % 12` is provably non-uniform from one disassembly. Twelve thousand
loot rolls that pass a chi-square test are Observational forever. DeG encodes
this as a hard cap and a conflict:

```dg
proof P_biased : biased(LootTable, 12) in b1 { … }

claim C_uniform : uniform(LootTable, bins: 12) … by e_loot require alpha: 1e-4, power: 0.999, delta: 0.02 …;

conflict C_loot : C_uniform vs P_biased prefer P_biased
  reason "the code does next() % 12; 12k samples cannot resolve a 2^-32 modular bias";
```

The uniform claim is not “wrong”; it is underpowered and remains recorded as a
hypothesis. The conflict explains why the lattice should not be averaged.

### Seed provenance

`srand(time(NULL))` is not a PRNG bug; it is a **keyspace** bug. The intended
claim is:

```dg
claim seed_entropy(srv_rng, during: c1.window) <= log2(60)
  by rule seeded_from(srv_rng, time_seconds@boot)
  ∧ boot_window(c1) ≈ 60s;
```

This is **designed, not implemented** in v0.1. The RNG declaration records the
seed source, and the report shows it, but there is no automated boot-window
entropy check yet. The same applies to fork detection across sessions.

## 13. Security claims and trust boundaries

The reason many people do this work is to answer: *who controls this value?*

DeG expresses the answer as a composition of claims:

```dg
claim C_tamperable : tamperable(Player.position) in b1
  from P_reads_packet_pos, P_absence, P_observable;

claim C_predictable : predictable(srv_rng, conn_7, 32) in b1
  from P_algo, P_recovered, P_observable;
```

- `P_reads_packet_pos` establishes the client reads the position from the
  packet (external trace, Observational).
- `P_absence` is a time- and scope-scoped absence certificate (Observational).
- `P_observable` says the attacker can see the relevant outputs (external,
  Observational).
- `C_predictable` inherits Observational and names `P_observable` as the
  bottleneck.

The report is the audit trail a reviewer needs: which conjunct is weakest, which
certificate backs an absence claim, which evidence is external, and what remains
an obligation. “How do you know the server doesn’t validate?” is answered by a
named certificate and a declared scope/window, not by confidence.

## 14. Patch porting

The whole point. Models are version-scoped, so a patch produces a structured
report, not a rewrite:

```console
$ deg port examples/port/model.dg --to b2
mappings:
  fn   read_position  0x140001000 -> 0x140001080  (0.98, structural_similarity)
  rng  srv_rng        0x140001200 -> 0x140001280  (0.96, structural_similarity)

P_reads       b1  rebased  demoted  heuristic
P_algo        b1  stale    stale    -
P_recovered   b1  failed   failed   -

new obligations:
  unique(b2, 0x140001080) [blocks seal]
  revalidate(P_algo, target: b2) [blocks seal]
  reanchor(P_recovered, target: b2) [blocks seal]
```

Semantics:

- **Re-anchor by pattern.** If a unique scan pattern survives in the target, the
  function is re-anchored at Deterministic and its evidence is replayed.
- **Structural fallback.** If a `port { rebase … }` rule is declared, a
  longest-common-subsequence similarity search over the target `.text` provides
  a candidate. The result is **Heuristic**, not Deterministic, and generates a
  `unique(target, addr)` obligation. A rebase never silently promotes.
- **Re-simulate RNG witnesses.** A recovery proof is re-run with a target
  observed dataset if declared (`revalidate e_recover with ds_obs_b2`). A
  changed constant or a different stream makes the simulation fail, which is
  the loud, correct outcome.
- **Statistical claims go stale.** A new build needs a new capture; v0.1 marks
  the claim stale and emits a revalidation obligation rather than carrying the
  old rate forward.
- **No silent keep.** Every claim is `ported`, `demoted`, `stale`, `failed`, or
  `unchanged`. The model source is not rewritten by `deg port`.
- **Derived claims** are recomputed from the ported premises, so a stale
  bottleneck propagates.

`port` is a report, not a mutating compiler, in v0.1. That is a deliberate
safety choice: an automated rewrite of a security claim is exactly where a tool
should be conservative.

## 15. Deliberate omissions

- **No general-purpose logic.** No quantifiers beyond scope-limited evidence;
  no LTL/CTL; no open-world negation. The kernel must stay decidable.
- **No native decompilation.** C-like declarations are claims/definitions, not
  source.
- **No statistical proof of uniformity.** Ever, encoded as a hard cap.
- **No certificate promotion by p-value.** A flat histogram is not a proof.
- **No full dataflow engine.** External certificates stand in, capped.
- **No rendering/UI meaning.** What a field *means to a player* is out of scope;
  structural, control-flow, timing, and trust-boundary claims are checkable.

## 16. Open problems

1. **Principled cross-patch similarity.** v0.1's LCS heuristic is auditable but
   weak under relinking, recompilation, and obfuscation. A soundness gain here
   is the most valuable next step.
2. **Anti-cheat-obfuscated binaries.** If even disassembly is Observational, the
   lattice still works, but the tactics do not. A verified disassembler
   certificate class would help.
3. **Statistical portability.** A rate measured on one capture is not a property
   of a build. The design marks it stale; a future version could support
   “coverage-relative” claims with explicit validity windows.
4. **Seed entropy and fork detection.** The keyspace argument needs boot-window
   estimation and per-connection seed provenance; designed, not implemented.
5. **Nonstationary timing.** Deliberate jitter and randomized ticks break the
   median estimator; detecting and representing nonstationarity is ongoing.
6. **Timer-wheel arithmetic.** Floating-point accumulation and variable frame
   time make `now - last_cast >= 30s` hard for SMT; those claims may only ever
   be Heuristic.
7. **Verified rule libraries.** User rules are trusted axioms. A future version
   could type-check rules against relation signatures and certify rule
   libraries, but the kernel still has to trust the rule authors.
8. **White-box RNG.** A statistically ideal, deterministic RNG may be
   indistinguishable from uniform by samples; the algebraic witness simply may
   not exist. DeG reports Speculative and an open obligation.

## 17. Implementation status

| Area | v0.1 |
|---|---|
| Artifact hashing, virtual mapping, pcap parse | ✅ |
| Scan / bytes / narrow x86 decode / constants / modulo | ✅ |
| MT19937, xorshift32/128, LCG forward simulation | ✅ |
| Recovery witnesses, projections, refutation by mismatch | ✅ |
| Rate/period claims, coverage, CI, stationarity | ✅ |
| Uniform claims, chi-square, power check, statistical cap | ✅ |
| Datalog facts/rules, maximin, provenance, derivations | ✅ |
| Proofs, composed claims, bottlenecks, conflicts, obligations | ✅ |
| Exact symbol/type store | ✅ (definitions/anchors) |
| External trace/absence/observability certificates | ✅ (capped) |
| Seal/lock/report/explain/JSON/CLI | ✅ |
| Porting: re-anchor, LCS rebase, stale/demote, obligations | ✅ |
| Cross-clock conversion, `relate` enforcement | ⛔ designed |
| Seed-keyspace entropy, fork detection | ⛔ designed |
| Full dataflow/disassembler, SMT, general temporal logic | ⛔ out of scope |

## 18. Formal semantics

The judgments, strength algebra, seal conditions, conflict resolution, and port
relation are specified in [semantics.md](semantics.md). The complete surface
grammar is in [grammar.ebnf](grammar.ebnf). The design conversation that seeded
this project is recorded in [source.md](source.md).

The honest soundness claim is:

> If `deg check` succeeds, then the goal follows from the named rules and the
> facts emitted by the evidence evaluators, each of which replayed against a
> verified artifact, and the reported strength is a lower bound computed by the
> kernel's lattice. It is **not** a claim that the model is the only possible
> interpretation of the game, that an external certificate is true, or that an
> observed statistical behavior holds forever.

That is the distinction this language exists to make explicit.

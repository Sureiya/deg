# Provenance

DeG began as a design conversation on DeepSeek:

<https://chat.deepseek.com/share/se3fnx5w114jq2c20i>

The conversation has three rounds:

1. **“Design a proof language for game client/server reverse engineering.”**
   It proposes DeG: four layers (artifacts, evidence, proofs, model), a
   confidence lattice, Datalog-flavored rules, obligations, refutation, a small
   checker, version scoping, `port`, and security claims.

2. **“Does this handle things like timing?”** It adds clock domains, sampled
   evidence with coverage, temporal predicates, the deductive/statistical split,
   time-scoped absence, and the refusal to adopt a general temporal logic.

3. **“Also how does it handle reverse engineering of rng?”** It adds RNG as a
   first-class object, constant-structure identification, algebraic recovery
   re-checked by forward simulation, the “prove bias, never prove uniformity”
   asymmetry, conflict as a first-class state, seed provenance, and patch
   behavior.

This repository is an independent implementation of those ideas, not a
transcript. The checked-in `.dg` files are the source of truth for the syntax,
and the kernel is the source of truth for the semantics.

## What was kept

- the name **DeG**, `.dg` files, and the `dg`-style CLI (`deg`);
- the four-layer architecture and the content-addressed artifacts;
- the strength lattice and the “strength is computed, never asserted” rule;
- Datalog-with-certificates, explicit rules, obligations, refutation;
- sealing and `port`;
- timing: clocks, coverage, statistical cap, stationarity, time-scoped absence;
- RNG: constants, simulation witnesses, projections, the uniformity asymmetry,
  conflict, keyspace/provenance concerns;
- security claims as compositions with a named bottleneck.

## What had to be decided to make it implementable

The conversation is a design sketch, not a parser grammar. The implementation
made these choices, all documented in [design](design.md):

1. **Proof bodies name evidence and rules, not tactics.** A proof is a selection
   of allowed evidence and rule names; the kernel runs the Datalog closure. This
   is smaller and more auditable than a tactic language, and makes `deg explain`
   a real derivation tree.
2. **Definitions are assumptions, not automatic theorems.** Struct layouts and
   function addresses generate definitional facts; they are audited in the lock
   and never appear in an evidence support set. A proof made only of definitions
   cannot seal.
3. **External certificates are capped at Observational.** The kernel checks
   their build digest and schema, not their analysis. This is the honest version
   of “a small trusted kernel”; a future verified checker can promote a specific
   certificate class.
4. **The x86 decoder is a narrow verified subset, not a disassembler.** A
   partial decode is Heuristic. A real disassembler can enter as external
   evidence, capped.
5. **Statistical checks are procedures, not proofs.** The kernel re-computes
   sample counts, coverage, chi-square, CI, power, and stationarity. It never
   promotes a p-value above Observational.
6. **Seal records hypotheses by default.** `deg check` reports the honest state;
   `deg seal` writes sealed claims plus hypotheses; `--strict` refuses
   hypotheses. This mirrors the conversation's “kernel OK with hypotheses and
   open obligations” while giving teams a stricter policy when they need it.
7. **Port is a report, not a rewrite.** v0.1 never edits the model. It re-anchors,
   rebases, re-simulates or marks stale, and emits obligations. Rewriting a
   security model automatically is the wrong default.
8. **The fixture power calculation is conservative.** The conversation's
   “power ≥ 0.999” is implemented as a worst-bin normal approximation for a
   two-sided proportion test, documented in
   [semantics](semantics.md#62-uniformity). It is intentionally conservative,
   not a claim of exactness.

## Naming

The conversation uses “DeG” and `dg` code fences. The repository uses the
`deg` binary and the `.dg` extension. The design notes' `dgcheck` corresponds to
`deg check` (the kernel) and `deg seal` (the lock writer).

The original conversation is linked for context; the repository does not
reproduce its text. If you are the author of that conversation and want the link
removed or a different attribution, open an issue.

# Changelog

## 0.1.0 — 2026-11-17

Initial working prototype.

- Surface language: artifacts, structs, packets, functions, RNGs, distributions,
  clocks, evidence, rules, proofs, certificate claims, derived claims, conflicts,
  obligations, refutations, and port blocks.
- Kernel: SHA-256 artifact binding, virtual-address mapping, byte-pattern scans,
  exact bytes, narrow x86-64 load/store decoding, constant windows, literal
  modulo witnesses, forward PRNG simulation (LCG / xorshift32 / xorshift128 /
  MT19937), pcap rate/sample statistics, symbol/type exactness, external
  certificates with an Observational cap.
- Proofs: negation-free Datalog closure, maximin strength, provenance,
  derivation explanations, `expect` checks, definition audit.
- Claims: period and uniformity checks, statistical cap, power check,
  provisional sealing, conflicts with explicit preference, composed claims with
  bottleneck reporting.
- Tooling: `check`, `seal`, `report`, `explain`, `artifacts`, `port`, `stdlib`,
  JSON output, Markdown reports, deterministic lock files, Mermaid derivations
  (`explain --mermaid`), Markdown port reports (`port --markdown`).
- Examples and deterministic fixtures for position/packet, timing, RNG, loot
  conflict, and patch porting. End-to-end tests for the checked examples and
  negative cases.

Designed but not implemented in 0.1.0:

- cross-clock conversion and `relate` enforcement;
- seed-keyspace entropy and fork detection;
- full disassembly/dataflow/SMT integration;
- porting of statistical claims (they go stale with a revalidation obligation);
- a general temporal fragment or quantifiers.

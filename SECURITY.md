# Security policy

## Scope

DeG is a **proof checker for artifacts**: binaries, packet captures, memory
dumps, and derived datasets. It does not interact with a live game, inject
packets, edit memory, or bypass access controls. The examples are synthetic.

This policy covers vulnerabilities in the tool itself, for example:

- an artifact digest is not actually verified, or a model can make evidence run
  against unverified bytes;
- a proof can seal from definitions alone, or an external certificate can exceed
  `Observational`;
- a statistical claim is promoted above `Observational`, or a conflict is
  silently averaged;
- a parser or evidence evaluator panics, hangs, or reads out of bounds on a
  malicious model/artifact;
- a port silently carries a claim instead of demoting or marking it stale.

It does **not** cover:

- game-specific anti-cheat bypasses, cheat development, or live-service abuse;
- the truth of an external certificate supplied by a third-party analysis tool;
- the cryptographic strength of a game's RNG (DeG predicts from a witness; it
  does not break the algorithm);
- the correctness of a user-written rule, which is part of that model's trusted
  specification.

## Reporting

Please use GitHub's private security advisories for this repository rather than
a public issue. Include:

- the version/commit,
- a minimal `.dg` model and artifact (or a description of the bytes),
- the expected and actual behavior,
- whether the result is a false seal, a panic, a hang, or a wrong audit report.

We will acknowledge and triage as time permits. This is a research prototype;
there is no bounty program.

## Hardening notes

- All artifacts are addressed by SHA-256; a mismatch is a hard error and no
  evidence is replayed.
- The kernel's decoders index bytes with bounds checks and cap fact counts and
  fixpoint rounds.
- External certificates are parsed as data (no code execution) and are capped
  at Observational.
- Statistical checks are intentionally conservative and never promote beyond
  Observational.
- Porting never rewrites the model source in v0.1; it emits a report and
  obligations.

# Contributing

DeG is a small, zero-dependency Rust project. The goal is a trustworthy kernel
with an auditable rule library and honest documentation.

## Setup

```console
cargo build
cargo test
cargo fmt
cargo clippy --all-targets -- -D warnings
make check
```

The example fixtures are checked in. Regenerate them only if you are changing
the fixture story:

```console
python3 tools/make_fixtures.py
```

If you regenerate, update the `sha256:` fields in every model that references
the changed files. The kernel is supposed to reject stale digests; do not
“fix” that by relaxing the check.

## What makes a good change

- **A kernel primitive should re-check something.** If the kernel cannot
  re-derive it from bytes or a capture, it belongs behind an external
  certificate with an explicit cap.
- **A rule should be visible in `deg stdlib` or the model.** Rules are trusted
  specification; do not hide a semantic assumption in a tactic.
- **Strength must be computed.** Never add syntax that lets a user assert
  `Deterministic`/`Exact`.
- **Statistics are procedures.** New statistical claims need a documented
  check, a sample/coverage requirement, and the Observational cap.
- **Examples are tests.** A new feature should have a checked example or an
  integration test, and the docs must distinguish “implemented” from “designed.”
- **No live-game attack code.** This project checks claims about artifacts for
  fair-use research; do not add memory editors, packet injectors, or bypasses.

## Adding an evidence primitive

1. Add a variant to `EvidenceKind` and parse it in `src/parser.rs`.
2. Implement the evaluator in `src/evidence.rs`. It must verify the artifact,
   emit ground facts, and assign a strength from its checks.
3. Add the facts to `docs/semantics.md` and the table in `docs/design.md`.
4. Add a rule (if the primitive is meant to feed proofs) to `src/stdlib.rs`.
5. Add unit tests for the primitive and an end-to-end example or negative test.
6. Update `docs/grammar.ebnf` and the tutorial's troubleshooting table if the
   failure modes are user-visible.

If the primitive shells out to an external tool, stop: that is an external
certificate. Add a certificate schema and keep the cap.

## Adding a rule

Add it to `STDLIB` in `src/stdlib.rs` with the smallest cap that is honest.
Add a unit test that compiles the standard library and a proof/example that
exercises it. If the rule encodes an ABI assumption (for example “the struct
base is in rdi”), say so in a comment and in the design doc.

## Style

- Rust 2021, `cargo fmt`, no new dependencies without a strong argument.
- Errors should name the artifact, address, rule, or fact that failed.
- Reports should be deterministic (sorted maps, no wall-clock timestamps in
  lock files).
- Keep the kernel small. Expensive analysis belongs outside it.

## Reporting

Use GitHub issues for bugs and design discussion. For a security issue in the
tool itself, see [SECURITY.md](SECURITY.md). Be precise about whether a failure
is a parser crash, a false seal, an artifact-binding bypass, or a wrong claim
about a checked-in example.

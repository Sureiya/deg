# DeG — compiled-in evidence extensions

The core evidence primitives (`scan`, `bytes`, `decode`, `constants`,
`modulo`, `recovery`, `rate`, `sample`, `table`, `symbols`, `external`,
`absence`) are fixed in the kernel. A domain crate — for example a
game-specific adapter — may **compile additional evidence kinds into the
binary** so domain analyses become first-class, kernel-checked evidence
instead of Observational-capped external certificates.

There is **no runtime loading**. An extension is a function pointer in the
trusted binary, registered at startup. A model file can never name code that
was not reviewed and built into the binary.

## Registering a kind

```rust
use deg::ast::EvidenceDecl;
use deg::artifact::ArtifactSet;
use deg::evidence::EvidenceOutcome;
use deg::semantic::ModelIndex;
use deg::strength::Strength;
use deg::value::Value;

fn manifest_eval(
    _index: &ModelIndex,
    artifacts: &ArtifactSet,
    decl: &EvidenceDecl,
) -> Result<EvidenceOutcome, String> {
    // Re-derive facts from a verified dataset, exactly like core evaluators.
    let dataset = match &decl.kind {
        deg::ast::EvidenceKind::Extension { args, .. } => {
            args.positional_string(0).ok_or("manifest needs a dataset")?
        }
        _ => unreachable!(),
    };
    let text = artifacts.dataset_text(&dataset)?;
    // ... parse and check ...
    let mut out = EvidenceOutcome::new(
        &decl.name,
        "manifest",
        Strength::Deterministic, // only if the check itself derived the facts
        format!("manifest parsed from {dataset}"),
    );
    out.fact("manifest_ok", vec![Value::sym(&decl.name)]);
    Ok(out)
}

fn manifest_build(index: &ModelIndex, decl: &EvidenceDecl) -> Option<String> {
    // Bind the evidence to a build so proofs are checked to live in it.
    // Return None when the kind is not build-bound.
    let _ = (index, decl);
    None
}

deg::ext::register(
    "manifest",
    deg::ext::Extension {
        eval: manifest_eval,
        build: Some(manifest_build),
        describe: "row facts for the game's opcode manifest",
    },
)
.unwrap();
```

A model can then write:

```dg
ev e_manifest := manifest(ds_ops, n: 3);
```

The parser accepts any evidence kind name syntactically; unknown kinds become
`EvidenceKind::Extension` and are dispatched through the registry. When the
kind is not registered, evaluation fails with

```text
evidence kind `manifest` is not registered; registered: [...]
```

so a model written for an extended binary fails loudly (not silently) under
the core binary. `deg extensions` prints the kinds compiled into the running
binary, one per line; the core binary registers none.

## The trust model

An extension runs *inside* the kernel's evidence stage, so it is reviewed
exactly like the core evaluators:

1. **Compiled into the trusted binary.** Registration is append-only and
   global; duplicate kinds are rejected at startup (`register` returns an
   error). There is no mechanism to load an evaluator from a model, a
   certificate, or a library at runtime.
2. **Bound to verified artifacts.** An evaluator receives the `ArtifactSet`
   and must itself check `verified`/digest before deriving facts from bytes —
   the same discipline as the core evaluators. The optional `build` hook
   lets static validation check that the evidence belongs to the proof's
   build.
3. **Same strength rules.** The evaluator assigns the strength of its own
   facts, and the invariant is: `Deterministic` (or above) only for facts the
   evaluator *re-derived from verified artifact bytes itself*; anything it
   admits without re-checking (certificates, measurements, external
   observations) must be capped at `Observational`, exactly like `external`
   and `absence`. A reviewer of a domain crate checks its extensions against
   this invariant the same way they would review a change to `evidence.rs`.
4. **Same strength algebra.** Extension facts flow through the ordinary
   maximin lattice with ordinary support sets; the kernel does not distinguish
   extension facts from core facts. Extensions cannot raise a fact above what
   their own evaluator assigned, and they cannot touch the seal threshold.
5. **Failures are hard errors.** A failed extension evaluation is a failed
   evidence term, which fails `deg check`, exactly like a failed scan.

In short: extensions widen *what can be checked in-kernel*, not *who is
trusted*. A binary with extensions has a larger trusted surface than the core
binary — that trade-off is explicit and is why `deg extensions` exists.

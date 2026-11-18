# DeG tutorial

This is a guided tour of the checked examples. It assumes you have built the
binary:

```console
$ cargo build --release
$ alias deg=./target/release/deg
```

## 1. A 60-second tour

```console
$ deg check examples/position/model.dg
deg check examples/position/model.dg
  artifacts   5 (5 verified)
  evidence    14 (14 ok)
  claims      7 sealed, 1 provisional, 6 hypothesis, 0 failed/refuted
  obligations 1 open
  conflicts   1 (0 unresolved)
  threshold   deterministic

claims:
  ◐ C_tick                       provisional  observational  period(srv_tick, stream:0x01f4) ~ 15625us +- 50us
  ✓ P_algo                       sealed       deterministic  algo(srv_rng, MT19937)
  ✓ P_anchor_exact               sealed       exact          anchored(read_position)
  ✓ P_biased                     sealed       deterministic  biased(LootTable, 12)
  ✓ P_recovered                  sealed       deterministic  recovered(srv_rng, 624, 64)
  ✓ P_reads_vec3_z               sealed       deterministic  reads(read_position, Vec3.z)
  ? P_reads_packet_pos           hypothesis   observational  reads(read_position, S2C_Position.pos)
      note: strength observational is below the seal threshold deterministic
...
kernel: OK
```

Every number in this output is derived from the fixture files, not from a mock:

- `P_reads_vec3_z` is Deterministic because a unique byte pattern anchors
  `read_position` and the kernel's decoder finds 32-bit loads at offsets 0, 4,
  and 8.
- `P_algo` is Deterministic because the MT19937 constants are present and
  unique in a declared window at the declared RNG site.
- `P_recovered` is Deterministic because the kernel ran MT19937 forward from a
  624-word state and reproduced 64 hashed outputs.
- `P_reads_packet_pos` is only Observational because the packet-field link is a
  dataflow certificate. The kernel checks the digest and schema, not the
  analysis.
- `C_tick` is Observational and sealed *provisionally* until 2099-12-31.
- `C_loot_uniform` is a hypothesis because the conflict with `P_biased` demoted
  it.

The model is still “OK”: hypotheses and open obligations are reported, not
hidden. `deg seal --strict` is the policy that refuses them.

## 2. Anatomy of a model

A `.dg` file has five layers. The flagship example is
[`examples/position/model.dg`](../examples/position/model.dg).

### Artifacts

```dg
build b1 = binary("../fixtures/game-b1.bin",
  sha256: "470d…", arch: x86_64,
  load: 0x140000000, text: 0x140001000..0x140001400);
capture c1 = capture("../fixtures/session-b1.pcap", sha256: "c9c0…", build: b1);
dataset ds_state = dataset("../fixtures/mt-state-b1.txt", sha256: "c306…", build: b1);
```

The digest is checked before anything else. `load` maps virtual addresses to
file offsets; `text` is the virtual range that scans may touch.

### Definitions

```dg
struct Vec3 in b1 { x: f32 @ 0; y: f32 @ 4; z: f32 @ 8; } size 12 align 4;
packet S2C_Position in b1 { opcode: u16 @ 0 = 0x1F4; seq: u32 @ 2; pos: Vec3 @ 6; flags: u8 @ 18; } size 19;
fn read_position in b1 at 0x140001000;
rng srv_rng in b1 at 0x140001200 { algo: MT19937; seed: from(time_seconds@boot); scope: per_server_process; }
dist LootTable in b1 { rng: srv_rng; site: loot_roll; bins: 12; }
```

Definitions generate facts such as `field_offset(Vec3.z, 8)` and
`fn_addr(read_position, 0x140001000)`. They are assumptions; the report lists
whether each has a justification (`layout_exact`, `anchored`, `algo`, …).

### Evidence

```dg
ev e_anchor := scan(b1, ".text", "48 B8 44 65 47 21 62 31 00 00") |> unique;
ev e_shape  := decode(b1, read_position, count: 8);
ev e_trace  := external("../fixtures/trace.json", kind: trace, build: b1);
```

Evidence is evaluated once. A failed evidence term is a hard error even if no
proof uses it, because the model's audit trail is broken.

### Rules and proofs

```dg
rule reader_reads_struct_field:
  reads(?f, ?field) if
    fn_addr(?f, ?a) and
    scan_hit(?e, ?a) and scan_unique(?e) and
    field_owner(?field, ?owner) and owner_kind(?owner, "struct") and
    field_offset(?field, ?o) and
    loads_set(?e2, ?f, ?offs, 4) and
    contains(?offs, ?o);

proof P_reads_vec3_z : reads(read_position, Vec3.z) in b1 {
  evidence e_anchor, e_shape;
  rules reader_reads_struct_field;
}
```

The proof names the evidence and rules it uses. The kernel does not search for
other rules.

### Claims

```dg
claim C_tick : period(srv_tick, stream: 0x01F4) ~ 15.625ms ± 0.05ms in b1
  during c1 provisional until "2099-12-31"
  by e_tick require coverage >= 60s, confidence >= 0.95;
```

`period` and `uniform` are certificate claims: the kernel checks the measured
value through the evidence, not through a rule.

## 3. Run it and read it

```console
$ deg explain examples/position/model.dg P_reads_vec3_z
claim P_reads_vec3_z
  goal        reads(read_position, Vec3.z)
  kind        proof
  status      sealed
  strength    deterministic
  support     e_anchor, e_shape

derivation:
  reads(read_position, Vec3.z)  [deterministic via rule reader_reads_struct_field]
      fn_addr(read_position, 5368713216)  [exact via definition]
      scan_hit(e_anchor, 5368713216)  [deterministic via evidence e_anchor]
      scan_unique(e_anchor)  [deterministic via evidence e_anchor]
      field_owner(Vec3.z, Vec3)  [exact via definition]
      owner_kind(Vec3, struct)  [exact via definition]
      field_offset(Vec3.z, 8)  [exact via definition]
      loads_set(e_shape, read_position, [0, 4, 8], 4)  [deterministic via evidence e_shape]

evidence:
  e_anchor (scan): unique match at 0x140001000 [deterministic]
      pattern: 48 B8 44 65 47 21 62 31 00 00
      matches: 1
      hit_0: 0x140001000
  e_shape (decode): 5 instruction(s) at 0x140001000 [deterministic]
      loads_w4: +0,+4,+8
      instructions: mov movs movs movs ret
```

The definition facts are visible in the derivation but do not appear in the
support set. That is deliberate: a proof cannot seal on definitions alone.

`deg explain … --mermaid` renders the same derivation as a GitHub-ready
Mermaid flowchart instead of text.

## 4. How strength is assigned

Read the table in the [design](../docs/design.md#5-evidence).
Two practical rules:

1. **Uniqueness must be proved.** A scan without `|> unique` is Heuristic even if
   it happens to match once. A unique scan over the full declared section is
   Deterministic.
2. **External is capped.** A trace/absence/observability certificate can never
   make a proof Deterministic. If you need a stronger claim, implement a kernel
   primitive that re-checks the analysis.

A rule can cap itself:

```dg
rule algo_hypothesis cap heuristic:
  algo(?r, ?a) if rng_algo_decl(?r, ?a);
```

This lets an exploratory model record an algorithm choice without letting it
seal as if it were proved.

## 5. Timing

```console
$ deg check examples/timing/model.dg
...
  ◐ C_tick  provisional  observational  period(srv_tick, stream:0x01f4) ~ 15625us +- 50us
```

The kernel measured the median inter-arrival of 6,400 UDP packets, a CI from
the MAD, coverage, and a split-half stationarity test. It cannot prove “64 Hz
forever”; the claim is provisional for that reason.

Try a tolerance tighter than the evidence:

```console
$ sed 's/± 0.05ms/± 0.0001ms/' examples/timing/model.dg > /tmp/tight.dg
$ deg check /tmp/tight.dg
...
  ✗ C_tick  failed  -  ...
      error: measured period 15624.000us differs from claimed 15625us by more than 0us
```

(The copied model's relative fixture paths need adjusting; the checked-in
example uses `../fixtures`.)

## 6. RNG

```console
$ deg check examples/rng/model.dg
  ✓ P_algo       sealed  deterministic  algo(srv_rng, MT19937)
  ✓ P_recovered  sealed  deterministic  recovered(srv_rng, 624, 64)
  ✓ R_not_xorshift sealed deterministic algo(srv_rng, XORSHIFT128)
  ? C_predictable hypothesis observational predictable(srv_rng, conn_7, 32)
      bottleneck: P_observable
```

The recovery evidence contains:

```dg
ev e_recover := recovery(srv_rng, state: ds_state, index: 624, observed: ds_obs);
```

`ds_state` is 624 hex words; `ds_obs` is 64 outputs from a reference MT19937
stream. The kernel simulates the algorithm forward and compares the outputs.
The *solver* that recovered the state is not trusted and is not part of the
kernel.

The refutation uses a deliberate wrong algorithm:

```dg
ev e_xs_refute := recovery(srv_rng, algo: XORSHIFT128, state: ds_xs_state,
  index: 0, observed: ds_obs);
refute R_not_xorshift : algo(srv_rng, XORSHIFT128) in b1 by e_xs_refute;
```

A mismatch is a positive observation (`sim_fail`), so it kills the hypothesis
without needing general negation.

## 7. Conflict

```console
$ deg check examples/loot/model.dg
  ✓ P_biased    sealed      deterministic  biased(LootTable, 12)
  ? C_uniform   hypothesis  observational  uniform(LootTable, bins:12)
      note: demoted by conflict C_loot: ...
```

The sample really is indistinguishable from uniform at this sample size. The
code really does `next() % 12`. DeG records both and prefers the code proof,
because “fails to reject uniform” is not “uniform.” The demotion and reason are
in the report and the lock.

## 8. Seal

```console
$ deg seal examples/position/model.dg
sealed 7 claim(s) (1 provisional) into examples/position/model.lock.json
recorded 6 hypothesis/hypotheses: C_loot_uniform, C_predictable, C_tamperable, P_absence, P_observable, P_reads_packet_pos
open obligations recorded: O_recheck_rate
```

The lock is deterministic JSON. It contains the digests, sealed claims,
hypotheses, open obligations, conflict resolution, and definition audit. Commit
it with the model; it is what a reviewer reads.

`deg seal --strict` refuses if any claim is a hypothesis. `deg check --strict`
runs the same policy without writing a lock.

## 9. Port

```console
$ deg port examples/port/model.dg --to b2
deg port -> b2
  mappings: 2
    fn         read_position  0x140001000 -> 0x140001080  (0.98, structural_similarity)
    rng        srv_rng        0x140001200 -> 0x140001280  (0.96, structural_similarity)

claims:
  P_algo       b1  stale   stale  -
  P_reads      b1  rebased demoted heuristic
  P_recovered  b1  failed  failed -

new obligations:
  unique(b2, 0x140001080) [blocks seal]
  revalidate(P_algo, target: b2) [blocks seal]
  reanchor(P_recovered, target: b2) [blocks seal]
```

The b2 fixture moves the functions and changes one MT constant. The pattern
disappears; the declared `rebase` finds the new address by LCS similarity. The
reader proof is re-derived at Heuristic, not silently kept at Deterministic.
The changed constant makes the algorithm proof stale, and the old state run
against the new observed stream fails. The report tells you exactly what to
re-earn before sealing b2.

`deg port … --markdown` renders the same report as GitHub-ready Markdown
(mappings and claims tables, obligations, warnings) instead of plain text;
`--json` stays available for machines.

## 10. Writing your own model

1. **Hash your artifacts.** Put the real SHA-256 in every `build`/`capture`/
   `dataset`. A wrong digest is a hard error.
2. **Declare only what you can name.** Definitions are assumptions. Keep them
   small and concrete.
3. **Start with evidence, not claims.** Run `deg check`; fix failed evidence
   before writing proofs. `deg report` shows the evidence table.
4. **Use unique scans.** A scan without `|> unique` is Heuristic; it cannot seal
   a Deterministic claim.
5. **Name your rules.** Copy the relevant rule from `deg stdlib` into the model
   if you need to change its assumptions, and give it a distinctive name. A
   proof only applies the rules it lists.
6. **Prefer a kernel primitive over an external certificate.** An external
   certificate is capped at Observational and is only as trustworthy as the
   tool that produced it.
7. **Seal with eyes open.** `deg seal` records hypotheses; `--strict` refuses
   them. Review the open obligations and definition audit in the lock.

## 11. Troubleshooting

| Symptom | Likely cause |
|---|---|
| `digest mismatch` | Fixture changed; update `sha256:` in the model |
| `pattern matched 0 times` | Wrong section/load mapping or the bytes moved |
| `expected exactly one` | The pattern is not unique; add context bytes |
| `could not derive …; available … facts` | Missing evidence, missing rule, or the rule's offsets/widths do not match |
| `strength observational is below the seal threshold` | External evidence or a statistical claim; it is intentionally capped |
| `claim is only a hypothesis` on seal | `deg seal --strict`, or add evidence that reaches the threshold |
| `unresolved conflict` | Add a `conflict … prefer … reason …;` block |
| `tolerance tighter than the evidence CI` | The claim is more precise than the capture supports |
| `underpowered` | Increase the sample size or state a larger `delta` |
| `recovery … mismatch` | Wrong algorithm/state/index/projection, or a re-seed |
| `port … stale` | A new build needs a new capture/dataset; do not carry statistics across patches |

## 12. Exit codes

| Code | Meaning |
|---|---|
| 0 | check passed / seal wrote / port produced a report |
| 1 | hard check failure, seal refusal, or artifact verification failure |
| 2 | usage, parse, or semantic-model error |

The `check --json` output is stable enough to feed a CI dashboard. The lock
format is documented by the `kernel::lock_json` writer and the examples.

#!/usr/bin/env python3
"""Verify that the command outputs pasted into README.md match the binary.

The README's "See it work" section shows excerpts of real `deg` output. This
script re-runs each command against the built binary, re-applies the elisions
the README documents (its `…`/`...` markers), and diffs the excerpts
byte-for-byte. For the compacted lock-JSON excerpt, the names and values are
checked against the regenerated lock file. It fails (non-zero exit) on any
drift, so a README edit that changes output without re-running the commands
cannot land unnoticed.

Usage (from the repository root, after `cargo build`):

    python3 tools/verify_readme.py
"""
import json
import os
import re
import subprocess
import sys

ROOT = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))

# The seal excerpt in the README shows `--out /tmp/show.lock.json`, so the
# regenerated seal must write to that exact path for the stdout line to match.
SEAL_OUT = "/tmp/show.lock.json"


def deg_binary():
    for candidate in (
        os.path.join(ROOT, "target", "debug", "deg"),
        os.path.join(ROOT, "target", "release", "deg"),
    ):
        if os.path.exists(candidate):
            return candidate
    sys.exit(
        "error: no deg binary found under target/; run `cargo build` first"
    )


def run(args, cwd=ROOT):
    return subprocess.run(
        [deg_binary()] + args,
        cwd=cwd,
        capture_output=True,
        text=True,
        check=True,
    ).stdout


def read_blocks():
    """Return the fenced code blocks of the See-it-work section, in order."""
    text = open(os.path.join(ROOT, "README.md")).read()
    start = text.index("## See it work")
    end = text.index("## Why DeG")
    section = text[start:end]
    blocks = []
    for match in re.finditer(
        r"^(`{3,4})(\w+)?\n(.*?)^\1\s*$", section, re.M | re.S
    ):
        blocks.append((match.group(2), match.group(3).rstrip("\n")))
    return blocks


def main():
    fails = []

    def check(name, got, want):
        if got.rstrip("\n") != want.rstrip("\n"):
            fails.append(name)
            import difflib

            print(f"--- FAIL: {name} ---")
            for line in difflib.unified_diff(
                want.splitlines(), got.splitlines(), "want", "got", lineterm=""
            ):
                print(line)
        else:
            print(f"ok: {name}")

    blocks = read_blocks()
    langs = [lang for lang, _ in blocks]
    assert langs == [
        "console",
        "console",
        "console",
        "json",
        "console",
        "console",
    ], langs

    # ── 1. deg check ───────────────────────────────────────────────────────
    out = run(["check", "examples/position/model.dg"]).splitlines()
    trimmed = out[11].replace(" by orders of magnitude", "…")
    want = "\n".join(out[:11] + [trimmed] + out[12:26] + ["..."])
    got = blocks[0][1].split("\n", 1)[1]  # drop the `$ deg check …` prompt
    check("check summary + first claim lines", got, want)

    # ── 2. explain --mermaid ───────────────────────────────────────────────
    out = run(
        [
            "explain",
            "examples/position/model.dg",
            "P_reads_vec3_z",
            "--mermaid",
        ]
    )
    got = blocks[1][1].split("\n", 1)[1]
    check("explain --mermaid (full block)", got, out)

    # ── 3. seal stdout ─────────────────────────────────────────────────────
    out = run(
        ["seal", "examples/position/model.dg", "--out", SEAL_OUT]
    )
    got = blocks[2][1].split("\n", 1)[1]
    check("seal stdout", got, out)

    # ── 4. lock JSON excerpt ───────────────────────────────────────────────
    lock = json.load(open(SEAL_OUT))
    block = blocks[3][1]
    lines = block.splitlines()
    hyps_line = next(l for l in lines if '"hypotheses"' in l)
    sealed_line = next(l for l in lines if '"sealed"' in l)
    obls_line = next(l for l in lines if '"obligations"' in l)

    def names(line):
        return re.findall(r'"([A-Za-z0-9_.]+)"', line.split(":", 1)[1])

    ok = True
    ok &= lock["artifact_count"] == 5
    art0 = lock["artifacts"][0]
    for key, value in [
        ("kind", "binary"),
        ("name", "b1"),
        ("path", "examples/fixtures/game-b1.bin"),
        (
            "sha256",
            "470de64c4b572ec064a0e14e1831017dea5c6204f24383f0bc31b9cd474beca6",
        ),
        ("verified", True),
    ]:
        ok &= art0[key] == value
    ok &= names(hyps_line) == [h["name"] for h in lock["hypotheses"]]
    ok &= names(sealed_line) == [s["name"] for s in lock["sealed"]]
    ok &= names(obls_line) == [o["name"] for o in lock["obligations"]]
    ok &= any('"deg_version": "0.1.0"' in l for l in lines)
    ok &= any('"model": "examples/position/model.dg"' in l for l in lines)
    ok &= any('"seal_threshold": "deterministic"' in l for l in lines)
    ok &= any('"artifact_count": 5' in l for l in lines)
    print("ok: lock JSON excerpt" if ok else "--- FAIL: lock JSON excerpt ---")
    if not ok:
        fails.append("lock JSON excerpt")

    # ── 5. port --markdown ─────────────────────────────────────────────────
    out = run(
        ["port", "examples/port/model.dg", "--to", "b2", "--markdown"]
    ).splitlines()
    # Real output lines: title through the last claims row, then the README's
    # `… the new-obligation and warning sections follow …` marker.
    want = "\n".join(out[:16])
    got = blocks[4][1].split("\n", 1)[1]
    got = got.rsplit("\n… the new-obligation", 1)[0]
    check("port --markdown (Mappings + Claims tables)", got, want)

    if fails:
        print(
            "FAILED: README excerpt(s) drifted from the binary output: "
            + ", ".join(fails)
        )
        return 1
    print("all README excerpts match the built binary")
    return 0


if __name__ == "__main__":
    sys.exit(main())

#!/usr/bin/env python3
"""Generate the deterministic DeG example fixtures.

Everything here is synthetic and checked in so `deg check examples/...` is
reproducible without a real game or network. The binary is a raw image with a
small .text region; the pcap contains UDP packets with two opcodes; the RNG
datasets are genuine MT19937 vectors.

Run from the repository root:

    python3 tools/make_fixtures.py

It prints (and writes) examples/fixtures/manifest.json. If the files change,
update the `sha256:` fields in the example models (the `--manifest` output
lists exactly which hash belongs to which artifact).
"""

from __future__ import annotations

import hashlib
import json
import random
import struct
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
FIX = ROOT / "examples" / "fixtures"
FIX.mkdir(parents=True, exist_ok=True)

LOAD = 0x140000000
TEXT_START = 0x140001000
TEXT_END = 0x140001400


def magic(tag: bytes) -> bytes:
    assert len(tag) == 4
    return b"DeG!" + tag


def read_position_code(tag: bytes) -> bytes:
    return (
        b"\x48\xb8"
        + magic(tag)
        + bytes.fromhex("F30F104708F30F104704F30F104700C3")
    )


def loot_roll_code(tag: bytes) -> bytes:
    return b"\x48\xb8" + magic(tag) + bytes.fromhex("B90C00000031D2F7F1C3")


def mt_step_code(tag: bytes, third: int) -> bytes:
    return (
        b"\x48\xb8"
        + magic(tag)
        + bytes.fromhex("B8DFB00899")
        + bytes.fromhex("B880562C9D")
        + b"\xb8"
        + struct.pack("<I", third)
        + b"\xc3"
    )


def make_binary(path: Path, prefix: bytes, shift: int, third_const: int) -> None:
    buf = bytearray(b"\x90" * (TEXT_END - LOAD))
    read_at = 0x1000 + shift
    loot_at = 0x1100 + shift
    mt_at = 0x1200 + shift
    for at, code in [
        (read_at, read_position_code(prefix + b"\x00\x00")),
        (loot_at, loot_roll_code(prefix + b"L\x00")),
        (mt_at, mt_step_code(prefix + b"M\x00", third_const)),
    ]:
        buf[at : at + len(code)] = code
    path.write_bytes(bytes(buf))


def write_pcap(path: Path, packets: list[tuple[int, bytes, int]]) -> None:
    packets.sort(key=lambda p: p[0])
    base_sec = 1_700_000_000
    out = bytearray()
    out += struct.pack("<IHHIIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    for ts_us, payload, dst_port in packets:
        sec = base_sec + ts_us // 1_000_000
        usec = ts_us % 1_000_000
        udp_len = 8 + len(payload)
        ip_len = 20 + udp_len
        ip = bytearray()
        ip.append(0x45)
        ip.append(0)
        ip += struct.pack(">H", ip_len)
        ip += b"\x00\x00\x00\x00"
        ip += bytes([64, 17])
        ip += b"\x00\x00"
        ip += bytes([10, 0, 0, 2])  # server
        ip += bytes([10, 0, 0, 1])  # client
        ip += struct.pack(">H", 27015)
        ip += struct.pack(">H", dst_port)
        ip += struct.pack(">H", udp_len)
        ip += b"\x00\x00"
        ip += payload
        frame = b"\x00" * 12 + b"\x08\x00" + bytes(ip)
        out += struct.pack("<IIII", sec, usec, len(frame), len(frame))
        out += frame
    path.write_bytes(bytes(out))


def position_payload(seq: int) -> bytes:
    return (
        struct.pack(">H", 0x01F4)
        + struct.pack(">I", seq)
        + struct.pack("<fff", 1.0, 2.0, 3.0)
        + b"\x00"
    )


def loot_payload(item: int) -> bytes:
    return struct.pack(">H", 0x02BC) + struct.pack(">H", item) + b"\x00" * 8


def make_capture(path: Path) -> None:
    jr = random.Random(42)
    position_jitter = [jr.randint(-100, 100) for _ in range(6400)]
    loot_jitter = [jr.randint(-100, 100) for _ in range(12_000)]
    packets: list[tuple[int, bytes, int]] = []
    for i in range(6400):
        packets.append(
            (1_000_000 + i * 15_625 + position_jitter[i], position_payload(i), 50000)
        )
    for j in range(12_000):
        packets.append(
            (1_000_000 + j * 10_000 + loot_jitter[j], loot_payload(j % 12), 50001)
        )
    write_pcap(path, packets)


def mt_words(seed: int) -> tuple[list[int], list[int]]:
    r = random.Random(seed)
    st = r.getstate()
    words = list(st[1][:-1])
    idx = st[1][-1]
    assert idx == 624 and len(words) == 624
    outputs = [r.getrandbits(32) for _ in range(64)]
    return words, outputs


def write_words(path: Path, words: list[int], fmt: str) -> None:
    path.write_text("".join((fmt % w) + "\n" for w in words))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main() -> None:
    make_binary(FIX / "game-b1.bin", b"b1", 0, 0xEFC60000)
    make_binary(FIX / "game-b2.bin", b"b2", 0x80, 0xEFC60001)

    make_capture(FIX / "session-b1.pcap")

    words1, outputs1 = mt_words(5489)
    words2, outputs2 = mt_words(987654321)
    write_words(FIX / "mt-state-b1.txt", words1, "0x%08x")
    write_words(FIX / "mt-observed-b1.txt", outputs1, "%d")
    write_words(FIX / "mt-state-b2.txt", words2, "0x%08x")
    write_words(FIX / "mt-observed-b2.txt", outputs2, "%d")
    write_words(
        FIX / "xs-state.txt",
        [123456789, 362436069, 521288629, 88675123],
        "%d",
    )

    b1 = sha(FIX / "game-b1.bin")
    b2 = sha(FIX / "game-b2.bin")
    cap = sha(FIX / "session-b1.pcap")

    (FIX / "trace.json").write_text(
        json.dumps(
            {
                "kind": "trace",
                "build": b1,
                "tool": "deg-fixture 0.1",
                "note": "This certificate stands in for a dataflow tool. The kernel admits it only at Observational.",
                "trace": {"from": "S2C_Position.pos", "to": "read_position"},
            },
            indent=2,
        )
        + "\n"
    )
    (FIX / "observability.json").write_text(
        json.dumps(
            {
                "kind": "observability",
                "build": b1,
                "tool": "deg-fixture 0.1",
                "observability": {"connection": "conn_7", "window": "c1"},
            },
            indent=2,
        )
        + "\n"
    )
    (FIX / "absence.json").write_text(
        json.dumps(
            {
                "kind": "absence",
                "build": b1,
                "tool": "mock-sound-analyzer 0.1",
                "absence": {
                    "field": "S2C_Position.pos",
                    "scope": ".text",
                    "window_start_us": 0,
                    "window_end_us": 100_000_000,
                    "writes": [],
                },
            },
            indent=2,
        )
        + "\n"
    )
    (FIX / "symbols-b1.json").write_text(
        json.dumps(
            {
                "build": b1,
                "tool": "fixture-pdb 0.1",
                "symbols": {
                    "read_position": "0x140001000",
                    "loot_roll": "0x140001100",
                    "mt_step": "0x140001200",
                },
                "types": {
                    "Vec3": {
                        "size": 12,
                        "align": 4,
                        "fields": [
                            {"name": "x", "type": "f32", "offset": 0},
                            {"name": "y", "type": "f32", "offset": 4},
                            {"name": "z", "type": "f32", "offset": 8},
                        ],
                    }
                },
            },
            indent=2,
        )
        + "\n"
    )

    manifest = {
        "builds": {"b1": b1, "b2": b2},
        "artifacts": {
            "game-b1.bin": b1,
            "game-b2.bin": b2,
            "session-b1.pcap": cap,
            "mt-state-b1.txt": sha(FIX / "mt-state-b1.txt"),
            "mt-observed-b1.txt": sha(FIX / "mt-observed-b1.txt"),
            "mt-state-b2.txt": sha(FIX / "mt-state-b2.txt"),
            "mt-observed-b2.txt": sha(FIX / "mt-observed-b2.txt"),
            "xs-state.txt": sha(FIX / "xs-state.txt"),
        },
    }
    (FIX / "manifest.json").write_text(json.dumps(manifest, indent=2) + "\n")
    print(json.dumps(manifest, indent=2))


if __name__ == "__main__":
    main()

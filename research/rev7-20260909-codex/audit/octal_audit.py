#!/usr/bin/env python3
"""Corrected, self-contained Rev 7 visible-group hex-to-octal endpoint probe."""
from __future__ import annotations

import hashlib
import json
import math
import platform
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
SOURCE = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OUT = HERE / "octal_audit_results.json"
ALLOW = {9, 10, 13} | set(range(32, 127))
EXPECTED_SHA256 = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"


def ciphertext() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    begin = text.index("`83 B57B2") + 1
    end = text.index("`", begin)
    value = "".join(text[begin:end].split()).upper()
    assert len(value) == 1092 and hashlib.sha256(value.encode("ascii")).hexdigest() == EXPECTED_SHA256
    return value


def orientations(value: str) -> dict[str, str]:
    pairs = [value[i:i+2] for i in range(0, len(value), 2)]
    return {
        "forward": value,
        "reverse": value[::-1],
        "byte_reverse": "".join(reversed(pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in pairs),
    }


def groups(value: str, alignment: str) -> list[str]:
    if alignment == "left":
        result = [value[:2]] + [value[i:i+5] for i in range(2, len(value), 5)]
    else:
        result = [value[i:i+5] for i in range(0, len(value)-2, 5)] + [value[-2:]]
    assert len(result) == 219 and sorted(map(len, result)).count(2) == 1
    assert "".join(result) == value
    return result


def serialize(grouped: list[str], render: str) -> tuple[str, list[int]]:
    pieces = []
    for group in grouped:
        piece = format(int(group, 16), "o")
        if render == "fixed":
            piece = piece.zfill(math.ceil(4 * len(group) / 3))
        pieces.append(piece)
    return "".join(pieces), list(map(len, pieces))


def inverse(stream: str, lengths: list[int], grouped: list[str]) -> str:
    pos = 0
    recovered = []
    for octal_len, original in zip(lengths, grouped):
        piece = stream[pos:pos+octal_len]
        pos += octal_len
        recovered.append(format(int(piece, 8), "X").zfill(len(original)))
    assert pos == len(stream)
    return "".join(recovered)


def fixed3(stream: str) -> bool:
    if len(stream) % 3:
        return False
    return all(int(stream[i:i+3], 8) in ALLOW for i in range(0, len(stream), 3))


def canonical_variable_count(stream: str) -> int:
    ways = [0] * (len(stream) + 1)
    ways[0] = 1
    for end in range(1, len(stream) + 1):
        for width in (2, 3):
            start = end - width
            if start < 0 or not ways[start]:
                continue
            token = stream[start:end]
            value = int(token, 8)
            if value in ALLOW and format(value, "o") == token:
                ways[end] += ways[start]
    return ways[-1]


def controls() -> dict:
    text = b"A\tZ\nM\r~"
    stream = "".join(format(value, "o") for value in text)
    assert canonical_variable_count(stream) >= 1
    assert fixed3("".join(f"{value:03o}" for value in text))
    assert not fixed3(f"{11:03o}") and not fixed3(f"{12:03o}")
    assert fixed3(f"{13:03o}")
    # A small end-to-end group fixture exercises leading-zero restoration.
    fixture_groups = ["41", "00009", "0005A"]
    for render in ("minimal", "fixed"):
        encoded, lengths = serialize(fixture_groups, render)
        assert inverse(encoded, lengths, fixture_groups) == "".join(fixture_groups)
    return {
        "allowed_endpoint": "TAB(9), LF(10), CR(13), printable ASCII 32..126",
        "variable_fixture_ascii_hex": text.hex().upper(),
        "variable_fixture_octal": stream,
        "variable_fixture_parse_count": canonical_variable_count(stream),
        "fixed3_fixture_passes": True,
        "forbidden_vt_ff_rejected": True,
        "minimal_and_fixed_group_inverse": True,
    }


def main() -> None:
    ct = ciphertext()
    rows = []
    inverse_checks = 0
    for orientation, value in orientations(ct).items():
        for alignment in ("left", "right"):
            grouped = groups(value, alignment)
            for render in ("minimal", "fixed"):
                forward, lengths = serialize(grouped, render)
                assert inverse(forward, lengths, grouped) == value
                inverse_checks += 1
                for reverse in (False, True):
                    stream = forward[::-1] if reverse else forward
                    rows.append({
                        "orientation": orientation,
                        "alignment": alignment,
                        "render": render,
                        "reverse": reverse,
                        "octal_length": len(stream),
                        "fixed3_complete": fixed3(stream),
                        "canonical_variable_parse_count": canonical_variable_count(stream),
                    })
    assert len(rows) == 32
    result = {
        "identity": "ASTRA",
        "python": sys.version,
        "platform": platform.platform(),
        "ciphertext_domain": "uppercase whitespace-free repository transcription, ASCII bytes",
        "ciphertext_sha256": hashlib.sha256(ct.encode("ascii")).hexdigest(),
        "scope": "4 orientations x 2 ragged alignments x minimal/fixed per-group octal x stream reversal; fixed 3-octal and canonical variable 2/3-octal ASCII endpoints",
        "allowed_codes": sorted(ALLOW),
        "row_count": len(rows),
        "unique_stream_descriptors": len({(r['orientation'],r['alignment'],r['render'],r['reverse']) for r in rows}),
        "complete_fixed3_rows": sum(r["fixed3_complete"] for r in rows),
        "complete_variable_rows": sum(r["canonical_variable_parse_count"] > 0 for r in rows),
        "maximum_variable_parse_count": max(r["canonical_variable_parse_count"] for r in rows),
        "exact_group_inverse_checks": inverse_checks,
        "controls": controls(),
        "rows": rows,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in (
        "ciphertext_sha256", "row_count", "complete_fixed3_rows",
        "complete_variable_rows", "maximum_variable_parse_count",
        "exact_group_inverse_checks", "controls")}, indent=2, sort_keys=True))
    print("results_sha256", hashlib.sha256(OUT.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Independent exhaustive reachability audit for Rev 7 fixed hex chunks -> decimal."""
from __future__ import annotations

import hashlib
import json
import math
import platform
import sys
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parent
REPO = HERE.parents[2]
SOURCE = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OWNER_RESULTS = RESEARCH / "numeral/results.json"
OUT = HERE / "decimal_audit_results.json"
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


def chunks(value: str, width: int, ragged: str) -> list[str]:
    remainder = len(value) % width
    if ragged == "left":
        result = ([value[:remainder]] if remainder else [])
        start, stop = remainder, len(value)
        result += [value[i:i+width] for i in range(start, stop, width)]
    else:
        stop = len(value) - remainder
        result = [value[i:i+width] for i in range(0, stop, width)]
        if remainder:
            result.append(value[stop:])
    assert "".join(result) == value and all(1 <= len(piece) <= width for piece in result)
    return result


def serialize(grouped: list[str], width: int, padded: bool) -> tuple[str, list[int]]:
    decimal_width = math.ceil(width * math.log10(16))
    pieces = []
    for group in grouped:
        piece = str(int(group, 16))
        if padded:
            piece = piece.zfill(decimal_width)
        pieces.append(piece)
    return "".join(pieces), list(map(len, pieces))


def invert(stream: str, lengths: list[int], grouped: list[str]) -> str:
    position = 0
    recovered = []
    for decimal_length, original in zip(lengths, grouped):
        token = stream[position:position+decimal_length]
        position += decimal_length
        recovered.append(format(int(token, 10), "X").zfill(len(original)))
    assert position == len(stream)
    return "".join(recovered)


def minimal_count(stream: str) -> int:
    """Exact count for canonical 1..3 decimal tokens in ALLOW."""
    ways = [0] * (len(stream) + 1)
    ways[0] = 1
    for end in range(1, len(stream) + 1):
        for width in (1, 2, 3):
            start = end - width
            if start < 0 or not ways[start]:
                continue
            token = stream[start:end]
            if width > 1 and token[0] == "0":
                continue
            if int(token) in ALLOW:
                ways[end] += ways[start]
    return ways[-1]


def fixed_count(stream: str, width: int) -> int:
    if len(stream) % width:
        return 0
    return int(all(int(stream[i:i+width]) in ALLOW for i in range(0, len(stream), width)))


def record_key(row: dict) -> tuple:
    return tuple(row[k] for k in ("orientation", "width", "ragged", "padded", "decimal_reverse", "parser"))


def compare_owner(rows: list[dict]) -> dict:
    if not OWNER_RESULTS.exists():
        return {"available": False}
    data = json.loads(OWNER_RESULTS.read_text(encoding="utf-8"))
    expected = {record_key(row): row["outputs"] for row in data["records"]}
    observed = {record_key(row): row["outputs"] for row in rows}
    mismatches = [(key, observed.get(key), expected.get(key)) for key in sorted(set(expected) | set(observed)) if observed.get(key) != expected.get(key)]
    return {
        "available": True,
        "owner_results_sha256": hashlib.sha256(OWNER_RESULTS.read_bytes()).hexdigest(),
        "record_mismatch_count": len(mismatches),
        "record_mismatch_examples": mismatches[:5],
    }


def controls() -> dict:
    minimal = "7210110810811132877982766813105718778"  # HELLO WORLD + LF/CR/TAB/~
    fixed2 = "726976767932877982766832091013"       # HELLO WORLD + TAB/LF/CR
    fixed3 = "117118119120121122"                    # uvwxyz
    assert minimal_count(minimal) > 0
    assert fixed_count(fixed2, 2) == 1
    assert fixed_count(fixed3, 3) == 1
    assert all(fixed_count(f"{value:03d}", 3) == 0 for value in (0, 11, 12, 127))
    return {
        "minimal_positive_parse_count": minimal_count(minimal),
        "fixed2_positive": True,
        "fixed3_positive": True,
        "forbidden_nul_vt_ff_del_rejected": True,
    }


def main() -> None:
    ct = ciphertext()
    rows = []
    unique_streams = set()
    inverse_checks = 0
    for orientation, value in orientations(ct).items():
        for width in range(2, 17):
            for ragged in ("left", "right"):
                grouped = chunks(value, width, ragged)
                for padded in (False, True):
                    forward, lengths = serialize(grouped, width, padded)
                    assert invert(forward, lengths, grouped) == value
                    inverse_checks += 1
                    for decimal_reverse in (False, True):
                        stream = forward[::-1] if decimal_reverse else forward
                        unique_streams.add(stream)
                        for parser in ("minimal", "fixed2", "fixed3"):
                            outputs = (minimal_count(stream) if parser == "minimal" else
                                       fixed_count(stream, int(parser[-1])))
                            rows.append({
                                "orientation": orientation, "width": width,
                                "ragged": ragged, "padded": padded,
                                "decimal_reverse": decimal_reverse, "parser": parser,
                                "outputs": outputs,
                            })
    assert len(rows) == 1440 and inverse_checks == 240
    result = {
        "identity": "ASTRA",
        "python": sys.version,
        "platform": platform.platform(),
        "ciphertext_domain": "uppercase whitespace-free repository transcription, ASCII bytes",
        "ciphertext_sha256": hashlib.sha256(ct.encode("ascii")).hexdigest(),
        "scope": "4 orientations x hex chunk widths 2..16 x 2 ragged alignments x minimal/full-width padded decimal x digit reversal x minimal/fixed2/fixed3 ASCII parsing",
        "allowed_codes": sorted(ALLOW),
        "labeled_decimal_streams": 480,
        "unique_decimal_streams": len(unique_streams),
        "parser_records": len(rows),
        "complete_parser_records": sum(row["outputs"] > 0 for row in rows),
        "total_complete_parses": sum(row["outputs"] for row in rows),
        "exact_chunk_inverse_checks": inverse_checks,
        "controls": controls(),
        "owner_comparison": compare_owner(rows),
        "records": rows,
    }
    OUT.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({k: result[k] for k in (
        "ciphertext_sha256", "labeled_decimal_streams", "unique_decimal_streams",
        "parser_records", "complete_parser_records", "total_complete_parses",
        "exact_chunk_inverse_checks", "controls", "owner_comparison")}, indent=2, sort_keys=True))
    print("results_sha256", hashlib.sha256(OUT.read_bytes()).hexdigest())


if __name__ == "__main__":
    main()

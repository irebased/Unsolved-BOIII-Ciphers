#!/usr/bin/env python3
"""Whole-integer hex -> base-8/base-10 exact endpoint driver.

Control and target actions are explicit mutually exclusive flags. Controls do not
parse Rev 7. Target parsing requires --run-target plus a source-matched gate.
"""
from __future__ import annotations

import argparse
import functools
import hashlib
import json
import os
import sys
from pathlib import Path
from typing import Iterable, Sequence

HERE = Path(__file__).resolve().parent
REPO = HERE.parents[2]
REV7_SOURCE = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
IDENTITY = "ASTRA"
EXPECTED_REV7_SHA256 = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
ALLOWED = {9, 10, 13} | set(range(32, 127))
ORIENTATIONS = ("forward", "reverse", "byte_reverse", "nibble_swap")
BASES = (8, 10)
DIGIT_REVERSE = (False, True)
RESTORED_ZEROS = (0, 1, 2)
TARGET_PARSERS = ("fixed3", "canonical_variable2_3")
CONTROL_PARSERS = TARGET_PARSERS + ("canonical_variable1_3",)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def atomic_json(path: Path, value: dict) -> None:
    temporary = path.with_name(path.name + ".tmp")
    temporary.write_text(json.dumps(value, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def orientations(value: str) -> dict[str, str]:
    assert len(value) % 2 == 0
    pairs = [value[i:i + 2] for i in range(0, len(value), 2)]
    return {
        "forward": value,
        "reverse": value[::-1],
        "byte_reverse": "".join(reversed(pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in pairs),
    }


def int_to_digits(number: int, base: int) -> str:
    assert base in BASES and number >= 0
    if number == 0:
        return "0"
    out = []
    while number:
        number, digit = divmod(number, base)
        out.append(str(digit))
    return "".join(reversed(out))


def digits_to_int(digits: str, base: int) -> int:
    assert digits and all(char.isdigit() and int(char) < base for char in digits)
    number = 0
    for char in digits:
        number = number * base + int(char)
    return number


def canonical_token(value: int, base: int) -> str:
    return str(value) if base == 10 else format(value, "o")


def fixed_token(value: int, base: int) -> str:
    return canonical_token(value, base).zfill(3)


def valid_digit_stream(stream: str, base: int) -> bool:
    return bool(stream) and all("0" <= char <= "9" and int(char) < base for char in stream)


def parse_fixed3(stream: str, base: int) -> dict:
    if not valid_digit_stream(stream, base) or len(stream) % 3:
        return {"count": 0, "samples": []}
    values = []
    for index in range(0, len(stream), 3):
        value = digits_to_int(stream[index:index + 3], base)
        if value not in ALLOWED:
            return {"count": 0, "samples": []}
        values.append(value)
    return {"count": 1, "samples": [{"plaintext_hex": bytes(values).hex(),
                                       "token_widths": [3] * len(values)}]}


def parse_variable_dp(stream: str, base: int, widths: Sequence[int], sample_limit: int = 3) -> dict:
    """Exact suffix DP count plus at most three concrete parse paths."""
    if not valid_digit_stream(stream, base):
        return {"count": 0, "samples": []}
    n = len(stream)
    ways = [0] * (n + 1)
    ways[n] = 1
    choices = [[] for _ in range(n + 1)]
    for index in range(n - 1, -1, -1):
        for width in widths:
            end = index + width
            if end > n:
                continue
            token = stream[index:end]
            if width > 1 and token[0] == "0":
                continue
            value = digits_to_int(token, base)
            if value in ALLOWED and ways[end]:
                ways[index] += ways[end]
                choices[index].append((end, value, width))
    samples = []

    def collect(index: int, values: list[int], token_widths: list[int]) -> None:
        if len(samples) >= sample_limit:
            return
        if index == n:
            samples.append({"plaintext_hex": bytes(values).hex(),
                            "token_widths": token_widths[:]})
            return
        for end, value, width in choices[index]:
            collect(end, values + [value], token_widths + [width])
            if len(samples) >= sample_limit:
                return

    if ways[0]:
        collect(0, [], [])
    return {"count": ways[0], "samples": samples}


def parse_stream(stream: str, base: int, parser: str, sample_limit: int = 3) -> dict:
    if parser == "fixed3":
        return parse_fixed3(stream, base)
    if parser == "canonical_variable2_3":
        return parse_variable_dp(stream, base, (2, 3), sample_limit)
    if parser == "canonical_variable1_3":
        return parse_variable_dp(stream, base, (1, 2, 3), sample_limit)
    raise ValueError(parser)


def naive_variable(stream: str, base: int, widths: Sequence[int]) -> list[tuple[bytes, tuple[int, ...]]]:
    """Independent short-string recursion used only as a DP oracle."""
    if not valid_digit_stream(stream, base):
        return []
    results = []

    def walk(remainder: str, values: tuple[int, ...], used_widths: tuple[int, ...]) -> None:
        if not remainder:
            results.append((bytes(values), used_widths))
            return
        for width in widths:
            token = remainder[:width]
            if len(token) != width or (width > 1 and token.startswith("0")):
                continue
            value = 0
            valid = True
            for char in token:
                digit = ord(char) - ord("0")
                if not 0 <= digit < base:
                    valid = False
                    break
                value = value * base + digit
            if valid and value in ALLOWED:
                walk(remainder[width:], values + (value,), used_widths + (width,))

    walk(stream, (), ())
    return results


def render_sample(sample: dict, base: int, parser: str) -> str:
    plaintext = bytes.fromhex(sample["plaintext_hex"])
    widths = sample["token_widths"]
    if parser == "fixed3":
        assert widths == [3] * len(plaintext)
        return "".join(fixed_token(value, base) for value in plaintext)
    rendered = "".join(canonical_token(value, base) for value in plaintext)
    assert widths == [len(canonical_token(value, base)) for value in plaintext]
    return rendered


def full_reconstruction(oriented_hex: str, examined: str, base: int, reverse: bool,
                        restored_zeros: int, parser: str, sample: dict) -> dict:
    assert render_sample(sample, base, parser) == examined
    assert examined.startswith("0" * restored_zeros)
    directed = examined[restored_zeros:]
    minimal = directed[::-1] if reverse else directed
    assert minimal and not minimal.startswith("0")
    recovered_number = digits_to_int(minimal, base)
    recovered_hex = format(recovered_number, "X")
    assert recovered_hex == oriented_hex
    return {
        "examined_stream_exact": True,
        "digit_reverse_undone": reverse,
        "restored_zero_count": restored_zeros,
        "minimal_digits_sha256": sha256_bytes(minimal.encode("ascii")),
        "recovered_oriented_hex_sha256": sha256_bytes(recovered_hex.encode("ascii")),
        "recovered_oriented_hex_exact": True,
    }


def encode_plaintext(plaintext: bytes, base: int, parser: str) -> str:
    if parser == "fixed3":
        return "".join(fixed_token(value, base) for value in plaintext)
    widths = (2, 3) if parser == "canonical_variable2_3" else (1, 2, 3)
    tokens = [canonical_token(value, base) for value in plaintext]
    assert all(len(token) in widths for token in tokens)
    return "".join(tokens)


def plant_control(base: int, parser: str, plaintext: bytes) -> dict:
    encoded = encode_plaintext(plaintext, base, parser)
    lost_zeros = len(encoded) - len(encoded.lstrip("0"))
    number = digits_to_int(encoded, base)
    oriented_hex = format(number, "X")
    minimal = int_to_digits(int(oriented_hex, 16), base)
    assert minimal == encoded[lost_zeros:]
    examined = "0" * lost_zeros + minimal
    parsed = parse_stream(examined, base, parser)
    wanted = plaintext.hex()
    matches = [sample for sample in parsed["samples"] if sample["plaintext_hex"] == wanted]
    assert matches
    inverse = full_reconstruction(oriented_hex, examined, base, False, lost_zeros, parser, matches[0])
    return {
        "identity": IDENTITY,
        "base": base,
        "parser": parser,
        "plaintext_hex": wanted,
        "plaintext_sha256": sha256_bytes(plaintext),
        "encoded_digits": encoded,
        "encoded_sha256": sha256_bytes(encoded.encode("ascii")),
        "leading_zeros_lost_by_integer_conversion": lost_zeros,
        "restored_zeros": lost_zeros,
        "hex": oriented_hex,
        "parse_count": parsed["count"],
        "plant_in_retained_samples": True,
        "inverse": inverse,
    }


def reverse_direction_control(base: int, restored_zeros: int, plaintext: bytes) -> dict:
    """Construct a fixed-3 plant in the reversed examined direction."""
    examined = encode_plaintext(plaintext, base, "fixed3")
    assert examined.startswith("0" * restored_zeros)
    directed = examined[restored_zeros:]
    assert directed and not directed.endswith("0")
    minimal = directed[::-1]
    assert not minimal.startswith("0")
    oriented_hex = format(digits_to_int(minimal, base), "X")
    regenerated_minimal = int_to_digits(int(oriented_hex, 16), base)
    regenerated_examined = "0" * restored_zeros + regenerated_minimal[::-1]
    assert regenerated_examined == examined
    parsed = parse_stream(examined, base, "fixed3")
    assert parsed["count"] == 1 and parsed["samples"][0]["plaintext_hex"] == plaintext.hex()
    inverse = full_reconstruction(oriented_hex, examined, base, True,
                                  restored_zeros, "fixed3", parsed["samples"][0])
    return {
        "identity": IDENTITY,
        "base": base,
        "digit_reverse": True,
        "restored_zeros": restored_zeros,
        "parser": "fixed3",
        "plaintext_hex": plaintext.hex(),
        "examined_digits": examined,
        "minimal_digits": minimal,
        "hex": oriented_hex,
        "parse_count": parsed["count"],
        "inverse": inverse,
    }


def reverse_direction_controls() -> dict:
    rows = [
        reverse_direction_control(10, 0, b"u"),   # 117
        reverse_direction_control(10, 1, b"\r"),  # 013
        reverse_direction_control(10, 2, b"\t"),  # 009
        reverse_direction_control(8, 0, b"A"),    # 101
        reverse_direction_control(8, 1, b"\t"),   # 011
    ]
    # With two restored zeroes, a base-8 fixed3 stream starts with 00d = 0..7,
    # none allowed; canonical variable parsing also rejects a leading-zero token.
    impossible_examined = "00101"
    fixed = parse_stream(impossible_examined, 8, "fixed3")
    variable = parse_stream(impossible_examined, 8, "canonical_variable2_3")
    assert fixed["count"] == variable["count"] == 0
    return {
        "identity": IDENTITY,
        "positive_rows": rows,
        "base8_two_zero_impossibility": {
            "restored_zeros": 2,
            "reason": "fixed3 first token 00d is 0..7 and disallowed; canonical variable tokens cannot start zero",
            "fixed3_count": fixed["count"],
            "canonical_variable2_3_count": variable["count"],
            "passed": True,
        },
    }


def dp_naive_controls() -> list[dict]:
    fixtures = {
        10: ["0", "9", "10", "13", "032", "065", "32", "65", "3265", "91013", "32101365"],
        8: ["0", "9", "11", "12", "15", "040", "101", "40", "101", "40101", "111215", "401215101"],
    }
    rows = []
    for base, streams in fixtures.items():
        for stream in streams:
            for parser, widths in (("canonical_variable1_3", (1, 2, 3)),
                                   ("canonical_variable2_3", (2, 3))):
                dp = parse_variable_dp(stream, base, widths)
                naive = naive_variable(stream, base, widths)
                dp_set = {(bytes.fromhex(sample["plaintext_hex"]), tuple(sample["token_widths"]))
                          for sample in dp["samples"]}
                naive_set = set(naive)
                assert dp["count"] == len(naive)
                assert dp["count"] <= 3
                assert dp_set == naive_set
                rows.append({
                    "identity": IDENTITY,
                    "base": base,
                    "stream": stream,
                    "parser": parser,
                    "dp_count": dp["count"],
                    "naive_count": len(naive),
                    "counts_equal": True,
                    "all_small_paths_equal": True,
                    "paths": [
                        {"plaintext_hex": plaintext.hex(), "token_widths": list(widths_used)}
                        for plaintext, widths_used in sorted(naive_set)
                    ],
                    "retained_sample_count": len(dp["samples"]),
                })
    return rows


def padding_controls() -> list[dict]:
    cases = [
        (10, "009", "fixed3", 1, "TAB padded decimal"),
        (10, "009", "canonical_variable2_3", 0, "leading-zero token forbidden"),
        (10, "9", "canonical_variable1_3", 1, "one-digit TAB control extension"),
        (10, "9", "canonical_variable2_3", 0, "one-digit TAB excluded"),
        (10, "032", "fixed3", 1, "padded decimal space"),
        (10, "032", "canonical_variable2_3", 0, "padded decimal noncanonical"),
        (10, "32", "canonical_variable2_3", 1, "canonical decimal space"),
        (10, "065", "fixed3", 1, "padded decimal A"),
        (10, "65", "canonical_variable2_3", 1, "canonical decimal A"),
        (8, "011", "fixed3", 1, "padded octal TAB"),
        (8, "011", "canonical_variable2_3", 0, "padded octal noncanonical"),
        (8, "11", "canonical_variable2_3", 1, "canonical octal TAB"),
        (8, "040", "fixed3", 1, "padded octal space"),
        (8, "040", "canonical_variable2_3", 0, "padded octal noncanonical"),
        (8, "40", "canonical_variable2_3", 1, "canonical octal space"),
    ]
    rows = []
    for base, stream, parser, expected, note in cases:
        parsed = parse_stream(stream, base, parser)
        assert parsed["count"] == expected
        rows.append({"identity": IDENTITY, "base": base, "stream": stream,
                     "parser": parser, "expected_count": expected,
                     "actual_count": parsed["count"], "passed": True, "note": note})
    return rows


def control_gate() -> dict:
    fixed_plain = b"\tFIXED WIDTH CONTROL\r\n"
    variable_plain = b"\nVARIABLE WIDTH CONTROL A~\r"
    plants = []
    for base in BASES:
        plants.append(plant_control(base, "fixed3", fixed_plain))
        plants.append(plant_control(base, "canonical_variable2_3", variable_plain))
    fixed_by_base = {row["base"]: row for row in plants if row["parser"] == "fixed3"}
    assert fixed_by_base[10]["encoded_digits"].startswith("009")
    assert fixed_by_base[10]["leading_zeros_lost_by_integer_conversion"] == 2
    assert fixed_by_base[8]["encoded_digits"].startswith("011")
    assert fixed_by_base[8]["leading_zeros_lost_by_integer_conversion"] == 1
    reverse_rows = reverse_direction_controls()
    dp_rows = dp_naive_controls()
    padding_rows = padding_controls()
    result = {
        "identity": IDENTITY,
        "target_evaluated": False,
        "allowed_bytes": sorted(ALLOWED),
        "scope": {
            "bases": list(BASES),
            "orientations": list(ORIENTATIONS),
            "digit_reverse": list(DIGIT_REVERSE),
            "restored_zeros": list(RESTORED_ZEROS),
            "labeled_digit_streams": 48,
            "target_parsers": list(TARGET_PARSERS),
            "target_parser_cells": 96,
            "control_only_parser": "canonical_variable1_3",
            "operation_order": "canonical whole-integer base digits; optionally reverse the canonical digits; prepend 0..2 restored zeros to that selected direction; parse",
        },
        "full_chain_plants": plants,
        "reverse_direction_controls": reverse_rows,
        "dp_vs_naive": dp_rows,
        "padding_and_canonicalization": padding_rows,
        "checks": {
            "four_full_chain_plants_pass": len(plants) == 4 and all(row["plant_in_retained_samples"] for row in plants),
            "five_feasible_reverse_direction_plants_pass": len(reverse_rows["positive_rows"]) == 5 and all(row["inverse"]["recovered_oriented_hex_exact"] for row in reverse_rows["positive_rows"]),
            "base8_two_zero_reverse_endpoint_impossible": reverse_rows["base8_two_zero_impossibility"]["passed"],
            "decimal_initial_tab_loses_two_zeros": True,
            "octal_initial_tab_loses_one_zero": True,
            "all_dp_naive_counts_equal": all(row["counts_equal"] for row in dp_rows),
            "all_small_sets_equal_when_fully_retained": all(row["all_small_paths_equal"] for row in dp_rows if row["dp_count"] <= 3),
            "all_padding_cases_pass": all(row["passed"] for row in padding_rows),
            "samples_limited_to_three": all(row["retained_sample_count"] <= 3 for row in dp_rows),
        },
        "source_hashes": {
            "controls_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
            "rev7_mdx_file_sha256": sha256_bytes(REV7_SOURCE.read_bytes()),
        },
        "runtime": {"python": sys.version},
    }
    assert all(result["checks"].values())
    return result


def require_frozen_controls() -> tuple[dict, str]:
    path = HERE / "controls.json"
    if not path.exists():
        raise SystemExit(f"target blocked: missing controls: {path}")
    data = json.loads(path.read_text(encoding="utf-8"))
    assert data["identity"] == IDENTITY and data["target_evaluated"] is False
    assert data["allowed_bytes"] == sorted(ALLOWED)
    assert data["scope"]["bases"] == list(BASES)
    assert data["scope"]["orientations"] == list(ORIENTATIONS)
    assert data["scope"]["digit_reverse"] == list(DIGIT_REVERSE)
    assert data["scope"]["restored_zeros"] == list(RESTORED_ZEROS)
    assert data["scope"]["target_parsers"] == list(TARGET_PARSERS)
    assert all(data["checks"].values())
    assert data["source_hashes"] == {
        "controls_py_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "rev7_mdx_file_sha256": sha256_bytes(REV7_SOURCE.read_bytes()),
    }
    return data, sha256_bytes(path.read_bytes())


def extract_rev7() -> str:
    text = REV7_SOURCE.read_text(encoding="utf-8")
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    value = "".join(text[start:end].split()).upper()
    assert len(value) == 1092 and sha256_bytes(value.encode("ascii")) == EXPECTED_REV7_SHA256
    return value


def run_target(output: Path) -> None:
    if output.exists():
        raise SystemExit(f"refusing existing target output: {output}")
    _controls, controls_sha256 = require_frozen_controls()
    rev7 = extract_rev7()
    rows = []
    for orientation, oriented_hex in orientations(rev7).items():
        number = int(oriented_hex, 16)
        for base in BASES:
            minimal = int_to_digits(number, base)
            assert digits_to_int(minimal, base) == number
            for restored_zeros in RESTORED_ZEROS:
                for reverse in DIGIT_REVERSE:
                    directed = minimal[::-1] if reverse else minimal
                    examined = "0" * restored_zeros + directed
                    for parser in TARGET_PARSERS:
                        parsed = parse_stream(examined, base, parser)
                        samples = []
                        for sample in parsed["samples"]:
                            samples.append({**sample, "inverse": full_reconstruction(
                                oriented_hex, examined, base, reverse, restored_zeros, parser, sample)})
                        rows.append({
                            "identity": IDENTITY,
                            "orientation": orientation,
                            "base": base,
                            "restored_zeros": restored_zeros,
                            "digit_reverse": reverse,
                            "parser": parser,
                            "examined_length": len(examined),
                            "examined_sha256": sha256_bytes(examined.encode("ascii")),
                            "exact_parse_count": parsed["count"],
                            "retained_samples": samples,
                        })
    assert len(rows) == 96
    result = {
        "identity": IDENTITY,
        "target_evaluated": True,
        "ciphertext_sha256": sha256_bytes(rev7.encode("ascii")),
        "controls_sha256": controls_sha256,
        "source_sha256": sha256_bytes(Path(__file__).read_bytes()),
        "rows": rows,
    }
    atomic_json(output, result)
    print(json.dumps({"identity": IDENTITY, "target_evaluated": True,
                      "rows": len(rows), "rows_with_parses": sum(row["exact_parse_count"] > 0 for row in rows),
                      "result_sha256": sha256_bytes(output.read_bytes())}, sort_keys=True))


def main() -> None:
    parser = argparse.ArgumentParser()
    actions = parser.add_mutually_exclusive_group(required=True)
    actions.add_argument("--controls", action="store_true")
    actions.add_argument("--run-target", action="store_true")
    parser.add_argument("--controls-output", type=Path, default=HERE / "controls.json")
    parser.add_argument("--target-output", type=Path, default=HERE / "target_results.json")
    args = parser.parse_args()
    if args.controls:
        if args.controls_output.exists():
            raise SystemExit(f"refusing existing controls output: {args.controls_output}")
        result = control_gate()
        atomic_json(args.controls_output, result)
        print(json.dumps({"identity": IDENTITY, "target_evaluated": False,
                          "controls_sha256": sha256_bytes(args.controls_output.read_bytes()),
                          "source_hashes": result["source_hashes"]}, indent=2, sort_keys=True))
    else:
        run_target(args.target_output)


if __name__ == "__main__":
    main()

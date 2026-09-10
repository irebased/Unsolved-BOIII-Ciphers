#!/usr/bin/env python3
from __future__ import annotations

"""Production character-AMSCO geometry plus independent synthetic controls."""

import argparse
import hashlib
import itertools
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEDGER = HERE / "geometry.json"
IDENTITY = "ASTRA"
ORIENTATION_ORDER = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def validate(n: int, width: int, start: str, order) -> tuple[int, ...]:
    order = tuple(order)
    if not 2 <= width <= 10:
        raise ValueError("width must be 2..10")
    if start not in ("12", "21"):
        raise ValueError("start must be 12 or 21")
    if len(order) != width or tuple(sorted(order)) != tuple(range(width)):
        raise ValueError("order must be an exact column permutation")
    if n < 0:
        raise ValueError("negative length")
    return order


# Production layout: a flat continuous cell stream assigned cyclically to columns.
def production_cells(n: int, width: int, start: str):
    size = 1 if start == "12" else 2
    position = 0
    cell_index = 0
    cells = []
    while position < n:
        actual = min(size, n - position)
        cells.append((cell_index % width, position, actual, size))
        position += actual
        cell_index += 1
        size = 3 - size
    return cells


def forward(value, order, start):
    n = len(value)
    width = len(order)
    order = validate(n, width, start, order)
    columns = [[] for _ in range(width)]
    for column, position, actual, _nominal in production_cells(n, width, start):
        columns[column].append((position, actual))
    output = []
    labels = []
    for column in order:
        for position, actual in columns[column]:
            output.extend(value[position:position + actual])
            labels.extend(range(position, position + actual))
    return output, labels


def inverse(cipher, order, start, n):
    width = len(order)
    order = validate(n, width, start, order)
    if len(cipher) != n:
        raise ValueError("cipher length must equal declared natural length")
    columns = [[] for _ in range(width)]
    for column, position, actual, _nominal in production_cells(n, width, start):
        columns[column].append((position, actual))
    restored = [None] * n
    cursor = 0
    for column in order:
        for position, actual in columns[column]:
            piece = cipher[cursor:cursor + actual]
            if len(piece) != actual:
                raise ValueError("short ciphertext")
            restored[position:position + actual] = piece
            cursor += actual
    if cursor != len(cipher) or any(value is None for value in restored):
        raise ValueError("cipher length/layout mismatch")
    return restored


def inverse_prefix(cipher, order, start, n, prefix_length):
    """Indexed gather of a natural-stream prefix without materializing full inverse."""
    width = len(order)
    order = validate(n, width, start, order)
    if len(cipher) != n:
        raise ValueError("cipher length must equal declared natural length")
    if not 0 <= prefix_length <= n:
        raise ValueError("prefix length")
    cells = production_cells(n, width, start)
    column_cells = [[] for _ in range(width)]
    for column, position, actual, _nominal in cells:
        column_cells[column].append((position, actual))
    offsets = {}
    cursor = 0
    for column in order:
        for position, actual in column_cells[column]:
            for within in range(actual):
                offsets[position + within] = cursor + within
            cursor += actual
    if cursor != len(cipher):
        raise ValueError("cipher length/layout mismatch")
    return [cipher[offsets[position]] for position in range(prefix_length)]


# Independent oracle: construct explicit rows of token cells, never calling production_cells.
def oracle_rows(n: int, width: int, start: str, order):
    validate(n, width, start, order)
    rows = []
    position = 0
    next_size = 1 if start == "12" else 2
    while position < n:
        row = []
        for column in range(width):
            if position >= n:
                break
            nominal = next_size
            actual = nominal if position + nominal <= n else n - position
            row.append({"column": column, "positions": tuple(range(position, position + actual)), "nominal": nominal})
            position += actual
            next_size = 3 - next_size
        rows.append(row)
    return rows


def oracle_forward(value, order, start):
    n = len(value)
    width = len(order)
    order = validate(n, width, start, order)
    rows = oracle_rows(n, width, start, order)
    output = []
    labels = []
    for wanted_column in order:
        for row in rows:
            for cell in row:
                if cell["column"] == wanted_column:
                    for position in cell["positions"]:
                        output.append(value[position])
                        labels.append(position)
    return output, labels


def oracle_inverse(cipher, order, start, n):
    width = len(order)
    order = validate(n, width, start, order)
    if len(cipher) != n:
        raise ValueError("oracle exact length")
    rows = oracle_rows(n, width, start, order)
    column_positions = {column: [] for column in range(width)}
    for row in rows:
        for cell in row:
            column_positions[cell["column"]].extend(cell["positions"])
    by_position = {}
    cursor = 0
    for column in order:
        for position in column_positions[column]:
            if cursor >= len(cipher):
                raise ValueError("oracle short ciphertext")
            by_position[position] = cipher[cursor]
            cursor += 1
    if cursor != len(cipher) or set(by_position) != set(range(n)):
        raise ValueError("oracle length/layout mismatch")
    return [by_position[position] for position in range(n)]


def nibble_swap(text: str) -> str:
    if len(text) % 2:
        raise ValueError("hex length")
    return "".join(text[i + 1] + text[i] for i in range(0, len(text), 2))


def byte_reverse(text: str) -> str:
    if len(text) % 2:
        raise ValueError("hex length")
    return "".join(reversed([text[i:i + 2] for i in range(0, len(text), 2)]))


def orientations(text: str) -> dict[str, str]:
    return {
        "forward": text,
        "full_hex_reverse": text[::-1],
        "byte_reverse": byte_reverse(text),
        "nibble_swap": nibble_swap(text),
    }


def deterministic_order(width: int, start: str, orientation: str) -> tuple[int, ...]:
    # Stable across Python versions: order columns by a fully specified SHA-256 key.
    values = sorted(range(width), key=lambda column: hashlib.sha256(
        f"ASTRA|{width}|{start}|{orientation}|{column}".encode()).digest())
    if width > 2 and tuple(values) in (tuple(range(width)), tuple(reversed(range(width)))):
        values = values[1:] + values[:1]
    return tuple(values)


def order_variants(width: int, start: str, orientation: str):
    return (
        ("identity", tuple(range(width))),
        ("reverse", tuple(reversed(range(width)))),
        ("deterministic_shuffle", deterministic_order(width, start, orientation)),
    )


def digest_rows(rows) -> str:
    return hashlib.sha256(json.dumps(rows, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def truncated_last_cell(n: int, width: int, start: str) -> bool:
    cells = production_cells(n, width, start)
    return bool(cells and cells[-1][2] < cells[-1][3])


def prefix_probes(n: int, width: int, start: str, order) -> list[int]:
    """Probe edges plus natural positions adjacent to odd ciphertext-column boundaries."""
    _cipher, labels = oracle_forward(list(range(n)), order, start)
    rows = oracle_rows(n, width, start, order)
    lengths = {column: 0 for column in range(width)}
    for row in rows:
        for cell in row:
            lengths[cell["column"]] += len(cell["positions"])
    boundaries = []
    cursor = 0
    for column in order[:-1]:
        cursor += lengths[column]
        if cursor % 2:
            boundaries.append(cursor)
    probes = {0, min(1, n), min(2, n), min(3, n), max(0, n - 1), n}
    for boundary in boundaries:
        for cipher_index in (boundary - 1, boundary):
            if 0 <= cipher_index < n:
                natural = labels[cipher_index]
                probes.update((max(0, natural), min(n, natural + 1), min(n, natural + 2)))
    return sorted(probes)


def expect_value_error(function, *args):
    try:
        function(*args)
    except ValueError:
        return
    raise AssertionError("expected ValueError")


def small_controls():
    examples = []
    wanted_examples = {
        (0, 2, (0, 1), "12"), (1, 2, (1, 0), "21"),
        (2, 3, (1, 2, 0), "12"), (7, 4, (3, 2, 1, 0), "21"),
        (24, 6, (2, 5, 1, 4, 0, 3), "12"),
    }
    row_hash = hashlib.sha256()
    cases = prefix_checks = truncated_cases = 0
    for n in range(25):
        source = [("token", i) for i in range(n)]
        for width in range(2, 7):
            for order in itertools.permutations(range(width)):
                for start in ("12", "21"):
                    production_cipher, production_labels = forward(source, order, start)
                    oracle_cipher, oracle_labels = oracle_forward(source, order, start)
                    assert production_cipher == oracle_cipher
                    assert production_labels == oracle_labels
                    assert inverse(production_cipher, order, start, n) == source
                    assert oracle_inverse(production_cipher, order, start, n) == source
                    for prefix_length in range(n + 1):
                        gathered = inverse_prefix(production_cipher, order, start, n, prefix_length)
                        assert gathered == source[:prefix_length]
                        assert gathered == oracle_inverse(production_cipher, order, start, n)[:prefix_length]
                        prefix_checks += 1
                    is_truncated = truncated_last_cell(n, width, start)
                    truncated_cases += is_truncated
                    compact = [n, width, list(order), start, production_labels, is_truncated]
                    row_hash.update(json.dumps(compact, separators=(",", ":")).encode() + b"\n")
                    if (n, width, tuple(order), start) in wanted_examples:
                        examples.append({"n": n, "width": width, "order": list(order), "start": start,
                                         "cipher_labels": production_labels, "truncated_last_cell": is_truncated})
                    cases += 1
    return {"cases": cases, "prefix_checks": prefix_checks, "truncated_last_cell_cases": truncated_cases,
            "digest": row_hash.hexdigest(), "examples": examples}


def validation_controls():
    rows = []
    for width in range(2, 11):
        for start in ("12", "21"):
            order = tuple(range(width))
            n = 3 * width + 2
            source = list(range(n))
            cipher, _ = forward(source, order, start)
            expect_value_error(inverse, cipher[:-1], order, start, n)
            expect_value_error(inverse, cipher + ["extra"], order, start, n)
            expect_value_error(inverse_prefix, cipher[:-1], order, start, n, n)
            expect_value_error(inverse_prefix, cipher + ["extra"], order, start, n, n)
            expect_value_error(inverse_prefix, cipher, order, start, n, -1)
            expect_value_error(inverse_prefix, cipher, order, start, n, n + 1)
            expect_value_error(oracle_inverse, cipher[:-1], order, start, n)
            expect_value_error(oracle_inverse, cipher + ["extra"], order, start, n)
            duplicate = tuple(range(width - 1)) + (0,)
            missing = tuple(range(width - 1))
            out_of_range = tuple(range(width - 1)) + (width,)
            expect_value_error(validate, n, width, start, duplicate)
            expect_value_error(validate, n, width, start, missing)
            expect_value_error(validate, n, width, start, out_of_range)
            expect_value_error(forward, source, order, "bad")
            rows.append({"width": width, "start": start, "short_rejected": True, "long_rejected": True,
                         "oracle_short_and_long_rejected": True, "bad_prefix_rejected": True,
                         "duplicate_missing_out_of_range_orders_rejected": True, "bad_start_rejected": True})
    expect_value_error(validate, 0, 1, "12", (0,))
    expect_value_error(validate, 0, 11, "12", tuple(range(11)))
    expect_value_error(validate, -1, 2, "12", (0, 1))
    return {"width_start_cases": len(rows), "rows": rows, "per_width_start_invalid_parameter_cases": 72,
            "global_invalid_width_or_length_cases": 3}


def full_controls():
    raw = bytes((index * 37 + 11) % 256 for index in range(546))
    base = raw.hex().upper()
    oriented = orientations(base)
    rows = []
    prefix_checks = odd_boundary_cases = partial_width10 = 0
    for orientation, text in oriented.items():
        expected_decoded = bytes.fromhex(text)
        for width in range(2, 11):
            for start in ("12", "21"):
                cells = production_cells(len(text), width, start)
                assert not truncated_last_cell(len(text), width, start)
                if width == 10:
                    assert len(cells) % width == 8
                    partial_width10 += 1
                for order_label, order in order_variants(width, start, orientation):
                    prod_cipher, prod_labels = forward(list(text), order, start)
                    oracle_cipher, oracle_labels = oracle_forward(list(text), order, start)
                    assert prod_cipher == oracle_cipher and prod_labels == oracle_labels
                    prod_plain = inverse(prod_cipher, order, start, len(text))
                    oracle_plain = oracle_inverse(prod_cipher, order, start, len(text))
                    assert prod_plain == oracle_plain == list(text)
                    restored = "".join(prod_plain)
                    decoded = bytes.fromhex(restored)
                    assert decoded == expected_decoded
                    probes = prefix_probes(len(text), width, start, order)
                    for length in probes:
                        gathered = inverse_prefix(prod_cipher, order, start, len(text), length)
                        assert gathered == prod_plain[:length] == oracle_plain[:length]
                        prefix_checks += 1
                    oracle_layout = oracle_rows(len(text), width, start, order)
                    assert sum(len(row) for row in oracle_layout) == len(cells)
                    lengths = [sum(len(cell["positions"]) for row in oracle_layout for cell in row if cell["column"] == c) for c in range(width)]
                    cumulative = 0
                    odd_boundaries = 0
                    for column in order[:-1]:
                        cumulative += lengths[column]
                        odd_boundaries += cumulative % 2
                    odd_boundary_cases += odd_boundaries > 0
                    rows.append({
                        "orientation": orientation, "width": width, "start": start,
                        "order_kind": order_label, "order": list(order),
                        "input_sha256": hashlib.sha256(text.encode()).hexdigest(),
                        "cipher_sha256": hashlib.sha256("".join(prod_cipher).encode()).hexdigest(),
                        "labels_sha256": hashlib.sha256(json.dumps(prod_labels, separators=(",", ":")).encode()).hexdigest(),
                        "recovered_sha256": hashlib.sha256(restored.encode()).hexdigest(),
                        "decoded_sha256": hashlib.sha256(decoded).hexdigest(),
                        "prefix_probe_count": len(probes), "odd_cipher_column_boundaries": odd_boundaries,
                        "cell_count": len(cells), "partial_final_row_cells": len(cells) % width,
                        "truncated_final_cell": False,
                    })
    assert len(rows) == 216 and partial_width10 == 8
    return {"source_formula": "byte[i]=(i*37+11)%256 for i=0..545", "source_chars": len(base),
            "source_sha256": hashlib.sha256(base.encode()).hexdigest(), "cases": len(rows),
            "prefix_checks": prefix_checks, "cases_with_odd_cipher_column_boundary": odd_boundary_cases,
            "width10_start_orientation_cases_with_8_cell_partial_row": partial_width10,
            "digest": digest_rows(rows), "examples": rows[:4] + rows[-4:]}


def tiny_orientation_controls():
    text = "0123456789AC"
    expected = {"forward": "0123456789AC", "full_hex_reverse": "CA9876543210",
                "byte_reverse": "AC8967452301", "nibble_swap": "1032547698CA"}
    actual = orientations(text)
    assert actual == expected
    return {"input": text, "expected": expected, "actual": actual, "all_exact": True}


def produce(output: Path):
    if output.exists():
        raise SystemExit("refusing existing output: " + str(output))
    small = small_controls()
    validation = validation_controls()
    full = full_controls()
    result = {
        "identity": IDENTITY, "target_evaluated": False, "rev7_read": False, "crypto_evaluated": False,
        "scope": "Synthetic character-token AMSCO geometry only.",
        "definition": {
            "unit": "one hexadecimal character/token",
            "groups": "continuous alternating 1,2 or 2,1 tokens across row boundaries",
            "assignment": "cells assigned row-major to natural columns; ciphertext concatenates columns in supplied order",
            "partial_row": "a row may end before width cells when input ends",
            "truncated_cell": "only the final cell may be shorter than its nominal 1/2 size; no padding",
            "inverse_length": "ciphertext length must equal declared natural length exactly",
        },
        "tiny_orientations": tiny_orientation_controls(),
        "small_exhaustive": small,
        "validation": validation,
        "deterministic_1092": full,
        "source_hashes": {"amsco_geometry.py": sha(Path(__file__))},
        "assertions": {
            "production_forward_equals_independent_oracle": True,
            "production_inverse_equals_independent_oracle": True,
            "production_indexed_prefix_equals_full_inverse": True,
            "short_and_long_ciphertext_rejected": True,
            "all_widths_2_through_10_and_both_starts_validated": True,
            "four_tiny_orientations_exact": True,
            "full_global_inverse_precedes_hex_decode": True,
            "n1092_has_no_truncated_last_cell": True,
            "width10_has_eight_cell_partial_final_row": True,
            "no_target_or_crypto": True,
        },
        "limits": [
            "Character/token geometry only; this does not claim equivalence to any historical tool implementation.",
            "Column permutations are sampled by identity, reverse, and deterministic shuffle for the 1,092-token controls; no 10! target search is performed.",
            "No cipher, key, IV, endpoint detector, Rev7 data, or target evaluation is used.",
        ],
    }
    output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")
    print(json.dumps({"identity": IDENTITY, "output": str(output), "sha256": sha(output),
                      "small_cases": small["cases"], "full_cases": full["cases"]}, sort_keys=True))


def verify(path: Path):
    data = json.loads(path.read_text())
    assert data["identity"] == IDENTITY and data["target_evaluated"] is False and data["rev7_read"] is False
    assert data["crypto_evaluated"] is False and data["source_hashes"]["amsco_geometry.py"] == sha(Path(__file__))
    assert data["small_exhaustive"]["cases"] == 43600
    assert data["small_exhaustive"]["prefix_checks"] > data["small_exhaustive"]["cases"]
    assert data["small_exhaustive"]["truncated_last_cell_cases"] > 0
    assert data["validation"]["width_start_cases"] == 18
    assert data["deterministic_1092"]["cases"] == 216
    assert data["deterministic_1092"]["source_chars"] == 1092
    assert data["deterministic_1092"]["width10_start_orientation_cases_with_8_cell_partial_row"] == 8
    assert data["deterministic_1092"]["cases_with_odd_cipher_column_boundary"] > 0
    assert all(data["assertions"].values())
    # Recompute every synthetic certificate using the current production and oracle paths.
    assert data["tiny_orientations"] == tiny_orientation_controls()
    assert data["small_exhaustive"] == small_controls()
    assert data["validation"] == validation_controls()
    assert data["deterministic_1092"] == full_controls()
    print(json.dumps({"identity": IDENTITY, "verified": True, "read_only": True,
                      "ledger_sha256": sha(path), "ledger_bytes": path.stat().st_size,
                      "small_cases": 43600, "full_cases": 216,
                      "target_evaluated": False}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--regenerate", type=Path)
    parser.add_argument("--verify", type=Path)
    args = parser.parse_args()
    if args.regenerate:
        produce(args.regenerate.resolve())
    elif args.verify:
        verify(args.verify.resolve())
    else:
        verify(LEDGER)


if __name__ == "__main__":
    main()

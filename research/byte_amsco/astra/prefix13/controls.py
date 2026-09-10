#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import importlib.util
import itertools
import json
import math
import platform
import sys
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
PROOF = HERE / "proof.py"
LEDGER = HERE / "controls.json"
PARENT = HERE.parent
PARENT_CORE = PARENT / "core.py"
PARENT_CONTROLS = PARENT / "controls.py"
RUNTIME_DIR = HERE.parents[2] / "rev7-20260909-codex" / "iv_independent" / "cascade" / "runtime"
RUNTIME_PY = RUNTIME_DIR / "runtime.py"
RUNTIME_LEDGER = RUNTIME_DIR / "controls.json"
IDENTITY = "ASTRA"
PINS = {
    "parent_core.py": "2e7b413cb01396c8c6c97f21ad4a1e46939c3c1488c27e1c48bed8e24a48b990",
    "parent_controls.py": "b187ab27bbde490399333c19ddf62f8cb13f514b90fb50614cb231b4a5f65ad0",
    "parent_controls.json": "767d651729055d1d6fa202e8983635d3afafd46d06729924569db7260ed21175",
    "runtime.py": "8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4",
    "runtime_controls.json": "483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5",
}

sys.path.insert(0, str(HERE))
import proof


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def digest_records(records) -> str:
    h = hashlib.sha256()
    for item in records:
        h.update(json.dumps(item, sort_keys=True, separators=(",", ":")).encode())
        h.update(b"\n")
    return h.hexdigest()


def check_pins():
    paths = {
        "parent_core.py": PARENT_CORE,
        "parent_controls.py": PARENT_CONTROLS,
        "parent_controls.json": PARENT / "controls.json",
        "runtime.py": RUNTIME_PY,
        "runtime_controls.json": RUNTIME_LEDGER,
    }
    for label, path in paths.items():
        got = sha(path)
        if got != PINS[label]:
            raise AssertionError((label, got, PINS[label]))


def load_module(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def oracle_forward(data: bytes, width: int, order: tuple[int, ...], start: int) -> bytes:
    """Independent matrix materialization; does not call proof geometry."""
    cells = []
    pos = 0
    size = start
    while pos < len(data):
        take = min(size, len(data) - pos)
        cells.append(data[pos : pos + take])
        pos += take
        size = 3 - size
    out = bytearray()
    for natural_column in order:
        for cell_number, value in enumerate(cells):
            if cell_number % width == natural_column:
                out.extend(value)
    return bytes(out)


def oracle_inverse(observed: bytes, width: int, order: tuple[int, ...], start: int) -> bytes:
    """Independent complete inverse: fill natural cells from observed columns."""
    sizes = []
    left = len(observed)
    size = start
    while left:
        take = min(size, left)
        sizes.append(take)
        left -= take
        size = 3 - size
    column_cells = [[i for i in range(len(sizes)) if i % width == c] for c in range(width)]
    filled = {}
    pos = 0
    for column in order:
        for cell in column_cells[column]:
            take = sizes[cell]
            filled[cell] = observed[pos : pos + take]
            pos += take
    return b"".join(filled[i] for i in range(len(sizes)))


def toy_block(block: bytes) -> bytes:
    if len(block) != 8:
        raise ValueError
    s = sum((i + 1) * value for i, value in enumerate(block)) & 255
    return bytes(((s + 29 * i + block[(i + 3) % 8]) & 255) for i in range(8))


def assignment_from_order(order: tuple[int, ...]) -> tuple[int, ...]:
    return tuple(order.index(column) for column in range(6))


def full_order_accepts(observed: bytes, width: int, order: tuple[int, ...], start: int, block=toy_block):
    natural = oracle_inverse(observed, width, order, start)
    rows, _chunk = proof.validate_rectangular(len(observed), width, start)
    pos = 0
    values = []
    size = start
    for row in range(rows):
        row_bytes = 0
        for column in range(width):
            row_bytes += size
            size = 3 - size
        first9 = natural[pos : pos + 9]
        value = first9[8] ^ block(first9[:8])[0]
        values.append(value)
        if value not in proof.A105:
            return False, tuple(values)
        pos += row_bytes
    return True, tuple(values)


def exhaustive_complete(width: int, rows: int, start: int):
    n = 3 * width * rows // 2
    natural = bytes((i * 71 + width * 13 + start * 17) & 255 for i in range(n))
    generating_order = tuple((3 * i + 1) % width for i in range(width)) if width % 3 else tuple(reversed(range(width)))
    if len(set(generating_order)) != width:
        generating_order = tuple(reversed(range(width)))
    observed = oracle_forward(natural, width, generating_order, start)

    prefix_results = {}
    prefix_records = []
    for assignment in itertools.permutations(range(width), 6):
        accepted, values = proof.evaluate_prefix(observed, width, start, assignment, toy_block)
        prefix_results[assignment] = accepted
        prefix_records.append((assignment, accepted, values))

    full_survivors = []
    full_digest_rows = []
    for order in itertools.permutations(range(width)):
        accepted, values = full_order_accepts(observed, width, order, start)
        assignment = assignment_from_order(order)
        assert accepted == prefix_results[assignment]
        if accepted:
            full_survivors.append(order)
        full_digest_rows.append((order, accepted, values))

    survivor_prefixes = sum(prefix_results.values())
    weight = proof.completion_weight(width)
    assert survivor_prefixes * weight == len(full_survivors)
    assert (len(prefix_results) - survivor_prefixes) * weight + len(full_survivors) == math.factorial(width)
    return {
        "width": width,
        "rows": rows,
        "n": n,
        "start": start,
        "prefixes": len(prefix_results),
        "completion_weight": weight,
        "survivor_prefixes": survivor_prefixes,
        "rejected_prefixes": len(prefix_results) - survivor_prefixes,
        "full_orders": math.factorial(width),
        "full_survivor_orders": len(full_survivors),
        "prefix_digest": digest_records(prefix_records),
        "full_order_digest": digest_records(full_digest_rows),
        "survivor_orders_digest": digest_records(full_survivors),
        "factorial_partition": True,
    }


def cfb8_encrypt(plain: bytes, iv: bytes, encrypt_block):
    reg = iv
    out = bytearray()
    for value in plain:
        c = value ^ encrypt_block(reg)[0]
        out.append(c)
        reg = reg[1:] + bytes([c])
    return bytes(out)


def planted_width13(runtime):
    plaintext = (b"PREFIX13 BYTE AMSCO ALL IV CONTROL 0123456789.\n" * 12)[:546]
    if len(plaintext) < 546:
        plaintext += b"X" * (546 - len(plaintext))
    assert len(plaintext) == 546 and set(plaintext) <= proof.A105
    width = 13
    rows, chunk = proof.validate_rectangular(546, width, 1)
    assert rows == 28 and chunk == 42
    order = (7, 0, 12, 4, 9, 2, 11, 5, 1, 8, 3, 10, 6)
    true_assignment = assignment_from_order(order)
    bounded_assignments = [true_assignment]
    for assignment in itertools.islice(itertools.permutations(range(width), 6), 1024):
        if assignment != true_assignment:
            bounded_assignments.append(assignment)
    records = []
    with tempfile.TemporaryDirectory(prefix="astra-prefix13-") as td:
        builds = runtime.build_source_libraries(Path(td))
        registry = runtime.registry(builds)
        for backend_index, name in enumerate(("des", "blowfish", "bfcompat", "rc2")):
            backend = registry[name]
            assert backend.block_size == 8
            for start in (1, 2):
                suite_records = []
                true_values_by_suite = []
                for suite in range(2):
                    iv = bytes((backend_index * 37 + suite * 83 + i * 19 + 5) & 255 for i in range(8))
                    ciphertext = cfb8_encrypt(plaintext, iv, backend.encrypt_block)
                    assert ciphertext == backend.encrypt_cfb8(plaintext, iv)
                    observed = oracle_forward(ciphertext, width, order, start)
                    assert len(observed) == 546
                    accepted, values = proof.evaluate_prefix(observed, width, start, true_assignment, backend.encrypt_block)
                    assert accepted and values == tuple(plaintext[sum(proof.cell_size(r0, c, start) for r0 in range(r) for c in range(width)) + 8] for r in range(rows))
                    true_values_by_suite.append(values)
                    comparisons = []
                    for assignment in bounded_assignments:
                        formula = proof.evaluate_prefix(observed, width, start, assignment, backend.encrypt_block)
                        # Derive an arbitrary complete order compatible with the six ranks.
                        rank_to_column = {rank: column for column, rank in enumerate(assignment)}
                        remaining_columns = iter(c for c in range(width) if c >= 6)
                        full_order_list = []
                        for rank in range(width):
                            full_order_list.append(rank_to_column[rank] if rank in rank_to_column else next(remaining_columns))
                        full_order = tuple(full_order_list)
                        oracle = full_order_accepts(observed, width, full_order, start, backend.encrypt_block)
                        assert formula == oracle
                        comparisons.append((assignment, formula[0], formula[1]))
                    suite_records.append({
                        "suite": suite,
                        "iv_hex": iv.hex(),
                        "observed_sha256": hashlib.sha256(observed).hexdigest(),
                        "true_assignment": list(true_assignment),
                        "true_plaintext_ninth_hex": bytes(values).hex(),
                        "true_retained": True,
                        "bounded_assignments": len(bounded_assignments),
                        "bounded_formula_oracle_digest": digest_records(comparisons),
                    })
                assert true_values_by_suite[0] == true_values_by_suite[1]
                records.append({
                    "backend": name,
                    "start": start,
                    "width": width,
                    "rows": rows,
                    "chunk_bytes": chunk,
                    "two_iv_suites_same_true_ninth_bytes": True,
                    "suites": suite_records,
                })
        build_evidence = {name: {"command": row["command"], "sha256": row["sha256"]} for name, row in builds.items() if isinstance(row, dict) and "sha256" in row}
        compiler = builds["compiler"]
    return {
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "plaintext_bytes": len(plaintext),
        "order": list(order),
        "records": records,
        "temporary_build_evidence": build_evidence,
        "compiler": compiler,
    }


def regenerate(output: Path):
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    check_pins()
    runtime = load_module("astra_prefix13_runtime", RUNTIME_PY)
    # Width 7 covers every 7! order for both starts. Width 9 covers every 9!
    # order for both starts with two complete rows.
    exhaustive = [
        exhaustive_complete(7, 4, 1),
        exhaustive_complete(7, 4, 2),
        exhaustive_complete(9, 2, 1),
        exhaustive_complete(9, 2, 2),
    ]
    plants = planted_width13(runtime)
    row_offsets = {}
    for start in (1, 2):
        rows, chunk = proof.validate_rectangular(546, 13, start)
        offsets = [[proof.column_offset(r, c, start) for c in range(13)] for r in range(rows)]
        sizes = [[proof.cell_size(r, c, start) for c in range(13)] for r in range(rows)]
        assert all(sum(row[:6]) == 9 for row in sizes)
        assert all(offsets[-1][c] + sizes[-1][c] == chunk for c in range(13))
        row_offsets[str(start)] = {
            "rows": rows,
            "chunk_bytes": chunk,
            "first_six_bytes_each_row": sorted(set(sum(row[:6]) for row in sizes)),
            "offset_digest": digest_records(offsets),
            "size_digest": digest_records(sizes),
        }

    result = {
        "identity": IDENTITY,
        "target_evaluated": False,
        "rev7_file_read": False,
        "scope": "Synthetic-only first-six natural-column necessary filter for rectangular odd-width byte AMSCO and 8-byte CFB8.",
        "theorem": {
            "width": 13,
            "n": 546,
            "rows": 28,
            "observed_chunk_bytes": 42,
            "first_natural_columns_assigned": 6,
            "first_six_bytes_per_row": 9,
            "prefix_assignments_per_start_orientation_backend": proof.prefix_count(13),
            "completion_weight": proof.completion_weight(13),
            "full_orders": math.factorial(13),
            "necessary_output_alphabet_size": len(proof.A105),
            "meaning": "If any row's computed ninth plaintext byte is outside A105, all 7! full column orders extending that six-rank assignment are rejected.",
        },
        "row_geometry": row_offsets,
        "exhaustive_full_order_controls": exhaustive,
        "width13_bounded_plants": plants,
        "dependencies": PINS,
        "runtime_source_hashes": runtime.SOURCE_HASHES,
        "artifact_hashes": {"proof.py": sha(PROOF), "controls.py": sha(Path(__file__))},
        "environment": {"python": sys.version, "platform": platform.platform()},
        "assertions": {
            "all_passed": True,
            "width7_both_starts_all_orders": True,
            "width9_both_starts_all_orders": True,
            "prefix_and_materialized_full_order_classification_equal": True,
            "factorial_partition_exact": True,
            "width13_four_backends_both_starts": len(plants["records"]) == 8,
            "manual_cfb_matches_accepted_runtime": True,
            "two_arbitrary_ivs_same_true_ninth_plaintext": True,
            "bounded_width13_formula_matches_materialized_oracle": True,
            "no_target": True,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"identity": IDENTITY, "written": str(output), "sha256": sha(output), "exhaustive": exhaustive}, indent=2))


def verify_default(path: Path):
    check_pins()
    data = json.loads(path.read_text())
    assert data["identity"] == IDENTITY and not data["target_evaluated"] and not data["rev7_file_read"]
    assert data["artifact_hashes"] == {"proof.py": sha(PROOF), "controls.py": sha(Path(__file__))}
    assert data["dependencies"] == PINS
    assert data["theorem"]["prefix_assignments_per_start_orientation_backend"] == 1_235_520
    assert data["theorem"]["completion_weight"] == 5_040
    assert data["theorem"]["full_orders"] == math.factorial(13)
    rows = data["exhaustive_full_order_controls"]
    assert [(x["width"], x["start"], x["full_orders"]) for x in rows] == [(7, 1, 5040), (7, 2, 5040), (9, 1, 362880), (9, 2, 362880)]
    assert all(x["factorial_partition"] for x in rows)
    assert len(data["width13_bounded_plants"]["records"]) == 8
    assert all(data["assertions"].values())
    runtime_ledger = json.loads(RUNTIME_LEDGER.read_text())
    assert data["runtime_source_hashes"] == runtime_ledger["source"]["files"]
    for rel, want in data["runtime_source_hashes"].items():
        assert sha(RUNTIME_DIR / "source" / rel) == want
    print(json.dumps({"identity": IDENTITY, "verified": True, "ledger_sha256": sha(path), "target_evaluated": False, "verification_scope": "standard-library integrity and accounting; no cryptographic replay"}, sort_keys=True))


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--regenerate", type=Path)
    parser.add_argument("--ledger", type=Path, default=LEDGER)
    args = parser.parse_args()
    if args.regenerate:
        regenerate(args.regenerate)
    else:
        verify_default(args.ledger)


if __name__ == "__main__":
    main()

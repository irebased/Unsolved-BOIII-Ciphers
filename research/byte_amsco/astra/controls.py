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
import time
from pathlib import Path

HERE = Path(__file__).resolve().parent
CORE = HERE / "core.py"
LEDGER = HERE / "controls.json"
RUNTIME_DIR = HERE.parents[1] / "rev7-20260909-codex" / "iv_independent" / "cascade" / "runtime"
RUNTIME_PY = RUNTIME_DIR / "runtime.py"
RUNTIME_CONTROLS = RUNTIME_DIR / "controls.json"
IDENTITY = "ASTRA"
PINNED_RUNTIME = {
    "runtime.py": "8b7899fc7aedb2de04cb900876987e6b3385922d4e2e53c913562659913818f4",
    "controls.json": "483fa566e1030e489f5bb2958bcada9f1f95762f83104b7b9e8437c360787ee5",
}

sys.path.insert(0, str(HERE))
import core


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":")).encode()


def oracle_forward(tokens: tuple[int, ...], width: int, order: tuple[int, ...], start: int) -> tuple[int, ...]:
    """Separate token oracle: make cells by slicing indices, then read columns."""
    cells = []
    position = 0
    cell_number = 0
    while position < len(tokens):
        nominal = start if cell_number % 2 == 0 else 3 - start
        stop = min(len(tokens), position + nominal)
        cells.append(tokens[position:stop])
        position = stop
        cell_number += 1
    output = []
    for wanted_column in order:
        for cell_number, cell in enumerate(cells):
            if cell_number % width == wanted_column:
                output.extend(cell)
    return tuple(output)


def oracle_inverse(observed: tuple[int, ...], width: int, order: tuple[int, ...], start: int) -> tuple[int, ...]:
    """Separate inverse oracle: derive cell sizes, fill columns, then read cell order."""
    sizes = []
    left = len(observed)
    toggle = start
    while left:
        take = min(toggle, left)
        sizes.append(take)
        left -= take
        toggle = 3 - toggle
    by_column = [[i for i in range(len(sizes)) if i % width == c] for c in range(width)]
    cursor = 0
    filled = {}
    for c in order:
        for cell_no in by_column[c]:
            size = sizes[cell_no]
            filled[cell_no] = observed[cursor : cursor + size]
            cursor += size
    return tuple(x for cell_no in range(len(sizes)) for x in filled[cell_no])


def load_runtime():
    if sha(RUNTIME_PY) != PINNED_RUNTIME["runtime.py"] or sha(RUNTIME_CONTROLS) != PINNED_RUNTIME["controls.json"]:
        raise AssertionError("accepted runtime dependency hash drift")
    spec = importlib.util.spec_from_file_location("astra_cascade_runtime", RUNTIME_PY)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def strict_fsa_suffix(data: bytes, initial_states=(0, 1, 2)) -> bool:
    states = set(initial_states)
    for value in data:
        nxt = set()
        for state in states:
            if state == 0:
                if value in (9, 10, 13) or 32 <= value <= 126:
                    nxt.add(0)
                elif value == 0xE2:
                    nxt.add(1)
            elif state == 1 and value == 0x80:
                nxt.add(2)
            elif state == 2 and value in (0x93, 0x94, 0x98, 0x99, 0xA6):
                nxt.add(0)
        states = nxt
        if not states:
            return False
    return 0 in states


def geometry_controls():
    rows = []
    cases = 0
    for n in range(0, 25):
        tokens = tuple(range(n))
        raw = bytes(tokens)
        for width in range(2, min(6, max(2, n + 2)) + 1):
            for order in itertools.permutations(range(width)):
                for start in (1, 2):
                    expected = oracle_forward(tokens, width, order, start)
                    actual = core.amsco_forward(raw, width, order, start)
                    assert tuple(actual) == expected
                    assert tuple(core.amsco_inverse(actual, width, order, start)) == tokens
                    assert oracle_inverse(expected, width, order, start) == tokens
                    layout = core.inverse_layout(n, width, order, start)
                    for prefix in {0, min(n, 1), min(n, 3), n}:
                        assert layout.prefix(actual, prefix) == raw[:prefix]
                    rows.append(bytes(expected))
                    cases += 1
    boundary = []
    source = bytes((i * 73 + 19) & 255 for i in range(546))
    for width in range(2, 10):
        order = tuple(reversed(range(width)))
        for start in (1, 2):
            transformed = core.amsco_forward(source, width, order, start)
            layout = core.inverse_layout(546, width, order, start)
            assert layout.inverse(transformed) == source
            sizes = [size for _natural, size, _source in layout.cells]
            assert sum(sizes) == 546 and sizes[-1] == (2 if start == 1 else 1)
            col_bytes = [0] * width
            for cell_no, size in enumerate(sizes):
                col_bytes[cell_no % width] += size
            boundary.append({
                "width": width,
                "start": start,
                "cell_count": len(sizes),
                "last_cell_bytes": sizes[-1],
                "column_byte_lengths": col_bytes,
                "roundtrip": True,
            })
    # Explicit shortened-final-cell fixtures (546 itself is exactly 182 1+2 cycles).
    truncated = []
    for n, start in ((1, 2), (4, 2), (5, 1), (7, 1)):
        raw = bytes(range(n))
        width = 3
        order = (2, 0, 1)
        transformed = core.amsco_forward(raw, width, order, start)
        layout = core.inverse_layout(n, width, order, start)
        assert layout.inverse(transformed) == raw
        last_size = layout.cells[-1][1] if layout.cells else 0
        last_cell_number = len(layout.cells) - 1
        nominal_last = start if last_cell_number % 2 == 0 else 3 - start
        truncated.append({"n": n, "start": start, "nominal_last": nominal_last, "actual_last": last_size, "was_shortened": last_size < nominal_last, "roundtrip": True})
    assert any(x["nominal_last"] != x["actual_last"] for x in truncated)
    return {
        "exhaustive_small": {"cases": cases, "digest": core.digest_rows(rows), "n_range": [0, 24], "widths_up_to": 6},
        "n546_boundaries": boundary,
        "truncated_final_group": truncated,
    }


def plant_controls(runtime):
    plaintext = (
        b"BYTE AMSCO CONTROL: arbitrary IV suffix survives. "
        b"En dash \xe2\x80\x93 em dash \xe2\x80\x94 quotes \xe2\x80\x98x\xe2\x80\x99 and ellipsis \xe2\x80\xa6.\n"
        * 6
    )[:546]
    assert strict_fsa_suffix(plaintext, (0,))
    width = 7
    order = (3, 5, 1, 6, 0, 4, 2)
    rows = []
    with tempfile.TemporaryDirectory(prefix="astra-byte-amsco-") as td:
        builds = runtime.build_source_libraries(Path(td))
        backends = runtime.registry(builds)
        for backend_index, (name, backend) in enumerate(backends.items()):
            start = 1 + (backend_index % 2)
            ivs = [
                bytes((backend_index * 23 + i * 11 + 7) & 255 for i in range(backend.block_size)),
                bytes((backend_index * 31 + i * 17 + 101) & 255 for i in range(backend.block_size)),
            ]
            orientation_rows = []
            recovered_suffixes = []
            for orientation in core.ORIENTATION_NAMES:
                suite_rows = []
                for suite, iv in enumerate(ivs):
                    ciphertext = backend.encrypt_cfb8(plaintext, iv)
                    transposed = core.amsco_forward(ciphertext, width, order, start)
                    displayed = core.canonical_for_orientation(transposed, orientation)
                    oriented = core.orient_bytes(displayed, orientation)
                    assert oriented == transposed
                    recovered_ciphertext = core.amsco_inverse(oriented, width, order, start)
                    assert recovered_ciphertext == ciphertext
                    known = backend.interval_decrypt(recovered_ciphertext, 0)
                    suffix = known["plaintext"]
                    assert known["offset"] == backend.block_size
                    assert suffix == plaintext[backend.block_size:]
                    assert strict_fsa_suffix(suffix, (0, 1, 2))
                    assert backend.encrypt_cfb8(backend.decrypt_cfb8(ciphertext, iv), iv) == ciphertext
                    recovered_suffixes.append(suffix)
                    suite_rows.append({
                        "suite": suite,
                        "iv_hex": iv.hex(),
                        "displayed_sha256": hashlib.sha256(displayed).hexdigest(),
                        "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
                        "recovered_ciphertext": True,
                        "suffix_offset": known["offset"],
                        "suffix_sha256": hashlib.sha256(suffix).hexdigest(),
                        "exact_reencrypt": True,
                    })
                assert suite_rows[0]["suffix_sha256"] == suite_rows[1]["suffix_sha256"]
                orientation_rows.append({"orientation": orientation, "iv_suites": suite_rows})
            assert len(set(recovered_suffixes)) == 1
            rows.append({
                "backend": name,
                "block_size": backend.block_size,
                "start": start,
                "width": width,
                "order": list(order),
                "orientations": orientation_rows,
                "two_iv_suites_same_suffix_all_orientations": True,
            })
        build_evidence = {
            name: {"sha256": row["sha256"], "command": row["command"]}
            for name, row in builds.items() if isinstance(row, dict) and "sha256" in row
        }
        compiler = builds["compiler"]
    return {
        "plaintext_bytes": len(plaintext),
        "plaintext_sha256": hashlib.sha256(plaintext).hexdigest(),
        "rows": rows,
        "temporary_build_evidence": build_evidence,
        "compiler": compiler,
    }


def benchmark():
    observed = bytes((i * 29 + 113) & 255 for i in range(546))
    records = []
    total = 0
    digest = hashlib.sha256()
    budget_each_start = 25000
    for start in (1, 2):
        began = time.perf_counter()
        count = 0
        for order in itertools.islice(itertools.permutations(range(9)), budget_each_start):
            prefix = core.inverse_layout(546, 9, order, start).prefix(observed, 64)
            digest.update(prefix)
            count += 1
        elapsed = time.perf_counter() - began
        total += count
        records.append({"width": 9, "start": start, "prefixes": count, "prefix_bytes": 64, "seconds": elapsed, "prefixes_per_second": count / elapsed})
    elapsed_total = sum(x["seconds"] for x in records)
    exact_grid = core.factorial_grid()
    return {
        "method": "Python geometry only: construct indexed inverse layout and gather first 64 bytes; no cipher calls",
        "bounded_prefixes": total,
        "rows": records,
        "digest": digest.hexdigest(),
        "exact_future_geometry_grid": exact_grid,
        "linear_geometry_seconds_estimate": exact_grid / (total / elapsed_total),
        "limits": "Excludes seven-backend block calls, endpoint checks, process overhead, and survivors requiring full reconstruction; estimate is not a runtime guarantee.",
        "implementation_note": "A target implementation should precompute natural cell metadata per width/start and gather only demanded ciphertext prefix/window bytes, stopping on the first impossible suffix byte instead of materializing 546 bytes for every order.",
    }


def regenerate(output: Path):
    if output.exists():
        raise SystemExit(f"refusing to overwrite {output}")
    runtime = load_runtime()
    geometry = geometry_controls()
    plants = plant_controls(runtime)
    bench = benchmark()
    result = {
        "identity": IDENTITY,
        "target_evaluated": False,
        "rev7_file_read": False,
        "scope": "Synthetic-only byte-unit AMSCO geometry, orientation, and all-IV CFB8 suffix controls.",
        "definition": {
            "unit": "byte",
            "widths": list(range(2, 10)),
            "starts": ["1,2", "2,1"],
            "alternation": "continuous across row boundaries",
            "column_orders": "all width! permutations",
            "orientations": list(core.ORIENTATION_NAMES),
            "exact_transform_count": core.factorial_grid(),
            "historical_limit": "Binary analogue only; not equivalent to historical PHP AMSCO character processing.",
        },
        "geometry": geometry,
        "all_iv_plants": plants,
        "benchmark": bench,
        "dependencies": {
            "accepted_runtime": PINNED_RUNTIME,
            "runtime_source_commit": runtime.SOURCE_COMMIT,
            "runtime_source_hashes": runtime.SOURCE_HASHES,
        },
        "environment": {"python": sys.version, "platform": platform.platform()},
        "artifact_hashes": {"core.py": sha(CORE), "controls.py": sha(Path(__file__))},
        "assertions": {
            "all_passed": True,
            "forward_matches_independent_token_oracle": True,
            "inverse_matches_independent_token_oracle": True,
            "exhaustive_small_roundtrips": True,
            "n546_boundaries": True,
            "shortened_final_group_controls": True,
            "all_seven_backends": len(plants["rows"]) == 7,
            "all_four_orientations": all(len(x["orientations"]) == 4 for x in plants["rows"]),
            "two_arbitrary_ivs_per_backend_orientation": True,
            "iv_free_suffix_exact": True,
            "exact_reencryption": True,
        },
    }
    output.parent.mkdir(parents=True, exist_ok=True)
    output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({"identity": IDENTITY, "written": str(output), "sha256": sha(output), "benchmark": bench}, indent=2))


def verify_default(path: Path):
    data = json.loads(path.read_text())
    assert data["identity"] == IDENTITY and data["target_evaluated"] is False and data["rev7_file_read"] is False
    assert data["artifact_hashes"] == {"core.py": sha(CORE), "controls.py": sha(Path(__file__))}
    assert data["dependencies"]["accepted_runtime"] == PINNED_RUNTIME
    assert sha(RUNTIME_PY) == PINNED_RUNTIME["runtime.py"]
    assert sha(RUNTIME_CONTROLS) == PINNED_RUNTIME["controls.json"]
    runtime_ledger = json.loads(RUNTIME_CONTROLS.read_text())
    assert data["dependencies"]["runtime_source_hashes"] == runtime_ledger["source"]["files"]
    for rel, want in data["dependencies"]["runtime_source_hashes"].items():
        assert sha(RUNTIME_DIR / "source" / rel) == want
    assert data["definition"]["exact_transform_count"] == 3_272_896
    assert data["definition"]["orientations"] == list(core.ORIENTATION_NAMES)
    assert data["geometry"]["exhaustive_small"]["cases"] > 0
    assert len(data["geometry"]["n546_boundaries"]) == 16
    assert len(data["all_iv_plants"]["rows"]) == 7
    assert [x["backend"] for x in data["all_iv_plants"]["rows"]] == ["aes128", "des", "blowfish", "bfcompat", "rc2", "twofish", "loki97"]
    for row in data["all_iv_plants"]["rows"]:
        assert len(row["orientations"]) == 4 and row["two_iv_suites_same_suffix_all_orientations"]
        for orient in row["orientations"]:
            assert len(orient["iv_suites"]) == 2
            assert all(s["recovered_ciphertext"] and s["exact_reencrypt"] for s in orient["iv_suites"])
    assert all(data["assertions"].values())
    print(json.dumps({"identity": IDENTITY, "verified": True, "verification_scope": "standard-library source/dependency/ledger structure only; no cryptographic replay", "ledger_sha256": sha(path), "target_evaluated": False}, sort_keys=True))


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

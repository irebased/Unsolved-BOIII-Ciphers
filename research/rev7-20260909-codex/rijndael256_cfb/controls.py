#!/usr/bin/env python3
from __future__ import annotations

"""Generate or read-only verify synthetic Rijndael-256 CFB8 interval controls."""

import argparse
import hashlib
import importlib.util
import json
import platform
import subprocess
import tempfile
from pathlib import Path

HERE = Path(__file__).resolve().parent
LEDGER = HERE / "controls.json"
RUNTIME = HERE / "runtime.py"
JS = HERE / "js_cfb8.js"
PLAN = HERE / "PLAN.md"
SELF_PINS = {
    "runtime.py": None,
    "js_cfb8.js": None,
    "PLAN.md": "ebc5fe98205067f2ee48936a76104f9a8287b2e7a24712463b6e96ebd068693d",
}
EXISTING = ("aes128", "des", "blowfish", "bfcompat", "rc2", "twofish", "loki97")
RKEYS = ("rijndael256_key16", "rijndael256_key24", "rijndael256_key32")
TRANSFORMS = ("forward", "byte_reverse", "nibble_swap", "full_hex_reverse")
THIRDS = {0x93, 0x94, 0x98, 0x99, 0xA6}
INTERVALS = ((0, 256), (17, 230), (31, 62), (31, 63), (31, 64), (64, 256), (200, 220))


def sha(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def load(name: str, path: Path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    assert spec.loader
    spec.loader.exec_module(module)
    return module


def endpoint(data: bytes, left: int, right: int, total: int) -> dict:
    """Independent boundary-aware strict ASCII plus five UTF-8 punctuation oracle."""
    states = {0} if left == 0 else {0, 1, 2}
    initial = sorted(states)
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
            elif state == 2 and value in THIRDS:
                nxt.add(0)
        states = nxt
        if not states:
            break
    terminal = {0} if right == total else {0, 1, 2}
    return {
        "accepted": bool(states & terminal),
        "initial_states": initial,
        "ending_states": sorted(states),
        "terminal_states": sorted(terminal),
    }


def valid_text(total: int = 384) -> bytes:
    phrase = "R256 CONTROL – — ‘ ’ … ALL FIVE. ".encode("utf-8")
    tail = b"END.\n"
    room = total - len(tail)
    return phrase * (room // len(phrase)) + b"A" * (room % len(phrase)) + tail


def ivs_for(layers: tuple[str, ...], suite: int, registry: dict) -> tuple[bytes, ...]:
    return tuple(
        bytes((suite * 67 + layer_index * 43 + byte_index * 29 + len(name) * 11) & 255
              for byte_index in range(registry[name].block_size))
        for layer_index, name in enumerate(layers)
    )


def js_roundtrips(jobs: list[dict]) -> list[dict]:
    result = subprocess.run(
        ["node", str(JS)], input=json.dumps({"jobs": jobs}).encode(),
        capture_output=True, check=True,
    )
    return json.loads(result.stdout)


def trace_endpoints(trace: list[dict], total: int) -> list[dict]:
    rows = []
    for index, item in enumerate(trace):
        tested = endpoint(item["data"], item["left"], item["right"], total)
        rows.append({
            "index": index,
            "stage": item["stage"],
            "name": item.get("backend", item.get("transform")),
            "left": item["left"], "right": item["right"],
            "length": len(item["data"]),
            "sha256": hashlib.sha256(item["data"]).hexdigest(),
            "endpoint": tested,
        })
    return rows


def recipe_rows() -> list[tuple[str, tuple[str, ...], tuple[str, ...]]]:
    rows = []
    for existing in EXISTING:
        for rkey in RKEYS:
            for position in range(2):
                layers = (rkey, existing) if position == 0 else (existing, rkey)
                for transform_name in TRANSFORMS:
                    rows.append((f"d2_{existing}_{rkey}_rpos{position}_{transform_name}", layers, (transform_name,)))
    for index, first in enumerate(EXISTING):
        second = EXISTING[(index + 1) % len(EXISTING)]
        for rkey in RKEYS:
            for position in range(3):
                base = [first, second]
                base.insert(position, rkey)
                for ta in TRANSFORMS:
                    for tb in TRANSFORMS:
                        rows.append((f"d3_{first}_{second}_{rkey}_rpos{position}_{ta}_{tb}", tuple(base), (ta, tb)))
    assert len(rows) == 1176 and len({row[0] for row in rows}) == len(rows)
    return rows


def normalize_build(value, build_dir: Path):
    """Remove ephemeral temporary directory names while retaining exact commands."""
    if isinstance(value, dict):
        return {key: normalize_build(item, build_dir) for key, item in value.items()}
    if isinstance(value, list):
        return [normalize_build(item, build_dir) for item in value]
    if isinstance(value, str):
        return value.replace(str(build_dir), "<temporary-build>")
    return value


def produce(output: Path) -> None:
    rt = load("astra_r256_runtime", RUNTIME)
    rt.verify_pins()
    text = valid_text()
    assert endpoint(text, 0, len(text), len(text))["accepted"]
    with tempfile.TemporaryDirectory(prefix="astra-r256-cfb-") as temp_name:
        build_dir = Path(temp_name)
        rlib, rcommand, cascade, existing_build = rt.build_sources(build_dir)
        registry = rt.extended_registry(rlib, cascade, existing_build)

        primitive_jobs = []
        primitive_inputs = []
        raw = bytes(range(256))
        for key_index, name in enumerate(RKEYS):
            for iv_index in range(2):
                iv = bytes((key_index * 37 + iv_index * 101 + i * 13) & 255 for i in range(32))
                primitive_inputs.append((name, iv, raw))
                primitive_jobs.append({"key_hex": registry[name].key.hex(), "iv_hex": iv.hex(), "data_hex": raw.hex(), "operation": "roundtrip"})
        js_rows = js_roundtrips(primitive_jobs)
        primitive = []
        for (name, iv, plain), js_row in zip(primitive_inputs, js_rows):
            backend = registry[name]
            cipher = backend.encrypt_cfb8(plain, iv)
            recovered = backend.decrypt_cfb8(cipher, iv)
            assert cipher.hex() == js_row["ciphertext_hex"]
            assert recovered == plain and js_row["decrypted_hex"] == plain.hex()
            primitive.append({
                "backend": name, "key_hex": backend.key.hex(), "iv_hex": iv.hex(),
                "plaintext_hex": plain.hex(), "ciphertext_hex": cipher.hex(),
                "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
                "c_encrypt_equals_untouched_js": True,
                "c_decrypt_equals_plaintext": True,
                "js_roundtrip_equals_plaintext": True,
            })

        direct_iv = []
        for key_index, name in enumerate(RKEYS):
            backend = registry[name]
            iv1 = bytes((key_index * 31 + i * 17) & 255 for i in range(32))
            iv2 = bytes((201 + key_index * 19 + i * 23) & 255 for i in range(32))
            fixed = backend.encrypt_cfb8(raw, iv1)
            p1 = backend.decrypt_cfb8(fixed, iv1)
            p2 = backend.decrypt_cfb8(fixed, iv2)
            assert p1[32:] == p2[32:]
            assert p1[:32] != p2[:32]
            direct_iv.append({
                "backend": name, "key_hex": backend.key.hex(),
                "fixed_ciphertext_hex": fixed.hex(), "iv1_hex": iv1.hex(), "iv2_hex": iv2.hex(),
                "iv1_plaintext_hex": p1.hex(), "iv2_plaintext_hex": p2.hex(),
                "prefixes_differ": True, "suffix_offset": 32,
                "suffix_hex": p1[32:].hex(), "suffix_sha256": hashlib.sha256(p1[32:]).hexdigest(),
                "same_fixed_ciphertext_suffix_equal_under_two_ivs": True,
            })

        interval_rows = []
        for key_index, name in enumerate(RKEYS):
            backend = registry[name]
            iv = bytes((71 + key_index * 41 + i * 7) & 255 for i in range(32))
            cipher = backend.encrypt_cfb8(raw, iv)
            full = backend.decrypt_cfb8(cipher, iv)
            for left, right in INTERVALS:
                result = backend.interval_decrypt(cipher[left:right], left)
                expected_left = min(left + 32, right)
                assert result["offset"] == expected_left
                assert result["plaintext"] == full[expected_left:right]
                interval_rows.append({
                    "backend": name, "input_interval": [left, right],
                    "output_interval": [expected_left, right],
                    "input_hex": cipher[left:right].hex(),
                    "output_hex": result["plaintext"].hex(),
                    "matches_full_reference": True,
                })

        cascades = []
        intermediate_reject_recipes = 0
        for recipe_id, layers, transforms in recipe_rows():
            suites = []
            suite_material = []
            for suite in (1, 2):
                iv_tuple = ivs_for(layers, suite, registry)
                cipher = rt.encrypt_chain(text, layers, transforms, iv_tuple, registry)
                full = rt.decrypt_chain(cipher, layers, transforms, iv_tuple, registry)
                left, right, known, trace = rt.known_interval(cipher, layers, transforms, registry)
                assert full == text and known == text[left:right]
                final_ep = endpoint(known, left, right, len(text))
                assert final_ep["accepted"]
                trace_rows = trace_endpoints(trace, len(text))
                suite_material.append((iv_tuple, cipher, full, left, right, known))
                suites.append({
                    "suite": suite, "ivs_hex": [iv.hex() for iv in iv_tuple],
                    "ciphertext_sha256": hashlib.sha256(cipher).hexdigest(),
                    "full_roundtrip_sha256": hashlib.sha256(full).hexdigest(),
                    "known_interval": [left, right],
                    "known_sha256": hashlib.sha256(known).hexdigest(),
                    "known_equals_plaintext_slice": True,
                    "final_endpoint": final_ep, "trace": trace_rows,
                })
            assert suite_material[0][3:6] == suite_material[1][3:6]

            iv1, fixed, full1, left, right, known = suite_material[0]
            iv2 = suite_material[1][0]
            alternate = rt.decrypt_chain(fixed, layers, transforms, iv2, registry)
            assert alternate[left:right] == known
            assert alternate[:left] + alternate[right:] != full1[:left] + full1[right:]
            rejects = sum(not row["endpoint"]["accepted"] for row in suites[0]["trace"][:-1])
            intermediate_reject_recipes += bool(rejects)
            cascades.append({
                "id": recipe_id, "layers": list(layers), "transforms": list(transforms),
                "block_sizes": [registry[name].block_size for name in layers],
                "plaintext_sha256": hashlib.sha256(text).hexdigest(), "plaintext_length": len(text),
                "known_interval": [left, right], "known_hex": known.hex(),
                "suites": suites,
                "fresh_iv_known_interval_equal": True,
                "fixed_ciphertext_alternate_iv": {
                    "ciphertext_sha256": hashlib.sha256(fixed).hexdigest(),
                    "alternate_ivs_hex": [iv.hex() for iv in iv2],
                    "known_interval": [left, right],
                    "alternate_full_sha256": hashlib.sha256(alternate).hexdigest(),
                    "same_known_interval": True, "outside_interval_differs": True,
                },
                "intermediate_endpoint_rejections_before_final": rejects,
                "no_intermediate_pruning": True,
            })
        assert len(cascades) == 1176 and intermediate_reject_recipes > 0

        source_hashes = {label: sha(path) for label, path in rt.pin_paths().items()}
        source_hashes.update({"runtime.py": sha(RUNTIME), "js_cfb8.js": sha(JS), "controls.py": sha(Path(__file__)), "PLAN.md": sha(PLAN)})
        result = {
            "identity": "ASTRA", "target_evaluated": False, "rev7_read": False,
            "scope": "Synthetic source-backed Rijndael-256 CFB8 known-interval adapter and mixed cascade composition controls.",
            "primitive": primitive, "primitive_count": len(primitive),
            "direct_fixed_ciphertext_two_iv": direct_iv, "direct_fixed_ciphertext_two_iv_count": len(direct_iv),
            "interval_vectors": interval_rows, "interval_vector_count": len(interval_rows),
            "cascade_recipes": cascades, "cascade_recipe_count": len(cascades),
            "cascade_execution_count": len(cascades) * 2,
            "depth2_recipe_count": sum(len(row["layers"]) == 2 for row in cascades),
            "depth3_recipe_count": sum(len(row["layers"]) == 3 for row in cascades),
            "recipes_with_intermediate_endpoint_rejection_before_valid_final": intermediate_reject_recipes,
            "model": {
                "mode": "CFB8", "rijndael_block_bytes": 32,
                "keys": {name: registry[name].key.hex() for name in RKEYS},
                "existing_backends": list(EXISTING), "transforms": list(TRANSFORMS),
                "interval_rule": "Known [L,R) becomes [min(L+block_size,R),R) at each CFB8 decryption layer; same-length involutions then map endpoints and bytes exactly.",
                "endpoint_rule": "TAB/LF/CR, ASCII 32..126, and UTF-8 E2 80 followed by 93/94/98/99/A6, with boundary state sets.",
            },
            "source_hashes": source_hashes,
            "build": {
                "rijndael256_command": normalize_build(rcommand, build_dir),
                "rijndael256_library_sha256_machine_evidence": sha(rlib),
                "cascade": normalize_build(existing_build, build_dir),
            },
            "runtime": {
                "python": platform.python_version(),
                "node": subprocess.check_output(["node", "--version"], text=True).strip(),
                "compiler": subprocess.check_output(["clang", "--version"], text=True).splitlines()[0],
            },
            "assertions": {
                "all_passed": True, "source_pins_match": True,
                "primitive_c_equals_untouched_js_all_bytes_two_ivs": True,
                "direct_same_fixed_ciphertext_two_iv_suffix_equal": True,
                "seven_interval_boundaries_each_key": len(interval_rows) == 21,
                "all_1176_recipes_two_iv_suites": len(cascades) == 1176,
                "all_2352_executions_exact_known_interval": len(cascades) * 2 == 2352,
                "intermediate_rejection_observed_without_pruning": intermediate_reject_recipes > 0,
                "no_target_read_or_evaluation": True,
            },
            "limits": [
                "Synthetic controls only; no Rev7 ciphertext was read or evaluated.",
                "The adapter establishes CFB8 interval behavior under the stated raw keys and source-backed Rijndael-256 primitive, not a complete historical wrapper.",
                "Endpoint validity is tested only on the final known interval; intermediate binary data is never pruned.",
                "Known intervals do not recover IV-dependent prefixes or any bytes outside the reported interval.",
                "Only same-length registered involutions and direct binary layer composition are covered; framing, encoding, padding, transposition, insertion, and deletion are outside scope.",
            ],
        }
        output.write_text(json.dumps(result, sort_keys=True, separators=(",", ":")) + "\n")


def verify() -> None:
    if not LEDGER.exists():
        raise SystemExit("missing controls.json; regenerate explicitly to a new path")
    data = json.loads(LEDGER.read_text())
    assert data["identity"] == "ASTRA" and data["target_evaluated"] is False and data["rev7_read"] is False
    assert data["source_hashes"]["runtime.py"] == sha(RUNTIME)
    assert data["source_hashes"]["js_cfb8.js"] == sha(JS)
    assert data["source_hashes"]["controls.py"] == sha(Path(__file__))
    assert data["source_hashes"]["PLAN.md"] == sha(PLAN) == SELF_PINS["PLAN.md"]
    rt = load("astra_r256_runtime_verify", RUNTIME)
    rt.verify_pins()
    for label, path in rt.pin_paths().items():
        assert data["source_hashes"][label] == sha(path)
    assert data["primitive_count"] == 6 and len(data["primitive"]) == 6
    assert data["direct_fixed_ciphertext_two_iv_count"] == 3
    assert data["interval_vector_count"] == 21
    assert data["cascade_recipe_count"] == 1176 and len(data["cascade_recipes"]) == 1176
    assert data["cascade_execution_count"] == 2352
    assert data["depth2_recipe_count"] == 168 and data["depth3_recipe_count"] == 1008
    expected = recipe_rows()
    assert [row["id"] for row in data["cascade_recipes"]] == [row[0] for row in expected]
    assert all(data["assertions"].values())
    for row in data["primitive"]:
        cipher = bytes.fromhex(row["ciphertext_hex"])
        assert hashlib.sha256(cipher).hexdigest() == row["ciphertext_sha256"]
        assert row["c_encrypt_equals_untouched_js"] and row["c_decrypt_equals_plaintext"] and row["js_roundtrip_equals_plaintext"]
    for row in data["direct_fixed_ciphertext_two_iv"]:
        p1 = bytes.fromhex(row["iv1_plaintext_hex"])
        p2 = bytes.fromhex(row["iv2_plaintext_hex"])
        suffix = bytes.fromhex(row["suffix_hex"])
        assert row["same_fixed_ciphertext_suffix_equal_under_two_ivs"] and p1[32:] == p2[32:] == suffix
        assert p1[:32] != p2[:32] and hashlib.sha256(suffix).hexdigest() == row["suffix_sha256"]
    for row, (_, layers, transforms) in zip(data["cascade_recipes"], expected):
        assert tuple(row["layers"]) == layers and tuple(row["transforms"]) == transforms
        left, right = row["known_interval"]
        known = bytes.fromhex(row["known_hex"])
        assert len(known) == right - left and len(row["suites"]) == 2
        assert all(suite["known_interval"] == [left, right] for suite in row["suites"])
        assert all(hashlib.sha256(known).hexdigest() == suite["known_sha256"] for suite in row["suites"])
        assert row["fixed_ciphertext_alternate_iv"]["same_known_interval"]
        assert row["no_intermediate_pruning"]
    print(json.dumps({
        "identity": "ASTRA", "verified": True, "read_only": True,
        "ledger_sha256": sha(LEDGER), "ledger_bytes": LEDGER.stat().st_size,
        "primitive_streams": 6, "interval_vectors": 21,
        "cascade_recipes": 1176, "cascade_executions": 2352,
        "target_evaluated": False,
    }, indent=2))


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--regenerate", type=Path)
    args = parser.parse_args()
    if args.regenerate is None:
        verify()
        return
    output = args.regenerate.resolve()
    if output.exists():
        raise SystemExit("refusing existing output: " + str(output))
    output.parent.mkdir(parents=True, exist_ok=True)
    produce(output)
    print(json.dumps({"identity": "ASTRA", "target_evaluated": False, "output": str(output), "sha256": sha(output), "bytes": output.stat().st_size}, indent=2))


if __name__ == "__main__":
    main()

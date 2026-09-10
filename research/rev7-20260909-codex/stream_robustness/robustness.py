#!/usr/bin/env python3
"""Generate fixed-map stream robustness ledgers from frozen Rev7 stream searches."""
import hashlib
import itertools
import json
import sys
from pathlib import Path

from Crypto.Cipher import AES, DES, Blowfish

HERE = Path(__file__).resolve().parent
R = HERE.parent
D = R / "stream_csp"
C = R / "stream_csp_compat"
N = 546
ASCII_CONTROL = {9, 10, 13} | set(range(32, 127))
UTF8_COMPONENTS = {0xE2, 0x80, 0x93, 0x94, 0x98, 0x99, 0xA6}
ALLOWED = ASCII_CONTROL | UTF8_COMPONENTS
assert len(ASCII_CONTROL) == 98 and len(UTF8_COMPONENTS) == 7
assert len(ALLOWED) == 105 and 0 not in ALLOWED and 65 in ALLOWED

def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

HELPER_HASHES = {
    R / "hex_cfb" / "prototype.py": "416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
    C / "compat_stream.py": "f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c",
}
for helper, expected in HELPER_HASHES.items():
    assert sha(helper) == expected, (helper, sha(helper))
sys.path[:0] = [str(R / "hex_cfb"), str(C)]
import prototype  # noqa: E402,F401
import compat_stream  # noqa: E402

PATHS = {
    "stream_target": D / "target_results.json",
    "stream_ledger": D / "witness_verification.json",
    "compat_target": C / "target_results.json",
    "compat_ledger": C / "verification.json",
}
EXPECTED = {
    "stream_target": "f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87",
    "stream_ledger": "07e61bdfbc777e43a36902720ef70b295a117953707653dc97060df372bf2c1c",
    "compat_target": "598dfa8ec497321f62f1b4f445de4f642f755ef0fb51c9d2164c708145aad7f2",
    "compat_ledger": "1937e53cdbb0487e8ff95326f3a1a131d7402eb3374d0556030f2508ef2d35d6",
}
actual = {name: sha(path) for name, path in PATHS.items()}
assert actual == EXPECTED, actual

mdx = R.parents[1] / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
EXPECTED_MDX = "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
assert sha(mdx) == EXPECTED_MDX
text = mdx.read_text()
start = text.index("`83 B57B2") + 1
end = text.index("`", start)
raw = "".join(text[start:end].split()).upper()
assert len(raw) == 1092
EXPECTED_RAW = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
assert hashlib.sha256(raw.encode()).hexdigest() == EXPECTED_RAW
pairs = [raw[i:i + 2] for i in range(0, len(raw), 2)]
ORIENTATIONS = {
    "forward": raw,
    "reverse": raw[::-1],
    "byte_reverse": "".join(reversed(pairs)),
    "nibble_swap": "".join(pair[::-1] for pair in pairs),
}

def standard_stream(cipher, mode, iv):
    key = {
        "aes128": b"Zombies".ljust(16, b"\0"),
        "blowfish": b"Zombies",
        "des": b"Zombies".ljust(8, b"\0"),
    }[cipher]
    module = {"aes128": AES, "blowfish": Blowfish, "des": DES}[cipher]
    ecb = module.new(key, module.MODE_ECB)
    register = iv
    output = bytearray()
    if mode == "ofb8":
        for _ in range(N):
            byte = ecb.encrypt(register)[0]
            output.append(byte)
            register = register[1:] + bytes([byte])
    else:
        while len(output) < N:
            register = ecb.encrypt(register)
            output.extend(register)
    return bytes(output[:N])

def pair_metrics(display, keystream):
    occurrences = {}
    for position in range(N):
        occurrences.setdefault(display[2 * position:2 * position + 2], []).append(position)
    rows = []
    for pair, positions in sorted(occurrences.items()):
        scores = [
            (sum((candidate ^ keystream[i]) not in ALLOWED for i in positions), candidate)
            for candidate in range(256)
        ]
        minimum = min(score for score, _ in scores)
        minimizers = [candidate for score, candidate in scores if score == minimum]
        rows.append({
            "display_pair": pair,
            "occurrence_count": len(positions),
            "positions": positions,
            "minimum_invalid": minimum,
            "minimizer_count": len(minimizers),
            "constructive_map": minimizers[0],
        })
    return rows

stream = json.loads(PATHS["stream_target"].read_text())
compat = json.loads(PATHS["compat_target"].read_text())
cells = []
for dataset, source in (("stream_csp", stream), ("stream_csp_compat", compat)):
    for source_cell in source["cells"]:
        if dataset == "stream_csp":
            keystream = standard_stream(
                source_cell["cipher"], source_cell["mode"], bytes.fromhex(source_cell["iv_hex"])
            )
        else:
            keystream = compat_stream.keystream(
                source_cell["mode"], bytes.fromhex(source_cell["iv_hex"]), N, compat_stream.load_block()
            )
        assert hashlib.sha256(keystream).hexdigest() == source_cell["keystream_sha256"]
        display = ORIENTATIONS[source_cell["orientation"]]
        metrics = pair_metrics(display, keystream)
        arbitrary = sum(row["minimum_invalid"] for row in metrics)
        for row in metrics:
            direct = sum(
                (row["constructive_map"] ^ keystream[i]) not in ALLOWED for i in row["positions"]
            )
            assert direct == row["minimum_invalid"]
        cell = {
            "dataset": dataset,
            "cipher": source_cell["cipher"],
            "mode": source_cell["mode"],
            "iv_kind": source_cell["iv_kind"],
            "orientation": source_cell["orientation"],
            "key_hex": source_cell["key_hex"],
            "iv_hex": source_cell["iv_hex"],
            "displayed_sha256": hashlib.sha256(display.encode()).hexdigest(),
            "keystream_sha256": source_cell["keystream_sha256"],
            "keystream_hex": keystream.hex(),
            "pair_metrics": metrics,
            "arbitrary_fixed_map_invalid_lower_bound": arbitrary,
            "pair_count": len(metrics),
            "min_pair_invalid": min(row["minimum_invalid"] for row in metrics),
            "max_pair_invalid": max(row["minimum_invalid"] for row in metrics),
            "crypto_recomputed": True,
            "independent_cipher_implementation": dataset == "stream_csp",
        }
        if (
            dataset == "stream_csp"
            and source_cell["cipher"] == "blowfish"
            and source_cell["iv_kind"] == "nul"
            and source_cell["mode"] == "ofb8"
        ):
            assert keystream == bytes(N)
            weights = sorted(row["occurrence_count"] for row in metrics)
            invalid_weight = sum(weights[:len(weights) - len(ALLOWED)])
            allowed_weight = sum(weights[len(weights) - len(ALLOWED):])
            assert invalid_weight == 179 and allowed_weight == N - 179
            cell["zero_stream_bijection_bound"] = {
                "distinct_pair_classes": len(metrics),
                "allowed_classes": len(ALLOWED),
                "forced_invalid_classes": len(metrics) - len(ALLOWED),
                "invalid_positions_lower_bound": invalid_weight,
                "top_allowed_class_weight_sum": allowed_weight,
            }
        cells.append(cell)
assert len(cells) == 96
assert len({
    (c["dataset"], c["cipher"], c["mode"], c["iv_kind"], c["orientation"], c["key_hex"], c["iv_hex"])
    for c in cells
}) == 96

# Computed controls.
all_keystream = list(range(256))
scores = [sum((candidate ^ k) not in ALLOWED for k in all_keystream) for candidate in range(256)]
control1 = {
    "keystream_bytes": all_keystream,
    "alphabet_size": len(ALLOWED),
    "minimum_invalid": min(scores),
    "minimizer_count": sum(score == min(scores) for score in scores),
}
assert control1["minimum_invalid"] == 151

classes = list(range(106))
unrestricted_outputs = [65 for _ in classes]
unrestricted_invalid = sum(value not in ALLOWED for value in unrestricted_outputs)
injective_outputs = sorted(ALLOWED) + [0]
assert len(injective_outputs) == 106 and len(set(injective_outputs)) == 106
injective_invalid = sum(value not in ALLOWED for value in injective_outputs)
control2 = {
    "distinct_pair_classes": len(classes),
    "unit_weights": True,
    "unrestricted_output_byte": 65,
    "unrestricted_output_name": "ASCII A",
    "unrestricted_outputs_are_injective": len(set(unrestricted_outputs)) == len(classes),
    "unrestricted_invalid_direct_count": unrestricted_invalid,
    "injective_outputs": injective_outputs,
    "injective_forbidden_output_byte": 0,
    "injective_invalid_direct_count": injective_invalid,
}
assert unrestricted_invalid == 0 and injective_invalid == 1
assert not control2["unrestricted_outputs_are_injective"]

weights = [5, 3, 1]
toy_allowed = [0, 1]
brute = min(
    sum(weights[i] for i, output in enumerate(mapping) if output not in toy_allowed)
    for mapping in itertools.permutations(range(3))
)
control3 = {
    "weights": weights,
    "allowable_plain_bytes": toy_allowed,
    "bruteforce_bijective_min_invalid_weight": brute,
    "expected": 1,
}
assert brute == 1

zero_cells = [cell for cell in cells if "zero_stream_bijection_bound" in cell]
assert len(zero_cells) == 4
assert {cell["zero_stream_bijection_bound"]["invalid_positions_lower_bound"] for cell in zero_cells} == {179}
nonzero = [cell for cell in cells if "zero_stream_bijection_bound" not in cell]
source_hashes = {
    **actual,
    "rev7_mdx": EXPECTED_MDX,
    "canonical_text_sha256": EXPECTED_RAW,
    "prototype.py": HELPER_HASHES[R / "hex_cfb" / "prototype.py"],
    "compat_stream.py": HELPER_HASHES[C / "compat_stream.py"],
}
scope = (
    "Minimum same-length ciphertext-byte corrections after choosing a fixed displayed-pair map; "
    "arbitrary per-pair map minima and separate injective byte-map bounds. "
    "No insertion/deletion, key search, IV search, or CFB hypothesis."
)
out = {
    "identity": "ASTRA",
    "target_evaluated": True,
    "crypto_evaluated": True,
    "scope": scope,
    "allowed_output_bytes": {
        "ascii_and_controls_count": len(ASCII_CONTROL),
        "ascii_and_controls": "TAB, LF, CR, and printable ASCII 32..126",
        "utf8_component_count": len(UTF8_COMPONENTS),
        "utf8_component_hex": [f"{value:02X}" for value in sorted(UTF8_COMPONENTS)],
        "total": len(ALLOWED),
    },
    "canonical_text_sha256": EXPECTED_RAW,
    "source_hashes": source_hashes,
    "cells": cells,
    "cell_count": len(cells),
    "summary": {
        "arbitrary_fixed_map_min_invalid": min(c["arbitrary_fixed_map_invalid_lower_bound"] for c in cells),
        "arbitrary_fixed_map_max_invalid": max(c["arbitrary_fixed_map_invalid_lower_bound"] for c in cells),
        "nonzero_stream_arbitrary_fixed_map_invalid_range": [
            min(c["arbitrary_fixed_map_invalid_lower_bound"] for c in nonzero),
            max(c["arbitrary_fixed_map_invalid_lower_bound"] for c in nonzero),
        ],
        "all_stream_hashes_matched": True,
        "zero_stream_bijection_cells": len(zero_cells),
        "zero_stream_distinct_pairs": 226,
        "zero_stream_arbitrary_fixed_map_invalid": 0,
        "zero_stream_bijection_invalid_positions_lower_bound": 179,
    },
    "controls": {
        "one_pair_all_keystream_bytes": control1,
        "zero_stream_106_classes": control2,
        "weighted_toy": control3,
    },
    "reliance": (
        "Standard streams independently reconstructed with PyCryptodome; compatibility streams "
        "recomputed with the hash-pinned, previously independently verified compat_stream helper."
    ),
}
ledger_path = HERE / "robustness.json"
ledger_path.write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
compact = {
    "identity": "ASTRA",
    "target_evaluated": True,
    "crypto_evaluated": True,
    "ledger_sha256": sha(ledger_path),
    "cell_count": len(cells),
    "scope": scope,
    "allowed_output_bytes": out["allowed_output_bytes"],
    "all_stream_hashes_matched": True,
    "arbitrary_fixed_map_invalid_range": [
        min(c["arbitrary_fixed_map_invalid_lower_bound"] for c in cells),
        max(c["arbitrary_fixed_map_invalid_lower_bound"] for c in cells),
    ],
    "nonzero_stream_context_count": len(nonzero),
    "nonzero_stream_arbitrary_fixed_map_invalid_range": out["summary"]["nonzero_stream_arbitrary_fixed_map_invalid_range"],
    "zero_stream_context_count": len(zero_cells),
    "zero_stream_arbitrary_fixed_map_invalid": 0,
    "zero_stream_bijection_invalid_positions_lower_bound": 179,
    "zero_stream_distinct_pair_classes": 226,
    "source_hashes": source_hashes,
    "contexts": [
        {key: cell[key] for key in (
            "dataset", "cipher", "mode", "iv_kind", "orientation", "key_hex", "iv_hex",
            "displayed_sha256", "arbitrary_fixed_map_invalid_lower_bound", "pair_count",
            "min_pair_invalid", "max_pair_invalid", "keystream_sha256"
        )}
        for cell in cells
    ],
    "controls": out["controls"],
    "regeneration": "python3 -B research/rev7-20260909-codex/stream_robustness/robustness.py",
    "verification": "python3 -B research/rev7-20260909-codex/stream_robustness/verifier.py",
}
(HERE / "robustness_summary.json").write_text(json.dumps(compact, indent=2, sort_keys=True) + "\n")
print(json.dumps({
    "identity": "ASTRA",
    "cells": len(cells),
    "result_sha256": sha(ledger_path),
    "summary_sha256": sha(HERE / "robustness_summary.json"),
}, indent=2))

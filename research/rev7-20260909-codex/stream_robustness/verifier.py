#!/usr/bin/env python3
"""Independent histogram and artifact-integrity verifier for robustness.json."""
import hashlib
import json
from pathlib import Path

HERE = Path(__file__).resolve().parent
R = HERE.parent
D = R / "stream_csp"
C = R / "stream_csp_compat"
N = 546
ASCII_CONTROL = {9, 10, 13} | set(range(32, 127))
UTF8_COMPONENTS = {0xE2, 0x80, 0x93, 0x94, 0x98, 0x99, 0xA6}
ALLOWED = ASCII_CONTROL | UTF8_COMPONENTS
assert len(ASCII_CONTROL) == 98 and len(UTF8_COMPONENTS) == 7 and len(ALLOWED) == 105
EXPECTED = {
    "stream_target": "f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87",
    "stream_ledger": "07e61bdfbc777e43a36902720ef70b295a117953707653dc97060df372bf2c1c",
    "compat_target": "598dfa8ec497321f62f1b4f445de4f642f755ef0fb51c9d2164c708145aad7f2",
    "compat_ledger": "1937e53cdbb0487e8ff95326f3a1a131d7402eb3374d0556030f2508ef2d35d6",
    "rev7_mdx": "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91",
    "prototype.py": "416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b",
    "compat_stream.py": "f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c",
}
PATHS = {
    "stream_target": D / "target_results.json",
    "stream_ledger": D / "witness_verification.json",
    "compat_target": C / "target_results.json",
    "compat_ledger": C / "verification.json",
    "prototype.py": R / "hex_cfb" / "prototype.py",
    "compat_stream.py": C / "compat_stream.py",
}
def sha(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()

for name, path in PATHS.items():
    assert sha(path) == EXPECTED[name], (name, sha(path))
mdx = R.parents[1] / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
assert sha(mdx) == EXPECTED["rev7_mdx"]
text = mdx.read_text()
start = text.index("`83 B57B2") + 1
end = text.index("`", start)
raw = "".join(text[start:end].split()).upper()
assert len(raw) == 1092
canonical_sha = hashlib.sha256(raw.encode()).hexdigest()
assert canonical_sha == "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
pairs = [raw[i:i + 2] for i in range(0, len(raw), 2)]
orientations = {
    "forward": raw,
    "reverse": raw[::-1],
    "byte_reverse": "".join(reversed(pairs)),
    "nibble_swap": "".join(pair[::-1] for pair in pairs),
}

ledger_path = HERE / "robustness.json"
summary_path = HERE / "robustness_summary.json"
ledger = json.loads(ledger_path.read_text())
summary = json.loads(summary_path.read_text())
assert ledger["identity"] == summary["identity"] == "ASTRA"
assert ledger["cell_count"] == summary["cell_count"] == 96
assert summary["ledger_sha256"] == sha(ledger_path)
assert ledger["source_hashes"] == summary["source_hashes"]
for name, expected in EXPECTED.items():
    assert ledger["source_hashes"][name] == expected
assert ledger["source_hashes"]["canonical_text_sha256"] == canonical_sha
assert ledger["allowed_output_bytes"] == summary["allowed_output_bytes"]
assert ledger["allowed_output_bytes"]["ascii_and_controls_count"] == 98
assert ledger["allowed_output_bytes"]["utf8_component_count"] == 7
assert ledger["allowed_output_bytes"]["total"] == 105

stream = json.loads((D / "target_results.json").read_text())
compat = json.loads((C / "target_results.json").read_text())
source_cells = [("stream_csp", cell) for cell in stream["cells"]] + [
    ("stream_csp_compat", cell) for cell in compat["cells"]
]
assert len(source_cells) == 96
ID_KEYS = ("dataset", "cipher", "mode", "iv_kind", "orientation", "key_hex", "iv_hex")
def source_id(dataset, cell):
    return (
        dataset, cell["cipher"], cell["mode"], cell["iv_kind"], cell["orientation"],
        cell["key_hex"], cell["iv_hex"],
    )
expected_ids = [source_id(dataset, cell) for dataset, cell in source_cells]
actual_ids = [tuple(cell[key] for key in ID_KEYS) for cell in ledger["cells"]]
assert actual_ids == expected_ids and len(set(actual_ids)) == 96

valid_candidates = [
    [candidate for candidate in range(256) if (candidate ^ key_byte) in ALLOWED]
    for key_byte in range(256)
]
zero_cells = []
global_constructive_invalid = 0
for index, ((dataset, source_cell), cell) in enumerate(zip(source_cells, ledger["cells"])):
    assert cell["keystream_sha256"] == source_cell["keystream_sha256"]
    keystream = bytes.fromhex(cell["keystream_hex"])
    assert len(keystream) == N
    assert hashlib.sha256(keystream).hexdigest() == source_cell["keystream_sha256"]
    display = orientations[cell["orientation"]]
    assert hashlib.sha256(display.encode()).hexdigest() == cell["displayed_sha256"]
    if "displayed_sha256" in source_cell:
        assert cell["displayed_sha256"] == source_cell["displayed_sha256"]
    expected_positions = {}
    for position in range(N):
        expected_positions.setdefault(display[2 * position:2 * position + 2], []).append(position)
    expected_rows = sorted(expected_positions.items())
    assert cell["pair_count"] == len(expected_rows) == len(cell["pair_metrics"])
    cell_total = 0
    constructive_total = 0
    for row, (pair, positions) in zip(cell["pair_metrics"], expected_rows):
        assert row["display_pair"] == pair
        assert row["positions"] == positions
        assert row["occurrence_count"] == len(positions)
        counts = [0] * 256
        for position in positions:
            counts[keystream[position]] += 1
        support = [0] * 256
        for key_byte, count in enumerate(counts):
            if count:
                for candidate in valid_candidates[key_byte]:
                    support[candidate] += count
        best = max(support)
        minimizers = [candidate for candidate, value in enumerate(support) if value == best]
        minimum_invalid = len(positions) - best
        assert row["minimum_invalid"] == minimum_invalid
        assert row["minimizer_count"] == len(minimizers)
        assert row["constructive_map"] == minimizers[0]
        direct = sum(
            (row["constructive_map"] ^ keystream[position]) not in ALLOWED
            for position in positions
        )
        assert direct == minimum_invalid
        cell_total += minimum_invalid
        constructive_total += direct
    assert cell_total == constructive_total == cell["arbitrary_fixed_map_invalid_lower_bound"]
    row_minima = [row["minimum_invalid"] for row in cell["pair_metrics"]]
    assert cell["min_pair_invalid"] == min(row_minima)
    assert cell["max_pair_invalid"] == max(row_minima)
    global_constructive_invalid += constructive_total
    if "zero_stream_bijection_bound" in cell:
        assert keystream == bytes(N)
        weights = sorted(len(positions) for _, positions in expected_rows)
        direct_bound = sum(weights[:len(weights) - len(ALLOWED)])
        bound = cell["zero_stream_bijection_bound"]
        assert len(expected_rows) == bound["distinct_pair_classes"] == 226
        assert bound["allowed_classes"] == 105
        assert bound["forced_invalid_classes"] == 121
        assert direct_bound == bound["invalid_positions_lower_bound"] == 179
        assert bound["top_allowed_class_weight_sum"] == N - 179
        zero_cells.append(cell)

assert len(zero_cells) == 4
computed_range = [
    min(cell["arbitrary_fixed_map_invalid_lower_bound"] for cell in ledger["cells"]),
    max(cell["arbitrary_fixed_map_invalid_lower_bound"] for cell in ledger["cells"]),
]
nonzero = [cell for cell in ledger["cells"] if "zero_stream_bijection_bound" not in cell]
computed_nonzero_range = [
    min(cell["arbitrary_fixed_map_invalid_lower_bound"] for cell in nonzero),
    max(cell["arbitrary_fixed_map_invalid_lower_bound"] for cell in nonzero),
]
assert summary["arbitrary_fixed_map_invalid_range"] == computed_range
assert summary["nonzero_stream_arbitrary_fixed_map_invalid_range"] == computed_nonzero_range
assert summary["nonzero_stream_context_count"] == len(nonzero) == 92
assert summary["zero_stream_context_count"] == 4
assert summary["zero_stream_arbitrary_fixed_map_invalid"] == 0
assert summary["zero_stream_bijection_invalid_positions_lower_bound"] == 179
assert summary["zero_stream_distinct_pair_classes"] == 226
compact_contexts = [
    {key: cell[key] for key in (
        "dataset", "cipher", "mode", "iv_kind", "orientation", "key_hex", "iv_hex",
        "displayed_sha256", "arbitrary_fixed_map_invalid_lower_bound", "pair_count",
        "min_pair_invalid", "max_pair_invalid", "keystream_sha256"
    )}
    for cell in ledger["cells"]
]
assert summary["contexts"] == compact_contexts

control = ledger["controls"]["zero_stream_106_classes"]
classes = list(range(106))
unrestricted = [65 for _ in classes]
injective = sorted(ALLOWED) + [0]
assert control["unrestricted_invalid_direct_count"] == sum(v not in ALLOWED for v in unrestricted) == 0
assert control["injective_invalid_direct_count"] == sum(v not in ALLOWED for v in injective) == 1
assert control["injective_outputs"] == injective and len(set(injective)) == 106
assert summary["controls"] == ledger["controls"]

print(json.dumps({
    "identity": "ASTRA",
    "verified_cells": len(ledger["cells"]),
    "unique_cell_identifiers": len(set(actual_ids)),
    "canonical_orientations_recovered": list(orientations),
    "pair_positions_exact": True,
    "stream_hashes_matched_frozen_ledgers": True,
    "histogram_argmins_and_counts_verified": True,
    "global_constructive_invalid_count": global_constructive_invalid,
    "zero_stream_cells": len(zero_cells),
    "zero_stream_weighted_bijection_bound": 179,
    "compact_summary_agreement": True,
    "ledger_sha256": sha(ledger_path),
    "summary_sha256": sha(summary_path),
}, indent=2, sort_keys=True))

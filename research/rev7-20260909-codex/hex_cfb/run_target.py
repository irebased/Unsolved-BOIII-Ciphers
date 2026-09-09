#!/usr/bin/env python3
"""ASTRA018: control-gated, capped hex-bijection/CFB8 search."""
import hashlib
import json
import math
import re
import sys
import time
from dataclasses import asdict
from pathlib import Path
import prototype as p

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
NODE_LIMIT = 10_000_000
EXPECTED_HASH = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
PLAN_URL = "https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5609059049"

def sha(data):
    return hashlib.sha256(data).hexdigest()

def save(value, name):
    destination = HERE / name
    temporary = destination.with_suffix(destination.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True, indent=2) + "\n")
    temporary.replace(destination)

def main():
    assert sys.argv[1:] == ["--target"], "explicit --target required"
    if (HERE / "results.json").exists():
        raise SystemExit("results.json already exists; refusing to rerun completed cells")
    controls = p.run_controls(250_000)
    save(controls, "target_controls.json")
    source = (ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx").read_text()
    match = re.search(r"`(83 B57B2.*?)`", source, re.S)
    assert match
    canonical = "".join(match.group(1).split()).upper()
    assert len(canonical) == 1092 and sha(canonical.encode("ascii")) == EXPECTED_HASH
    assert set(canonical) == set(p.HEX)
    source_hashes = {name: sha((HERE / name).read_bytes()) for name in ("prototype.py", "run_target.py")}
    result = {
        "identity": "ASTRA", "experiment": "ASTRA018", "plan_url": PLAN_URL,
        "rev7_sha256": EXPECTED_HASH, "hex_length": len(canonical),
        "scope": {"ciphers": list(p.cipher_specs()), "orientations": list(p.orientations(canonical)),
                  "node_limit_per_cell": NODE_LIMIT, "node_definition": "DFS entries, including terminal entries",
                  "endpoint": "TAB/LF/CR/ASCII32..126 plus UTF8 E28093/E28094/E28098/E28099; complete termination",
                  "full_mapping_space_per_cell": math.factorial(16), "workers": 1},
        "source_sha256": source_hashes, "controls_sha256": sha((HERE / "target_controls.json").read_bytes()),
        "cells": [], "all_cells_finished": False,
    }
    save(result, "results.json")
    print(json.dumps({"identity": "ASTRA", "controls": "passed", "target_cells": 12}), flush=True)
    for cipher_name in p.cipher_specs():
        for orientation, displayed in p.orientations(canonical).items():
            ecb, key, iv = p.ecb_oracle(cipher_name)
            start = time.perf_counter()
            solutions, stats = p.backtrack(displayed, ecb, iv, p.historical_utf8_transition, node_limit=NODE_LIMIT)
            elapsed = time.perf_counter() - start
            certificate = stats.rejected_completion_weight + stats.terminal_completion_weight
            complete = not stats.aborted_at_node_limit
            if complete:
                assert certificate == math.factorial(16)
            verified_solutions = []
            for candidate in solutions:
                mapping = candidate["mapping"]
                plaintext = candidate["plaintext"]
                assert sorted(mapping) == list(range(16))
                decoded = bytes.fromhex("".join(p.HEX[mapping[p.HEX.index(c)]] for c in displayed))
                assert len(plaintext) == len(decoded) == 546
                assert p.library_cfb8(decoded, cipher_name, True) == plaintext
                encrypted = p.library_cfb8(plaintext, cipher_name, False)
                assert encrypted == decoded
                assert p.display_encode(encrypted, mapping) == displayed
                assert p.orientations(p.display_encode(encrypted, mapping))[orientation] == canonical
                decoded_text = plaintext.decode("utf-8", errors="strict")
                allowed_codepoints = p.ALLOWED | {0x2013, 0x2014, 0x2018, 0x2019}
                assert all(ord(c) in allowed_codepoints for c in decoded_text)
                verified_solutions.append({"mapping_displayed_to_nibble": list(mapping),
                                           "plaintext_hex": plaintext.hex(), "plaintext_utf8": decoded_text,
                                           "plaintext_sha256": sha(plaintext), "ciphertext_sha256": sha(decoded),
                                           "library_decrypt_exact": True, "full_reconstruction_exact": True})
            cell = {"cipher": cipher_name, "orientation": orientation, "key_hex": key.hex(), "iv_hex": iv.hex(),
                    "elapsed_seconds": elapsed, "stats": asdict(stats), "complete": complete,
                    "certificate_weight": certificate, "unaccounted_mapping_weight": math.factorial(16) - certificate,
                    "survivors": verified_solutions}
            result["cells"].append(cell)
            save(result, "results.json")
            print(json.dumps({"identity": "ASTRA", "cipher": cipher_name, "orientation": orientation,
                              "nodes": stats.nodes, "seconds": round(elapsed, 3), "complete": complete,
                              "certificate_weight": certificate, "survivors": len(solutions)}), flush=True)
    result["all_cells_finished"] = True
    result["complete_cells"] = sum(c["complete"] for c in result["cells"])
    result["capped_cells"] = sum(not c["complete"] for c in result["cells"])
    result["survivor_records"] = sum(len(c["survivors"]) for c in result["cells"])
    assert len(result["cells"]) == 12
    save(result, "results.json")

if __name__ == "__main__":
    main()

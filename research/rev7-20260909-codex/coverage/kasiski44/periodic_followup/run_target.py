#!/usr/bin/env python3
"""ASTRA: bounded all-keys byte-bag test after fixed AMSCO decode."""
import argparse
import hashlib
import importlib.util
import json
import math
from pathlib import Path

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[4]
MODEL = HERE.parents[1] / "periodic_bytebag_controls" / "model.py"
GEOMETRY = HERE.parent / "geometry.py"
DATA = ROOT / "lavender/src/data/ciphers/revelations.json"
MDX = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
RESULT = HERE / "results.json"
CELLS = [(p, op) for p in (19, 38, 57) for op in ("xor", "subtract")]


def sha(path):
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def load(name, path):
    spec = importlib.util.spec_from_file_location(name, path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def check_gate():
    gate = json.loads((HERE / "gate.json").read_text())
    assert gate["identity"] == "ASTRA" and gate["target_authorized"] is True
    assert gate["cells"] == [[p, op] for p, op in CELLS]
    assert gate["scope"] == "AMSCO equal4/ZOMBIES decode forward; arbitrary repeating byte keys; bag165"
    for rel, pin in gate["files_sha256"].items():
        assert sha(ROOT / rel) == pin, rel
    return gate


def extract(gate, independent=False):
    assert sha(DATA) == gate["dataset_sha256"]
    assert sha(MDX) == gate["mdx_sha256"]
    raw = "".join(next(x["ciphertext"] for x in json.loads(DATA.read_text()) if x["id"] == "rev7").split()).upper()
    t = MDX.read_text(); a = t.index("`83 B57B")+1; b = t.index("`", a)
    assert raw == "".join(t[a:b].split()).upper()
    assert len(raw) == 1092 and hashlib.sha256(raw.encode()).hexdigest() == gate["canonical_hex_sha256"]
    if independent:
        ranks = {c: sorted("ZOMBIES").index(ch) for c, ch in enumerate("ZOMBIES")}
        out = "".join(raw[ranks[(i//4)%7]*156+(i//28)*4+i%4] for i in range(1092))
    else:
        out = load("kasiski_geometry", GEOMETRY).decode(raw)
    assert hashlib.sha256(out.encode()).hexdigest() == gate["decoded_hex_sha256"]
    return bytes.fromhex(out)


def compute(cipher, slow=False):
    model = load("periodic_mask_model", MODEL)
    mask_function = model.residue_masks_slow if slow else model.residue_masks_fast
    rows = []
    for period, operation in CELLS:
        masks = mask_function(cipher, period, operation)
        residues = []
        for r, mask in enumerate(masks):
            indices = list(range(r, len(cipher), period))
            residues.append({"residue": r, "byte_indices": indices,
                             "cipher_values": [cipher[i] for i in indices],
                             "key_mask_hex": model.mask_hex(mask),
                             "key_count": bin(mask).count("1")})
        empty = [r for r, mask in enumerate(masks) if mask == 0]
        rows.append({"id": f"byte_p{period}_{operation}", "period_bytes": period,
                     "operation": operation, "residues": residues,
                     "empty_residues": empty, "bag_compatible_key_count": str(math.prod(row["key_count"] for row in residues)),
                     "status": "excluded_bag165" if empty else "bag_compatible_unresolved"})
    return rows


def main():
    ap = argparse.ArgumentParser()
    mode = ap.add_mutually_exclusive_group()
    mode.add_argument("--run-target", action="store_true")
    mode.add_argument("--verify", action="store_true")
    args = ap.parse_args()
    gate = check_gate()
    if not (args.run_target or args.verify):
        print(json.dumps({"identity": "ASTRA", "source_gate": "PASS", "target_evaluated": False, "cells": len(CELLS)}))
        return
    if args.run_target:
        assert not RESULT.exists(), "refuse existing target results"
    cipher = extract(gate, independent=args.verify)
    rows = compute(cipher, slow=args.verify)
    result = {"identity": "ASTRA", "state": "complete", "gate_sha256": sha(HERE / "gate.json"),
              "source_sha256": sha(__file__), "cipher_bytes_sha256": hashlib.sha256(cipher).hexdigest(),
              "cipher_hex": cipher.hex().upper(), "cells": rows,
              "counts": {"total": len(rows), "excluded_bag165": sum(x["status"] == "excluded_bag165" for x in rows),
                         "bag_compatible_unresolved": sum(x["status"] == "bag_compatible_unresolved" for x in rows)},
              "limit": "All keys for exactly six declared byte-period/operation cells and fixed AMSCO decode. Necessary byte-union test for 201 codepoints only; no generic classical or Kasiski significance conclusion."}
    if args.verify:
        assert json.loads(RESULT.read_text()) == result
        print(json.dumps({"identity": "ASTRA", "independent_geometry_and_slow_masks": "PASS", "counts": result["counts"], "result_sha256": sha(RESULT)}))
    else:
        with RESULT.open("x") as f:
            f.write(json.dumps(result, indent=2, sort_keys=True)+"\n")
        print(json.dumps({"identity": "ASTRA", "counts": result["counts"], "result_sha256": sha(RESULT)}))


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Integrity, ranking, inverse-chain, and retained-output checks for ASTRA005."""
import csv
import hashlib
import json
from pathlib import Path

import run

HERE = Path(__file__).resolve().parent


def main():
    result = json.loads((HERE / "results.json").read_text())
    assert result["identity"] == "ASTRA"
    assert result["scope"]["grid_cells"] == 9696
    assert result["scope"]["numeral_digit_alphabet"] == run.STANDARD
    assert result["scope"]["trifid_cubes"]["ZOMBIES"] == run.keyed_cube("ZOMBIES")
    assert result["scope"]["coordinate_order"] == "layer,column,row"
    assert result["controls"]["rev11"]["decrypt_exact"]
    assert result["controls"]["rev11"]["encrypt_exact"]
    assert result["controls"]["rev13_plant"]["exact_recovery"]
    rev7 = run.extract_rev7()
    with (HERE / "target_ledger.tsv").open(newline="") as handle:
        ledger = list(csv.DictReader(handle, dialect="excel-tab"))
    assert len(ledger) == 9696
    for row in ledger:
        row["zero_digits"] = int(row["zero_digits"])
        row["period"] = row["period"] if row["period"] == "full" else int(row["period"])
        row["length"] = int(row["length"])
        row["ngram"] = float(row["ngram"])
        row["ioc"] = float(row["ioc"])
    digest = hashlib.sha256()
    for row in ledger:
        digest.update(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    assert digest.hexdigest() == result["target"]["enumeration_digest"]
    assert hashlib.sha256((HERE / "target_ledger.tsv").read_bytes()).hexdigest() == result["target"]["ledger_sha256"]
    assert [r["sha256"] for r in sorted(ledger, key=lambda r: (-r["ngram"], run.recipe_key(r)))[:20]] == [r["sha256"] for r in result["target"]["top20_ngram"]]
    assert [r["sha256"] for r in sorted(ledger, key=lambda r: (-r["ioc"], run.recipe_key(r)))[:20]] == [r["sha256"] for r in result["target"]["top20_ioc"]]
    records = json.loads(run.DATA.read_text())
    model = run.FourgramModel([x["plaintext"] for x in records if x.get("solved") and x["id"] not in ("rev7", "rev13")])
    checked = 0
    for row in result["target"]["top20_ngram"] + result["target"]["top20_ioc"]:
        value = run.orientations(rev7)[row["input"]]
        digits = [0] * row["zero_digits"] + run.int_to_base27(int(value, 16))
        if row["digit_order"] == "reverse":
            digits.reverse()
        stream = "".join(run.STANDARD[d] for d in digits)
        cube = run.STANDARD if row["cube"] == "standard" else run.keyed_cube("ZOMBIES")
        period = len(stream) if row["period"] == "full" else row["period"]
        fn = run.trifid_decrypt if row["operation"] == "decrypt" else run.trifid_encrypt
        output = fn(stream, cube, period)
        assert output == row["output"]
        assert hashlib.sha256(output.encode()).hexdigest() == row["sha256"]
        assert model.score(output) == row["ngram"]
        assert run.ioc(output) == row["ioc"]
        assert run.reference_encrypt(run.reference_decrypt(output, cube, period), cube, period) == output
        inverse = run.trifid_encrypt if row["operation"] == "decrypt" else run.trifid_decrypt
        recovered_stream = inverse(output, cube, period)
        recovered_digits = [run.STANDARD.index(c) for c in recovered_stream]
        if row["digit_order"] == "reverse":
            recovered_digits.reverse()
        assert recovered_digits[:row["zero_digits"]] == [0] * row["zero_digits"]
        minimal_digits = recovered_digits[row["zero_digits"]:]
        recovered_oriented_hex = format(run.base27_to_int(minimal_digits), "X")
        assert recovered_oriented_hex == run.orientations(rev7)[row["input"]]
        assert undo_orientation(recovered_oriented_hex, row["input"]) == rev7
        checked += 1
    ledger = {
        "identity": "ASTRA",
        "readme_sha256": hashlib.sha256((HERE / "README.md").read_bytes()).hexdigest(),
        "report_sha256": hashlib.sha256((HERE / "report.json").read_bytes()).hexdigest(),
        "results_sha256": hashlib.sha256((HERE / "results.json").read_bytes()).hexdigest(),
        "target_ledger_sha256": hashlib.sha256((HERE / "target_ledger.tsv").read_bytes()).hexdigest(),
        "run_py_sha256": hashlib.sha256((HERE / "run.py").read_bytes()).hexdigest(),
        "verify_py_sha256": hashlib.sha256((HERE / "verify.py").read_bytes()).hexdigest(),
        "retained_records_checked": checked,
        "status": "verified",
    }
    (HERE / "verification.json").write_text(json.dumps(ledger, sort_keys=True, indent=2) + "\n")
    print(json.dumps(ledger, sort_keys=True, indent=2))


def undo_orientation(value, name):
    if name == "forward":
        return value
    if name == "reverse":
        return value[::-1]
    if name == "byte_reverse":
        pairs = [value[i:i + 2] for i in range(0, len(value), 2)]
        return "".join(pairs[::-1])
    if name == "nibble_swap":
        return "".join(value[i + 1] + value[i] for i in range(0, len(value), 2))
    raise ValueError(name)


if __name__ == "__main__":
    main()

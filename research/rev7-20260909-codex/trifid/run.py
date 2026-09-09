#!/usr/bin/env python3
"""Frozen Rev7 whole-integer base27 -> Trifid experiment (ASTRA005).

The numeral alphabet is always STANDARD.  The independently selected Trifid
cube alphabet may be STANDARD or keyed by ZOMBIES; those roles are deliberately
kept separate.
"""
from __future__ import annotations

import hashlib
import csv
import json
import math
import platform
import re
import sys
import time
from collections import Counter
from pathlib import Path

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
DATA = ROOT / "lavender/src/data/ciphers/revelations.json"
REV7_SOURCE = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
STANDARD = "ABCDEFGHIJKLMNOPQRSTUVWXYZ."
PLAN_URL = "https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5608447431"
REV11_SOURCE_URL = "https://www.reddit.com/r/CODZombies/comments/1rqb3nt/revelations_bigram_cipher_solved/"


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def keyed_cube(key: str) -> str:
    return "".join(dict.fromkeys(key.upper() + STANDARD))


def coords(cube: str, char: str) -> tuple[int, int, int]:
    i = cube.index(char)
    # Rev11's standard convention reads layer, column, row.
    return i // 9 + 1, i % 3 + 1, i // 3 % 3 + 1


def symbol(cube: str, triple: tuple[int, int, int]) -> str:
    a, b, c = triple
    return cube[(a - 1) * 9 + (c - 1) * 3 + b - 1]


def trifid_encrypt(text: str, cube: str, period: int) -> str:
    out = []
    for start in range(0, len(text), period):
        block = text[start:start + period]
        triples = [coords(cube, c) for c in block]
        flat = [v for axis in range(3) for triple in triples for v in (triple[axis],)]
        out.extend(symbol(cube, tuple(flat[i:i + 3])) for i in range(0, len(flat), 3))
    return "".join(out)


def trifid_decrypt(text: str, cube: str, period: int) -> str:
    out = []
    for start in range(0, len(text), period):
        block = text[start:start + period]
        flat = [v for c in block for v in coords(cube, c)]
        n = len(block)
        rows = (flat[:n], flat[n:2 * n], flat[2 * n:])
        out.extend(symbol(cube, (rows[0][i], rows[1][i], rows[2][i])) for i in range(n))
    return "".join(out)


def reference_encrypt(text: str, cube: str, period: int) -> str:
    """Separate coordinate-transpose formulation used only for validation."""
    lookup = {c: divmod(i, 9) for i, c in enumerate(cube)}
    out = []
    for start in range(0, len(text), period):
        block = text[start:start + period]
        matrix = []
        for c in block:
            plane, rem = lookup[c]
            row, col = divmod(rem, 3)
            matrix.append((plane, col, row))
        stream = [value for row in zip(*matrix) for value in row]
        for i in range(0, len(stream), 3):
            plane, col, row = stream[i:i + 3]
            out.append(cube[9 * plane + 3 * row + col])
    return "".join(out)


def reference_decrypt(text: str, cube: str, period: int) -> str:
    """Inverse reference via reshaping coordinate rows, independent of helpers."""
    lookup = {c: divmod(i, 9) for i, c in enumerate(cube)}
    out = []
    for start in range(0, len(text), period):
        block = text[start:start + period]
        stream = []
        for c in block:
            plane, rem = lookup[c]
            row, col = divmod(rem, 3)
            stream.extend((plane, col, row))
        n = len(block)
        matrix = [stream[i * n:(i + 1) * n] for i in range(3)]
        out.extend(cube[9 * matrix[0][i] + 3 * matrix[2][i] + matrix[1][i]] for i in range(n))
    return "".join(out)


def int_to_base27(value: int) -> list[int]:
    if value == 0:
        return [0]
    digits = []
    while value:
        value, digit = divmod(value, 27)
        digits.append(digit)
    return digits[::-1]


def base27_to_int(digits: list[int]) -> int:
    value = 0
    for digit in digits:
        assert 0 <= digit < 27
        value = value * 27 + digit
    return value


def orientations(s: str) -> dict[str, str]:
    pairs = [s[i:i + 2] for i in range(0, len(s), 2)]
    return {
        "forward": s,
        "reverse": s[::-1],
        "byte_reverse": "".join(pairs[::-1]),
        "nibble_swap": "".join(p[1] + p[0] for p in pairs),
    }


def normalize(text: str) -> str:
    return "".join(c if c in STANDARD else "." for c in text.upper())


class FourgramModel:
    def __init__(self, texts: list[str], alpha: float = 0.1):
        self.n = 4
        self.alpha = alpha
        self.counts = Counter()
        self.total = 0
        for text in texts:
            text = normalize(text)
            grams = [text[i:i + self.n] for i in range(len(text) - self.n + 1)]
            self.counts.update(grams)
            self.total += len(grams)
        self.denom = self.total + alpha * (len(STANDARD) ** self.n)
        self.floor = math.log(alpha / self.denom)

    def score(self, text: str) -> float:
        if len(text) < self.n:
            return self.floor
        total = 0.0
        count = len(text) - self.n + 1
        for i in range(count):
            gram = text[i:i + self.n]
            total += math.log((self.counts.get(gram, 0) + self.alpha) / self.denom)
        return total / count


def ioc(text: str) -> float:
    n = len(text)
    return sum(v * (v - 1) for v in Counter(text).values()) / (n * (n - 1)) if n > 1 else 0.0


def extract_rev7() -> str:
    source = REV7_SOURCE.read_text()
    match = re.search(r"`(83 B57B2.*?)`", source, re.S)
    assert match
    value = "".join(match.group(1).split()).upper()
    assert len(value) == 1092 and re.fullmatch(r"[0-9A-F]+", value)
    return value


def recipe_key(r: dict) -> tuple:
    period = r["period"]
    return (r["input"], r["zero_digits"], r["digit_order"], r["cube"], str(period), r["operation"])


LEDGER_FIELDS = ["input", "zero_digits", "digit_order", "cube", "period", "operation", "length", "sha256", "ngram", "ioc"]


def write_ledger(rows: list[dict], path: Path) -> None:
    with path.open("w", newline="") as handle:
        writer = csv.DictWriter(handle, fieldnames=LEDGER_FIELDS, dialect="excel-tab", lineterminator="\n")
        writer.writeheader()
        for row in rows:
            writer.writerow({key: row[key] for key in LEDGER_FIELDS})


def scan(cipher_hex: str, model: FourgramModel, retain_output: bool) -> tuple[list[dict], str, int]:
    rows = []
    digest = hashlib.sha256()
    stream_count = 0
    for orientation, value in orientations(cipher_hex).items():
        minimal = int_to_base27(int(value, 16))
        for zero_digits in range(3):
            restored = [0] * zero_digits + minimal
            for digit_order in ("forward", "reverse"):
                digits = restored if digit_order == "forward" else restored[::-1]
                # Numeral digit-to-symbol mapping is fixed and never keyed.
                stream = "".join(STANDARD[d] for d in digits)
                stream_count += 1
                for cube_name, cube in (("standard", STANDARD), ("ZOMBIES", keyed_cube("ZOMBIES"))):
                    periods = list(range(1, 101)) + ["full"]
                    for label in periods:
                        period = len(stream) if label == "full" else label
                        for operation, fn in (("decrypt", trifid_decrypt), ("encrypt", trifid_encrypt)):
                            output = fn(stream, cube, period)
                            row = {
                                "input": orientation,
                                "zero_digits": zero_digits,
                                "digit_order": digit_order,
                                "cube": cube_name,
                                "period": label,
                                "operation": operation,
                                "length": len(output),
                                "sha256": sha(output.encode()),
                                "ngram": model.score(output),
                                "ioc": ioc(output),
                            }
                            rows.append(row)
                            digest.update(json.dumps(row, sort_keys=True, separators=(",", ":")).encode() + b"\n")
    assert len(rows) == 9696 and stream_count == 24
    top_ngram = sorted(rows, key=lambda r: (-r["ngram"], recipe_key(r)))[:20]
    top_ioc = sorted(rows, key=lambda r: (-r["ioc"], recipe_key(r)))[:20]
    if retain_output:
        lookup = {recipe_key(r): r for r in rows}
        for chosen in top_ngram + top_ioc:
            row = lookup[recipe_key(chosen)]
            value = orientations(cipher_hex)[row["input"]]
            digits = [0] * row["zero_digits"] + int_to_base27(int(value, 16))
            if row["digit_order"] == "reverse":
                digits.reverse()
            stream = "".join(STANDARD[d] for d in digits)
            cube = STANDARD if row["cube"] == "standard" else keyed_cube("ZOMBIES")
            period = len(stream) if row["period"] == "full" else row["period"]
            fn = trifid_decrypt if row["operation"] == "decrypt" else trifid_encrypt
            chosen["output"] = fn(stream, cube, period)
    return rows, digest.hexdigest(), stream_count


def main() -> None:
    started = time.perf_counter()
    data_bytes = DATA.read_bytes()
    records = json.loads(data_bytes)
    rev11 = next(x for x in records if x["id"] == "rev11")
    rev13 = next(x for x in records if x["id"] == "rev13")
    rev7_hex = extract_rev7()
    training = [x["plaintext"] for x in records if x.get("solved") and x["id"] not in ("rev7", "rev13")]
    model = FourgramModel(training)

    # First actual Rev11 vector: inserted/repaired Trifid ciphertext -> Trifid output.
    steps = rev11["solution"]["steps"]
    rev11_cipher = next(x["output"] for x in steps if x["method"] == "insert_characters").upper()
    rev11_plain = next(x["output"] for x in steps if x["method"] == "Trifid").upper()
    p11 = len(rev11_cipher)
    control_rev11 = {
        "ciphertext_sha256": sha(rev11_cipher.encode()),
        "plaintext_sha256": sha(rev11_plain.encode()),
        "length": p11,
        "period": "full",
        "decrypt_exact": trifid_decrypt(rev11_cipher, STANDARD, p11) == rev11_plain,
        "encrypt_exact": trifid_encrypt(rev11_plain, STANDARD, p11) == rev11_cipher,
        "reference_decrypt_exact": reference_decrypt(rev11_cipher, STANDARD, p11) == rev11_plain,
        "reference_encrypt_exact": reference_encrypt(rev11_plain, STANDARD, p11) == rev11_cipher,
    }

    formulation_checks = 0
    sample = (STANDARD * 5)[:113]
    for cube in (STANDARD, keyed_cube("ZOMBIES")):
        for period in list(range(1, 101)) + [len(sample)]:
            enc = trifid_encrypt(sample, cube, period)
            assert enc == reference_encrypt(sample, cube, period)
            assert trifid_decrypt(enc, cube, period) == sample
            assert reference_decrypt(enc, cube, period) == sample
            formulation_checks += 1

    # Held-out Rev13 is planted through a complete reversible chain.  Keyed
    # cube/period 2 in the decrypt direction gives exactly one leading zero
    # base27 digit, which int->hex necessarily loses and the frozen 0..2
    # restoration bound must recover.  The grid's inverse is therefore encrypt.
    rev13_plain = normalize(rev13["plaintext"])
    plant_cube = keyed_cube("ZOMBIES")
    plant_cipher = trifid_decrypt(rev13_plain, plant_cube, 2)
    plant_digits = [STANDARD.index(c) for c in plant_cipher]
    lost = len(plant_digits) - len(list(iter_drop_initial_zeroes(plant_digits)))
    assert lost == 1
    plant_int = base27_to_int(plant_digits)
    plant_hex = format(plant_int, "X")
    recovered_digits = [0] * lost + int_to_base27(int(plant_hex, 16))
    assert recovered_digits == plant_digits
    assert trifid_encrypt("".join(STANDARD[d] for d in recovered_digits), plant_cube, 2) == rev13_plain

    # All controls above must pass before either held-out or target enumeration.
    assert all(v is True for k, v in control_rev11.items() if k.endswith("exact"))
    control_rows, control_digest, _ = scan(plant_hex, model, retain_output=False)
    expected_recipe = {
        "input": "forward", "zero_digits": 1, "digit_order": "forward",
        "cube": "ZOMBIES", "period": 2, "operation": "encrypt",
    }
    expected = next(r for r in control_rows if all(r[k] == v for k, v in expected_recipe.items()))
    expected_rank = 1 + sorted(control_rows, key=lambda r: (-r["ngram"], recipe_key(r))).index(expected)
    assert expected["sha256"] == sha(rev13_plain.encode()) and expected_rank <= 20

    target_rows, target_digest, stream_count = scan(rev7_hex, model, retain_output=True)
    ledger_path = HERE / "target_ledger.tsv"
    write_ledger(target_rows, ledger_path)
    top_ngram = sorted(target_rows, key=lambda r: (-r["ngram"], recipe_key(r)))[:20]
    top_ioc = sorted(target_rows, key=lambda r: (-r["ioc"], recipe_key(r)))[:20]
    retained = {}
    for row in top_ngram + top_ioc:
        retained.setdefault(row["sha256"], row)

    result = {
        "identity": "ASTRA",
        "experiment": "ASTRA005",
        "plan_url": PLAN_URL,
        "scope": {
            "grid_cells": len(target_rows), "streams": stream_count,
            "orientations": list(orientations(rev7_hex)), "zero_digits": [0, 1, 2],
            "digit_orders": ["forward", "reverse"],
            "numeral_digit_alphabet": STANDARD,
            "trifid_cubes": {"standard": STANDARD, "ZOMBIES": keyed_cube("ZOMBIES")},
            "coordinate_order": "layer,column,row",
            "plan_coordinate_note": "The illustrative ASTRA005 pseudocode transposed row/column labels; the actual Rev11 control selected layer,column,row before target enumeration.",
            "periods": "1..100 plus full stream", "operations": ["decrypt", "encrypt"],
            "transcription_repairs": "none",
        },
        "inputs": {
            "rev7_length": len(rev7_hex), "rev7_sha256": sha(rev7_hex.encode()),
            "revelations_json_sha256": sha(data_bytes),
            "rev7_source_sha256": sha(REV7_SOURCE.read_bytes()),
        },
        "model": {
            "type": "mean natural-log fourgram probability, additive alpha=0.1",
            "alphabet": STANDARD, "training_ids": [x["id"] for x in records if x.get("solved") and x["id"] not in ("rev7", "rev13")],
            "held_out": "rev13", "training_fourgrams": model.total,
        },
        "controls": {
            "rev11": control_rev11,
            "coordinate_formulation_comparisons": formulation_checks,
            "rev13_plant": {
                "plaintext_sha256": sha(rev13_plain.encode()), "plaintext_length": len(rev13_plain),
                "ciphertext_sha256": sha(plant_cipher.encode()), "hex_sha256": sha(plant_hex.encode()),
                "hex_length": len(plant_hex), "lost_leading_zero_digits": lost,
                "recipe": expected_recipe, "ngram_rank": expected_rank,
                "exact_recovery": expected["sha256"] == sha(rev13_plain.encode()),
                "grid_digest": control_digest,
            },
        },
        "target": {
            "enumeration_digest": target_digest,
            "ledger_file": "target_ledger.tsv", "ledger_sha256": sha(ledger_path.read_bytes()),
            "unique_outputs": len({r["sha256"] for r in target_rows}),
            "top20_ngram": top_ngram,
            "top20_ioc": top_ioc,
            "retained_unique_outputs": len(retained),
        },
        "sources": [REV11_SOURCE_URL, PLAN_URL],
        "commands": ["python3 run.py", "python3 verify.py"],
        "tools": {"python": sys.version.split()[0], "implementation": platform.python_implementation()},
        "runtime_seconds": round(time.perf_counter() - started, 6),
    }
    (HERE / "results.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    print(json.dumps({
        "grid_cells": len(target_rows), "unique_outputs": result["target"]["unique_outputs"],
        "rev11": control_rev11, "rev13_rank": expected_rank,
        "top_ngram": top_ngram[0], "top_ioc": top_ioc[0],
        "results_sha256": sha((HERE / "results.json").read_bytes()),
    }, sort_keys=True, indent=2))


def iter_drop_initial_zeroes(digits: list[int]):
    seen = False
    for digit in digits:
        if digit or seen:
            seen = True
            yield digit


if __name__ == "__main__":
    main()

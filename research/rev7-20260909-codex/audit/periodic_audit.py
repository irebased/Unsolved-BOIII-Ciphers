#!/usr/bin/env python3
"""Independent bounded audit of the Rev 7 periodic-column IoC scan.

This does not import the implementation under audit.  Its null replicate shuffles
each canonical base-converted orientation once, then derives the zero-prefix and
reversal cases.  Thus cases which are deterministically related in the target
remain related in every null replicate.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import platform
import random
import sys
from collections import Counter
from pathlib import Path

HERE = Path(__file__).resolve().parent
RESEARCH = HERE.parent
REPO = RESEARCH.parents[1]
SOURCE = REPO / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
OWNER_RESULTS = RESEARCH / "coverage/periodic/results.json"
EXPECTED_CT_SHA256 = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"


def ciphertext() -> str:
    text = SOURCE.read_text(encoding="utf-8")
    start = text.index("`83 B57B2") + 1
    end = text.index("`", start)
    value = "".join(text[start:end].split()).upper()
    assert len(value) == 1092 and set(value) == set("0123456789ABCDEF")
    assert hashlib.sha256(value.encode("ascii")).hexdigest() == EXPECTED_CT_SHA256
    return value


def orientations(value: str) -> dict[str, str]:
    pairs = [value[i : i + 2] for i in range(0, len(value), 2)]
    rows = {
        "forward": value,
        "reverse": value[::-1],
        "byte_reverse": "".join(reversed(pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in pairs),
    }
    assert rows["reverse"] == "".join(pair[::-1] for pair in reversed(pairs))
    assert all(len(v) == 1092 for v in rows.values()) and len(set(rows.values())) == 4
    return rows


def int_to_base(number: int, base: int) -> list[int]:
    if number == 0:
        return [0]
    out: list[int] = []
    while number:
        number, digit = divmod(number, base)
        out.append(digit)
    return out[::-1]


def base_to_int(digits: list[int], base: int) -> int:
    number = 0
    for digit in digits:
        assert 0 <= digit < base
        number = number * base + digit
    return number


def derive(core: list[int], zeros: int, reverse: bool) -> list[int]:
    out = [0] * zeros + core
    return out[::-1] if reverse else out


def invert_derived(stream: list[int], base: int, zeros: int, reverse: bool) -> int:
    work = stream[::-1] if reverse else stream[:]
    assert work[:zeros] == [0] * zeros
    return base_to_int(work[zeros:], base)


def pooled_column_ioc(stream: list[int], period: int) -> float:
    counts = [Counter() for _ in range(period)]
    sizes = [0] * period
    for index, symbol in enumerate(stream):
        column = index % period
        counts[column][symbol] += 1
        sizes[column] += 1
    numerator = sum(n * (n - 1) for column in counts for n in column.values())
    denominator = sum(n * (n - 1) for n in sizes)
    return numerator / denominator if denominator else 0.0


def detector_controls() -> dict:
    rows = {}
    for base in (26, 27):
        # Numeric symbols avoid conflating the 27th symbol with text rendering.
        plain = [0, 1, 25, 26 if base == 27 else 24, 4, 19, 0, 7, 12, 25, 2, 8, 17, 5]
        key_digits = [25, 14, 12, 1, 8, 4, 18]  # ZOMBIES as A=0
        encrypted = [(value + key_digits[i % len(key_digits)]) % base for i, value in enumerate(plain)]
        assert encrypted[0] != 0
        number = base_to_int(encrypted, base)
        recovered_cipher = int_to_base(number, base)
        recovered_plain = [(value - key_digits[i % len(key_digits)]) % base for i, value in enumerate(recovered_cipher)]
        assert recovered_cipher == encrypted and recovered_plain == plain
        # Whole-integer conversion drops a real leading zero; explicit restoration recovers it.
        leading_zero_cipher = [0] + encrypted
        lost = int_to_base(base_to_int(leading_zero_cipher, base), base)
        assert lost == encrypted and [0] + lost == leading_zero_cipher
        rows[str(base)] = {
            "numeric_plain": plain,
            "encrypted": encrypted,
            "exact_periodic_decrypt": True,
            "contains_symbol_26": 26 in plain,
            "leading_zero_lost_without_restore": True,
            "leading_zero_exact_after_restore": True,
            "control_period_ioc": pooled_column_ioc(encrypted, len(key_digits)),
        }
    assert rows["27"]["contains_symbol_26"]
    return rows


def target_rows(ct: str) -> list[dict]:
    rows = []
    for base in (26, 27):
        for name, oriented in orientations(ct).items():
            number = int(oriented, 16)
            core = int_to_base(number, base)
            assert core[0] != 0 and base_to_int(core, base) == number
            for zeros in range(3):
                for reverse in (False, True):
                    stream = derive(core, zeros, reverse)
                    assert invert_derived(stream, base, zeros, reverse) == number
                    for period in range(1, 41):
                        rows.append({
                            "base": base, "orientation": name, "zeros": zeros,
                            "reverse": reverse, "period": period,
                            "length": len(stream), "ioc": pooled_column_ioc(stream, period),
                        })
    return rows


def key(row: dict) -> tuple:
    return tuple(row[k] for k in ("base", "orientation", "zeros", "reverse", "period"))


def audit_owner(rows: list[dict]) -> dict:
    if not OWNER_RESULTS.exists():
        return {"available": False, "reason": "large owner result artifact not present"}
    owner = json.loads(OWNER_RESULTS.read_text(encoding="utf-8"))
    saved = {key(row): row for row in owner["target"]}
    assert len(rows) == len(saved) == 1920
    mismatches = []
    for row in rows:
        other = saved[key(row)]
        if row["length"] != other["length"] or abs(row["ioc"] - other["ioc"]) > 1e-15:
            mismatches.append({"key": key(row), "independent": row, "saved": other})
    # Reversal only permutes residue columns, so pooled IoC must be invariant.
    by = {key(row): row for row in rows}
    reversal_mismatches = []
    for row in rows:
        if row["reverse"]:
            peer = by[(row["base"], row["orientation"], row["zeros"], False, row["period"])]
            if abs(row["ioc"] - peer["ioc"]) > 1e-15:
                reversal_mismatches.append(key(row))
    return {
        "available": True,
        "saved_cipher_sha256": owner["cipher_sha256"],
        "target_mismatch_count": len(mismatches),
        "target_mismatch_examples": mismatches[:3],
        "reversal_invariance_mismatch_count": len(reversal_mismatches),
    }


def matched_grid_null(ct: str, target: list[dict], repetitions: int, seed: int) -> dict:
    """Family-wise null, conditional on each base/orientation core multiset.

    Orientations are treated as four separately conditioned streams.  Within an
    orientation, zero-prefix and reversal cases are derived after one shuffle,
    preserving their deterministic relation.  Each replicate statistic is the
    maximum over the same 4*3*2*40 grid as the target for that base.
    """
    rng = random.Random(seed)
    target_max = {base: max(r["ioc"] for r in target if r["base"] == base) for base in (26, 27)}
    cores = {
        (base, name): int_to_base(int(oriented, 16), base)
        for base in (26, 27)
        for name, oriented in orientations(ct).items()
    }
    maxima = {26: [], 27: []}
    for _rep in range(repetitions):
        replicate_max = {26: float("-inf"), 27: float("-inf")}
        for (base, _name), core in cores.items():
            shuffled = core[:]
            rng.shuffle(shuffled)
            for zeros in range(3):
                stream = derive(shuffled, zeros, False)
                # Reverse is an exact duplicate for this pooled statistic.
                for period in range(1, 41):
                    value = pooled_column_ioc(stream, period)
                    replicate_max[base] = max(replicate_max[base], value)
        for base in (26, 27):
            maxima[base].append(replicate_max[base])
    result = {}
    for base in (26, 27):
        ge = sum(value >= target_max[base] for value in maxima[base])
        ordered = sorted(maxima[base])
        result[str(base)] = {
            "target_grid_max": target_max[base],
            "null_grid_max_min": ordered[0],
            "null_grid_max_median": (ordered[(repetitions - 1)//2] + ordered[repetitions//2]) / 2,
            "null_grid_max_max": ordered[-1],
            "replicates_at_least_target": ge,
            "monte_carlo_p_plus_one": (ge + 1) / (repetitions + 1),
            "replicate_maxima": maxima[base],
        }
    return result


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--repetitions", type=int, default=200)
    parser.add_argument("--seed", type=int, default=20260910)
    parser.add_argument("--output", type=Path, default=HERE / "periodic_audit_results.json")
    args = parser.parse_args()
    ct = ciphertext()
    rows = target_rows(ct)
    result = {
        "identity": "ASTRA",
        "audit": "independent periodic-column IoC target and matched family-wise null",
        "python": sys.version,
        "platform": platform.platform(),
        "ciphertext_domain": "uppercase whitespace-free repository transcription, ASCII bytes",
        "ciphertext_length": len(ct),
        "ciphertext_sha256": hashlib.sha256(ct.encode("ascii")).hexdigest(),
        "owner_results_sha256": (hashlib.sha256(OWNER_RESULTS.read_bytes()).hexdigest()
                                  if OWNER_RESULTS.exists() else None),
        "target_count": len(rows),
        "target_rows": rows,
        "target_maxima": {
            str(base): max((row for row in rows if row["base"] == base), key=lambda row: row["ioc"])
            for base in (26, 27)
        },
        "owner_audit": audit_owner(rows),
        "detector_controls": detector_controls(),
        "null_design": {
            "repetitions": args.repetitions,
            "seed": args.seed,
            "conditioning": "one symbol-multiset-conditioned shuffle per base/orientation/replicate",
            "derived_cases": "prepend 0, 1, or 2 zeros; reversal is retained in target count but omitted from null computation because pooled IoC is exactly invariant",
            "replicate_statistic": "maximum pooled column IoC across the full 4 orientations x 3 zero counts x 2 reversal labels x periods 1..40 grid for one base",
            "orientation_dependence_limit": "the four base-converted orientations are shuffled independently; this is a stated product-conditional null, not a ciphertext-generative model",
        },
        "matched_grid_null": matched_grid_null(ct, rows, args.repetitions, args.seed),
    }
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    print(json.dumps({
        "output": str(args.output),
        "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
        "target_maxima": result["target_maxima"],
        "owner_audit": result["owner_audit"],
        "null_summary": {
            base: {k: v for k, v in data.items() if k != "replicate_maxima"}
            for base, data in result["matched_grid_null"].items()
        },
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

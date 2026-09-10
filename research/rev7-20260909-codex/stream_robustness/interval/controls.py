#!/usr/bin/env python3
"""Independent brute-force controls for interval.shortest_feasible_intervals."""
import hashlib
import itertools
import json
import random
from pathlib import Path

from interval import shortest_feasible_intervals

HERE = Path(__file__).resolve().parent

def direct_oracle(pairs, keystream, allowed, candidates):
    """All-interval oracle: rebuild each class candidate set for every [left,right)."""
    pairs = tuple(pairs)
    keystream = tuple(keystream)
    allowed = set(allowed)
    candidates = tuple(candidates)
    classes = tuple(dict.fromkeys(pairs))
    feasible = []
    for left in range(len(pairs) + 1):
        for right in range(left, len(pairs) + 1):
            maps = {}
            ok = True
            for symbol in classes:
                survivors = []
                for candidate in candidates:
                    valid = True
                    for position, pair in enumerate(pairs):
                        if pair == symbol and not (left <= position < right):
                            if (candidate ^ keystream[position]) not in allowed:
                                valid = False
                                break
                    if valid:
                        survivors.append(candidate)
                if not survivors:
                    ok = False
                    break
                maps[symbol] = survivors[0]
            if ok:
                feasible.append((right - left, left, right, tuple(maps.items())))
    best = min(row[0] for row in feasible)
    minima = [(left, right) for length, left, right, _ in feasible if length == best]
    witnesses = [mapping for length, _, _, mapping in feasible if length == best]
    return best, minima, witnesses, feasible

def check_case(name, pairs, stream, allowed, candidates):
    result = shortest_feasible_intervals(pairs, stream, allowed, candidates)
    best, minima, _, feasible = direct_oracle(pairs, stream, allowed, candidates)
    assert result.length == best
    assert list(result.intervals) == minima
    for (left, right), mapping in zip(result.intervals, result.witnesses):
        mapping = dict(mapping)
        assert len(mapping) == len(set(pairs))
        for position, symbol in enumerate(pairs):
            if not (left <= position < right):
                assert (mapping[symbol] ^ stream[position]) in set(allowed)
    return {
        "name": name,
        "pairs": list(pairs),
        "keystream": list(stream),
        "allowed": sorted(allowed),
        "candidate_domain": list(candidates),
        "shortest_length": result.length,
        "minimizing_intervals": [list(x) for x in result.intervals],
        "feasible_interval_count": len(feasible),
    }

fixtures = []
fixtures.append(check_case("zero_length_sequence", [], [], {0}, range(4)))
fixtures.append(check_case("already_feasible_zero_erasure", ["A", "B"], [0, 1], {0, 1}, range(4)))
fixtures.append(check_case("full_erasure_required", ["A", "B"], [1, 1], {0}, [0]))
fixtures.append(check_case("repeated_class_constraints", ["A", "B", "A", "A"], [0, 0, 1, 2], {0}, range(4)))
fixtures.append(check_case("singleton_classes", ["A", "B", "C"], [0, 1, 2], {0}, range(4)))
fixtures.append(check_case("left_boundary_minimum", ["A", "A", "B"], [1, 0, 0], {0}, [0]))
fixtures.append(check_case("right_boundary_minimum", ["B", "A", "A"], [0, 0, 1], {0}, [0]))

# Discover and freeze a small case with more than one distinct minimizing interval.
multiple = None
for pairs in itertools.product("AB", repeat=4):
    for stream in itertools.product(range(3), repeat=4):
        row = check_case("multiple_minima", pairs, stream, {0, 1}, range(3))
        if len(row["minimizing_intervals"]) >= 2 and row["shortest_length"] > 0:
            multiple = row
            break
    if multiple:
        break
assert multiple is not None
fixtures.append(multiple)

exhaustive_cases = 0
for n in range(5):
    for pairs in itertools.product("AB", repeat=n):
        for stream in itertools.product(range(4), repeat=n):
            for mask in range(1, 1 << 4):
                allowed = {value for value in range(4) if mask & (1 << value)}
                check_case("exhaustive", pairs, stream, allowed, range(4))
                exhaustive_cases += 1

rng = random.Random(0xA57A)
seeded_cases = 500
for index in range(seeded_cases):
    n = rng.randrange(0, 13)
    class_count = rng.randrange(1, 5)
    pairs = [f"P{rng.randrange(class_count)}" for _ in range(n)]
    stream = [rng.randrange(8) for _ in range(n)]
    allowed = {value for value in range(8) if rng.randrange(2)}
    if not allowed:
        allowed.add(rng.randrange(8))
    check_case(f"seeded_{index}", pairs, stream, allowed, range(8))

out = {
    "identity": "ASTRA",
    "target_evaluated": False,
    "crypto_evaluated": False,
    "algorithm": "monotone two-pointer window with per-class per-candidate outside-invalid counters",
    "coordinates": "half-open [start,end) intervals in the supplied oriented decoded-byte sequence",
    "complexity": {
        "feasibility_core_time": "O(n*q), where q is candidate-domain size (256 for byte mappings)",
        "witness_materialization_time_upper_bound": "O(n*k*q)",
        "counter_space": "O(k*q), where k is the number of displayed-pair classes",
        "retained_witness_space": "O(m*k), where m is the number of minimizing intervals",
    },
    "scope": (
        "Synthetic-only controls for the shortest span of one contiguous ignored/corrupt byte region "
        "needed to make an arbitrary fixed pair-to-byte mapping feasible outside it; no injectivity."
    ),
    "fixtures": fixtures,
    "exhaustive_cases": exhaustive_cases,
    "seeded_cases": seeded_cases,
}
(HERE / "controls.json").write_text(json.dumps(out, indent=2, sort_keys=True) + "\n")
print(json.dumps({
    "identity": "ASTRA",
    "target_evaluated": False,
    "exhaustive_cases": exhaustive_cases,
    "seeded_cases": seeded_cases,
    "fixture_count": len(fixtures),
    "controls_sha256": hashlib.sha256((HERE / "controls.json").read_bytes()).hexdigest(),
}, indent=2))

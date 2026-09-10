#!/usr/bin/env python3
"""Shortest erased interval for feasibility of an arbitrary fixed pair-to-byte map.

The sliding feasibility core is O(n*q). Materializing witnesses whenever a new
or tied minimum is observed adds up to O(n*k*q), where k is the class count.
"""
from __future__ import annotations
from collections import defaultdict
from dataclasses import dataclass
from typing import Hashable, Iterable, Sequence

@dataclass(frozen=True)
class IntervalResult:
    length: int
    intervals: tuple[tuple[int, int], ...]
    witnesses: tuple[tuple[tuple[Hashable, int], ...], ...]
    sequence_length: int
    pair_class_count: int
    candidate_domain_size: int

def shortest_feasible_intervals(
    pair_symbols: Sequence[Hashable],
    keystream: bytes | Sequence[int],
    allowed_plain_bytes: Iterable[int],
    candidate_domain: Iterable[int] = range(256),
) -> IntervalResult:
    """Return every shortest half-open interval [start,end) whose removal is feasible.

    Coordinates refer only to the supplied oriented decoded-byte sequence. A class
    candidate is feasible when every occurrence outside the removed interval XORs
    with its keystream byte into allowed_plain_bytes.
    """
    pairs = tuple(pair_symbols)
    stream = tuple(keystream)
    allowed = frozenset(allowed_plain_bytes)
    candidates = tuple(candidate_domain)
    n = len(pairs)
    if len(stream) != n:
        raise ValueError("pair_symbols and keystream lengths differ")
    if len(set(candidates)) != len(candidates) or not candidates:
        raise ValueError("candidate_domain must be nonempty and unique")
    if any(not isinstance(value, int) or not 0 <= value <= 255 for value in stream):
        raise ValueError("keystream bytes must be integers in 0..255")
    if any(not isinstance(value, int) or not 0 <= value <= 255 for value in candidates):
        raise ValueError("candidate bytes must be integers in 0..255")
    if any(not isinstance(value, int) or not 0 <= value <= 255 for value in allowed):
        raise ValueError("allowed bytes must be integers in 0..255")

    classes = tuple(dict.fromkeys(pairs))
    class_index = {symbol: index for index, symbol in enumerate(classes)}
    counts = [[0] * len(candidates) for _ in classes]
    zero_counts = [len(candidates) for _ in classes]

    def change_position(position: int, delta: int) -> None:
        class_id = class_index[pairs[position]]
        row = counts[class_id]
        key_byte = stream[position]
        for candidate_index, candidate in enumerate(candidates):
            if (candidate ^ key_byte) not in allowed:
                before = row[candidate_index]
                after = before + delta
                assert after >= 0
                row[candidate_index] = after
                if before == 0 and after != 0:
                    zero_counts[class_id] -= 1
                elif before != 0 and after == 0:
                    zero_counts[class_id] += 1

    for position in range(n):
        change_position(position, +1)

    infeasible_classes = sum(count == 0 for count in zero_counts)

    def update(position: int, delta: int) -> None:
        nonlocal infeasible_classes
        class_id = class_index[pairs[position]]
        before = zero_counts[class_id]
        change_position(position, delta)
        after = zero_counts[class_id]
        if before == 0 and after > 0:
            infeasible_classes -= 1
        elif before > 0 and after == 0:
            infeasible_classes += 1

    def witness() -> tuple[tuple[Hashable, int], ...]:
        answer = []
        for class_id, symbol in enumerate(classes):
            candidate = next(
                candidates[index] for index, count in enumerate(counts[class_id]) if count == 0
            )
            answer.append((symbol, candidate))
        return tuple(answer)

    best = n + 1
    minima: list[tuple[int, int]] = []
    witnesses: list[tuple[tuple[Hashable, int], ...]] = []
    right = 0
    left = 0
    while left <= n:
        while infeasible_classes and right < n:
            update(right, -1)
            right += 1
        if infeasible_classes:
            break
        length = right - left
        if length < best:
            best = length
            minima = [(left, right)]
            witnesses = [witness()]
        elif length == best:
            minima.append((left, right))
            witnesses.append(witness())
        if left == n:
            break
        if left < right:
            update(left, +1)
        else:
            # Empty window: advance both endpoints together without changing state.
            right += 1
        left += 1

    assert best <= n
    return IntervalResult(
        length=best,
        intervals=tuple(minima),
        witnesses=tuple(witnesses),
        sequence_length=n,
        pair_class_count=len(classes),
        candidate_domain_size=len(candidates),
    )

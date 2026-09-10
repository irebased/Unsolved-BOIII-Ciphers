#!/usr/bin/env python3
"""Reference for the rectangular variant-A first-block all-IV certificate."""
from __future__ import annotations
import itertools
import math
from typing import Callable, Iterable, Sequence

IDENTITY = "ASTRA"
A105 = {9, 10, 13} | set(range(32, 127)) | {0xE2, 0x80, 0x93, 0x94, 0x98, 0x99, 0xA6}

def inverse_order(fable_order: Sequence[int]) -> tuple[int, ...]:
    """Convert FABLE order[rank]=natural_column to slots[natural_column]=rank."""
    order = tuple(fable_order)
    if sorted(order) != list(range(len(order))):
        raise ValueError("order must be a permutation")
    slots = [-1] * len(order)
    for rank, natural_column in enumerate(order):
        slots[natural_column] = rank
    return tuple(slots)

def observe_variant_a(natural_ciphertext: bytes, width: int, fable_order: Sequence[int]) -> bytes:
    """FABLE columnarA encryption for a rectangular byte matrix."""
    if width <= 0 or len(natural_ciphertext) % width:
        raise ValueError("rectangular length required")
    order = tuple(fable_order)
    slots = inverse_order(order)
    del slots
    rows = len(natural_ciphertext) // width
    return bytes(
        natural_ciphertext[row * width + natural_column]
        for natural_column in order
        for row in range(rows)
    )

def invert_variant_a(observed: bytes, width: int, fable_order: Sequence[int]) -> bytes:
    """FABLE columnarA inverse; natural rows from contiguous observed chunks."""
    if width <= 0 or len(observed) % width:
        raise ValueError("rectangular length required")
    slots = inverse_order(fable_order)
    rows = len(observed) // width
    return bytes(
        observed[slots[natural_column] * rows + row]
        for row in range(rows)
        for natural_column in range(width)
    )

def evaluate_first_block_tuple(
    observed: bytes,
    width: int,
    block_size: int,
    first_slots: Sequence[int],
    block_first_byte: Callable[[bytes], int],
    allowed_plain_bytes: Iterable[int] = A105,
) -> dict:
    """Intersect possible observed ranks for natural column block_size.

    first_slots[j] is the observed chunk rank assigned to natural column j.
    The result is only a prefix/candidate certificate, never a full order or
    plaintext.
    """
    if width <= block_size or block_size <= 0:
        raise ValueError("require width > block_size > 0")
    if len(observed) % width:
        raise ValueError("rectangular length required")
    prefix = tuple(first_slots)
    if len(prefix) != block_size or len(set(prefix)) != block_size:
        raise ValueError("first_slots must be a distinct block-size tuple")
    if any(rank < 0 or rank >= width for rank in prefix):
        raise ValueError("slot rank outside width")
    allowed = frozenset(allowed_plain_bytes)
    rows = len(observed) // width
    candidates = set(range(width)) - set(prefix)
    rows_checked = 0
    candidate_tests = 0
    for row in range(rows):
        if not candidates:
            break
        block = bytes(observed[rank * rows + row] for rank in prefix)
        key_byte = block_first_byte(block)
        if not isinstance(key_byte, int) or not 0 <= key_byte <= 255:
            raise ValueError("block_first_byte must return an integer byte")
        retained = set()
        for rank in candidates:
            candidate_tests += 1
            if (observed[rank * rows + row] ^ key_byte) in allowed:
                retained.add(rank)
        candidates = retained
        rows_checked += 1
    return {
        "first_slots": list(prefix),
        "surviving_ninth_ranks": sorted(candidates),
        "empty_candidate_mask": not candidates,
        "rows_checked": rows_checked,
        "block_calls": rows_checked,
        "candidate_tests": candidate_tests,
    }

def scan_first_block_prefixes(
    observed: bytes,
    width: int,
    block_size: int,
    block_first_byte: Callable[[bytes], int],
    allowed_plain_bytes: Iterable[int] = A105,
) -> dict:
    """Enumerate P(width,block_size) prefixes and partition width! completions."""
    rejected = 0
    survivors = []
    block_calls = 0
    candidate_tests = 0
    rows_checked = 0
    for prefix in itertools.permutations(range(width), block_size):
        row = evaluate_first_block_tuple(
            observed, width, block_size, prefix, block_first_byte, allowed_plain_bytes
        )
        block_calls += row["block_calls"]
        candidate_tests += row["candidate_tests"]
        rows_checked += row["rows_checked"]
        if row["empty_candidate_mask"]:
            rejected += 1
        else:
            survivors.append(row)
    prefixes = math.perm(width, block_size)
    completion_weight = math.factorial(width - block_size)
    rejected_weight = rejected * completion_weight
    unresolved_weight = len(survivors) * completion_weight
    assert rejected + len(survivors) == prefixes
    assert rejected_weight + unresolved_weight == math.factorial(width)
    return {
        "width": width,
        "block_size": block_size,
        "prefixes_examined": prefixes,
        "rejected_prefixes": rejected,
        "survivor_prefix_count": len(survivors),
        "completion_weight_per_prefix": completion_weight,
        "rejected_completion_weight": rejected_weight,
        "unresolved_completion_weight": unresolved_weight,
        "expected_completion_weight": math.factorial(width),
        "block_calls": block_calls,
        "rows_checked": rows_checked,
        "candidate_tests": candidate_tests,
        "survivor_prefixes": survivors,
    }

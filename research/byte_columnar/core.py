#!/usr/bin/env python3
"""Synthetic-only reference for prefix-pruned equal-column byte transpositions."""
from __future__ import annotations
from dataclasses import dataclass, field
import itertools, math

IDENTITY = "ASTRA"
PUNCT3 = {0x93, 0x94, 0x98, 0x99, 0xA6}
AES_KEY = b"Zombies" + bytes(9)
AES_IV = b"0" * 16

def fsa_step(state: int, value: int) -> int | None:
    if state == 0:
        if value in {9, 10, 13} or 32 <= value <= 126:
            return 0
        if value == 0xE2:
            return 1
        return None
    if state == 1:
        return 2 if value == 0x80 else None
    if state == 2:
        return 0 if value in PUNCT3 else None
    raise AssertionError(state)

def fsa_valid(data: bytes) -> bool:
    state = 0
    for value in data:
        state = fsa_step(state, value)
        if state is None:
            return False
    return state == 0

def cfb8(data: bytes, decrypt: bool) -> bytes:
    from Crypto.Cipher import AES
    cipher = AES.new(AES_KEY, AES.MODE_CFB, iv=AES_IV, segment_size=8)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)

def validate_shape(data: bytes, width: int) -> int:
    assert 3 <= width <= 14 and len(data) % width == 0
    return len(data) // width

def transpose_encrypt(ciphertext: bytes, width: int, order: tuple[int, ...], variant: str) -> bytes:
    """FABLE semantics: order[k] is the natural column read at rank k."""
    rows = validate_shape(ciphertext, width)
    assert sorted(order) == list(range(width))
    out = bytearray(len(ciphertext))
    if variant == "A":
        for k, col in enumerate(order):
            for row in range(rows):
                out[k * rows + row] = ciphertext[row * width + col]
    elif variant == "B":
        for row in range(rows):
            for k, col in enumerate(order):
                out[row * width + k] = ciphertext[col * rows + row]
    else:
        raise ValueError(variant)
    return bytes(out)

def transpose_inverse(observed: bytes, width: int, order: tuple[int, ...], variant: str) -> bytes:
    rows = validate_shape(observed, width)
    assert sorted(order) == list(range(width))
    out = bytearray(len(observed))
    if variant == "A":
        for k, col in enumerate(order):
            for row in range(rows):
                out[row * width + col] = observed[k * rows + row]
    elif variant == "B":
        for row in range(rows):
            for k, col in enumerate(order):
                out[col * rows + row] = observed[row * width + k]
    else:
        raise ValueError(variant)
    return bytes(out)

def order_from_slots(slots: tuple[int, ...]) -> tuple[int, ...]:
    """slots[c]=observed rank of natural column c; return FABLE order[k]=c."""
    order = [-1] * len(slots)
    for col, rank in enumerate(slots):
        order[rank] = col
    return tuple(order)

@dataclass
class Stats:
    nodes: int = 0
    rejected_prefix: int = 0
    rejected_full: int = 0
    rejected_unterminated: int = 0
    accepted_complete: int = 0
    rejected_weight: int = 0
    terminal_weight: int = 0
    maximum_depth: int = 0
    capped: bool = False

@dataclass
class Result:
    stats: Stats
    solutions: list[dict] = field(default_factory=list)

def search(observed: bytes, width: int, variant: str, node_limit: int) -> Result:
    """DFS assigns natural columns 0..w-1 to unused observed ranks."""
    rows = validate_shape(observed, width)
    stats = Stats()
    slots = [-1] * width
    used = [False] * width
    solutions: list[dict] = []
    from Crypto.Cipher import AES
    aes = AES.new(AES_KEY, AES.MODE_ECB)

    def rec(depth: int, state: int, reg: bytes, plain_prefix: bytes) -> None:
        if stats.capped:
            return
        if stats.nodes >= node_limit:
            stats.capped = True
            return
        stats.nodes += 1
        stats.maximum_depth = max(stats.maximum_depth, depth)
        if depth == width:
            if state != 0:
                stats.rejected_unterminated += 1
                stats.rejected_weight += 1
                return
            stats.accepted_complete += 1
            stats.terminal_weight += 1
            order = order_from_slots(tuple(slots))
            ciphertext = transpose_inverse(observed, width, order, variant)
            plaintext = cfb8(ciphertext, True)
            assert plaintext.startswith(plain_prefix)
            assert fsa_valid(plaintext)
            solutions.append({"order": list(order), "plaintext_hex": plaintext.hex()})
            return

        for rank in range(width):
            if stats.capped:
                return
            if used[rank]:
                continue
            slots[depth] = rank
            used[rank] = True
            if variant == "A":
                emitted = bytes([observed[rank * rows]])
            else:
                emitted = bytes(observed[row * width + rank] for row in range(rows))
            next_state = state
            next_reg = bytearray(reg)
            next_plain = bytearray()
            ok = True
            for cb in emitted:
                pb = cb ^ aes.encrypt(bytes(next_reg))[0]
                maybe = fsa_step(next_state, pb)
                if maybe is None:
                    ok = False
                    break
                next_state = maybe
                next_plain.append(pb)
                next_reg[:-1] = next_reg[1:]
                next_reg[-1] = cb
            remaining = width - depth - 1
            if ok and variant == "A" and depth + 1 == width:
                order = order_from_slots(tuple(slots))
                ciphertext = transpose_inverse(observed, width, order, variant)
                suffix = cfb8(ciphertext, True)[width:]
                for pb in suffix:
                    maybe = fsa_step(next_state, pb)
                    if maybe is None:
                        ok = False
                        stats.rejected_full += 1
                        break
                    next_state = maybe
                if ok:
                    next_plain.extend(suffix)
            if ok:
                rec(depth + 1, next_state, bytes(next_reg), plain_prefix + bytes(next_plain))
            else:
                stats.rejected_prefix += 1
                stats.rejected_weight += math.factorial(remaining)
            used[rank] = False
            slots[depth] = -1

    rec(0, 0, AES_IV, b"")
    expected = math.factorial(width)
    assert stats.rejected_weight + stats.terminal_weight <= expected
    if not stats.capped:
        assert stats.rejected_weight + stats.terminal_weight == expected
    return Result(stats, solutions)

def naive(observed: bytes, width: int, variant: str) -> list[dict]:
    out = []
    for order in itertools.permutations(range(width)):
        ciphertext = transpose_inverse(observed, width, order, variant)
        plaintext = cfb8(ciphertext, True)
        if fsa_valid(plaintext):
            out.append({"order": list(order), "plaintext_hex": plaintext.hex()})
    return out

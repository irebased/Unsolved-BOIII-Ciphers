#!/usr/bin/env python3
"""Synthetic-only prototype for hex-alphabet permutation before CFB8.

No Rev 7 ciphertext is loaded or evaluated by this file.  The search assigns a
global bijection from displayed hexadecimal symbols to nibble values as symbols
are first encountered, decrypts one CFB8 byte, and rejects the branch as soon as
the plaintext predicate fails.
"""
from __future__ import annotations

import argparse
import hashlib
import itertools
import json
import math
import random
import sys
import time
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Callable, Iterable, Optional, Sequence

from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES, Blowfish, DES

HEX = "0123456789ABCDEF"
ALLOWED = {9, 10, 13} | set(range(32, 127))
HERE = Path(__file__).resolve().parent


def cipher_specs():
    """The deliberately bounded initial cipher/key/IV scope."""
    return {
        "aes128": (AES, b"Zombies".ljust(16, b"\0"), b"0" * 16),
        "blowfish": (Blowfish, b"Zombies", b"0" * 8),
        "des": (DES, b"Zombies".ljust(8, b"\0"), b"0" * 8),
    }


def ecb_oracle(name: str):
    module, key, iv = cipher_specs()[name]
    return module.new(key, module.MODE_ECB), key, iv


def manual_cfb8(data: bytes, ecb, iv: bytes, decrypt: bool) -> bytes:
    register = iv
    out = bytearray()
    for value in data:
        transformed = value ^ ecb.encrypt(register)[0]
        if decrypt:
            plaintext, ciphertext = transformed, value
        else:
            plaintext, ciphertext = value, transformed
        out.append(plaintext if decrypt else ciphertext)
        register = register[1:] + bytes([ciphertext])
    return bytes(out)


def library_cfb8(data: bytes, name: str, decrypt: bool) -> bytes:
    module, key, iv = cipher_specs()[name]
    cipher = module.new(key, module.MODE_CFB, iv=iv, segment_size=8)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def orientations(value: str) -> dict[str, str]:
    assert len(value) % 2 == 0
    pairs = [value[i:i + 2] for i in range(0, len(value), 2)]
    return {
        "forward": value,
        "reverse": value[::-1],
        "byte_reverse": "".join(reversed(pairs)),
        "nibble_swap": "".join(pair[::-1] for pair in pairs),
    }


def display_encode(ciphertext: bytes, mapping: Sequence[int]) -> str:
    """Encode true nibbles using inverse(display-symbol -> true-nibble)."""
    inverse = [None] * 16
    for displayed, actual in enumerate(mapping):
        inverse[actual] = displayed
    assert all(value is not None for value in inverse)
    return "".join(HEX[inverse[nibble]] for byte in ciphertext for nibble in (byte >> 4, byte & 15))


@dataclass
class SearchStats:
    nodes: int = 0
    rejected_plaintext: int = 0
    complete: int = 0
    maximum_depth: int = 0
    aborted_at_node_limit: bool = False
    rejected_completion_weight: int = 0
    terminal_completion_weight: int = 0
    rejected_unterminated_endpoint: int = 0


def ascii_transition(state: int, _position: int, value: int) -> Optional[int]:
    assert state == 0
    return 0 if value in ALLOWED else None


def historical_utf8_transition(state: int, _position: int, value: int) -> Optional[int]:
    """ASCII plus four explicitly allowed UTF-8 punctuation code points.

    Accepted multibyte sequences are E2 80 93/94/98/99: en dash, em dash,
    left single quotation mark, and right single quotation mark.
    """
    if state == 0:
        if value in ALLOWED:
            return 0
        return 1 if value == 0xE2 else None
    if state == 1:
        return 2 if value == 0x80 else None
    assert state == 2
    return 0 if value in (0x93, 0x94, 0x98, 0x99) else None


def backtrack(
    displayed_hex: str,
    ecb,
    iv: bytes,
    transition: Callable[[int, int, int], Optional[int]],
    actual_values: Iterable[int] = range(16),
    node_limit: Optional[int] = None,
    solution_limit: Optional[int] = None,
    initial_endpoint_state: int = 0,
    terminal_endpoint_state: int = 0,
    seed_mapping: Optional[dict[int, int]] = None,
):
    """Enumerate mappings whose sequential CFB8 plaintext passes ``accept``.

    ``transition(state, position, plaintext_byte)`` returns the next endpoint
    state or ``None`` to reject.  Values outside ``actual_values``
    are unavailable, enabling an exhaustive small-alphabet comparison.
    """
    assert len(displayed_hex) % 2 == 0 and set(displayed_hex) <= set(HEX)
    symbols = [(HEX.index(displayed_hex[i]), HEX.index(displayed_hex[i + 1]))
               for i in range(0, len(displayed_hex), 2)]
    allowed_values = tuple(actual_values)
    allowed_mask = sum(1 << value for value in allowed_values)
    mapping = [-1] * 16
    seed_mapping = seed_mapping or {}
    assert set(seed_mapping) <= set(range(16))
    assert set(seed_mapping.values()) <= set(allowed_values)
    assert len(set(seed_mapping.values())) == len(seed_mapping)
    for displayed, actual in seed_mapping.items():
        mapping[displayed] = actual
    initial_used_mask = sum(1 << value for value in seed_mapping.values())
    expected_completion_weight = math.factorial(len(allowed_values) - len(seed_mapping))
    plaintext = bytearray()
    solutions = []
    stats = SearchStats()

    def recurse(position: int, register: bytes, used_mask: int, endpoint_state: int):
        if stats.aborted_at_node_limit or (solution_limit is not None and len(solutions) >= solution_limit):
            return
        if node_limit is not None and stats.nodes >= node_limit:
            stats.aborted_at_node_limit = True
            return
        stats.nodes += 1
        stats.maximum_depth = max(stats.maximum_depth, position)
        if position == len(symbols):
            if endpoint_state != terminal_endpoint_state:
                stats.rejected_unterminated_endpoint += 1
                stats.rejected_completion_weight += math.factorial(len(allowed_values) - bin(used_mask).count("1"))
                return
            stats.complete += 1
            stats.terminal_completion_weight += math.factorial(len(allowed_values) - bin(used_mask).count("1"))
            solutions.append({"mapping": tuple(mapping), "plaintext": bytes(plaintext)})
            return

        high_symbol, low_symbol = symbols[position]
        high_current, low_current = mapping[high_symbol], mapping[low_symbol]
        unused = [value for value in allowed_values if not (used_mask >> value) & 1]
        if high_symbol == low_symbol:
            choices = [(high_current, high_current)] if high_current >= 0 else [(v, v) for v in unused]
        elif high_current >= 0 and low_current >= 0:
            choices = [(high_current, low_current)]
        elif high_current >= 0:
            choices = [(high_current, v) for v in unused]
        elif low_current >= 0:
            choices = [(v, low_current) for v in unused]
        else:
            choices = itertools.permutations(unused, 2)

        keystream = ecb.encrypt(register)[0]
        for high, low in choices:
            assigned_high = high_current < 0
            assigned_low = low_current < 0 and low_symbol != high_symbol
            if assigned_high:
                mapping[high_symbol] = high
            if assigned_low:
                mapping[low_symbol] = low
            new_used = used_mask
            if assigned_high:
                new_used |= 1 << high
            if assigned_low:
                new_used |= 1 << low
            ciphertext_byte = (high << 4) | low
            plaintext_byte = ciphertext_byte ^ keystream
            next_endpoint_state = transition(endpoint_state, position, plaintext_byte)
            if next_endpoint_state is not None:
                plaintext.append(plaintext_byte)
                recurse(position + 1, register[1:] + bytes([ciphertext_byte]), new_used, next_endpoint_state)
                plaintext.pop()
            else:
                stats.rejected_plaintext += 1
                assigned_count = bin(new_used).count("1")
                stats.rejected_completion_weight += math.factorial(len(allowed_values) - assigned_count)
            if assigned_high:
                mapping[high_symbol] = -1
            if assigned_low:
                mapping[low_symbol] = -1

    recurse(0, iv, initial_used_mask, initial_endpoint_state)
    # For a completed root traversal, the disjoint rejected and terminal subtrees
    # partition every full bijection.  With a cap, the sum is strictly smaller.
    certificate = stats.rejected_completion_weight + stats.terminal_completion_weight
    assert certificate <= expected_completion_weight
    if not stats.aborted_at_node_limit and solution_limit is None:
        assert certificate == expected_completion_weight
    return solutions, stats


def naive_small(displayed_hex: str, ecb, iv: bytes, values: Sequence[int]):
    used_symbols = sorted({HEX.index(char) for char in displayed_hex})
    assert used_symbols == list(range(len(values)))
    survivors = {}
    for permutation in itertools.permutations(values):
        table = dict(zip(used_symbols, permutation))
        ciphertext = bytes((table[HEX.index(displayed_hex[i])] << 4) |
                           table[HEX.index(displayed_hex[i + 1])]
                           for i in range(0, len(displayed_hex), 2))
        plaintext = manual_cfb8(ciphertext, ecb, iv, decrypt=True)
        if all(value in ALLOWED for value in plaintext):
            survivors[tuple(permutation)] = plaintext
    return survivors


def run_controls(node_limit: int) -> dict:
    rng = random.Random(20260909)
    cfb_checks = {}
    for name in cipher_specs():
        ecb, _key, iv = ecb_oracle(name)
        plaintext = b"CFB8 manual/library control: full bytes \x00\x7f\x80\xff"
        ciphertext = manual_cfb8(plaintext, ecb, iv, decrypt=False)
        assert ciphertext == library_cfb8(plaintext, name, decrypt=False)
        assert manual_cfb8(ciphertext, ecb, iv, decrypt=True) == plaintext
        assert library_cfb8(ciphertext, name, decrypt=True) == plaintext
        cfb_checks[name] = {
            "ciphertext_sha256": hashlib.sha256(ciphertext).hexdigest(),
            "manual_matches_library_segment_size_8": True,
            "full_byte_roundtrip": True,
        }

    # A nontrivial full permutation is recovered under known plaintext.  This
    # validates assignment, feedback, rollback, and inverse display encoding;
    # the target search would use only the allowed-byte predicate.
    mapping = list(range(16))
    rng.shuffle(mapping)
    ecb, _key, iv = ecb_oracle("aes128")
    planted_plaintext = ("KNOWN PLANT: en–em—left‘right’ and the permutation is exact.\r\n" * 2).encode("utf-8")
    planted_ciphertext = manual_cfb8(planted_plaintext, ecb, iv, decrypt=False)
    displayed = display_encode(planted_ciphertext, mapping)
    assert len(set(displayed)) == 16
    plant_solutions, plant_stats = backtrack(
        displayed, ecb, iv,
        lambda state, position, value: state if value == planted_plaintext[position] else None)
    assert len(plant_solutions) == 1
    assert plant_solutions[0]["mapping"] == tuple(mapping)
    assert plant_solutions[0]["plaintext"] == planted_plaintext

    # Target-like endpoint control: leave five mapping entries unknown and use
    # only the ASCII-plus-four-punctuation FSA.  The known plant must survive.
    unknown_symbols = sorted(set(HEX.index(char) for char in displayed))[-5:]
    seed = {symbol: actual for symbol, actual in enumerate(mapping) if symbol not in unknown_symbols}
    endpoint_solutions, endpoint_stats = backtrack(
        displayed, ecb, iv, historical_utf8_transition, seed_mapping=seed)
    endpoint_matches = [solution for solution in endpoint_solutions
                        if solution["mapping"] == tuple(mapping) and solution["plaintext"] == planted_plaintext]
    assert len(endpoint_matches) == 1

    # Exhaustive reduced-domain agreement against naive permutation enumeration.
    small_display = "140203333103"
    fast, small_stats = backtrack(
        small_display, ecb, iv, ascii_transition,
        actual_values=range(5))
    fast_outputs = {tuple(solution["mapping"][:5]): solution["plaintext"] for solution in fast}
    naive_outputs = naive_small(small_display, ecb, iv, tuple(range(5)))
    assert fast_outputs == naive_outputs and fast_outputs

    # Synthetic-only feasibility sample.  It is intentionally node-capped and
    # must never be reported as a target result.
    synthetic = "".join(rng.choice(HEX) for _ in range(160))
    started = time.perf_counter()
    _solutions, benchmark_stats = backtrack(
        synthetic, ecb, iv, historical_utf8_transition,
        node_limit=node_limit, solution_limit=1)
    seconds = time.perf_counter() - started
    return {
        "identity": "ASTRA",
        "target_evaluated": False,
        "python": sys.version,
        "pycryptodome": crypto_version,
        "allowed_plaintext_bytes": sorted(ALLOWED),
        "cipher_scope": {
            name: {"key_hex": key.hex(), "iv_hex": iv.hex(), "block_size": len(iv)}
            for name, (_module, key, iv) in cipher_specs().items()
        },
        "cfb8_controls": cfb_checks,
        "known_plant": {
            "mapping": mapping,
            "displayed_sha256": hashlib.sha256(displayed.encode("ascii")).hexdigest(),
            "unique_solution": True,
            "stats": asdict(plant_stats),
        },
        "historical_utf8_endpoint_control": {
            "accepted_codepoints": ["U+2013", "U+2014", "U+2018", "U+2019"],
            "unknown_mapping_entries": len(unknown_symbols),
            "total_survivors": len(endpoint_solutions),
            "plant_survives_exactly_once": True,
            "fully_terminated": True,
            "stats": asdict(endpoint_stats),
        },
        "small_alphabet_exhaustive": {
            "actual_values": list(range(5)),
            "naive_mapping_count": len(naive_outputs),
            "backtracking_mapping_count": len(fast_outputs),
            "mapping_and_plaintext_sets_equal": True,
            "survivors": [
                {"mapping": list(mapping), "plaintext_hex": plaintext.hex()}
                for mapping, plaintext in sorted(fast_outputs.items())
            ],
            "stats": asdict(small_stats),
        },
        "synthetic_feasibility": {
            "node_limit": node_limit,
            "stats": asdict(benchmark_stats),
            "seconds": seconds,
            "nodes_per_second": benchmark_stats.nodes / seconds,
            "warning": "synthetic node-capped timing only; not a Rev 7 runtime or result",
        },
    }


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--controls", action="store_true", help="run synthetic controls (the only implemented action)")
    parser.add_argument("--node-limit", type=int, default=250_000)
    parser.add_argument("--output", type=Path, default=HERE / "feasibility.json")
    args = parser.parse_args()
    if not args.controls:
        parser.error("target execution is deliberately unavailable; pass --controls")
    result = run_controls(args.node_limit)
    args.output.write_text(json.dumps(result, indent=2, sort_keys=True) + "\n")
    print(json.dumps({
        "target_evaluated": result["target_evaluated"],
        "known_plant": result["known_plant"],
        "small_alphabet_exhaustive": result["small_alphabet_exhaustive"],
        "synthetic_feasibility": result["synthetic_feasibility"],
        "output_sha256": hashlib.sha256(args.output.read_bytes()).hexdigest(),
    }, indent=2, sort_keys=True))


if __name__ == "__main__":
    main()

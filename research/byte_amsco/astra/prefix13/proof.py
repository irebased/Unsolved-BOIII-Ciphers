from __future__ import annotations

"""First-six-column necessary filter for odd-width byte AMSCO and 8-byte CFB8."""

import math
from typing import Callable, Sequence

A105 = frozenset((9, 10, 13, *range(32, 127), 0x80, 0x93, 0x94, 0x98, 0x99, 0xA6, 0xE2))


def validate_rectangular(n: int, width: int, start: int) -> tuple[int, int]:
    if width < 7 or width % 2 == 0:
        raise ValueError("width must be odd and at least 7")
    if start not in (1, 2):
        raise ValueError("start must be 1 or 2")
    cycle_bytes = 3 * width
    if (2 * n) % cycle_bytes:
        raise ValueError("input does not contain an integral number of rows")
    rows = 2 * n // cycle_bytes
    if rows % 2:
        raise ValueError("row count must be even")
    chunk = 3 * rows // 2
    if chunk * width != n:
        raise AssertionError("rectangle partition")
    return rows, chunk


def cell_size(row: int, column: int, start: int) -> int:
    return start if (row + column) % 2 == 0 else 3 - start


def column_offset(row: int, column: int, start: int) -> int:
    # Each pair of rows contributes three bytes to every natural column.
    return 3 * (row // 2) + (row % 2) * (start if column % 2 == 0 else 3 - start)


def first_nine_for_row(observed: bytes, width: int, start: int, assignment: Sequence[int], row: int) -> bytes:
    """Recover row's first nine natural bytes from ranks assigned to columns 0..5."""
    rows, chunk = validate_rectangular(len(observed), width, start)
    if len(assignment) != 6 or len(set(assignment)) != 6 or any(not 0 <= x < width for x in assignment):
        raise ValueError("assignment must contain six distinct observed chunk ranks")
    if not 0 <= row < rows:
        raise ValueError("row")
    out = bytearray()
    for column, rank in enumerate(assignment):
        size = cell_size(row, column, start)
        source = rank * chunk + column_offset(row, column, start)
        out.extend(observed[source : source + size])
    if len(out) != 9:
        raise AssertionError("first six cells must contain nine bytes")
    return bytes(out)


def evaluate_prefix(
    observed: bytes,
    width: int,
    start: int,
    assignment: Sequence[int],
    encrypt_block: Callable[[bytes], bytes],
    allowed=A105,
) -> tuple[bool, tuple[int, ...]]:
    """Return necessary-filter result and the computed ninth plaintext bytes."""
    rows, _chunk = validate_rectangular(len(observed), width, start)
    plaintext_ninth = []
    for row in range(rows):
        first9 = first_nine_for_row(observed, width, start, assignment, row)
        value = first9[8] ^ encrypt_block(first9[:8])[0]
        plaintext_ninth.append(value)
        if value not in allowed:
            return False, tuple(plaintext_ninth)
    return True, tuple(plaintext_ninth)


def prefix_count(width: int) -> int:
    return math.factorial(width) // math.factorial(width - 6)


def completion_weight(width: int) -> int:
    return math.factorial(width - 6)

from __future__ import annotations

"""Byte-unit AMSCO geometry. This module is target-agnostic and standard-library only."""

import hashlib
import math
from dataclasses import dataclass
from typing import Iterable, Sequence

ORIENTATION_NAMES = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")


def _validate(n: int, width: int, order: Sequence[int], start: int) -> None:
    if n < 0:
        raise ValueError("negative length")
    if not 2 <= width <= 9:
        raise ValueError("width must be 2..9")
    if tuple(sorted(order)) != tuple(range(width)):
        raise ValueError("order must be a width-element permutation")
    if start not in (1, 2):
        raise ValueError("start must be 1 or 2")


def amsco_forward(data: bytes, width: int, order: Sequence[int], start: int) -> bytes:
    """Forward AMSCO using an independently materialized row/cell matrix."""
    _validate(len(data), width, order, start)
    rows: list[list[bytes]] = []
    offset = 0
    size = start
    while offset < len(data):
        row: list[bytes] = []
        for _column in range(width):
            if offset >= len(data):
                break
            take = min(size, len(data) - offset)
            row.append(data[offset : offset + take])
            offset += take
            size = 3 - size
        rows.append(row)
    out = bytearray()
    for column in order:
        for row in rows:
            if column < len(row):
                out.extend(row[column])
    return bytes(out)


@dataclass(frozen=True)
class InverseLayout:
    n: int
    width: int
    order: tuple[int, ...]
    start: int
    # For each natural cell: (natural output offset, byte length, observed input offset).
    cells: tuple[tuple[int, int, int], ...]

    def prefix(self, observed: bytes, length: int) -> bytes:
        if len(observed) != self.n:
            raise ValueError("observed length does not match layout")
        if not 0 <= length <= self.n:
            raise ValueError("invalid prefix length")
        out = bytearray()
        for natural, size, source in self.cells:
            if natural >= length:
                break
            take = min(size, length - natural)
            out.extend(observed[source : source + take])
        if len(out) != length:
            raise AssertionError("prefix reconstruction length")
        return bytes(out)

    def inverse(self, observed: bytes) -> bytes:
        return self.prefix(observed, self.n)


def inverse_layout(n: int, width: int, order: Sequence[int], start: int) -> InverseLayout:
    """Build an inverse map without calling or sharing forward-map generation."""
    _validate(n, width, order, start)
    # Enumerate only cell metadata in natural order. A final cell is shortened
    # when fewer than its nominal one/two bytes remain.
    metadata: list[tuple[int, int, int]] = []
    natural = 0
    cell_index = 0
    size = start
    column_lengths = [0] * width
    while natural < n:
        take = min(size, n - natural)
        column = cell_index % width
        metadata.append((natural, take, column))
        column_lengths[column] += take
        natural += take
        cell_index += 1
        size = 3 - size

    column_starts = [0] * width
    cursor = 0
    for column in order:
        column_starts[column] = cursor
        cursor += column_lengths[column]
    if cursor != n:
        raise AssertionError("column length partition")

    used = [0] * width
    cells: list[tuple[int, int, int]] = []
    for natural, take, column in metadata:
        source = column_starts[column] + used[column]
        cells.append((natural, take, source))
        used[column] += take
    return InverseLayout(n, width, tuple(order), start, tuple(cells))


def amsco_inverse(observed: bytes, width: int, order: Sequence[int], start: int) -> bytes:
    return inverse_layout(len(observed), width, order, start).inverse(observed)


def orient_bytes(displayed: bytes, name: str) -> bytes:
    if name == "forward":
        return displayed
    if name == "byte_reverse":
        return displayed[::-1]
    if name == "nibble_swap":
        return bytes(((v << 4) | (v >> 4)) & 0xFF for v in displayed)
    if name == "full_hex_reverse":
        return bytes(((v << 4) | (v >> 4)) & 0xFF for v in displayed[::-1])
    raise ValueError("unknown orientation")


def canonical_for_orientation(oriented: bytes, name: str) -> bytes:
    # All four registered transforms are involutions.
    return orient_bytes(oriented, name)


def factorial_grid(widths: Iterable[int] = range(2, 10), starts: Iterable[int] = (1, 2), orientations: int = 4) -> int:
    return sum(math.factorial(w) for w in widths) * len(tuple(starts)) * orientations


def digest_rows(rows: Iterable[bytes]) -> str:
    h = hashlib.sha256()
    for row in rows:
        h.update(len(row).to_bytes(4, "big"))
        h.update(row)
    return h.hexdigest()

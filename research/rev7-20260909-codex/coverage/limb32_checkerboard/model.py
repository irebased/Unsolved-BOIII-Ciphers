#!/usr/bin/env python3
"""ASTRA fixed-width limb decimalization and ordinary checkerboard primitives."""
from itertools import combinations

IDENTITY = "ASTRA"
ORIENTATIONS = ("forward", "full_hex_reverse", "byte_reverse", "nibble_swap")
ENDIANS = ("big", "little")
ORDERS = ("forward", "reverse")
DIRECTIONS = ("forward", "reverse")
REV3_KEY = "FKMCPDYEHBIGQROSAZLUTJNWVX"
REV3_HEADERS = (3, 7)


def orient_hex(text, name):
    if len(text) % 2 or any(c not in "0123456789abcdefABCDEF" for c in text):
        raise ValueError("even hexadecimal text required")
    if name == "forward": out = text
    elif name == "full_hex_reverse": out = text[::-1]
    elif name == "byte_reverse": out = "".join(reversed([text[i:i+2] for i in range(0,len(text),2)]))
    elif name == "nibble_swap": out = "".join(text[i:i+2][::-1] for i in range(0,len(text),2))
    else: raise ValueError(name)
    return out.upper()


def chunk_lengths(n):
    if n < 1: raise ValueError("nonempty bytes required")
    return [4] * (n // 4) + ([n % 4] if n % 4 else [])


def decimal_width(nbytes):
    if nbytes not in (1,2,3,4): raise ValueError(nbytes)
    return len(str(256 ** nbytes - 1))


def serialize(data, endian="big", limb_order="forward", digit_direction="forward"):
    if endian not in ENDIANS or limb_order not in ORDERS or digit_direction not in DIRECTIONS:
        raise ValueError("bad serializer parameter")
    lengths=chunk_lengths(len(data));chunks=[];at=0
    for n in lengths:
        raw=data[at:at+n];at+=n
        chunks.append((raw,n))
    if limb_order == "reverse": chunks.reverse()
    parts=[f"{int.from_bytes(raw,endian):0{decimal_width(n)}d}" for raw,n in chunks]
    digits="".join(parts)
    if digit_direction == "reverse": digits=digits[::-1]
    return digits


def deserialize(digits, nbytes, endian="big", limb_order="forward", digit_direction="forward"):
    if not digits or any(c not in "0123456789" for c in digits): raise ValueError("decimal digits required")
    lengths=chunk_lengths(nbytes)
    if limb_order == "reverse": lengths=list(reversed(lengths))
    if digit_direction == "reverse": digits=digits[::-1]
    widths=[decimal_width(n) for n in lengths]
    if len(digits) != sum(widths): raise ValueError("wrong fixed-width stream length")
    chunks=[];at=0
    for n,w in zip(lengths,widths):
        value=int(digits[at:at+w]);at+=w
        if value >= 256 ** n: raise ValueError("limb value out of range")
        chunks.append(value.to_bytes(n,endian))
    if limb_order == "reverse": chunks.reverse()
    return b"".join(chunks)


def board_codes(headers):
    h=tuple(headers)
    if len(h)!=2 or len(set(h))!=2 or any(not 0<=x<=9 for x in h): raise ValueError("two distinct digit headers required")
    return [str(i) for i in range(10) if i not in h] + [str(h[0])+str(i) for i in range(10)] + [str(h[1])+str(i) for i in range(10)]


def parse_tokens(digits, headers):
    if any(c not in "0123456789" for c in digits): raise ValueError("decimal digits required")
    hs={str(x) for x in headers}; out=[]; i=0
    while i < len(digits):
        n=2 if digits[i] in hs else 1
        if i+n > len(digits): return None
        out.append(digits[i:i+n]); i+=n
    return out


def decode_fixed(digits, headers=REV3_HEADERS, alphabet=REV3_KEY):
    codes=board_codes(headers)
    if len(alphabet)>len(codes) or len(set(alphabet))!=len(alphabet): raise ValueError("injective alphabet required")
    board=dict(zip(codes,alphabet)); tokens=parse_tokens(digits,headers)
    if tokens is None or any(t not in board for t in tokens): return None
    return "".join(board[t] for t in tokens)


def encode_fixed(text, headers=REV3_HEADERS, alphabet=REV3_KEY):
    codes=board_codes(headers); board={ch:code for code,ch in zip(codes,alphabet)}
    try:return "".join(board[ch] for ch in text)
    except KeyError as e: raise ValueError(f"symbol absent from board: {e.args[0]}")


def all_headers(): return list(combinations(range(10),2))

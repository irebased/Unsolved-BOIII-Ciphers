"""Prefix lower bound for a replaced/padded final block; target agnostic."""
from __future__ import annotations

def zero_unpad(x: bytes) -> bytes:
    return x.rstrip(b"\0")

def dcount(x: bytes) -> int:
    return len(set(x))

def thresholds(table: dict) -> dict[int,int]:
    return {r["n"]:r["d"] for r in table["rows"]}

def classify(n: int, d: int, ds: dict[int,int]) -> dict:
    if n < min(ds): return {"status":"short","screen_hit":None,"threshold_d":None}
    if n > max(ds): return {"status":"out-of-range","screen_hit":None,"threshold_d":None}
    t=ds[n]; return {"status":"flagged" if d<=t else "unflagged","screen_hit":d<=t,"threshold_d":t}

def bound(prefix: bytes, padded_length: int, ds: dict[int,int]) -> dict:
    if padded_length < len(prefix): raise ValueError("padded length before prefix")
    q=zero_unpad(prefix); supported=[n for n in range(len(q),padded_length+1) if n in ds]
    return {"prefix_length":len(prefix),"q_length":len(q),"q_distinct":dcount(q),
      "padded_length":padded_length,"possible_output_length_min":len(q),
      "possible_output_length_max":padded_length,
      "supported_length_count":len(supported),
      "maximum_supported_threshold":max((ds[n] for n in supported),default=None),
      "proves_no_screen_hit":bool(supported) and dcount(q)>max(ds[n] for n in supported)}

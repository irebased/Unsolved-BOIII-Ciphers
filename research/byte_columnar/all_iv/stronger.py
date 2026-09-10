#!/usr/bin/env python3
"""Stronger all-IV invariant: any invalid variant-B chunk excludes every order."""
from __future__ import annotations
import hashlib,math,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE))
import core

IDENTITY="ASTRA"

def chunk_witness(observed:bytes,width:int,rank:int)->dict:
    assert width in (13,14) and len(observed)==546 and len(observed)%width==0
    assert 0<=rank<width
    chunk=observed[rank::width]
    suffix=core.iv_independent_suffix(chunk)
    states={0,1,2}
    first_failure=None
    trace=[]
    for suffix_offset,value in enumerate(suffix):
        before=sorted(states)
        states=core.propagate(states,bytes([value]))
        after=sorted(states)
        trace.append({"suffix_offset":suffix_offset,
          "chunk_relative_plaintext_offset":core.BLOCK_SIZE+suffix_offset,
          "plaintext_byte":value,"states_before":before,"states_after":after})
        if not states:
            first_failure=trace[-1]
            break
    rejected=first_failure is not None
    return {"observed_rank":rank,"observed_positions":{
        "start":rank,"stride":width,"count":len(chunk)},
      "ciphertext_chunk_hex":chunk.hex(),"ciphertext_chunk_sha256":hashlib.sha256(chunk).hexdigest(),
      "iv_independent_plaintext_suffix_hex":suffix.hex(),
      "iv_independent_plaintext_suffix_sha256":hashlib.sha256(suffix).hexdigest(),
      "suffix_bytes":len(suffix),"starting_state_set":[0,1,2],
      "end_state_set":[] if rejected else sorted(states),
      "first_failure":first_failure,"chunk_rejected":rejected}

def evaluate_any_bad(observed:bytes,width:int)->dict:
    witnesses=[chunk_witness(observed,width,rank) for rank in range(width)]
    rejected=[x["observed_rank"] for x in witnesses if x["chunk_rejected"]]
    original=core.evaluate(observed,width)
    complete=bool(rejected)
    return {"identity":IDENTITY,"width":width,"rows":len(observed)//width,
      "variant":"B","chunk_witnesses":witnesses,"rejected_chunk_ranks":rejected,
      "retained_chunk_ranks":[x["observed_rank"] for x in witnesses if not x["chunk_rejected"]],
      "original_first_column_rejected_weight":original["rejected_completion_weight"],
      "original_first_column_expected_weight":original["expected_completion_weight"],
      "stronger_certificate_weight":math.factorial(width) if complete else 0,
      "expected_completion_weight":math.factorial(width),
      "complete_every_iv_every_order_exclusion":complete,
      "claim":"Every observed rank is one unavoidable contiguous natural ciphertext chunk under rectangular variant B; one chunk invalid from every reachable FSA boundary state excludes every order and external IV."}

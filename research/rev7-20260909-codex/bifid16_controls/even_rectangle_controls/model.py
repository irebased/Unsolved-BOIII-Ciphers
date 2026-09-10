#!/usr/bin/env python3
"""Empty 4x4 rectangle necessary-condition model on directed 16-symbol pair graphs."""
from __future__ import annotations
import itertools
IDENTITY="ASTRA";SYMBOLS=tuple(range(16));FOURSETS=tuple(itertools.combinations(SYMBOLS,4));assert len(FOURSETS)==1820
FULL=(1<<16)-1
def graph_masks(edges):
 rows=[0]*16
 for a,b in edges:
  if not 0<=a<16 or not 0<=b<16:raise ValueError((a,b))
  rows[a]|=1<<b
 return tuple(rows)
def analyze(edges):
 rows=graph_masks(edges);records=[];best=None
 for aset in FOURSETS:
  missing=FULL
  for a in aset:missing&=FULL^rows[a]
  count=bin(missing).count("1");record={"row_set":list(aset),"common_missing_columns_mask":f"{missing:04x}","common_missing_count":count};records.append(record)
  if best is None or count>best[0]:best=(count,aset,missing)
 assert best is not None
 witness=None
 if best[0]>=4:
  cols=[x for x in SYMBOLS if best[2]>>x&1][:4];witness={"row_set":list(best[1]),"column_set":cols,"all_16_directed_edges_absent":all(not (rows[a]>>b&1) for a in best[1] for b in cols)}
 return {"directed_edge_count":sum(bin(x).count("1") for x in rows),"adjacency_masks":[f"{x:04x}" for x in rows],"row_sets_examined":len(records),"row_set_records":records,"max_common_missing_count":best[0],"empty_4x4_rectangle_exists_relaxed":best[0]>=4,"witness":witness,"excluded_bag213":best[0]<4}

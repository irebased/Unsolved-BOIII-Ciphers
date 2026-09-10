#!/usr/bin/env python3
"""ASTRA exact equal-cell column geometry and collapsed-repeat statistic."""
from __future__ import annotations
import hashlib,itertools
CELL=4; COLS=7; ROWS=39; LENGTH=CELL*COLS*ROWS; SUPPORT_GAP=114; MIN_REPEAT=4
ZOMBIES_ORDER=(3,5,4,2,1,6,0)
def sha_text(s:str)->str:return hashlib.sha256(s.encode('ascii')).hexdigest()
def validate_order(order):
 order=tuple(order)
 if len(order)!=COLS or sorted(order)!=list(range(COLS)):raise ValueError('order must be a permutation of 0..6')
 return order
def decode_equal(observed:str,order)->str:
 order=validate_order(order)
 if len(observed)!=LENGTH:raise ValueError('expected 1092 symbols')
 span=ROWS*CELL; cols=['']*COLS
 for rank,col in enumerate(order):cols[col]=observed[rank*span:(rank+1)*span]
 return ''.join(cols[col][row*CELL:(row+1)*CELL] for row in range(ROWS) for col in range(COLS))
def encode_equal(natural:str,order)->str:
 order=validate_order(order)
 if len(natural)!=LENGTH:raise ValueError('expected 1092 symbols')
 cols=[''.join(natural[(row*COLS+col)*CELL:(row*COLS+col+1)*CELL] for row in range(ROWS)) for col in range(COLS)]
 return ''.join(cols[col] for col in order)
def decode_indices(order):
 order=validate_order(order);span=ROWS*CELL;starts=[0]*COLS
 for rank,col in enumerate(order):starts[col]=rank*span
 return [starts[col]+row*CELL+k for row in range(ROWS) for col in range(COLS) for k in range(CELL)]
def maximal_pairs_fast(s:str,min_length:int=MIN_REPEAT):
 if min_length<1:raise ValueError('min_length')
 seeds={}
 for i in range(len(s)-min_length+1):seeds.setdefault(s[i:i+min_length],[]).append(i)
 out=[]
 for starts in seeds.values():
  for ai in range(len(starts)):
   i=starts[ai]
   for j in starts[ai+1:]:
    if i and s[i-1]==s[j-1]:continue
    n=min_length
    while j+n<len(s) and s[i+n]==s[j+n]:n+=1
    out.append({'start_a':i,'start_b':j,'gap':j-i,'length':n,'text':s[i:i+n]})
 return sorted(out,key=lambda x:(x['start_a'],x['start_b'],x['length'],x['text']))
def qualifying(s:str):
 return [r for r in maximal_pairs_fast(s) if r['gap']%SUPPORT_GAP==0]
def score(witnesses):
 return (max((r['length'] for r in witnesses),default=0),len(witnesses))
def all_orders():return itertools.permutations(range(COLS))

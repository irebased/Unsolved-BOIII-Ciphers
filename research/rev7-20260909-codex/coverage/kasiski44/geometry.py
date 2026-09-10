#!/usr/bin/env python3
"""Exact rectangular equal-cut column geometry for key ZOMBIES."""
from __future__ import annotations
KEY='ZOMBIES';CELL=4;COLS=len(KEY);ORDER=tuple(sorted(range(COLS),key=lambda i:(KEY[i],i)))
assert ORDER==(3,5,4,2,1,6,0)
def encode(text:str)->str:
 if len(text)%(CELL*COLS):raise ValueError('requires complete 4-symbol cells and rectangular rows')
 rows=len(text)//(CELL*COLS);return ''.join(text[(r*COLS+c)*CELL:(r*COLS+c+1)*CELL] for c in ORDER for r in range(rows))
def decode(cipher:str)->str:
 if len(cipher)%(CELL*COLS):raise ValueError('requires complete 4-symbol cells and rectangular rows')
 rows=len(cipher)//(CELL*COLS);chunks=[cipher[i:i+CELL] for i in range(0,len(cipher),CELL)];out=['']*(rows*COLS)
 k=0
 for c in ORDER:
  for r in range(rows):out[r*COLS+c]=chunks[k];k+=1
 return ''.join(out)
def encode_indices(n:int):
 if n%(CELL*COLS):raise ValueError('rectangle')
 rows=n//(CELL*COLS);return tuple((r*COLS+c)*CELL+d for c in ORDER for r in range(rows) for d in range(CELL))
def decode_indices(n:int):
 e=encode_indices(n);inv=[0]*n
 for output_i,natural_i in enumerate(e):inv[natural_i]=output_i
 return tuple(inv)

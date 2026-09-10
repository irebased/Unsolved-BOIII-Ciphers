#!/usr/bin/env python3
"""Concrete and SMT formulations of the declared 4x4 Bifid model."""
from __future__ import annotations
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
sys.path.insert(0,str(HERE/"dependency/runtime"))
import z3
IDENTITY="ASTRA"
ASCII=frozenset([9,10,13,*range(32,127)])
THIRD=frozenset([0x93,0x94,0x98,0x99,0xA6])
def endpoint_accepts(data:bytes)->bool:
 state=0
 for b in data:
  if state==0:
   if b in ASCII:state=0
   elif b==0xE2:state=1
   else:return False
  elif state==1:
   if b==0x80:state=2
   else:return False
  else:
   if b in THIRD:state=0
   else:return False
 return state==0
def check_square(square):
 if len(square)!=16 or sorted(square)!=list(range(16)):raise ValueError("square must be permutation 0..15")
def encrypt_symbols(plain,square,period):
 check_square(square)
 if period<=0:raise ValueError("period")
 pos=[0]*16
 for i,s in enumerate(square):pos[s]=i
 out=[]
 for start in range(0,len(plain),period):
  block=plain[start:start+period];rows=[pos[s]//4 for s in block];cols=[pos[s]%4 for s in block];stream=rows+cols
  out.extend(square[4*stream[i]+stream[i+1]] for i in range(0,len(stream),2))
 return out
def decrypt_symbols(cipher,square,period):
 check_square(square)
 if period<=0:raise ValueError("period")
 pos=[0]*16
 for i,s in enumerate(square):pos[s]=i
 out=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];flat=[]
  for s in block:flat.extend((pos[s]//4,pos[s]%4))
  L=len(block)
  out.extend(square[4*flat[i]+flat[L+i]] for i in range(L))
 return out
def bytes_to_symbols(data):return [v for b in data for v in (b>>4,b&15)]
def symbols_to_bytes(symbols):
 if len(symbols)%2:raise ValueError("odd symbol count")
 return bytes(16*symbols[i]+symbols[i+1] for i in range(0,len(symbols),2))
def encrypt_bytes(data,square,period):return symbols_to_bytes(encrypt_symbols(bytes_to_symbols(data),square,period))
def decrypt_bytes(data,square,period):return symbols_to_bytes(decrypt_symbols(bytes_to_symbols(data),square,period))
def inverse_symbol(k,target):
 expr=z3.IntVal(15)
 for symbol in reversed(range(15)):expr=z3.If(k[symbol]==target,z3.IntVal(symbol),expr)
 return expr
def build_solver(ciphertext:bytes,period:int,fixed=None,endpoint=True,timeout_ms=None):
 if period<=0:raise ValueError("period")
 cipher=bytes_to_symbols(ciphertext);k=[z3.Int(f"k_{s:X}") for s in range(16)];solver=z3.Solver()
 if timeout_ms is not None:solver.set(timeout=timeout_ms)
 solver.add(*[z3.And(x>=0,x<16) for x in k]);solver.add(z3.Distinct(k))
 for symbol,position in (fixed or {}).items():solver.add(k[symbol]==position)
 plain=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];flat=[]
  for symbol in block:flat.extend((k[symbol]/4,k[symbol]%4))
  L=len(block)
  for i in range(L):plain.append(inverse_symbol(k,4*flat[i]+flat[L+i]))
 if len(plain)%2:raise ValueError("odd plaintext symbol count")
 states=[z3.Int(f"state_{i}") for i in range(len(plain)//2+1)];solver.add(states[0]==0)
 bytes_expr=[]
 for i in range(0,len(plain),2):
  b=16*plain[i]+plain[i+1];bytes_expr.append(b);s=states[i//2];n=states[i//2+1]
  if endpoint:
   solver.add(z3.Or(z3.And(s==0,z3.Or(*[b==x for x in sorted(ASCII)]),n==0),z3.And(s==0,b==0xE2,n==1),z3.And(s==1,b==0x80,n==2),z3.And(s==2,z3.Or(*[b==x for x in sorted(THIRD)]),n==0)))
 if endpoint:solver.add(states[-1]==0)
 return solver,k,plain,bytes_expr,states
def square_from_model(model,k):
 square=[None]*16
 for symbol,var in enumerate(k):square[model.eval(var).as_long()]=symbol
 check_square(square);return square
def plaintext_from_model(model,plain):return symbols_to_bytes([model.eval(x).as_long() for x in plain])

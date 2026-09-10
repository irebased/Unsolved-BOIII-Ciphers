#!/usr/bin/env python3
"""QF_BV relaxation of the arbitrary-square Bifid model."""
from pathlib import Path
import sys
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE/"dependency/runtime"));import z3
import bifid16 as concrete
def inverse(k,target):
 out=z3.BitVecVal(15,4)
 for s in reversed(range(15)):out=z3.If(k[s]==target,z3.BitVecVal(s,4),out)
 return out
def allowed(byte,bag):
 ascii_ok=z3.Or(byte==9,byte==10,byte==13,z3.And(z3.UGE(byte,32),z3.ULE(byte,126)))
 continuation=z3.And(z3.UGE(byte,0x80),z3.ULE(byte,0xBF))
 if bag==165:return z3.Or(ascii_ok,continuation,byte==0xC2,byte==0xC3,byte==0xE2)
 if bag==213:return z3.Or(ascii_ok,continuation,z3.And(z3.UGE(byte,0xC2),z3.ULE(byte,0xF4)))
 raise ValueError(bag)
def build(ciphertext,period,bag,prefix_bytes=None,fixed=None,timeout_ms=10000):
 if period<=0:raise ValueError(period)
 symbols=concrete.bytes_to_symbols(ciphertext);k=[z3.BitVec(f"k_{s:X}",4) for s in range(16)];solver=z3.SolverFor("QF_BV");solver.set(timeout=timeout_ms);solver.add(z3.Distinct(k))
 for s,p in (fixed or {}).items():solver.add(k[s]==z3.BitVecVal(p,4))
 plain=[]
 for start in range(0,len(symbols),period):
  block=symbols[start:start+period];flat=[]
  for sym in block:flat.extend((z3.Extract(3,2,k[sym]),z3.Extract(1,0,k[sym])))
  L=len(block)
  for i in range(L):plain.append(inverse(k,z3.Concat(flat[i],flat[L+i])))
 if len(plain)%2:raise ValueError("odd symbols")
 bytes_expr=[z3.Concat(plain[i],plain[i+1]) for i in range(0,len(plain),2)];limit=len(bytes_expr) if prefix_bytes is None else min(prefix_bytes,len(bytes_expr));solver.add(*[allowed(x,bag) for x in bytes_expr[:limit]])
 return solver,k,plain,bytes_expr,limit
def square(model,k):
 out=[None]*16
 for s,v in enumerate(k):out[model.eval(v).as_long()]=s
 concrete.check_square(out);return out
def plaintext(model,plain):return concrete.symbols_to_bytes([model.eval(x).as_long() for x in plain])

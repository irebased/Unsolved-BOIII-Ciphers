#!/usr/bin/env python3
"""QF_BV coordinate-avoidance model for typed odd-block Bifid high nibbles."""
from __future__ import annotations
import sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
PKG=HERE.parent
sys.path.insert(0,str(PKG/'dependency/runtime'))
import z3
IDENTITY='ASTRA'; TYPES=('RR','RC','CR','CC')
def axis(value,kind,axis_bits,total_bits):
 if kind=='R': return z3.Extract(total_bits-1,axis_bits,value)
 if kind=='C': return z3.Extract(axis_bits-1,0,value)
 raise ValueError(kind)
def normalize_edges(edges,symbols):
 out=[]
 for edge in edges:
  if isinstance(edge,dict): a,b,kind=edge['a'],edge['b'],edge['type']
  else: a,b,kind=edge
  a=int(a);b=int(b);kind=str(kind)
  if not(0<=a<symbols and 0<=b<symbols and kind in TYPES): raise ValueError((a,b,kind))
  out.append((a,b,kind))
 return tuple(out)
def build(side,edges,one_square=False,prefix='m',fixed_mapping=None):
 if side not in (2,4): raise ValueError('controls support side 2 or 4')
 axis_bits={2:1,4:2}[side];total_bits=2*axis_bits;symbols=side*side;edges=normalize_edges(edges,symbols)
 k=[z3.BitVec(f'{prefix}_k_{s}',total_bits) for s in range(symbols)];t=z3.BitVec(f'{prefix}_t',total_bits)
 solver=z3.SolverFor('QF_BV');solver.add(z3.Distinct(k))
 if fixed_mapping is not None:
  if sorted(fixed_mapping)!=list(range(symbols)):raise ValueError('fixed mapping is not a permutation')
  for x,v in zip(k,fixed_mapping):solver.add(x==z3.BitVecVal(v,total_bits))
 if one_square: solver.add(t==k[1])
 for a,b,kind in edges:
  coord=z3.Concat(axis(k[a],kind[0],axis_bits,total_bits),axis(k[b],kind[1],axis_bits,total_bits))
  solver.add(coord!=t)
 return solver,k,t,edges
def satisfies(side,edges,mapping,t,one_square=False):
 symbols=side*side
 if sorted(mapping)!=list(range(symbols)) or not 0<=t<symbols:return False
 if one_square and t!=mapping[1]:return False
 def ax(v,c):return v//side if c=='R' else v%side
 return all(side*ax(mapping[a],kind[0])+ax(mapping[b],kind[1])!=t for a,b,kind in normalize_edges(edges,symbols))
def enumerate_solutions(side,edges,one_square=False,limit=None,prefix='e'):
 solver,k,t,_=build(side,edges,one_square,prefix);smt=solver.to_smt2();solutions=[];complete=False;terminal_status=None;reason_unknown=None
 while True:
  check=solver.check()
  if check==z3.unsat:complete=True;terminal_status='unsat';break
  if check==z3.unknown:terminal_status='unknown';reason_unknown=solver.reason_unknown();break
  assert check==z3.sat
  m=solver.model();row=(tuple(m.eval(x,model_completion=True).as_long() for x in k),m.eval(t,model_completion=True).as_long());solutions.append(row)
  solver.add(z3.Or(*[x!=z3.BitVecVal(v,x.size()) for x,v in zip(k,row[0])],t!=z3.BitVecVal(row[1],t.size())))
  if limit is not None and len(solutions)>=limit:terminal_status='limit';break
 solutions.sort()
 return {'status':'sat' if solutions else terminal_status,'terminal_status':terminal_status,'reason_unknown':reason_unknown,'complete_enumeration':complete,'solutions':solutions,'smt2':smt}
def solve(side,edges,one_square=False,timeout_ms=10000,prefix='s',fixed_mapping=None):
 solver,k,t,norm=build(side,edges,one_square,prefix,fixed_mapping);solver.set(timeout=timeout_ms);smt=solver.to_smt2();status=solver.check();witness=None
 if status==z3.sat:
  m=solver.model();witness={'mapping':[m.eval(x,model_completion=True).as_long() for x in k],'forbidden_coordinate':m.eval(t,model_completion=True).as_long()}
  assert satisfies(side,norm,witness['mapping'],witness['forbidden_coordinate'],one_square)
 return {'status':str(status),'witness':witness,'edge_count':len(norm),'constraint_count':len(solver.assertions()),'smt2':smt,'one_square':one_square,'side':side,'z3_version':z3.get_version_string()}

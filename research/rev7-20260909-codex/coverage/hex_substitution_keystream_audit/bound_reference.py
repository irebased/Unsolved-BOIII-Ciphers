#!/usr/bin/env python3
"""ASTRA target-free checks for relaxations of a global symbol bijection."""
from itertools import permutations
import hashlib,json,random

def exact_score(symbol_pairs,ks,perm,m,allowed):
 return sum((((perm[a]*m+perm[b]) ^ k) in allowed) for (a,b),k in zip(symbol_pairs,ks))

def pair_class_upper(symbol_pairs,ks,m,allowed):
 groups={}
 for ab,k in zip(symbol_pairs,ks): groups.setdefault(ab,[]).append(k)
 total=0
 for (a,b),vv in groups.items():
  best=0
  for x in range(m):
   for y in range(m):
    if (a==b)!=(x==y): continue
    best=max(best,sum((((x*m+y)^k) in allowed) for k in vv))
  total+=best
 return total

def high_assignment_weights(symbol_pairs,ks,m,allowed):
 # Per-high-symbol assignment; the low image is independently optimistic per occurrence.
 w=[[0]*m for _ in range(m)]
 for s in range(m):
  for x in range(m):
   for (a,b),k in zip(symbol_pairs,ks):
    if a!=s: continue
    ys=[x] if a==b else [y for y in range(m) if y!=x]
    w[s][x]+=any((((x*m+y)^k) in allowed) for y in ys)
 return w

def high_assignment_upper(symbol_pairs,ks,m,allowed):
 w=high_assignment_weights(symbol_pairs,ks,m,allowed)
 return max(sum(w[s][p[s]] for s in range(m)) for p in permutations(range(m)))

def high_independent_upper(symbol_pairs,ks,m,allowed):
 w=high_assignment_weights(symbol_pairs,ks,m,allowed)
 return sum(max(row) for row in w)

def run():
 rng=random.Random(676); rows=[]
 for case in range(64):
  m=4;n=7+case%17
  pairs=[(rng.randrange(m),rng.randrange(m)) for _ in range(n)]
  ks=[rng.randrange(m*m) for _ in range(n)]
  allowed={v for v in range(m*m) if rng.randrange(3)!=0}
  scores=[exact_score(pairs,ks,p,m,allowed) for p in permutations(range(m))]
  exact=max(scores);pc=pair_class_upper(pairs,ks,m,allowed);hi=high_assignment_upper(pairs,ks,m,allowed);hir=high_independent_upper(pairs,ks,m,allowed)
  assert exact<=pc<=n and exact<=hi<=hir<=n
  rows.append({'case':case,'n':n,'exact':exact,'pair_class_upper':pc,'high_assignment_upper':hi,'high_independent_upper':hir})
 out={'identity':'ASTRA','target_evaluated':False,'status':'PASS','cases':len(rows),'assertion':'exact maximum <= each independently relaxed upper bound','rows':rows}
 print(json.dumps(out,sort_keys=True,separators=(',',':')))
if __name__=='__main__':run()

#!/usr/bin/env python3
"""Deterministic bounded monoalphabetic annealer for checkerboard token streams."""
from __future__ import annotations
import hashlib,math,random
ALPHABET='ABCDEFGHIJKLMNOPQRSTUVWXYZ .'
def pack4(a,b,c,d):return ((a*28+b)*28+c)*28+d
def compile_model(obj):
 idx={c:i for i,c in enumerate(ALPHABET)};den=obj['tetragrams']+28**4;default=math.log(1/den)
 table={pack4(*(idx[c] for c in g)):math.log((n+1)/den) for g,n in obj['counts'].items()}
 freq=[obj['unigrams'].get(c,0) for c in ALPHABET]
 return table,default,freq
def tokenize(tokens):
 labels=sorted(set(tokens));ix={x:i for i,x in enumerate(labels)};return [ix[x] for x in tokens],labels
def decoded(seq,mapping):return ''.join(ALPHABET[mapping[x]] for x in seq)
def score_seq(seq,mapping,table,default):
 return sum(table.get(pack4(mapping[seq[i]],mapping[seq[i+1]],mapping[seq[i+2]],mapping[seq[i+3]]),default) for i in range(len(seq)-3))
def anneal(tokens,model,restarts=6,steps=8000,seed=20260910):
 seq,labels=tokenize(tokens);k=len(labels)
 if k>28:raise ValueError('more than 28 token classes')
 table,default,freq=compile_model(model);positions=[]
 for x in range(k):
  s=set()
  for i,v in enumerate(seq):
   if v==x:s.update(range(max(0,i-3),min(i,len(seq)-4)+1))
  positions.append(s)
 pair_starts={(a,b):sorted(positions[a] | (positions[b] if b<k else set())) for a in range(k) for b in range(a+1,28)}
 corder=sorted(range(k),key=lambda x:(-seq.count(x),x));porder=sorted(range(28),key=lambda x:(-freq[x],x))
 best=None;rows=[]
 for restart in range(restarts):
  rng=random.Random(seed+restart);mapping=list(range(28))
  if restart==0:
   used=set()
   for c,p in zip(corder,porder):mapping[c]=p;used.add(p)
   rest=[p for p in range(28) if p not in used]
   for c,p in zip([x for x in range(28) if x>=k],rest):mapping[c]=p
   # repair to a permutation if unused cipher slots overlap frequency-assigned values
   assigned=mapping[:k];mapping[k:]=[p for p in range(28) if p not in assigned]
  else:rng.shuffle(mapping)
  cur=score_seq(seq,mapping,table,default);local_best=(cur,mapping.copy())
  for step in range(steps):
   a=rng.randrange(28);b=rng.randrange(27);b+=b>=a
   if a>b:a,b=b,a
   starts=pair_starts[(a,b)] if a<k else (pair_starts[(b,a)] if b<k else [])
   old=0.0
   for i in starts:old+=table.get(pack4(mapping[seq[i]],mapping[seq[i+1]],mapping[seq[i+2]],mapping[seq[i+3]]),default)
   mapping[a],mapping[b]=mapping[b],mapping[a]
   new=0.0
   for i in starts:new+=table.get(pack4(mapping[seq[i]],mapping[seq[i+1]],mapping[seq[i+2]],mapping[seq[i+3]]),default)
   delta=new-old;t=15.0*(0.01**(step/max(1,steps-1)))
   if delta>=0 or rng.random()<math.exp(delta/t):cur+=delta
   else:mapping[a],mapping[b]=mapping[b],mapping[a]
   if cur>local_best[0]:local_best=(cur,mapping.copy())
  row={'restart':restart,'seed':seed+restart,'score':local_best[0],'mapping':{labels[i]:ALPHABET[local_best[1][i]] for i in range(k)},'plaintext':decoded(seq,local_best[1])}
  row['plaintext_sha256']=hashlib.sha256(row['plaintext'].encode()).hexdigest();rows.append(row)
  if best is None or row['score']>best['score']:best=row
 return {'token_classes':k,'restarts':restarts,'steps_per_restart':steps,'best':best,'restarts_retained':rows}

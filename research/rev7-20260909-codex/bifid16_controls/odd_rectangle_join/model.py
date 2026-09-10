#!/usr/bin/env python3
"""Exact coupled typed-rectangle join for the odd Bifid coordinate-avoidance model."""
from __future__ import annotations
import hashlib,itertools,json,math
IDENTITY='ASTRA';TYPES=('RC','CR','RR','CC')
def canon_set(x):return tuple(sorted(int(v) for v in x))
def edge_masks(edges,symbols):
 rows=[0]*symbols
 for a,b in edges:
  if not(0<=a<symbols and 0<=b<symbols):raise ValueError((a,b))
  rows[a]|=1<<b
 return tuple(rows)
def absent(rows,left,right):return all(not(rows[a]>>b&1) for a in left for b in right)
def iter_cross_candidates(rows,side):
 symbols=side*side;full=(1<<symbols)-1
 for left in itertools.combinations(range(symbols),side):
  missing=full
  for a in left:missing&=full^rows[a]
  avail=[b for b in range(symbols) if missing>>b&1]
  if len(avail)<side:continue
  for right in itertools.combinations(avail,side):
   if len(set(left)&set(right))==1:yield left,right
def cross_candidates(rows,side,limit=None):
 out=[]
 for item in iter_cross_candidates(rows,side):
  if limit is not None and len(out)>=limit:return out,False
  out.append(item)
 return out,True
def cross_candidate_count(rows,side):return sum(1 for _ in iter_cross_candidates(rows,side))
def geometry(A,B,C,D):
 if A==D and C==B:return 'diagonal'
 if set(A).isdisjoint(D) and set(C).isdisjoint(B) and all(len(set(x)&set(y))==1 for x,y in ((A,C),(A,B),(D,C),(D,B))):return 'off_diagonal'
 return None
def complete_square(A,B,C,D,side):
 A,B,C,D=map(canon_set,(A,B,C,D));kind=geometry(A,B,C,D);assert kind
 symbols=set(range(side*side));rows=[None]*side;cols=[None]*side
 rows[0]=set(A);cols[0]=set(C)
 if kind=='diagonal':
  assert A==D and C==B
  ar=sorted(set(A)-set(C));cr=sorted(set(C)-set(A));assert len(ar)==len(cr)==side-1
  for j,x in enumerate(ar,1):
   if cols[j] is None:cols[j]=set()
   cols[j].add(x)
  for i,x in enumerate(cr,1):
   if rows[i] is None:rows[i]=set()
   rows[i].add(x)
  outside=sorted(symbols-set(A)-set(C))
  assert len(outside)==(side-1)**2
  q=0
  for i in range(1,side):
   for j in range(1,side):rows[i].add(outside[q]);cols[j].add(outside[q]);q+=1
  t=0
 else:
  rows[1]=set(D);cols[1]=set(B)
  for i,row in ((0,set(A)),(1,set(D))):
   rem=sorted(row-set(C)-set(B));assert len(rem)==side-2
   for j,x in enumerate(rem,2):
    if cols[j] is None:cols[j]=set()
    cols[j].add(x)
  for j,col in ((0,set(C)),(1,set(B))):
   rem=sorted(col-set(A)-set(D));assert len(rem)==side-2
   for i,x in enumerate(rem,2):
    if rows[i] is None:rows[i]=set()
    rows[i].add(x)
  outside=sorted(symbols-set(A)-set(D)-set(C)-set(B));assert len(outside)==(side-2)**2
  q=0
  for i in range(2,side):
   for j in range(2,side):rows[i].add(outside[q]);cols[j].add(outside[q]);q+=1
  t=1
 assert all(len(x)==side for x in rows+cols)
 assert set().union(*rows)==symbols and set().union(*cols)==symbols
 assert all(len(rows[i]&cols[j])==1 for i in range(side) for j in range(side))
 mapping=[None]*(side*side)
 for i in range(side):
  for j in range(side):mapping[next(iter(rows[i]&cols[j]))]=side*i+j
 assert sorted(mapping)==list(range(side*side))
 return {'mapping':mapping,'forbidden_coordinate':t,'orbit':kind,'rows':[sorted(x) for x in rows],'columns':[sorted(x) for x in cols]}
def validate_witness(graphs,witness,side):
 mapping=witness['mapping'];t=witness['forbidden_coordinate'];assert sorted(mapping)==list(range(side*side));u,v=divmod(t,side)
 rows=[{s for s,p in enumerate(mapping) if p//side==r} for r in range(side)];cols=[{s for s,p in enumerate(mapping) if p%side==c} for c in range(side)]
 A,D,C,B=rows[u],rows[v],cols[u],cols[v]
 sets={'RC':(A,B),'CR':(C,D),'RR':(A,D),'CC':(C,B)}
 return all((a,b) not in graphs.get(kind,set()) for kind,(left,right) in sets.items() for a in left for b in right)
def analyze(graphs,side=4,max_join_pairs=None,max_cross_candidates=None):
 if side not in (2,4):raise ValueError(side)
 symbols=side*side;graphs={k:{(int(a),int(b)) for a,b in graphs.get(k,())} for k in TYPES};masks={k:edge_masks(graphs[k],symbols) for k in TYPES}
 candidate_limit=max_cross_candidates if max_cross_candidates is not None else max_join_pairs
 rc,rc_complete=cross_candidates(masks['RC'],side,candidate_limit)
 if not rc_complete:return {'status':'incomplete','complete':False,'phase':'RC_candidate_generation','side':side,'candidate_counts':{'RC_lower_bound':len(rc)+1,'CR':None,'join_space':None,'joins_examined':0},'witness':None,'limit':{'join_pairs':max_join_pairs,'cross_candidates':candidate_limit}}
 if not rc:
  cr_count=cross_candidate_count(masks['CR'],side);empty=hashlib.sha256().hexdigest()
  return {'status':'unsat','complete':True,'side':side,'candidate_counts':{'RC':0,'CR':cr_count,'join_space':0,'joins_examined':0},'obstruction_counts':{},'all_pairs_obstruction_digest':empty,'witness':None,'limit':{'join_pairs':max_join_pairs,'cross_candidates':candidate_limit}}
 cr,cr_complete=cross_candidates(masks['CR'],side,candidate_limit)
 if not cr_complete:return {'status':'incomplete','complete':False,'phase':'CR_candidate_generation','side':side,'candidate_counts':{'RC':len(rc),'CR_lower_bound':len(cr)+1,'join_space':None,'joins_examined':0},'witness':None,'limit':{'join_pairs':max_join_pairs,'cross_candidates':candidate_limit}}
 space=len(rc)*len(cr);digest=hashlib.sha256();reasons={};examined=0
 for i,(A,B) in enumerate(rc):
  for j,(C,D) in enumerate(cr):
   if max_join_pairs is not None and examined>=max_join_pairs:
    return {'status':'incomplete','complete':False,'side':side,'candidate_counts':{'RC':len(rc),'CR':len(cr),'join_space':space,'joins_examined':examined},'obstruction_counts':reasons,'partial_obstruction_digest':digest.hexdigest(),'witness':None,'limit':{'join_pairs':max_join_pairs,'cross_candidates':candidate_limit}}
   examined+=1;kind=geometry(A,B,C,D)
   if kind is None:reason='geometry'
   elif not absent(masks['RR'],A,D):reason='RR_edge'
   elif not absent(masks['CC'],C,B):reason='CC_edge'
   else:
    witness=complete_square(A,B,C,D,side);assert validate_witness(graphs,witness,side)
    return {'status':'sat','complete':False,'side':side,'candidate_counts':{'RC':len(rc),'CR':len(cr),'join_space':space,'joins_examined':examined},'obstruction_counts':reasons,'partial_obstruction_digest':digest.hexdigest(),'witness':witness,'selected':{'A':list(A),'B':list(B),'C':list(C),'D':list(D)},'limit':{'join_pairs':max_join_pairs,'cross_candidates':candidate_limit}}
   reasons[reason]=reasons.get(reason,0)+1;digest.update(json.dumps([i,j,reason],separators=(',',':')).encode()+b'\n')
 assert examined==space and sum(reasons.values())==space
 return {'status':'unsat','complete':True,'side':side,'candidate_counts':{'RC':len(rc),'CR':len(cr),'join_space':space,'joins_examined':examined},'obstruction_counts':reasons,'all_pairs_obstruction_digest':digest.hexdigest(),'witness':None,'limit':{'join_pairs':max_join_pairs,'cross_candidates':candidate_limit}}

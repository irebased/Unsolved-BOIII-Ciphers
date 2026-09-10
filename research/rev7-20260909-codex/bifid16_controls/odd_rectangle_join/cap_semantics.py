#!/usr/bin/env python3
"""ASTRA independent control of candidate and join cap return paths."""
import hashlib,json
from pathlib import Path
import model
HERE=Path(__file__).resolve().parent
assert hashlib.sha256((HERE/'model.py').read_bytes()).hexdigest()=='221ea25d48f80a26476e1fe4abea0e89e099bf35f4325ed8e8f7aef6bd00be45'
A={0,1};B={0,2};g={k:set() for k in ('RC','CR','RR','CC')}
g['RC']={(a,b) for a in range(4) for b in range(4) if not(a in A and b in B)}
# The only RC rectangle is A x B. A compatible diagonal choice is C=B,D=A.
unbounded=model.analyze(g,side=2)
assert unbounded['status']=='sat'
crcap=model.analyze(g,side=2,max_cross_candidates=1,max_join_pairs=1)
assert crcap['status']=='incomplete' and crcap['phase']=='CR_candidate_generation' and crcap['candidate_counts']['RC']==1 and crcap['candidate_counts']['CR_lower_bound']==2 and crcap['candidate_counts']['joins_examined']==0 and crcap['witness'] is None
joincap=model.analyze(g,side=2,max_cross_candidates=24,max_join_pairs=1)
assert joincap['status']=='incomplete' and joincap['candidate_counts']['RC']==1 and joincap['candidate_counts']['CR']==24 and joincap['candidate_counts']['join_space']==24 and joincap['candidate_counts']['joins_examined']==1 and joincap['witness'] is None
# Directly verify the unbounded witness's coordinate inequalities.
w=unbounded['witness'];mapping=w['mapping'];t=w['forbidden_coordinate']
for kind,edges in g.items():
 for a,b in edges:
  x=mapping[a]//2 if kind[0]=='R' else mapping[a]%2
  y=mapping[b]//2 if kind[1]=='R' else mapping[b]%2
  assert 2*x+y!=t
print(json.dumps({'identity':'ASTRA','target_evaluated':False,'ok':True,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'uncapped':unbounded,'CR_candidate_cap':crcap,'join_cap':joincap},sort_keys=True,indent=2))

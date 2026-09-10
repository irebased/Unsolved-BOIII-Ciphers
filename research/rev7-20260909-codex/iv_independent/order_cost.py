#!/usr/bin/env python3
import hashlib,json,math
from functools import lru_cache
from pathlib import Path
HERE=Path(__file__).resolve().parent; R=HERE.parents[0]; geom=HERE/'geometry.json'; solver=HERE/'solver/solver.py'; G_SHA='1069eef993bfe27ca6fe8f7aa34395da744d35fd986979267da6a1996b39ac07'; S_SHA='23b8755b61276f9a3fc30b1ab385dd7296cffd95407eed9663f505553f949343'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(geom)==G_SHA and sha(solver)==S_SHA
mdx=R.parents[1]/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'; MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91'; assert sha(mdx)==MDX_SHA
t=mdx.read_text(); a=t.index('`83 B57B2')+1; b=t.index('`',a); raw=''.join(t[a:b].split()).upper(); assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
pairs=[raw[i:i+2] for i in range(0,len(raw),2)]; ORIENTS={'forward':raw,'reverse':raw[::-1],'byte_reverse':''.join(reversed(pairs)),'nibble_swap':''.join(z[::-1] for z in pairs)}
d=json.loads(geom.read_text()); q=105/256; P=lambda n,k:math.factorial(n)//math.factorial(n-k)
def calc(name,x):
 wins=[set(w['symbols']) for w in x['BS8']['windows']]; anchor=set(x['BS8']['anchor']['symbols']); rem=sorted(set('0123456789ABCDEF')-anchor); syms='0123456789ABCDEF'
 def B(s):return sum(w<=s for w in wins)
 def cost(k,b0,b1):return P(16,k+1)*q**b0*(1-q**(b1-b0))/(1-q)
 initial=P(16,7)*(1-q**B(anchor))/(1-q)
 bmask=[B(anchor|{rem[i] for i in range(9) if mask>>i&1}) for mask in range(512)]
 @lru_cache(None)
 def dp(mask):
  s=anchor|{rem[i] for i in range(9) if mask>>i&1}; k=7+bin(mask).count("1"); b=B(s)
  if mask==full:return (0,())
  best=None
  for i,z in enumerate(rem):
   if not (mask>>i)&1:
    nmask=mask|(1<<i); ns=anchor|{rem[j] for j in range(9) if nmask>>j&1}; nb=B(ns); tail,order=dp(nmask); cand=(cost(k,b,nb)+tail,(z,)+order)
    if best is None or cand[0]<best[0] or (cand[0]==best[0] and cand[1]<best[1]):best=cand
  return best
 full=(1<<9)-1; val,order=dp(0)
 Bcounts={str(k):sum(B(anchor|set(order[:k-7]))==b for b in [B(anchor|set(order[:k-7]))]) for k in []}
 allB=[B(anchor|set(order[:i])) for i in range(10)]
 # reproduce solver._order tie rules: anchor max containment then earliest; symbols by frequency, then additions new, contained, symbol.
 h=ORIENTS[name]; freq={z:h.count(z) for z in syms}; so=sorted(anchor,key=lambda z:(-freq[z],z)); selected=set(so); bound=B(selected); counts=[bound]
 while len(so)<16:
  choices=[]
  for z in set(syms)-selected:
   after=selected|{z}; new=B(after)-bound; contained=sum(z in w for w in wins); choices.append((new,contained,-int(z,16),z))
  z=max(choices)[3];so.append(z);selected.add(z);bound=B(selected);counts.append(bound)
 def model(order):
  bs=[B(anchor|set(order[:i])) for i in range(10)]; total=initial
  for i in range(9): total+=cost(7+i,bs[i],bs[i+1])
  return total,bs
 greedy_total,greedy_bs=model(so[7:])
 import itertools
 def model_order(order):
  mask=0; total=initial; prev=bmask[0]
  rem_index={z:i for i,z in enumerate(rem)}
  for j,z in enumerate(order):
   mask |= 1<<rem_index[z]; cur=bmask[mask]; total += cost(7+j,prev,cur); prev=cur
  return total
 brute_best=(None,None)
 if name=='forward':
  brute_best=(float('inf'),None)
  for oo in itertools.permutations(rem):
   vv=model_order(oo)
   if vv<brute_best[0]-1e-9 or (abs(vv-brute_best[0])<=1e-9 and (brute_best[1] is None or oo<brute_best[1])): brute_best=(vv,oo)
  assert abs(brute_best[0]-(initial+val))<=1e-6 and tuple(order)==brute_best[1]
 return {'window_count':len(wins),'anchor_symbols':sorted(anchor),'anchor_B':B(anchor),'B_for_optimal_order':allB,'optimal_remaining_order':list(order),'optimal_full_order':sorted(anchor)+list(order),'optimal_model_cost':initial+val,'initial_anchor_cost':initial,'solver_greedy_remaining_order':so[7:],'solver_greedy_B_counts':counts,'bruteforce_9_factorial_cost':brute_best[0],'bruteforce_9_factorial_remaining_order':list(brute_best[1]) if brute_best[1] else None,'bruteforce_crosscheck':name=='forward','solver_greedy_model_cost':greedy_total,'greedy_speed_ratio':greedy_total/(initial+val),'all_B_counts_by_optimal_size':allB,'dp_states':dp.cache_info().currsize,'dp_states_expected':512}
res={'identity':'ASTRA','target_evaluated':True,'crypto_evaluated':False,'scope':'planning-model geometry order cost only; q=105/256 independent-uniform assumption is not probability evidence or runtime guarantee','geometry_sha256':G_SHA,'solver_sha256':S_SHA,'q':q,'orientations':{o:calc(o,v) for o,v in d['orientations'].items()}}
(HERE/'order_cost.json').write_text(json.dumps(res,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':'ASTRA','dp_states':sum(x['dp_states'] for x in res['orientations'].values()),'result_sha256':sha(HERE/'order_cost.json')},indent=2))

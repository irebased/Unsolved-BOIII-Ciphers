#!/usr/bin/env python3
import hashlib,json,math
from pathlib import Path
HERE=Path(__file__).resolve().parent; R=HERE.parents[0]; mdx=R.parents[1]/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'; proto=R/'hex_cfb/prototype.py'
EXPECTED={'rev7_mdx':'085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91','prototype.py':'416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(mdx)==EXPECTED['rev7_mdx'] and sha(proto)==EXPECTED['prototype.py']
t=mdx.read_text(); a=t.index('`83 B57B2')+1;b=t.index('`',a); raw=''.join(t[a:b].split()).upper(); assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
pairs=[raw[i:i+2] for i in range(0,len(raw),2)]; orientations={'forward':raw,'reverse':raw[::-1],'byte_reverse':''.join(reversed(pairs)),'nibble_swap':''.join(x[::-1] for x in pairs)}
def perm(n,k):return math.factorial(n)//math.factorial(n-k)
def calc(h,bs):
 wins=[]
 for i in range(bs,len(h)//2):
  text=h[2*(i-bs):2*(i+1)]; sy=sorted(set(text)); wins.append({'endpoint_byte':i,'hex_start':2*(i-bs),'hex_end_exclusive':2*(i+1),'k':len(sy),'symbols':sy})
 hist={}
 for w in wins:hist[str(w['k'])]=hist.get(str(w['k']),0)+1
 m=min(w['k'] for w in wins); mins=[w for w in wins if w['k']==m]
 anchor=min(mins,key=lambda w:(-sum(set(x['symbols'])<=set(w['symbols']) for x in wins),w['endpoint_byte']))
 contained=[w for w in wins if set(w['symbols'])<=set(anchor['symbols'])]
 chosen=set(anchor['symbols']); steps=[];remaining=set('0123456789ABCDEF')-chosen
 while remaining:
  base=sum(set(w['symbols'])<=chosen for w in wins); best=max(remaining,key=lambda s:(sum(set(w['symbols'])<=chosen|{s} for w in wins)-base,s)); chosen.add(best); remaining.remove(best); after=sum(set(w['symbols'])<=chosen for w in wins); steps.append({'added_symbol':best,'newly_fully_bound_windows':after-base,'cumulative_fully_bound_windows':after,'chosen_symbols':sorted(chosen)})
 return {'window_count':len(wins),'histogram_k':hist,'min_k':m,'P(16,k)':perm(16,m),'minimizer_windows':mins,'anchor':{'endpoint_byte':anchor['endpoint_byte'],'symbols':anchor['symbols'],'contained_window_count':len(contained),'contained_endpoints':[w['endpoint_byte'] for w in contained]},'greedy_steps':steps,'windows':wins}
out={'identity':'ASTRA','target_evaluated':True,'crypto_evaluated':False,'scope':'structural byte-window geometry only; no key, IV, crypto, or plaintext evaluation','source_hashes':EXPECTED,'canonical_hex_sha256':'5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c','orientations':{o:{'BS'+str(bs):calc(h,bs) for bs in (8,16)} for o,h in orientations.items()}}
(HERE/'geometry.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':'ASTRA','orientations':4,'block_sizes':[8,16],'result_sha256':sha(HERE/'geometry.json')},indent=2))

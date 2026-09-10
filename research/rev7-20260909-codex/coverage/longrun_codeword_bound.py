#!/usr/bin/env python3
"""ASTRA: exact uniform-byte model for the complete-codepoint gate described in FABLE268.
This does not execute FABLE's scorer or assert that every search transform preserves a uniform null.
"""
from fractions import Fraction
from itertools import product
import hashlib,json
from pathlib import Path
EXTRA=(0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
WORDS=tuple(chr(c).encode('utf8') for c in (9,10,13,*range(32,127),*range(160,256),*EXTRA))
def weights(words,base):
 return {k:Fraction(sum(len(w)==k for w in words),base**k) for k in set(map(len,words))}
def reaches(limit,w):
 f={0:Fraction(1)}
 for n in range(1,limit+1): f[n]=sum((v*f.get(n-k,Fraction(1)) for k,v in w.items()),Fraction(0))
 return f

def brute_reaches(data,words,limit):
 pos=0
 while pos<limit:
  matches=[w for w in words if data[pos:pos+len(w)]==w]
  if not matches:return False
  assert len(matches)==1
  pos+=len(matches[0])
 return True

def compute():
 assert len(WORDS)==len(set(WORDS))==201
 assert all(not b.startswith(a) for a in WORDS for b in WORDS if a!=b)
 counts={k:sum(len(w)==k for w in WORDS) for k in (1,2,3)}
 assert counts=={1:98,2:96,3:7}
 # Independent finite enumeration under a reduced seven-byte alphabet, enough bytes to finish crossing L.
 small=(b'A',b'B',bytes.fromhex('c2a0'),bytes.fromhex('e28094'))
 alphabet=tuple(sorted(set(b''.join(small))));assert len(alphabet)==7
 fsmall=reaches(4,weights(small,7));checks=[]
 for n in range(1,5):
  size=n+2; total=7**size
  accepted=sum(brute_reaches(bytes(v),small,n) for v in product(alphabet,repeat=size))
  assert Fraction(accepted,total)==fsmall[n]
  checks.append({'L':n,'strings':total,'accepted':accepted,'exact_probability':str(fsmall[n])})
 f=reaches(80,weights(WORDS,256));rows=[]
 for combos in (184,4232,67712,389344,105984,4376736):
  starts=combos*538
  row={'combos':combos,'starts_upper_bound':starts,'minimum_L_union_bound_at_most_0_01':next(n for n in range(1,81) if starts*f[n]<=Fraction(1,100))}
  rows.append(row)
 return {'identity':'ASTRA','target_evaluated':False,'scope':'Exact probability under independent uniform bytes for a prefix-free complete-codepoint gate with98 one-byte,96 two-byte,7 three-byte words. Scorer implementation equivalence and null-preserving search transforms are not established here.','formula':'f(L)=98/256*f(L-1)+96/256^2*f(L-2)+7/256^3*f(L-3), f(L)=1 for L<=0; P(max>=L)<=min(1,T*f(L)) by union bound','assumptions':['Each candidate output is marginally uniform over its byte sequence under the chosen null. Independence between candidates or start offsets is unnecessary for the union bound.','A run starts at a codepoint boundary and counts only complete allowed codepoints. Finite end-of-buffer truncation can only lower the probability.','538 possible starts per candidate is an illustrative input parameter, not audited coverage of a FABLE grid.','Adaptive missing-ciphertext reconstruction is not modeled by fixed uniform candidate outputs.'], 'codeword_counts_by_length':counts,'reduced_alphabet_exact_checks':checks,'illustrative_grid_bounds':rows,'probabilities':{str(n):{'exact':str(f[n]),'float':float(f[n])} for n in (20,25,30,35,40)},'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest()}
if __name__=='__main__':
 out=compute();path=Path(__file__).with_suffix('.json')
 if path.exists():assert json.loads(path.read_text())==json.loads(json.dumps(out))
 else:path.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'identity':'ASTRA','verified':True,'illustrative_grid_bounds':out['illustrative_grid_bounds'],'ledger_sha256':hashlib.sha256(path.read_bytes()).hexdigest()},indent=2))

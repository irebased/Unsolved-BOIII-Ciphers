#!/usr/bin/env python3
"""Synthetic-only controls for group reversal G and shared proof dispatch."""
from __future__ import annotations
import hashlib,importlib.util,json,random,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PKG=HERE.parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
R=load('gre_driver',HERE/'run_target.py');B=load('gre_bifid',PKG/'bifid16.py')
def sha_bytes(x):return hashlib.sha256(bytes(x) if not isinstance(x,str) else x.encode()).hexdigest()

def positions(square):
 out=[None]*16
 for i,symbol in enumerate(square):out[symbol]=i
 assert sorted(out)==list(range(16));return out
def encrypt_two_square(plain_symbols,cipher_square,plain_square,period):
 pp=positions(plain_square);out=[]
 for start in range(0,len(plain_symbols),period):
  block=plain_symbols[start:start+period];digits=[pp[x]//4 for x in block]+[pp[x]%4 for x in block]
  out.extend(cipher_square[4*digits[i]+digits[i+1]] for i in range(0,len(digits),2))
 return out
def decrypt_two_square(cipher,cipher_square,plain_square,period):
 cp=positions(cipher_square);out=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];flat=[]
  for x in block:flat.extend((cp[x]//4,cp[x]%4))
  L=len(block);out.extend(plain_square[4*flat[i]+flat[L+i]] for i in range(L))
 return out
def coordinate_reference(cipher,period):
 graphs={k:set() for k in ('RC','CR','RR','CC')};positions_out=[];even_pair_stream=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];L=len(block);flat=[item for j,symbol in enumerate(block) for item in ((symbol,'R',start+j),(symbol,'C',start+j))]
  for i in range(L):
   if (start+i)&1:continue
   left,right=flat[i],flat[L+i];kind=left[1]+right[1]
   graphs[kind].add((left[0],right[0]));positions_out.append((start+i,left[2],right[2],kind))
  if L%2==0:
   for j in range(L//2):
    h0,h1=flat[2*j],flat[L+2*j];l0,l1=flat[2*j+1],flat[L+2*j+1]
    assert h0[1]==h1[1]=='R' and l0[1]==l1[1]=='C' and h0[0]==l0[0] and h1[0]==l1[0]
    even_pair_stream.append((h0[0]<<4)|h1[0])
 return graphs,positions_out,bytes(even_pair_stream)

def generate():
 R.verify_deps();rng=random.Random(0x47524F5550524556);square=list(range(16));rng.shuffle(square);plain_square=list(range(16));rng.shuffle(plain_square);assert plain_square!=square
 # 546 bytes, restricted endpoint, deliberately varied and target-independent.
 phrase=b'THE GROUP REVERSE CONTROL CHECKS BIFID PERIOD BOUNDARIES AND THE FINAL SHORT TOKEN.\n'
 plain=(phrase*((546+len(phrase)-1)//len(phrase)))[:546];symbols=B.bytes_to_symbols(plain);assert len(symbols)==1092
 index_cases=[]
 for n in list(range(0,18))+[31,32,1091,1092]:
  src=list(range(n));obs=R.group_reverse_forward(src,5);back=R.group_reverse_inverse(obs,5);assert back==src and sorted(obs)==src
  index_cases.append({'n':n,'remainder':n%5,'observed_prefix':obs[:min(7,n)],'roundtrip':True})
 cipher=B.encrypt_symbols(symbols,square,31);natural=''.join(format(x,'X') for x in cipher);observed=R.group_reverse_forward(natural,5)
 assert len(observed)==1092 and observed[:2]==natural[-2:] and R.group_reverse_inverse(observed,5)==natural
 # Independent index formula: observed has natural final token first, followed by reversed full tokens.
 idx_formula=[(1090+i if i<2 else 5*(217-(i-2)//5)+(i-2)%5) for i in range(1092)]
 idx_tokens=R.group_reverse_forward(list(range(1092)),5);assert idx_formula==idx_tokens
 # Reapplying forward left-chunking is not the inverse when the remainder is nonzero.
 assert R.group_reverse_forward(observed,5)!=natural
 variants={'forward':natural,'full_reverse':natural[::-1],'byte_reverse':''.join(reversed([natural[i:i+2] for i in range(0,len(natural),2)])),'nibble_swap':''.join(natural[i+1]+natural[i] for i in range(0,len(natural),2)),'group_reverse':observed}
 assert len(set(variants.values()))==5
 periods=[1,2,3,4,5,6,31,32,545,546,1091,1092];rounds=[]
 for p in periods:
  c=encrypt_two_square(symbols,square,plain_square,p);assert decrypt_two_square(c,square,plain_square,p)==symbols
  o=R.group_reverse_forward(c,5);assert R.group_reverse_inverse(o,5)==c
  graphs_ref,pos_ref,pairs_ref=coordinate_reference(c,p);graphs_drv,pos_drv=R.odd_graphs(c,p)
  assert graphs_ref==graphs_drv
  assert pos_ref==pos_drv
  cp=positions(square);pp=positions(plain_square);actual={'mapping':cp,'forbidden_coordinate':pp[1]}
  assert R.JOIN.validate_witness(graphs_drv,actual,4) # planted plaintext contains no high nibble 1
  lens=R.block_lengths(len(c),p)
  if all(L%2==0 for L in lens):assert pairs_ref==R.even_pairs(c,p)
  o=R.group_reverse_forward(c,5);assert R.group_reverse_inverse(o,5)==c
  row={'period':p,'block_lengths':lens,'cipher_sha256':sha_bytes(c),'observed_sha256':sha_bytes(o),'coordinate_graph_sha256':hashlib.sha256(json.dumps({k:sorted(v) for k,v in graphs_ref.items()},sort_keys=True,separators=(',',':')).encode()).hexdigest(),'coordinate_positions':len(pos_ref),'actual_two_square_witness_valid':True,'even_pair_reference_equal':all(L%2==0 for L in lens)}
  # Necessary-condition dispatch must retain a real distinct-square plaintext.
  if p in (2,31,1092):
   a=R.analyze_cipher(c,p,join_cap=1_000_000,cross_cap=10_000);assert a['status'] in ('unresolved','incomplete'),(p,a['status'],a['method']);row['analysis_status']=a['status'];row['analysis_method']=a['method']
  rounds.append(row)
 assert R.block_lengths(1092,31)[-1]==7 and R.block_lengths(1092,1091)==[1091,1]
 return {'identity':'ASTRA','target_evaluated':False,'kind':'synthetic_controls','seed':'0x47524F5550524556','cipher_square':square,'plaintext_square':plain_square,'squares_distinct':True,'plain_sha256':sha_bytes(plain),'plain_length':len(plain),'symbol_length':len(symbols),'group_width':5,'leading_short_token_length':2,'natural_sha256':sha_bytes(natural),'observed_sha256':sha_bytes(observed),'inverse_exact':True,'forward_reapplication_is_not_inverse':True,'index_formula_sha256':sha_bytes(bytes().join(int(i).to_bytes(2,'big') for i in idx_formula)),'natural_token_lengths':[5]*218+[2],'observed_token_lengths':[2]+[5]*218,'orientation_hashes':{k:sha_bytes(v) for k,v in variants.items()},'orientation_distinct_count':len(set(variants.values())),'index_cases':index_cases,'period_roundtrips':rounds,'scope':R.scope(),'source_hashes':{'run_target.py':R.sha(HERE/'run_target.py'),'bifid16.py':R.sha(PKG/'bifid16.py')},'accepted_dependency_hashes':R.DEPS}
def main():
 out=generate();saved=json.loads((HERE/'controls.json').read_text())
 assert out==saved
 print(json.dumps({'identity':'ASTRA','status':'PASS','ledger_sha256':R.sha(HERE/'controls.json'),'period_controls':len(out['period_roundtrips']),'index_controls':len(out['index_cases'])},sort_keys=True))
if __name__=='__main__':main()

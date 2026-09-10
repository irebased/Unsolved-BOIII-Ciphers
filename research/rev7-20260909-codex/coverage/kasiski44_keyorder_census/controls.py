#!/usr/bin/env python3
"""ASTRA synthetic controls for the exact 7! key-order census."""
from __future__ import annotations
import argparse,hashlib,importlib.util,itertools,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;OUT=HERE/'controls.json';MODEL=HERE/'model.py'
def sha(path):return hashlib.sha256(path.read_bytes()).hexdigest()
def load():
 spec=importlib.util.spec_from_file_location('astra_kasiski_keyorder_model',MODEL);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;spec.loader.exec_module(m);return m
def brute(s,min_length=4):
 out=[]
 for i in range(len(s)-min_length+1):
  for j in range(i+1,len(s)-min_length+1):
   if s[i:i+min_length]!=s[j:j+min_length]:continue
   if i and s[i-1]==s[j-1]:continue
   n=min_length
   while j+n<len(s) and s[i+n]==s[j+n]:n+=1
   out.append({'start_a':i,'start_b':j,'gap':j-i,'length':n,'text':s[i:i+n]})
 return sorted(out,key=lambda x:(x['start_a'],x['start_b'],x['length'],x['text']))
def labelled_decode(observed,order,rows,cell=4):
 span=rows*cell;cols=['']*len(order)
 for rank,col in enumerate(order):cols[col]=observed[rank*span:(rank+1)*span]
 return ''.join(cols[c][r*cell:(r+1)*cell] for r in range(rows) for c in range(len(order)))
def compute():
 m=load(); exhaustive=0
 for n in range(12):
  for bits in itertools.product('01',repeat=n):
   s=''.join(bits);assert m.maximal_pairs_fast(s)==brute(s);exhaustive+=1
 fixtures={
  'nested':'QABCDEZQABCDEX',
  'overlap':'ABABABABX',
  'boundary_end':'WXYZ0WXYZ',
  'no_repeat':'0123456789ABCDEF'}
 fixture_rows={}
 for name,s in fixtures.items():
  f=m.maximal_pairs_fast(s);b=brute(s);assert f==b;fixture_rows[name]={'text':s,'pairs':f}
 chars=list('#'*236)
 for q,(pos,left,right) in enumerate(((0,None,'u'),(114,'v','w'),(228,'x','y'))):
  if left is not None:chars[pos-1]=left
  chars[pos:pos+5]=list('ABCDE');chars[pos+5]=right
 trip=''.join(chars);tf=m.maximal_pairs_fast(trip);tb=brute(trip);assert tf==tb
 planted=[r for r in tf if r['text'].startswith('ABCDE') and r['gap'] in (114,228)]
 assert {(r['start_a'],r['start_b'],r['gap']) for r in planted}=={(0,114,114),(0,228,228),(114,228,114)}
 # Independent two-row labelled fixture (generalized locally rather than calling production length checks).
 order=(3,5,4,2,1,6,0);natural=''.join(f'{r}{c}ab' for r in range(2) for c in range(7))
 cols=[''.join(natural[(r*7+c)*4:(r*7+c+1)*4] for r in range(2)) for c in range(7)]
 observed=''.join(cols[c] for c in order);assert labelled_decode(observed,order,2)==natural
 # Every order: independent index gather equals production materialization and both inverse round trips.
 synthetic=''.join('0123456789ABCDEF'[(i*11+i//17)%16] for i in range(m.LENGTH));geom_digest=hashlib.sha256();count=0
 for order in m.all_orders():
  idx=m.decode_indices(order);assert len(idx)==m.LENGTH and sorted(idx)==list(range(m.LENGTH))
  direct=''.join(synthetic[i] for i in idx);decoded=m.decode_equal(synthetic,order);assert direct==decoded
  assert m.encode_equal(decoded,order)==synthetic
  natural=m.encode_equal(synthetic,order);assert m.decode_equal(natural,order)==synthetic
  geom_digest.update(bytes(order));geom_digest.update(hashlib.sha256(decoded.encode()).digest());count+=1
 assert count==5040
 return {'identity':'ASTRA','target_evaluated':False,'scope':'Synthetic-only exact 7! equal-cut-4 geometry and maximal-repeat controls.','exhaustive_binary_strings':exhaustive,'fixtures':fixture_rows,'triplicate':{'length':len(trip),'qualifying_planted_pairs':planted},'geometry':{'orders':count,'synthetic_sha256':hashlib.sha256(synthetic.encode()).hexdigest(),'all_order_stream_digest_sha256':geom_digest.hexdigest(),'two_row_natural':natural[:0] if False else 'labelled r,c cells','two_row_observed_sha256':hashlib.sha256(observed.encode()).hexdigest()},'assertions':{'fast_equals_independent_brute':True,'nested_and_overlapping_supported':True,'triplicate_occurrence_pairs_retained':True,'boundary_ending_supported':True,'all_5040_order_indices_permutations':True,'independent_gather_matches_decode':True,'both_geometry_roundtrips':True},'source_hashes':{'model.py':sha(MODEL),'controls.py':sha(Path(__file__))}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',metavar='NEW_PATH');a=ap.parse_args();got=compute()
 if a.regenerate:
  q=Path(a.regenerate);assert not q.exists();q.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','written':str(q),'sha256':sha(q)},sort_keys=True));return
 assert OUT.exists();expected=json.loads(OUT.read_text());assert got==expected
 print(json.dumps({'identity':'ASTRA','controls_verified':True,'ledger_sha256':sha(OUT),'orders':5040,'exhaustive_binary_strings':got['exhaustive_binary_strings']},sort_keys=True))
if __name__=='__main__':main()

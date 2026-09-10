#!/usr/bin/env python3
"""ASTRA saved-ledger partition check; no ciphertext extraction or cipher search."""
from pathlib import Path
import argparse,base64,hashlib,itertools,json,zlib
HERE=Path(__file__).resolve().parent;PKG=HERE.parent
PINS={
 'odd_single_graph_target/run_target.py':'3c7ba1c60150a000018da4a1b14d523a827f8ed6b9f2187be39e169135babe06',
 'even_target/run_target.py':'b86fdd8402319753eb0292e75b9f0712a1ed2044038761e5d7a23af30cd4ff85',
 'even_target/target_results.pack.json':'3d9913b1253fc9acb52520dc2098ada980f16ad9b38958df891247033236fb12',
 'even_rectangle_target/broad_reconciliation.json':'a5dbf6d4dd79769daf7756160f7f3d861c2aa3dfdebc6dfc1514aae238434295',
 'even_rectangle_target/target_results.json':'eec0e9f643d3b5ae2498b85eee8b8999b9ce2a8d3d714b8db1e971a048bf8ce1',
 'odd_single_graph_target/target_results.json':'1c90eaaf17af19b51d20ee29e720e4ee14fb7cd3c15ea9b919ff2ada28b1443d',
 'odd_single_graph_target/verification.json':'5552bcbad04d7019c13bd22f32bde1d1f1bba8036262b69a6688fc5784142952',
 'odd_rectangle_join_target/target_results.json':'46fe703714c05abf9fe32127f9e1517a1e8a6db8b4184b4825130611e66b6df4',
 'odd_rectangle_join_target/verification.json':'3facf405ef174105bec0b51438f74532b5fc603a15260e335349f4a677ba3ff8',
 'odd_rectangle_join_target/independent_replay.py':'4d86b9414843bfbeca0136250696e9aca454ab6e1ab76f4095be6641064775bc',
 'odd_rectangle_join_target/independent_replay.json':'4e4c7c74f61e04c1152c1887867b6cb70145122b9624a0bf8e51366c8d7824fa'
}
# The earlier even driver calls the exact symbol reversal full_hex_reverse.
ORIENTS=('forward','reverse','byte_reverse','nibble_swap')
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(rel):return json.loads((PKG/rel).read_text())
def ids(rows):
 out=[(x['orientation'],x['period']) for x in rows]
 assert len(out)==len(set(out))
 for x,k in zip(rows,out):
  assert k[0] in (*ORIENTS,'full_hex_reverse') and 1<=k[1]<=1092
  if 'id' in x:assert x['id']==f'{k[0]}:p{k[1]}'
 normalized=[('reverse' if o=='full_hex_reverse' else o,p) for o,p in out]
 assert len(normalized)==len(set(normalized))
 return set(normalized)
def pack_read():
 e=load('even_target/target_results.pack.json');assert e['identity']=='ASTRA' and e['target_evaluated'] is True and e['format']=='gzip-level9-mtime0/base64' and e['raw_name']=='target_results.json' and e['compressed_length']==468922 and e['compressed_sha256']=='a5fb5d169a4f21ba70367b9cc46fd5e652db577e8683cb1cff68bc18dd08c706' and e['raw_length']==7464776 and e['raw_sha256']=='acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8'
 c=base64.b64decode(e['payload_base64'],validate=True)
 assert len(c)==468922 and hb(c)=='a5fb5d169a4f21ba70367b9cc46fd5e652db577e8683cb1cff68bc18dd08c706'
 z=zlib.decompressobj(31);raw=z.decompress(c,7464777)+z.flush()
 assert z.eof and not z.unused_data and not z.unconsumed_tail
 assert len(raw)==7464776 and hb(raw)=='acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8'
 return json.loads(raw)
def build():
 for rel,w in PINS.items():assert sha(PKG/rel)==w,(rel,sha(PKG/rel),w)
 even=pack_read();broad=load('even_rectangle_target/broad_reconciliation.json');rect=load('even_rectangle_target/target_results.json');odd=load('odd_single_graph_target/target_results.json');join=load('odd_rectangle_join_target/target_results.json');ind=load('odd_rectangle_join_target/independent_replay.json')
 for d in (even,odd,join):assert d['identity']=='ASTRA' and d['status']=='complete' and d['target_evaluated'] is True
 # The pinned source definitions establish that the two differently named reversal labels are identical.
 assert "if n=='full_hex_reverse': return s[::-1]" in (PKG/'even_target/run_target.py').read_text()
 assert "if name=='reverse':return s[::-1]" in (PKG/'odd_single_graph_target/run_target.py').read_text()
 assert even['summary']['cells']==2184 and even['scope']['orientations']==['forward','full_hex_reverse','byte_reverse','nibble_swap'] and even['scope']['periods']==list(range(2,1093,2)) and even['configuration']['driver_sha256']==PINS['even_target/run_target.py']
 assert odd['summary']['cells']==2184 and odd['summary']['status_counts']=={'excluded':2104,'unresolved':80} and odd['scope']['orientations']==list(ORIENTS) and odd['scope']['odd_periods']==[1,1091,2] and odd['configuration']['driver_sha256']==PINS['odd_single_graph_target/run_target.py']
 odd_receipt=load('odd_single_graph_target/verification.json');assert odd_receipt['result_sha256']==PINS['odd_single_graph_target/target_results.json'] and odd_receipt['cells']==2184 and odd_receipt['status_counts']==odd['summary']['status_counts']
 assert join['summary']['cells']==80 and join['summary']['status_counts']=={'incomplete':0,'sat':0,'unsat':80} and join['summary']['join_pairs_examined']==5329 and join['configuration']['prior_result_sha256']==PINS['odd_single_graph_target/target_results.json'] and join['configuration']['prior_receipt_sha256']==PINS['odd_single_graph_target/verification.json']
 join_receipt=load('odd_rectangle_join_target/verification.json');assert join_receipt['result_sha256']==PINS['odd_rectangle_join_target/target_results.json'] and join_receipt['cells']==80 and join_receipt['status_counts']==join['summary']['status_counts'] and join_receipt['join_pairs_examined']==5329
 expected_even=set(itertools.product(ORIENTS,range(2,1093,2)));expected_odd=set(itertools.product(ORIENTS,range(1,1092,2)));universe=set(itertools.product(ORIENTS,range(1,1093)))
 assert ids(even['cells'])==expected_even and ids(odd['cells'])==expected_odd
 cardinal=[];remaining=[]
 for c in even['cells']:
  h=c['histogram'];assert len(h)==256 and sum(h)==546 and sum(x>0 for x in h)==c['distinct_pair_count']
  if c['distinct_pair_count']>213:
   assert c['bound_213']=='excluded_all_squares';cardinal.append(c)
  else:
   assert c['bound_213']=='unresolved';remaining.append(c)
 assert len(cardinal)==2177 and len(remaining)==7 and ids(remaining)==ids(rect['cells'])==ids(broad['seven_rows'])
 assert rect['identity']=='ASTRA' and rect['target_evaluated'] is True and rect['status']=='complete' and rect['counts']=={'total':7,'excluded_bag213':7,'empty_rectangle_unresolved':0} and rect['canonical_hex_sha256']=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
 for c in rect['cells']:
  a=c['analysis'];assert c['status']=='excluded_bag213' and a['excluded_bag213'] and not a['empty_4x4_rectangle_exists_relaxed'] and a['witness'] is None
  assert a['row_sets_examined']==len(a['row_set_records'])==1820 and a['max_common_missing_count']==1
 assert broad['identity']=='ASTRA' and broad['target_evaluated'] is True and broad['verification_only'] is True and broad['new_target_search'] is False and broad['seven_rectangle_result_sha256']==PINS['even_rectangle_target/target_results.json']
 assert broad['proof_accounting']['even_prior_distinct_pair_cardinality_exclusions_bag213']==2177 and broad['proof_accounting']['even_new_empty_rectangle_exclusions_bag213']==7 and broad['proof_accounting']['even_cells_excluded_for_any_ordered_pair_of_fixed_cipher_and_plain_squares']==2184
 excluded=[];unresolved=[]
 for c in odd['cells']:
  assert {x['kind'] for x in c['types']}=={'RR','RC','CR','CC'}
  for x in c['types']:
   assert x['checked_first_sets'] in (0,1820)
   if x['feasible']:assert x['classification'] in ('feasible_unresolved','no_constraints') and x['surviving_first_sets']>0 and x['exclusion_certificate'] is None
  bad=[x for x in c['types'] if not x['feasible']]
  if bad:
   assert c['status']=='excluded' and c['excluded_two_square_bag213'] is True
   assert set(c['impossible_types'])=={x['kind'] for x in bad}
   for x in bad:assert x['classification']=='impossible_excluded' and x['checked_first_sets']==1820 and x['surviving_first_sets']==0 and x['exclusion_certificate'] is not None
   excluded.append(c)
  else:
   assert c['status']=='unresolved' and c['excluded_two_square_bag213'] is False;unresolved.append(c)
 assert len(excluded)==2104 and len(unresolved)==80
 assert [x['id'] for x in unresolved]==[x['id'] for x in join['cells']]==[x['id'] for x in ind['cells']]
 assert ind['identity']=='ASTRA' and ind['verification_only'] is True and ind['new_target_search'] is False and ind['summary']['cells']==80 and ind['summary']['independent_status_counts']=={'incomplete':0,'sat':0,'unsat':80} and ind['summary']['join_pairs_total']==5329
 for j,v in zip(join['cells'],ind['cells']):
  a=j['analysis'];assert a['status']=='unsat' and a['complete'] and a['witness'] is None and v['independent_status']=='unsat'
  assert a['candidate_counts']==v['candidate_counts'] and a['obstruction_counts']==v['obstruction_counts'] and a['all_pairs_obstruction_digest']==v['full_join_trace_sha256']
  assert a['candidate_counts']['joins_examined']==a['candidate_counts']['join_space']==len(v['full_join_trace'])
 partitions={'even_cardinality':ids(cardinal),'even_empty_rectangle':ids(rect['cells']),'odd_single_typed_graph':ids(excluded),'odd_joint_typed_rectangles':ids(join['cells'])}
 for a,b in itertools.combinations(partitions.values(),2):assert a.isdisjoint(b)
 union=set().union(*partitions.values());assert union==universe and len(union)==4368
 bag={9,10,13,*range(32,127),*range(128,192),*range(194,245)};assert len(bag)==213 and bag=={9,10,13,*range(0x20,0x7f),*range(0x80,0xc0),*range(0xc2,0xf5)} and not(set(range(0x10,0x20))&bag)
 return {'identity':'ASTRA','verification_only':True,'new_target_search':False,'canonical_ciphertext_extracted':False,'orientation_alias':{'full_hex_reverse':'reverse; both pinned drivers use s[::-1]'},'source_hashes':PINS|{'odd_rectangle_join_target/reconcile_two_squares.py':sha(Path(__file__))},'scope':{'direction':'standard Bifid DECRYPT directly on canonical symbols','squares':'arbitrary ordered pair of fixed 4x4 cipher and plaintext squares','orientations':list(ORIENTS),'periods_inclusive':[1,1092],'periods_at_least_1092_equivalent':True,'necessary_byte_bag':sorted(bag)},'partitions':{k:{'count':len(v),'ids':[f'{o}:p{p}' for o,p in sorted(v)]} for k,v in partitions.items()},'all_partitions_pairwise_disjoint':True,'union_equals_complete_cartesian_grid':True,'certificate_checks':{'packed_even_envelope_and_raw_hashes':True,'even_histograms_and_cardinality_statuses':2184,'even_rectangle_full_records':7,'odd_single_type_records':2184,'odd_join_and_independent_records':80,'receipts_bound':2},'excluded_cells':4368,'unresolved_cells':0,'join_pairs_independently_replayed':5329,'limits':['This verifies the union and consistency of previously accepted certificates; it does not rerun earlier solvers or graph verifiers.','The exclusion is conditional on direct standard decryption, fixed squares, registered orientations and the stated endpoint. It does not solve Rev7 or classify it as modern/classical.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();d=build();out=HERE/'two_square_coverage.json'
 if a.regenerate:
  with a.regenerate.open('x') as f:json.dump(d,f,sort_keys=True,indent=2);f.write('\n')
  out=a.regenerate
 else:assert json.loads(out.read_text())==d
 print(json.dumps({'identity':'ASTRA','verified':True,'excluded_cells':4368,'ledger_sha256':sha(out)},sort_keys=True))
if __name__=='__main__':main()

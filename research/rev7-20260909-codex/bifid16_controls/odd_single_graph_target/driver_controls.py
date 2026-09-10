#!/usr/bin/env python3
"""ASTRA synthetic-only controls for the inert odd single-graph driver."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,random,sys
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;PKG=HERE.parent;OUT=HERE/'driver_controls.json';SEED=20260912
DRIVER=HERE/'run_target.py';ORACLE=PKG/'odd_typed_rectangles/controls.py'
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':')).encode()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
rt=load('astra_single_graph_driver_controls_target',DRIVER);oracle=load('astra_odd_typed_oracle_controls',ORACLE)
def tables(square):
 pos=[None]*16
 for i,s in enumerate(square):pos[s]=divmod(i,4)
 return pos
def encrypt(plain,cs,ps,period):
 pc=tables(ps);out=[]
 for start in range(0,len(plain),period):
  block=plain[start:start+period];digits=[pc[s][0] for s in block]+[pc[s][1] for s in block]
  out.extend(cs[4*digits[i]+digits[i+1]] for i in range(0,len(digits),2))
 return out
def decrypt(cipher,cs,ps,period):
 cc=tables(cs);out=[]
 for start in range(0,len(cipher),period):
  block=cipher[start:start+period];digits=[v for s in block for v in cc[s]];L=len(block);out.extend(ps[4*digits[i]+digits[L+i]] for i in range(L))
 return out
def bytes_to_syms(value):return [z for b in value for z in (b>>4,b&15)]
def axis(coords,s,k):return coords[s][0 if k=='R' else 1]
def build():
 rt.check_parents();rng=random.Random(SEED);phrase=b'ASTRA two square odd Bifid graph plant: 09!? Mixed CASE. '
 plaintext=(phrase*((546+len(phrase)-1)//len(phrase)))[:546];plain=bytes_to_syms(plaintext);assert len(plain)==1092 and all(b<128 for b in plaintext) and all((b>>4)!=1 for b in plaintext)
 rows=[]
 for distinct in (False,True):
  for period in (1,3,31,99,1091):
   cs=rng.sample(list(range(16)),16);ps=rng.sample(list(range(16)),16) if distinct else cs[:];cipher=encrypt(plain,cs,ps,period);assert decrypt(cipher,cs,ps,period)==plain and encrypt(decrypt(cipher,cs,ps,period),cs,ps,period)==cipher
   lengths=[min(period,len(cipher)-a) for a in range(0,len(cipher),period)];ours=rt.metadata(len(cipher),period);theirs=oracle.typed_high_edges(cipher,cs,lengths)
   left=[(k,cipher[a],cipher[b],s,L,i) for k,a,b,s,L,i in ours];right=[(e['type'],e['a'],e['b'],e['block_start'],e['block_length'],e['local_nibble']) for e in theirs];assert left==right
   coord=tables(ps)[1];cc=tables(cs)
   for orientation in rt.ORIENTS:
    displayed=rt.orient(''.join(format(x,'X') for x in cipher),orientation);recovered=[int(x,16) for x in rt.orient(displayed,orientation)];assert recovered==cipher
    cell=rt.scan_cell(recovered,orientation,period);assert cell['status']=='unresolved' and not cell['excluded_two_square_bag213'] and cell['high_nibble_positions']==546
    direct={}
    for tr in cell['types']:
     es=rt.graph_from(cipher,ours,tr['kind']);u,v=coord
     survives=all(not(axis(cc,a,tr['kind'][0])==u and axis(cc,b,tr['kind'][1])==v) for a,b in es)
     assert survives and (not es or tr['feasible']);direct[tr['kind']]={'edge_count':len(es),'known_plain_square_symbol1_coordinate':list(coord),'known_coordinate_survives':True,'filter_feasible':tr['feasible']}
    rows.append({'id':f"{'distinct' if distinct else 'same'}|p{period}|{orientation}",'distinct_squares':distinct,'period':period,'orientation':orientation,'plaintext_sha256':hb(plaintext),'cipher_symbols_sha256':hb(bytes(cipher)),'displayed_sha256':hb(displayed.encode()),'block_lengths_sha256':hb(canonical(lengths)),'metadata_sha256':cell['source_index_metadata_sha256'],'typed_oracle_exact':True,'concrete_decrypt_exact':True,'concrete_reencrypt_exact':True,'known_coordinate_checks':direct,'cell_status':cell['status']})
 # Reachable binary negative through scan_cell: p1 high positions cycle all symbols,
 # so RC contains every diagonal edge. Every row/column class pair intersects once.
 neg_cipher=[(i//2)%16 for i in range(1092)];neg_cell=rt.scan_cell(neg_cipher,'forward',1);rc=next(x for x in neg_cell['types'] if x['kind']=='RC')
 assert neg_cell['status']=='excluded' and neg_cell['excluded_two_square_bag213'] and 'RC' in neg_cell['impossible_types']
 assert rc['edge_count']==16 and rc['graph_hex']==format(sum(1<<(16*i+i) for i in range(16)),'064x') and not rc['feasible'] and rc['surviving_first_sets']==0 and rc['checked_first_sets']==1820 and rc['exclusion_certificate']
 neg_square_rows=[]
 for case in range(8):
  ncs=rng.sample(list(range(16)),16);nps=rng.sample(list(range(16)),16);decoded=decrypt(neg_cipher,ncs,nps,1);assert set(decoded[::2])==set(range(16))
  neg_square_rows.append({'case':case,'cipher_square_sha256':hb(bytes(ncs)),'plaintext_square_sha256':hb(bytes(nps)),'decoded_high_symbol_set':sorted(set(decoded[::2]))})
 # Parent-model complete-graph extreme remains a direct model control, not driver reachability.
 full={(a,b) for a in range(16) for b in range(16)};full_record=rt.MODEL_MOD.analyze(full,'RC',4,retain=True);assert not full_record['feasible'] and full_record['checked_first_sets']==1820 and full_record['surviving_first_sets']==0
 # Orientation definitions must match the established names and be involutions.
 sample='123456';orientation_values={o:rt.orient(sample,o) for o in rt.ORIENTS};assert orientation_values=={'forward':'123456','reverse':'654321','byte_reverse':'563412','nibble_swap':'214365'} and all(rt.orient(v,o)==sample for o,v in orientation_values.items())
 return {'identity':IDENTITY,'target_evaluated':False,'canonical_source_bytes_hashed_only':True,'target_ciphertext_extracted':False,'seed':SEED,'scope':'Synthetic fixed-546-byte ASCII positive plants plus one reachable binary negative; same/distinct arbitrary 4x4 squares, five odd periods, four orientations.','source_hashes':{'run_target.py':sha(DRIVER),'driver_controls.py':sha(Path(__file__)),'single_graph_model.py':sha(rt.MODEL),'typed_oracle_controls.py':sha(ORACLE)},'orientation_values':orientation_values,'plants':rows,'plant_count':len(rows),'reachable_binary_negative':{'period':1,'cipher_rule':'cipher[i]=(i//2)%16','cell_status':neg_cell['status'],'impossible_types':neg_cell['impossible_types'],'rc_graph_hex':rc['graph_hex'],'rc_edge_count':rc['edge_count'],'surviving_first_sets':rc['surviving_first_sets'],'checked_first_sets':rc['checked_first_sets'],'exclusion_certificate':rc['exclusion_certificate'],'independent_literal_square_pairs':neg_square_rows,'not_a_valid_text_plant':True},'direct_model_complete_graph_extreme':{'kind':'RC','edges':256,'checked_first_sets':full_record['checked_first_sets'],'surviving_first_sets':0,'feasible':False,'records_sha256':rt.mask_digest(full_record['records']),'driver_reachability_claimed':False},'assertions':{'all_40_plants_exact_roundtrip':len(rows)==40 and all(x['concrete_decrypt_exact'] and x['concrete_reencrypt_exact'] for x in rows),'typed_source_indices_equal_independent_published_oracle':all(x['typed_oracle_exact'] for x in rows),'known_plain_square_coordinate_survives_every_nonempty_graph':all(all(z['known_coordinate_survives'] for z in x['known_coordinate_checks'].values()) for x in rows),'same_and_distinct_squares':{x['distinct_squares'] for x in rows}=={False,True},'all_orientations_and_periods':{x['orientation'] for x in rows}==set(rt.ORIENTS) and {x['period'] for x in rows}=={1,3,31,99,1091},'reachable_scan_cell_exclusion_branch':True,'independent_literal_decrypt_high_symbols_all16':all(x['decoded_high_symbol_set']==list(range(16)) for x in neg_square_rows),'target_ciphertext_not_extracted':True,'no_target_evaluation':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f'refusing existing output: {a.regenerate}')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');path=a.regenerate
 else:path=OUT;assert json.loads(path.read_text())==json.loads(json.dumps(got))
 print(json.dumps({'identity':IDENTITY,'verified':True,'target_evaluated':False,'plants':len(got['plants']),'ledger_sha256':sha(path)},sort_keys=True))
if __name__=='__main__':main()

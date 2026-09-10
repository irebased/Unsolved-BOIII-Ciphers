#!/usr/bin/env python3
"""ASTRA independent read-only verification; no production-model import or crypto."""
import hashlib,json
from pathlib import Path
P=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def load(p,w):
 b=p.read_bytes();assert sha(b)==w,(p,sha(b));return json.loads(b)
a=load(P.parent/'ra_prefix_inventory/target_results.json','448ff7f95d9d07a334439ec4ddca831da5d15173bcba104858aed337f4cd67cb')
r=load(P/'saved_bound_results.json','40db1f8ae0a80153ff0caa9808d2bf2a830eabed2de1b1700da82331b879259f')
t=load(P.parent/'occupancy_screen_controls/threshold_table.json','2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447')
m=load(P.parent/'ra_partial_block_inventory_audit/evidence.json','91c7e7c686f4cf74e9c801d7d7a199b7ac904b0cc51c8a077c6a844d244b1835')['primitive_metadata']
cutoff={x['n']:x['d'] for x in t['rows']}
expected={x['id']:x for x in a['rows'] if x['status']=='ready' and x['primitive'] not in {'RC4','Salsa20'} and x['mode'] in {'ecb','cbc'}}
actual={x['id']:x for x in r['rows']};assert len(expected)==len(actual)==len(r['rows'])==3312;assert expected.keys()==actual.keys()
qlens=[];qds=[];margins=[];cutoffs=[];excluded=0;incomplete=0
for key,x in expected.items():
 y=actual[key];bs=m[x['primitive']]['block_size'];assert bs in (8,16,32)
 b=bytes.fromhex(x['bytes_hex']);assert len(b)==546 and sha(b)==x['sha256'];assert 546%bs==2
 n0=546//bs*bs;assert n0==544
 end=n0
 while end>0 and b[end-1]==0:end-=1
 q=b[:end];mask=0
 for v in q:mask|=1<<v
 D=bin(mask).count('1');L=n0+bs
 every_length=tuple(range(end,L+1));assert all(n in cutoff for n in every_length)
 maxcut=max(cutoff[n] for n in every_length)
 proof=all(D>cutoff[n] for n in every_length)
 checks={'pre':x['pre'],'primitive':x['primitive'],'mode':x['mode'],'block_size':bs,'stored_output_sha256':x['sha256'],'stored_output_D':len(set(b)),
 'fixed_prefix_sha256':sha(b[:n0]),'q_sha256':sha(q),'q_length':end,'q_distinct':D,'padded_length':L,
 'candidate_length_min':end,'candidate_length_max':L,'supported_length_count':len(every_length),'unsupported_length_ranges':[],
 'maximum_supported_threshold':maxcut,'all_candidate_lengths_supported':True,'fully_excluded':proof}
 assert set(y)==set(checks)|{'id'}
 for k,v in checks.items():assert y[k]==v,(key,k,y[k],v)
 excluded+=int(proof);incomplete+=int(not proof);qlens.append(end);qds.append(D);cutoffs.append(maxcut);margins.append(D-maxcut)
summary={'rows':len(actual),'fully_excluded':excluded,'incomplete':incomplete,'unsupported_interval_rows':0,'q_length_min':min(qlens),'q_length_max':max(qlens),'q_distinct_min':min(qds),'q_distinct_max':max(qds)}
assert summary==r['summary'];assert excluded==3312 and incomplete==0
print(json.dumps({'identity':'ASTRA','status':'PASS','new_decryption':False,'verifier_sha256':sha(Path(__file__).read_bytes()),'result_sha256':'40db1f8ae0a80153ff0caa9808d2bf2a830eabed2de1b1700da82331b879259f','summary':summary,'maximum_cutoff':max(cutoffs),'minimum_margin':min(margins),'method':'Independent last-nonzero scan, bitmask distinct count, and comparison at EVERY supported candidate output length for every saved row. No production model imports.'},indent=2,sort_keys=True))

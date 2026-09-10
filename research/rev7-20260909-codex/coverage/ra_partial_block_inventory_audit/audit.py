#!/usr/bin/env python3
"""ASTRA post-hoc accounting of partial ECB/CBC rows in a frozen RA result."""
from __future__ import annotations
import argparse,collections,hashlib,json,re
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
INV=HERE.parent/'ra_prefix_inventory'
RESULT=INV/'target_results.json'
RA=INV/'source/ra'
MODE_RS=RA/'crates/ra-prim/src/mode.rs'
PRIM_RS=RA/'crates/ra-prim/src/prim.rs'
WRAPPER=HERE/'source/mcrypt_wrapper.c'
APP=HERE/'source/app.js'
EXPECTED={
 'target_results.json':'448ff7f95d9d07a334439ec4ddca831da5d15173bcba104858aed337f4cd67cb',
 'mode.rs':'1bcd119703cccf4a644673bdeae0b503d2190a2dff10c072923fa0df57933495',
 'prim.rs':'179c69feb1b3c164bc01effbd6027c73ca41388fe9cae488b186d5f598c7af4d',
 'mcrypt_wrapper.c':'ae134769f33ea4f6f1e42599706d7050670ad33669ce9c8c3fc22d1496f38982',
 'app.js':'c8aa498de890039bab86af507e49b89d382c67594f463691deda427b04059113'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def canon(x):return (json.dumps(x,sort_keys=True,indent=2)+'\n').encode()
def digest_ids(rows):return hashlib.sha256(('\n'.join(sorted(r['id'] for r in rows))+'\n').encode()).hexdigest()
def group(rows,fields):
 c=collections.Counter(tuple(r[f] for f in fields) for r in rows)
 return [{'keys':dict(zip(fields,k)),'count':v} for k,v in sorted(c.items())]
def summary(rows):
 return {'labels':len(rows),'unique_output_sha256':len({r['sha256'] for r in rows}),
  'minimum_distinct_bytes':min(r['distinct_bytes'] for r in rows) if rows else None,
  'occupancy_flags':sum(bool(r['occupancy']['screen_hit']) for r in rows),
  'label_id_sha256':digest_ids(rows)}
def generate():
 files={'target_results.json':RESULT,'mode.rs':MODE_RS,'prim.rs':PRIM_RS,'mcrypt_wrapper.c':WRAPPER,'app.js':APP}
 assert {n:sha(p) for n,p in files.items()}==EXPECTED
 ps=PRIM_RS.read_text(); found=re.findall(r'PrimInfo\s*\{.*?display_name:\s*"([^"]+)".*?block_size:\s*(\d+).*?kind:\s*PrimKind::(Block|Stream)',ps,re.S)
 x=json.loads(RESULT.read_bytes()); scope_prims=set(x['scope']['primitives'])
 meta={n:{'block_size':int(b),'kind':k.lower()} for n,b,k in found if n in scope_prims}
 assert set(meta)==scope_prims and {n for n,v in meta.items() if v['kind']=='stream'}=={'RC4','Salsa20'}
 ready=[r for r in x['rows'] if r['status']=='ready']; assert len(ready)==11700
 strict=[r for r in ready if meta[r['primitive']]['kind']=='block' and r['mode'] in ('ecb','cbc') and r['length']%meta[r['primitive']]['block_size']]
 strictids={r['id'] for r in strict}; remain=[r for r in ready if r['id'] not in strictids]
 assert len(strict)==3312 and len(remain)==8388 and not any(r['occupancy']['screen_hit'] for r in ready)
 c=WRAPPER.read_text(); app=APP.read_text(); mode=MODE_RS.read_text()
 for s in ['#define MODE_CFB8 0','#define MODE_ECB  1','#define MODE_CBC  2','#define MODE_CFB  3','#define MODE_OFB  4','#define MODE_CTR  5','if (dlen % bs != 0) return -1;']:assert s in c
 assert "var MODE_MAP = { cfb8: 0, ecb: 1, cbc: 2, cfb: 3, ofb: 4, ctr: 5 };" in app
 assert 'Mode::Ecb => {' in mode and 'out.chunks_exact_mut(bs)' in mode and 'out.extend_from_slice(&data[whole..]);' in mode
 return {'identity':'ASTRA','target_evaluated':False,'new_decryption':False,'classification':'post_hoc_saved_result_accounting',
  'source_pins':{n:{'sha256':sha(p),'bytes':p.stat().st_size} for n,p in files.items()},
  'input':{'frozen_ready_labels':len(ready),'frozen_exact_output_groups':len(x['exact_output_groups']),'length':546},
  'primitive_metadata':meta,
  'strict_wrapper_rejected_subset':summary(strict)|{'reason':'READY RA block-primitive ECB/CBC rows have nonaligned 546-byte input; the captured C wrapper returns -1 on decrypt when dlen % block_size != 0.','by_pre_cipher_mode':group(strict,['pre','primitive','mode']),'by_primitive_mode':group(strict,['primitive','mode'])},
  'remaining_ready_subset':summary(remain)|{'by_pre_mode':group(remain,['pre','mode'])},
  'screen_check':{'original_ready_flags':0,'removed_subset_flags':0,'remaining_subset_flags':0,'conclusion':'The strict partial-block filter reveals no occupancy flags hidden by those RA-only partial ECB/CBC outputs.'},
  'mode_mapping':[
   {'wasm_code':0,'wrapper_symbol':'MODE_CFB8','libmcrypt_semantics':'cfb8','ra_name':'cfb'},
   {'wasm_code':3,'wrapper_symbol':'MODE_CFB','libmcrypt_semantics':'ncfb (full-block CFB)','ra_name':'ncfb'},
   {'wasm_code':4,'wrapper_symbol':'MODE_OFB','libmcrypt_semantics':'nofb (full-block OFB)','ra_name':'nofb'},
   {'wasm_code':5,'wrapper_symbol':'MODE_CTR','libmcrypt_semantics':'wrapper custom counter mode','ra_name':None}],
  'mode_note':'The old wrapper UI label `ofb` means its full-block OFB implementation (libmcrypt nofb semantics), not byte-feedback OFB8. RA separately names byte-feedback OFB8 as `ofb` and full-block OFB as `nofb`.',
  'limits':['No row was decrypted or rescored. Output hashes and occupancy values are read from the frozen result.','This is compatibility accounting between two implementations, not a new C-wrapper conformance run.','Stream primitives RC4 and Salsa20 are excluded from the rejected subset even when retained RA labels say ECB or CBC, because their mode label is ignored.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();got=generate()
 if a.generate:
  if a.generate.exists():raise SystemExit('refusing existing output')
  a.generate.write_bytes(canon(got));print(a.generate);return
 p=HERE/'evidence.json';assert json.loads(p.read_bytes())==got
 print(json.dumps({'identity':'ASTRA','status':'PASS','ledger_sha256':sha(p),'removed':got['strict_wrapper_rejected_subset']['labels'],'remaining':got['remaining_ready_subset']['labels']},sort_keys=True))
if __name__=='__main__':main()

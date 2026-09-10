#!/usr/bin/env python3
"""Lossless stdlib pack/unpack and structural verifier for the cascade target ledger."""
from __future__ import annotations
import argparse,base64,hashlib,itertools,json,zlib
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];PACK=HERE/'target_results.pack.json';GATE=HERE/'target_gate.json';MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
IDENTITY='ASTRA';FULL_SHA='2eb167a4ec5503a3b27fe84dd4a3a96f781443eade8d78bfefdab9ff01aacf7e';FULL_BYTES=23151009;GATE_SHA='80471b6c6de67bfa07370a5b18c0a024200f6a6b7b5617df79bc5562d9605620';DRIVER_SHA='dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91'
BACKENDS=('aes128','des','blowfish','bfcompat','rc2','twofish','loki97');TRANSFORMS=('forward','full_hex_reverse','byte_reverse','nibble_swap');BLOCK={'aes128':16,'des':8,'blowfish':8,'bfcompat':8,'rc2':8,'twofish':16,'loki97':16};RELAXED={9,10,13,*range(32,127),0xe2,0x80,0x93,0x94,0x98,0x99,0xa6}
def sha_bytes(x):return hashlib.sha256(x).hexdigest()
def sha(path):return sha_bytes(Path(path).read_bytes())
def expected_ids():
 out=set()
 for orient in TRANSFORMS:
  for depth in (1,2,3):
   for layers in itertools.product(BACKENDS,repeat=depth):
    for between in itertools.product(TRANSFORMS,repeat=depth-1):out.add(orient+'|d'+str(depth)+'|'+','.join(layers)+'|'+(','.join(between) if between else '-'))
 return out
def unpack_bytes(pack_path=PACK):
 envelope=json.loads(pack_path.read_text());assert envelope['identity']==IDENTITY and envelope['format']=='zlib-9 + RFC1924 base85 of exact original JSON bytes' and envelope['full_sha256']==FULL_SHA and envelope['full_bytes']==FULL_BYTES
 compressed=base64.b85decode(envelope['payload_base85'].encode('ascii'));assert len(compressed)==envelope['compressed_bytes'] and sha_bytes(compressed)==envelope['compressed_sha256']
 dec=zlib.decompressobj();raw=dec.decompress(compressed,FULL_BYTES+1);assert len(raw)<=FULL_BYTES and dec.eof and not dec.unused_data and not dec.unconsumed_tail and len(raw)==FULL_BYTES and sha_bytes(raw)==FULL_SHA
 return raw,envelope
def geometry(row):
 left=0;right=546
 for i,name in enumerate(row['backends']):
  left=min(left+BLOCK[name],right)
  if i<len(row['interlayer_transforms']) and row['interlayer_transforms'][i] in ('byte_reverse','full_hex_reverse'):left,right=546-right,546-left
 return [left,right]
def verify():
 raw,envelope=unpack_bytes();data=json.loads(raw);assert data['identity']==IDENTITY and data['target_evaluated'] is True and data['status']=='complete'
 gate=json.loads(GATE.read_text());assert sha(GATE)==GATE_SHA and sha(HERE/'run_target.py')==DRIVER_SHA and sha(MDX)==MDX_SHA
 config=data['configuration'];assert config['gate_sha256']==GATE_SHA and config['driver_sha256']==DRIVER_SHA and config['mdx_sha256']==MDX_SHA and gate['artifact_hashes']==config['artifact_hashes'] and gate['scope']==config['scope']
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,rel
 ids=set();depth={1:0,2:0,3:0};classes={};witnesses=0
 for row in data['cases']:
  assert row['identity']==IDENTITY and row['orientation'] in TRANSFORMS and row['depth']==len(row['backends']) and row['depth'] in depth and len(row['interlayer_transforms'])==row['depth']-1
  assert all(x in BACKENDS for x in row['backends']) and all(x in TRANSFORMS for x in row['interlayer_transforms'])
  want=row['orientation']+'|d'+str(row['depth'])+'|'+','.join(row['backends'])+'|'+(','.join(row['interlayer_transforms']) if row['interlayer_transforms'] else '-');assert row['case_id']==want and want not in ids;ids.add(want);depth[row['depth']]+=1
  assert row['known_interval']==geometry(row) and row['known_bytes']==row['known_interval'][1]-row['known_interval'][0] and len(row['known_sha256'])==64
  ep=row['endpoint'];classes[ep['classification']]=classes.get(ep['classification'],0)+1
  assert ep['classification']=='rejected_a105' and ep['accepted'] is False and ep['ending_states']==[] and ep['witness']['reason']=='outside A105' and ep['witness']['byte'] not in RELAXED
  assert ep['witness']['absolute_offset']==row['known_interval'][0]+ep['witness']['relative_offset'] and 0<=ep['witness']['relative_offset']<row['known_bytes'];witnesses+=1
  assert row['candidate_hex'] is None and row['two_iv_full_chain_replays'] is None
 assert ids==expected_ids() and depth=={1:28,2:784,3:21952} and classes=={'rejected_a105':22764} and witnesses==22764
 summary=data['summary'];assert summary['path_endpoints']==summary['unique_case_ids']==22764 and summary['counts_by_depth']=={'1':28,'2':784,'3':21952} and summary['endpoint_classes']=={'rejected_a105':22764,'rejected_fsa_transition':0,'rejected_fsa_terminal':0,'retained':0,'inconclusive_empty':0} and summary['retained_candidates']==summary['empty_inconclusive']==0 and summary['intermediate_rejections_did_not_prune_children']
 print(json.dumps({'identity':IDENTITY,'verified':True,'verification_scope':'lossless byte reconstruction plus artifact, Cartesian ID, interval geometry, summary, and witness structural checks; no second cryptographic target replay','pack_sha256':sha(PACK),'full_sha256':FULL_SHA,'full_bytes':FULL_BYTES,'compressed_bytes':envelope['compressed_bytes'],'cases':len(ids),'witnesses':witnesses},indent=2,sort_keys=True))
def create(source,output):
 if output.exists():raise SystemExit('refusing existing output: '+str(output))
 raw=source.read_bytes();assert len(raw)==FULL_BYTES and sha_bytes(raw)==FULL_SHA;compressed=zlib.compress(raw,9);env={'identity':IDENTITY,'target_evaluated':True,'format':'zlib-9 + RFC1924 base85 of exact original JSON bytes','full_bytes':len(raw),'full_sha256':sha_bytes(raw),'compressed_bytes':len(compressed),'compressed_sha256':sha_bytes(compressed),'payload_base85':base64.b85encode(compressed).decode('ascii')};output.write_text(json.dumps(env,sort_keys=True,separators=(',',':'))+'\n');print(json.dumps({'identity':IDENTITY,'output':str(output),'sha256':sha(output),'compressed_bytes':len(compressed)},indent=2))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--create',type=Path);ap.add_argument('--output',type=Path);ap.add_argument('--unpack',type=Path);a=ap.parse_args()
 if a.create:
  if a.output is None or a.unpack:ap.error('--create requires --output and excludes --unpack')
  create(a.create,a.output)
 elif a.unpack:
  if a.output:ap.error('--unpack excludes --output')
  if a.unpack.exists():raise SystemExit('refusing existing output: '+str(a.unpack))
  raw,_=unpack_bytes();a.unpack.write_bytes(raw);print(json.dumps({'identity':IDENTITY,'output':str(a.unpack),'sha256':sha(a.unpack),'bytes':len(raw)},indent=2))
 else:
  if a.output:ap.error('--output requires --create')
  verify()
if __name__=='__main__':main()

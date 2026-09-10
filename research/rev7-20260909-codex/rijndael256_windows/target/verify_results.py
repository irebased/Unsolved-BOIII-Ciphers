#!/usr/bin/env python3
"""Portable structural and endpoint replay for every packed Rijndael-256 window row."""
from pathlib import Path
import hashlib,json,re,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';GATE=HERE/'target_gate.json'
sys.path.insert(0,str(HERE));import pack_results
IDENTITY='ASTRA';GATE_SHA='a9611eb904ae8575f6b85368f339be69500bae45bd15710abe77d77ee580464d';DRIVER_SHA='e9796cad76be085775e6c0532faf11f1390b0792863d391be2381c965554f416';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
KEYS={n:b'Zombies'+b'\0'*(n-7) for n in (16,24,32)};ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap');MODES=('ecb','cbc')
A105={9,10,13,*range(32,127),0xe2,0x80,0x93,0x94,0x98,0x99,0xa6};P3={0x93,0x94,0x98,0x99,0xa6}
def h(x):return hashlib.sha256(x).hexdigest()
def sha(p):return h(Path(p).read_bytes())
def orient(data,name):
 if name=='forward':return data
 if name=='byte_reverse':return data[::-1]
 if name=='nibble_swap':return bytes(((x&15)<<4)|(x>>4) for x in data)
 if name=='full_hex_reverse':return bytes.fromhex(data.hex()[::-1])
 raise ValueError(name)
def canonical():
 assert sha(MDX)==MDX_SHA;text=MDX.read_text();a=text.index('`83 B57B2')+1;b=text.index('`',a);raw=''.join(text[a:b].split()).upper();assert len(raw)==1092 and h(raw.encode())==TEXT_SHA
 return bytes.fromhex(raw)
def step(state,value):
 if state==0:
  if value in (9,10,13) or 32<=value<=126:return 0
  if value==0xe2:return 1
  return None
 if state==1:return 2 if value==0x80 else None
 if state==2:return 0 if value in P3 else None
 raise AssertionError(state)
def endpoint(data):
 states={0,1,2}
 for i,value in enumerate(data):
  if value not in A105:return {'accepted':False,'classification':'rejected_a105','ending_states':[],'witness':{'byte':value,'offset':i,'reason':'outside A105'}}
  nxt={z for state in states if (z:=step(state,value)) is not None}
  if not nxt:return {'accepted':False,'classification':'rejected_fsa_transition','ending_states':[],'witness':{'byte':value,'offset':i,'prior_states':sorted(states),'reason':'no five-sequence FSA transition'}}
  states=nxt
 return {'accepted':True,'classification':'retained','ending_states':sorted(states),'witness':None}
def regex_cut(data):
 token=re.compile(rb'(?:[\x09\x0a\x0d\x20-\x7e]|\xe2\x80[\x93\x94\x98\x99\xa6])*\Z')
 return any(token.fullmatch(a+data+b) is not None for a in (b'',b'\xe2',b'\xe2\x80') for b in (b'',b'\x80\x93',b'\x93'))
def cid(k,o,m):return f'k{k*8}|{o}|{m}'
def main():
 raw,envelope=pack_results.unpack_bytes();data=json.loads(raw);assert data['identity']==IDENTITY and data['target_evaluated'] is True and data['status']=='complete'
 assert sha(GATE)==GATE_SHA and sha(HERE/'run_target.py')==DRIVER_SHA;gate=json.loads(GATE.read_text());config=data['configuration']
 assert config['gate_sha256']==GATE_SHA and config['driver_sha256']==DRIVER_SHA and config['mdx_sha256']==MDX_SHA and config['canonical_text_sha256']==TEXT_SHA and config['canonical_text_length']==1092
 assert config['artifact_hashes']==gate['artifact_hashes'] and config['scope']==gate['scope']
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,rel
 source=canonical();streams={o:orient(source,o) for o in ORIENTATIONS};expected=[cid(k,o,m) for k in KEYS for o in ORIENTATIONS for m in MODES]
 assert len(data['cells'])==24;seen=[];total=0;classes={'rejected_a105':0,'rejected_fsa_transition':0,'retained':0};regex_negative=0
 for cell in data['cells']:
  k=cell['key_bytes'];o=cell['orientation'];m=cell['mode'];want=cid(k,o,m);assert cell['identity']==IDENTITY and cell['cell_id']==want and cell['key_hex']==KEYS[k].hex();seen.append(want)
  stream=streams[o];assert cell['oriented_input_sha256']==h(stream);window=64 if m=='ecb' else 96;count=547-window
  assert cell['window_bytes']==window and cell['context_rows']==count and cell['all_rows_preserved'] and cell['all_candidates_independent_js_and_regex_replayed']
  assert cell['retained_candidates']==[];local={x:0 for x in classes};rows=cell['rows'];assert len(rows)==count and [x['offset'] for x in rows]==list(range(count))
  for row in rows:
   off=row['offset'];w=stream[off:off+window];assert row['input_window_sha256']==h(w)
   blocks=[bytes.fromhex(x) for x in row['decrypted_blocks_hex']];assert len(blocks)==2 and all(len(x)==32 for x in blocks)
   plain=bytes.fromhex(row['plaintext_hex']);assert len(plain)==64 and plain==blocks[0]+blocks[1]
   want_ep=endpoint(plain);assert row['classification']==want_ep['classification'] and row['accepted']==want_ep['accepted'] and row['ending_states']==want_ep['ending_states'] and row['witness']==want_ep['witness']
   assert regex_cut(plain)==row['accepted'];regex_negative+=not row['accepted'];local[row['classification']]+=1
  assert local==cell['class_counts'];total+=count
  for x,n in local.items():classes[x]+=n
 assert seen==expected and len(set(seen))==24 and total==11208 and classes=={'rejected_a105':11006,'rejected_fsa_transition':202,'retained':0} and regex_negative==11208
 summary=data['summary'];assert summary=={'cells':24,'unique_cell_ids':24,'context_rows':11208,'class_counts':classes,'retained_candidates':0,'all_rows_preserved':True,'all_candidates_independent_js_and_regex_replayed':True}
 assert config['temporary_build']['source_sha256']=='fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821' and config['temporary_build']['command'][-1]=='<temporary-output>'
 print(json.dumps({'identity':IDENTITY,'verified':True,'pack_sha256':sha(pack_results.PACK),'full_sha256':pack_results.FULL_SHA,'full_bytes':pack_results.FULL_BYTES,'cells':24,'context_rows':total,'class_counts':classes,'regex_negative_rows':regex_negative,'verification_scope':'lossless reconstruction; all gate/artifact pins, Cartesian cells, offsets/window hashes, two-block/full-plaintext consistency, and every A105/FSA witness plus independent regex endpoint replay; no second cryptographic enumeration'},indent=2,sort_keys=True))
if __name__=='__main__':main()

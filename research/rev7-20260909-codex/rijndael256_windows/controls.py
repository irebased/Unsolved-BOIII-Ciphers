#!/usr/bin/env python3
"""Synthetic-only controls for Rijndael-256 ECB/CBC known-window scanning."""
from __future__ import annotations
from pathlib import Path
import argparse, hashlib, importlib.util, json, re, subprocess, sys, tempfile
HERE=Path(__file__).resolve().parent
PRIM=HERE.parent/'rijndael256_controls'
LEDGER=HERE/'controls.json'; IDENTITY='ASTRA'; BS=32
KEYS={n:b'Zombies'+b'\0'*(n-7) for n in (16,24,32)}
IVS={'nul':bytes(32),'ascii_zero':b'0'*32,'nonuniform':bytes((29*i+7)&255 for i in range(32))}
ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap')
PINS={
 '../rijndael256_controls/controls.py':'c35dde4e66b4a5633c0b0d14086bb1011ae313448d4e460ef405dd53d29f6cb2',
 '../rijndael256_controls/controls.json':'2e164a7b6091f5a1c76a1863cd45ddb2c919597350ff20e3ce52c131ed9c804c',
 '../rijndael256_controls/build_source.py':'d32cac36412340865b2fd28d8b6437f9c2f508cd229c58881c3285d3e3039961',
 '../rijndael256_controls/js_blocks.js':'ceefc2c2c15b7cb60b07ba14539c1ec99bda682409a728bc2fa04ee4df292f52',
 '../rijndael256_controls/source/rijndael-256.c':'fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821',
 '../rijndael256_controls/source/rijndael.h':'57142416d7b11f6788a10ded626ad426aca430ed5bff34d60b87868feb3fe0e2',
 '../rijndael256_controls/source/aes.js':'c8d6903ff7d6b090b2050f1c59dcf63ee08ac0c084caa11f9912bf5b20f90a8a',
 '../rijndael256_controls/source/COPYING.LIB':'ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532',
 '../rijndael256_controls/source/libdefs.h':'556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e',
 '../rijndael256_controls/source/mcrypt_modules.h':'2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180',
}
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def load(path:Path,name:str):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
engine=load(HERE/'engine.py','rijndael256_window_engine')
def verify_pins():
 for rel,want in PINS.items():
  got=sha(HERE/rel);assert got==want,(rel,got,want)
def orient(data:bytes,name:str)->bytes:
 if name=='forward':return data
 if name=='byte_reverse':return data[::-1]
 if name=='nibble_swap':return bytes(((x&15)<<4)|(x>>4) for x in data)
 if name=='full_hex_reverse':return bytes.fromhex(data.hex()[::-1])
 raise ValueError(name)
def deterministic_bytes(label:str,n:int)->bytes:
 out=b'';i=0
 while len(out)<n:
  out+=hashlib.sha256((label+':'+str(i)).encode()).digest();i+=1
 return out[:n]
def strict64()->bytes:
 x='EN – EM — LEFT ‘ RIGHT ’ ELLIPSIS … '.encode()+b'ALIGNED TEXT.\n'
 return x+b'X'*(64-len(x))
def cbc_encrypt(block,plain:bytes,iv:bytes)->bytes:
 out=[];reg=iv
 for i in range(0,len(plain),BS):
  reg=block(bytes(a^b for a,b in zip(plain[i:i+BS],reg)));out.append(reg)
 return b''.join(out)
def cbc_decrypt(block,cipher:bytes,iv:bytes)->bytes:
 out=[];reg=iv
 for i in range(0,len(cipher),BS):
  c=cipher[i:i+BS];out.append(bytes(a^b for a,b in zip(block(c),reg)));reg=c
 return b''.join(out)
def js_batch(ops:list[dict])->list[bytes]:
 cp=subprocess.run(['node',str(PRIM/'js_blocks.js')],input=json.dumps({'operations':ops}),text=True,capture_output=True,check=True)
 return [bytes.fromhex(x) for x in json.loads(cp.stdout)]
def independent_cut_oracle(data:bytes)->bool:
 token=re.compile(rb'(?:[\x09\x0a\x0d\x20-\x7e]|\xe2\x80[\x93\x94\x98\x99\xa6])*\Z')
 prefixes=(b'',b'\xe2',b'\xe2\x80');suffixes=(b'',b'\x80\x93',b'\x93')
 return any(token.fullmatch(a+data+b) is not None for a in prefixes for b in suffixes)
def source_hashes():
 d={'engine.py':sha(HERE/'engine.py'),'controls.py':sha(Path(__file__)),'README.md':sha(HERE/'README.md')}
 d.update(PINS);return d

def regenerate(out:Path):
 if out.exists():raise FileExistsError(f'refusing to overwrite {out}')
 verify_pins(); sys.path.insert(0,str(PRIM)); pc=load(PRIM/'controls.py','rijndael256_primitive_controls'); builder=load(PRIM/'build_source.py','rijndael256_builder')
 text=strict64();assert len(text)==64 and engine.classify(text)['accepted'] and independent_cut_oracle(text)
 with tempfile.TemporaryDirectory(prefix='rijndael256-windows-') as td:
  lib=Path(td)/'r.dylib';build=builder.build(lib)
  ciphers={n:pc.CPrimitive(lib,key) for n,key in KEYS.items()}
  plants=[]; js_jobs=[]; retained_refs=[]; negative_refs=[]; full_capture=None
  for mode in ('ecb','cbc'):
   for keybytes,key in KEYS.items():
    c=ciphers[keybytes];enc=lambda b,c=c:c.crypt(b);dec=lambda b,c=c:c.crypt(b,True)
    if mode=='ecb': planted=enc(text[:32])+enc(text[32:])
    else:
     p0=b'CBC PREFIX BLOCK IS NOT RETURNED'[:32];assert len(p0)==32
     planted=cbc_encrypt(enc,p0+text,IVS['nonuniform'])
    for orientation in ORIENTATIONS:
     for residue in range(32):
      oriented=bytearray(deterministic_bytes(f'{mode}:{keybytes}:{orientation}:{residue}',546));oriented[residue:residue+len(planted)]=planted
      canonical=orient(bytes(oriented),orientation);assert orient(canonical,orientation)==bytes(oriented)
      capture=(mode=='ecb' and keybytes==16 and orientation=='forward' and residue==0)
      scan=engine.scan(bytes(oriented),mode,dec,collect_all=capture)
      if capture:
       assert len(scan['rows'])==483 and all(len(bytes.fromhex(r['plaintext_hex']))==64 and len(r['decrypted_blocks_hex'])==2 and all(len(bytes.fromhex(b))==32 for b in r['decrypted_blocks_hex']) and ((r['witness'] is None)==r['accepted']) for r in scan['rows'])
       full_capture={'mode':mode,'key_bytes':keybytes,'orientation':orientation,'residue':residue,'row_count':len(scan['rows']),'rows_sha256':hashlib.sha256(json.dumps(scan['rows'],sort_keys=True,separators=(',',':')).encode()).hexdigest(),'every_row_has_exact_two_blocks_full_plaintext_classification_and_witness':True}
       for classification in ('rejected_a105','rejected_fsa_transition'):
        chosen=[r for r in scan['rows'] if r['classification']==classification][:2];assert len(chosen)==2
        for neg in chosen:
         raw=bytes(oriented)[neg['offset']:neg['offset']+64];begin=len(js_jobs)
         js_jobs.extend({'op':'decrypt','key_hex':key.hex(),'data_hex':b.hex()} for b in (raw[:32],raw[32:]))
         negative_refs.append((begin,raw,neg))
      hits=[x for x in scan['retained'] if x['offset']==residue]
      assert len(hits)==1 and bytes.fromhex(hits[0]['plaintext_hex'])==text
      for hit in scan['retained']:
       raw=bytes(oriented)[hit['offset']:hit['offset']+scan['window_bytes']]
       if mode=='ecb': blocks=(raw[:32],raw[32:])
       else:blocks=(raw[32:64],raw[64:96])
       begin=len(js_jobs);js_jobs.extend({'op':'decrypt','key_hex':key.hex(),'data_hex':b.hex()} for b in blocks)
       retained_refs.append((begin,mode,raw,hit))
      plants.append({'mode':mode,'key_bytes':keybytes,'orientation':orientation,'alignment_residue':residue,
       'canonical_sha256':hashlib.sha256(canonical).hexdigest(),'oriented_sha256':hashlib.sha256(oriented).hexdigest(),
       'tested_offsets':scan['tested_offsets'],'class_counts':scan['class_counts'],'retained_offsets':[x['offset'] for x in scan['retained']],
       'known_offset':residue,'known_plaintext_hex':text.hex(),'known_result_exact':True})
  js_out=js_batch(js_jobs);replays=[]
  for begin,mode,raw,hit in retained_refs:
   a,b=js_out[begin:begin+2]
   plain=a+b if mode=='ecb' else bytes(x^y for x,y in zip(a,raw[:32]))+bytes(x^y for x,y in zip(b,raw[32:64]))
   assert plain.hex()==hit['plaintext_hex']
   replays.append([mode,hit['offset'],hashlib.sha256(raw).hexdigest(),hashlib.sha256(plain).hexdigest()])
  negative_replays=[]
  for begin,raw,row in negative_refs:
   plain=js_out[begin]+js_out[begin+1];assert plain.hex()==row['plaintext_hex'] and not independent_cut_oracle(plain)
   witness_offset=row['witness']['offset'];outside=any(x not in engine.A105 for x in plain[:witness_offset+1])
   assert outside==(row['classification']=='rejected_a105')
   negative_replays.append({'offset':row['offset'],'classification':row['classification'],'window_sha256':hashlib.sha256(raw).hexdigest(),
    'plaintext_sha256':hashlib.sha256(plain).hexdigest(),'js_equals_c_full_plaintext':True,'independent_regex_oracle':False,
    'independent_byte_reason':'outside A105' if outside else 'all bytes through rejection offset A105 but invalid five-sequence transition'})
  # Direct CBC all-IV property: same C0,C1,C2 yields identical returned P1||P2 under two external IVs.
  cbc_iv=[]
  for keybytes,c in ciphers.items():
   enc=lambda b,c=c:c.crypt(b);dec=lambda b,c=c:c.crypt(b,True)
   p0=b'CBC PREFIX BLOCK IS NOT RETURNED'[:32];ct=cbc_encrypt(enc,p0+text,IVS['nonuniform'])
   full1=cbc_decrypt(dec,ct,IVS['nonuniform']);full2=cbc_decrypt(dec,ct,IVS['ascii_zero'])
   known=engine.decode_window(ct,0,'cbc',dec)[0]
   assert known==full1[32:]==full2[32:]==text and full1[:32]!=full2[:32]
   cbc_iv.append({'key_bytes':keybytes,'ciphertext_hex':ct.hex(),'iv1_hex':IVS['nonuniform'].hex(),'iv2_hex':IVS['ascii_zero'].hex(),
    'first_plaintext_block_differs':True,'returned_64_bytes_equal':True,'returned_hex':known.hex()})
  boundaries=[]
  cases=[('left_state1',b'\x80\xa6'+b'A'*62),('left_state2',b'\xa6'+b'A'*63),('right_state1',b'A'*63+b'\xe2'),('right_state2',b'A'*62+b'\xe2\x80'),('bad_e2_ascii',b'A'*30+b'\xe2A'+b'A'*32)]
  for name,data in cases:
   row=engine.classify(data);oracle=independent_cut_oracle(data);assert row['accepted']==oracle
   boundaries.append({'name':name,'data_hex':data.hex(),'engine_accepted':row['accepted'],'independent_regex_oracle':oracle,'ending_states':row['ending_states'],'classification':row['classification']})
  assert [x['engine_accepted'] for x in boundaries]==[True,True,True,True,False]
  framing=[]
  for lead,trail in ((0,2),(1,1),(2,0)):
   payload=deterministic_bytes(f'frame:{lead}:{trail}',17*32);frame=b'H'*lead+payload+b'T'*trail
   assert len(frame)==546
   framing.append({'leading_bytes':lead,'aligned_payload_bytes':len(payload),'aligned_blocks':17,'trailing_bytes':trail,'frame_bytes':len(frame),
    'payload_offset':lead,'claim':'explicit framing arithmetic only; no implicit fitting, padding, stripping, or target interpretation'})
  result={'identity':IDENTITY,'target_evaluated':False,'scope':{'stream_bytes':546,'block_bytes':32,'keys':{str(n):k.hex() for n,k in KEYS.items()},
   'modes':{'ecb':{'window_bytes':64,'offsets':483,'returned_bytes':64},'cbc':{'window_bytes':96,'offsets':451,'returned_bytes':64}},
   'orientations':list(ORIENTATIONS),'future_contexts':11208,'endpoint':'A105 plus five-sequence UTF-8 FSA; initial and terminal states {0,1,2} because both ends are cuts',
   'plaintext_condition':'two complete consecutive aligned plaintext blocks under the hypothesized window, not an arbitrary 64-byte substring'},
   'source_hashes':source_hashes(),'build_command':build[:-1]+['<temporary-output>'],'plants':plants,'full_row_capture_control':full_capture,
   'negative_js_replays':negative_replays,
   'retained_replay':{'count':len(replays),'all_independent_js_block_replays_equal':True,'rows_sha256':hashlib.sha256(json.dumps(replays,separators=(',',':')).encode()).hexdigest()},
   'cbc_every_iv_controls':cbc_iv,'boundary_fsa_controls':boundaries,'framing_controls':framing,
   'counts':{'plants':len(plants),'ecb_plants':sum(x['mode']=='ecb' for x in plants),'cbc_plants':sum(x['mode']=='cbc' for x in plants),
    'alignment_residues':len({x['alignment_residue'] for x in plants}),'retained_windows_replayed':len(replays),'negative_windows_replayed':len(negative_replays),'boundary_fsa':len(boundaries),'framing':len(framing)},
   'assertions':{'all_passed':True,'all_32_alignment_residues_both_modes_3keys_4orientations':len(plants)==32*2*3*4,
    'every_known_offset_exact':all(x['known_result_exact'] for x in plants),'every_retained_window_independent_js_replayed':True,'representative_negative_windows_independent_js_regex_replayed':len(negative_replays)==4,
    'cbc_returned_bytes_same_under_two_external_ivs':True,'full_row_capture_path_checked':True,'no_trim_or_unpad':True,'no_target_read_or_evaluation':True}}
 out.parent.mkdir(parents=True,exist_ok=True);out.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n');return result

def verify(path:Path=LEDGER):
 d=json.loads(path.read_text());assert d['identity']==IDENTITY and d['target_evaluated'] is False;verify_pins()
 for rel,want in d['source_hashes'].items():assert sha(HERE/rel)==want,(rel,sha(HERE/rel),want)
 s=d['scope'];assert s['stream_bytes']==546 and s['block_bytes']==32 and s['future_contexts']==11208
 assert s['modes']=={'ecb':{'window_bytes':64,'offsets':483,'returned_bytes':64},'cbc':{'window_bytes':96,'offsets':451,'returned_bytes':64}}
 assert s['orientations']==list(ORIENTATIONS) and s['keys']=={str(n):k.hex() for n,k in KEYS.items()}
 c=d['counts'];assert c=={'plants':768,'ecb_plants':384,'cbc_plants':384,'alignment_residues':32,'retained_windows_replayed':d['retained_replay']['count'],'negative_windows_replayed':4,'boundary_fsa':5,'framing':3}
 ids={(x['mode'],x['key_bytes'],x['orientation'],x['alignment_residue']) for x in d['plants']};assert len(ids)==768
 assert ids=={(m,k,o,r) for m in ('ecb','cbc') for k in KEYS for o in ORIENTATIONS for r in range(32)}
 for x in d['plants']:
  assert x['tested_offsets']==(483 if x['mode']=='ecb' else 451) and x['known_offset']==x['alignment_residue'] and x['known_result_exact']
  assert x['known_offset'] in x['retained_offsets'] and len(bytes.fromhex(x['known_plaintext_hex']))==64
  assert sum(x['class_counts'].values())==x['tested_offsets'] and x['class_counts']['retained']==len(x['retained_offsets'])
 f=d['full_row_capture_control'];assert f['row_count']==483 and f['mode']=='ecb' and f['key_bytes']==16 and f['orientation']=='forward' and f['residue']==0 and f['every_row_has_exact_two_blocks_full_plaintext_classification_and_witness']
 assert re.fullmatch(r'[0-9a-f]{64}',f['rows_sha256'])
 assert len(d['negative_js_replays'])==4 and {x['classification'] for x in d['negative_js_replays']}=={'rejected_a105','rejected_fsa_transition'}
 assert all(x['js_equals_c_full_plaintext'] and x['independent_regex_oracle'] is False for x in d['negative_js_replays'])
 assert {x['independent_byte_reason'] for x in d['negative_js_replays']}=={'outside A105','all bytes through rejection offset A105 but invalid five-sequence transition'}
 assert d['retained_replay']['all_independent_js_block_replays_equal'] and d['retained_replay']['count']==sum(len(x['retained_offsets']) for x in d['plants'])
 assert {x['key_bytes'] for x in d['cbc_every_iv_controls']}==set(KEYS) and all(x['first_plaintext_block_differs'] and x['returned_64_bytes_equal'] and len(bytes.fromhex(x['returned_hex']))==64 for x in d['cbc_every_iv_controls'])
 assert [x['engine_accepted'] for x in d['boundary_fsa_controls']]==[True,True,True,True,False] and all(x['engine_accepted']==x['independent_regex_oracle'] for x in d['boundary_fsa_controls'])
 assert [(x['leading_bytes'],x['trailing_bytes'],x['frame_bytes']) for x in d['framing_controls']]==[(0,2,546),(1,1,546),(2,0,546)]
 assert d['assertions']=={'all_passed':True,'all_32_alignment_residues_both_modes_3keys_4orientations':True,'every_known_offset_exact':True,'every_retained_window_independent_js_replayed':True,'representative_negative_windows_independent_js_regex_replayed':True,'cbc_returned_bytes_same_under_two_external_ivs':True,'full_row_capture_path_checked':True,'no_trim_or_unpad':True,'no_target_read_or_evaluation':True}
 return d

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();d=regenerate(a.regenerate) if a.regenerate else verify()
 print(json.dumps({'identity':IDENTITY,'status':'passed','counts':d['counts'],'ledger':str(a.regenerate or LEDGER)},sort_keys=True))
if __name__=='__main__':main()

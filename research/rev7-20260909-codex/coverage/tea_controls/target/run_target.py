#!/usr/bin/env python3
"""Inert exact 160-cell TEA driver; target evaluation requires a root-created gate."""
import argparse,hashlib,json,os,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;PKG=HERE.parent;ROOT=HERE.parents[4]
sys.path.insert(0,str(PKG));import model
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';G_SHA='c2abbfb1160cb78d4b5f7e39c337a899d739192c8a0f35f34cd877243ddc65c8'
OUT=HERE/'target_results.json';TMP=HERE/'target_results.json.tmp';GATE=HERE/'target_gate.json'
ORIENTATIONS=('forward','full_hex_reverse','byte_pair_reverse','nibble_swap','visible_token_reverse');PACKINGS=('be','le');KEYS=('Zombies','ZOMBIES');IVS=('null','ascii0');MODES=('cfb8','ncfb','ofb','ctr')
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def scope():return {'identity':'ASTRA','cells':160,'orientations':list(ORIENTATIONS),'packings':list(PACKINGS),'keys':list(KEYS),'key_derivation':'NUL-pad to16','ivs':list(IVS),'modes':list(MODES),'primitive':'TEA','cycles':32,'block_bytes':8,'input_hex_symbols':1092,'output_bytes':546,'retain_all_outputs':True}
def chunks_left(s,w=5):return [s[i:i+w] for i in range(0,len(s),w)]
def oriented(hextext,tokens):
 pairs=[hextext[i:i+2] for i in range(0,len(hextext),2)]
 d={'forward':hextext,'full_hex_reverse':hextext[::-1],'byte_pair_reverse':''.join(reversed(pairs)),'nibble_swap':''.join(x[::-1] for x in pairs),'visible_token_reverse':''.join(reversed(tokens))}
 assert tuple(d)==ORIENTATIONS and all(len(v)==1092 for v in d.values());return d
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 t=MDX.read_text();a=t.index('`83 B57B')+1;b=t.index('`',a);m=''.join(t[a:b].split()).upper()
 raw=next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'];tokens=raw.upper().split();d=''.join(tokens)
 assert m==d and len(d)==1092 and hashlib.sha256(d.encode()).hexdigest()==TEXT_SHA and list(map(len,tokens))==[2]+[5]*218
 o=oriented(d,tokens);assert hashlib.sha256(o['visible_token_reverse'].encode()).hexdigest()==G_SHA
 return o
def endpoint(b):
 hist=[0]*256
 for x in b:hist[x]+=1
 try:b.decode('utf-8');utf8=True
 except UnicodeDecodeError:utf8=False
 allowed165=set([9,10,13]+list(range(32,127))+list(range(128,192))+list(range(194,245)))
 return {'length':len(b),'sha256':hashlib.sha256(b).hexdigest(),'histogram':hist,'distinct_bytes':sum(x>0 for x in hist),'valid_utf8':utf8,'bag165':all(x in allowed165 for x in b),'ascii_text':all(x in (9,10,13) or 32<=x<=126 for x in b)}
def execute(ciphertext,orientation,packing,keyname,ivname,mode_name):
 key=keyname.encode().ljust(16,b'\0');iv=bytes(8) if ivname=='null' else b'0'*8;pt=model.crypt(ciphertext,key,iv,mode_name,packing,True)
 return {'id':f'{orientation}|{packing}|{keyname}|{ivname}|{mode_name}','orientation':orientation,'packing':packing,'key':keyname,'key_hex':key.hex(),'iv':ivname,'iv_hex':iv.hex(),'mode':mode_name,'ciphertext_sha256':hashlib.sha256(ciphertext).hexdigest(),'plaintext_hex':pt.hex()}|endpoint(pt)
def gate():
 g=json.loads(GATE.read_text());assert g['identity']=='ASTRA' and g['authorized'] is True and g['target_evaluated'] is False and g['scope']==scope() and 'ASTRA' in g['fable_reference'];assert g['driver_sha256']==sha(__file__) and g['model_sha256']==sha(PKG/'model.py') and g['controls_sha256']==sha(PKG/'controls.json') and g['controls_source_sha256']==sha(PKG/'controls.py') and g['mdx_sha256']==MDX_SHA and g['dataset_sha256']==DATA_SHA and g['canonical_sha256']==TEXT_SHA;return g
def main(run=False):
 if not run:print(json.dumps({'identity':'ASTRA','target_evaluated':False,'scope':scope(),'gate_present':GATE.exists()},sort_keys=True,indent=2));return
 gate();assert not OUT.exists() and not TMP.exists(),'refuse existing output/tmp';oo=canonical();rows=[]
 for orientation in ORIENTATIONS:
  ct=bytes.fromhex(oo[orientation])
  for packing in PACKINGS:
   for key in KEYS:
    for iv in IVS:
     for mode in MODES:rows.append(execute(ct,orientation,packing,key,iv,mode))
 assert len(rows)==160 and len({r['id'] for r in rows})==160
 out={'identity':'ASTRA','target_evaluated':True,'status':'complete','scope':scope(),'configuration':{'gate_sha256':sha(GATE),'driver_sha256':sha(__file__),'model_sha256':sha(PKG/'model.py'),'controls_sha256':sha(PKG/'controls.json'),'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'canonical_sha256':TEXT_SHA,'g_sha256':G_SHA},'rows':rows,'summary':{'rows':160,'valid_utf8':sum(r['valid_utf8'] for r in rows),'bag165':sum(r['bag165'] for r in rows),'ascii_text':sum(r['ascii_text'] for r in rows),'min_distinct':min(r['distinct_bytes'] for r in rows),'max_distinct':max(r['distinct_bytes'] for r in rows)}}
 TMP.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');os.replace(TMP,OUT);print(json.dumps({'status':'complete','sha256':sha(OUT),'summary':out['summary']},sort_keys=True))
if __name__=='__main__':
 a=argparse.ArgumentParser();a.add_argument('--run-target',action='store_true');x=a.parse_args();main(x.run_target)

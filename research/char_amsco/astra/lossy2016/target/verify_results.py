#!/usr/bin/env python3
"""Independent bounded replay of each saved empty-frontier certificate."""
from pathlib import Path
import argparse,hashlib,json,math,sys
from Crypto.Cipher import AES,DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];IDENTITY='ASTRA';RESULT_SHA='1bc9a98a2af2f6d3f2f9c5c2adde5c87c78f7327840a8de7ba39407cf4676995';GATE_SHA='da753b01353e65fc5d81e6905ab5a0b9747be0091fbbc6c7bd0a20336f24f9a7';DRIVER_SHA='036ab0f597906ca90699d63f4ea42033030e21a1fca28476e2746b735144ae4c';ALLOWED=bytes([32]+list(range(65,91)));ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap');CIPHERS=('des','aes128');IVS=('nul','ascii0')
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def orient(s,n):
 if n=='forward':return s
 if n=='full_hex_reverse':return s[::-1]
 ps=[s[i:i+2] for i in range(0,len(s),2)]
 if n=='byte_reverse':return ''.join(reversed(ps))
 if n=='nibble_swap':return ''.join(x[::-1] for x in ps)
 raise AssertionError(n)
def masks(obs):
 rows=273;v=[0]*819;m=[0]*819
 for r in range(rows):
  a=obs[2*r:2*r+2];b=obs[546+2*r:546+2*r+2];v[3*r]=int(b,16);m[3*r]=255;v[3*r+1]=int(a[0],16);m[3*r+1]=15;v[3*r+2]=int(a[1],16)<<4;m[3*r+2]=240
 return bytes(v),bytes(m)
def primitive(c):
 if c=='des':return DES.new(b'Zombies'+bytes(1),DES.MODE_ECB),8,b'Zombies'+bytes(1)
 return AES.new(b'Zombies'+bytes(9),AES.MODE_ECB),16,b'Zombies'+bytes(9)
def iv(c,n):return bytes(primitive(c)[1]) if n=='nul' else b'0'*primitive(c)[1]
def emit(ct):
 s=ct.hex().upper();rs=[s[i:i+6] for i in range(0,len(s),6)];return ''.join(x[3:5] for x in rs)+''.join(x[0:2] for x in rs)
def replay(cell,canonical):
 obs=orient(canonical,cell['orientation']);assert hb(obs.encode())==cell['observed_sha256'];vals,ms=masks(obs);e,bs,key=primitive(cell['cipher']);front=[(iv(cell['cipher'],cell['iv']),b'',b'')];counts=[];calls=0;accepted=0;failure=[]
 for pos,(v,m) in enumerate(zip(vals,ms)):
  nxt=[]
  for reg,pt,ct in front:
   k=e.encrypt(reg)[0];calls+=1;candidates=[]
   if m==255:
    pairs=[(v,v^k)]
   else:pairs=[(p^k,p) for p in ALLOWED]
   for c,p in pairs:
    ok=(p in ALLOWED and c&m==v&m);candidates.append({'plaintext_byte':p,'ciphertext_byte':c,'mask_match':bool(ok)})
    if ok:nxt.append((reg[1:]+bytes([c]),pt+bytes([p]),ct+bytes([c])))
   if not nxt:failure.append({'register_hex':reg.hex(),'keystream_byte':k,'observed_value':v,'observed_mask':m,'candidates':candidates})
  accepted+=len(nxt);counts.append(len(nxt));front=nxt
  if not front:break
 assert counts==cell['frontier_counts'] and len(counts)==cell['stopped_after_bytes'] and calls==cell['block_calls'] and accepted==cell['accepted_states'] and max(counts,default=1)==cell['max_frontier'] and not cell['solutions']
 assert counts[-1]==0 and failure
 return {'id':cell['id'],'first_empty_after_bytes':len(counts),'failure_offset':len(counts)-1,'frontier_counts':counts,'failing_states':failure,'all_failed_candidates_retained':True}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write-verification',type=Path);a=ap.parse_args();rp=HERE/'target_results.json';gp=HERE/'target_gate.json';assert sha(rp)==RESULT_SHA and sha(gp)==GATE_SHA and sha(HERE/'run_target.py')==DRIVER_SHA
 result=json.loads(rp.read_text());gate=json.loads(gp.read_text());assert result['identity']==IDENTITY and result['target_evaluated'] and result['configuration']['gate_sha256']==GATE_SHA and result['configuration']['driver_sha256']==DRIVER_SHA
 assert set(gate['artifact_hashes'])==set(result['configuration']['artifact_hashes'])
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want
 mdx=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';t=mdx.read_text();i=t.index('`83 B57B2')+1;j=t.index('`',i);canonical=''.join(t[i:j].split()).upper();assert hb(canonical.encode())==result['configuration']['canonical_text_sha256']
 expected=[f'{o}|{c}|{v}' for o in ORIENTS for c in CIPHERS for v in IVS];assert [x['id'] for x in result['cells']]==expected
 checks=[replay(c,canonical) for c in result['cells']];assert result['summary']=={'complete_contexts':16,'incomplete_contexts':0,'solutions':0} and all(c['complete'] and c['capped_reason'] is None for c in result['cells'])
 out={'identity':IDENTITY,'target_evaluated':True,'verification_kind':'independent bounded first-empty-frontier replay; no full target rerun','result_sha256':RESULT_SHA,'gate_sha256':GATE_SHA,'driver_sha256':DRIVER_SHA,'cells':checks,'summary':{'cells':16,'all_complete':True,'solutions':0,'failure_offsets':{str(k):sum(x['failure_offset']==k for x in checks) for k in sorted({x['failure_offset'] for x in checks})}}}
 if a.write_verification:
  if a.write_verification.exists():raise SystemExit('refusing existing output')
  a.write_verification.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
 else:
  frozen=json.loads((HERE/'verification.json').read_text());assert frozen==out;print(json.dumps({'identity':IDENTITY,'status':'PASS','result_sha256':RESULT_SHA,'cells':16},sort_keys=True))
if __name__=='__main__':main()

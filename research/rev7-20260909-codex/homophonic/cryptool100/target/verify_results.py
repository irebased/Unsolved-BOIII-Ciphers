#!/usr/bin/env python3
"""Portable structural/content replay of saved CrypTool100 results; no target enumeration."""
from pathlib import Path
import hashlib,json,math,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];sys.path.insert(0,str(HERE));import pack_results as pack
IDENTITY='ASTRA';RESULT_SHA='426a5be079cf553ba657e3bb3f9d4e8153ee15422efc0e8793e1840249dcac39';RESULT_LEN=67783676;SUMMARY_SHA='a1f04beb731abc2d3f4c9557bb82fa345e6ebf128599f66e33e07b08b8e9beec';GATE_SHA='7e4abe97633b97442ff8a6c807e5efd6fa80c4416717594847e7f8bff3cfb448';DRIVER_SHA='e76c3da624a5fef003ca8853fa3466d826c7afaf143f3606810ca2e3ee8013e0';PACK_SHA='625517b3832a7a14c42d90ff9cb1c7fca42d7abe571561727ab5c017bb89f3d8'
MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
HEX=('forward','full_hex_reverse','byte_reverse','nibble_swap');DEC=('identity','digit_reverse','pair_reverse','swap_within_pair');A=tuple(x for x in range(1,100) if math.gcd(x,100)==1);ALLOC=(6,2,3,5,16,2,3,4,7,1,1,3,4,9,3,1,1,7,7,6,4,1,1,1,1,1);ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZ'
def h(b):return hashlib.sha256(b).hexdigest()
def hp(p):return h(Path(p).read_bytes())
def ho(s,n):
 if n=='forward':return s
 if n=='full_hex_reverse':return s[::-1]
 ps=[s[i:i+2] for i in range(0,len(s),2)]
 if n=='byte_reverse':return ''.join(reversed(ps))
 if n=='nibble_swap':return ''.join(x[::-1] for x in ps)
 raise AssertionError(n)
def do(s,n):
 if n=='identity':return s
 if n=='digit_reverse':return s[::-1]
 ps=[s[i:i+2] for i in range(0,len(s),2)]
 if n=='pair_reverse':return ''.join(reversed(ps))
 if n=='swap_within_pair':return ''.join(x[::-1] for x in ps)
 raise AssertionError(n)
def recover(raw,dn,hn):
 x=ho(raw,hn);m=str(int(x,16));e=('0'+m) if len(m)%2 else m;return do(e,dn)
def decoder(a,b):
 codes=[f'{a*(t+b)%100:02d}' for t in range(100)];d={};i=0
 for ch,n in zip(ALPHA,ALLOC):
  for c in codes[i:i+n]:d[c]=ch
  i+=n
 assert len(d)==100;return d
def main():
 assert hp(HERE/'results.pack.json')==PACK_SHA and hp(HERE/'target_summary.json')==SUMMARY_SHA and hp(HERE/'target_gate.json')==GATE_SHA and hp(HERE/'run_target.py')==DRIVER_SHA
 raw=pack.unpack_obj(json.loads((HERE/'results.pack.json').read_text()));assert len(raw)==RESULT_LEN and h(raw)==RESULT_SHA
 mdx=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';data=ROOT/'lavender/src/data/ciphers/revelations.json';assert hp(mdx)==MDX_SHA and hp(data)==DATA_SHA
 text=mdx.read_text();i=text.index('`83 B57B2')+1;j=text.index('`',i);canonical=''.join(text[i:j].split()).upper();assert h(canonical.encode())==TEXT_SHA
 rec=next(x for x in json.loads(data.read_text()) if x['id']=='rev7');assert ''.join(rec['ciphertext'].split()).upper()==canonical
 summary=json.loads((HERE/'target_summary.json').read_text());gate=json.loads((HERE/'target_gate.json').read_text());assert gate['driver_sha256']==DRIVER_SHA and gate['mdx_sha256']==MDX_SHA and gate['canonical_text_sha256']==TEXT_SHA and gate['dataset_sha256']==DATA_SHA
 assert set(gate['artifact_hashes'])==set(summary['configuration']['artifact_hashes'])
 for rel,x in gate['artifact_hashes'].items():assert hp(ROOT/rel)==x
 lines=raw.splitlines();assert len(lines)==64001;header=json.loads(lines[0]);assert header['identity']==IDENTITY and header['record']=='header' and header['target_evaluated'] and header['gate_sha256']==GATE_SHA and header['driver_sha256']==DRIVER_SHA
 path_meta={x['id']:x for x in summary['aggregate']['paths']};tops={k:[] for k in path_meta};expected=[];n=0
 for hn in HEX:
  for dn in DEC:
   pid=f'h={hn}|d={dn}';codes=recover(canonical,dn,hn);pm=path_meta[pid];assert pm['code_stream']==codes and pm['code_stream_sha256']==h(codes.encode()) and pm['digits']==len(codes) and pm['rows']==4000
   pairs=[codes[i:i+2] for i in range(0,len(codes),2)]
   for a in A:
    dd=decoder(a,0) # b changes below; object reset intentionally
    for b in range(100):
     r=json.loads(lines[n+1]);eid=f'{pid}|a={a:02d}|b={b:02d}';assert r['identity']==IDENTITY and r['record']=='candidate' and r['id']==eid and r['hex_orientation']==hn and r['decimal_orientation']==dn and r['a']==a and r['b']==b
     plain=r['plaintext'];assert len(plain)==r['letters'] and set(plain)<=set(ALPHA) and h(plain.encode())==r['plaintext_sha256'] and r['observed_codes_valid_for_board'] is True and r['exact_integer_reencryption'] is True
     dmap=decoder(a,b);assert plain==''.join(dmap[c] for c in pairs)
     assert isinstance(r['score_per_tetragram'],float) and math.isfinite(r['score_per_tetragram']);tops[pid].append(r);n+=1
 assert n==64000 and summary['aggregate']['rows']==64000 and summary['record_count']==64001 and summary['result_sha256']==RESULT_SHA and summary['result_bytes']==RESULT_LEN
 for pid,rows in tops.items():
  best=sorted(rows,key=lambda r:(-r['score_per_tetragram'],r['a'],r['b']))[:20]
  compact=[{k:r[k] for k in ('id','a','b','score_per_tetragram','plaintext_sha256','plaintext')} for r in best]
  assert compact==summary['aggregate']['top20_by_path'][pid]
 print(json.dumps({'identity':IDENTITY,'status':'PASS','rows':n,'paths':len(tops),'result_sha256':RESULT_SHA,'verification':'saved-byte reconstruction, Cartesian IDs, source pins, independent board decode, plaintext hashes, and stored top-20 ordering; no second target enumeration'},sort_keys=True))
if __name__=='__main__':main()

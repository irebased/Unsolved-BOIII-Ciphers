#!/usr/bin/env python3
import hashlib,json,sys,re
from pathlib import Path
from Crypto.Cipher import AES,DES,Blowfish
HERE=Path(__file__).resolve().parent; R=HERE.parents[1]; sys.path[:0]=[str(R/'stream_csp'),str(R/'hex_cfb'),str(R/'stream_csp_compat')]
import prototype,compat_stream
D=R/'stream_csp'; C=R/'stream_csp_compat'; mdx=R.parent.parent/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
DEPS={'rev7_mdx':'085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91','prototype.py':'416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b','compat_stream.py':'f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c'}
OLD={9,10,13}|set(range(32,127))|{226,128,147,148,152,153}; NEW=OLD|{166}; N=546
PATHS={'stream_target':D/'target_results.json','stream_ledger':D/'witness_verification.json','compat_target':C/'target_results.json','compat_ledger':C/'verification.json'}
EXPECTED={'stream_target':'f1d9024065f82e75479c4e03f1c871f9c2e0c661e63c6a42cb6da6594addde87','stream_ledger':'07e61bdfbc777e43a36902720ef70b295a117953707653dc97060df372bf2c1c','compat_target':'598dfa8ec497321f62f1b4f445de4f642f755ef0fb51c9d2164c708145aad7f2','compat_ledger':'1937e53cdbb0487e8ff95326f3a1a131d7402eb3374d0556030f2508ef2d35d6'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
actual={k:sha(v) for k,v in PATHS.items()}; assert actual==EXPECTED
assert sha(mdx)==DEPS['rev7_mdx'] and sha(R/'hex_cfb/prototype.py')==DEPS['prototype.py'] and sha(C/'compat_stream.py')==DEPS['compat_stream.py']
text=mdx.read_text(); a=text.index('`83 B57B2')+1; b=text.index('`',a); raw=''.join(text[a:b].split()).upper(); assert len(raw)==1092
orients=prototype.orientations(raw)
def stdks(cipher,mode,iv):
 key={'aes128':b'Zombies'.ljust(16,b'\0'),'blowfish':b'Zombies','des':b'Zombies'.ljust(8,b'\0')}[cipher]; mod={'aes128':AES,'blowfish':Blowfish,'des':DES}[cipher]; e=mod.new(key,mod.MODE_ECB); reg=iv; out=bytearray()
 if mode=='ofb8':
  for _ in range(N): k=e.encrypt(reg)[0];out.append(k);reg=reg[1:]+bytes([k])
 else:
  while len(out)<N: reg=e.encrypt(reg);out.extend(reg)
 return bytes(out[:N])
def occurrences(display,ks):
 pairs={}
 for i in range(N):pairs.setdefault(display[2*i:2*i+2],[]).append(i)
 out=[]
 for pair,pos in sorted(pairs.items()):
  if len(pos)<2:continue
  surv=[c for c in range(256) if all((c^ks[i]) in NEW for i in pos)]
  if not surv: out.append({'display_pair':pair,'positions':pos,'keystream_bytes':[ks[i] for i in pos],'survivors_expanded':[]})
 return out
stream=json.loads(PATHS['stream_target'].read_text()); compat=json.loads(PATHS['compat_target'].read_text()); rows=[]
for dataset,d in [('stream_csp',stream),('stream_csp_compat',compat)]:
 for c in d['cells']:
  if dataset=='stream_csp':
   iv=bytes.fromhex(c['iv_hex']); ks=stdks(c['cipher'],c['mode'],iv)
  else:
   block=compat_stream.load_block(); iv=bytes.fromhex(c['iv_hex']); ks=compat_stream.keystream(c['mode'],iv,N,block)
  kh=sha_bytes=hashlib.sha256(ks).hexdigest(); assert kh==c['keystream_sha256'],(dataset,c['cipher'],c['mode'],c['iv_kind'],c['orientation'],kh,c['keystream_sha256'])
  display=orients[c['orientation']]; w=c.get('unrestricted_fixed_byte_witness'); count=(dataset=='stream_csp' and c['cipher']=='blowfish' and c['iv_kind']=='nul' and w is None)
  if count: continue
  fixed=[x for x in range(256) if w and all((x^k) in NEW for k in w['keystream_bytes'])]
  final=occurrences(display,ks)
  rows.append({'dataset':dataset,'cipher':c['cipher'],'mode':c['mode'],'iv_kind':c['iv_kind'],'orientation':c['orientation'],'key_hex':c['key_hex'],'iv_hex':c['iv_hex'],'keystream_sha256':kh,'original_witness':w,'original_witness_expanded_survivors':fixed,'all_repeated_pair_empty_support_under_expanded_set':final,'old_short_witness_lost':bool(fixed),'crypto_recomputed':True,'independent_cipher_implementation':dataset=='stream_csp'})
assert len(rows)==92 and all(x['all_repeated_pair_empty_support_under_expanded_set'] for x in rows)
for x in rows:
 x['representative_regenerated_contradiction']=x['all_repeated_pair_empty_support_under_expanded_set'][0]
 x['total_contradictory_pairs']=len(x['all_repeated_pair_empty_support_under_expanded_set'])
 del x['all_repeated_pair_empty_support_under_expanded_set']
ledger=json.loads(PATHS['stream_ledger'].read_text()); counts=[]
for x in ledger['rows']:
 if x['kind']!='constant_stream_distinct_byte_count': continue
 assert x['cipher']=='blowfish' and x['mode']=='ofb8' and x['iv_kind']=='nul' and x['keystream_byte']==0
 match=next(c for c in stream['cells'] if c['cipher']=='blowfish' and c['mode']=='ofb8' and c['iv_kind']=='nul' and c['orientation']==x['orientation'] and c.get('unrestricted_fixed_byte_witness') is None)
 zks=stdks('blowfish','ofb8',bytes.fromhex(match['iv_hex'])); assert zks==bytes(N) and hashlib.sha256(zks).hexdigest()==match['keystream_sha256']
 disp=orients[x['orientation']]; distinct=len(set(disp[i:i+2] for i in range(0,len(disp),2))); assert distinct==226 and distinct==x['distinct_display_bytes']
 counts.append({'dataset':'stream_csp','cipher':x['cipher'],'mode':x['mode'],'iv_kind':x['iv_kind'],'orientation':x['orientation'],'keystream_sha256':match['keystream_sha256'],'distinct_display_bytes':distinct,'allowed_expanded':len(NEW),'bijection_impossible':distinct>len(NEW)})
assert len(counts)==4 and all(x['bijection_impossible'] for x in counts)
out={'identity':'ASTRA','target_evaluated':True,'evaluation_kind':'hash-matched stream reconstruction plus arithmetic witness regeneration','crypto_recomputed':True,'prior_input_hashes':actual,'dependency_hashes':DEPS,'allowlists':{'old_size':len(OLD),'expanded_size':len(NEW),'added':'A6'},'fixed_byte_witnesses':rows,'fixed_count':len(rows),'old_short_witness_lost_count':sum(bool(x['original_witness_expanded_survivors']) for x in rows),'unresolved_after_regeneration_count':sum(not bool(x['representative_regenerated_contradiction']) for x in rows),'total_contradictory_pairs':sum(x['total_contradictory_pairs'] for x in rows),'bijection_count_proofs':counts,'bijection_count':4,'reconstruction_scope':'AES/DES/Blowfish PyCryptodome ECB OFB8/fullblock; Blowfish-compat uses the previously independently verified compat_stream block recurrence; every generated stream SHA was matched to its target cell before arithmetic checks.'}
(HERE/'extended_result.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(json.dumps({'identity':'ASTRA','fixed_count':92,'bijection_count':4,'old_short_witness_lost_count':out['old_short_witness_lost_count'],'unresolved_after_regeneration_count':out['unresolved_after_regeneration_count'],'result_sha256':sha(HERE/'extended_result.json')},indent=2))

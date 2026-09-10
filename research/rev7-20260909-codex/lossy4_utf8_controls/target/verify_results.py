#!/usr/bin/env python3
"""Independent read-only replay of saved zero-result prefix certificates."""
from pathlib import Path
from functools import lru_cache
import argparse,hashlib,itertools,json
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];RESULT=HERE/'target_results.json';CERT=HERE/'independent_zero_certificates.json';GATE=HERE/'target_gate.json';IDENTITY='ASTRA'
RESULT_SHA='c409b9ae4aafb3093694f615075f180d828ef6ec994f3719bcf612c84d44f690';GATE_SHA='c5908da398b3929adc218ebb5da8b79a44b5caedc4b46067f8ded003087d9c8f';DRIVER_SHA='828b43e45f0267dd0bd2bd6ee1c105c6c068cab6020c3cd2a665398c18cc8983';MDX_SHA='085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91';DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c';KEY=b'Zombies\0';ORIENTATIONS=('forward','full_hex_reverse','byte_reverse','nibble_swap')
CODEPOINTS=(9,10,13,*range(0x20,0x7f),*range(0xa0,0x100),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
WORDS=tuple(chr(cp).encode('utf-8') for cp in CODEPOINTS);WORD_SET=frozenset(WORDS);PREFIX_SET=frozenset(w[:i] for w in WORDS for i in range(len(w)));BOUNDARY=b'';INITIAL=frozenset(PREFIX_SET)
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def step_one(state,b):
 candidate=state+bytes((b,))
 if candidate in WORD_SET:return BOUNDARY
 if candidate in PREFIX_SET:return candidate
 return None
def step(states,b):return frozenset(x for state in states if (x:=step_one(state,b)) is not None)
def orient(text,name):
 if name=='forward':return text
 if name=='full_hex_reverse':return text[::-1]
 pairs=[text[i:i+2] for i in range(0,len(text),2)]
 if name=='byte_reverse':return ''.join(reversed(pairs))
 if name=='nibble_swap':return ''.join(x[::-1] for x in pairs)
 raise ValueError(name)
def source_indices(length,key):
 rows={};pos=cell=0;size=2
 while pos<length:
  take=min(size,length-pos);row=cell//4;col=cell%4;rows.setdefault(row,{})[int(key[col])]=tuple(range(pos,pos+take));pos+=take;cell+=1;size=3-size
 out=[]
 for label in range(1,5):
  for row in range(max(rows)+1):out.extend(rows.get(row,{}).get(label,()))
 return tuple(out)
def reconstruct(observed,nbytes,indices):
 vals=bytearray(nbytes);masks=bytearray(nbytes)
 for ch,index in zip(observed,indices):
  nib=int(ch,16);j=index//2
  if index&1:vals[j]|=nib;masks[j]|=15
  else:vals[j]|=nib<<4;masks[j]|=240
 return bytes(vals),bytes(masks)
def replay(observed,indices,saved):
 vals,masks=reconstruct(observed,655,indices);domains=[tuple(c for c in range(256) if (c&m)==(v&m)) for v,m in zip(vals[:8],masks[:8])];total=1
 for x in domains:total*=len(x)
 assert total==saved['initial_registers_total'];e=DES.new(KEY,DES.MODE_ECB);counts=[0]*647;calls=accepted=maxlive=terminals=0;dist={};digest=hashlib.sha256();root_count=0
 for product in itertools.product(*domains):
  seed=bytes(product);root_count+=1;front=[(seed,INITIAL)];empty=None
  for pos in range(8,655):
   nxt=[];v=vals[pos];m=masks[pos]
   for reg,states in front:
    k=e.encrypt(reg)[0];calls+=1
    for c in range(256):
     if (c&m)!=(v&m):continue
     plain=c^k;ns=step(states,plain)
     if ns:nxt.append((reg[1:]+bytes((c,)),ns));accepted+=1;counts[pos-8]+=1
   front=nxt;maxlive=max(maxlive,len(front))
   if not front:empty=pos;break
  if front:
   terminals+=sum(BOUNDARY in states for _,states in front);empty=655
  dist[str(empty)]=dist.get(str(empty),0)+1;digest.update(seed);digest.update(empty.to_bytes(2,'big'));digest.update(len(front).to_bytes(8,'big'))
 assert root_count==total and accepted==sum(counts)
 return {'initial_registers_total':total,'roots_replayed':root_count,'accepted_states':accepted,'block_calls':calls,'max_live_frontier_per_root':maxlive,'accepted_states_by_suffix_byte_sha256':hb(json.dumps(counts,separators=(',',':')).encode()),'root_first_empty_position_counts':dist,'root_outcome_digest_sha256':digest.hexdigest(),'terminal_paths_with_boundary':terminals,'all_roots_ended_before_terminal':terminals==0 and dist.get('655',0)==0},counts
def extract():
 mdx=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx';data=ROOT/'lavender/src/data/ciphers/revelations.json';assert sha(mdx)==MDX_SHA and sha(data)==DATA_SHA;t=mdx.read_text();a=t.index('`83 B57B2')+1;b=t.index('`',a);s=''.join(t[a:b].split()).upper();other=''.join(next(x for x in json.loads(data.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper();assert s==other and len(s)==1092 and hb(s.encode())==TEXT_SHA;return s
def generate():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(HERE/'run_target.py')==DRIVER_SHA;result=json.loads(RESULT.read_text());gate=json.loads(GATE.read_text());assert result['identity']==gate['identity']==IDENTITY and result['target_evaluated'] is True and gate['target_evaluated'] is False and result['configuration']['gate_sha256']==GATE_SHA and result['configuration']['driver_sha256']==DRIVER_SHA and result['configuration']['artifact_hashes']==gate['artifact_hashes']
 for rel,want in gate['artifact_hashes'].items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel),want)
 inv=json.loads((ROOT/'research/char_amsco/astra/lossy4_onechar_inventory/inventory.json').read_text());maps=[x for x in inv['map_classes'] if x['input_chars']==1310];expected=[f"{x['class_id']}|{o}" for x in maps for o in ORIENTATIONS];assert [x['id'] for x in result['cells']]==expected and len(expected)==48
 canonical=extract();certs=[]
 for meta in maps:
  indices=source_indices(1310,meta['representative_key']);assert list(indices)==meta['emission_indices'] and hb(json.dumps(list(indices),separators=(',',':')).encode())==meta['map_sha256']
  for o in ORIENTATIONS:
   saved=result['cells'][len(certs)];assert saved['id']==f"{meta['class_id']}|{o}" and saved['complete'] and saved['capped_reason'] is None and saved['partial_root'] is None and saved['roots_completed']==saved['initial_registers_total'] and saved['roots_unexamined']==0 and saved['solution_count']==0 and saved['solutions']==[]
   observed=orient(canonical,o);assert saved['observed_sha256']==hb(observed.encode());cert,counts=replay(observed,indices,saved);assert cert['accepted_states']==saved['accepted_states'] and cert['block_calls']==saved['block_calls'] and cert['max_live_frontier_per_root']==saved['max_live_frontier_per_root'] and counts==saved['accepted_states_by_suffix_byte'] and cert['terminal_paths_with_boundary']==0;certs.append({'id':saved['id'],**cert})
 assert result['summary']=={'accepted_states':sum(x['accepted_states'] for x in result['cells']),'block_calls':sum(x['block_calls'] for x in result['cells']),'complete_contexts':48,'contexts':48,'incomplete_contexts':0,'terminal_solutions':0}
 return {'identity':IDENTITY,'target_evaluated':True,'verification_kind':'independent ciphertext-first replay of every compatible C[0:8] root with separately implemented source geometry and a literal-codeword trie for the Unicode prefix transition; this repeats only the necessary zero-certificate frontier, not candidate full plaintext decryption','result_sha256':RESULT_SHA,'gate_sha256':GATE_SHA,'driver_sha256':DRIVER_SHA,'contexts':48,'complete_contexts':48,'incomplete_contexts':0,'terminal_solutions':0,'total_roots_replayed':sum(x['roots_replayed'] for x in certs),'accepted_states_replayed':sum(x['accepted_states'] for x in certs),'block_calls_replayed':sum(x['block_calls'] for x in certs),'cells':certs,'assertions':{'exact_ordered_48_cell_grid':True,'all_gate_artifact_hashes_current':True,'canonical_mdx_dataset_equal':True,'all_cells_complete_uncapped':True,'all_saved_counters_match_independent_replay':True,'all_roots_fail_before_terminal':True,'zero_terminal_paths_with_boundary':True}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();out=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  assert json.loads(CERT.read_text())==out;print(json.dumps({'identity':IDENTITY,'verified':True,'certificate_sha256':sha(CERT),'result_sha256':RESULT_SHA,'contexts':48,'terminal_solutions':0},sort_keys=True))
if __name__=='__main__':main()

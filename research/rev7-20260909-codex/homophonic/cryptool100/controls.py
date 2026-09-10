#!/usr/bin/env python3
"""Synthetic controls for CrypTool legacy 100-code homophonic boards. No Rev7 access."""
from pathlib import Path
import argparse,base64,collections,hashlib,json,math,random,re,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
SRC=HERE/'source'
REVELATIONS=ROOT/'lavender/src/data/ciphers/revelations.json'
IDENTITY='ASTRA'
PINS={'functions.homo.php':'01ad993c3b8c40faab2d80a21ed260441b205f65a27b9872ee21378e69d664f5','alfa_dat.php':'4db1baed5abd8aa86e428db2bed579e9cc52930e9cd527e1cf57487fd43eda3a','default_tool.php':'a0ca15a0f873a5f5c33cfbd8532697b2c882c0a11b33d851ee37c5fcdb155234'}
HIST_COMMIT='4fc443f0d87c0e86815695a47ab2d6174c725f82'
EXPECTED_H=(6,2,3,5,16,2,3,4,7,1,1,3,4,9,3,1,1,7,7,6,4,1,1,1,1,1)
ALPHA='ABCDEFGHIJKLMNOPQRSTUVWXYZ'

def sha_bytes(b):return hashlib.sha256(b).hexdigest()
def sha(p):return sha_bytes(p.read_bytes())
def canonical(x):return json.dumps(x,sort_keys=True,separators=(',',':'),ensure_ascii=True).encode()
B64_PIN='1020d8d7cdd0b69543ff924e9082d761e1149cc661fbe78e6f2792c32f8f7124'
def source_bytes(n):
 p=SRC/n
 if p.exists():return p.read_bytes()
 assert n=='alfa_dat.php'
 enc=SRC/'alfa_dat.php.base64';assert sha(enc)==B64_PIN
 raw=base64.b64decode(b''.join(enc.read_bytes().split()),validate=True);assert len(raw)==5376 and sha_bytes(raw)==PINS[n]
 return raw
def verify_sources():
 for n,h in PINS.items(): assert sha_bytes(source_bytes(n))==h,(n,sha_bytes(source_bytes(n)))
 raw=source_bytes('alfa_dat.php').decode('latin1')
 m=re.search(r"\$homo\['de'\]\s*=\s*array\((.*?)\);",raw,re.S); assert m
 h=tuple(map(int,re.findall(r'\d+',m.group(1))))
 assert h==EXPECTED_H and sum(h)==100
 f=source_bytes('functions.homo.php').decode('utf8')
 assert 'indexVonBuchstabe($alfa,$alfa[$t])*$key' in f and 'indexVonBuchstabe($alfa,$alfa[$t])+$key' in f
 return h

def coprimes100():return tuple(a for a in range(1,100) if math.gcd(a,100)==1)
def literal_php_codes(a,b):
 subst=[f'{i:02d}' for i in range(100)]
 mul=[subst[(t*a)%100] for t in range(100)]
 return [mul[(t+b)%100] for t in range(100)]
def direct_codes(a,b):return [f'{(a*(t+b))%100:02d}' for t in range(100)]
def board(a,b,h=EXPECTED_H):
 codes=literal_php_codes(a,b); out=[];i=0
 for letter,n in zip(ALPHA,h):out.append((letter,tuple(codes[i:i+n])));i+=n
 assert i==100
 return tuple(out)
def decoder(a,b):return {c:L for L,codes in board(a,b) for c in codes}
def encode(text,a,b,choice=0):
 d=dict(board(a,b)); return ''.join(d[ch][choice%len(d[ch])] for ch in text)
def encode_varying(text,a,b,seed):
 d=dict(board(a,b)); seen=collections.Counter(); used=collections.Counter(); out=[]
 for ch in text:
  # Seeded per-letter phase followed by a complete cycle through that letter's codes.
  start=int.from_bytes(hashlib.sha256((seed+ch).encode()).digest()[:4],'big')%len(d[ch])
  code=d[ch][(start+seen[ch])%len(d[ch])];seen[ch]+=1;used[code]+=1;out.append(code)
 return ''.join(out),used
def decode(ds,a,b):
 assert len(ds)%2==0 and ds.isdigit();d=decoder(a,b)
 return ''.join(d[ds[i:i+2]] for i in range(0,len(ds),2))
def normalize(s):return ''.join(c for c in s.upper() if 'A'<=c<='Z')
def decimal_to_hex(ds):
 assert ds and ds.isdigit();return format(int(ds),'X')
def hex_to_decimal(h):
 d=str(int(h,16));return ('0'+d) if len(d)%2 else d
def orient(h,name):
 assert len(h)%2==0
 if name=='forward':return h
 if name=='full_hex_reverse':return h[::-1]
 if name=='byte_reverse':return ''.join(reversed([h[i:i+2] for i in range(0,len(h),2)]))
 if name=='nibble_swap':return ''.join(h[i+1]+h[i] for i in range(0,len(h),2))
 raise ValueError(name)
def train_model():
 model_path=HERE/'sibling_tetragrams.json'
 assert sha(model_path)=='f182a6fb524c8ca07797ab7f24be05f98d63d295d667dcd70a3dc0abb21a5fbb'
 meta=json.loads(model_path.read_text())
 assert meta['identity']==IDENTITY and meta['source_sha256']==sha(REVELATIONS)
 assert meta['ids']==['rev1','rev2','rev3','rev4','rev5','rev6','rev8','rev9','rev10','rev11','rev12','rev13','rev14']
 counts=collections.Counter({k:int(v) for k,v in meta['counts'].items()})
 assert all(len(k)==4 and set(k)<=set(ALPHA) and v>0 for k,v in counts.items())
 assert meta['cross_record_tetragrams'] is False
 assert sum(counts.values())==meta['tetragrams']==sum(max(0,n-3) for n in meta['record_lengths'])
 assert meta['normalized_letters']==sum(meta['record_lengths'])
 return counts,meta
def score(s,counts,total):
 s=normalize(s);den=total+26**4; unseen=math.log(1/den)
 if len(s)<4:return float('-inf')
 return sum(math.log((counts.get(s[i:i+4],0)+1)/den) for i in range(len(s)-3))/(len(s)-3)
def generate():
 h=verify_sources(); alphas=coprimes100(); assert len(alphas)==40
 mapping_hashes=[]; parameter_rows=[]
 for a in alphas:
  for b in range(100):
   assert literal_php_codes(a,b)==direct_codes(a,b)
   bd=board(a,b,h);flat=[c for _,cs in bd for c in cs]
   assert len(flat)==100 and len(set(flat))==100 and set(flat)=={f'{i:02d}' for i in range(100)}
   dec=decoder(a,b);assert len(dec)==100
   mapping=[dec[f'{i:02d}'] for i in range(100)]
   mh=sha_bytes(''.join(mapping).encode())
   mapping_hashes.append(mh);parameter_rows.append({'a':a,'b':b,'mapping_sha256':mh})
 assert len(mapping_hashes)==4000 and len(set(mapping_hashes))==4000
 counts,model=train_model(); model_hash=sha_bytes(canonical(model)); model_total=sum(counts.values())
 plant_seeds=[normalize(x) for x in [
  'Lanterns flicker beneath the observatory while patient archivists compare every numbered token and record the quiet result. Brass gears carry the message onward, and each careful witness writes the sequence twice before dawn. Sphinx of black quartz judge my vow.',
  'Beyond the frozen courtyard a brass mechanism turns slowly, carrying a precise message through wheels that never guess. Patient readers follow every symbol, compare the numbered slips, and preserve the full account for the next watch. Pack my box with five dozen liquor jugs.'
 ]]
 plants=[(seed*((n+len(seed)-1)//len(seed)))[:n] for seed,n in zip(plant_seeds,(546,658))]
 plant_rows=[]
 for idx,(plain,a,b,seed) in enumerate(zip(plants,(37,73),(42,19),('vary-plant-1','vary-plant-2')),1):
  ds,usage=encode_varying(plain,a,b,seed); assert decode(ds,a,b)==plain
  reachable={c for ch in set(plain) for c in dict(board(a,b))[ch]}
  assert set(usage)==reachable
  hx=decimal_to_hex(ds); recovered=hex_to_decimal(hx); assert len(recovered)%2==0 and ds.endswith(recovered)
  recovered_plain=decode(recovered,a,b); assert plain.endswith(recovered_plain)
  candidates=[]
  for aa in alphas:
   for bb in range(100):candidates.append((score(decode(recovered,aa,bb),counts,model_total),aa,bb))
  candidates.sort(key=lambda x:(-x[0],x[1],x[2]))
  truth=next(i+1 for i,x in enumerate(candidates) if x[1:]==(a,b))
  truth_text=decode(recovered,a,b); ties=sum(abs(x[0]-score(truth_text,counts,model_total))<1e-15 for x in candidates)
  plant_rows.append({'id':idx,'letters':len(plain),'a':a,'b':b,'decimal_sha256':sha_bytes(ds.encode()),'hex_sha256':sha_bytes(hx.encode()),'recovered_decimal_sha256':sha_bytes(recovered.encode()),'choice_scheme':'seeded per-letter phase then occurrence cycle','choice_seed':seed,'distinct_codes_used':len(usage),'reachable_codes':len(reachable),'all_reachable_codes_used':set(usage)==reachable,'code_usage_sha256':sha_bytes(canonical(dict(sorted(usage.items())))),'leading_digits_lost':len(ds)-len(recovered),'full_chain_suffix_exact':plain.endswith(recovered_plain),'roundtrip':True,'truth_rank':truth,'score_ties':ties,'top5':[{'a':aa,'b':bb,'score_per_tetragram':sc} for sc,aa,bb in candidates[:5]]})
 rng=random.Random(164100)
 random_text=''.join(rng.choice(ALPHA) for _ in range(546))
 null_score=score(random_text,counts,model_total)
 english_scores=[score(x,counts,model_total) for x in plants]
 # A minimal fixed-choice witness is retained separately from the varying-homophone plants.
 minimal_plain=normalize('The quick brown fox jumps over the lazy dog')
 minimal_ds=encode(minimal_plain,37,42,choice=0);assert decode(minimal_ds,37,42)==minimal_plain
 minimal_witness={'letters':len(minimal_plain),'a':37,'b':42,'choice':0,'decimal_sha256':sha_bytes(minimal_ds.encode()),'roundtrip':True,'distinct_codes_used':len(set(minimal_ds[i:i+2] for i in range(0,len(minimal_ds),2)))}
 # Whole-integer representation controls.
 rep=[]
 for label,ds in [('no_loss','12345678'),('one_zero','051234'),('zero_pair','001234'),('two_zero_pairs','00001234')]:
  hx=decimal_to_hex(ds); restored=hex_to_decimal(hx)
  rep.append({'id':label,'input':ds,'hex':hx,'restored':restored,'lost_leading_digits':len(ds)-len(restored),'pair_aligned':len(restored)%2==0,'suffix_matches':ds.endswith(restored)})
 # All orientation functions are involutions and preserve byte count on a synthetic hex string.
 hh='0123456789ABCDEF1032547698BADCFE'
 orientation_rows=[]
 for name in ('forward','full_hex_reverse','byte_reverse','nibble_swap'):
  x=orient(hh,name);assert orient(x,name)==hh
  orientation_rows.append({'name':name,'sha256':sha_bytes(x.encode()),'involution':True,'length':len(x)})
 return {'identity':IDENTITY,'target_evaluated':False,'historical_commit':HIST_COMMIT,'source_hashes':{**PINS,'alfa_dat.php.base64':sha(SRC/'alfa_dat.php.base64'),'build_model.py':sha(HERE/'build_model.py'),'sibling_tetragrams.json':sha(HERE/'sibling_tetragrams.json'),'revelations.json':sha(REVELATIONS)},'source_semantics':{'allocation':list(h),'sum':sum(h),'coprime_multipliers':list(alphas),'rotations':100,'boards':4000,'formula':'code_at_natural_slot_t = 2digit(a*(t+b) mod 100)'},'board_checks':{'all_literal_equal_direct':True,'all_codes_bijective':True,'distinct_mapping_hashes':len(set(mapping_hashes)),'mapping_digest_in_parameter_order':sha_bytes(''.join(mapping_hashes).encode()),'parameter_mapping_digest':sha_bytes(canonical(parameter_rows))},'model':{**model,'counts_sha256':model_hash},'minimal_choice0_witness':minimal_witness,'heldout_plants':plant_rows,'random_null':{'seed':164100,'letters':546,'score_per_tetragram':null_score,'english_plant_scores':english_scores},'representation_controls':rep,'orientation_controls':orientation_rows,'limitations':['scores rank all retained candidates and never exclude a candidate','model is small and sibling-specific','one parity zero restores pair phase; further leading 00 code pairs are unrecoverable unknown plaintext prefix','synthetic controls do not read or evaluate Rev7']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args()
 got=generate()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n');print(a.regenerate)
 else:
  frozen=json.loads((HERE/'controls.json').read_text());assert frozen==got;print('PASS',sha(HERE/'controls.json'))
if __name__=='__main__':main()

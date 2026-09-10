#!/usr/bin/env python3
import argparse,hashlib,json,math,subprocess,sys,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;IDENTITY='ASTRA'
PINS={'source/ra-oracle/src/ioc.rs':'4f9e0e692877c4541353f21cbaa90196921be77fd21ff16801b52bfdc9e3107a','source/ra-oracle/src/lib.rs':'982aab255f334b1fc3ed22f46e039a095ef3cddf70a48b2bb615ce4a91e1b02f','source/ra-cli/src/sweep.rs':'cac270638d68a4c828b9aeaeee5fa3aa4f13513b0a5138916f87fe301a13c1af','source/claims/rev7-t3-retriage-ioc-english.json':'7cc712d378c8acd6a6c7b1b051045967458adf9054c56a965103debde146d06d'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def fixtures():
 concentrated=b'A'*90+b'\0'*456
 prose=b'The mountain must be searched for the frozen one. In the cell below the waves is where honor suffers. When finished we will return to the house and the infinite. A city of fire surrounds the warrior, the last of his kind.'
 embedded=prose+b'\x80'*(546-len(prose))
 state=0x6a09e667f3bcc909;random=bytearray()
 for _ in range(546):
  x=state;x^=(x<<13)&((1<<64)-1);x^=x>>7;x^=(x<<17)&((1<<64)-1);state=x&((1<<64)-1);random.append((state*0x2545f4914f6cdd1d)&255)
 return {'ninety_A_plus_nonletters':concentrated,'known_prose_plus_nonletters':embedded,'fixed_seed_uniform_bytes':bytes(random)}
def reference(b):
 c=[0]*26
 for x in b:
  if 65<=x<=90:c[x-65]+=1
  elif 97<=x<=122:c[x-97]+=1
 n=sum(c);ioc=sum(x*(x-1) for x in c)/(n*(n-1)) if n>=2 else 0
 return {'scored_len':len(b),'letter_count':n,'ioc':ioc,'passed':n>=90 and ioc+1e-12>=.055,'sha256':hashlib.sha256(b).hexdigest()}
def gate_prob(n,k=90,p=52/256):
 return sum(math.exp(math.lgamma(n+1)-math.lgamma(i+1)-math.lgamma(n-i+1)+i*math.log(p)+(n-i)*math.log1p(-p)) for i in range(k,n+1))
def build():
 for p,w in PINS.items():assert sha(HERE/p)==w,p
 lib=(HERE/'source/ra-oracle/src/lib.rs').read_text();sweep=(HERE/'source/ra-cli/src/sweep.rs').read_text()
 assert 'scored_len: tail.len()' in lib and 'ioc::letter_count(tail) >= ioc::MIN_SCORED_LETTERS' in lib
 assert 'longest_scored_region_among_passes' in sweep and 'r.pass_lens.keys().next_back()' in sweep
 with tempfile.TemporaryDirectory() as td:
  td=Path(td);testbin=td/'ioc_tests';subprocess.run(['rustc','--edition=2021','--test',str(HERE/'source/ra-oracle/src/ioc.rs'),'-o',str(testbin)],check=True,stdout=subprocess.DEVNULL);testout=subprocess.check_output([str(testbin)],text=True)
  original=(HERE/'source/ra-oracle/src/ioc.rs').read_text();body='\n'.join(('//'+line[3:] if line.startswith('//!') else line) for line in original.splitlines())
  expanded=(HERE/'harness.rs').read_text().replace('    include!("source/ra-oracle/src/ioc.rs");',body);rs=td/'harness.rs';rs.write_text(expanded);binary=td/'harness';subprocess.run(['rustc','--edition=2021',str(rs),'-o',str(binary)],check=True);rows=subprocess.check_output([str(binary)],text=True).splitlines()
 assert rows[0].split('\t')==['constants','90','0.05500000000000000'];actual={}
 for row in rows[1:]:
  _,name,L,n,v,p=row.split('\t');actual[name]={'scored_len':int(L),'letter_count':int(n),'ioc':float(v),'passed':p=='true'}
 refs={k:reference(v) for k,v in fixtures().items()}
 for k,a in actual.items():
  r=refs[k];assert a['scored_len']==r['scored_len'] and a['letter_count']==r['letter_count'] and abs(a['ioc']-r['ioc'])<1e-15 and a['passed']==r['passed']
 claim=json.loads((HERE/'source/claims/rev7-t3-retriage-ioc-english.json').read_text());t=claim['tiers'][0]
 assert claim['target']=='rev7' and claim['oracle']=='ioc-english' and claim['candidates_evaluated']==346816512 and claim['hits']==513
 assert len(claim['tiers'])==1 and t['candidates_evaluated']==346816512 and t['hits']==513 and t['longest_scored_region']==546 and t['longest_scored_region_among_passes']==546
 assert 'hit_samples' not in t and 'scored_lens' not in t and t['expected_false_positives']==2998.4411437619196
 gp=gate_prob(546);return {'identity':IDENTITY,'target_evaluated':False,'sweep_replayed':False,'source_hashes':{**PINS,'harness.rs':sha(HERE/'harness.rs'),'audit.py':sha(Path(__file__))},'source_commit':'e6c282187cc8a555580349d819210b544e5417b1','runtime':{'python':sys.version.split()[0],'rustc':subprocess.check_output(['rustc','--version'],text=True).strip()},'actual_module_tests':{'passed':3,'all_named_tests_ok':all(x in testout for x in ['known_english_sentences_cluster_near_the_textbook_rate ... ok','short_input_does_not_panic ... ok','uniform_random_letters_center_near_the_textbook_rate ... ok'])},'synthetic':{k:{'actual_rust':actual[k],'independent_reference':refs[k]} for k in actual},'score_semantics':{'scored_len':'tail byte length before ASCII-letter filter','letter_filter':'ASCII alphabetic only, case folded','minimum_letters':90,'threshold':.055,'printability_gate':False},'claim_accounting':{'candidates_evaluated':claim['candidates_evaluated'],'hits':claim['hits'],'longest_scored_region':t['longest_scored_region'],'longest_scored_region_among_passes':t['longest_scored_region_among_passes'],'expected_false_positives_reported':t['expected_false_positives'],'hit_samples_present':False,'scored_length_histogram_present':False},'uniform_byte_model_at_546':{'ascii_letter_probability':52/256,'probability_at_least_90_letters':gp,'code_estimated_pass_probability_upper':gp*1e-4,'expected_if_all_346816512_candidates_had_scored_len_546':claim['candidates_evaluated']*gp*1e-4,'conditional_ioc_factor':1e-4,'factor_basis':'empirical conservative factor from documented 20,000,000-trial-per-letter-length calibration; not a mathematical guarantee'},'findings':['A pass with scored_len 546 establishes a 546-byte tail and at least 90 ASCII letters, not 546 letters, printability, or full-message prose.','The synthetic 90-A plus 456-nonletter witness passes with IoC 1.0 and reports scored_len 546, proving the field cannot be interpreted as the amount of textual signal.','The claim retains 513 aggregate hits but no hit rows, letter counts, or scored-length histogram, so the 546-byte passing candidate and the reported expected-false-positive total cannot be independently diagnosed from the claim file.','The fixed-seed random fixture is one mechanics control only and carries no significance claim.'],'limits':['No Rev7 candidate is decrypted or rescored by this audit.','The false-positive formula is a model-based estimate combining an analytic binomial letter gate with an empirical conditional IoC factor; it is not a guaranteed p-value or coverage theorem.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();x=build()
 if a.generate:
  if a.generate.exists():raise SystemExit('refuse overwrite')
  a.generate.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n');print(a.generate);return
 p=HERE/'audit.json';assert json.loads(p.read_text())==x;print(json.dumps({'identity':IDENTITY,'status':'PASS','audit_sha256':sha(p),'synthetic':{k:v['actual_rust'] for k,v in x['synthetic'].items()}}))
if __name__=='__main__':main()

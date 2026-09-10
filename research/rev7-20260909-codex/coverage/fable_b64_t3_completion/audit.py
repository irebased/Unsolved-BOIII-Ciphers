#!/usr/bin/env python3
import argparse,base64,gzip,hashlib,io,json,math,subprocess,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;U=HERE/'upstream';IDENTITY='ASTRA'
EXPECTED_IDS=[('REAL','displayed'),('REAL','fullReversed'),('REAL','bytePairReversed'),('REAL','nibbleSwap'),('REAL','lowercased'),('NEG','random_hexalpha'),('POS','plant_twofish_cfb8_Zombies')]
EXPECTED_META=[a+':'+b for a,b in EXPECTED_IDS]
KEY_ENDPOINTS=['utf8_longestRun','utf8_validFrac','printableFrac','run.printable','small_1_26','small_0_31','frac.base64std','run.base64std','frac.decimal','run.decimal','frac.octal','run.octal','frac.hexupper','run.hexupper','frac.upperspace','run.upperspace','frac.base32','run.base32']
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def build():
 source={}
 for p in sorted(x for x in U.rglob('*') if x.is_file()):source[str(p.relative_to(HERE))]={'bytes':p.stat().st_size,'sha256':sha(p)}
 source['audit.py']={'bytes':Path(__file__).stat().st_size,'sha256':sha(Path(__file__))};source['controls.js']={'bytes':(HERE/'controls.js').stat().st_size,'sha256':sha(HERE/'controls.js')}
 gz=(U/'dictkey/keys_dict.txt.gz').read_bytes();assert hashlib.sha256(gz).hexdigest()=='f09908bec27d1ce35178512db4003fa092dec1963b5d9da0a582f14e545202f8'
 with gzip.GzipFile(fileobj=io.BytesIO(gz),mode='rb') as z:
  raw=z.read(7449349);extra=z.read(1)
 assert extra==b'' and len(raw)==7449348 and hashlib.sha256(raw).hexdigest()=='a6a970dcd6335844976d2834e6279fece5ec687ce9a65e91f79056caa7532d91'
 node=json.loads(subprocess.check_output(['node',str(HERE/'controls.js')],text=True));assert node['identity']==IDENTITY and node['dedup_count']==704667
 ds=[];stored=[];total=0
 for i in range(4):
  p=U/f'b64read/out_t{i}.json';x=json.loads(p.read_text());ds.append(x);n=x['meta']['nKeys'];assert x['meta']['tier']==f't{i}' and x['meta']['targets']==EXPECTED_META;assert len(x['results'])==7 and {(r['label'],r['reading']) for r in x['results']}==set(EXPECTED_IDS)
  expect=n*80
  for r in x['results']:assert r['trials']==expect and r['errors']==0
  got=sum(r['trials'] for r in x['results']);total+=got;stored.append({'tier':f't{i}','nkeys':n,'per_target_trials':expect,'all_target_trials':got,'errors':0,'seconds_reported':x['meta']['seconds'],'sha256':sha(p)})
 assert [x['nkeys'] for x in stored]==[3,280,2338,704667] and total==396081280
 t3=ds[3];assert t3['meta']['nKeys']==node['dedup_count'] and sum(r['trials'] for r in t3['results'])==394613520
 merged={}
 for d in ds:
  for r in d['results']:
   k=r['label']+'/'+r['reading'];o=merged.setdefault(k,{'trials':0,'best':{}});o['trials']+=r['trials']
   for e,v in r['best'].items():
    if e not in o['best'] or v['value']>o['best'][e]['value']:o['best'][e]={**v,'tier':d['meta']['tier']}
 neg=merged['NEG/random_hexalpha']['best'];comparisons={}
 for k in sorted(x for x in merged if x.startswith('REAL/')):
  vals=[]
  for e in KEY_ENDPOINTS:
   v=merged[k]['best'][e];n=neg[e];vals.append({'endpoint':e,'real_value':v['value'],'negative_max':n['value'],'beats_negative':v['value']>n['value'],'real_params':v['params'],'real_tier':v['tier'],'negative_params':n['params'],'negative_tier':n['tier']})
  comparisons[k]={'trials':merged[k]['trials'],'highlighted_endpoints':vals,'beats_count':sum(x['beats_negative'] for x in vals)}
 assert {k:v['beats_count'] for k,v in comparisons.items()}=={'REAL/bytePairReversed':7,'REAL/displayed':7,'REAL/fullReversed':6,'REAL/lowercased':7,'REAL/nibbleSwap':9}
 targets=json.loads((U/'b64read/targets.json').read_text());lower=next(x for x in targets if x['reading']=='lowercased')['b64string'];negstr=next(x for x in targets if x['reading']=='random_hexalpha')['b64string']
 assert set(negstr)<=set('0123456789ABCDEF') and set(lower)<=set('0123456789abcdef') and any(c in 'abcdef' for c in lower)
 posrow=next(r for r in t3['results'] if r['label']=='POS');hit=posrow['best']['utf8_longestRun'];assert hit['value']==803 and hit['params']=={'reading':'plant_twofish_cfb8_Zombies','cipher':'twofish','mode':'cfb8','key':'Zombies'}
 return {'identity':IDENTITY,'target_evaluated':False,'full_sweep_replayed':False,'source_hashes':source,'runtime':{'python':sys.version.split()[0],'node':node['node']},'key_union':node,'worker_accounting':{'block_ciphers':19,'modes_per_block_cipher':4,'stream_ciphers':4,'contexts_per_key_per_target':80,'targets':7,'tiers':stored,'total_trials':total,'t3_trials':394613520,'all_stored_errors':0},'assembled_highlighted_endpoint_comparisons':comparisons,'stored_positive_t3':{'trials':posrow['trials'],'errors':posrow['errors'],'best_utf8_longestRun':hit},'null_comparability':{'negative_glyph_alphabet':'0123456789ABCDEF','lowercased_glyph_alphabet':'0123456789abcdef','separate_lowercase_negative_present':False,'lowercase_comparison_to_uppercase_negative_is_distribution_mismatched':True,'readings_null_seed_saved':False},'findings':['The four stored tiers exactly account for 396,081,280 trials with zero recorded errors.','Every real reading beats the single merged negative maximum on at least six of the 18 highlighted endpoints, contradicting the literal hard-coded verdict that every real reading is at or below the negative on every endpoint.','Those isolated maxima are selected over a very large grid and have no per-grid null calibration, so beating one negative is not evidence of a decode.','The lowercase reading is compared against an uppercase-hex negative; no separately generated lowercase negative appears in the source or stored targets.','The finite grid and endpoint maxima do not prove impossibility for all ciphers, keys, or deterministic constructions.'],'limits':['No cipher target trial is rerun. Stored trial/error fields and endpoint maxima are checked for internal consistency.','The 7.45 MB dictionary is transported losslessly as deterministic gzip and read through the actual captured JavaScript readKeyFile plus Set union semantics.','The prior accepted Base64 source audit supplies the positive worker-path replay; this completion package checks the stored tier-3 positive metadata only.']}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();x=build()
 if a.generate:
  if a.generate.exists():raise SystemExit('refuse overwrite')
  a.generate.write_text(json.dumps(x,indent=2,sort_keys=True)+'\n');print(a.generate);return
 p=HERE/'audit.json';assert json.loads(p.read_text())==x;print(json.dumps({'identity':IDENTITY,'status':'PASS','audit_sha256':sha(p),'total_trials':x['worker_accounting']['total_trials'],'highlighted_beats':{k:v['beats_count'] for k,v in x['assembled_highlighted_endpoint_comparisons'].items()}}))
if __name__=='__main__':main()

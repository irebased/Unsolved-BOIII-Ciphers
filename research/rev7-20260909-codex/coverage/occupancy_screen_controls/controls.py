#!/usr/bin/env python3
"""ASTRA synthetic controls for the standalone occupancy threshold scorer."""
from __future__ import annotations
import argparse,hashlib,json,random,subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent;TABLE=HERE/'threshold_table.json';JS=HERE/'score.js';BUILD=HERE/'build_table.py';OUT=HERE/'controls.json'
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def exact_d_bytes(n,d,offset=0):
 assert 0<=d<=256 and (d==0 or n>=d)
 if d==0:return b''
 vals=bytes((offset+i)%256 for i in range(d));return bytes(vals[i%d] for i in range(n))
def py_score(data,thresholds):
 n=len(data);D=len(set(data))
 if n<128:return {'n':n,'D':D,'status':'short','screen_hit':None}
 if n>1092:return {'n':n,'D':D,'status':'out-of-range','screen_hit':None}
 d=thresholds[n];hit=D<=d;return {'n':n,'D':D,'threshold_d':d,'status':'flagged' if hit else 'unflagged','screen_hit':hit}
def compute():
 subprocess.run(['python3','-B',str(BUILD)],cwd=HERE.parents[3],check=True,capture_output=True,text=True)
 table=json.loads(TABLE.read_text());assert [r['n'] for r in table['rows']]==list(range(128,1093));thresholds={r['n']:r['d'] for r in table['rows']}
 fixtures=[]
 def add(name,data):fixtures.append({'id':name,'hex':data.hex()})
 add('empty_short',b'');add('length127_short',exact_d_bytes(127,50,128));add('length1093_out_of_range',exact_d_bytes(1093,240))
 for n in (128,129,256,546,1091,1092):
  d=thresholds[n]
  add(f'n{n}_below_d',exact_d_bytes(n,d-1));add(f'n{n}_at_d',exact_d_bytes(n,d));add(f'n{n}_above_d',exact_d_bytes(n,d+1))
 custom=bytes(128+i%40 for i in range(546));assert all(x>=128 for x in set(custom)) and len(set(custom))==40
 rng=random.Random(2026091001);perm=list(range(len(custom)));rng.shuffle(perm);custom_perm=bytes(custom[i] for i in perm)
 add('custom_non_ascii_alphabet',custom);add('custom_non_ascii_permuted',custom_perm);add('custom_non_ascii_reversed',custom[::-1])
 base64_alphabet=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/='
 letters=b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz'
 add('literal_base64_alphabet',bytes(base64_alphabet[i%len(base64_alphabet)] for i in range(546)))
 add('literal_letters_alphabet',bytes(letters[i%len(letters)] for i in range(546)))
 label_base=exact_d_bytes(546,thresholds[546]+1)
 label_map=bytes((i*73+41)%256 for i in range(256));assert len(set(label_map))==256
 label_mapped=bytes(label_map[x] for x in label_base)
 add('byte_label_bijection_base',label_base);add('byte_label_bijection_mapped',label_mapped)
 with tempfile.TemporaryDirectory(prefix='astra-occupancy-') as td:
  q=Path(td)/'batch.json';q.write_text(json.dumps(fixtures,separators=(',',':')))
  cp=subprocess.run(['node',str(JS),'--table',str(TABLE),'--batch',str(q)],check=True,capture_output=True,text=True)
  bad=Path(td)/'bad-table.json';bad_data=json.loads(TABLE.read_text());bad_data['model']['labels']=255;bad.write_text(json.dumps(bad_data))
  bad_cp=subprocess.run(['node',str(JS),'--table',str(bad),'--batch',str(q)],capture_output=True,text=True)
  assert bad_cp.returncode==2 and 'invalid table profile' in bad_cp.stderr
 js=json.loads(cp.stdout);expected=[{'id':x['id'],**py_score(bytes.fromhex(x['hex']),thresholds)} for x in fixtures]
 assert js=={'identity':'ASTRA','rows':expected}
 by={r['id']:r for r in expected}
 for n in (128,129,256,546,1091,1092):
  assert by[f'n{n}_below_d']['status']=='flagged' and by[f'n{n}_at_d']['status']=='flagged' and by[f'n{n}_above_d']['status']=='unflagged'
 assert by['length127_short']['status']=='short' and by['length127_short']['screen_hit'] is None and by['length1093_out_of_range']['status']=='out-of-range' and by['length1093_out_of_range']['screen_hit'] is None
 assert len({by[x]['D'] for x in ('custom_non_ascii_alphabet','custom_non_ascii_permuted','custom_non_ascii_reversed')})==1
 assert len({by[x]['status'] for x in ('custom_non_ascii_alphabet','custom_non_ascii_permuted','custom_non_ascii_reversed')})==1
 assert by['literal_base64_alphabet']['D']==65 and by['literal_base64_alphabet']['screen_hit'] is True
 assert by['literal_letters_alphabet']['D']==52 and by['literal_letters_alphabet']['screen_hit'] is True
 assert by['byte_label_bijection_base']['D']==by['byte_label_bijection_mapped']['D']==thresholds[546]+1
 assert by['byte_label_bijection_base']['status']==by['byte_label_bijection_mapped']['status']=='unflagged'
 compact=[]
 for f,r in zip(fixtures,expected):compact.append({**r,'input_sha256':hashlib.sha256(bytes.fromhex(f['hex'])).hexdigest()})
 return {'identity':'ASTRA','target_evaluated':False,'scope':'Synthetic-only exact occupancy threshold table and standalone JavaScript scorer controls.','table':{'rows':len(table['rows']),'n_range':[128,1092],'threshold_probability':'1/10^15','first':table['rows'][0],'selected':[next(r for r in table['rows'] if r['n']==n) for n in (256,546,1092)],'last':table['rows'][-1]},'scorer_rows':compact,'byte_label_bijection':{'formula':'f(x)=(73*x+41) mod 256','all_256_outputs_distinct':True,'base_and_mapped_D_equal':True,'base_and_mapped_status_equal':True},'custom_alphabet':{'values_hex':[f'{x:02X}' for x in sorted(set(custom))],'all_values_outside_ascii':True,'distinct':40,'permutation_invariance':True},'assertions':{'table_all_965_lengths_contiguous':True,'javascript_rejects_wrong_table_profile':True,'exact_d_flagged_and_d_plus_1_unflagged':True,'short_and_out_of_range_distinguished':True,'javascript_equals_independent_python_count':True,'position_permutation_preserves_D_and_status':True,'bijective_byte_label_mapping_preserves_D_and_status':True,'literal_base64_and_letters_flagged':True,'no_encoding_membership_used':True},'source_hashes':{'build_table.py':sha(BUILD),'threshold_table.json':sha(TABLE),'score.js':sha(JS),'controls.py':sha(Path(__file__)),'published_occupancy.py':table['source_pins']['published_occupancy.py']}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',metavar='NEW_PATH');a=ap.parse_args();got=compute()
 if a.generate:
  q=Path(a.generate);assert not q.exists(),'refuse overwrite';q.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','generated':str(q),'sha256':sha(q),'cases':len(got['scorer_rows'])},sort_keys=True));return
 assert OUT.exists();assert json.loads(OUT.read_text())==got
 print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sha(OUT),'cases':len(got['scorer_rows']),'table_rows':got['table']['rows']},sort_keys=True))
if __name__=='__main__':main()

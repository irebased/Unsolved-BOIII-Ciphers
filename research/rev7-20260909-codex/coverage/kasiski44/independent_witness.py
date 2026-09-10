#!/usr/bin/env python3
"""ASTRA independent source-index replay of the equal-cut Kasiski witness."""
from pathlib import Path
import hashlib,json,itertools
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
assert hashlib.sha256(DATA.read_bytes()).hexdigest()=='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
raw=''.join(next(x['ciphertext'] for x in json.loads(DATA.read_text()) if x['id']=='rev7').split()).upper()
assert len(raw)==1092 and hashlib.sha256(raw.encode()).hexdigest()=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
key='ZOMBIES';ranks={c:sorted(key).index(ch) for c,ch in enumerate(key)}
# Each serialized column contains39cells*4symbols=156symbols.
# Direct output-position formula, without importing the geometry implementation.
out=''.join(raw[ranks[(i//4)%7]*156+(i//28)*4+i%4] for i in range(1092))
assert hashlib.sha256(out.encode()).hexdigest()=='1cb32555f497309352adec7f5757bc3e9f5fb02fe077995ae0b83ff3a052d1be'
assert out[828:833]==out[942:947]=='030E6'
assert out[827]!=out[941] and out[833]!=out[947]
witnesses=[];all_repeats=[]
for n in range(4,9):
 occ={}
 for i in range(len(out)-n+1):occ.setdefault(out[i:i+n],[]).append(i)
 for gram,starts in sorted(occ.items()):
  for a,b in itertools.combinations(starts,2):
   r={'n':n,'ngram':gram,'start_a_zero_based':a,'start_b_zero_based':b,'gap':b-a,'supports':[p for p in (19,38,57) if (b-a)%p==0]}
   all_repeats.append(r)
   if r['supports']:witnesses.append(r)
assert [(r['ngram'],r['start_a_zero_based'],r['start_b_zero_based']) for r in witnesses]==[('030E',828,942),('30E6',829,943),('030E6',828,942)]
assert all(r['gap']==114 and r['supports']==[19,38,57] for r in witnesses)
print(json.dumps({'identity':'ASTRA','target_evaluated':True,'verification_only':True,'new_transform_search':False,'source_sha256':hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),'geometry':'rectangularequal4cells,ZOMBIES,standarddecode,forwardinput','transformed_sha256':hashlib.sha256(out.encode()).hexdigest(),'n_range':[4,8],'all_repeat_pairs':len(all_repeats),'support_counts':{str(p):sum(p in r['supports'] for r in witnesses) for p in (19,38,57)},'witnesses':witnesses,'maximal_common_repetition':{'text':'030E6','starts_zero_based':[828,942],'gap':114,'not_left_or_right_extendible':True},'outside_Z_formula_known':False,'outside_program_confirmed':False},sort_keys=True,indent=2))

#!/usr/bin/env python3
"""ASTRA read-only structural audit of frozen FABLE layer-two census rows."""
import collections,hashlib,json,pathlib,re,sys
H=pathlib.Path(__file__).resolve().parent; U=H/'upstream'
P={'l2census_v2.js':'e2a3ec96909c8a4a6fcd8388ce76fbf58d57dee426eefd07bf9e5fb1239b0a8b','l2census_rows.json':'043a19052984429cea07bf7247fd5683e2dca9b917b1f1d4448c0d4c66673929','l2census_summary.json':'bfd8f04d67908076d340e669dbb19278d3f8a298503c0ae7e642942b57372bfb'}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
for n,h in P.items():assert sha(U/n)==h
rows=json.loads((U/'l2census_rows.json').read_text());s=json.loads((U/'l2census_summary.json').read_text())
assert len(rows)==14288==s['evaluated']; assert s['planned_labels']==188*2*21*2==15792
ids={r['id'] for r in rows};assert len(ids)==188
keys={(r['id'],r['xf'],r['prim'],r['key']) for r in rows};assert len(keys)==len(rows)
assert {r['xf'] for r in rows}=={'identity','reverse'} and {r['key'] for r in rows}=={'Zombies','ZOMBIES'} and {r['mode'] for r in rows}=={'cfb8'}
pc=collections.Counter(r['prim'] for r in rows);assert len(pc)==19 and set(pc.values())=={752}
assert s['skipped']=={'no-such-primitive-in-oracle:idea':376,'no-such-primitive-in-oracle:salsa20':376}
# Each skip event is before the two-key loop: 376 events represent 752 omitted labels per primitive.
assert s['planned_labels']-len(rows)==2*752==1504
lengths=collections.Counter(r['in_len'] for r in rows);assert lengths==collections.Counter({546:7296,552:3040,560:2736,576:608,102:304,96:152,104:76,98:76})
assert all(r['in_len']==r['out_len'] for r in rows)
D=collections.Counter(r['D'] for r in rows);assert min(D)==s['minD']==71
assert sum(v for k,v in D.items() if k<=64)==s['D_le_64']==0
assert sum(v for k,v in D.items() if k<=70)==s['D_le_70']==0
assert sum(v for k,v in D.items() if k<=100)==s['D_le_100']==608
assert min(r['D'] for r in rows if r['in_len']>=546)==s['fulllen_minD']==211
first={}; aliases=0
for r in rows:
 assert 0<=r['D']<=r['out_len'] and re.fullmatch('[0-9a-f]{64}',r['sha256'])
 desc=f"{r['id']}/{r['xf']}/{r['prim']}/{r['key']}"
 if r['sha256'] in first: assert r['alias_of']==first[r['sha256']];aliases+=1
 else: assert r['alias_of'] is None;first[r['sha256']]=desc
assert len(first)==s['distinct_outputs']==7054 and aliases==14288-7054
mins=[r for r in rows if r['D']==71];assert len(mins)==2 and {r['in_len'] for r in mins}=={96,98}
out={'identity':'ASTRA','status':'PASS','target_evaluated':False,'verification_only':True,'source_pins':P,'rows':len(rows),'stageA_ids':len(ids),'planned_labels':s['planned_labels'],'effective_primitives':len(pc),'evaluated_per_primitive':dict(sorted(pc.items())),'omitted_label_counts':{'idea':752,'salsa20':752},'stored_skip_event_counts':s['skipped'],'distinct_output_hashes':len(first),'alias_rows':aliases,'length_histogram':dict(sorted(lengths.items())),'minD':min(D),'full_length_minD':s['fulllen_minD'],'D_le_64':s['D_le_64'],'D_le_70':s['D_le_70'],'D_le_100':s['D_le_100'],'limits':['Rows retain only output hashes, lengths and D; this audit cannot recompute D or output hashes from bytes.','The pinned stage-A manifest and revelations input named by source were not present in the supplied mirror; only its recorded SHA-256 is available.','No cipher calls were made.']}
print(json.dumps(out,sort_keys=True,separators=(',',':')))

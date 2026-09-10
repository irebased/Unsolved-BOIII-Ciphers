#!/usr/bin/env python3
"""ASTRA: upload frozen evidence as detached Git trees; never commit/update refs."""
from pathlib import Path
import hashlib,json,re,subprocess
HERE=Path(__file__).resolve().parent
MANIFEST=HERE/'odd_join_publication_manifest.json'
EXPECTED_PARENT='f1df87c53a2f403d6557adc83f09c90440489215'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
m=json.loads(MANIFEST.read_text());assert m['identity']=='ASTRA' and m['parent_commit']==EXPECTED_PARENT
assert subprocess.check_output(['gh','api','user','--jq','.login'],text=True).strip()=='irebased'
by={x['path']:x for x in m['artifacts']}
for x in m['artifacts']+m['existing_dependencies']:assert sha(x['path'])==x['sha256'],x['path']
state_path=HERE/'odd_join_tree_upload_state.json'
if state_path.exists():
 state=json.loads(state_path.read_text());assert state['manifest_sha256']==sha(MANIFEST)
else:state={'identity':'ASTRA','manifest_sha256':sha(MANIFEST),'batches':[]}
current=m['base_tree']
for i,paths in enumerate(m['batches']):
 if i<len(state['batches']):
  rec=state['batches'][i];assert rec['base_tree']==current and rec['paths']==paths;current=rec['tree'];continue
 tree=[]
 for rel in paths:
  data=Path(rel).read_bytes();assert hashlib.sha256(data).hexdigest()==by[rel]['sha256'];tree.append({'path':rel,'mode':'100644','type':'blob','content':data.decode('utf-8')})
 payload=Path('/private/tmp')/f'astra-odd-join-tree-{i:02d}.json'
 payload.write_text(json.dumps({'base_tree':current,'tree':tree},ensure_ascii=False))
 response=HERE/f'odd_join_tree_response_{i:02d}.json'
 with response.open('w') as out:subprocess.run(['gh','api','--method','POST','repos/irebased/Unsolved-BOIII-Ciphers/git/trees','--input',str(payload)],stdout=out,check=True)
 result=json.loads(response.read_text());assert re.fullmatch('[0-9a-f]{40}',result['sha']) and result['truncated'] is False
 state['batches'].append({'index':i,'base_tree':current,'tree':result['sha'],'paths':paths,'payload':str(payload),'payload_sha256':sha(payload),'payload_bytes':payload.stat().st_size});current=result['sha'];state_path.write_text(json.dumps(state,sort_keys=True,indent=2)+'\n')
 print(json.dumps({'identity':'ASTRA','uploaded_batch':i+1,'total_batches':len(m['batches']),'tree':current}),flush=True)
recursive=HERE/'odd_join_recursive_tree.json'
with recursive.open('w') as out:subprocess.run(['gh','api',f'repos/irebased/Unsolved-BOIII-Ciphers/git/trees/{current}?recursive=1'],stdout=out,check=True)
r=json.loads(recursive.read_text());assert r['sha']==current and r['truncated'] is False;remote={x['path']:x for x in r['tree']}
for x in m['artifacts']+m['existing_dependencies']:
 assert sha(x['path'])==x['sha256'] and remote[x['path']]['sha']==x['git_blob_sha1'],x['path']
state.update({'final_tree':current,'all_new_and_existing_blobs_verified':True,'artifacts':len(m['artifacts']),'existing_dependencies':len(m['existing_dependencies'])});state_path.write_text(json.dumps(state,sort_keys=True,indent=2)+'\n')
print(json.dumps({'identity':'ASTRA','verified_final_tree':current,'artifacts':len(m['artifacts']),'bytes':m['total_bytes'],'commit_created':False}),flush=True)

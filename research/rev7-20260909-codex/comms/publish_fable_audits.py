#!/usr/bin/env python3
"""ASTRA publication helper for two frozen FABLE audits. Detached Git tree writes require `publish`; commits and refs are never changed."""
from __future__ import annotations
import argparse,base64,hashlib,json,re,subprocess,tempfile
from pathlib import Path
ROOT=Path(__file__).resolve().parents[3]
HERE=Path(__file__).resolve().parent
DEFAULT_INVENTORY=HERE/'fable_audits_final_inventory.json'
REPO='irebased/Unsolved-BOIII-Ciphers'; LOGIN='irebased'; DEFAULT_BRANCH='codex/rev7-astra-20260909'
HEX40=re.compile(r'^[0-9a-f]{40}$')
def sha256(b):return hashlib.sha256(b).hexdigest()
def git_blob(b):return hashlib.sha1(b'blob '+str(len(b)).encode()+b'\0'+b).hexdigest()
def read_json(p):return json.loads(Path(p).read_text())
def local_record(rel):
 p=ROOT/rel;b=p.read_bytes()
 return {'path':rel,'bytes':len(b),'sha256':sha256(b),'git_blob_sha1':git_blob(b),'encoding':'base64' if p.suffix=='.wasm' else 'utf-8'}
def gh(args,input_obj=None):
 cmd=['gh','api']+args
 if input_obj is None:return json.loads(subprocess.check_output(cmd,text=True))
 with tempfile.NamedTemporaryFile('w',encoding='utf-8',delete=False,prefix='astra-fable-audit-',suffix='.json') as f:
  json.dump(input_obj,f,ensure_ascii=False,separators=(',',':'));name=f.name
 try:return json.loads(subprocess.check_output(cmd+['--input',name],text=True))
 finally:Path(name).unlink(missing_ok=True)
def verify_inventory(inv):
 assert inv['identity']=='ASTRA' and inv['publication_excludes']==['drafts','__pycache__']
 assert len(inv['artifacts'])==len(set(x['path'] for x in inv['artifacts']))
 for x in inv['artifacts']:
  assert x==local_record(x['path']),x['path']
  assert '/drafts/' not in x['path'] and '/__pycache__/' not in x['path']
  if x['encoding']=='utf-8':(ROOT/x['path']).read_bytes().decode('utf-8')
  else:assert x['path'].endswith('.wasm')
def check_base(records,tree):
 assert tree['truncated'] is False and HEX40.fullmatch(tree['sha'])
 remote={x['path']:x for x in tree['tree'] if x.get('type')=='blob'}
 for x in records:
  if x['path'] in remote and remote[x['path']]['sha']!=x['git_blob_sha1']:
   raise SystemExit(f"refuse overwrite changed remote source: {x['path']}")
 return remote
def prepare(a):
 inv=read_json(a.inventory);verify_inventory(inv)
 inventory_rel=str(a.inventory.resolve().relative_to(ROOT));assert inventory_rel not in {x['path'] for x in inv['artifacts']}
 inv['artifacts']=inv['artifacts']+[local_record(inventory_rel)]
 assert HEX40.fullmatch(a.parent) and HEX40.fullmatch(a.base_tree)
 tree=read_json(a.recursive_tree);assert tree['sha']==a.base_tree
 remote=check_base(inv['artifacts'],tree)
 m={'identity':'ASTRA','repository':REPO,'branch':a.branch,'parent_commit':a.parent,'base_tree':a.base_tree,
    'artifacts':inv['artifacts'],'new_or_identical':{x['path']:('identical' if x['path'] in remote else 'new') for x in inv['artifacts']},
    'total_bytes':sum(x['bytes'] for x in inv['artifacts']),'binary_paths':[x['path'] for x in inv['artifacts'] if x['encoding']=='base64'],
    'transport':'UTF-8 files use Git tree inline content; .wasm files use Git blob API encoding=base64 and their verified SHA in the tree.',
    'publisher_sha256':sha256(Path(__file__).read_bytes())}
 if a.output.exists():raise SystemExit('refuse existing manifest output')
 a.output.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'identity':'ASTRA','prepared':str(a.output),'artifacts':len(m['artifacts']),'bytes':m['total_bytes'],'manifest_sha256':sha256(a.output.read_bytes()),'network_writes':False}))
def verify_remote_blob(rec):
 obj=gh([f"repos/{REPO}/git/blobs/{rec['git_blob_sha1']}"])
 assert obj['sha']==rec['git_blob_sha1'] and obj['encoding']=='base64'
 raw=base64.b64decode(''.join(obj['content'].split()),validate=True)
 assert len(raw)==rec['bytes'] and sha256(raw)==rec['sha256'] and git_blob(raw)==rec['git_blob_sha1']
def publish(a):
 m=read_json(a.manifest);assert m['identity']=='ASTRA' and m['repository']==REPO and m['branch']==a.branch
 assert m['publisher_sha256']==sha256(Path(__file__).read_bytes())
 for x in m['artifacts']:assert x==local_record(x['path'])
 login=subprocess.check_output(['gh','api','user','--jq','.login'],text=True).strip();assert login==LOGIN
 ref=gh([f'repos/{REPO}/git/ref/heads/{a.branch}']);assert ref['object']['sha']==m['parent_commit'],'remote head changed'
 parent=gh([f"repos/{REPO}/git/commits/{m['parent_commit']}"]);assert parent['tree']['sha']==m['base_tree'],'parent/base tree mismatch'
 fresh=gh([f"repos/{REPO}/git/trees/{m['base_tree']}?recursive=1"]);assert fresh['sha']==m['base_tree'];check_base(m['artifacts'],fresh)
 binary_sha={}
 for x in m['artifacts']:
  if x['encoding']!='base64':continue
  if x['git_blob_sha1'] not in binary_sha:
   raw=(ROOT/x['path']).read_bytes();obj=gh(['--method','POST',f'repos/{REPO}/git/blobs'],{'content':base64.b64encode(raw).decode(),'encoding':'base64'})
   assert obj['sha']==x['git_blob_sha1'];binary_sha[x['git_blob_sha1']]=obj['sha'];verify_remote_blob(x)
 entries=[]
 for x in m['artifacts']:
  if x['encoding']=='base64':entries.append({'path':x['path'],'mode':'100644','type':'blob','sha':x['git_blob_sha1']})
  else:entries.append({'path':x['path'],'mode':'100644','type':'blob','content':(ROOT/x['path']).read_bytes().decode('utf-8')})
 tree=gh(['--method','POST',f'repos/{REPO}/git/trees'],{'base_tree':m['base_tree'],'tree':entries});assert HEX40.fullmatch(tree['sha']) and not tree.get('truncated',False)
 recursive=gh([f"repos/{REPO}/git/trees/{tree['sha']}?recursive=1"]);assert not recursive['truncated'];by={x['path']:x for x in recursive['tree']}
 for x in m['artifacts']:
  assert by[x['path']]['sha']==x['git_blob_sha1'];verify_remote_blob(x)
 # Root creates the commit and updates the branch separately after reviewing identity.
 out=HERE/'fable_audits_recursive_tree.json';out.write_text(json.dumps(recursive,sort_keys=True,indent=2)+'\n')
 receipt={'identity':'ASTRA','final_tree':tree['sha'],'parent':m['parent_commit'],'artifacts':len(m['artifacts']),'bytes':m['total_bytes'],'all_remote_bytes_verified':True,'manifest_sha256':sha256(Path(a.manifest).read_bytes()),'commit_created':False,'ref_updated':False}
 (HERE/'fable_audits_upload_receipt.json').write_text(json.dumps(receipt,sort_keys=True,indent=2)+'\n')
 print(json.dumps(receipt))

def main():
 ap=argparse.ArgumentParser();sp=ap.add_subparsers(dest='cmd',required=True)
 p=sp.add_parser('prepare');p.add_argument('--inventory',type=Path,default=DEFAULT_INVENTORY);p.add_argument('--parent',required=True);p.add_argument('--base-tree',required=True);p.add_argument('--recursive-tree',type=Path,required=True);p.add_argument('--branch',default=DEFAULT_BRANCH);p.add_argument('--output',type=Path,required=True);p.set_defaults(fn=prepare)
 p=sp.add_parser('publish');p.add_argument('--manifest',type=Path,required=True);p.add_argument('--branch',default=DEFAULT_BRANCH);p.set_defaults(fn=publish)
 a=ap.parse_args();a.fn(a)
if __name__=='__main__':main()

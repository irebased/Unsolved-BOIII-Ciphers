#!/usr/bin/env python3
"""ASTRA audit of a 2020 community gist's Rev7 representation and provenance."""
from __future__ import annotations
import ast, base64, hashlib, json, re
from pathlib import Path
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[3]
GIST=HERE/'source'/'base64_rot13.py'
META=HERE/'source'/'gist_metadata.json'
HISTORY=HERE/'source'/'rev7_mdx_git_history.txt'
KEY_EVIDENCE=HERE/'source'/'key_spelling_evidence.json'
LEDGER=HERE/'audit.json'
FILES={
 'gist':'source/base64_rot13.py','metadata':'source/gist_metadata.json','git_history':'source/rev7_mdx_git_history.txt','key_evidence':'source/key_spelling_evidence.json',
 'mdx':'../../../../lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx',
 'dataset':'../../../../lavender/src/data/ciphers/revelations.json',
 'notebook':'../../notebook-snapshot.json','latest_comments':'../../latest-comments.json',
 'origins':'../../../../lavender/src/data/ciphers/origins.json','motd':'../../../../lavender/src/data/ciphers/motd.json'}
EXPECTED={
 'source/base64_rot13.py':'e800836503c2d9da327dd8a0c8efdea7f0e677910b4e432b35e6a4a98b827426',
 'source/gist_metadata.json':'897eff01e17b4613ea0de22f5ff609d78a83aa5c4ca432dd37096096e47c8c7b', 'source/rev7_mdx_git_history.txt':'8245263b7d2cc852d59c30ef20855bb74335a92daaedda4d3ee0bb936d4a0081',
 'source/key_spelling_evidence.json':'c7d050f3609f078bfb72302ee1b1f7ddba36279d693bb08d0daaa8e4cbdf7c75',
 '../../../../lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx':'085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91',
 '../../../../lavender/src/data/ciphers/revelations.json':'68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'}
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def path(rel):return (HERE/rel).resolve()
def extract_x(source:str)->str:
 tree=ast.parse(source); vals=[]
 for node in ast.walk(tree):
  if isinstance(node,ast.Assign) and any(isinstance(t,ast.Name) and t.id=='x' for t in node.targets) and isinstance(node.value,ast.Constant) and isinstance(node.value.value,str): vals.append(node.value.value)
 assert len(vals)==1
 return vals[0]
def canonical():
 data=json.loads(path(FILES['dataset']).read_text())
 rows=[x for x in data if x.get('id')=='rev7']; assert len(rows)==1
 return rows[0]['ciphertext']
def matches(file:Path,terms):
 out=[]
 for no,line in enumerate(file.read_text(errors='replace').splitlines(),1):
  found=[t for t in terms if re.search(t,line,re.I)]
  if found: out.append({'line':no,'terms':found,'text':line})
 return out
def produce():
 for rel,want in EXPECTED.items():
  if want.startswith('__'):continue
  assert sha(path(rel))==want,(rel,sha(path(rel)))
 key_evidence=json.loads(KEY_EVIDENCE.read_text())
 documented=key_evidence['variants']['documented']; alternative=key_evidence['variants']['suggested_alternative']
 assert documented=='wewerethereatthebeginningandattheend' and len(documented)==36
 assert alternative=='wewerehereatthebeginningandattheend' and len(alternative)==35
 assert all(row['value']==documented for row in key_evidence['community_sources'])
 assert all(row['there_exact_lines']==3 and row['here_exact_lines']==0 for row in key_evidence['captured_fable_keylists'])
 meta=json.loads(META.read_text()); assert meta['revisions'][-1]['commit']=='cc559bba7406ed8489eaaf2f9a5481d5fd500bc2' and meta['head_bytes']==8830
 source=GIST.read_text(); x=extract_x(source); decoded=base64.b64decode(x,validate=True)
 assert decoded.isascii(); tokens=decoded.decode('ascii').split(); compact=''.join(tokens)
 assert len(x)==1748 and len(decoded)==1310 and len(tokens)==219 and len(compact)==1092
 assert tokens[0]=='83' and all(len(t)==5 for t in tokens[1:]) and re.fullmatch('[0-9A-F]{1092}',compact)
 canon=canonical(); canon_tokens=canon.split(); canon_compact=''.join(canon_tokens)
 assert tokens==canon_tokens and compact==canon_compact
 assert hashlib.sha256(compact.encode()).hexdigest()=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
 mdx=path(FILES['mdx']).read_text(); assert '| Location | By the Origins mound |' in mdx
 assert '2025-12-18T16:13:14-06:00' in HISTORY.read_text() and 'By the Origins mound' in HISTORY.read_text()
 terms=[r'ORIGINS[_ -]?TRENCH',r'8a8f4109ae19210d18435914265f220e',r'wewerethereatthebeginningandattheend',r'INFERNO',r'MOBOFTHEDEADABCD',r'Origins mound']
 prior={}
 for key in ['mdx','dataset','notebook','latest_comments','origins','motd']:
  p=path(FILES[key]);prior[key]={'path':FILES[key],'sha256':sha(p),'matches':matches(p,terms)}
 assert not any(any(re.search(r'ORIGINS[_ -]?TRENCH',m['text'],re.I) for m in row['matches']) for row in prior.values())
 assert not any(any('8a8f4109ae19210d18435914265f220e' in m['text'] for m in row['matches']) for row in prior.values())
 assert any('Origins mound' in m['text'] for k in ['mdx','notebook','latest_comments'] for m in prior[k]['matches'])
 assert any('wewerethereatthebeginningandattheend' in m['text'] for m in prior['origins']['matches'])
 assert any('INFERNO' in m['text'] for m in prior['origins']['matches'])
 assert any('MOBOFTHEDEADABCD' in m['text'] for m in prior['motd']['matches'])
 return {'identity':'ASTRA','schema':'astra-community-gist-location-audit-v1','target_evaluated':False,
  'canonical_ciphertext_read_for_comparison':True,
  'gist':{'owner':'redknight99','gist_id':meta['gist_id'],'revision':meta['revisions'][-1], 'revision_count':len(meta['revisions']),
   'filename':meta['filename'],'bytes':len(GIST.read_bytes()),'sha256':sha(GIST),'git_blob_sha1':meta['head_blob_sha1'],'urls':{'page':meta['gist_url'],'immutable_raw':meta['immutable_raw_url']}},
  'representation':{'base64_characters':len(x),'base64_decoded_type':'spaced ASCII hexadecimal text','base64_decoded_bytes':len(decoded),
   'base64_decoded_sha256':hashlib.sha256(decoded).hexdigest(),'display_tokens':len(tokens),'first_token_length':len(tokens[0]),
   'remaining_token_length':5,'hex_glyphs_after_whitespace_removal':len(compact),'compact_sha256':hashlib.sha256(compact.encode()).hexdigest(),
   'binary_bytes_after_additional_hex_decode':len(bytes.fromhex(compact)),'exact_token_sequence_matches_dataset':True,
   'note':'Base64 decoding alone yields 1,310 ASCII bytes. A separate whitespace removal and hex decode yields 546 binary bytes.'},
  'origins_key_spelling':{'documented':documented,'documented_length':len(documented),'suggested_alternative':alternative,'suggested_alternative_length':len(alternative),'finding':'THERE is consistently documented; 35 characters was a count error.','captured_keylists_with_there':4,'captured_keylists_with_here':0,'exact_unsynced_new_run_keylist_verified':False,'evidence_sha256':sha(KEY_EVIDENCE)},
  'labels':{'gist_alias':'Origins_Trench','gist_number':'Cipher #6','repository_label':'Rev7 / Revelations 7','repository_location':'By the Origins mound',
   'finding':'The exact alias and gist ID were absent from the reviewed prior corpus, but the broader Origins-mound location was already present.'},
  'history_inventory':prior,
  'provenance_assessment':{'community_copy_corrobates_exact_tokens':True,'independent_transcription_established':False,
   'reason':'The gist links the community Revelations wiki as background and supplies no image-to-text method or capture provenance; identical grouping can reflect a shared upstream transcription.',
   'physical_location_verified_from_gist_alone':False,
   'location_scope':'Origins_Trench is the gist author’s alias. It is consistent with the pre-existing Origins-mound description but does not by itself establish exact game coordinates.'},
  'limits':['This is a representation, provenance, and local-history audit, not a cipher test.',
   'The reported 70,656-combination FABLE key sweep is not present in the gist and was not rerun or treated as gist evidence.',
   'Absence claims apply only to the six pinned local history sources inventoried here.'],
  'source_hashes':{'audit.py':sha(Path(__file__)),'gist_metadata.json':sha(META),'rev7_mdx_git_history.txt':sha(HISTORY),'key_spelling_evidence.json':sha(KEY_EVIDENCE)}}
def main():
 got=produce()
 if LEDGER.exists():
  saved=json.loads(LEDGER.read_text()); assert saved==got
  print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sha(LEDGER),'compact_sha256':got['representation']['compact_sha256']},sort_keys=True))
 else:
  LEDGER.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','written':str(LEDGER),'sha256':sha(LEDGER)},sort_keys=True))
if __name__=='__main__':main()

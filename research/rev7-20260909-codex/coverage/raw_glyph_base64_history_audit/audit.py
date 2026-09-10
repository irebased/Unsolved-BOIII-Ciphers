#!/usr/bin/env python3
"""ASTRA source/history audit for direct Base64 decoding of the 1092 displayed glyphs."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
IDENTITY="ASTRA"; HERE=Path(__file__).resolve().parent; REPO=HERE.parents[3]; OUT=HERE/'audit.json'
PINS={
'research/rev7-20260909-codex/hex_cfb/encoded/run_encoded.py':'b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c',
'research/rev7-20260909-codex/hex_cfb/native/run_target.py':'2cd00b724cc435899a3cdaf853e393343bd9e64bb202c95cdb109ade35ca0ddd',
'research/rev7-20260909-codex/hex_cfb/native/RESULTS.md':'1e39a097298d3e7171cd22908bec11e0cb5b69b2f242286d0fb2f1660426be8e',
'research/rev7-20260909-codex/hex_cfb/native/target_results.json':'74ce86bd01c4bbeb1492f61707039d07884ac7c3d9b63ec20bde5ea3d9301644',
'research/char_amsco/astra/lossy2016/target/run_target.py':'036ab0f597906ca90699d63f4ea42033030e21a1fca28476e2746b735144ae4c',
'research/char_amsco/astra/lossy2016/target/RESULTS.md':'fe7568209609b6a080448ff7384f4e393c03988f373392254c5f34a03504c301',
'research/rev7-20260909-codex/comms/encoded-go-20260910.json':'cc45e8b55823b4cfcc9ba36b7cf6727ef493ea1df6875acdcafb77bbc932ad9e',
'research/rev7-20260909-codex/comms/encoded-result-20260910.json':'0eb6e25b14385f9246f5948639b67a8e337f73497166fdbcc831c8313524eec0',
'research/rev7-20260909-codex/comms/base64-result-native-plan-20260910.json':'5b0680658ea81e1cd5615a3abeef7502dd09915192b5d3f7bd711b8f8f6d27a2',
'research/rev7-20260909-codex/comms/brainstorm-021.json':'b1d1737e470939aa38ef530fb94af5f9a28a0b40dc05bd3bfa2f948e1f69d181',
'research/rev7-20260909-codex/comms/kasiski_periodic_recursive_tree.json':'2667034f5a4d1b8cd8569737093f2424f4669285cc1a5f51c750ee032ae9eee0'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def category(path):
 s=str(path)
 if 'native_siblings/controls.py' in s or 'sources/rev9_source/controls.py' in s:return 'solved_sibling_full_buffer'
 if 'prefix_group_alignment_audit/audit.py' in s:return 'synthetic_alignment_control'
 if any(x in s for x in ('pack_results.py','pack_controls.py','complete_transport/','restore_smt.py')):return 'result_or_solver_transport'
 if any(x in s for x in ('cryptool_bug/analyze.py','fable_nofb_audit/audit.py','restore_native.py','homophonic/cryptool100/controls.py','homophonic/pollux_source/controls.py','homophonic/pollux_source/target/verify_results.py','fable_bytebag_replay/verify_outputs.py')):return 'source_or_binary_packaging'
 return 'unclassified'
def calls(paths=None):
 rows=[]
 candidates=(REPO/p for p in paths) if paths is not None else (REPO/'research').rglob('*')
 for p in sorted(candidates):
  if p.suffix not in ('.py','.js') or any(x in p.parts for x in ('dependency','smt','drafts','raw_glyph_base64_history_audit')):continue
  text=p.read_text(errors='replace')
  hits=[]
  for i,line in enumerate(text.splitlines(),1):
   lo=line.lower()
   if 'b64decode' in lo or 'base64_decode' in lo or 'atob(' in lo or ('buffer.from' in lo and 'base64' in lo):hits.append({'line':i,'sha256':hashlib.sha256(line.strip().encode()).hexdigest()})
  if hits:rows.append({'path':str(p.relative_to(REPO)),'file_sha256':sha(p),'category':category(p),'calls':hits})
 return rows
def line(text,needle):
 hits=[i for i,s in enumerate(text.splitlines(),1) if needle in s];assert len(hits)==1,(needle,hits);return hits[0]
def build(paths=None):
 for rel,want in PINS.items():assert sha(REPO/rel)==want,rel
 rows=calls(paths);assert rows and all(x['category']!='unclassified' for x in rows)
 native=(REPO/'research/rev7-20260909-codex/hex_cfb/native/run_target.py').read_text()
 lossy=(REPO/'research/char_amsco/astra/lossy2016/target/run_target.py').read_text()
 assert 'ALLOWED=set(prior.ENDPOINTS["base64"])' in native and 'base64.b64decode' not in native
 assert "NBYTES=819" in lossy and "legacy.legacy_encode(ct.hex()" in lossy and 'base64.b64decode' not in lossy
 tree=json.loads((REPO/'research/rev7-20260909-codex/comms/kasiski_periodic_recursive_tree.json').read_text())
 entries={x['path']:x for x in tree['tree']}
 published={k:{'blob_sha1':entries[k]['sha'],'bytes':entries[k]['size']} for k in (
  'research/rev7-20260909-codex/hex_cfb/encoded/run_encoded.py','research/rev7-20260909-codex/hex_cfb/native/run_target.py','research/rev7-20260909-codex/hex_cfb/native/RESULTS.md','research/rev7-20260909-codex/hex_cfb/native/target_results.json','research/char_amsco/astra/lossy2016/target/run_target.py')}
 result=json.loads((REPO/'research/rev7-20260909-codex/hex_cfb/native/target_results.json').read_text())
 assert len(result['phases']['prefix_validation']['cells'])==12 and len(result['phases']['extension']['cells'])==6
 assert result['summary']=={'extension_capped_cells':0,'extension_complete_cells':6,'extension_survivors':0,'prefix_cells_exactly_matched':12}
 results_text=(REPO/'research/rev7-20260909-codex/hex_cfb/native/RESULTS.md').read_text();assert 'exhaustive coverage of all 12 registered cells' in results_text
 assert sum(x['stats']['certificate_complete'] for x in result['phases']['prefix_validation']['cells'])==6
 assert all(not x['survivors'] for phase in result['phases'].values() for x in phase['cells'])
 return {'identity':IDENTITY,'target_evaluated':False,'new_target_route_executed':False,
  'claim_reviewed':'Literal displayed Rev7 glyph sequence, whitespace removed, interpreted directly as standard Base64 and decoded to 819 bytes.',
  'finding':'No exact prior execution of that input route was found in the reviewed ASTRA Python/JavaScript source and saved bus records. This is a bounded corpus statement, not a global absence claim.',
  'route_arithmetic_only':{'displayed_glyphs':1092,'quartets':273,'decoded_bytes_if_unpadded_standard_base64':819,'calculation':'1092 / 4 * 3','target_bytes_not_decoded_in_this_audit':True},
  'closest_prior_experiment':{'model':'global displayed-hex-to-nibble bijection, CFB8 decryption, then membership in a permissive 69-byte Base64-plus-whitespace endpoint','not_same_because':'It first interprets pairs of displayed glyphs as mapped hexadecimal ciphertext bytes and tests decrypted bytes. It never Base64-decodes the literal displayed glyph characters.','source':{'path':'research/rev7-20260909-codex/hex_cfb/native/run_target.py','sha256':PINS['research/rev7-20260909-codex/hex_cfb/native/run_target.py'],'lines':[line(native,'ALLOWED=set(prior.ENDPOINTS["base64"])'),line(native,'CIPHERS=("aes128","blowfish","des")'),line(native,'ORIENTATIONS=("forward","reverse","byte_reverse","nibble_swap")')]},'counts':{'cells':12,'ciphers':3,'orientations':4,'complete':12,'survivors':0},'result_sha256':PINS['research/rev7-20260909-codex/hex_cfb/native/target_results.json']},
  'coincidental_819_prior_experiment':{'model':'lossy historical character-AMSCO key 2016 reconstructs a natural 819-byte ciphertext from 1092 observed hex characters, then CFB8-searches it','not_same_because':'819 is the inferred pre-loss ciphertext length. The observed glyphs are constrained as lossy hexadecimal emission, not standard Base64 input.','source':{'path':'research/char_amsco/astra/lossy2016/target/run_target.py','sha256':PINS['research/char_amsco/astra/lossy2016/target/run_target.py'],'lines':[line(lossy,"NBYTES=819"),line(lossy,"legacy.legacy_encode(ct.hex().upper().encode(),'2016')")]},'contexts':16},
  'base64_decode_call_inventory':{'roots':'Snapshot of textual Base64 decode-call matches in research/**/*.py and research/**/*.js; excludes dependency, smt, drafts, and this audit directory. Default verification checks only these frozen inventoried paths.','files_with_calls':len(rows),'call_count':sum(len(x['calls']) for x in rows),'rows':rows,'categories':{k:sum(x['category']==k for x in rows) for k in sorted({x['category'] for x in rows})},'exact_raw_rev7_glyph_route_calls':0},
  'saved_bus_history':{'encoded_go':'5 alphabets x 3 ciphers x 4 orientations; Base64 means output-byte membership','encoded_result':'explicitly calls the 69-byte set permissive alphabet membership, not Base64 grammar','native_result':'completed the same 12 membership cells','brainstorm_note':'discusses an immediate hex-decoded object claimed to be Base64 text; it does not report direct decoding of the displayed 1092 glyphs'},
  'published_snapshot':{'evidence_kind':'cached recursive Git tree response; tree SHA is not represented here as a commit SHA','tree_sha1':tree['sha'],'entries':published},
  'minimum_controls_for_future_source_review':['Pin the exact 1092-glyph whitespace-stripped input and its source/image/data hashes before decoding.','Assert length 1092, length modulo four zero, and every glyph belongs to the chosen standard Base64 alphabet; declare case, padding, and whitespace policy.','Strict-decode the literal glyph bytes once; require exactly 819 output bytes, retain their full hash/bytes, and require exact standard Base64 re-encoding to the original glyph string.','Use a synthetic binary fixture with exact encode/decode and corruption/padding rejection controls.','Treat the decoded 819 bytes as binary. Any subsequent cipher, decompressor, parser, or language claim needs its own preregistered model and full inverse/roundtrip checks.'],
  'pins':PINS,'assertions':{'all_pins_match':True,'all_decode_call_text_matches_classified':True,'exact_prior_route_found':False,'closest_prior_membership_grid_exactly_12_complete_zero':True,'lossy_819_is_not_base64_decode':True}}
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+'\n'
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();saved=None if a.regenerate else json.loads(OUT.read_text());got=build(None if saved is None else [x['path'] for x in saved['base64_decode_call_inventory']['rows']])
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f'refusing existing output: {a.regenerate}')
  a.regenerate.write_text(canonical(got));print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)}));return
 assert json.loads(OUT.read_text())==got;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(OUT),'exact_prior_route_found':False,'decode_call_files':got['base64_decode_call_inventory']['files_with_calls']}))
if __name__=='__main__':main()

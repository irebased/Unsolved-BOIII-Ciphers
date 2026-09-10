#!/usr/bin/env python3
# Read-only ASTRA final one-square Bifid16 coverage reconciler; never calls a solver.
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;REPO=HERE.parents[3]
EVEN=PACKAGE/'even_target/target_results.json';PILOT=PACKAGE/'odd_pilot/target_results.json';FULL=PACKAGE/'odd_fullbag/target_results.json';FINAL=HERE/'target_results.json';CHECKPOINT=HERE/'checkpoint.jsonl';STATUS=HERE/'status.json';RECEIPT=HERE/'verification.json';ENCODED=REPO/'research/rev7-20260909-codex/coverage/encoded_endpoint_subset/results.json'
ORIENTS=('forward','reverse','byte_reverse','nibble_swap');PERIODS=range(1,1093);IDENTITY='ASTRA';TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
FILES={'even_target/target_results.json':'acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8','odd_pilot/target_results.json':'5ffb45b7191689e119bbb4e930f124eda5f78d8ddbb229085e9c522245c5a4a1','odd_fullbag/target_results.json':'3bbb8ccd756ea29082b2394108544601c79eb0fe19d2259b2c8ba732294225a3','complete_periods/target_results.json':'736a34aed38826a8c1a1bf5e4fcd24d6f4aad817a435f2e09384fe493d4d35d6','complete_periods/checkpoint.jsonl':'67a5eeaf6d94329726243fcee9f8c49665bc4d10623f30a830c88ea86b37395d','complete_periods/status.json':'8121d83592c85a890e12382d3fe81530dbdcf0dd0409c0cb78542384db7fd20d','complete_periods/target_gate.json':'dba3f6a962392cd4bdcacb7b81bfd459f9b27387dc36b87d5bdddd0791f43ff2','complete_periods/run_target.py':'6dd45ffb0d2a5825f9388b363bc2c97bbb799bc16a1a24587884455e95ffce56','complete_periods/verify_results.py':'d070482f30750a9f58eece9d3caaaad294255d0dd8281ca58dda750b28312ef5','COVERAGE_RECONCILIATION.md':'c092b9994fb04a3a401720fee04a485d35ba89f5c493bb5c306b2d3338f2c8d0'}
ENCODED_SHA='fbef3e7d26b0a6806532c53b0fc22a8ca54625414685fd202daad93abbd5fa35'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load(p):return json.loads(Path(p).read_text())
def norm(o):return 'reverse' if o=='full_hex_reverse' else o
def pins():
 for rel,digest in FILES.items():assert sha(PACKAGE/rel)==digest,rel
 assert sha(ENCODED)==ENCODED_SHA
 return {**FILES,'coverage/encoded_endpoint_subset/results.json':ENCODED_SHA}
def verify_receipt():
 if not RECEIPT.exists():return None
 receipt=load(RECEIPT);expected={'identity':IDENTITY,'ok':True,'verification_only':True,'new_target_search':False,'complete_cells':2175,'formulas_reconstructed':2175,'summary':{'sat':0,'unsat':2168,'unknown':7},'result_sha256':FILES['complete_periods/target_results.json']}
 assert receipt==expected
 return {'path':'complete_periods/verification.json','sha256':sha(RECEIPT),**receipt}
def reconcile():
 source_hashes=pins();even=load(EVEN);pilot=load(PILOT);full=load(FULL);final=load(FINAL);encoded=load(ENCODED);status=load(STATUS)
 universe={(o,p) for o in ORIENTS for p in PERIODS};assert len(universe)==4368
 assert even['identity']==IDENTITY and even['target_evaluated'] is True and even['status']=='complete' and len(even['cells'])==2184
 even_ids={(norm(x['orientation']),x['period']) for x in even['cells']};assert even_ids=={(o,p) for o in ORIENTS for p in PERIODS if p%2==0}
 assert all(x['bound_165']=='excluded_all_squares' and x['distinct_pair_count']>165 for x in even['cells'])
 even_broad_unsat={(norm(x['orientation']),x['period']) for x in even['cells'] if x['bound_213']=='excluded_all_squares'};even_broad_unknown=even_ids-even_broad_unsat
 assert len(even_broad_unsat)==2177 and even_broad_unknown=={('forward',562),('forward',972),('reverse',16),('reverse',514),('byte_reverse',16),('nibble_swap',850),('nibble_swap',972)}
 assert pilot['identity']==full['identity']==IDENTITY and len(pilot['cells'])==16 and len(full['cells'])==9
 pilot_ids={(x['orientation'],x['period']) for x in pilot['cells']};assert pilot_ids=={(o,p) for o in ORIENTS for p in (3,31,99,1091)}
 pilot_unsat={(x['orientation'],x['period']) for x in pilot['cells'] if x['status']=='unsat'};full_ids={(x['orientation'],x['period']) for x in full['cells']}
 assert full_ids==pilot_ids-pilot_unsat and all(x['status']=='unsat' and x['classified_as_negative'] for x in full['cells']);prior_odd=pilot_unsat|full_ids;assert len(prior_odd)==16
 fresh_expected=universe-even_broad_unsat-prior_odd;assert len(fresh_expected)==2175 and sum(p%2 for _,p in fresh_expected)==2168
 assert final['identity']==IDENTITY and final['target_evaluated'] is True and final['status']=='complete' and final['normalized_text_sha256']==TEXT_SHA and len(final['cells'])==2175
 final_ids={(x['orientation'],x['period']) for x in final['cells']};assert final_ids==fresh_expected and len(final_ids)==len(final['cells'])
 fresh_odd={(x['orientation'],x['period']) for x in final['cells'] if x['period']%2};fresh_even=final_ids-fresh_odd
 assert len(fresh_odd)==2168 and all(x['status']=='unsat' and x['classified_as_negative'] for x in final['cells'] if x['period']%2)
 assert fresh_even==even_broad_unknown and all(x['status']=='unknown' and not x['classified_as_negative'] for x in final['cells'] if x['period']%2==0)
 assert final['summary']=={'negative_claims':2168,'sat':0,'unknown':7,'unsat':2168} and final['checkpoint_sha256']==sha(CHECKPOINT)==FILES['complete_periods/checkpoint.jsonl']
 assert [json.loads(x) for x in CHECKPOINT.read_text().splitlines()]==final['cells']
 assert status['identity']==IDENTITY and status['state']=='complete' and status['completed_cells']==2175 and status['result_sha256']==sha(FINAL) and status['summary']==final['summary']
 narrow={9,10,13,*range(32,127),*range(128,192),0xC2,0xC3,0xE2};broad={9,10,13,*range(32,127),*range(128,192),*range(0xC2,0xF5)}
 assert len(narrow)==165 and len(broad)==213 and narrow<broad and not narrow-broad
 assert encoded['identity']==IDENTITY and encoded['target_evaluated'] is False and encoded['assertions']['all_18_variants_subset_bag165'] and encoded['assertions']['all_18_variants_subset_bag213']
 closure=even_ids|prior_odd|fresh_odd;assert closure==universe and len(closure)==4368
 receipt=verify_receipt()
 return {'identity':IDENTITY,'target_evaluated':True,'new_target_search':False,'verification_receipt_present':receipt is not None,'final_narrow_closure_ready':receipt is not None,'universe_cells':4368,'partition':{'even_cardinality165':2184,'prior_odd_unsat213':16,'fresh_odd_unsat213':2168,'union':len(closure)},'broad213':{'excluded':4361,'unresolved_even_cells':[{'orientation':o,'period':p} for o,p in sorted(even_broad_unknown)],'unresolved_count':7,'closure':False},'subset':{'bag165_size':165,'bag213_size':213,'strict_165_subset_213':True,'additional_bag213_bytes':48},'period_equivalence':{'message_symbols':1092,'representative_period':1092,'all_positive_nominal_periods_at_or_above_1092_same_single_block':True},'scope':'one arbitrary fixed 4x4 square, direct oriented 1092 hex symbols to 546 bytes, four canonical orientations, periods1..1092, exact201 endpoint whose byte union has size165','receipt':receipt,'source_hashes':source_hashes,'limits':'No claim for odd two-square variants, Bifid at another layer, arbitrary binary layers, transforms outside the four orientations, or all classical ciphers.'}
def report(data):
 assert data['final_narrow_closure_ready'];r=data['receipt'];lines=['# Final Bifid16 one-square coverage reconciliation','',f'Identity: **ASTRA**. Verification receipt SHA-256: `{r["sha256"]}`.','','The independently verified evidence union covers all **4,368 registered cells** for the narrow exact-201 endpoint: 2,184 even-period cells are excluded by the square-independent cardinality invariant for any byte alphabet of size at most 165; 16 prior odd cells and 2,168 fresh odd cells are UNSAT under the broader 213-byte necessary bag. Because bag165 is a strict subset of bag213, every broad-bag UNSAT result also excludes the narrow endpoint.','','The seven completion-run UNKNOWN cells are all even: forward periods 562/972, reverse 16/514, byte-reverse 16, and nibble-swap 850/972. They prevent a broad-bag213 closure, but each was already excluded at cardinality165 by the even invariant. No SAT cell exists.','','Period 1092 is the whole-message representative for every positive nominal period at or above 1092 because each produces the same single block.','','This covers one arbitrary fixed 4x4 square applied directly to the four canonical orientations of the 1,092 hexadecimal symbols, with nibbles paired into 546 bytes and tested against the exact 201-codepoint endpoint. The audited ASCII binary/octal/decimal/hex/Base32/Base64 alphabets, padding, and whitespace are subsets of that byte bag.','','It does not extend the odd-period result to distinct input/output squares, place Bifid at another pipeline layer, cover arbitrary binary layers or other transforms, or close all classical cipher families.', '',f'The verifier receipt records 2,175 reconstructed formulas and result SHA-256 `{r["result_sha256"]}`.']
 return '\n'.join(lines)+'\n'
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write-report',type=Path);a=ap.parse_args();data=reconcile()
 if a.write_report:
  if not data['final_narrow_closure_ready']:raise SystemExit('refusing final report: successful verification.json receipt absent')
  if a.write_report.exists():raise SystemExit(f'refusing existing report: {a.write_report}')
  a.write_report.write_text(report(data));print(json.dumps({'identity':IDENTITY,'report':str(a.write_report),'sha256':sha(a.write_report),'final_narrow_closure':True}));return
 print(json.dumps(data,sort_keys=True,indent=2))
if __name__=='__main__':main()

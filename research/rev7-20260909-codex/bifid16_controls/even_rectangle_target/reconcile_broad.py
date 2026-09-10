#!/usr/bin/env python3
"""Read-only ASTRA reconciliation of the seven even empty-rectangle certificates."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path
HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
REPO=HERE.parents[3]
OUT=HERE/'broad_reconciliation.json'
FILES={
 'research/rev7-20260909-codex/bifid16_controls/complete_periods/reconciliation.json':'781a33597decf6f60dc0f101157dbe478d4f7d4c8f64f31eee1edd0489568b6c',
 'research/rev7-20260909-codex/bifid16_controls/complete_periods/verification.json':'58ddd2f79f9227e288b2982644ba24ea908158745e14b98efddfe7d1d6819b6d',
 'research/rev7-20260909-codex/bifid16_controls/complete_periods/target_results.json':'736a34aed38826a8c1a1bf5e4fcd24d6f4aad817a435f2e09384fe493d4d35d6',
 'research/rev7-20260909-codex/bifid16_controls/even_target/target_results.json':'acc7df78f141e79b9d3c4e23dba3124ddb7665d5cb5f7450eabd5d9a88ce1dc8',
 'research/rev7-20260909-codex/bifid16_controls/even_period_invariant.py':'1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2',
 'research/rev7-20260909-codex/bifid16_controls/even_rectangle_controls/model.py':'46c1f18e473450aba5dde3675b594d9f0b86f28d4a670514e10a806a92942e84',
 'research/rev7-20260909-codex/bifid16_controls/even_rectangle_controls/controls.py':'431d315688a2dd4f95b1db874622dd013f3be6bbaa8879f53ceea49164e634f3',
 'research/rev7-20260909-codex/bifid16_controls/even_rectangle_controls/controls.json':'9f443af6c503d7fc377551b2842d5f701a21649d910d9aebdaf30597efe17f57',
 'research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/run_target.py':'6ff6e2ed30aafdea13102ac5113b051a57705a3ba4cfdfc9f5140d1eb82032aa',
 'research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/target_gate.json':'410a9040fd2a40715680fe613dcf9fdc2383a5b5154289ce10fc04f3acbdf20c',
 'research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/target_results.json':'eec0e9f643d3b5ae2498b85eee8b8999b9ce2a8d3d714b8db1e971a048bf8ce1',
}
EXPECTED=(('forward',562),('forward',972),('reverse',16),('reverse',514),('byte_reverse',16),('nibble_swap',850),('nibble_swap',972))
def sha(path): return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(rel): return json.loads((REPO/rel).read_text())
def verify_inputs():
 for rel,digest in FILES.items(): assert sha(REPO/rel)==digest,rel
 narrow=load('research/rev7-20260909-codex/bifid16_controls/complete_periods/reconciliation.json')
 receipt=load('research/rev7-20260909-codex/bifid16_controls/complete_periods/verification.json')
 result=load('research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/target_results.json')
 assert narrow['identity']=='ASTRA' and narrow['final_narrow_closure_ready'] is True and narrow['verification_receipt_present'] is True
 assert narrow['universe_cells']==4368 and narrow['partition']['union']==4368
 assert narrow['broad213']['excluded']==4361 and narrow['broad213']['unresolved_count']==7 and narrow['broad213']['closure'] is False
 assert narrow['receipt']['sha256']==FILES['research/rev7-20260909-codex/bifid16_controls/complete_periods/verification.json']
 assert receipt=={k:v for k,v in narrow['receipt'].items() if k not in ('path','sha256')}
 # The receipt's compact content is checked explicitly, independent of the reconciliation embedding.
 assert receipt=={'complete_cells':2175,'formulas_reconstructed':2175,'identity':'ASTRA','new_target_search':False,'ok':True,'result_sha256':FILES['research/rev7-20260909-codex/bifid16_controls/complete_periods/target_results.json'],'summary':{'sat':0,'unknown':7,'unsat':2168},'verification_only':True}
 prior={(x['orientation'],x['period']) for x in narrow['broad213']['unresolved_even_cells']}
 assert prior==set(EXPECTED)
 assert result['identity']=='ASTRA' and result['target_evaluated'] is True and result['status']=='complete'
 assert result['gate_sha256']==FILES['research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/target_gate.json']
 assert result['driver_sha256']==FILES['research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/run_target.py']
 assert result['counts']=={'empty_rectangle_unresolved':0,'excluded_bag213':7,'total':7}
 rows=[]
 assert [(x['orientation'],x['period']) for x in result['cells']]==list(EXPECTED)
 for x in result['cells']:
  a=x['analysis']; assert x['status']=='excluded_bag213' and x['pair_count']==546 and x['upstream_even_row_exact'] is True and x['upstream_bound_213']=='unresolved'
  assert len(x['histogram'])==256 and sum(x['histogram'])==546 and sum(v>0 for v in x['histogram'])==x['distinct_pair_count']
  assert a['row_sets_examined']==1820 and len(a['row_set_records'])==1820 and a['max_common_missing_count']==1
  assert a['empty_4x4_rectangle_exists_relaxed'] is False and a['witness'] is None and a['excluded_bag213'] is True
  assert max(r['common_missing_count'] for r in a['row_set_records'])==1
  rows.append({'cell_id':x['cell_id'],'orientation':x['orientation'],'period':x['period'],'distinct_pairs':x['distinct_pair_count'],'max_common_missing_count':1,'row_sets_checked':1820,'classification':'excluded_bag213'})
 assert [x['distinct_pairs'] for x in rows]==[212,212,213,209,213,212,212]
 return narrow,rows

def build():
 narrow,rows=verify_inputs()
 bag213={9,10,13,*range(32,127),*range(128,192),*range(194,245)}
 assert len(bag213)==213 and not (set(range(0x10,0x20)) & bag213)
 return {
  'identity':'ASTRA','target_evaluated':True,'verification_only':True,'new_target_search':False,
  'scope':'one fixed arbitrary 4x4 Bifid square, direct four canonical orientations, all positive periods represented by 1..1092, UTF-8-scalar necessary byte bag213',
  'source_hashes':FILES,
  'prior_narrow_reconciliation_sha256':FILES['research/rev7-20260909-codex/bifid16_controls/complete_periods/reconciliation.json'],
  'successful_formula_verification_receipt_sha256':FILES['research/rev7-20260909-codex/bifid16_controls/complete_periods/verification.json'],
  'seven_rectangle_result_sha256':FILES['research/rev7-20260909-codex/bifid16_controls/even_rectangle_target/target_results.json'],
  'bag213':{'size':213,'ascii_allowed':[9,10,13]+list(range(32,127)),'bytes_0x10_through_0x1f_allowed':False,'role':'necessary byte union for valid UTF-8 scalar text with ASCII restricted to TAB/LF/CR and 0x20..0x7E'},
  'seven_rows':rows,
  'proof_accounting':{
   'registered_one_square_cells':4368,
   'odd_one_square_unsat_bag213':2184,
   'even_prior_distinct_pair_cardinality_exclusions_bag213':2177,
   'even_new_empty_rectangle_exclusions_bag213':7,
   'one_square_excluded_bag213':4368,
   'one_square_unresolved_bag213':0,
   'even_cells_excluded_for_any_ordered_pair_of_fixed_cipher_and_plain_squares':2184,
  },
  'period_equivalence':{'message_symbols':1092,'representative_period':1092,'all_positive_periods_at_or_above_1092_same_single_block':True},
  'proof':'Absence of high nibble 1 is necessary for bag213. For any fixed cipher square Sc and plaintext square Sp, Sp(1) selects row r and column c. Avoiding high nibble 1 requires the observed directed-pair graph to omit A x B, where A is cipher-square row r and B row c. Both have size four. The relaxed test allows arbitrary four-sets A and B; every registered residual has no empty 4x4 rectangle (maximum common missing count one), so no such Sc,Sp exist.',
  'limits':['Odd-period distinct input/output-square constructions are not covered.','Bifid at another pipeline layer, UTF-16, arbitrary binary intermediates, transforms beyond the four canonical orientations, and other classical cipher families are not covered.','The byte bag is a necessary UTF-8 condition, not a sufficient UTF-8 grammar or an English-language model.'],
 }
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists(): raise SystemExit('refusing existing output')
  got['reconciler_sha256']=sha(Path(__file__))
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n')
  print(json.dumps({'identity':'ASTRA','output':str(a.regenerate),'sha256':sha(a.regenerate),'one_square_bag213':'4368/4368'}));return
 saved=json.loads(OUT.read_text()); assert saved==got|{'reconciler_sha256':sha(Path(__file__))}
 print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sha(OUT),'one_square_bag213':'4368/4368','even_two_fixed_squares':'2184/2184'}))
if __name__=='__main__': main()

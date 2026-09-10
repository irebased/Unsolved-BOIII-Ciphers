#!/usr/bin/env python3
"""ASTRA source-level scope audit for RA reverse_words; no target search."""
import argparse,hashlib,json,re,subprocess,tempfile
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[1]
SNAP=HERE/'source_snapshot.json'
PINS={
 'coverage/prefix_group_alignment_audit/audit.py':'2a9ddb87a2856ff1903266ac353c99b910f3561f79fc30a4a6660bd75a4424ba',
 'coverage/prefix_group_alignment_audit/README.md':'7f1942c4d4179b47bb06480c938141bca3a767133f8c7ddfd4ca1256c30dea5a',
 'hex_cfb/prototype.py':'416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b',
 'audit/octal_audit.py':'e25cfe75323e941a0fc951b518b43f6dfc5c4473c0bb125048d227c8e40e05a0',
 'audit/octal_audit_results.json':'8b6f059370dc9e6cdbe427f76e7fedd5cdbb3df4e3d5eff93c8b27122637fddd',
 'bifid16_controls/odd_rectangle_join_target/COVERAGE_FINAL.md':'10e0b6e84df820d401454d92f2f6cb3dc4869fb42fb365bc1ab9bcd0950633c4',
}
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def reverse_words(data):
 assert data.isascii()
 return b' '.join(reversed([x for x in re.split(rb'[ \t\n\r\f]+',data) if x]))
def stripws(data):return bytes(x for x in data if x not in b' \t\r\n\x0c')
def orient(s):
 pairs=[s[i:i+2] for i in range(0,len(s),2)]
 return {'forward':s,'reverse':s[::-1],'byte_reverse':''.join(reversed(pairs)),'nibble_swap':''.join(x[::-1] for x in pairs)}
def make():
 snap=json.loads(SNAP.read_text())
 for row in snap['sources']+snap['claims']:
  raw=(HERE/row['capture']).read_bytes()
  assert hashlib.sha256(raw).hexdigest()==row['sha256'],row['path']
  if 'line_ranges' in row:
   lines=raw.decode().splitlines()
   for part in row['line_ranges']:
    assert part['text']=='\n'.join(lines[part['start']-1:part['end']]),(row['path'],part['start'])
  else:
   text=raw.decode()
   assert text.count('reverse_words')==row['reverse_words_matches']
   assert text.count('toolfmt')==row['toolfmt_matches']
 assert stripws(b'A\x0bB\tC')==b'A\x0bBC'
 assert reverse_words(b'A\x0bB C')==b'C A\x0bB'
 with tempfile.TemporaryDirectory() as tmp:
  binary=Path(tmp)/'ascii_whitespace'
  subprocess.run(['rustc','--edition=2021',str(HERE/'ascii_whitespace.rs'),'-o',str(binary)],check=True)
  rust=json.loads(subprocess.check_output([str(binary)],text=True))
 assert rust==[[9,10,12,13,32],list(reverse_words(b'A\x0bB C'))]
 assert snap['claim_count']==25 and snap['claim_term_totals']=={'reverse_words':0,'toolfmt':0}
 for rel,want in PINS.items():assert sha(ROOT/rel)==want,(rel,sha(ROOT/rel))
 src={x['path']:x for x in snap['sources']}
 assert src['crates/ra-core/src/nodes.rs']['sha256']=='ea93e1b0e235f691d7814eec0eef2b2a2b0c7f7c0fc1a76ffbebbc218796c43c'
 assert src['crates/ra-cli/src/sweep.rs']['sha256']=='cac270638d68a4c828b9aeaeee5fa3aa4f13513b0a5138916f87fe301a13c1af'
 assert src['crates/ra-cli/src/corpus.rs']['sha256']=='964793ef1019be613b28bcfb68cf177285e88562b34be7acd90cf4b31d703e01'
 assert src['crates/ra-core/src/classical/toolfmt.rs']['sha256']=='c4717437e85ac583cca4e412784b8665f2b2b1ee1e83e6eef5d8fcd2e2f9c303'
 joined='\n'.join(r['text'] for x in snap['sources'] for r in x['line_ranges'])
 for needle in ['split_ascii_whitespace()','.filter(|c| !c.is_ascii_whitespace())','self.axes.vspace.apply(mask, self.compact','let input = Repr::new(target.raw.clone().into_bytes()']:
  assert needle in joined,needle
 raw=b'12 34567 89ABC'
 compact=stripws(raw)
 raw_rw=reverse_words(raw)
 sweep_rw=reverse_words(compact)
 raw_composite=reverse_words(stripws(raw))
 assert raw_rw==b'89ABC 34567 12'
 assert sweep_rw==compact==raw_composite
 full=compact[::-1]
 assert full!=sweep_rw
 mock=['AB']+[f'{i:05X}'[-5:] for i in range(218)]
 group_reverse=''.join(reversed(mock));full_reverse=''.join(mock)[::-1]
 assert list(map(len,reversed(mock)))==[5]*218+[2] and group_reverse!=full_reverse
 o=orient('1234567890AB')
 assert len(set(o.values()))==4
 return {
  'identity':'ASTRA','target_evaluated':False,'new_target_search':False,
  'question':'Does RA or accepted ASTRA coverage establish or test visible five-token-order reversal for Rev7?',
  'source_snapshot_sha256':sha(SNAP),'source_pins':PINS,'ascii_whitespace_control_sha256':sha(HERE/'ascii_whitespace.rs'),'actual_rust_ascii_whitespace':rust,
  'ra':{'head':snap['ra_head'],'source_hashes':{k:v['sha256'] for k,v in src.items()},'stored_claims':{'count':25,'reverse_words_matches':0,'toolfmt_matches':0}},
  'semantics':{
   'node_reverse_words':'split on ASCII-whitespace runs, reverse tokens, join with one ASCII space',
   'target_loader':'load_target preserves ciphertext in Target.raw and infers display from a whitespace-compacted copy',
   'sweep_actual_input':'run separately compacts Target.raw; Ctx.stage applies Pre to that compact buffer, despite comments calling it raw text',
   'consequence':'For Rev7 sweep input, reverse_words and stripws+reverse_words are identity-pre duplicates; neither reverses visible group order.',
   'raw_composition':'On whitespace-bearing raw text, stripws+reverse_words (left-to-right) equals stripws, not the original raw text.',
   'toolfmt':'Applied after initial display decoding, immediately before modern decrypt; it does not restore the discarded visible grouping to --pre.'},
  'synthetic':{'raw':raw.decode(),'compact':compact.decode(),'raw_reverse_words':raw_rw.decode(),'sweep_reverse_words':sweep_rw.decode(),'raw_stripws_then_reverse_words':raw_composite.decode(),'full_character_reverse':full.decode(),'mock_1092_group_lengths_after_token_reverse':[5,2],'assertions':{'raw_reverse_words_distinct':True,'sweep_reverse_words_identity':True,'stripws_then_reverse_words_equals_stripws':True,'full_and_group_order_reverse_distinct':True}},
  'formatting_inference':{
   'fact':'1092=218*5+2 and the preserved display has a leading two-symbol token.',
   'conditional':'If an unformatted 1092-symbol string was first grouped left-to-right in width five and a later operation moved whole output tokens or all characters in reverse order, either reversal moves the short final token to the front.',
   'not_proved':'The token lengths alone do not prove any reversal occurred: original right-aligned/manual grouping or already-spaced source text also yields a leading short token; and the lengths cannot distinguish full-character from whole-token reversal.'},
  'astra_prior_scope':{
   'four_direct_orientations':{'forward':'s','reverse':'s[::-1]','byte_reverse':'reverse 546 two-symbol byte tokens, interiors intact','nibble_swap':'reverse each two-symbol byte token, order intact'},
   'visible_group_octal':'The pinned 32-cell probe tests left/right placement of one two-symbol ragged group and reverses the serialized octal character stream; it does not apply raw five-token-order reversal.',
   'prefix_alignment_audit':'Audits grouped decoder phase after prefix cuts, not visible token-order reversal.',
   'reviewed_exact_raw_five_token_order_transform':'No implementation was found in the pinned selected ASTRA sources; this is a bounded source-corpus statement, not a global/private-history absence claim.'},
  'proof_effects':{
   'preserved_without_target_rerun':['Any theorem stated for every input sequence remains algebraically valid.','Global hexadecimal symbol histogram and distinct-symbol cardinality are invariant under token permutation.'],
   'requires_new_input_certificates':['Direct Bifid pair histograms, typed graphs, SMT formulas and their saved exclusions depend on symbol positions.','Pairing hex symbols into bytes changes under a five-token permutation because five is odd; exact byte-bag, periodic-residue and CFB constraints depend on the resulting byte sequence.'],
   'interpretation':'Prior results remain valid for their four named orientations; a fifth token-order input lies outside them rather than invalidating them.'},
  'recommendation':{
   'first_step':'Implement one source-defined operation G on the preserved 219 display tokens: reverse token order, retain token interiors, join, and assert its hash differs from all four direct orientations. Do not use RA sweep --pre reverse_words until its compact-before-pre wiring is fixed or bypassed.',
   'smallest_new_experiment':'Run G as one additional input through the accepted direct Bifid certificate pipeline: even-period pair-cardinality/rectangle filters, then odd typed-graph and coupled-join filters only for residuals. This reuses input-independent proofs but recomputes input-dependent certificates and avoids a broad modern-cipher sweep.',
   'controls':['Synthetic 2+5+5 token fixture distinguishing G from full reversal and four direct orientations.','Round-trip token-order reversal and exact preservation of 1092 symbols/token lengths.','A planted direct Bifid fixture evaluated under G and inverted exactly.'],
   'limits':'This tests one formatting transform at one direct layer. It does not justify RA tier-3 expansion, infer historical use, or invalidate earlier cells.'},
  'assertions':{'leading_short_token_is_conditional_evidence_not_proof':True,'ra_sweep_reverse_words_currently_duplicates_identity':True,'stored_claim_inventory_has_no_axis_terms':True,'prior_four_orientation_results_not_invalidated':True}
 }
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();d=make()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refuse existing output')
  a.regenerate.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n')
  print(json.dumps({'status':'WROTE','path':str(a.regenerate),'sha256':sha(a.regenerate)}));return
 saved=json.loads((HERE/'audit.json').read_text());assert saved==d
 print(json.dumps({'identity':'ASTRA','status':'PASS','audit_sha256':sha(HERE/'audit.json'),'source_snapshot_sha256':sha(SNAP),'target_evaluated':False},indent=2,sort_keys=True))
if __name__=='__main__':main()

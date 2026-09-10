#!/usr/bin/env python3
"""Portable ASTRA source review of RA raw-pre commit; no target execution."""
import hashlib,json
from pathlib import Path
H=Path(__file__).resolve().parent;S=H/'source'
PINS={'sweep.rs':'59465e5c1d2d43ef102bbbc41d6dd2930ab7f29eeb753f60825a1bcf83663dcf','variants.rs':'6199e8658bfa4ce0cba1043b75a5a667a37f43203d9f32c80109c5711959782b','Cargo.lock':'03f3b58196c11fcd795d1ebffc97b29e441785989e4e44ebfb568be945198dd6'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def line(s,needle):
 for i,x in enumerate(s.splitlines(),1):
  if needle in x:return i
 raise AssertionError(needle)
def build():
 for n,h in PINS.items():assert sha(S/n)==h
 sw=(S/'sweep.rs').read_text();va=(S/'variants.rs').read_text();receipt=json.loads((H/'test_receipt.json').read_text())
 for needle in ['fn sweep_input_text','apply_preserving_whitespace(mask, self.text','let raw_text: Vec<u8> = sweep_input_text(&target)','text: &raw_text','"staged_inputs": staged_inputs_json']:
  assert needle in sw
 for needle in ['pub fn apply_preserving_whitespace','if byte.is_ascii_whitespace()','self.positions[next] == seen']:
  assert needle in va
 # The verifier body does not bind the newly emitted side metadata.
 verify=sw[sw.index('pub fn verify(data:'):sw.index('\n#[cfg(test)]')]
 # XF metadata is explicitly based on the first pre value, not their cross-product.
 xf=sw[sw.index('fn xf_staged_inputs'):sw.index('fn staged_input_census')]
 assert '.pres\n        .first()' in xf
 return {'identity':'ASTRA','review_only':True,'target_evaluated':False,'commit':'e127b8d6c17f567b930fe67624d3ea199528b775','parent':'e6c282187cc8a555580349d819210b544e5417b1','source_hashes':PINS|{'commit.patch':sha(S/'commit.patch'),'test_receipt.json':sha(H/'test_receipt.json')},'diff':{'files':['crates/ra-cli/src/sweep.rs','crates/ra-cli/src/variants.rs'],'insertions':885,'deletions':35},'accepted_core':{'raw_target_helper_line':line(sw,'fn sweep_input_text'),'execution_splice_line':line(sw,'apply_preserving_whitespace(mask, self.text'),'sweep_ctx_raw_line':line(sw,'text: &raw_text'),'verify_recompute_raw_helper_line':line(sw,'let raw_text: Vec<u8> = sweep_input_text(&target)'),'variant_splice_line':line(va,'pub fn apply_preserving_whitespace'),'assessment':'Execution and --recompute use the same verbatim target helper. Variant masks are mapped to the kth non-ASCII-whitespace byte, preserving mask meaning and whitespace positions.'},'focused_tests':receipt['results'],'findings':[{'severity':'auditability','title':'Saved staged-input metadata is not verified','evidence':{'emission_line':line(sw,'"staged_inputs": staged_inputs_json'),'verify_line':line(sw,'pub fn verify(data:')},'effect':'Structural and --recompute claim verification can pass if staged_inputs hashes, statuses, tuple counts or collision fields are altered. Merkle execution evidence remains checked; this defect concerns the new side metadata.','recommendation':'Reconstruct staged_inputs_json from the loaded target and recorded axes during verification and require exact equality.'},{'severity':'scope-labeling','title':'XF census is a first-pre pre-decrypt probe, not actual T3 XF provenance','evidence':{'function_line':line(sw,'fn xf_staged_inputs'),'first_pre_line':line(sw,'.first()')},'effect':'It applies XF to the first pre value immediately after display decode. Under T3 the actual XF runs after layer-1 decryption and therefore depends on primitive, key, mode and IV; under all tiers later pre values can produce different inputs. The global-looking XF census is not provenance for actual T3 XF inputs. This does not change candidate execution.','recommendation':'Label this as a first-variant/first-pre, pre-decrypt/T2 diagnostic. For T3 provenance, record actual post-layer1 XF inputs or omit the census; for T1/T2, qualify or record the relevant pre cross-product.'},{'severity':'scope-labeling','title':'Pre degeneracy diagnostic uses only the first transcription variant','evidence':{'function_line':line(sw,'fn pre_staged_inputs'),'first_mask_line':line(sw,'let mask = axes.variant_masks[0]')},'effect':'A warning based on one reading is worded as if it establishes the whole axis contributes no distinct coverage. The actual candidates retain all variants.','recommendation':'Qualify the warning to the recorded representative variant or census all variants.'}], 'conclusion':'Scoped acceptance of the raw-whitespace execution and recompute fix. The new side-metadata certificate is not yet self-verifying and its census scope is narrower than its presentation.'}
def main():
 d=build();saved=json.loads((H/'review.json').read_text());assert d==saved
 print(json.dumps({'identity':'ASTRA','status':'PASS','review_sha256':sha(H/'review.json'),'core_fix':'accepted','findings':len(d['findings'])},sort_keys=True))
if __name__=='__main__':main()

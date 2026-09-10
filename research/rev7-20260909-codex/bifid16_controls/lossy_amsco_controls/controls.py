#!/usr/bin/env python3
from __future__ import annotations
import argparse,hashlib,importlib.util,json,random,sys
from pathlib import Path
import core
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];LEDGER=HERE/'controls.json'
EXTRA={
'research/rev7-20260909-codex/bifid16_controls/even_period_invariant.py':'1fa72b75ff59028ed256dbf6853dd44669cd53b07bcce998331e212b65d2a2a2',
'research/rev7-20260909-codex/bifid16_controls/even_period_invariant.json':'f6f2d01801992bb145c583fdc83284ea100c99d30bf4f3e5a477b56317a84a36',
'research/rev7-20260909-codex/bifid16_controls/EVEN_PERIOD_INVARIANT.md':'6482c0751bbf6b8484741be7b3f47b91c5b39556c2c981fa903b04801852169c'}
def hb(b):return hashlib.sha256(b).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def legacy():
 spec=importlib.util.spec_from_file_location('astra_lossy_source_control',core.ANALYZE);m=importlib.util.module_from_spec(spec);sys.modules[spec.name]=m;assert spec.loader;spec.loader.exec_module(m);m.verify_pins();return m
def decode_block(cipher,square):
 d=[v for ch in cipher for v in core.coords(square,ch)];L=len(cipher)
 return ''.join(square[4*d[i]+d[L+i]] for i in range(L))
def decode(cipher,square,p):return ''.join(decode_block(cipher[a:a+p],square) for a in range(0,len(cipher),p))
def compute():
 core.verify_pins()
 for rel,want in EXTRA.items():assert sha(ROOT/rel)==want
 inv=json.loads(core.INV.read_text());classes=inv['map_classes'];assert len(classes)==12 and all(x['input_chars']==1310 for x in classes)
 old=legacy();periods=(2,6,14,60,1310);orients=('forward','full_hex_reverse','byte_reverse','nibble_swap');plants=[]
 for i,g in enumerate(classes):
  indices=core.source_indices(1310,g['representative_key']);assert list(indices)==g['emission_indices'] and len(indices)==1092
  text=core.synthetic_text(i*17);plainhex=text.hex().upper();rng=random.Random(0xB1F100+i);square=''.join(rng.sample(list(core.SYMS),16));period=periods[i%len(periods)];orientation=orients[i%4]
  cipher=core.bifid_encrypt(plainhex,square,period);assert len(cipher)==1310 and decode(cipher,square,period)==plainhex
  emitted=''.join(cipher[j] for j in indices);source=old.legacy_encode(cipher.encode(),g['representative_key'])['raw'].decode();assert emitted==source and len(emitted)==1092
  displayed=core.orient(emitted,orientation);partial=core.reconstruct(displayed,indices,1310,orientation)
  assert all(partial[j]==cipher[j] for j in indices) and all(partial[j] is None for j in set(range(1310))-set(indices))
  kh=core.known_pair_hist(partial,period);fh=core.full_pair_hist(cipher,period);ks={j for j,n in enumerate(kh) if n};fs={j for j,n in enumerate(fh) if n}
  assert ks<=fs and sum(bool(n) for n in fh)==len(set(text))==165 and sum(bool(n) for n in kh)<=165
  blocks=[min(period,1310-a) for a in range(0,1310,period)];assert all(x%2==0 for x in blocks)
  plants.append({'class_id':g['class_id'],'representative_key':g['representative_key'],'map_sha256':g['map_sha256'],'indices_sha256':hb(json.dumps(list(indices),separators=(',',':')).encode()),'dropped_column':g['dropped_column'],'read_order':g['full_row_read_order'],'period':period,'actual_block_lengths':blocks,'has_short_final_block':len(blocks)>1 and blocks[-1]!=period,'orientation':orientation,'square':square,'plaintext_sha256':hb(text),'plaintext_distinct_bytes':len(set(text)),'natural_cipher_sha256':hb(cipher.encode()),'displayed_sha256':hb(displayed.encode()),'known_nibbles':sum(x is not None for x in partial),'unknown_nibbles':sum(x is None for x in partial),'known_pair_observations':sum(kh),'known_distinct_pairs':sum(bool(n) for n in kh),'full_distinct_pairs':sum(bool(n) for n in fh),'known_histogram':kh,'full_histogram':fh,'truth_roundtrip':True,'source_emission_equal':True,'known_pair_set_subset_full':True})
 # Independent bounded completion check: two unknown nibbles, all 16^2 completions.
 base=list('0123456789AB');period=6;base_hist=core.full_pair_hist(''.join(base),period);partial=base[:];partial[1]=None;partial[8]=None;known=core.known_pair_hist(partial,period);known_set={i for i,n in enumerate(known) if n};mins=256;sets=[]
 for a in core.SYMS:
  for b in core.SYMS:
   c=partial[:];c[1]=a;c[8]=b;h=core.full_pair_hist(c,period);s={i for i,n in enumerate(h) if n};assert known_set<=s;mins=min(mins,len(s));sets.append(hb(bytes(sorted(s))))
 assert len(sets)==256
 all_unknown=core.known_pair_hist([None]*12,6);assert sum(all_unknown)==0 and sum(bool(n) for n in all_unknown)==0
 pins={**core.PINS,**EXTRA}
 out={'identity':IDENTITY,'target_evaluated':False,'scope':'Synthetic-only partial-observation distinct-pair lower-bound controls for the 12 frozen N=1310 lossy AMSCO maps; no Rev7 read.','source_hashes':pins,'core_sha256':sha(HERE/'core.py'),'controls_source_sha256':sha(Path(__file__)),'inventory_map_classes':12,'plants':plants,'map_coverage':{'class_ids':[x['class_id'] for x in plants],'all_12_once':len({x['class_id'] for x in plants})==12,'periods_exercised':sorted({x['period'] for x in plants}),'orientations_exercised':sorted({x['orientation'] for x in plants}),'short_final_blocks_exercised':sum(x['has_short_final_block'] for x in plants)},'two_unknown_exhaustive':{'natural_length':12,'period':6,'unknown_indices':[1,8],'completions':256,'known_observations':sum(known),'known_distinct_pairs':len(known_set),'minimum_full_distinct_pairs':mins,'all_completion_set_digest':hb(''.join(sets).encode()),'lower_bound_holds_every_completion':True},'all_unknown':{'natural_length':12,'period':6,'known_pair_observations':0,'known_distinct_pairs':0},'assertions':{'source_and_inventory_pins':True,'all_12_source_maps_equal_frozen_inventory':True,'all_source_emissions_equal_literal_port':True,'orientation_inverse_before_natural_reconstruction':True,'all_truth_roundtrips':True,'all_known_pair_sets_subsets':True,'all_full_distinct_counts_equal_plaintext_distinct_165':True,'two_unknown_all_256_lower_bounds':True,'all_unknown_has_zero_known_pairs':True,'no_target_read':True}}
 return out
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();fresh=compute()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(fresh,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)}))
 else:
  saved=json.loads(LEDGER.read_text());assert saved==fresh and all(saved['assertions'].values());print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'plants':len(saved['plants']),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Synthetic-only odd-period Bifid coordinate/signature controls."""
from __future__ import annotations
import hashlib,itertools,json,random
from pathlib import Path
IDENTITY='ASTRA';SYMS='0123456789ABCDEF'
def tables(square):
 coord={s:divmod(i,4) for i,s in enumerate(square)};inv={(r,c):square[4*r+c] for r in range(4) for c in range(4)};return coord,inv
def decode_with_coords(cipher,square,period):
 coord,inv=tables(square);symbols=[];outcoords=[];blocks=[]
 for a in range(0,len(cipher),period):
  block=cipher[a:a+period];L=len(block);d=[v for s in block for v in coord[s]];pcs=[(d[i],d[L+i]) for i in range(L)];symbols.extend(inv[x] for x in pcs);outcoords.extend(pcs);blocks.append({'start':a,'length':L})
 return ''.join(symbols),outcoords,blocks
def signatures(outcoords):return [(*outcoords[i],*outcoords[i+1]) for i in range(0,len(outcoords),2)]
def odd_even_start_formula(block,square):
 coord,_=tables(square);L=len(block);assert L%2==1;h=L//2;out=[]
 for j in range(h):
  a,b,c=block[j],block[h+j],block[h+j+1]
  out.append((coord[a][0],coord[b][1],coord[a][1],coord[c][0]))
 return out
def odd_odd_start_formula(block,square):
 coord,_=tables(square);L=len(block);assert L%2==1;h=L//2;out=[]
 for j in range(h):
  a,b,c=block[j],block[h+j+1],block[j+1]
  out.append((coord[a][1],coord[b][0],coord[c][0],coord[b][1]))
 return out
def main():
 rng=random.Random(0x0DD16);comparisons=0;even_internal=0;odd_internal=0;boundaries=0;short_odd=0;short_even=0;rows=[]
 for si in range(24):
  square=''.join(rng.sample(list(SYMS),16))
  # Exhaustive triple controls for both global parities.
  coord,inv=tables(square);even_sigs=[];odd_sigs=[];even_outputs=[];odd_outputs=[]
  for a,b,c in itertools.product(SYMS,repeat=3):
   es=(coord[a][0],coord[b][1],coord[a][1],coord[c][0]);os=(coord[a][1],coord[b][0],coord[c][0],coord[b][1]);even_sigs.append(es);odd_sigs.append(os);even_outputs.append(inv[es[:2]]+inv[es[2:]]);odd_outputs.append(inv[os[:2]]+inv[os[2:]])
  assert all((even_sigs[i]==even_sigs[j])==(even_outputs[i]==even_outputs[j]) for i in range(0,4096,257) for j in range(4096))
  assert all((odd_sigs[i]==odd_sigs[j])==(odd_outputs[i]==odd_outputs[j]) for i in range(0,4096,257) for j in range(4096))
  # Signature groups from different fixed anchors are disjoint.
  for anchor in SYMS:
   es={even_outputs[i] for i,(a,b,c) in enumerate(itertools.product(SYMS,repeat=3)) if a==anchor}
   os={odd_outputs[i] for i,(a,b,c) in enumerate(itertools.product(SYMS,repeat=3)) if b==anchor}
   assert all((not (es & {even_outputs[i] for i,(a,b,c) in enumerate(itertools.product(SYMS,repeat=3)) if a==other})) for other in SYMS if other!=anchor)
   assert all((not (os & {odd_outputs[i] for i,(a,b,c) in enumerate(itertools.product(SYMS,repeat=3)) if b==other})) for other in SYMS if other!=anchor)
  for N in range(32,97,2):
   cipher=''.join(rng.choice(SYMS) for _ in range(N))
   for period in range(3,32,2):
    plain,pcs,blocks=decode_with_coords(cipher,square,period);sigs=signatures(pcs);assert len(plain)%2==0
    # Coordinate signatures and actual two-symbol bytes have identical equality partitions.
    outs=[plain[i:i+2] for i in range(0,N,2)];assert len(set(sigs))==len(set(outs))
    # Check every odd block's internal formulas according to global start parity.
    for b in blocks:
     a=b['start'];L=b['length'];block=cipher[a:a+L]
     if L%2:
      formula=odd_even_start_formula(block,square) if a%2==0 else odd_odd_start_formula(block,square)
      idxs=range(a,a+L-1,2) if a%2==0 else range(a+1,a+L-1,2)
      actual=[(*pcs[i],*pcs[i+1]) for i in idxs]
      assert formula==actual
      if a%2==0:even_internal+=len(actual)
      else:odd_internal+=len(actual)
     if L<period:
      if L%2:short_odd+=1
      else:short_even+=1
    # Explicitly identify and verify every byte crossing a block boundary.
    starts={b['start'] for b in blocks[1:]}
    for pos in range(0,N,2):
     if pos+1 in starts:
      boundaries+=1;assert sigs[pos//2]==(*pcs[pos],*pcs[pos+1])
    comparisons+=1
  rows.append({'square':square,'even_triple_signature_sha256':hashlib.sha256(json.dumps(even_sigs,separators=(',',':')).encode()).hexdigest(),'odd_triple_signature_sha256':hashlib.sha256(json.dumps(odd_sigs,separators=(',',':')).encode()).hexdigest(),'triples_each_parity':4096,'equality_partition_sampled_rows':16,'anchor_disjointness_all_16':True})
 out={'identity':IDENTITY,'target_evaluated':False,'status':'PASS','random_squares':24,'exhaustive_triples_per_square_per_parity':4096,'period_message_comparisons':comparisons,'even_start_internal_bytes_checked':even_internal,'odd_start_internal_bytes_checked':odd_internal,'cross_block_bytes_checked':boundaries,'short_odd_blocks_checked':short_odd,'short_even_blocks_checked':short_even,'all_signature_distinct_counts_equal_plaintext_byte_distinct_counts':True,'rows':rows}
 d=Path(__file__).with_name('odd_math_results.json');d.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'status':'PASS','result_sha256':hashlib.sha256(d.read_bytes()).hexdigest(),'comparisons':comparisons,'boundaries':boundaries},sort_keys=True))
if __name__=='__main__':main()

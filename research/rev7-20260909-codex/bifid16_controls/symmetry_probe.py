#!/usr/bin/env python3
"""Synthetic 4x4 Bifid equations and symmetry checks; never reads Rev7."""
from __future__ import annotations
import hashlib, itertools, json, random
from pathlib import Path

SYMS = "0123456789ABCDEF"
IDENTITY = "ASTRA"

def coords(square: str, symbol: str) -> tuple[int,int]:
    q=square.index(symbol); return divmod(q,4)

def encode_block(plain: str, square: str) -> str:
    # Legacy encodePolybios followed by encodeNumbers: coordinate pairs,
    # then first coordinates followed by second coordinates.
    pairs=[coords(square,s) for s in plain]
    digits=[r for r,_ in pairs]+[c for _,c in pairs]
    return ''.join(square[4*digits[i]+digits[i+1]] for i in range(0,len(digits),2))

def decode_block(cipher: str, square: str) -> str:
    # Legacy decodeNumbers: flatten ciphertext coordinate pairs, split in half,
    # and interleave the halves into plaintext coordinate pairs.
    d=[x for s in cipher for x in coords(square,s)]
    n=len(cipher)
    return ''.join(square[4*d[i]+d[n+i]] for i in range(n))

def encode(plain: str, square: str, period: int) -> str:
    assert period>0
    return ''.join(encode_block(plain[i:i+period],square) for i in range(0,len(plain),period))

def decode(cipher: str, square: str, period: int) -> str:
    assert period>0
    return ''.join(decode_block(cipher[i:i+period],square) for i in range(0,len(cipher),period))

def relabel(square: str, row_perm: tuple[int,...], col_perm: tuple[int,...]) -> str:
    out=['?']*16
    for r in range(4):
        for c in range(4): out[4*row_perm[r]+col_perm[c]]=square[4*r+c]
    return ''.join(out)

def first_counterexample(square: str, row_perm: tuple[int,...], col_perm: tuple[int,...]):
    sq2=relabel(square,row_perm,col_perm)
    for n in range(2,9):
        for period in range(1,n+1):
            for tup in itertools.product(SYMS[:4],repeat=n):
                c=''.join(tup)
                a=decode(c,square,period); b=decode(c,sq2,period)
                if a!=b: return {'cipher':c,'period':period,'plain_original':a,'plain_relabelled':b}
    return None

def main():
    rng=random.Random(0xB1F1D16)
    fixtures=[]
    perms=list(itertools.permutations(range(4)))
    for case in range(16):
        square=''.join(rng.sample(list(SYMS),16))
        n=rng.randrange(2,50); period=rng.randrange(1,18)
        plain=''.join(rng.choice(SYMS) for _ in range(n))
        cipher=encode(plain,square,period)
        assert decode(cipher,square,period)==plain
        for pi in perms:
            assert decode(cipher,relabel(square,pi,pi),period)==plain
        fixtures.append({'square':square,'length':n,'period':period,
                         'last_block_length':n%period or period,
                         'plain_sha256':hashlib.sha256(plain.encode()).hexdigest(),
                         'cipher_sha256':hashlib.sha256(cipher.encode()).hexdigest()})
    # Separate row/column relabelling is not a general symmetry.
    swap=(1,0,2,3); ident=(0,1,2,3)
    sep=first_counterexample(SYMS,swap,ident)
    assert sep is not None
    # Transposition is also not a general plaintext-preserving symmetry.
    transpose_square=relabel(SYMS, (0,1,2,3), (0,1,2,3))
    transpose_square=''.join(SYMS[4*c+r] for r in range(4) for c in range(4))
    trans=None
    for n in range(2,9):
        for period in range(1,n+1):
            for tup in itertools.product(SYMS[:4],repeat=n):
                c=''.join(tup)
                a=decode(c,SYMS,period); b=decode(c,transpose_square,period)
                if a!=b:
                    trans={'cipher':c,'period':period,'plain_original':a,'plain_transposed':b}; break
            if trans: break
        if trans: break
    assert trans
    out={'identity':IDENTITY,'target_evaluated':False,
         'synthetic_roundtrips':fixtures,
         'diagonal_s4_checks':len(fixtures)*len(perms),
         'diagonal_s4_all_passed':True,
         'separate_row_column_counterexample':sep,
         'transpose_counterexample':trans}
    dest=Path(__file__).with_name('symmetry_results.json')
    dest.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'identity':IDENTITY,'status':'PASS','result':str(dest),
                      'result_sha256':hashlib.sha256(dest.read_bytes()).hexdigest()}))
if __name__=='__main__': main()

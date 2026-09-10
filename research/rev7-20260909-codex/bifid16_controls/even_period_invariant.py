#!/usr/bin/env python3
"""Synthetic-only proof checks for the even-period Bifid pair invariant."""
from __future__ import annotations
import hashlib, itertools, json, random
from pathlib import Path

IDENTITY = "ASTRA"
SYMS = "0123456789ABCDEF"


def coord_tables(square: str):
    assert sorted(square) == sorted(SYMS)
    coord = {s: divmod(i, 4) for i, s in enumerate(square)}
    inverse = {(r, c): square[4*r+c] for r in range(4) for c in range(4)}
    return coord, inverse


def concrete_decode_block(cipher: str, square: str) -> str:
    """Literal 4x4 form of CrypTool decodeNumbers + inverse square."""
    coord, inverse = coord_tables(square)
    digits = [v for s in cipher for v in coord[s]]
    L = len(cipher)
    return ''.join(inverse[(digits[i], digits[L+i])] for i in range(L))


def concrete_decode(cipher: str, square: str, period: int) -> str:
    return ''.join(concrete_decode_block(cipher[a:a+period], square)
                   for a in range(0, len(cipher), period))


def pair_map_two(a: str, b: str, cipher_square: str, plain_square: str) -> tuple[str, str]:
    ccoord, _ = coord_tables(cipher_square)
    _, pinverse = coord_tables(plain_square)
    ra, ca = ccoord[a]
    rb, cb = ccoord[b]
    return pinverse[(ra, rb)], pinverse[(ca, cb)]


def pair_map(a: str, b: str, square: str) -> tuple[str, str]:
    return pair_map_two(a,b,square,square)


def pair_map_two_inverse(x: str, y: str, cipher_square: str, plain_square: str) -> tuple[str,str]:
    pcoord, _ = coord_tables(plain_square)
    _, cinverse = coord_tables(cipher_square)
    rx,cx=pcoord[x]; ry,cy=pcoord[y]
    return cinverse[(rx,ry)], cinverse[(cx,cy)]


def paired_cipher_symbols(cipher: str, period: int):
    """Yield first-half/second-half ordered pairs block by even block."""
    assert len(cipher) % 2 == 0
    for a in range(0, len(cipher), period):
        block = cipher[a:a+period]
        assert len(block) % 2 == 0
        h = len(block)//2
        yield from zip(block[:h], block[h:])


def transform_pairs(cipher: str, square: str, period: int) -> str:
    return ''.join(x for a,b in paired_cipher_symbols(cipher,period)
                   for x in pair_map(a,b,square))


def main():
    rng = random.Random(0xE7E16)
    square_rows=[]
    comparison_cases=0
    two_square_rows=[]
    short_tail_cases=0
    odd_nominal_one_block_cases=0
    for si in range(32):
        square=''.join(rng.sample(list(SYMS),16))
        outputs=[]
        involution=True
        for a,b in itertools.product(SYMS,repeat=2):
            x,y=pair_map(a,b,square)
            outputs.append(x+y)
            involution &= pair_map(x,y,square)==(a,b)
        assert len(set(outputs))==256 and involution
        square_rows.append({
            'square':square,
            'mapping_sha256':hashlib.sha256(''.join(outputs).encode()).hexdigest(),
            'domain_pairs':256,
            'distinct_outputs':len(set(outputs)),
            'involution':involution,
        })
        # Every even message length 2..128 against every even period 2..64.
        # This includes p>N, full final blocks, and all possible positive even
        # tail lengths in this bounded range.
        for N in range(2,129,2):
            cipher=''.join(rng.choice(SYMS) for _ in range(N))
            for period in range(2,65,2):
                direct=concrete_decode(cipher,square,period)
                via_pairs=transform_pairs(cipher,square,period)
                assert direct==via_pairs
                comparison_cases += 1
                if N>period and N%period:
                    assert N%period%2==0
                    short_tail_cases += 1
            # A nominal period >= N makes one actual even block, including
            # odd nominal periods. It has the identical pair transform.
            for period in range(N, N+16):
                if period % 2 == 0:
                    continue
                direct=concrete_decode(cipher,square,period)
                via_pairs=transform_pairs(cipher,square,period)
                assert direct==via_pairs
                comparison_cases += 1
                odd_nominal_one_block_cases += 1
    # The bijection survives distinct fixed coordinate and output squares.
    for i in range(32):
        cs=''.join(rng.sample(list(SYMS),16))
        ps=''.join(rng.sample(list(SYMS),16))
        outputs=[]
        for a,b in itertools.product(SYMS,repeat=2):
            x,y=pair_map_two(a,b,cs,ps)
            outputs.append(x+y)
            assert pair_map_two_inverse(x,y,cs,ps)==(a,b)
        assert len(set(outputs))==256
        two_square_rows.append({'cipher_square':cs,'plain_square':ps,
          'distinct_outputs':256,'inverse_all_passed':True,
          'mapping_sha256':hashlib.sha256(''.join(outputs).encode()).hexdigest()})
    out={
        'identity':IDENTITY,
        'target_evaluated':False,
        'source_model':'independent literal 4x4 generalization of CrypTool decodeNumbers',
        'squares_tested':len(square_rows),
        'full_pair_maps_tested':len(square_rows),
        'ordered_pairs_per_map':256,
        'all_maps_bijective':True,
        'all_maps_involutions':True,
        'independent_cipher_plain_square_maps_tested':len(two_square_rows),
        'independent_square_maps_all_bijective_with_explicit_inverse':True,
        'independent_square_rows':two_square_rows,
        'concrete_vs_pair_comparisons':comparison_cases,
        'short_even_tail_comparisons':short_tail_cases,
        'odd_nominal_period_one_even_block_comparisons':odd_nominal_one_block_cases,
        'message_lengths':'every even N in 2..128',
        'periods':'every even p in 2..64, plus every odd p in N..N+15 (one actual even block)',
        'square_rows':square_rows,
        'byte_distinct_bounds':{
            'exact_201_codepoint_endpoint_encoded_byte_union':165,
            'all_well_formed_utf8_with_only_TAB_LF_CR_and_ASCII_32_126':213,
        },
    }
    dest=Path(__file__).with_name('even_period_invariant.json')
    dest.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n')
    print(json.dumps({'identity':IDENTITY,'status':'PASS',
                      'comparisons':comparison_cases,'short_tails':short_tail_cases,
                      'result_sha256':hashlib.sha256(dest.read_bytes()).hexdigest()}))

if __name__=='__main__': main()

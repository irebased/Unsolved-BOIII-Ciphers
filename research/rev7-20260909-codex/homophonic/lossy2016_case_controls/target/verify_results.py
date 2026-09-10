#!/usr/bin/env python3
"""Read-only independent replay of the mixed-case target's first-empty prefixes."""
from pathlib import Path
import argparse,hashlib,json,re
from Crypto.Cipher import AES,DES

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[4]
RESULT=HERE/'target_results.json'
LEDGER=HERE/'empty_prefix_certificates.json'
GATE=HERE/'target_gate.json'
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx'
DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
ORIENTS=('forward','full_hex_reverse','byte_reverse','nibble_swap')
CIPHERS=('des','aes128')
IVS=('nul','ascii0')
ALLOWED=bytes([32]+list(range(65,91))+list(range(97,123)))
EXPECTED_RESULT_SHA='813ced86f6b41ba1418e641bfb72cff5e760c9e5a5226fb7ee9618058fd9f4f5'
EXPECTED_GATE_SHA='775cb1ca73b30b286075d27bc8b7b7ef48a14220ddd3546cc5db6914b69a4840'
TEXT_SHA='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'

def hb(x): return hashlib.sha256(x).hexdigest()
def sha(p): return hb(Path(p).read_bytes())

def orient(s,name):
    if name=='forward': return s
    if name=='full_hex_reverse': return s[::-1]
    pairs=[s[i:i+2] for i in range(0,len(s),2)]
    if name=='byte_reverse': return ''.join(reversed(pairs))
    if name=='nibble_swap': return ''.join(x[::-1] for x in pairs)
    raise ValueError(name)

def reconstruct(observed,nbytes=819):
    assert len(observed)==4*(nbytes//3)
    rows=nbytes//3; vals=[]; masks=[]
    for r in range(rows):
        kept=observed[2*r:2*r+2]
        full=observed[2*rows+2*r:2*rows+2*r+2]
        vals.extend((int(full,16),int(kept[0],16),int(kept[1],16)<<4))
        masks.extend((255,15,240))
    return bytes(vals),bytes(masks)

def transition(st,b):
    if b==32: return 'B'
    if 97<=b<=122: return {'B':'L','L':'L','U':'L'}.get(st)
    if 65<=b<=90: return {'B':'U','U':'C','C':'C'}.get(st)
    return None

def cipher(name):
    if name=='des': return DES.new(b'Zombies\0',DES.MODE_ECB),8
    return AES.new(b'Zombies'+b'\0'*9,AES.MODE_ECB),16

def independent_cell(observed,cipher_name,iv_name):
    vals,masks=reconstruct(observed)
    e,bs=cipher(cipher_name)
    iv=(bytes(bs) if iv_name=='nul' else b'0'*bs)
    # state tuple: complete register, plaintext prefix, ciphertext prefix, DFA state
    front=[(iv,b'',b'','B')]
    counts=[]; accepted=0; calls=0; final_attempts=[]
    for pos,(v,m) in enumerate(zip(vals,masks)):
        nxt=[]; attempts=[]
        for reg,pt,ct,st in front:
            k=e.encrypt(reg)[0]; calls+=1
            candidates=[v^k] if m==255 else ALLOWED
            for plain in candidates:
                ns=transition(st,plain)
                c=v if m==255 else plain^k
                mask_ok=((c&m)==(v&m))
                ok=ns is not None and mask_ok
                attempts.append({
                    'parent_plaintext_hex':pt.hex(),
                    'parent_ciphertext_hex':ct.hex(),
                    'state_before':st,
                    'keystream_byte':k,
                    'plaintext_byte':plain,
                    'ciphertext_byte':c,
                    'mask':m,
                    'masked_observed':v&m,
                    'mask_match':mask_ok,
                    'state_after':ns,
                    'accepted':ok,
                })
                if ok:
                    nxt.append((reg[1:]+bytes([c]),pt+bytes([plain]),ct+bytes([c]),ns))
        accepted+=len(nxt); counts.append(len(nxt)); front=nxt
        if not front:
            final_attempts=attempts
            assert attempts and not any(x['accepted'] for x in attempts)
            return {
                'first_empty_after_bytes':pos+1,
                'frontier_counts':counts,
                'accepted_states':accepted,
                'block_calls':calls,
                'empty_position':pos,
                'value':v,
                'mask':m,
                'attempt_count':len(attempts),
                'failure_counts':{
                    'dfa':sum(x['state_after'] is None for x in attempts),
                    'mask':sum(x['state_after'] is not None and not x['mask_match'] for x in attempts),
                },
                'attempts':attempts,
            }
    raise AssertionError('expected an empty frontier')

def canonical():
    t=MDX.read_text()
    a=t.index('`83 B57B2')+1; b=t.index('`',a)
    s=''.join(t[a:b].split()).upper()
    assert len(s)==1092 and hb(s.encode())==TEXT_SHA
    d=''.join(next(x for x in json.loads(DATA.read_text()) if x.get('id')=='rev7')['ciphertext'].split()).upper()
    assert s==d
    return s

def build_ledger():
    assert sha(RESULT)==EXPECTED_RESULT_SHA and sha(GATE)==EXPECTED_GATE_SHA
    out=json.loads(RESULT.read_text())
    assert out['identity']=='ASTRA' and out['target_evaluated'] is True
    expected=[f'{o}|{c}|{v}' for o in ORIENTS for c in CIPHERS for v in IVS]
    assert [x['id'] for x in out['cells']]==expected
    can=canonical(); rows=[]
    for stored in out['cells']:
        obs=orient(can,stored['orientation'])
        cert=independent_cell(obs,stored['cipher'],stored['iv'])
        assert stored['complete'] and stored['capped_reason'] is None and stored['solutions']==[]
        assert cert['first_empty_after_bytes']==stored['stopped_after_bytes']
        assert cert['frontier_counts']==stored['frontier_counts']
        assert cert['accepted_states']==stored['accepted_states']
        assert cert['block_calls']==stored['block_calls']
        assert hb(obs.encode())==stored['observed_sha256']
        rows.append({'id':stored['id'],'observed_sha256':stored['observed_sha256'],**cert})
    return {
        'identity':'ASTRA',
        'target_evaluated':True,
        'verification_kind':'independent PyCryptodome ECB recurrence and separately coded four-state DFA; first empty prefix only',
        'result_sha256':EXPECTED_RESULT_SHA,
        'gate_sha256':EXPECTED_GATE_SHA,
        'canonical_text_sha256':TEXT_SHA,
        'cells_verified':len(rows),
        'all_first_empty_certificates_valid':True,
        'rows':rows,
    }

def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--write-ledger',type=Path)
    a=ap.parse_args()
    got=build_ledger()
    if a.write_ledger:
        if a.write_ledger.exists(): raise SystemExit('refusing existing ledger')
        a.write_ledger.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
    else:
        assert LEDGER.exists() and json.loads(LEDGER.read_text())==got
    print(json.dumps({'identity':'ASTRA','verified':True,'cells':16,'result_sha256':EXPECTED_RESULT_SHA,'ledger_sha256':sha(a.write_ledger or LEDGER)},sort_keys=True))

if __name__=='__main__': main()

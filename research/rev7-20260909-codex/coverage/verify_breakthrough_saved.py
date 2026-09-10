#!/usr/bin/env python3
"""ASTRA: independent retained-data checks; never re-executes target crypto/search."""
from pathlib import Path
from collections import Counter
import json,hashlib,gzip,math
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[2]
def raw(path):
    return path.read_bytes() if path.exists() else gzip.decompress(path.with_suffix(path.suffix+'.gz').read_bytes())
def read(path): return json.loads(raw(path))
def sha(b):return hashlib.sha256(b).hexdigest()
def main():
    limb_path=HERE/'limb32_checkerboard/target_results.json';limb=read(limb_path)
    lang=read(HERE/'limb32_checkerboard/sibling_char4.json');den=lang['tetragrams']+28**4;checked=0;maxerr=0
    assert len(limb['cells'])==1440 and len(limb['serializers'])==32
    for candidate in limb['selected_heuristic_candidates']:
        toks=candidate['tokens'];n=len(toks);counts=Counter(toks)
        ioc=sum(v*(v-1) for v in counts.values())/(n*(n-1));assert abs(ioc-candidate['token_ioc'])<1e-15
        for row in candidate['anneal']['restarts_retained']:
            assert len(row['mapping'])==len(set(row['mapping'].values()))
            text=''.join(row['mapping'][t] for t in toks)
            assert text==row['plaintext'] and sha(text.encode())==row['plaintext_sha256']
            score=math.fsum(math.log((lang['counts'].get(text[i:i+4],0)+1)/den) for i in range(len(text)-3))
            err=abs(score-row['score']);maxerr=max(maxerr,err);assert err<1e-7;checked+=1
    assert checked==80
    path=HERE/'byte_dihedral_modern/target_results.json';b=read(path)
    corpus=read(ROOT/'lavender/src/data/ciphers/revelations.json')
    tokens=next(r['ciphertext'] for r in corpus if r['id']=='rev7').split();hx=''.join(tokens)
    assert sha(hx.encode())=='5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c'
    pairs=[hx[i:i+2] for i in range(0,len(hx),2)]
    oriented={'forward':hx,'full_hex_reverse':hx[::-1],'byte_pair_reverse':''.join(pairs[::-1]),'nibble_swap':''.join(p[::-1] for p in pairs),'visible_token_reverse':''.join(tokens[::-1])}
    # Independent string-of-bits construction of each byte permutation.
    groups={}
    for orientation,h in oriented.items():
        for reflect in (False,True):
            for k in range(8):
                values=[]
                for value in bytes.fromhex(h):
                    bits=f'{value:08b}';bits=bits[::-1] if reflect else bits
                    bits=bits[k:]+bits[:k];values.append(int(bits,2))
                transformed=bytes(values);key=sha(transformed);alias=(orientation,('reflect:' if reflect else 'rotate:')+str(k))
                if key not in groups:groups[key]={'input':transformed,'aliases':set()}
                assert groups[key]['input']==transformed;groups[key]['aliases'].add(alias)
    assert len(groups)==48 and sum(len(g['aliases']) for g in groups.values())==80
    recorded={g['input_sha256']:{(a['orientation'],a['transform']) for a in g['aliases']} for g in b['input_groups']}
    assert recorded=={h:g['aliases'] for h,g in groups.items()}
    rows=b['rows'];assert len(rows)==14976 and len({r['id'] for r in rows})==len(rows)
    per_input=Counter(r['input_sha256'] for r in rows);assert set(per_input)==set(groups) and set(per_input.values())=={312}
    table={r['n']:r['d'] for r in read(HERE/'occupancy_screen_controls/threshold_table.json')['rows']}
    windows=0;flags=0
    for row in rows:
        assert row['status']=='ok' and row['output_length']==546
        expected=[]
        for which in ('full','tail'):
            score=row.get(which)
            if score is None:continue
            windows+=1
            assert score['threshold_d']==table[score['n']] and score['screen_hit']==(score['D']<=table[score['n']])
            if score['screen_hit']:expected.append('occupancy:'+which)
            a=row['ascii'][which];assert a['total']==score['n'] and abs(a['ratio']-a['allowed']/a['total'])<1e-15
            assert a['hit']==(a['allowed']*4>=a['total']*3)
            if a['hit']:expected.append('ascii:'+which)
        assert sorted(expected)==sorted(row['flagged_windows']);flags+=bool(expected)
    assert windows==29568 and flags==0
    # Compare every old direct computation with its corresponding retained new row.
    old=read(HERE/'first_layer_occupancy/target_results.json')
    new_index={(r['input_sha256'],r['cipher'],r['mode'],r['key'],r['iv']):r for r in rows}
    overlap=0
    for row in old['rows']:
        h=sha(bytes.fromhex(oriented[row['orientation']]))
        other=new_index[(h,row['cipher'],row['mode'],row['key'],row['iv'])]
        assert other['output_sha256']==row['output_sha256'] and other['output_length']==row['output_length']
        assert other['full']==row['full'] and other['tail']==row['tail'];overlap+=1
    assert overlap==1560
    report={'identity':'ASTRA','target_reexecuted':False,'script_sha256':sha(Path(__file__).read_bytes()),
      'limb32':{'result_sha256':sha(raw(limb_path)),'candidates_reconstructed':checked,'independent_full_score_max_error':maxerr},
      'byte_dihedral':{'result_sha256':sha(raw(path)),'independently_rebuilt_inputs':len(groups),'aliases':80,'row_count':len(rows),'windows':windows,'flags':flags,'old_direct_outputs_matched':overlap,'new_input_contexts':len(rows)-overlap}}
    output=HERE/'breakthrough_saved_verification.json'
    if output.exists():assert read(output)==report
    else:output.write_text(json.dumps(report,indent=2,sort_keys=True)+'\n')
    print(json.dumps(report,sort_keys=True))
if __name__=='__main__':main()

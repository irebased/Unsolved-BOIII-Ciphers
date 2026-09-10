#!/usr/bin/env python3
"""ASTRA exhaustive reduced-grid and independent literal-square controls."""
from __future__ import annotations
import argparse,hashlib,itertools,json,random
from pathlib import Path
from model import analyze
HERE=Path(__file__).resolve().parent

def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def fibers(square,kind,side):
    # Independent full-pair coordinate evaluation. Square is position -> symbol.
    coords={s:divmod(pos,side) for pos,s in enumerate(square)}
    patterns=[0]*(side*side)
    for a in range(side*side):
        for b in range(side*side):
            x=coords[a][0 if kind[0]=='R' else 1]
            y=coords[b][0 if kind[1]=='R' else 1]
            patterns[side*x+y]|=1<<(side*side*a+b)
    return patterns

def square_from_witness(w,kind,side):
    n=side*side; A={a for a in range(n) if w['A']>>a&1};B={a for a in range(n) if w['B']>>a&1};sq=[None]*n
    if kind[0]!=kind[1]:
        row,col=(A,B) if kind=='RC' else (B,A)
        assert len(row&col)==1
        sq[0]=next(iter(row&col))
        for j,s in enumerate(sorted(row-col),1):sq[j]=s
        for i,s in enumerate(sorted(col-row),1):sq[side*i]=s
        target=0
    else:
        assert A==B or not(A&B)
        if kind=='RR':
            for j,s in enumerate(sorted(A)):sq[j]=s
            if A!=B:
                for j,s in enumerate(sorted(B)):sq[side+j]=s
        else:
            for i,s in enumerate(sorted(A)):sq[side*i]=s
            if A!=B:
                for i,s in enumerate(sorted(B)):sq[side*i+1]=s
        target=0 if A==B else 1
    unused=iter(sorted(set(range(n))-set(sq)))
    for i in range(n):
        if sq[i] is None:sq[i]=next(unused)
    assert sorted(sq)==list(range(n))
    return sq,target

def build():
    reduced=[]
    for kind in ('RR','RC','CR','CC'):
        patterns=set(p for sq in itertools.permutations(range(4)) for p in fibers(sq,kind,2))
        counts={'feasible':0,'impossible':0};digest=hashlib.sha256()
        for graph in range(1<<16):
            edges=[divmod(i,4) for i in range(16) if graph>>i&1]
            got=analyze(edges,kind,2)
            oracle=any((graph&p)==0 for p in patterns)
            assert got['feasible']==oracle
            if got['witness']:
                sq,t=square_from_witness(got['witness'],kind,2)
                assert not(graph&fibers(sq,kind,2)[t])
            counts['feasible' if oracle else 'impossible']+=1;digest.update(bytes([oracle]))
        reduced.append({'kind':kind,'all_graphs':65536,'all_squares':24,'coordinates_per_square':4,'unique_coordinate_fibers':len(patterns),'counts':counts,'feasibility_digest':digest.hexdigest()})
    rng=random.Random(20260912);full=[]
    for kind in ('RR','RC','CR','CC'):
        fixtures=[('empty',0),('complete',(1<<256)-1)]
        for i in range(24):
            sq=rng.sample(list(range(16)),16);t=rng.randrange(16);forbidden=fibers(sq,kind,4)[t]
            # Every graph in this family must preserve the deliberately absent coordinate.
            g=sum(1<<bit for bit in range(256) if not(forbidden>>bit&1) and rng.random()<(0.3,0.7,1.0)[i%3])
            fixtures.append(('planted_'+str(i),g))
        for i in range(16):
            fixtures.append(('random_'+str(i),sum(1<<bit for bit in range(256) if rng.random()<(0.25,0.5,0.75,0.95)[i%4])))
        for name,graph in fixtures:
            edges=[divmod(i,16) for i in range(256) if graph>>i&1]
            got=analyze(edges,kind,4,retain=True)
            # Replay every intersection with direct edge membership, independent of bitmasks.
            edge_set=set(edges)
            for row in got['records']:
                aa=[a for a in range(16) if row['A']>>a&1]
                missing={b for b in range(16) if all((a,b) not in edge_set for a in aa)}
                assert row['common_missing']==sum(1<<b for b in missing)
                assert row['inside']==len(missing&set(aa)) and row['outside']==len(missing-set(aa))
            if got['witness']:
                sq,t=square_from_witness(got['witness'],kind,4)
                assert not(graph&fibers(sq,kind,4)[t])
            if name=='empty' or name.startswith('planted_'):assert got['feasible']
            if name=='complete':assert not got['feasible']
            full.append({'kind':kind,'name':name,'graph_hex':format(graph,'064x'),'feasible':got['feasible'],'witness':got['witness'],'surviving_first_sets':got['surviving_first_sets'],'all_1820_direct_intersections_checked':True})
    return {'identity':'ASTRA','target_evaluated':False,'rev7_read':False,'source_hashes':{'model.py':sha(HERE/'model.py'),'controls.py':sha(Path(__file__))},'reduced_exhaustive':reduced,'full_fixtures':full,'scope':'Exact existence of an absent coordinate for ONE typed graph; independent surviving witnesses across types cannot be combined without coupled-square consistency.'}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();result=build()
    if a.regenerate:
        with a.regenerate.open('x') as f:json.dump(result,f,sort_keys=True,indent=2);f.write('\n')
        path=a.regenerate
    else:
        path=HERE/'controls.json';assert result==json.loads(path.read_text())
    print(json.dumps({'identity':'ASTRA','ok':True,'target_evaluated':False,'reduced_graphs':262144,'full_fixtures':len(result['full_fixtures']),'ledger_sha256':sha(path)},sort_keys=True))
if __name__=='__main__':main()

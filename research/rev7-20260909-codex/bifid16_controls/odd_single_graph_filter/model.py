#!/usr/bin/env python3
"""ASTRA exact single typed graph missing-coordinate feasibility, no target I/O."""
from itertools import combinations

def analyze(edges, kind, side=4, retain=False):
    assert side in (2,4) and kind in ('RR','RC','CR','CC')
    n=side*side; full=(1<<n)-1; present=[0]*n
    for a,b in edges:
        assert 0<=a<n and 0<=b<n
        present[a]|=1<<b
    missing=[full^m for m in present]
    witness=None; accepted=0; rows=[]
    for aa in combinations(range(n),side):
        A=sum(1<<a for a in aa); M=full
        for a in aa:M&=missing[a]
        inside=bin(M&A).count("1");outside=bin(M&(full^A)).count("1")
        if kind[0]!=kind[1]:
            survives=inside>=1 and outside>=side-1
            if survives:
                ins=[b for b in range(n) if (M&A)>>b&1]
                outs=[b for b in range(n) if (M&(full^A))>>b&1]
                B=(1<<ins[0])+sum(1<<b for b in outs[:side-1])
        else:
            survives=(M&A)==A or outside>=side
            if survives:
                B=A if (M&A)==A else sum(1<<b for b in [b for b in range(n) if (M&(full^A))>>b&1][:side])
        if survives:
            accepted+=1
            if witness is None:witness={'A':A,'B':B}
        if retain:rows.append({'A':A,'common_missing':M,'inside':inside,'outside':outside,'survives':survives})
    return {'kind':kind,'side':side,'feasible':witness is not None,'witness':witness,'surviving_first_sets':accepted,'checked_first_sets':len(tuple(combinations(range(n),side))),'records':rows}

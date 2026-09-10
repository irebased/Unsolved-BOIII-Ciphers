#!/usr/bin/env python3
import hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent; src=HERE/'geometry.json'; expected='1069eef993bfe27ca6fe8f7aa34395da744d35fd986979267da6a1996b39ac07'
assert hashlib.sha256(src.read_bytes()).hexdigest()==expected
d=json.loads(src.read_text()); out=dict(d); out['full_ledger_sha256']=expected; out['full_ledger_regeneration_command']='python3 research/rev7-20260909-codex/iv_independent/geometry.py'; out['omitted_from_summary']='per-window complete endpoint records (the full geometry.json remains the ledger)'; out['orientations']={}
for o,v in d['orientations'].items():
 out['orientations'][o]={}
 for bs,x in v.items():
  y=dict(x); y.pop('windows',None); out['orientations'][o][bs]=y
(HERE/'geometry_summary.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n'); print(hashlib.sha256((HERE/'geometry_summary.json').read_bytes()).hexdigest())

#!/usr/bin/env python3
import argparse,json
from pathlib import Path
import run_target as R
p=argparse.ArgumentParser();p.add_argument('--fable-reference',required=True);p.add_argument('--output',default=str(R.GATE));a=p.parse_args();o=Path(a.output)
assert 'ASTRA' in a.fable_reference and a.fable_reference.strip();assert not o.exists()
g={'identity':'ASTRA','authorized':True,'target_evaluated':False,'fable_reference':a.fable_reference,'scope':{'labels':16128,'pre':['identity','reverse','reverse_words'],'variant':['hex-exact'],'toolfmt':['none'],'boundary':'l1.decrypt output before xf/codec/layer2/oracle'},'artifact_hashes':R.required()}
o.write_text(json.dumps(g,sort_keys=True,separators=(',',':')));print(R.sha(o))

#!/usr/bin/env python3
"""ASTRA: input-pinned replay of frozen Rev5 control only (no main/DFS)."""
import hashlib, importlib.util, json
from pathlib import Path
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[3]
DATA=REPO/'lavender/src/data/ciphers/revelations.json'
CONTROLS=HERE/'controls.json'; SOURCE=HERE/'controls.py'
EXPECTED_DATA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
EXPECTED_CONTROLS='bc7ba1a64dbc2a951d9edc126a5ff5c97c181c470d3772b690b9dbdffe517739'
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(DATA)==EXPECTED_DATA
assert sha(SOURCE)==EXPECTED_CONTROLS
spec=importlib.util.spec_from_file_location('frozen_controls',SOURCE)
mod=importlib.util.module_from_spec(spec); spec.loader.exec_module(mod)
returned=mod.rev5_control() # deliberately not main(); no DFS
expected=json.loads(CONTROLS.read_text())['rev5_full_chain']
assert returned==expected
assert all(returned['complete_chain_reencryptions'].values())
out={'identity':'ASTRA','target_evaluated':False,'replay':'rev5_control() only; frozen source implementation, not an independent cipher implementation','input_source':str(DATA),'input_sha256':EXPECTED_DATA,'controls_source':str(SOURCE),'controls_sha256':EXPECTED_CONTROLS,'controls_json':str(CONTROLS),'controls_json_sha256':sha(CONTROLS),'returned_result':returned}
(HERE/'rev5_reproduction.json').write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
print(json.dumps(out,indent=2,sort_keys=True))

#!/usr/bin/env python3
"""Create a new immutable gate only after an external FABLE preregistration."""
from pathlib import Path
import argparse,hashlib,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
sys.path.insert(0,str(HERE));import run_target as driver
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fable-reference',required=True);ap.add_argument('--output',type=Path,required=True);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing gate output')
 assert a.fable_reference.strip() and sha(driver.MDX)==driver.MDX_SHA
 controls=json.loads((HERE/'controls.json').read_text());assert controls['identity']=='ASTRA' and controls['target_evaluated'] is False and controls['assertions']['all_passed']
 artifacts={rel:sha(ROOT/rel) for rel in driver.REQUIRED_ARTIFACTS}
 gate={'identity':'ASTRA','target_evaluated':False,'authorization':'FABLE preregistered; root GO required','fable_reference':a.fable_reference,
  'scope':driver.scope(),'driver_sha256':sha(HERE/'run_target.py'),'mdx_sha256':driver.MDX_SHA,'canonical_text_sha256':driver.TEXT_SHA,'artifact_hashes':artifacts}
 a.output.parent.mkdir(parents=True,exist_ok=True);a.output.write_text(json.dumps(gate,indent=2,sort_keys=True)+'\n')
 print(json.dumps({'identity':'ASTRA','gate':str(a.output),'sha256':sha(a.output),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

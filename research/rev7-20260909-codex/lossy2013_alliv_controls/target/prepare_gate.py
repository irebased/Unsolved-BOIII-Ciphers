#!/usr/bin/env python3
from pathlib import Path
import argparse,json,sys
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
sys.path.insert(0,str(HERE))
import run_target as driver

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fable-reference',required=True);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing gate')
 assert a.fable_reference.strip()
 assert driver.sha(driver.MDX)==driver.MDX_SHA and driver.sha(driver.DATA)==driver.DATA_SHA
 controls=json.loads((HERE/'controls.json').read_text())
 assert controls['identity']=='ASTRA' and controls['target_evaluated'] is False and all(controls['assertions'].values())
 assert controls['driver_sha256']==driver.sha(HERE/'run_target.py')
 assert controls['source_sha256']==driver.SOURCE_SHA and controls['parent_controls_sha256']==driver.CONTROLS_SHA
 artifacts={rel:driver.sha(ROOT/rel) for rel in driver.REQUIRED}
 out={'identity':'ASTRA','target_evaluated':False,'authorization':'external preregistration; separate root GO required','fable_reference':a.fable_reference,'scope':driver.scope(),'driver_sha256':driver.sha(HERE/'run_target.py'),'source_sha256':driver.SOURCE_SHA,'controls_sha256':driver.CONTROLS_SHA,'mdx_sha256':driver.MDX_SHA,'dataset_sha256':driver.DATA_SHA,'canonical_text_sha256':driver.TEXT_SHA,'artifact_hashes':artifacts}
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
 print(driver.sha(a.output))
if __name__=='__main__':main()

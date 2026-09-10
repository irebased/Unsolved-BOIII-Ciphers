#!/usr/bin/env python3
from pathlib import Path
import argparse,json,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[4];sys.path.insert(0,str(HERE));import run_target as d
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--fable-reference',required=True);ap.add_argument('--output',required=True,type=Path);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing gate')
 if d.RESULT.exists() or d.RESULT.with_suffix('.json.tmp').exists() or any(d.checkpoint_path(o).exists() or d.checkpoint_path(o).with_suffix('.json.tmp').exists() for o in d.ORIENTATIONS):raise SystemExit('refusing while target output exists')
 assert a.fable_reference.strip() and d.sha(d.MDX)==d.MDX_SHA and d.sha(d.DATA)==d.DATA_SHA and d.sha(d.BIN)==d.BIN_SHA and d.sha(d.BUILD)==d.BUILD_SHA
 ctl=json.loads((HERE/'controls.json').read_text());parent=json.loads((d.PACKAGE/'controls.json').read_text());assert ctl['identity']==parent['identity']=='ASTRA' and ctl['target_evaluated'] is False and parent['target_evaluated'] is False and all(ctl['assertions'].values()) and all(parent['assertions'].values()) and ctl['driver_sha256']==d.sha(HERE/'run_target.py') and ctl['native_binary_sha256']==d.BIN_SHA and ctl['native_build_sha256']==d.BUILD_SHA and ctl['parent_controls_source_sha256']==d.PARENT_CONTROLS_SOURCE_SHA and ctl['parent_controls_sha256']==d.PARENT_CONTROLS_SHA
 artifacts={rel:d.sha(ROOT/rel) for rel in d.REQUIRED};assert set(artifacts)==set(d.REQUIRED)
 out={'identity':'ASTRA','target_evaluated':False,'authorization':'external preregistration; separate root GO required','fable_reference':a.fable_reference,'scope':d.scope(),'driver_sha256':d.sha(HERE/'run_target.py'),'native_binary_sha256':d.BIN_SHA,'native_build_sha256':d.BUILD_SHA,'parent_controls_source_sha256':d.PARENT_CONTROLS_SOURCE_SHA,'parent_controls_sha256':d.PARENT_CONTROLS_SHA,'mdx_sha256':d.MDX_SHA,'dataset_sha256':d.DATA_SHA,'canonical_text_sha256':d.TEXT_SHA,'artifact_hashes':artifacts}
 a.output.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(d.sha(a.output))
if __name__=='__main__':main()

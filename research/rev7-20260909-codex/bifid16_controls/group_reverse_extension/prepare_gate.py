#!/usr/bin/env python3
"""Root-only gate builder. This source is inert unless --write and a preregistration reference are supplied."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'target_gate.json';TMP=HERE/'target_gate.json.tmp'
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def load_driver():
 p=HERE/'run_target.py';s=importlib.util.spec_from_file_location('gre_gate_driver',p);m=importlib.util.module_from_spec(s);s.loader.exec_module(m);return m
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write',action='store_true');ap.add_argument('--fable-reference');a=ap.parse_args();r=load_driver();r.verify_deps()
 preview={'identity':'ASTRA','target_evaluated':False,'authorized':True,'scope':r.scope(),'driver_sha256':sha(HERE/'run_target.py'),'controls_sha256':sha(HERE/'controls.json'),'controls_source_sha256':sha(HERE/'controls.py'),'readme_sha256':sha(HERE/'README.md'),'prepare_gate_sha256':sha(__file__),'dependency_hashes':r.DEPS,'mdx_sha256':r.MDX_SHA,'dataset_sha256':r.DATA_SHA,'canonical_sha256':r.TEXT_SHA,'fable_reference':a.fable_reference}
 if not a.write:
  print(json.dumps(preview|{'authorized':False,'gate_written':False},sort_keys=True,indent=2));return
 assert a.fable_reference and 'ASTRA' in a.fable_reference,'exact preregistration reference required';assert not OUT.exists() and not TMP.exists();TMP.write_text(json.dumps(preview,sort_keys=True,indent=2)+'\n');os.replace(TMP,OUT);print(json.dumps({'identity':'ASTRA','gate_sha256':sha(OUT),'gate_written':True},sort_keys=True))
if __name__=='__main__':main()

#!/usr/bin/env python3
"""Root-only helper to prepare a post-preregistration target gate; it never evaluates ciphertext."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
import run_target as driver
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def manifest():
 assert sha(driver.MDX)==driver.MDX_SHA
 return {'identity':'ASTRA','target_evaluated':False,'authorization':'FABLE preregistered; root GO required','fable_reference':None,'scope':driver.scope(),'driver_sha256':sha(HERE/'run_target.py'),'mdx_sha256':driver.MDX_SHA,'canonical_text_sha256':driver.TEXT_SHA,'artifact_hashes':{rel:sha(driver.ROOT/rel) for rel in driver.REQUIRED_ARTIFACTS}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--selftest',action='store_true');ap.add_argument('--output',type=Path);ap.add_argument('--fable-reference');a=ap.parse_args();m=manifest()
 if a.selftest:
  if a.output or a.fable_reference:ap.error('--selftest takes no output/reference')
  print(json.dumps({**m,'artifact_count':len(m['artifact_hashes'])},indent=2,sort_keys=True));return
 if a.output is None or not a.fable_reference:ap.error('gate creation requires --output NEW_PATH and --fable-reference after root preregistration')
 if a.output.exists():raise SystemExit('refusing existing output: '+str(a.output))
 m['fable_reference']=a.fable_reference;a.output.write_text(json.dumps(m,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':'ASTRA','target_evaluated':False,'output':str(a.output),'sha256':sha(a.output)},indent=2))
if __name__=='__main__':main()

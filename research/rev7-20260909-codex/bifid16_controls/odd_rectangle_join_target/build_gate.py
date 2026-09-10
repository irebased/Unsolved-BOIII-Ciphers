#!/usr/bin/env python3
"""Build a root-reviewed authorization gate at an absent path; never runs the target."""
import argparse,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
def load(name,path):
 s=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(s);sys.modules[name]=m;s.loader.exec_module(m);return m
rt=load('astra_join_gate_driver',HERE/'run_target.py')
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',type=Path,required=True);ap.add_argument('--authorization-reference',required=True);ap.add_argument('--review-evidence',action='append',required=True);a=ap.parse_args()
 if a.output.exists():raise SystemExit('refusing existing output')
 rt.check_pins();g={'identity':'ASTRA','authorized':True,'target_evaluated':False,'scope':rt.scope(),'driver_sha256':rt.sha(HERE/'run_target.py'),'source_pins':rt.source_pins(),'authorization_reference':a.authorization_reference,'review_evidence':a.review_evidence}
 a.output.write_text(json.dumps(g,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','output':str(a.output),'sha256':rt.sha(a.output),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

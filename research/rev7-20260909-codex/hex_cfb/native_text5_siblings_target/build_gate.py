#!/usr/bin/env python3
"""Build a reviewed gate without reading target ciphertext."""
from __future__ import annotations
import argparse,hashlib,json,subprocess,sys
from pathlib import Path
import preflight,run_target
HERE=Path(__file__).resolve().parent
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 p=argparse.ArgumentParser();p.add_argument("--write",type=Path);p.add_argument("--authorized",action="store_true");p.add_argument("--authorization-reference");p.add_argument("--review-evidence");a=p.parse_args()
 pre=preflight.validate();subprocess.run([sys.executable,"-B",str(HERE/"driver_controls.py")],check=True)
 if a.write is None:
  print(json.dumps({"identity":"ASTRA","target_evaluated":False,"status":"preflight-only","scope":run_target.scope(),"artifact_hashes":run_target.EXPECTED,"extension_hashes":run_target.extension_hashes()},indent=2,sort_keys=True));return
 if not a.authorized or not a.authorization_reference or not a.review_evidence:raise SystemExit("gate write requires authorized flag, authorization reference, and review evidence")
 if a.write.exists():raise SystemExit(f"refusing existing gate: {a.write}")
 obj={"identity":"ASTRA","target_evaluated":False,"authorized":True,"authorization_reference":a.authorization_reference,"review_evidence":a.review_evidence,"scope":run_target.scope(),"artifact_hashes":run_target.EXPECTED,"extension_hashes":run_target.extension_hashes(),"driver_sha256":sha(HERE/"run_target.py"),"canonical_text_sha256":preflight.TEXT_SHA256,"authorization":"No target execution before a separate explicit GO."}
 a.write.write_text(json.dumps(obj,sort_keys=True,indent=2)+"\n");print(json.dumps({"ok":True,"gate":str(a.write),"sha256":sha(a.write)}))
if __name__=="__main__":main()

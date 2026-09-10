#!/usr/bin/env python3
"""Verify the frozen ASTRA native binary transport; restore only if absent."""
from pathlib import Path
import argparse,base64,hashlib,json
HERE=Path(__file__).resolve().parent
WANT='24b323b9eac28b438bac3760baad4683704884e12288407719390daed2db923c'
def main():
 p=argparse.ArgumentParser();p.add_argument('--restore',action='store_true');a=p.parse_args()
 b=base64.b64decode((HERE/'native_r256.base64').read_text().strip(),validate=True)
 assert hashlib.sha256(b).hexdigest()==WANT
 target=HERE/'native_r256'
 if target.exists():assert target.read_bytes()==b
 elif a.restore:
  with target.open('xb') as f:f.write(b)
  target.chmod(0o755)
 print(json.dumps({'identity':'ASTRA','verified':True,'native_sha256':WANT,'native_present':target.exists(),'bytes':len(b)}))
if __name__=='__main__':main()

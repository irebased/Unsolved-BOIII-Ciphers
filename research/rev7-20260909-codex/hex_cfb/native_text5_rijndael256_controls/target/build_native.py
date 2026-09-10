#!/usr/bin/env python3
from pathlib import Path
import argparse,hashlib,json,subprocess
HERE=Path(__file__).resolve().parent;PACKAGE=HERE.parent;ROOT=HERE.parents[4];IDENTITY='ASTRA';SRC=ROOT/'research/rev7-20260909-codex/rijndael256_controls/source'
PINS={'native.cpp':'da036a3e55a1f771bc31bb4795be85e1acc2ed58b6f744085e6c01525b3abf2a','rijndael-256.c':'fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821','rijndael.h':'57142416d7b11f6788a10ded626ad426aca430ed5bff34d60b87868feb3fe0e2','libdefs.h':'556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e','mcrypt_modules.h':'2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180'}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--output',required=True,type=Path);ap.add_argument('--ledger',required=True,type=Path);a=ap.parse_args()
 if a.output.exists() or a.ledger.exists():raise SystemExit('refusing existing output or ledger')
 assert sha(PACKAGE/'native.cpp')==PINS['native.cpp']
 for n in ('rijndael-256.c','rijndael.h','libdefs.h','mcrypt_modules.h'):assert sha(SRC/n)==PINS[n]
 a.output.parent.mkdir(parents=True,exist_ok=True);obj=a.output.with_suffix('.o')
 if obj.exists():raise SystemExit('refusing existing object')
 cc=['clang','-std=c99','-O2','-I',str(SRC),'-c',str(SRC/'rijndael-256.c'),'-o',str(obj)];cxx=['clang++','-std=c++17','-O3',str(PACKAGE/'native.cpp'),str(obj),'-o',str(a.output)]
 try:subprocess.run(cc,check=True);subprocess.run(cxx,check=True)
 finally:
  if obj.exists():obj.unlink()
 out={'identity':IDENTITY,'source_pins':PINS,'binary_sha256':sha(a.output),'binary_size':a.output.stat().st_size,'commands':[[x.replace(str(ROOT),'<worktree>') for x in cc],[x.replace(str(ROOT),'<worktree>') for x in cxx]],'compiler':subprocess.check_output(['clang++','--version'],text=True).splitlines()[0],'build_source_sha256':sha(Path(__file__))}
 a.ledger.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'binary_sha256':out['binary_sha256'],'ledger_sha256':sha(a.ledger)},sort_keys=True))
if __name__=='__main__':main()

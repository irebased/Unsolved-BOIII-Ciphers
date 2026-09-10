#!/usr/bin/env python3
"""Build hash-pinned Rijndael-256 C sources into a caller-selected new path."""
from pathlib import Path
import argparse, hashlib, subprocess
HERE=Path(__file__).resolve().parent
SRC=HERE/'source'
PINS={
 'rijndael-256.c':'fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821',
 'rijndael.h':'57142416d7b11f6788a10ded626ad426aca430ed5bff34d60b87868feb3fe0e2',
 'libdefs.h':'556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e',
 'mcrypt_modules.h':'2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180',
}
def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def verify_sources()->None:
    for name,want in PINS.items():
        got=sha(SRC/name)
        if got!=want: raise RuntimeError(f'source hash mismatch {name}: {got} != {want}')
def build(output: Path) -> list[str]:
    verify_sources(); output=output.resolve()
    if output.exists(): raise FileExistsError(f"refusing to overwrite {output}")
    output.parent.mkdir(parents=True, exist_ok=True)
    cmd=['clang','-std=c99','-O2','-dynamiclib','-I',str(SRC),str(SRC/'rijndael-256.c'),'-o',str(output)]
    subprocess.run(cmd,check=True)
    return cmd
if __name__=='__main__':
    ap=argparse.ArgumentParser(); ap.add_argument('output',type=Path)
    args=ap.parse_args(); print(' '.join(build(args.output)))

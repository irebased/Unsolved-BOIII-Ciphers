#!/usr/bin/env python3
"""ASTRA reproducible transcription audit for PHP mcrypt key-size dispatch.
Reads only the pinned local source snapshots; it never executes PHP/libmcrypt.
"""
import hashlib, json
from pathlib import Path
ROOT=Path(__file__).parent
EXPECTED={
 "php-5.4.45":"56b2234165f25fe3abb1fc9322b19fed9d11ba7eb83eb05399ecef59e399aa9f",
 "php-5.6.25":"340fa4d3282823c7072c820704e0e544f0d863b12641a3b748d99cd9d3d7956d",
 "rijndael-128":"0a006fb52fb31b4ea912d7b79ba478e514c27bf65ff9aa778f4e3132e125c88f",
 "des":"b4cc7bb28a0286584ef6456d03acfd69847390f3bbf88c9a01b7923dd4f0d0a4",
 "blowfish":"c384305eb4f5d7134e60f6deaed92bba94757826da4b8d35de8326422c286736",
}
FILES={
 "php-5.4.45":ROOT/"php-5.4.45-mcrypt.c",
 "php-5.6.25":ROOT/"php-5.6.25-mcrypt.c",
 "rijndael-128":ROOT/"rijndael-128.c",
 "des":ROOT/"des.c",
 "blowfish":ROOT.parent.parent/"hex_cfb/native_compat/source/blowfish.c",
}
def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def excerpt(path, lo, hi):
 lines=path.read_text(errors='replace').splitlines()
 return [f"{i}: {lines[i-1]}" for i in range(lo, min(hi,len(lines))+1)]
# This is a source transcription of the two PHP branches, not a runtime test.
def php54(length, supported, maximum):
 if not supported: return {"accepted":True,"effective_length":length,"action":"raw supplied length (count=0)"}
 if len(supported)==1: return {"accepted":True,"effective_length":supported[0],"action":"zero-pad/truncate to singleton supported size"}
 use=maximum
 for n in supported:
  if n >= length and n < use: use=n
 return {"accepted":True,"effective_length":use,"action":"zero-pad/truncate to smallest supported size >= supplied"}
def php56(length, supported, maximum):
 ok=(0 < length <= maximum) and (not supported or length in supported)
 return {"accepted":ok,"effective_length":length if ok else None,"action":"pass exact supplied length" if ok else "reject unsupported length"}
checks={"AES/Rijndael-128 raw7":{"max":32,"supported":[16,24,32]},"DES raw7":{"max":8,"supported":[8]},"Blowfish raw7":{"max":56,"supported":[]}}
actual={k:sha(v) for k,v in FILES.items()}
assert actual == EXPECTED, {k:(EXPECTED.get(k),actual.get(k)) for k in EXPECTED if EXPECTED.get(k)!=actual.get(k)}
out={"identity":"ASTRA","source_sha256":actual,"representative_decisions":checks,"php54_transcription":{},"php56_transcription":{},"excerpts":{}}
for name,c in checks.items():
 out["php54_transcription"][name]=php54(7,c["supported"],c["max"])
 out["php56_transcription"][name]=php56(7,c["supported"],c["max"])
out["excerpts"]={
 "php-5.4.45_do_crypt":excerpt(FILES["php-5.4.45"],1172,1219),
 "php-5.6.25_validation":excerpt(FILES["php-5.6.25"],1193,1241),
 "php-5.6.25_do_crypt":excerpt(FILES["php-5.6.25"],1273,1316),
 "rijndael_metadata":excerpt(FILES["rijndael-128"],418,428),
 "des_metadata":excerpt(FILES["des"],586,597),
 "blowfish_metadata":excerpt(FILES["blowfish"],493,501),
}
print(json.dumps(out,indent=2,sort_keys=True))

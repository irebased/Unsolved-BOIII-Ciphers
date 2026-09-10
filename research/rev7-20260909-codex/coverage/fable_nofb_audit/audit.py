#!/usr/bin/env python3
"""Source/control audit only; never loads Rev7 target inputs or results."""
from __future__ import annotations
import argparse,base64,hashlib,json,shutil,subprocess,tempfile
from collections import Counter
from pathlib import Path
from Crypto.Cipher import AES,Blowfish,DES
ROOT=Path(__file__).resolve().parent; SOURCE=ROOT/"source"; LEDGER=ROOT/"audit.json"
PINS={
"source/rev7/nofb/lib.js":"f8ed74f03f5bd3c6d8a49fcc790cd878d81faa6feceac20007405a5ecf0a8948",
"source/rev7/nofb/verify.js":"fe06d3f3290e51d84c66453005a037ddfe8614794139fe2da6ddbfd0bbaa9a8e",
"source/rev7/nofb/verify_py.py":"6f5609cf1cf3c32ed7a0355c73805284c940e479f33423324d0a62a6059a3ef5",
"source/rev7/nofb/vectors.json":"b7904a820fb1bcf1aeea01f2ad46de7559ebd15ee37584a1fff88e3110c2de9e",
"source/rev7/nofb/crosscheck.json":"beaf36b7593df1e8df751b004578c5ce7b61a6a78a1897a576038a0fcb7d3a79",
"source/rev7/nofb/divergence.json":"3f72080e07cc509e1a5a18deb3cd44e6e61171d2e44b48c9af1eed3ca10a92a8",
"source/rev7/ofb8/lib.js":"568eba04cc2bf3595e2929deae18fc585995bbf209bdb1f4105ccc554f64afd1",
"source/old-ciphers/js/mcrypt.js":"8998b6dd50ebc24aede3df84228826951f2143fde393e15f95d1455e074d5061",
"source/old-ciphers/js/mcrypt.wasm.base64":"e86b6b95e2fcdf4d813d84d438b525abfe380c7370ee70a6d0a177044a826f46"}
WASM="60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7"
SPECS={"des":(DES,8,8),"rijndael-128":(AES,16,16),"blowfish":(Blowfish,16,8)}
def sha(b): return hashlib.sha256(b).hexdigest()
def canon(o): return (json.dumps(o,sort_keys=True,indent=2)+"\n").encode()
def pins():
 out={k:sha((ROOT/k).read_bytes()) for k in PINS}
 assert out==PINS
 raw=base64.b64decode((SOURCE/"old-ciphers/js/mcrypt.wasm.base64").read_text().strip(),validate=True); assert sha(raw)==WASM
 return out
def manual(mod,key,iv,data):
 e=mod.new(key,mod.MODE_ECB); reg=iv; out=bytearray()
 for off in range(0,len(data),len(iv)):
  reg=e.encrypt(reg); out.extend(a^b for a,b in zip(data[off:off+len(iv)],reg))
 return bytes(out)
def saved():
 rows=json.loads((SOURCE/"rev7/nofb/vectors.json").read_text()); assert len(rows)==180
 counts=Counter(); lens=[]; h=hashlib.sha256()
 for i,r in enumerate(rows):
  mod,kl,bs=SPECS[r["cipher"]]; key=bytes.fromhex(r["key"]); iv=bytes.fromhex(r["iv"]); data=bytes.fromhex(r["data"]); expected=bytes.fromhex(r["out"])
  assert len(key)==kl and len(iv)==bs and 1<=len(data)<=200
  assert expected==mod.new(key,mod.MODE_OFB,iv=iv).decrypt(data)==manual(mod,key,iv,data)
  counts[r["cipher"]]+=1; lens.append(len(data)); h.update(i.to_bytes(4,"big")+expected)
 assert counts==Counter({"des":60,"rijndael-128":60,"blowfish":60})
 c=json.loads((SOURCE/"rev7/nofb/crosscheck.json").read_text()); assert c["total"]==180 and c["mismatches"]==0 and c["comparisons"]==dict(counts)
 d=json.loads((SOURCE/"rev7/nofb/divergence.json").read_text()); assert d["summary"]=={"trials":60,"ofb8_identical_count":0,"mode4_equals_nofb":60,"mode4_equals_ofb8":0}
 assert all(x["firstDiffVsNofb"]==-1 and x["firstDiffVsOfb8"]==1 for x in d["vs_mode4"])
 return {"vector_count":180,"per_cipher":dict(counts),"data_length_min":min(lens),"data_length_max":max(lens),"output_ordered_sha256":h.hexdigest(),"independent_formulations":["PyCryptodome MODE_OFB","PyCryptodome ECB recurrence register=E_key(register), whole-block XOR"],"archived_mode4_evidence":d}
def mode4():
 with tempfile.TemporaryDirectory(prefix="astra-nofb-") as td:
  t=Path(td); shutil.copytree(SOURCE,t/"source"); raw=base64.b64decode((t/"source/old-ciphers/js/mcrypt.wasm.base64").read_text().strip(),validate=True); assert sha(raw)==WASM; (t/"source/old-ciphers/js/mcrypt.wasm").write_bytes(raw)
  p=subprocess.run(["node",str(ROOT/"mode4_check.js"),str(t/"source")],check=True,capture_output=True,text=True,timeout=60); obj=json.loads(p.stdout)
 rows=obj["rows"]; assert len(rows)==6 and Counter(r["cipher"] for r in rows)==Counter({k:2 for k in SPECS})
 for r in rows:
  mod,kl,bs=SPECS[r["cipher"]]; key=bytes.fromhex(r["key_hex"]); iv=bytes.fromhex(r["iv_hex"]); data=bytes.fromhex(r["data_hex"]); exp=bytes.fromhex(r["nofb_hex"])
  assert len(key)==kl and len(iv)==bs and exp==manual(mod,key,iv,data)==mod.new(key,mod.MODE_OFB,iv=iv).decrypt(data)
  assert r["mode4_hex"]==r["nofb_hex"] and r["mode4_equals_nofb"] and not r["mode4_equals_ofb8"] and r["first_diff_nofb_ofb8"]==1
 return {"fixture_count":6,"per_cipher":dict(Counter(r["cipher"] for r in rows)),"all_mode4_equal_fullblock":True,"all_mode4_differ_ofb8":True,"rows":rows}
def build(run):
 return {"identity":"ASTRA","target_evaluated":False,"scope":"source and controls only; no Rev7 target input or target result loaded","source_sha256":pins(),"decoded_wasm_sha256":WASM,"saved_vector_replay":saved(),"deterministic_mode4_replay":mode4() if run else None,"conclusion":{"recurrence":"register=E_key(register); XOR complete encrypted blocks; truncate only final output block","supported_ciphers":["des","rijndael-128","blowfish"],"key_lengths_bytes":{"des":8,"rijndael-128":16,"blowfish":16},"mode4_statement":"For the six deterministic fixtures on these three ciphers, wrapper mode 4 equaled full-block OFB and differed from OFB8.","generalization_limit":"No inference is made for the other wrapper ciphers."}}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("--regenerate",type=Path); ap.add_argument("--replay-mode4",action="store_true"); a=ap.parse_args()
 if a.regenerate:
  if a.regenerate.exists(): raise SystemExit("refusing existing output")
  a.regenerate.write_bytes(canon(build(True))); print(json.dumps({"ok":True,"sha256":sha(a.regenerate.read_bytes())})); return
 exp=json.loads(LEDGER.read_text()); got=build(a.replay_mode4)
 if not a.replay_mode4: got["deterministic_mode4_replay"]=exp["deterministic_mode4_replay"]
 assert got==exp
 print(json.dumps({"ok":True,"identity":"ASTRA","ledger_sha256":sha(LEDGER.read_bytes()),"saved_vectors":180,"mode4_fixtures":6,"mode4_replayed_now":a.replay_mode4}))
if __name__=="__main__": main()

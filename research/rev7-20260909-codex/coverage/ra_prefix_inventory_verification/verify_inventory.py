#!/usr/bin/env python3
"""Independent stdlib integrity/accounting verifier for the RA prefix inventory."""
from __future__ import annotations
import argparse, collections, gzip, hashlib, json, sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
PARENT=ROOT/"research/rev7-20260909-codex/coverage/ra_prefix_inventory"
TABLE_PATH=ROOT/"research/rev7-20260909-codex/coverage/occupancy_screen_controls/threshold_table.json"
CONTROLS=HERE/"controls.json"
SOURCE_PINS={
 "ra_prefix_inventory/source/ra/crates/ra-cli/src/prefix_inventory.rs":"a5670a8caf27d415e1c451ad7bc231c02674829da7cfbb0009bae8c30abfff1c",
 "ra_prefix_inventory/score_inventory.js":"ba580bdfee52cc401618759894812bfa87e6d703eb71c308d2f7bca70ff11a86",
 "ra_prefix_inventory/provenance.json":"80f5a7286af043b7eff683cdd0c538af777d8d5dbcfc21fcfaffd7c1f1478378",
 "occupancy_screen_controls/threshold_table.json":"2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447",
}
AXES={
 "pre":["identity","reverse","reverse_words"],
 "primitives":["DES","RC2","RC4","Blowfish","Blowfish-compat","Twofish","Serpent","Rijndael-256","AES","XTEA","Loki97","Saferplus","3DES","CAST-128","IDEA","Salsa20"],
 "modes":["cbc","cfb","ecb","ncfb","nofb","ofb","stream"],
 "keys":["ZOMBIE","ZOMBIES","Zombie","Zombies","zombie","zombies"],
 "kds":["natural","null-pad-max","null-pad-next-supported","repeat-pad-max"],
 "ivs":["ascii0","null"],
}
ALLOWED_STATUSES={"ready","ready_empty","decode_failed","layer_inapplicable"}

def sha_bytes(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def sha_file(p:Path)->str:return sha_bytes(p.read_bytes())
def stable(x)->str:return json.dumps(x,sort_keys=True,separators=(",",":"))+"\n"
def check_sources():
 paths={
  "ra_prefix_inventory/source/ra/crates/ra-cli/src/prefix_inventory.rs":PARENT/"source/ra/crates/ra-cli/src/prefix_inventory.rs",
  "ra_prefix_inventory/score_inventory.js":PARENT/"score_inventory.js",
  "ra_prefix_inventory/provenance.json":PARENT/"provenance.json",
  "occupancy_screen_controls/threshold_table.json":TABLE_PATH,
 }
 got={k:sha_file(v) for k,v in paths.items()}
 assert got==SOURCE_PINS,(got,SOURCE_PINS)
 return got

def load_table():
 d=json.loads(TABLE_PATH.read_text())
 assert d["identity"]=="ASTRA" and d["model"]=={
  "labels":256,"n_max":1092,"n_min":128,
  "recurrence":"C[n,k]=k*C[n-1,k]+(256-k+1)*C[n-1,k-1]",
  "threshold":"largest d with sum(C[n,0..d])*10^15 <= 256^n",
  "threshold_probability":"1/10^15"}
 rows=d["rows"];assert len(rows)==965
 out={}
 for r in rows:
  n,dv=r["n"],r["d"];assert n not in out and 128<=n<=1092 and 0<=dv<=min(n,256);out[n]=dv
 assert set(out)==set(range(128,1093))
 return out

def score(buf:bytes,table):
 n=len(buf);D=len(set(buf))
 if n<128:return {"n":n,"D":D,"status":"short","screen_hit":None}
 if n>1092:return {"n":n,"D":D,"status":"out-of-range","screen_hit":None}
 d=table[n];hit=D<=d
 return {"n":n,"D":D,"threshold_d":d,"status":"flagged" if hit else "unflagged","screen_hit":hit}

def expected_rows(axes):
 out=[];unit=len(axes["primitives"])*len(axes["modes"])*len(axes["keys"])*len(axes["kds"])*len(axes["ivs"])
 for pre in axes["pre"]:
  ix=0
  for prim in axes["primitives"]:
   for mode in axes["modes"]:
    for key in axes["keys"]:
     for kd in axes["kds"]:
      for iv in axes["ivs"]:
       rid=f"pre={pre}|prim={prim}|mode={mode}|key={key}|kd={kd}|iv={iv}"
       out.append((rid,pre,ix,prim,mode,key,kd,iv));ix+=1
  assert ix==unit
 return out

def group_rows(rows):
 grouped={}
 for r in rows:
  if r["status"] in ("ready","ready_empty"):
   b=bytes.fromhex(r["bytes_hex"])
   grouped.setdefault(b,[]).append(r["id"])
 return [{"length":len(b),"sha256":sha_bytes(b),"ids":ids} for b,ids in sorted(grouped.items())]

def validate(doc,axes,table,require_target):
 assert doc["identity"]=="ASTRA"
 assert doc["target_evaluated"] is require_target
 assert doc["boundary"]=="l1.decrypt output before xf/codec/layer2/oracle"
 expected_scope={"labels":len(expected_rows(axes)),"variant":["hex-exact"],"pre":axes["pre"],"primitives":axes["primitives"],"modes":axes["modes"],"keys":axes["keys"],"kds":axes["kds"],"ivs":axes["ivs"],"toolfmt":["none"]}
 assert doc["scope"]==expected_scope
 exp=expected_rows(axes);rows=doc["rows"];assert len(rows)==len(exp)
 ids=set();status=collections.Counter();lengths=collections.Counter();flags=[];minD=None;minrows=[];minMargin=None;marginrows=[]
 for row,e in zip(rows,exp):
  rid,pre,ix,prim,mode,key,kd,iv=e
  assert row["id"]==rid and row["id"] not in ids;ids.add(rid)
  assert (row["pre"],row["layer_index"],row["primitive"],row["mode"],row["key"],row["kd"],row["iv"])==(pre,ix,prim,mode,key,kd,iv)
  assert row["key_hex"]==key.encode("ascii").hex()
  st=row["status"];assert st in ALLOWED_STATUSES;status[st]+=1
  if st in ("ready","ready_empty"):
   required={"length","sha256","distinct_bytes","histogram","bytes_hex","occupancy"}
   assert required<=row.keys()
   hx=row["bytes_hex"];assert isinstance(hx,str) and len(hx)%2==0 and hx==hx.lower()
   b=bytes.fromhex(hx);assert len(b)==row["length"] and sha_bytes(b)==row["sha256"]
   h=[0]*256
   for x in b:h[x]+=1
   assert h==row["histogram"] and len(h)==256 and sum(h)==len(b)
   D=sum(x>0 for x in h);assert D==row["distinct_bytes"]
   got=score(b,table);assert row["occupancy"]==got
   assert (st=="ready_empty")== (len(b)==0)
   lengths[len(b)]+=1
   if got["screen_hit"] is True:flags.append({"id":rid,"n":len(b),"D":D,"threshold_d":got["threshold_d"]})
   if minD is None or D<minD:minD,minrows=D,[{"id":rid,"n":len(b),"D":D}]
   elif D==minD:minrows.append({"id":rid,"n":len(b),"D":D})
   if got["screen_hit"] is not None:
    margin=D-got["threshold_d"]
    rr={"id":rid,"n":len(b),"D":D,"threshold_d":got["threshold_d"],"margin":margin}
    if minMargin is None or margin<minMargin:minMargin,marginrows=margin,[rr]
    elif margin==minMargin:marginrows.append(rr)
  else:
   for k in ("length","sha256","distinct_bytes","histogram","bytes_hex"):assert k not in row
   assert row.get("occupancy") is None
 assert len(ids)==len(exp)
 groups=group_rows(rows);assert doc["exact_output_groups"]==groups
 grouped_ids=[x for g in groups for x in g["ids"]]
 ready_ids=[r["id"] for r in rows if r["status"] in ("ready","ready_empty")]
 assert len(grouped_ids)==len(ready_ids) and set(grouped_ids)==set(ready_ids)
 occ=doc["occupancy"]
 assert occ=={"source_sha256":"6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27","table_sha256":SOURCE_PINS["occupancy_screen_controls/threshold_table.json"],"window":"full output only","supported_n":[128,1092],"ready_rows_scored":len(ready_ids),"unsupported_ready_rows":sum(r["occupancy"]["screen_hit"] is None for r in rows if r["status"] in ("ready","ready_empty"))}
 return {"rows":len(rows),"status_counts":dict(sorted(status.items())),"ready_length_counts":{str(k):v for k,v in sorted(lengths.items())},"unique_exact_outputs":len(groups),"flagged_count":len(flags),"flags":flags,"minimum_distinct":{"D":minD,"rows":minrows},"minimum_threshold_margin":{"margin":minMargin,"rows":marginrows}}

def mini_doc(table):
 axes={"pre":["identity","reverse"],"primitives":["P"],"modes":["m"],"keys":["K"],"kds":["d"],"ivs":["a","b"]}
 specs=[("ready",bytes(i%69 for i in range(128))),("ready",bytes(i%69 for i in range(128))),("ready",bytes(i%70 for i in range(128))),("ready_empty",b"")]
 rows=[]
 for e,(st,b) in zip(expected_rows(axes),specs):
  rid,pre,ix,prim,mode,key,kd,iv=e
  r={"id":rid,"pre":pre,"layer_index":ix,"primitive":prim,"mode":mode,"key":key,"key_hex":"4b","kd":kd,"iv":iv,"status":st}
  h=[0]*256
  for x in b:h[x]+=1
  r.update(length=len(b),sha256=sha_bytes(b),distinct_bytes=len(set(b)),histogram=h,bytes_hex=b.hex(),occupancy=score(b,table));rows.append(r)
 doc={"identity":"ASTRA","target_evaluated":False,"boundary":"l1.decrypt output before xf/codec/layer2/oracle","scope":{"labels":4,"variant":["hex-exact"],"pre":axes["pre"],"primitives":axes["primitives"],"modes":axes["modes"],"keys":axes["keys"],"kds":axes["kds"],"ivs":axes["ivs"],"toolfmt":["none"]},"rows":rows,"exact_output_groups":group_rows(rows),"occupancy":{"source_sha256":"6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27","table_sha256":SOURCE_PINS["occupancy_screen_controls/threshold_table.json"],"window":"full output only","supported_n":[128,1092],"ready_rows_scored":4,"unsupported_ready_rows":1}}
 return doc,axes

def controls_payload():
 check_sources();table=load_table();doc,axes=mini_doc(table);summary=validate(doc,axes,table,False)
 rejected=[]
 mutations=[
  ("bytes_without_hash",lambda d:d["rows"][0].__setitem__("bytes_hex","ff"+d["rows"][0]["bytes_hex"][2:])),
  ("histogram",lambda d:d["rows"][0]["histogram"].__setitem__(0,d["rows"][0]["histogram"][0]+1)),
  ("alias_membership",lambda d:d["exact_output_groups"][0]["ids"].pop()),
  ("duplicate_id",lambda d:d["rows"][1].__setitem__("id",d["rows"][0]["id"])),
  ("occupancy",lambda d:d["rows"][2]["occupancy"].__setitem__("D",69)),
 ]
 for name,mut in mutations:
  bad=json.loads(json.dumps(doc));mut(bad)
  try:validate(bad,axes,table,False)
  except (AssertionError,ValueError,KeyError):rejected.append(name)
  else:raise AssertionError("corruption accepted "+name)
 assert len(rejected)==len(mutations)
 return {"identity":"ASTRA","status":"synthetic controls complete","target_evaluated":False,"source_pins":check_sources(),"verifier_sha256":sha_file(Path(__file__)),"positive_summary":summary,"corruptions_rejected":rejected}

def read_doc(p:Path):
 raw=p.read_bytes()
 if p.suffix==".gz":
  assert len(raw)>=10 and int.from_bytes(raw[4:8],"little")==0,"gzip mtime must be zero"
  raw=gzip.decompress(raw)
 return json.loads(raw),sha_bytes(raw),sha_file(p),len(raw),p.stat().st_size

def main():
 ap=argparse.ArgumentParser();ap.add_argument("result",nargs="?");ap.add_argument("--write-controls");a=ap.parse_args()
 payload=controls_payload()
 if a.write_controls:
  out=Path(a.write_controls);assert not out.exists(),"refuse existing controls output";out.write_text(json.dumps(payload,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":"ASTRA","status":"controls written","path":str(out),"sha256":sha_file(out)}));return
 assert CONTROLS.exists(),"controls.json absent";assert json.loads(CONTROLS.read_text())==payload,"controls ledger mismatch"
 rp=Path(a.result) if a.result else next((p for p in (PARENT/"target_results.json",PARENT/"target_results.json.gz") if p.exists()),None)
 if rp is None:print(json.dumps({"identity":"ASTRA","status":"PASS awaiting target result","target_evaluated":False,"controls_sha256":sha_file(CONTROLS)}));return
 doc,rawsha,filesha,rawbytes,filebytes=read_doc(rp);summary=validate(doc,AXES,load_table(),True)
 print(json.dumps({"identity":"ASTRA","status":"PASS","verification_only":True,"new_target_decryption":False,"result_path":str(rp),"raw_json_sha256":rawsha,"container_sha256":filesha,"raw_json_bytes":rawbytes,"container_bytes":filebytes,"summary":summary},sort_keys=True))

if __name__=="__main__":
 try:main()
 except Exception as e:
  print(f"FAIL: {type(e).__name__}: {e}",file=sys.stderr);raise

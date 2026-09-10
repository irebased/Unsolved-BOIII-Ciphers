#!/usr/bin/env python3
"""Verify the manual de_6_ref.webp board transcription and extract saved a=79,b=64 rows."""
from __future__ import annotations
import argparse,base64,hashlib,importlib.util,io,json,sys,zlib
from pathlib import Path

HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
IMAGE=ROOT/"lavender/src/assets/bo3/de/de_6_ref.webp"
CONTROLS=HERE.parent/"cryptool100/controls.py"
TARGET=HERE.parent/"cryptool100/target/target_results.ndjson"
PACK=HERE.parent/"cryptool100/target/results.pack.json"
PACKER=HERE.parent/"cryptool100/target/pack_results.py"
BOARD=HERE/"board.json"
ROWS=HERE/"target_rows_a79_b64.json"
IMAGE_SHA="93fc3bc1107cdae631993476f014ea0369610e95ff091837b3221ab451a613bd"
CONTROLS_SHA="1d4bfae906bc01815866298aa9740ab283393dffa5275aed0b3dd2ba1648b567"
TARGET_SHA="426a5be079cf553ba657e3bb3f9d4e8153ee15422efc0e8793e1840249dcac39"
TARGET_BYTES=67783676
PACK_SHA="625517b3832a7a14c42d90ff9cb1c7fca42d7abe571561727ab5c017bb89f3d8"
PACKER_SHA="8ae2d148942e75d45c15c75109ce95a47c712d067bd79592ba5ac0de7cd4bbd5"
TRANSCRIPTION=(
 ("A",("56","35","14","93","72","51")),("B",("30","09")),("C",("88","67","46")),
 ("D",("25","04","83","62","41")),("E",("20","99","78","57","36","15","94","73","52","31","10","89","68","47","26","05")),
 ("F",("84","63")),("G",("42","21","00")),("H",("79","58","37","16")),
 ("I",("95","74","53","32","11","90","69")),("J",("48",)),("K",("27",)),("L",("06","85","64")),
 ("M",("43","22","01","80")),("N",("59","38","17","96","75","54","33","12","91")),
 ("O",("70","49","28")),("P",("07",)),("Q",("86",)),("R",("65","44","23","02","81","60","39")),
 ("S",("18","97","76","55","34","13","92")),("T",("71","50","29","08","87","66")),
 ("U",("45","24","03","82")),("V",("61",)),("W",("40",)),("X",("19",)),("Y",("98",)),("Z",("77",)),
)

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module
def canonical(value):return json.dumps(value,sort_keys=True,separators=(",",":")).encode()

def expected_board():
 assert sha(IMAGE)==IMAGE_SHA and sha(CONTROLS)==CONTROLS_SHA
 flat=[code for _letter,codes in TRANSCRIPTION for code in codes]
 assert len(TRANSCRIPTION)==26 and len(flat)==100 and set(flat)=={f"{i:02d}" for i in range(100)}
 assert TRANSCRIPTION[0][1][0]=="56"
 # 79*64 mod 100 = 56 and successive natural slots advance by 79.
 assert (79*64)%100==56
 assert all(int(flat[i+1])==(int(flat[i])+79)%100 for i in range(99))
 module=load("astra_de6_cryptool_controls",CONTROLS)
 generated=tuple((letter,tuple(codes)) for letter,codes in module.board(79,64))
 assert generated==TRANSCRIPTION
 return flat

def build_board():
 flat=expected_board()
 return {
  "identity":"ASTRA","target_evaluated":False,
  "source_asset":{"path":"lavender/src/assets/bo3/de/de_6_ref.webp","sha256":IMAGE_SHA,"visual_inspection":"manual row-by-row transcription from the rendered original-resolution board"},
  "transcription":[{"letter":letter,"codes":list(codes),"count":len(codes)} for letter,codes in TRANSCRIPTION],
  "flat_natural_slot_codes":flat,
  "parameters":{"a":79,"b":64,"derivation":"first code 56 = 79*64 mod 100; each successive natural slot adds 79 mod 100"},
  "comparison":{"controls_source_sha256":CONTROLS_SHA,"generated_expression":"cryptool100.controls.board(79,64)","all_100_codes_exact":True,"mismatches":[],"all_codes_00_through_99_exactly_once":True},
 }

def target_bytes(force_pack=False):
 assert sha(PACK)==PACK_SHA and sha(PACKER)==PACKER_SHA
 if TARGET.exists() and not force_pack:
  raw=TARGET.read_bytes();assert len(raw)==TARGET_BYTES and hashlib.sha256(raw).hexdigest()==TARGET_SHA;return raw,"raw"
 env=json.loads(PACK.read_text());assert env["identity"]=="ASTRA" and env["target_evaluated"] is True and env["codec"]=="zlib-9+base85"
 assert env["raw_name"]=="target_results.ndjson" and env["raw_length"]==TARGET_BYTES and env["raw_sha256"]==TARGET_SHA
 encoded=env["payload"].encode("ascii");assert len(encoded)<=TARGET_BYTES*2
 compressed=base64.b85decode(encoded);assert len(compressed)==env["compressed_length"] and hashlib.sha256(compressed).hexdigest()==env["compressed_sha256"]
 decoder=zlib.decompressobj();raw=decoder.decompress(compressed,TARGET_BYTES+1);assert len(raw)<=TARGET_BYTES
 raw+=decoder.flush(TARGET_BYTES+1-len(raw));assert decoder.eof and not decoder.unused_data and not decoder.unconsumed_tail
 assert len(raw)==TARGET_BYTES and hashlib.sha256(raw).hexdigest()==TARGET_SHA;return raw,"packed_in_memory"

def path_id(row):return "h="+row["hex_orientation"]+"|d="+row["decimal_orientation"]
def extract_rows(raw=None):
 expected_board();groups={};selected={}
 if raw is None:raw,_route=target_bytes()
 with io.TextIOWrapper(io.BytesIO(raw),encoding="utf-8") as handle:
  header=json.loads(next(handle));assert header["record"]=="header" and header["scope"]["rows"]==64000
  for line in handle:
   row=json.loads(line);assert row["record"]=="candidate";pid=path_id(row);groups.setdefault(pid,[]).append(row)
   if row["a"]==79 and row["b"]==64:
    assert pid not in selected;selected[pid]=row
 assert len(groups)==16 and all(len(rows)==4000 for rows in groups.values()) and len(selected)==16
 output=[]
 for pid in sorted(groups):
  ordered=sorted(groups[pid],key=lambda row:(-row["score_per_tetragram"],row["a"],row["b"]))
  row=selected[pid];rank=next(i for i,item in enumerate(ordered,1) if item["id"]==row["id"])
  tied=sum(item["score_per_tetragram"]==row["score_per_tetragram"] for item in ordered)
  output.append({"path_id":pid,"rank_within_4000":rank,"score_tie_count":tied,"plaintext_prefix":row["plaintext"][:120],"saved_row":row})
 assert len({x["path_id"] for x in output})==16
 return {
  "identity":"ASTRA","target_rerun":False,"source_target_ndjson_sha256":TARGET_SHA,
  "reference_parameters":{"a":79,"b":64},"ranking_rule":"ascending tuple (-score_per_tetragram,a,b), matching frozen target source",
  "paths":16,"rows_per_path":4000,"full_saved_rows_retained":True,"rows":output,
 }

def write_new(path,value):
 if path.exists():raise SystemExit("refusing existing output "+str(path))
 path.parent.mkdir(parents=True,exist_ok=True);path.write_bytes(canonical(value)+b"\n")

def regenerate(board_path,rows_path):
 write_new(board_path,build_board());write_new(rows_path,extract_rows())
 print(json.dumps({"identity":"ASTRA","board":{"path":str(board_path),"sha256":sha(board_path),"bytes":board_path.stat().st_size},"saved_rows":{"path":str(rows_path),"sha256":sha(rows_path),"bytes":rows_path.stat().st_size},"target_rerun":False},indent=2))

def verify():
 board=build_board();packed,packed_route=target_bytes(force_pack=True);rows=extract_rows(packed);routes=[packed_route]
 if TARGET.exists():
  raw,raw_route=target_bytes();assert extract_rows(raw)==rows;routes.insert(0,raw_route)
 assert json.loads(BOARD.read_text())==board and json.loads(ROWS.read_text())==rows
 print(json.dumps({"identity":"ASTRA","verified":True,"image_sha256":IMAGE_SHA,"board_sha256":sha(BOARD),"target_rows_sha256":sha(ROWS),"all_100_codes_exact":True,"saved_paths":16,"target_routes_verified":routes,"target_rerun":False},indent=2))

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",action="store_true");parser.add_argument("--board-output",type=Path,default=BOARD);parser.add_argument("--rows-output",type=Path,default=ROWS);args=parser.parse_args()
 if args.regenerate:regenerate(args.board_output,args.rows_output)
 else:verify()
if __name__=="__main__":main()

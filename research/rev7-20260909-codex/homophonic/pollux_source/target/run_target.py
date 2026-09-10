#!/usr/bin/env python3
"""Inert gated driver for the two historical numeric Pollux boards."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,os,sys
from pathlib import Path

HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
ROOT=HERE.parents[4]
CONTROLS_PATH=PACKAGE/"controls.py"
CONTROL_LEDGER=PACKAGE/"controls.json"
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
DATASET=ROOT/"lavender/src/data/ciphers/revelations.json"
GATE=HERE/"target_gate.json"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
DATASET_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
BOARDS=("numeric_plain","numeric_mul7")
DECIMAL_DIRECTIONS=("identity","digit_reverse")
HEX_ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
ARTIFACTS={
 "pollux_source/controls.py":CONTROLS_PATH,
 "pollux_source/controls.json":CONTROL_LEDGER,
 "pollux_source/REPORT.md":PACKAGE/"REPORT.md",
 "pollux_source/source/functions.pollux.php":PACKAGE/"source/functions.pollux.php",
 "pollux_source/source/default_tool.php":PACKAGE/"source/default_tool.php",
 "pollux_source/source/form.template":PACKAGE/"source/form.template",
 "pollux_source/source/alfa_dat.php.base64":PACKAGE/"source/alfa_dat.php.base64",
 "target/README.md":HERE/"README.md",
 "target/driver_controls.py":HERE/"driver_controls.py",
 "target/driver_controls.json":HERE/"driver_controls.json",
 "target/prepare_gate.py":HERE/"prepare_gate.py",
}

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);module=importlib.util.module_from_spec(spec);sys.modules[name]=module;assert spec.loader;spec.loader.exec_module(module);return module
def scope():
 return {"identity":"ASTRA","boards":list(BOARDS),"decimal_directions":list(DECIMAL_DIRECTIONS),"hex_orientations":list(HEX_ORIENTATIONS),"contexts":16,"representation":"single Pollux decimal digits -> optional whole-string digit reverse -> whole integer -> uppercase even-length hex -> hex orientation","leading_zero":"none restored or inserted; valid nonempty encoder streams cannot begin or end separator digit 0","grammar":"nonempty sequence of any of the 44 literal Morse-table codewords separated by exactly one Morse space","retention":"all 16 full decimal digit strings and Morse strings, exact witness or complete positive; no score cutoff","crypto":"none"}

def require_gate():
 if not GATE.exists():raise RuntimeError("target gate absent")
 gate=json.loads(GATE.read_text());assert gate["identity"]=="ASTRA" and gate["target_evaluated"] is False
 assert gate["authorization"]=="FABLE plan 221 registered; separate root GO required" and gate["fable_reference"]=="FABLE message 221"
 assert gate["scope"]==scope() and gate["driver_sha256"]==sha(Path(__file__))
 assert gate["mdx_sha256"]==MDX_SHA and gate["dataset_sha256"]==DATASET_SHA and gate["canonical_text_sha256"]==TEXT_SHA
 assert gate["artifact_hashes"]=={name:sha(path) for name,path in ARTIFACTS.items()}
 controls=load("astra_pollux_target_controls_dependency",CONTROLS_PATH);controls.verify_sources();ledger=json.loads(CONTROL_LEDGER.read_text())
 assert ledger["identity"]=="ASTRA" and ledger["target_evaluated"] is False and ledger["rev7_read"] is False and all(ledger["assertions"].values())
 assert gate["control_source_sha256"]==sha(CONTROLS_PATH) and gate["control_ledger_sha256"]==sha(CONTROL_LEDGER)
 assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
 return gate,sha(GATE),controls

def normalize(value):return "".join(value.split()).upper()
def extract_canonical():
 text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a);left=normalize(text[a:b])
 rows=json.loads(DATASET.read_text());row=next(x for x in rows if x.get("id")=="rev7");right=normalize(row["ciphertext"])
 assert left==right and len(left)==1092 and all(c in "0123456789ABCDEF" for c in left) and hashlib.sha256(left.encode()).hexdigest()==TEXT_SHA
 return left,hashlib.sha256(row["ciphertext"].encode()).hexdigest()

def validate_morse(value,codewords,digits):
 assert len(value)==len(digits)
 if not value:return False,{"kind":"empty_stream","offset":0,"reason":"necessary language requires at least one Morse token"}
 start=0
 for position,char in enumerate(value):
  if char!=" ":continue
  if position==0:return False,{"kind":"head_separator","offset":0,"digit":digits[0],"morse":" ","reason":"leading empty token"}
  token=value[start:position]
  if not token:return False,{"kind":"empty_token","offset":position,"digit":digits[position],"morse":" ","reason":"consecutive separators"}
  if token not in codewords:return False,{"kind":"invalid_token","offset":start,"end_offset":position,"token":token,"reason":"not one of 44 literal table codewords"}
  start=position+1
 if start==len(value):return False,{"kind":"tail_separator","offset":len(value)-1,"digit":digits[-1],"morse":" ","reason":"trailing empty token"}
 token=value[start:]
 if token not in codewords:return False,{"kind":"invalid_token","offset":start,"end_offset":len(value),"token":token,"reason":"not one of 44 literal table codewords"}
 return True,None

def evaluate_context(canonical,board_name,decimal_direction,hex_orientation,controls):
 unshown=controls.hex_orient(canonical,hex_orientation)
 decimal_from_integer=controls.even_hex_to_decimal(unshown)
 digits=controls.decimal_transform(decimal_from_integer,decimal_direction)
 morse=controls.decode_pollux(digits,board_name)
 accepted,witness=validate_morse(morse,controls.CODEWORDS,digits)
 retransformed=controls.decimal_transform(digits,decimal_direction);rebuilt=controls.hex_orient(controls.decimal_to_even_hex(retransformed),hex_orientation)
 assert rebuilt==canonical
 return {"id":"board="+board_name+"|decimal="+decimal_direction+"|hex="+hex_orientation,"board":board_name,"decimal_direction":decimal_direction,"hex_orientation":hex_orientation,"decimal_digits":digits,"decimal_digits_sha256":hashlib.sha256(digits.encode()).hexdigest(),"decimal_digits_length":len(digits),"morse":morse,"morse_sha256":hashlib.sha256(morse.encode()).hexdigest(),"morse_length":len(morse),"necessary_language_accepted":accepted,"witness":witness,"exact_integer_reencryption":True,"leading_or_pair_zero_inserted":False}

def evaluate_grid(canonical,controls):
 rows=[evaluate_context(canonical,b,d,h,controls) for b in BOARDS for d in DECIMAL_DIRECTIONS for h in HEX_ORIENTATIONS]
 assert len(rows)==16 and len({row["id"] for row in rows})==16 and all(row["exact_integer_reencryption"] and not row["leading_or_pair_zero_inserted"] for row in rows)
 return rows

def write_new(path,value):
 if path.exists():raise SystemExit("refusing existing output")
 temporary=path.with_name(path.name+".tmp")
 with temporary.open("x") as handle:json.dump(value,handle,indent=2,sort_keys=True);handle.write("\n")
 os.replace(temporary,path)

def run(output):
 gate,gate_sha,controls=require_gate();canonical,dataset_field_sha=extract_canonical();rows=evaluate_grid(canonical,controls)
 classes={}
 for row in rows:
  key="accepted" if row["necessary_language_accepted"] else row["witness"]["kind"];classes[key]=classes.get(key,0)+1
 result={"identity":"ASTRA","target_evaluated":True,"configuration":{"scope":scope(),"gate_sha256":gate_sha,"driver_sha256":sha(Path(__file__)),"control_source_sha256":sha(CONTROLS_PATH),"control_ledger_sha256":sha(CONTROL_LEDGER),"mdx_sha256":MDX_SHA,"dataset_sha256":DATASET_SHA,"dataset_ciphertext_field_sha256":dataset_field_sha,"canonical_text_sha256":TEXT_SHA,"artifact_hashes":gate["artifact_hashes"]},"rows":rows,"summary":{"contexts":16,"complete":True,"accepted":sum(row["necessary_language_accepted"] for row in rows),"rejected":sum(not row["necessary_language_accepted"] for row in rows),"witness_classes":dict(sorted(classes.items())),"all_full_strings_retained":True,"all_exact_integer_reencryptions":True,"parity_zero_insertions":0}}
 write_new(output,result);print(json.dumps({"identity":"ASTRA","output":str(output),"sha256":sha(output),"summary":result["summary"]},indent=2))

def selftest():
 assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
 controls=load("astra_pollux_target_selftest_controls",CONTROLS_PATH);controls.verify_sources();ledger=json.loads(CONTROL_LEDGER.read_text());assert ledger["controls_source_sha256"]==sha(CONTROLS_PATH)
 assert scope()["contexts"]==16
 if GATE.exists():require_gate()
 print(json.dumps({"identity":"ASTRA","target_evaluated":False,"rev7_handling":"MDX and dataset bytes hashed only; target ciphertext not extracted, converted, decoded, or evaluated","driver_sha256":sha(Path(__file__)),"mdx_sha256":MDX_SHA,"dataset_sha256":DATASET_SHA,"scope":scope(),"gate_present":GATE.exists()},indent=2,sort_keys=True))

def main():
 parser=argparse.ArgumentParser();mode=parser.add_mutually_exclusive_group(required=True);mode.add_argument("--selftest",action="store_true");mode.add_argument("--run-target",action="store_true");parser.add_argument("--target-output",type=Path,default=HERE/"target_results.json");args=parser.parse_args()
 if args.selftest:selftest()
 else:run(args.target_output)
if __name__=="__main__":main()

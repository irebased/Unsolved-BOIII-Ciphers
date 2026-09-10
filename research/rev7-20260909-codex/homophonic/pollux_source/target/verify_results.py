#!/usr/bin/env python3
"""Portable independent fixed-grid verifier for the completed 16-context Pollux result."""
from __future__ import annotations
import base64,hashlib,json,re
from pathlib import Path

HERE=Path(__file__).resolve().parent
PACKAGE=HERE.parent
ROOT=HERE.parents[4]
RESULT=HERE/"target_results.json"
GATE=HERE/"target_gate.json"
MDX=ROOT/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
DATASET=ROOT/"lavender/src/data/ciphers/revelations.json"
RESULT_SHA="05ebcee30a780e7efa07008f8d6f4cb79c2150d5aef1591c343e239b131a0969"
GATE_SHA="dc1f7a11cd9b876b1119da9c90138409873486678f669753b73315c84dfe7a5e"
DRIVER_SHA="4871d10c2339ac27f390dbda79e750c83b893c275f3700007013dbcfed0ba029"
CONTROL_SOURCE_SHA="67d4455153a3d1caead4d6a57686dd29bbbd59ebd57b6eb051a4513272bf4d84"
CONTROL_LEDGER_SHA="18841da097e68c8e0416dabaf98e115147a1b0dd09e2dddcf4ec13ee21b2ed03"
MDX_SHA="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
DATASET_SHA="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
TEXT_SHA="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
DATASET_FIELD_SHA="1256ed980e4f4c3ade5fc681bdec6002650716898ef2d00f2d69e938e9420059"
BOARDS={
 "numeric_plain":{"0":" ","1":" ","2":" ","3":"-","4":"-","5":"-","6":".","7":".","8":".","9":"."},
 "numeric_mul7":{"0":" ","7":" ","4":" ","1":"-","8":"-","5":"-","2":".","9":".","6":".","3":"."},
}
DIRECTIONS=("identity","digit_reverse")
ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")
CODEWORDS=frozenset((".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--","-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--..",".----","..---","...--","....-",".....","-....","--...","---..","----.","-----",".-.-.-","--..--","..--..","---...","-.-.-.","-...-","-..-.",".-..-."))
ARTIFACTS={
 "pollux_source/controls.py":PACKAGE/"controls.py",
 "pollux_source/controls.json":PACKAGE/"controls.json",
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
def normalize(value):return "".join(value.split()).upper()
def orient(value,name):
 if name=="forward":return value
 if name=="full_hex_reverse":return value[::-1]
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 if name=="byte_reverse":return "".join(reversed(pairs))
 if name=="nibble_swap":return "".join(pair[::-1] for pair in pairs)
 raise ValueError(name)
def witness(value,digits):
 if not value:return False,{"kind":"empty_stream","offset":0,"reason":"necessary language requires at least one Morse token"}
 parts=value.split(" ");cursor=0
 for index,token in enumerate(parts):
  if token=="":
   if index==0:return False,{"kind":"head_separator","offset":0,"digit":digits[0],"morse":" ","reason":"leading empty token"}
   if index==len(parts)-1:return False,{"kind":"tail_separator","offset":len(value)-1,"digit":digits[-1],"morse":" ","reason":"trailing empty token"}
   return False,{"kind":"empty_token","offset":cursor,"digit":digits[cursor],"morse":" ","reason":"consecutive separators"}
  if token not in CODEWORDS:return False,{"kind":"invalid_token","offset":cursor,"end_offset":cursor+len(token),"token":token,"reason":"not one of 44 literal table codewords"}
  cursor+=len(token)+1
 return True,None
def regex_accepts(value):
 if not value:return False
 atom="(?:"+"|".join(re.escape(x) for x in sorted(CODEWORDS,key=lambda x:(-len(x),x)))+")"
 return re.fullmatch(atom+"(?: "+atom+")*",value) is not None
def canonical():
 assert sha(MDX)==MDX_SHA and sha(DATASET)==DATASET_SHA
 text=MDX.read_text();a=text.index("`83 B57B2")+1;b=text.index("`",a);left=normalize(text[a:b])
 rows=json.loads(DATASET.read_text());row=next(x for x in rows if x.get("id")=="rev7");right=normalize(row["ciphertext"])
 assert left==right and hashlib.sha256(left.encode()).hexdigest()==TEXT_SHA and hashlib.sha256(row["ciphertext"].encode()).hexdigest()==DATASET_FIELD_SHA
 return left
def expected_row(canonical_hex,board,direction,orientation):
 unshown=orient(canonical_hex,orientation);decimal=str(int(unshown,16));digits=decimal if direction=="identity" else decimal[::-1];morse="".join(BOARDS[board][x] for x in digits);accepted,why=witness(morse,digits);assert accepted==regex_accepts(morse)
 transformed=digits if direction=="identity" else digits[::-1];packed=format(int(transformed),"X");packed=("0"+packed) if len(packed)%2 else packed;assert orient(packed,orientation)==canonical_hex
 return {"id":"board="+board+"|decimal="+direction+"|hex="+orientation,"board":board,"decimal_direction":direction,"hex_orientation":orientation,"decimal_digits":digits,"decimal_digits_sha256":hashlib.sha256(digits.encode()).hexdigest(),"decimal_digits_length":len(digits),"morse":morse,"morse_sha256":hashlib.sha256(morse.encode()).hexdigest(),"morse_length":len(morse),"necessary_language_accepted":accepted,"witness":why,"exact_integer_reencryption":True,"leading_or_pair_zero_inserted":False}
def main():
 assert sha(RESULT)==RESULT_SHA and sha(GATE)==GATE_SHA and sha(HERE/"run_target.py")==DRIVER_SHA and sha(PACKAGE/"controls.py")==CONTROL_SOURCE_SHA and sha(PACKAGE/"controls.json")==CONTROL_LEDGER_SHA
 gate=json.loads(GATE.read_text());assert gate["identity"]=="ASTRA" and gate["target_evaluated"] is False and gate["driver_sha256"]==DRIVER_SHA and gate["fable_reference"]=="FABLE message 221"
 assert gate["artifact_hashes"]=={name:sha(path) for name,path in ARTIFACTS.items()}
 raw=base64.b64decode(b"".join((PACKAGE/"source/alfa_dat.php.base64").read_bytes().split()),validate=True);assert hashlib.sha256(raw).hexdigest()=="4db1baed5abd8aa86e428db2bed579e9cc52930e9cd527e1cf57487fd43eda3a"
 canonical_hex=canonical();expected=[expected_row(canonical_hex,b,d,h) for b in BOARDS for d in DIRECTIONS for h in ORIENTATIONS]
 data=json.loads(RESULT.read_text());assert data["identity"]=="ASTRA" and data["target_evaluated"] is True and data["configuration"]["gate_sha256"]==GATE_SHA and data["configuration"]["driver_sha256"]==DRIVER_SHA and data["configuration"]["canonical_text_sha256"]==TEXT_SHA
 assert data["rows"]==expected and len(expected)==16 and len({row["id"] for row in expected})==16
 classes={}
 for row in expected:
  key="accepted" if row["necessary_language_accepted"] else row["witness"]["kind"];classes[key]=classes.get(key,0)+1
 assert classes=={"empty_token":7,"head_separator":4,"invalid_token":5}
 assert data["summary"]=={"contexts":16,"complete":True,"accepted":0,"rejected":16,"witness_classes":classes,"all_full_strings_retained":True,"all_exact_integer_reencryptions":True,"parity_zero_insertions":0}
 print(json.dumps({"identity":"ASTRA","verified":True,"verification":"independent fixed 16-context conversion plus split/regex grammar, source/gate/canonical integrity; no expanded search","result_sha256":RESULT_SHA,"contexts":16,"accepted":0,"witness_classes":classes},indent=2,sort_keys=True))
if __name__=="__main__":main()

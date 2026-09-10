#!/usr/bin/env python3
"""Synthetic controls for the source-derived CrypTool Pollux numeric boards."""
from __future__ import annotations
import argparse,base64,hashlib,itertools,json,re
from pathlib import Path

HERE=Path(__file__).resolve().parent
SRC=HERE/"source"
LEDGER=HERE/"controls.json"
IDENTITY="ASTRA"
PINS={
 "functions.pollux.php":"3b49d000ad5352c37b49a83fb34b078d44c3f8045109ce5b9f4df0d6ef6ecb1c",
 "default_tool.php":"ca9f9ad05d3260203a1d8130ce4dc0b3da251cb845913e5985b45287fbd6224d",
 "form.template":"f359d01b0a4a19e3db7d83b78be5a4c7573e96476c2cdf741b8efd5450b8695a",
 "alfa_dat.php":"4db1baed5abd8aa86e428db2bed579e9cc52930e9cd527e1cf57487fd43eda3a",
 "alfa_dat.php.base64":"1020d8d7cdd0b69543ff924e9082d761e1149cc661fbe78e6f2792c32f8f7124",
}
BLOBS={
 "functions.pollux.php":"d3f3d0e1353241c167b20a9ce61a90131b2041c3",
 "default_tool.php":"4722f1511331a667dd6c36f560ef89f1d8e93e3f",
 "form.template":"68c65fa4cc470c5dc918e58fff706b6ee3171dc9",
 "alfa_dat.php":"63a0f7fc0d67b481515ae2625ddb5137992ac049",
}
SYMBOLS=tuple("ABCDEFGHIJKLMNOPQRSTUVWXYZ")+tuple("123456789")+(".",",","?",":",";","/")
MORSE_CODES=(
 ".-","-...","-.-.","-..",".","..-.","--.","....","..",".---","-.-",".-..","--","-.","---",".--.","--.-",".-.","...","-","..-","...-",".--","-..-","-.--","--..",
 ".----","..---","...--","....-",".....","-....","--...","---..","----.",
 ".-.-.-","--..--","..--..","---...","-.-.-.","-..-.",
)
MORSE=dict(zip(SYMBOLS,MORSE_CODES))
assert len(SYMBOLS)==len(MORSE_CODES)==41 and len(MORSE)==41
SOURCE_TABLE_CODEWORDS=frozenset(MORSE_CODES+("-----","-...-",".-..-."))
CODEWORDS=SOURCE_TABLE_CODEWORDS
BOARDS={
 "numeric_plain":{"separator":tuple("012"),"dash":tuple("345"),"dot":tuple("6789")},
 "numeric_mul7":{"separator":tuple("074"),"dash":tuple("185"),"dot":tuple("2963")},
}
HEX_ORIENTATIONS=("forward","full_hex_reverse","byte_reverse","nibble_swap")

def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def git_blob_bytes(data):return hashlib.sha1(b"blob "+str(len(data)).encode()+b"\0"+data).hexdigest()
def git_blob(path):return git_blob_bytes(Path(path).read_bytes())
def load_alfa(force_base64=False):
 encoded_path=SRC/"alfa_dat.php.base64";assert sha(encoded_path)==PINS["alfa_dat.php.base64"]
 decoded=base64.b64decode(b"".join(encoded_path.read_bytes().split()),validate=True);assert hashlib.sha256(decoded).hexdigest()==PINS["alfa_dat.php"] and git_blob_bytes(decoded)==BLOBS["alfa_dat.php"]
 raw_path=SRC/"alfa_dat.php"
 if raw_path.exists() and not force_base64:
  raw=raw_path.read_bytes();assert raw==decoded;return raw,"raw_equal_pinned_base64"
 return decoded,"pinned_base64_in_memory"
def verify_sources():
 for name,want in PINS.items():
  if name!="alfa_dat.php":assert sha(SRC/name)==want,(name,sha(SRC/name),want)
 for name,want in BLOBS.items():
  if name!="alfa_dat.php":assert git_blob(SRC/name)==want,(name,git_blob(SRC/name),want)
 raw,route=load_alfa();fallback,fallback_route=load_alfa(force_base64=True);assert raw==fallback and fallback_route=="pinned_base64_in_memory"
 funcs=(SRC/"functions.pollux.php").read_bytes().decode("utf-8");default=(SRC/"default_tool.php").read_bytes().decode("utf-8");form=(SRC/"form.template").read_bytes().decode("utf-8");alfa=raw.decode("latin-1")
 for needle in ("case ' ':","case '-':","case '.':","function createMulAlfa($alfa, $key)","function toMorse($orgtxt)","function fromMorse($codtxt)"):assert needle in funcs
 for needle in ("$_POST[num]","$_POST[alf]","$_POST[misch]","createMulAlfa($palfa, 7)","array_slice($palfa,0,$pvert[$n][0])","$orgtxt=str_replace(' ','',$orgtxt)","normalisiere($orgtxt,$morse[0])","trim(toMorse(trim($orgtxt)))"):assert needle in default
 assert form.count("type=checkbox")==3 and 'name=num' in form and 'name=alf' in form and 'name=misch' in form and 'name="key"' not in form
 for needle in ("$pvert[0] =  array( 3, 3, 4)","$pvert[1] =  array( 8, 8, 10)","$pvert[2] =  array( 11, 11, 14)","'9','10',","'.-.-.-', '--..--', '..--..', '---...', '-.-.-.', '-...-'","'-..-.',  '.-..-.'"):assert needle in alfa
 return True

def normalize_frontend(text):
 text=text.replace("ä","AE").replace("Ä","AE").replace("ö","OE").replace("Ö","OE").replace("ü","UE").replace("Ü","UE").replace("ß","SS")
 text=text.replace(" ","")
 return "".join(ch for ch in text.upper() if ch in MORSE)

def to_morse(text):
 normalized=normalize_frontend(text)
 return " ".join(MORSE[ch] for ch in normalized),normalized

def strict_encoder_language(value):
 if value=="":return False
 if value.startswith(" ") or value.endswith(" ") or "  " in value:return False
 return all(word in CODEWORDS for word in value.split(" "))

def independent_language(value):
 if value=="":return False
 atom="(?:"+"|".join(re.escape(x) for x in sorted(CODEWORDS,key=lambda x:(-len(x),x)))+")"
 return re.fullmatch(atom+"(?: "+atom+")*",value) is not None

def encode_pollux(morse,board_name):
 board=BOARDS[board_name];classes={" ":board["separator"],"-":board["dash"],".":board["dot"]};seen={" ":0,"-":0,".":0};out=[]
 for token in morse:
  choices=classes[token];out.append(choices[seen[token]%len(choices)]);seen[token]+=1
 return "".join(out)

def decode_pollux(digits,board_name):
 board=BOARDS[board_name];mapping={d:symbol for symbol,key in ((" ", "separator"),("-","dash"),(".","dot")) for d in board[key]}
 assert len(mapping)==10
 try:return "".join(mapping[d] for d in digits)
 except KeyError as exc:raise ValueError("outside numeric board") from exc

def decimal_transform(value,name):
 if name=="identity":return value
 if name=="digit_reverse":return value[::-1]
 raise ValueError(name)

def hex_orient(value,name):
 if len(value)%2:raise ValueError("even hex required")
 if name=="forward":return value
 if name=="full_hex_reverse":return value[::-1]
 pairs=[value[i:i+2] for i in range(0,len(value),2)]
 if name=="byte_reverse":return "".join(reversed(pairs))
 if name=="nibble_swap":return "".join(pair[::-1] for pair in pairs)
 raise ValueError(name)

def decimal_to_even_hex(digits):
 if not digits or not digits.isdigit():raise ValueError("nonempty decimal digits")
 value=format(int(digits),"X")
 return ("0"+value) if len(value)%2 else value

def even_hex_to_decimal(value):
 if not value or len(value)%2 or any(ch not in "0123456789ABCDEF" for ch in value):raise ValueError("uppercase even hex")
 return str(int(value,16))

def source_facts():
 return {
  "ui_controls":{"checkboxes":["num","alf","misch"],"freeform_key":False,"boards":6,"numeric_boards":2},
  "domains":{"numeric":"0..9","alphabetic":"A..Z","mixed":"A..Z then 0..9"},
  "class_counts":{"numeric":[3,3,4],"alphabetic":[8,8,10],"mixed":[11,11,14]},
  "mix":"createMulAlfa(palfa,7)",
  "default_no_boxes":"sets num, alf, and misch; selects the 36-symbol mixed board, then multiplies by 7",
  "numeric_boards":{name:{k:list(v) for k,v in board.items()} for name,board in BOARDS.items()},
  "frontend":{"removes_plaintext_spaces":True,"normalizes_against_morse0":True,"trims_morse_before_pollux":True,"encoder_nonempty_never_begins_or_ends_separator":True},
  "morse_quirks":{"zero_label_literal":"10","input_zero_removed_by_normalization":True,"space_code":"-...-","spaces_removed_before_normalization":True,"quote_table_label":"&quot;","literal_quote_not_accessible":True,"function_fromMorse_unknown_array_search_false_aliases_A":True,"encoder_controls_do_not_use_fromMorse":True},
 }

def produce(output):
 verify_sources();language_digest=hashlib.sha256();language_cases=0
 for length in range(7):
  for tup in itertools.product(".- ",repeat=length):
   value="".join(tup);a=strict_encoder_language(value);b=independent_language(value);assert a==b;language_digest.update(bytes((length,a))+value.encode());language_cases+=1
 inputs=("HELLO WORLD","TEST 123456789","PUNCT.,?:;/","ÄÖÜß","0 QUOTE \" @","SOS","A1/Z9;")
 rows=[]
 for source in inputs:
  morse,normalized=to_morse(source);assert strict_encoder_language(morse) and (not morse or (not morse.startswith(" ") and not morse.endswith(" ")))
  for board_name in BOARDS:
   digits=encode_pollux(morse,board_name);assert decode_pollux(digits,board_name)==morse
   if digits:assert digits[0]!="0" and digits[-1]!="0"
   for decimal_orientation in ("identity","digit_reverse"):
    transformed=decimal_transform(digits,decimal_orientation)
    if not transformed:continue
    assert transformed[0]!="0"
    packed=decimal_to_even_hex(transformed)
    for hex_orientation in HEX_ORIENTATIONS:
     shown=hex_orient(packed,hex_orientation);unshown=hex_orient(shown,hex_orientation);recovered=even_hex_to_decimal(unshown);assert recovered==transformed
     original=decimal_transform(recovered,decimal_orientation);assert original==digits and decode_pollux(original,board_name)==morse and strict_encoder_language(morse)
     rows.append({"input":source,"normalized":normalized,"morse":morse,"board":board_name,"digits":digits,"decimal_orientation":decimal_orientation,"hex_orientation":hex_orientation,"hex":shown,"roundtrip_exact":True})
 # A leading decimal zero is lossy under whole-integer conversion. No pair-phase zero is restored.
 lost={}
 for sample in ("0123","000","0"):
  packed=decimal_to_even_hex(sample);recovered=even_hex_to_decimal(packed);assert recovered==str(int(sample));lost[sample]={"hex":packed,"recovered_decimal":recovered,"lossy":recovered!=sample,"restored_digits":0}
 assert not strict_encoder_language("") and not strict_encoder_language(" ") and not strict_encoder_language(".  -") and not strict_encoder_language(".......") and strict_encoder_language("-...-") and strict_encoder_language("-----") and strict_encoder_language(".-..-.")
 result={
  "identity":IDENTITY,"target_evaluated":False,"rev7_read":False,
  "scope":"Source-derived Pollux frontend audit and synthetic controls for the two fixed numeric UI boards only.",
  "source":{"commit":"4fc443f0d87c0e86815695a47ab2d6174c725f82","sha256":PINS,"git_blob_sha1":BLOBS,"latin1_raw_base64_exact":True,"latin1_routes_verified":["raw_equal_pinned_base64","pinned_base64_in_memory"]},
  "facts":source_facts(),
  "morse_encoder_language":{"necessary_language":"all 44 literal Morse-table codewords, including frontend-unreachable entries as a safe superset","accessible_positive_symbols":"A-Z, digits 1-9, and . , ? : ; /","controlled_positive_codewords":MORSE,"table_codewords":sorted(CODEWORDS),"maximum_codeword_length":max(map(len,CODEWORDS)),"interletter_separator":"exactly one space","empty_string_accepted":False,"exhaustive_dot_dash_space_strings_length0through6":language_cases,"independent_regex_agreement":True,"digest":language_digest.hexdigest()},
  "synthetic_roundtrips":{"inputs":len(inputs),"rows":len(rows),"rows_data":rows,"integer_decimal_hex_exact":True,"reverse_digit_checked":True,"four_hex_orientations_checked":True},
  "leading_zero_controls":{"numeric_zero_role":"separator in both boards","valid_nonempty_encoder_output_starts_zero":False,"whole_integer_examples":lost,"pair_parity_zero_added":False,"meaning":"Pollux digits are single units; whole-integer conversion loses actual leading decimal zeros only."},
  "limitations":["Synthetic only; no Rev7 extraction, target driver, or target run.","Only the two source-fixed numeric UI boards are controlled here; alphabetic and mixed boards are audited but not searched.","The necessary-language filter accepts all 44 source-table tokens, including frontend-unreachable entries, as a conservative superset.","No generic class maps, radix-26, or radix-36 variants are enumerated."],
  "assertions":{"all_passed":True,"source_hashes_and_git_blobs_exact":True,"portable_latin1_base64_fallback":True,"only_three_ui_checkboxes_no_key":True,"six_ui_boards_two_numeric":True,"strict_encoder_language_not_fromMorse_alias":True,"single_digit_units_no_pair_zero":True,"no_target":True},
  "controls_source_sha256":sha(Path(__file__)),
 }
 if output.exists():raise SystemExit("refusing existing output")
 output.write_text(json.dumps(result,sort_keys=True,separators=(",",":"))+"\n")

def verify():
 verify_sources();data=json.loads(LEDGER.read_text());assert data["identity"]==IDENTITY and data["target_evaluated"] is False and data["rev7_read"] is False and data["controls_source_sha256"]==sha(Path(__file__))
 assert data["source"]["sha256"]==PINS and data["source"]["git_blob_sha1"]==BLOBS and data["facts"]==source_facts()
 assert data["morse_encoder_language"]["exhaustive_dot_dash_space_strings_length0through6"]==1093 and data["morse_encoder_language"]["independent_regex_agreement"] is True
 assert data["synthetic_roundtrips"]["rows"]==len(data["synthetic_roundtrips"]["rows_data"])==112 and all(x["roundtrip_exact"] for x in data["synthetic_roundtrips"]["rows_data"])
 assert all(data["assertions"].values()) and data["leading_zero_controls"]["pair_parity_zero_added"] is False
 print(json.dumps({"identity":IDENTITY,"verified":True,"read_only":True,"ledger_sha256":sha(LEDGER),"source_files":5,"numeric_boards":2,"roundtrip_rows":112,"target_evaluated":False},indent=2))

def main():
 parser=argparse.ArgumentParser();parser.add_argument("--regenerate",type=Path);args=parser.parse_args()
 if args.regenerate:
  output=args.regenerate.resolve();produce(output);print(json.dumps({"identity":IDENTITY,"output":str(output),"sha256":sha(output),"target_evaluated":False},indent=2))
 else:verify()
if __name__=="__main__":main()

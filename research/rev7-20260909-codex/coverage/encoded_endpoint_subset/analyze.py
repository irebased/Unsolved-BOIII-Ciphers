#!/usr/bin/env python3
"""ASTRA target-free encoded-alphabet subset audit."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,string
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[3]
MODEL=HERE.parent/"periodic_bytebag_controls/model.py";BROAD_SOURCE=REPO/"research/rev7-20260909-codex/bifid16_controls/complete_periods/run_target.py";OUT=HERE/"results.json"
IDENTITY="ASTRA";MODEL_SHA="bce745611e7a9b91d6471b348587c4f9af84ad39ffddae1c148a2ab5a670a444"
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def canonical(x):return json.dumps(x,sort_keys=True,indent=2)+"\n"
def load_model():
 assert sha(MODEL)==MODEL_SHA;spec=importlib.util.spec_from_file_location("periodic_bytebag_model",MODEL);m=importlib.util.module_from_spec(spec);spec.loader.exec_module(m);return m
def rec(name,alphabet,padding,narrow,broad):
 core=set(alphabet.encode("ascii"));pad={ord("=")};ws={9,10,13,32};variants=[]
 choices=[("alphabet",core),("alphabet_plus_whitespace",core|ws)]
 if padding:choices.extend((("alphabet_plus_padding",core|pad),("alphabet_plus_padding_and_whitespace",core|pad|ws)))
 for label,values in choices:
  variants.append({"variant":label,"bytes":sorted(values),"ascii":"".join(chr(x) for x in sorted(values) if 32<=x<=126),"byte_count":len(values),"subset_bag165":values<=narrow,"missing_from_bag165":sorted(values-narrow),"subset_bag213":values<=broad,"missing_from_bag213":sorted(values-broad)})
 return {"name":name,"alphabet":alphabet,"padding_registered":padding,"variants":variants}
def build():
 m=load_model();narrow=set(m.BYTE_BAG);broad={9,10,13,*range(32,127),*range(0x80,0xC0),*range(0xC2,0xF5)}
 assert len(narrow)==165 and len(broad)==213 and narrow<broad
 alphabets=[("binary","01",False),("octal","01234567",False),("decimal","0123456789",False),("hex_upper","0123456789ABCDEF",False),("hex_lower","0123456789abcdef",False),("base32_rfc4648","ABCDEFGHIJKLMNOPQRSTUVWXYZ234567",True),("base64_standard",string.ascii_uppercase+string.ascii_lowercase+string.digits+"+/",True)]
 rows=[rec(*x,narrow,broad) for x in alphabets]
 german=[]
 for ch,label in (("ä","a_umlaut"),("ö","o_umlaut"),("ü","u_umlaut"),("Ä","A_umlaut"),("Ö","O_umlaut"),("Ü","U_umlaut"),("ß","eszett")):
  encoded=ch.encode("utf-8");cp=ord(ch);german.append({"character":ch,"label":label,"codepoint":f"U+{cp:04X}","utf8_hex":encoded.hex().upper(),"utf8_bytes":list(encoded),"all_utf8_bytes_in_bag165":set(encoded)<=narrow,"all_utf8_bytes_in_bag213":set(encoded)<=broad,"codepoint_in_exact_201_repertoire":cp in m.CODEPOINTS})
 outside=[]
 for ch,label in (("ẞ","capital_eszett"),("„","double_low_quote"),("‚","single_low_quote"),("€","euro_sign")):
  encoded=ch.encode("utf-8");outside.append({"character":ch,"label":label,"codepoint":f"U+{ord(ch):04X}","utf8_hex":encoded.hex().upper(),"all_utf8_bytes_in_bag165":set(encoded)<=narrow,"all_utf8_bytes_in_bag213":set(encoded)<=broad,"codepoint_in_exact_201_repertoire":ord(ch) in m.CODEPOINTS})
 return {"identity":IDENTITY,"target_evaluated":False,"rev7_read":False,"claim":"Every declared ASCII encoding alphabet, optional equals padding, and TAB/LF/CR/space separator byte is a subset of both existing necessary byte bags.","bags":{"bag165":{"size":len(narrow),"bytes":sorted(narrow),"source":"coverage/periodic_bytebag_controls/model.py"},"bag213":{"size":len(broad),"bytes":sorted(broad),"source":"bifid16_controls/complete_periods/run_target.py BAG_VALUES"},"strict_subset_165_in_213":narrow<broad},"encoded_alphabets":rows,"german_latin1_letters":german,"german_counterexamples_outside_exact201":outside,"source_hashes":{"analyze.py":sha(Path(__file__)),"periodic_bytebag_model.py":sha(MODEL),"broad_bag_source.py":sha(BROAD_SOURCE)},"assertions":{"all_passed":True,"seven_alphabets":len(rows)==7,"all_18_variants_subset_bag165":all(v["subset_bag165"] for r in rows for v in r["variants"]),"all_18_variants_subset_bag213":all(v["subset_bag213"] for r in rows for v in r["variants"]),"seven_german_letters_bytes_in_both":all(x["all_utf8_bytes_in_bag165"] and x["all_utf8_bytes_in_bag213"] for x in german),"seven_german_letters_in_exact201":all(x["codepoint_in_exact_201_repertoire"] for x in german),"not_all_german_typography_in_exact201":all(not x["codepoint_in_exact_201_repertoire"] for x in outside)}}
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":IDENTITY,"output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert got==json.loads(OUT.read_text());print(json.dumps({"identity":IDENTITY,"verified":True,"ledger_sha256":sha(OUT),"alphabet_variants":18,"target_evaluated":False}))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""ASTRA read-only audit of grouped decoders after an IV-dependent prefix cut."""
from __future__ import annotations
import argparse, base64, hashlib, json
from pathlib import Path

IDENTITY = "ASTRA"
HERE = Path(__file__).resolve().parent
REPO = HERE.parents[3]
OUT = HERE / "audit.json"
FILES = {
 "hex_cfb/encoded/run_encoded.py": "b2359b18171523ee4bc37cab4d6bab6a5633dba72e28f76d6fae98898ac22b3c",
 "hex_cfb/encoded_extend/run_extend.py": "255b37a642cc01feec0f4327c809a3be6917ff6cb9a33f50f5eec51bfa397aef",
 "iv_independent/cascade/target/run_target.py": "dea3bceff94993abb7f59993300f71552c3ca84b344e96b22d27479c3dc05d41",
 "iv_independent/cascade/proof.py": "1152ff62572b5914c1840ddd4af14efdc1ff26c58051a566c62bfb2ed1a1f8c0",
 "whole_numeric/controls.py": "937dfea250ca67e6788263db4431d4b324c08d807eade51c034755bbe745408e",
 "coverage/encoded_endpoint_subset/analyze.py": "e988916779770abdfe7e23cd542c87e3bed3048572ed30e519da0557df26c78f",
 "coverage/fable_bytebag_replay/verify_outputs.py": "721b7584c6daa3034ccca56c4e53a1010edff0cc1b940266b304cda6dc3af389",
 "hex_cfb/native_siblings/controls.py": "bc7ba1a64dbc2a951d9edc126a5ff5c97c181c470d3772b690b9dbdffe517739",
 "sources/rev9_source/controls.py": "df6fa534502134f7f50a760064c28f62832dd15d3fe40ec01c2658272e4d611d",
 "comms/encoded-go-20260910.json": "cc45e8b55823b4cfcc9ba36b7cf6727ef493ea1df6875acdcafb77bbc932ad9e",
 "comms/whole-numeric-go-20260910.json": "345d53de32bae68853aeecd7917f9995e9cb78a18368323ac9f2f605cb031063",
 "comms/astra_cascade_prereg_payload.json": "06e87c76cd7893e5dc13fd91d1e203617b6d21cb2170ee296a1a15df20cbe3f3",
}
BASE = REPO / "research/rev7-20260909-codex"
def sha(path: Path) -> str: return hashlib.sha256(path.read_bytes()).hexdigest()
def line_of(text: str, needle: str) -> int:
 lines=text.splitlines()
 hits=[i for i,x in enumerate(lines,1) if needle in x]
 assert len(hits)==1,(needle,hits)
 return hits[0]
def evidence(rel: str, needles: list[str], classification: str, effect: str) -> dict:
 path=BASE/rel; text=path.read_text(errors="strict")
 assert sha(path)==FILES[rel]
 return {"path":f"research/rev7-20260909-codex/{rel}","sha256":FILES[rel],
         "lines":[line_of(text,n) for n in needles],"classification":classification,"alignment_effect":effect}
def fixed3_decode(stream: bytes) -> bytes:
 assert len(stream)%3==0 and stream.isdigit()
 return bytes(int(stream[i:i+3]) for i in range(0,len(stream),3))
def build() -> dict:
 for rel,want in FILES.items(): assert sha(BASE/rel)==want,rel
 # A decimal fixed-three stream cut at a nonmultiple of three cannot be regrouped at local zero.
 plain=bytes(range(65,91)); decimal=b"".join(f"{x:03d}".encode() for x in plain)
 decimal_rows=[]
 for cut in (8,16,32):
  trim=(-cut)%3; aligned=cut+trim; recovered=fixed3_decode(decimal[aligned:])
  assert recovered==plain[aligned//3:]
  naive=decimal[cut:]
  naive_accepted=len(naive)%3==0
  if naive_accepted:
   try: naive_value=fixed3_decode(naive)
   except (ValueError,OverflowError): naive_value=None
   assert naive_value!=plain[cut//3:]
  decimal_rows.append({"cut":cut,"phase":cut%3,"leading_trim_to_next_original_boundary":trim,
                       "naive_local_zero_length_mod3":len(naive)%3,"naive_local_zero_fixed3_accepted":naive_accepted,
                       "aligned_global_offset":aligned,"aligned_decoded_hex":recovered.hex()})
 # Ordinary Base64 quartet phase is preserved by the registered 8/16/32-byte block cuts.
 raw=bytes(range(60)); encoded=base64.b64encode(raw); assert len(encoded)==80 and not encoded.endswith(b"=")
 base64_rows=[]
 for cut in (8,16,32):
  decoded=base64.b64decode(encoded[cut:],validate=True)
  assert cut%4==0 and decoded==raw[(cut//4)*3:]
  base64_rows.append({"cut":cut,"phase":cut%4,"decoded_raw_offset":cut//4*3,"exact":True})
 inventory=[
  evidence("hex_cfb/encoded/run_encoded.py",["\"decimal\": CONTROL_BYTES","\"base64\": CONTROL_BYTES","return 0 if value in allowed else None","assert all(value in allowed for value in plaintext)"],"position-independent encoded-alphabet detector","No grouping or decoding occurs; a phase cut cannot itself create a false negative. A retained alphabet-only candidate was never claimed to decode."),
  evidence("hex_cfb/encoded_extend/run_extend.py",["ALLOWED = set(prior.ENDPOINTS[\"base64\"])","return 0 if value in ALLOWED else None"],"position-independent Base64-byte detector","No quartet decoder is called."),
  evidence("iv_independent/cascade/target/run_target.py",["def endpoint(data,left,right,total):","if v not in RELAXED:","states=set(initial)"],"known-interval A105/UTF-8 detector","No decimal/Base64 grouping occurs; boundary-aware UTF-8 states are enumerated."),
  evidence("coverage/fable_bytebag_replay/verify_outputs.py",["out[r['skippedPrefixBytes']:]"],"skipped-suffix byte-bag detector","No grouped decoding occurs."),
  evidence("whole_numeric/controls.py",["def parse_fixed3(stream: str, base: int)","rev7 = extract_rev7()","number = int(oriented_hex, 16)","for parser in TARGET_PARSERS:"],"actual grouped decoder on a whole-buffer numeral transform","The complete oriented ciphertext is converted to a whole integer before parsing; no CFB-derived prefix is sliced."),
  evidence("hex_cfb/native_siblings/controls.py",["outer=base64.b64decode","stripped=s1.rstrip", "b3=base64.b64decode(s4)"],"solved Rev5 full-buffer control","Every grouped transformation consumes a complete fixed-IV layer output; no unknown-IV prefix is discarded."),
  evidence("sources/rev9_source/controls.py",["step1=cfb8(outer,des,IV8,True)","tokens=re.findall", "twofish_input=base64.b64decode"],"solved Rev9 full-buffer control","Three-digit and Base64 decoding use the complete fixed-IV DES output."),
  evidence("iv_independent/cascade/proof.py",["No interposed hex/Base64/numeric encoding"],"explicit direct-binary theorem limit","The theorem excludes grouped interlayers rather than decoding a cut suffix."),
 ]
 return {"identity":IDENTITY,"target_evaluated":False,"new_target_search":False,
  "question":"Does accepted ASTRA source skip an IV-dependent CFB8 prefix and then parse fixed-width decimal or Base64 groups at suffix-local offset zero?",
  "answer":"No such accepted target pipeline was found in the reviewed encoded-endpoint, whole-numeric, or direct-cascade sources.",
  "valid_warning":"A future fixed-width decoder over a known suffix must preserve the original stream phase. For width g, begin at the first retained global offset congruent to zero modulo g (and handle an incomplete right edge), or enumerate the justified phase when the origin is unknown.",
  "synthetic_witness":{"fixed_decimal3":decimal_rows,"base64_quartets":base64_rows,
    "interpretation":"Cuts 8,16,32 have decimal phases 2,1,2 and therefore cannot be fed directly to a local-zero fixed3 parser. The same cuts all have Base64 phase zero because they are multiples of four."},
  "reviewed_inventory":inventory,
  "scope_notes":[
   "Alphabet and byte-bag gates are necessary position-independent filters. They do not perform or certify grouped decoding.",
   "A detector that runs before a grouped decoder can retain false positives, but group phase does not make that detector reject an otherwise alphabet-valid suffix.",
   "Whole-buffer numeral and solved-sibling pipelines use complete buffers and fixed IVs; the prefix-cut concern does not apply to them.",
   "The direct cascade family explicitly excludes interposed Base64, numeric, framing, and length-changing transforms.",
   "Base64 phase-zero at block-size cuts does not establish decodability of every arbitrary known interval: its right boundary, padding, and any non-block transform still require explicit handling.",
   "This source audit is not a proof that no unpublished, superseded draft, or FABLE pipeline has the defect. It makes no new claim about Rev7 plaintext."
  ],
  "source_hashes":FILES,
  "assertions":{"all_pins_match":True,"reviewed_paths":len(inventory),"vulnerable_accepted_pipeline_found":False,
    "decimal3_nonzero_phases":{"8":2,"16":1,"32":2},"base64_zero_phases":{"8":0,"16":0,"32":0}}
 }
def canonical(x): return json.dumps(x,indent=2,sort_keys=True)+"\n"
def main():
 ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args();got=build()
 if a.regenerate:
  if a.regenerate.exists(): raise SystemExit(f"refusing existing output: {a.regenerate}")
  a.regenerate.write_text(canonical(got));print(json.dumps({"identity":IDENTITY,"output":str(a.regenerate),"sha256":sha(a.regenerate)}));return
 assert json.loads(OUT.read_text())==got
 print(json.dumps({"identity":IDENTITY,"verified":True,"audit_sha256":sha(OUT),"vulnerable_accepted_pipeline_found":False}))
if __name__=="__main__": main()

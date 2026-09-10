#!/usr/bin/env python3
"""ASTRA source/serialization audit; no Rev7 ciphertext or decryption."""
from pathlib import Path
import hashlib,json
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
PINS={'lavender/src/content/docs/ciphers/bo3/zns/zns5.mdx': '4b125343323a4e8e817c1aa0d6bea38ed6512f153a8e7ec3aa1c6730cae75696', 'lavender/src/content/docs/ciphers/bo3/gk/gk8.mdx': '2326f36425b3507d39d6a4f0c734783d0c32c94b8865fe92b3aa97c0a50ef160', 'lavender/src/data/ciphers/zetsubou.json': '5714592132cb97223180e5b786e6b9239fe76136d92d885a9a21f629698415d3', 'lavender/src/data/ciphers/gorod_krovi.json': 'f05703ae5173e02187e4840593cf9137048a60e5dec13898961ec606ddef0d3d', 'lavender/src/assets/bo3/zns/zns_5.webp': 'd66661148b93f934075ee4e6ef9fb19c1f7ed39d4f73d853b29db02ed873d8ad', 'lavender/src/assets/bo3/gk/gk_8.webp': '6aaa50753c84a9e0209915af38102b18cf02841b5e8cc8aced50fd4b18c241b1'}
for rel,pin in PINS.items():assert hashlib.sha256((ROOT/rel).read_bytes()).hexdigest()==pin
rows={}
for rel,ident in [("lavender/src/data/ciphers/zetsubou.json","zns5"),("lavender/src/data/ciphers/gorod_krovi.json","gk8")]:
    row=next(x for x in json.loads((ROOT/rel).read_text()) if x["id"]==ident)
    rows[ident]={k:row[k] for k in ("id","title","image","ciphertext","solution")}
assert rows["zns5"]["solution"]["steps"][0]["method"]=="numbers_to_letters"
assert rows["gk8"]["solution"]["steps"][0]["method"]=="baudot_code"
# Six pairs manually read by ASTRA from the source image, not inferred by OCR.
prefix="050423011804"
pairs=[int(prefix[i:i+2]) for i in range(0,len(prefix),2)]
word="".join(chr(64+n) for n in pairs);assert word=="EDWARD"
print(json.dumps({"identity":"ASTRA","rev7_read":False,"source_files_sha256":PINS,"records":rows,"zns5_manually_observed_image_prefix":prefix,"prefix_pair_values":pairs,"prefix_decodes_to":word,"limits":"The dataset has no ciphertext transcription for either entry. Image inspection establishes displayed decimal digits for zns5 and a punched-tape drawing for gk8; neither documents a raw-byte serialization feeding another cipher. This is not an end-to-end cipher replay."},sort_keys=True,indent=2))

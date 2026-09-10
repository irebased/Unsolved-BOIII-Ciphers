#!/usr/bin/env python3
"""ASTRA exact production-codec replay of the fixed prior 64-file sample."""
from pathlib import Path
import hashlib,json,tempfile
import codec
HERE=Path(__file__).resolve().parent
assert hashlib.sha256((HERE/"codec.py").read_bytes()).hexdigest()=="2984ce1a8a8053bc7bc7745880da603832a7b8d3708828d75841f6a7b607278a"
assert hashlib.sha256((HERE/"results.json").read_bytes()).hexdigest()=="5e4a1b5b04e9d6bd94408f100e4e6806b874992ebdfd44187c0f9a828631c08e"
ledger=json.loads((HERE/"results.json").read_text());rows=[]
for row in ledger["sample"]["records"]:
    raw=(HERE.parent/row["path"]).read_bytes()
    assert len(raw)==row["gzip_bytes"] and hashlib.sha256(raw).hexdigest()==row["gzip_sha256"]
    rows.append((row["path"],raw))
assert len(rows)==64
parts=codec.pack(rows)
restored=[]
for part in parts:restored.extend(codec.unpack(part))
assert restored==rows
with tempfile.TemporaryDirectory(prefix="astra-bifid-codec-sample-") as td:
    for part in parts:codec.restore(part,td)
    for name,raw in rows:assert (Path(td)/name).read_bytes()==raw
print(json.dumps({"identity":"ASTRA","new_target_search":False,"new_solver_run":False,"whole_corpus_packed":False,"fixed_sample_records":64,"original_gzip_bytes":sum(len(b) for _,b in rows),"transport_part_bytes":[len(b) for b in parts],"transport_part_sha256":[hashlib.sha256(b).hexdigest() for b in parts],"exact_in_memory_and_filesystem_restore":"PASS","codec_sha256":hashlib.sha256((HERE/"codec.py").read_bytes()).hexdigest()},sort_keys=True,indent=2))

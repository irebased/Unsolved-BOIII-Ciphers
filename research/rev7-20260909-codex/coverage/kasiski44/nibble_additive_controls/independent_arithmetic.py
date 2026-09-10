#!/usr/bin/env python3
"""ASTRA independent candidate-key derivation from plaintext bytes."""
from pathlib import Path
import hashlib,json
import model
HERE=Path(__file__).resolve().parent
assert hashlib.sha256((HERE/"model.py").read_bytes()).hexdigest()=="d0a4c73f3fa61f198f59b0a662f4f3b3039c2fc092aed19dce9e70cbbad4a010"
assert hashlib.sha256((model.PBC/"model.py").read_bytes()).hexdigest()=="bce745611e7a9b91d6471b348587c4f9af84ad39ffddae1c148a2ab5a670a444"
rows=[]
for operation in ("subtract","beaufort"):
    digest=hashlib.sha256()
    for cipher in range(256):
        ch,cl=divmod(cipher,16)
        keys=set()
        for plain in model.BYTE_BAG:
            ph,pl=divmod(plain,16)
            if operation=="subtract":kh,kl=(ch-ph)%16,(cl-pl)%16
            else:kh,kl=(ph+ch)%16,(pl+cl)%16
            keys.add(16*kh+kl)
        assert len(keys)==165
        expected=sum(2**k for k in keys)
        assert expected==model.candidate_mask(cipher,operation)
        digest.update(expected.to_bytes(32,"big"))
    rows.append({"operation":operation,"cipher_values":256,"expected_keys_per_value":165,"mask_table_sha256":digest.hexdigest()})
print(json.dumps({"identity":"ASTRA","target_read":False,"status":"PASS","method":"derive keys from all permitted plaintext bytes, independently of model decryption","tables":rows},indent=2,sort_keys=True))

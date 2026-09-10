#!/usr/bin/env python3
"""ASTRA synthetic counterexample to D>=71 excluding formatted Base64."""
import base64, hashlib, json
alphabet = b'ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'
core = alphabet + b'A' * 26 + b'=='
whitespace = b' \t\n\r\v\f'
text = core + whitespace
clean = bytes(x for x in text if x not in whitespace)
decoded = base64.b64decode(clean, validate=True)
assert len(text) == 98 and len(set(text)) == 71
assert len(core) == 92 and len(set(core)) == 65
assert base64.b64encode(decoded) == core
print(json.dumps({'identity':'ASTRA','target_evaluated':False,'status':'PASS','formatted_length':len(text),'distinct_bytes':len(set(text)),'core_length':len(core),'core_distinct':len(set(core)),'decoded_length':len(decoded),'formatted_hex':text.hex(),'sha256':hashlib.sha256(text).hexdigest(),'scope':'explicitly remove the six ASCII whitespace symbols, then strict canonical padded Base64'}))

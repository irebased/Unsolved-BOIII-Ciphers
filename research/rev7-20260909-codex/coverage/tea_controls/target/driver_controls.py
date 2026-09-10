#!/usr/bin/env python3
import hashlib,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;sys.path.insert(0,str(HERE));import run_target as R
sys.path.insert(0,str(HERE.parent));import model
plant=(b'TEA driver mixed UTF8 control \xc2\xa0 \xe2\x80\xa6. '+bytes(range(32,127)))*8;plant=plant[:546].ljust(546,b'X')
def inverse_observed(hextext,o):
 if o=='forward':return hextext,[hextext]
 if o=='full_hex_reverse':return hextext[::-1],[hextext[::-1]]
 if o=='byte_pair_reverse':return ''.join(reversed([hextext[i:i+2] for i in range(0,len(hextext),2)])),[''.join(reversed([hextext[i:i+2] for i in range(0,len(hextext),2)]))]
 if o=='nibble_swap':return ''.join(hextext[i+1]+hextext[i] for i in range(0,len(hextext),2)),[''.join(hextext[i+1]+hextext[i] for i in range(0,len(hextext),2))]
 natural=R.chunks_left(hextext,5);obs=list(reversed(natural));return ''.join(obs),obs
rows=[]
for o in R.ORIENTATIONS:
 for packing in R.PACKINGS:
  for keyname in R.KEYS:
   key=keyname.encode().ljust(16,b'\0')
   for ivname in R.IVS:
    iv=bytes(8) if ivname=='null' else b'0'*8
    for mode in R.MODES:
     ct=model.crypt(plant,key,iv,mode,packing,False);obs,tokens=inverse_observed(ct.hex().upper(),o);got=bytes.fromhex(R.oriented(obs,tokens)[o]);assert got==ct
     row=R.execute(got,o,packing,keyname,ivname,mode);assert bytes.fromhex(row['plaintext_hex'])==plant and row['sha256']==hashlib.sha256(plant).hexdigest();rows.append(row['id'])
assert len(rows)==160 and len(set(rows))==160
print(json.dumps({'identity':'ASTRA','target_evaluated':False,'status':'PASS','cells':160,'ids_sha256':hashlib.sha256('\n'.join(rows).encode()).hexdigest()},sort_keys=True))

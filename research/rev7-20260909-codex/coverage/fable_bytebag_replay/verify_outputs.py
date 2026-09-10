#!/usr/bin/env python3
"""Read-only verification of FABLE replay's saved bytes and corrected modes."""
import base64,hashlib,json
from pathlib import Path
HERE=Path(__file__).resolve().parent
sha=lambda b:hashlib.sha256(b).hexdigest()
def main():
 data=json.loads((HERE/'verified_outputs.json').read_text());manifest=(HERE/'manifest.json').read_bytes()
 assert sha(manifest)==data['sourceManifestSHA256'] and sha((HERE/'replay.js').read_bytes())==data['scriptSHA256']
 for f in json.loads(manifest)['files']:
  path=HERE/f['local_path']
  raw=base64.b64decode(path.with_suffix('.wasm.base64').read_text(),validate=False) if path.suffix=='.wasm' else path.read_bytes()
  assert len(raw)==f['bytes'] and sha(raw)==f['sha256']
 original=(HERE/'source/record/bytebag_184rows.json').read_bytes();assert sha(original)==data['originalLedgerSHA256']
 old={ (r['orientation'],r['cipher'],r['keyString']):r for r in json.loads(original)['rows'] }
 points=(9,10,13,*range(32,127),*range(160,256),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
 bag={b for cp in points for b in chr(cp).encode('utf-8')};assert len(bag)==165
 seen=set();cfb=[];streams=[]
 for r in data['rows']:
  key=(r['orientation'],r['cipher'],r['keyString']);assert key not in seen;seen.add(key);o=old[key]
  out=bytes.fromhex(r['outputHex']);assert len(out)==o['outputLength']==546 and sha(out)==o['outputSha256']==r['outputSha256']
  count=sum(b not in bag for b in out[r['skippedPrefixBytes']:]);assert count==o['bytesOutsideBag']==r['bytesOutsideBag']
  stream=r['cipher'] in {'enigma','panama','arcfour','wake'};assert r['mode']==('stream' if stream else 'cfb8')
  if stream:
   assert r['blockSize']==0 and r['skippedPrefixBytes']==8 and r['singleEditCFB8Margin'] is None;streams.append(r)
  else:
   assert r['skippedPrefixBytes']==r['blockSize'] and r['singleEditCFB8Margin']==count-r['blockSize']-1>0;cfb.append(r)
 assert seen==set(old) and len(seen)==184 and len(cfb)==152 and len(streams)==32
 assert min(r['bytesOutsideBag'] for r in data['rows'])==153
 assert min(r['singleEditCFB8Margin'] for r in cfb)==136
 print(json.dumps({'identity':'ASTRA','verified':True,'saved_outputs':184,'cfb8':152,'stream':32,'minimum_outside':153,'minimum_cfb8_single_edit_margin':136,'verified_outputs_sha256':sha((HERE/'verified_outputs.json').read_bytes()),'cryptography_repeated':False},sort_keys=True))
if __name__=='__main__':main()

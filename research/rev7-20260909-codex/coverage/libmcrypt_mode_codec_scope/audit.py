#!/usr/bin/env python3
"""ASTRA source-only libmcrypt mode and pinned-RA codec audit."""
from __future__ import annotations
import argparse, base64, hashlib, json
from pathlib import Path
import re
HERE=Path(__file__).resolve().parent
REF='3bd338e2f808e985f5b229a7642d48c26615993f'
RA='e127b8d6c17f567b930fe67624d3ea199528b775'
SOURCES={
'COPYING.LIB':'ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532',
'configure.in':'4945332b33d0bb0012443e56b498cba71e5b6271a4c59150e956f61f2bb8c7de',
'lib__libdefs.h':'d3de33ad9a60f716dbebe5826ed714cf9ab00b7fe66209f53e826e584151a901',
'lib__mcrypt_extra.c':'e452ef3505da277b91ae316c68fdf4e64fbbebfa594141933d79cf04dcd4f578',
'lib__mcrypt_internal.h':'6d9f69a455d9194c9a0ef6c188a3e6609e5b9daa378249233ccd8205647249cf',
'lib__mcrypt_modules.c':'8e1962b8b52c4ad94c3e2f629c488f8aa6c4fc6c62c4b89a578e62437b5122f8',
'modules__modes__ctr.c':'3d4f2d464f3e03e804fde84f5eab4fc3a74504622159eff31fb31d7ce4ace034',
'modules__modes__Makefile.am':'37698dd3a5609c6663e9735bd00a17ed521ff444a03b4f79f14ef6f8b045e2fc',
'modules__modes__cbc.c':'c39741d240c6d38121df6fb5f8cf5fefefeb4fe1a64ce71f47d2e013e959e90d',
'modules__modes__cfb.c':'85ed165227f4db7decf3ccdc576b96a8c5cbe51af1882a30cbefeeaff37c2f39',
'modules__modes__ecb.c':'71140021f9e8853e58c8c1941bb080866e14c39a0fcbf98b694904fdec903f05',
'modules__modes__ncfb.c':'0150a78e220c740ddbba55cbd26afe728fcc38cce56fad429618416968f3bcee',
'modules__modes__nofb.c':'d0df49d847478c83fa9a1cbf21686623e390a80fbbd558d2640aa4e4d8c246e9',
'modules__modes__ofb.c':'aec1699eecb37e4791e704d074e88fbe210f62dd75e6c1face8a5fc302ee926d',
'modules__modes__stream.c':'f2984cb0f1641ca3bb8f45c0411a234e41c39af5dcc5cc176b2d637efed22f4c',
'ra-e127b8d__Cargo.lock':'03f3b58196c11fcd795d1ebffc97b29e441785989e4e44ebfb568be945198dd6',
'ra-e127b8d__crates__ra-core__src__nodes.rs':'ea93e1b0e235f691d7814eec0eef2b2a2b0c7f7c0fc1a76ffbebbc218796c43c',
'ra-e127b8d__crates__ra-core__src__repr.rs':'cd2223d43482615951e0e8b4808aa48982da3a3fb8967ef7a67a51c43014bb22',
}
def sha(b): return hashlib.sha256(b).hexdigest()
def line(s,n):
 assert n in s,n
 return s[:s.index(n)].count('\n')+1
def ra_b64_filter(data:bytes):
 s=bytes(c for c in data if chr(c).isalnum() and c<128 or c in b'+/=')
 # isalnum differs for >127, but c<128 binds the accepted alphanumeric branch.
 s+=b'='*((-len(s))%4)
 try:return base64.b64decode(s,validate=True),s
 except Exception:return None,s
def ra_hex_filter(data:bytes):
 s=bytes(c for c in data if c in b'0123456789abcdefABCDEF')
 if len(s)%2:s=s[:-1]
 return bytes.fromhex(s.decode()),s
def ra_decimal(data:bytes):
 try:s=data.decode('utf-8')
 except UnicodeDecodeError:return None
 # Witness model only; source uses Rust split_ascii_whitespace.
 stripped=s.strip(' \t\n\f\r')
 if not stripped:return None
 toks=re.split(r'[ \t\n\f\r]+',stripped)
 try:
  if any(not t.isascii() or not t.isdigit() for t in toks):return None
  vals=[int(t,10) for t in toks]
  return bytes(vals) if all(v<=255 for v in vals) else None
 except ValueError:return None

def build():
 src={}; files={}
 for n,h in SOURCES.items():
  b=(HERE/'source'/n).read_bytes(); assert sha(b)==h,(n,sha(b));src[n]=b.decode();files[n]={'bytes':len(b),'sha256':h}
 cfg=src['configure.in']; assert all(x in cfg for x in ['LIBMCRYPT_MAJOR_VERSION=2','LIBMCRYPT_MINOR_VERSION=5','LIBMCRYPT_MICRO_VERSION=8'])
 make=src['modules__modes__Makefile.am']
 declared=['ofb','ctr','cfb','ncfb','nofb','ecb','cbc','stream']
 for mode in declared: assert f'{mode}_la_SOURCES = {mode}.c' in make
 assert make.count('_la_SOURCES = ')==len(declared)
 mods=src['lib__mcrypt_modules.c']
 q=['int mcrypt_enc_is_block_mode(MCRYPT td)','_is_block_mode = mcrypt_dlsym(td->mode_handle, "_is_block_mode");','return _is_block_mode();']
 for x in q:assert x in mods
 modes={}
 for mode,want in [('ecb',1),('cbc',1),('cfb',0),('ctr',0),('ncfb',0),('ofb',0),('nofb',0),('stream',0)]:
  name=f'modules__modes__{mode}.c';s=src[name];needle=f'int _is_block_mode() {{ return {want}; }}';assert needle in s
  modes[mode]={'is_block_mode':want,'line':line(s,needle),'source':name,'source_sha256':SOURCES[name]}
 reprs=src['ra-e127b8d__crates__ra-core__src__repr.rs']
 for needle in [
  '.filter(|c| c.is_ascii_hexdigit())','if s.len() % 2 == 1 {','s.pop();',
  ".filter(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/' || *c == b'=')",
  'while s.len() % 4 != 0 {','s.push(b\'=\');','STANDARD.decode(&s).ok()',
  'let s = std::str::from_utf8(data).ok()?;','for tok in s.split_ascii_whitespace() {','u8::from_str_radix(tok, radix).ok()?'
 ]:assert needle in reprs
 b546=b'A'*546; out,padded=ra_b64_filter(b546);assert out is not None and len(padded)==548 and len(out)==409
 bmix_out,bmix_filtered=ra_b64_filter(b'!!QUJD??');assert bmix_filtered==b'QUJD' and bmix_out==b'ABC'
 hout,hfiltered=ra_hex_filter(b'GG41 zz4');assert hfiltered==b'41' and hout==b'A'
 assert ra_decimal(b'065 255\n0')==bytes([65,255,0]);assert ra_decimal(b'65x 1') is None;assert ra_decimal(bytes([0xff])) is None
 utf8_b64_out,utf8_b64_kept=ra_b64_filter('QéUJD'.encode());assert utf8_b64_kept==b'QUJD' and utf8_b64_out==b'ABC'
 utf8_hex_out,utf8_hex_kept=ra_hex_filter('4é1'.encode());assert utf8_hex_kept==b'41' and utf8_hex_out==b'A'
 assert ra_decimal('65 66'.encode()) is None
 return {'identity':'ASTRA','target_evaluated':False,'source_only':True,'source_files':files,
 'libmcrypt':{'version':'2.5.8','mirror_commit':REF,'query_trace':{'definition_line':line(mods,q[0]),'dlsym_line':line(mods,q[1]),'return_line':line(mods,q[2])},'declared_mode_modules':declared,'mode_module_count':len(declared),'modes':modes},
 'ra':{'commit':RA,'base64_crate':{'version':'0.22.1','checksum':'72b3254f16251a8381aa12e40e3c4d2f0199f8c6508fbecb9d91f575e0fbb8c6'},
 'codec_semantics':{
 'base64':'Retain only ASCII alphanumeric,+,/ and =; silently discard all other bytes; append = until length is divisible by four; then STANDARD decode, which may still reject invalid padding/structure.',
 'hex':'Retain only ASCII hex digits; silently discard all other bytes; if retained nibble count is odd, drop its last nibble; decode the remainder.',
 'decimal':'Require the whole buffer to be UTF-8; split on ASCII whitespace; require at least one token; parse every token as a base-10 u8. No fixed token width.'},
 'source_bytes_also_match_ancestor_commit':'e6c282187cc8a555580349d819210b544e5417b1',
 'anchors':{'hex_filter':line(reprs,'.filter(|c| c.is_ascii_hexdigit())'),'base64_filter':line(reprs,".filter(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/' || *c == b'=')"),'base64_repad':line(reprs,'while s.len() % 4 != 0 {'),'decimal_utf8':line(reprs,'let s = std::str::from_utf8(data).ok()?;'),'decimal_tokens':line(reprs,'for tok in s.split_ascii_whitespace() {')},
 'witnesses':{'clean_unpadded_base64_546':{'filtered_length':len(padded),'decoded_length':len(out),'accepted':True},'filtered_base64':{'input_hex':b'!!QUJD??'.hex(),'retained':bmix_filtered.decode(),'decoded_hex':bmix_out.hex()},'filtered_odd_hex':{'input_hex':b'GG41 zz4'.hex(),'retained_after_odd_drop':hfiltered.decode(),'decoded_hex':hout.hex()},'decimal_valid_hex':ra_decimal(b'065 255\n0').hex(),'valid_utf8_nonascii_filtering':{'base64_input_utf8_hex':'QéUJD'.encode().hex(),'base64_retained':utf8_b64_kept.decode(),'base64_decoded_hex':utf8_b64_out.hex(),'hex_input_utf8_hex':'4é1'.encode().hex(),'hex_retained':utf8_hex_kept.decode(),'hex_decoded_hex':utf8_hex_out.hex(),'decimal_nbsp_rejected':True}}},
 'conclusions':[
 'PHP block rounding is selected by the mode callback: ECB and CBC return one; CFB, CTR, nCFB, OFB, nOFB, and STREAM return zero.',
 'Length 546 alone does not reject Base64 under pinned RA: a clean unpadded 546-symbol input is re-padded and decodes to 409 bytes.',
 'Pinned RA Base64 and hex decoders do not require the entire input to belong to their alphabets because they discard other bytes.',
 'Pinned RA decimal decoding is strict about UTF-8, whitespace tokenization, base-10 syntax, and u8 range, but imposes no fixed token width.',
 'Padding ciphertext to 552 or 560 changes downstream bytes and alignment, but length alone neither proves nor disproves codec acceptance.'
 ]}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();got=build()
 if a.generate:
  if a.generate.exists():raise SystemExit('refusing existing output')
  a.generate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
 else:assert got==json.loads((HERE/'audit.json').read_text())
 print(json.dumps({'identity':'ASTRA','status':'PASS','modes':got['libmcrypt']['modes'],'base64_546':got['ra']['witnesses']['clean_unpadded_base64_546']},sort_keys=True))
if __name__=='__main__':main()

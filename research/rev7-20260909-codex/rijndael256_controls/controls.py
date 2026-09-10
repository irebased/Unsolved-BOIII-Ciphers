#!/usr/bin/env python3
"""Read-only verifier and explicit synthetic Rijndael-256 control generator."""
from __future__ import annotations
from pathlib import Path
import argparse, ctypes, hashlib, json, os, platform, subprocess, tempfile

HERE=Path(__file__).resolve().parent
LEDGER=HERE/'controls.json'
IDENTITY='ASTRA'
BS=32
EXPECTED={
 'source/rijndael-256.c':'fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821',
 'source/rijndael.h':'57142416d7b11f6788a10ded626ad426aca430ed5bff34d60b87868feb3fe0e2',
 'source/COPYING.LIB':'ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532',
 'source/aes.js':'c8d6903ff7d6b090b2050f1c59dcf63ee08ac0c084caa11f9912bf5b20f90a8a',
 'source/libdefs.h':'556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e',
 'source/mcrypt_modules.h':'2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180',
}
KAT_KEY=bytes((j*2+10)%256 for j in range(32))
KAT_PT=bytes(range(32))
KAT_CT=bytes.fromhex('45af6c269326fd935edd24733cff74fc1aa358841a6cd80b79f242d983f8ff2e')

def sha(p:Path)->str: return hashlib.sha256(p.read_bytes()).hexdigest()
def hx(b:bytes)->str:return b.hex()
def xor(a:bytes,b:bytes)->bytes:return bytes(x^y for x,y in zip(a,b))

def verify_pins()->None:
    for rel,want in EXPECTED.items():
        got=sha(HERE/rel)
        if got!=want: raise RuntimeError(f'pinned input mismatch {rel}: {got} != {want}')

def hashes()->dict[str,str]:
    names=['controls.py','build_source.py','js_blocks.js','provenance.json','README.md',
           'source/rijndael-256.c','source/rijndael.h','source/COPYING.LIB',
           'source/libdefs.h','source/mcrypt_modules.h','source/aes.js']
    return {n:sha(HERE/n) for n in names}

class CPrimitive:
 def __init__(self,libpath:Path,key:bytes):
    self.lib=ctypes.CDLL(str(libpath))
    self.size=self.lib.rijndael_256_LTX__mcrypt_get_size; self.size.restype=ctypes.c_int; self.size.argtypes=[]
    self.bs=self.lib.rijndael_256_LTX__mcrypt_get_block_size; self.bs.restype=ctypes.c_int; self.bs.argtypes=[]
    self.setkey=self.lib.rijndael_256_LTX__mcrypt_set_key; self.setkey.restype=ctypes.c_int; self.setkey.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ubyte),ctypes.c_int]
    self.enc=self.lib.rijndael_256_LTX__mcrypt_encrypt; self.enc.restype=None; self.enc.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ubyte)]
    self.dec=self.lib.rijndael_256_LTX__mcrypt_decrypt; self.dec.restype=None; self.dec.argtypes=[ctypes.c_void_p,ctypes.POINTER(ctypes.c_ubyte)]
    self.ctx=ctypes.create_string_buffer(self.size())
    kb=(ctypes.c_ubyte*len(key)).from_buffer_copy(key)
    assert len(key) in (16,24,32) and self.bs()==BS
    assert self.setkey(self.ctx,kb,len(key))==0
 def crypt(self,data:bytes,decrypt=False)->bytes:
    assert len(data)==BS
    b=(ctypes.c_ubyte*BS).from_buffer_copy(data)
    (self.dec if decrypt else self.enc)(self.ctx,b)
    return bytes(b)

class JSPrimitive:
 def __init__(self,key:bytes): self.key=key
 def crypt(self,data:bytes,decrypt=False)->bytes:
    req={'operations':[{'op':'decrypt' if decrypt else 'encrypt','key_hex':hx(self.key),'data_hex':hx(data)}]}
    cp=subprocess.run(['node',str(HERE/'js_blocks.js')],input=json.dumps(req),text=True,capture_output=True,check=True)
    out=json.loads(cp.stdout); assert len(out)==1
    return bytes.fromhex(out[0])

def ecb(prim,plain:bytes,decrypt=False)->bytes:
    assert len(plain)%BS==0
    return b''.join(prim.crypt(plain[i:i+BS],decrypt) for i in range(0,len(plain),BS))

def cbc_encrypt(prim,plain:bytes,iv:bytes)->bytes:
    assert len(iv)==BS and len(plain)%BS==0
    out=[]; reg=iv
    for i in range(0,len(plain),BS):
        reg=prim.crypt(xor(plain[i:i+BS],reg)); out.append(reg)
    return b''.join(out)

def cbc_decrypt(prim,cipher:bytes,iv:bytes)->bytes:
    assert len(iv)==BS and len(cipher)%BS==0
    out=[]; reg=iv
    for i in range(0,len(cipher),BS):
        c=cipher[i:i+BS]; out.append(xor(prim.crypt(c,True),reg)); reg=c
    return b''.join(out)

def block_row(c,j,key,data)->dict:
    ce=c.crypt(data); je=j.crypt(data)
    assert ce==je and c.crypt(ce,True)==data and j.crypt(je,True)==data
    return {'key_bytes':len(key),'key_hex':hx(key),'plaintext_hex':hx(data),'ciphertext_hex':hx(ce),
            'c_js_encrypt_equal':True,'c_decrypt_roundtrip':True,'js_decrypt_roundtrip':True}

def regenerate(out:Path)->dict:
    if out.exists(): raise FileExistsError(f'refusing to overwrite {out}')
    verify_pins()
    from build_source import build
    with tempfile.TemporaryDirectory(prefix='rijndael256-controls-') as td:
      lib=Path(td)/'rijndael256.dylib'; cmd=build(lib)
      raw=ctypes.CDLL(str(lib))
      st=raw.rijndael_256_LTX__mcrypt_self_test; st.restype=ctypes.c_int; st.argtypes=[]
      gs=raw.rijndael_256_LTX__mcrypt_get_supported_key_sizes; gs.restype=ctypes.POINTER(ctypes.c_int); gs.argtypes=[ctypes.POINTER(ctypes.c_int)]
      n=ctypes.c_int(); arr=gs(ctypes.byref(n)); supported=[arr[i] for i in range(n.value)]
      gb=raw.rijndael_256_LTX__mcrypt_get_block_size; gb.restype=ctypes.c_int; gb.argtypes=[]
      assert st()==0 and gb()==32 and supported==[16,24,32]
      keys={str(n):b'Zombies'+b'\0'*(n-7) for n in (16,24,32)}
      blocks=[bytes(range(32)),bytes((17*i+31)&255 for i in range(32)),bytes([0])*32,bytes([255])*32]
      rows=[]
      for key in keys.values():
        c=CPrimitive(lib,key); j=JSPrimitive(key)
        for b in blocks: rows.append(block_row(c,j,key,b))
      kat=block_row(CPrimitive(lib,KAT_KEY),JSPrimitive(KAT_KEY),KAT_KEY,KAT_PT)
      assert bytes.fromhex(kat['ciphertext_hex'])==KAT_CT
      ecb_rows=[]; cbc_rows=[]
      ivs={'nul':bytes(32),'ascii_zero':b'0'*32,'nonuniform':bytes((29*i+7)&255 for i in range(32))}
      full_payload=b''.join(bytes((i*53+j*11+3)&255 for j in range(32)) for i in range(3))
      for key in keys.values():
        c=CPrimitive(lib,key); j=JSPrimitive(key)
        for block_count in (1,2,3):
          payload=full_payload[:block_count*BS]
          ec=ecb(c,payload); ej=ecb(j,payload)
          assert ec==ej and ecb(c,ec,True)==payload and ecb(j,ej,True)==payload
          ecb_rows.append({'key_bytes':len(key),'plaintext_hex':hx(payload),'ciphertext_hex':hx(ec),
            'plaintext_bytes':len(payload),'ciphertext_bytes':len(ec),'blocks':block_count,'c_js_equal':True,'both_roundtrip':True})
          for ivname,iv in ivs.items():
            cc=cbc_encrypt(c,payload,iv); cj=cbc_encrypt(j,payload,iv)
            assert cc==cj and cbc_decrypt(c,cc,iv)==payload and cbc_decrypt(j,cj,iv)==payload
            cbc_rows.append({'key_bytes':len(key),'iv_name':ivname,'iv_hex':hx(iv),'plaintext_hex':hx(payload),
             'ciphertext_hex':hx(cc),'plaintext_bytes':len(payload),'ciphertext_bytes':len(cc),
             'blocks':block_count,'c_js_equal':True,'both_roundtrip':True})
      key=keys['32']; c=CPrimitive(lib,key); j=JSPrimitive(key); iv=ivs['nonuniform']
      payload=full_payload
      padded=(b'header:synthetic Rijndael-256 framing control|'+bytes(range(39)))
      padded=padded+b'\0'*((-len(padded))%32); assert len(padded)==96 and padded.endswith(b'\0')
      ct=cbc_encrypt(c,padded,iv); assert ct==cbc_encrypt(j,padded,iv)
      external_prefix=iv+ct; trailer=bytes((255-i)&255 for i in range(32)); external_trailer=ct+trailer
      encrypted_header=b'H'*32+padded
      header_ct=cbc_encrypt(c,encrypted_header,iv)
      framing=[
       {'name':'external_iv_prefix','frame_hex':hx(external_prefix),'cipher_slice':[32,len(external_prefix)],'roundtrip_exact':cbc_decrypt(j,external_prefix[32:],external_prefix[:32])==padded},
       {'name':'external_trailer_stripped','frame_hex':hx(external_trailer),'cipher_slice':[0,len(ct)],'trailer_hex':hx(trailer),'roundtrip_exact':cbc_decrypt(j,external_trailer[:-32],iv)==padded},
       {'name':'leading_plaintext_header_is_encrypted','plaintext_hex':hx(encrypted_header),'ciphertext_hex':hx(header_ct),'roundtrip_exact':cbc_decrypt(j,header_ct,iv)==encrypted_header,'differs_from_external_prefix':header_ct!=external_prefix},
       {'name':'trailing_nuls_retained','plaintext_hex':hx(padded),'trailing_nul_count':len(padded)-len(padded.rstrip(b'\0')),'decrypted_hex':hx(cbc_decrypt(j,ct,iv)),'no_implicit_unpadding':cbc_decrypt(j,ct,iv)==padded},
      ]
      assert all(x.get('roundtrip_exact',x.get('no_implicit_unpadding')) for x in framing)
      ledger={'identity':IDENTITY,'target_evaluated':False,'scope':{'block_size_bits':256,'block_size_bytes':32,
       'key_sizes_bits':[128,192,256],'key_construction':'ASCII Zombies followed by NUL to 16/24/32 bytes'},
       'source_hashes':hashes(),'runtime':{'python':platform.python_version(),'node':subprocess.check_output(['node','--version'],text=True).strip(),
       'clang':subprocess.check_output(['clang','--version'],text=True).splitlines()[0],'build_command':cmd[:-1]+['<temporary-output>']},
       'c_api':{'embedded_self_test':True,'embedded_decrypt_strcmp_is_weak':True,'independent_full_32_byte_kat_decrypt':True,'block_size':32,'supported_key_sizes':[16,24,32]},
       'embedded_kat':kat,'block_vectors':rows,'ecb_vectors':ecb_rows,'cbc_vectors':cbc_rows,'framing_controls':framing,
       'counts':{'block_vectors':len(rows),'ecb_vectors':len(ecb_rows),'cbc_vectors':len(cbc_rows),'framing_controls':len(framing)}}
    out.parent.mkdir(parents=True,exist_ok=True)
    out.write_text(json.dumps(ledger,indent=2,sort_keys=True)+'\n')
    return ledger

def verify(path:Path=LEDGER)->dict:
    d=json.loads(path.read_text()); assert d['identity']==IDENTITY and d['target_evaluated'] is False
    verify_pins()
    for rel,h in d['source_hashes'].items(): assert sha(HERE/rel)==h,(rel,sha(HERE/rel),h)
    assert d['scope']['block_size_bytes']==32 and d['scope']['key_sizes_bits']==[128,192,256]
    assert d['c_api']=={'embedded_self_test':True,'embedded_decrypt_strcmp_is_weak':True,'independent_full_32_byte_kat_decrypt':True,'block_size':32,'supported_key_sizes':[16,24,32]}
    kat=d['embedded_kat']; assert kat['key_hex']==KAT_KEY.hex() and kat['plaintext_hex']==KAT_PT.hex() and kat['ciphertext_hex']==KAT_CT.hex()
    assert kat['key_bytes']==32 and kat['c_js_encrypt_equal'] and kat['c_decrypt_roundtrip'] and kat['js_decrypt_roundtrip']
    assert d['counts']=={'block_vectors':12,'ecb_vectors':9,'cbc_vectors':27,'framing_controls':4}
    expected_keys={n:(b'Zombies'+b'\0'*(n-7)).hex() for n in (16,24,32)}
    by_key={16:0,24:0,32:0}
    for r in d['block_vectors']:
        k=r['key_bytes']; by_key[k]+=1; assert r['key_hex']==expected_keys[k]
        assert len(bytes.fromhex(r['plaintext_hex']))==32 and len(bytes.fromhex(r['ciphertext_hex']))==32
        assert r['c_js_encrypt_equal'] and r['c_decrypt_roundtrip'] and r['js_decrypt_roundtrip']
    assert by_key=={16:4,24:4,32:4}
    ivs={'nul':bytes(32).hex(),'ascii_zero':(b'0'*32).hex(),'nonuniform':bytes((29*i+7)&255 for i in range(32)).hex()}
    assert {(r['key_bytes'],r['blocks']) for r in d['ecb_vectors']}=={(k,b) for k in (16,24,32) for b in (1,2,3)}
    assert {(r['key_bytes'],r['iv_name'],r['blocks']) for r in d['cbc_vectors']}=={(k,v,b) for k in (16,24,32) for v in ivs for b in (1,2,3)}
    for r in d['ecb_vectors']:
        assert r['plaintext_bytes']==r['ciphertext_bytes']==32*r['blocks']
        assert len(bytes.fromhex(r['plaintext_hex']))==len(bytes.fromhex(r['ciphertext_hex']))==32*r['blocks']
        assert r['c_js_equal'] and r['both_roundtrip']
    for r in d['cbc_vectors']:
        assert r['iv_hex']==ivs[r['iv_name']] and len(bytes.fromhex(r['iv_hex']))==32
        assert r['plaintext_bytes']==r['ciphertext_bytes']==32*r['blocks']
        assert len(bytes.fromhex(r['plaintext_hex']))==len(bytes.fromhex(r['ciphertext_hex']))==32*r['blocks']
        assert r['c_js_equal'] and r['both_roundtrip']
    fs={r['name']:r for r in d['framing_controls']}; assert set(fs)=={'external_iv_prefix','external_trailer_stripped','leading_plaintext_header_is_encrypted','trailing_nuls_retained'}
    assert len(bytes.fromhex(fs['external_iv_prefix']['frame_hex']))==128 and fs['external_iv_prefix']['cipher_slice']==[32,128]
    assert len(bytes.fromhex(fs['external_trailer_stripped']['frame_hex']))==128 and fs['external_trailer_stripped']['cipher_slice']==[0,96] and len(bytes.fromhex(fs['external_trailer_stripped']['trailer_hex']))==32
    assert len(bytes.fromhex(fs['leading_plaintext_header_is_encrypted']['plaintext_hex']))==128 and len(bytes.fromhex(fs['leading_plaintext_header_is_encrypted']['ciphertext_hex']))==128
    assert fs['leading_plaintext_header_is_encrypted']['differs_from_external_prefix']
    assert fs['trailing_nuls_retained']['trailing_nul_count']>0 and fs['trailing_nuls_retained']['decrypted_hex']==fs['trailing_nuls_retained']['plaintext_hex']
    assert all(r.get('roundtrip_exact',r.get('no_implicit_unpadding')) for r in fs.values())
    return d

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--regenerate',type=Path)
    args=ap.parse_args()
    d=regenerate(args.regenerate) if args.regenerate else verify()
    print(json.dumps({'identity':IDENTITY,'status':'passed','ledger':str(args.regenerate or LEDGER),'counts':d['counts']},sort_keys=True))
if __name__=='__main__': main()

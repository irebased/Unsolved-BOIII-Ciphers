#!/usr/bin/env python3
from __future__ import annotations
import ctypes, hashlib, json, platform, subprocess, sys
from pathlib import Path
import Crypto
from Crypto.Cipher import AES, Blowfish, DES
HERE=Path(__file__).resolve().parent
SOURCE=HERE/"ofb.c"; BUILD=HERE/"build"; LIB=BUILD/"libofb8.so"; RESULTS=HERE/"results.json"
SOURCE_SHA256="aec1699eecb37e4791e704d074e88fbe210f62dd75e6c1face8a5fc302ee926d"
PIN="3bd338e2f808e985f5b229a7642d48c26615993f"
class OFBBuffer(ctypes.Structure):
    _fields_=[("s_register",ctypes.c_void_p),("enc_s_register",ctypes.c_void_p),("blocksize",ctypes.c_int)]
def sha256(data): return hashlib.sha256(data).hexdigest()
def specs():
    return {"aes128":(AES,b"Zombies".ljust(16,b"\0")),"blowfish":(Blowfish,b"Zombies"),"des":(DES,b"Zombies".ljust(8,b"\0"))}
def compile_source():
    assert sha256(SOURCE.read_bytes())==SOURCE_SHA256
    BUILD.mkdir(exist_ok=True)
    command=["cc","-shared","-fPIC","-O2","-I",str(HERE),"-o",str(LIB),str(SOURCE)]
    subprocess.run(command,check=True,timeout=60,capture_output=True)
    version=subprocess.run(["cc","--version"],check=True,timeout=10,capture_output=True,text=True).stdout.splitlines()[0]
    return command,version
def actual_ofb8(data,module,key,iv,decrypt):
    lib=ctypes.CDLL(str(LIB)); init=lib.ofb_LTX__init_mcrypt
    crypt=lib.ofb_LTX__mdecrypt if decrypt else lib.ofb_LTX__mcrypt
    end=lib.ofb_LTX__end_mcrypt
    callback_type=ctypes.CFUNCTYPE(None,ctypes.c_void_p,ctypes.c_void_p)
    init.argtypes=[ctypes.POINTER(OFBBuffer),ctypes.c_void_p,ctypes.c_int,ctypes.c_void_p,ctypes.c_int]; init.restype=ctypes.c_int
    crypt.argtypes=[ctypes.POINTER(OFBBuffer),ctypes.c_void_p,ctypes.c_int,ctypes.c_int,ctypes.c_void_p,callback_type,callback_type]; crypt.restype=ctypes.c_int
    end.argtypes=[ctypes.POINTER(OFBBuffer)]; end.restype=None
    ecb=module.new(key,module.MODE_ECB); block_size=module.block_size
    @callback_type
    def encrypt_block(_key_pointer,block_pointer):
        ctypes.memmove(block_pointer,ecb.encrypt(ctypes.string_at(block_pointer,block_size)),block_size)
    state=OFBBuffer(); iv_buffer=(ctypes.c_ubyte*block_size).from_buffer_copy(iv)
    payload=bytearray(data); payload_buffer=(ctypes.c_ubyte*len(payload)).from_buffer(payload)
    assert init(ctypes.byref(state),None,0,iv_buffer,block_size)==0
    try:
        assert crypt(ctypes.byref(state),payload_buffer,len(payload),block_size,None,encrypt_block,encrypt_block)==0
    finally: end(ctypes.byref(state))
    return bytes(payload)
def independent_ofb8(data,module,key,iv):
    ecb=module.new(key,module.MODE_ECB); register=bytes(iv); output=bytearray()
    for value in data:
        k=ecb.encrypt(register)[0]; output.append(value^k); register=register[1:]+bytes([k])
    return bytes(output)
def main():
    command,compiler_version=compile_source()
    fixtures={"all_256_bytes":bytes(range(256)),"literal_ascii":b"OFB8 source control: Zombies / ASCII 0 / NUL IV / 0123456789ABCDEF\r\n"}
    rows=[]
    for cipher_name,(module,key) in specs().items():
        for iv_name,iv_byte in (("ascii_zero",b"0"),("nul",b"\0")):
            iv=iv_byte*module.block_size
            for fixture_name,plaintext in fixtures.items():
                actual=actual_ofb8(plaintext,module,key,iv,False); independent=independent_ofb8(plaintext,module,key,iv)
                assert actual==independent
                assert actual_ofb8(actual,module,key,iv,True)==plaintext
                full_block=module.new(key,module.MODE_OFB,iv=iv).encrypt(plaintext)
                assert actual[:1]==full_block[:1]
                assert len(actual)<2 or actual[1:]!=full_block[1:]
                rows.append({"cipher":cipher_name,"fixture":fixture_name,"key_hex":key.hex(),"iv_kind":iv_name,"iv_hex":iv.hex(),"plaintext_hex":plaintext.hex(),"plaintext_sha256":sha256(plaintext),"ciphertext_hex":actual.hex(),"ciphertext_sha256":sha256(actual),"actual_c_matches_independent_recurrence":True,"actual_c_decrypt_roundtrip":True,"full_block_ofb_matches_first_byte":True,"full_block_ofb_differs_after_first_byte":True})
    result={"identity":"ASTRA","target_evaluated":False,"scope":{"row_count":len(rows),"ciphers":list(specs()),"iv_kinds":["ascii_zero","nul"],"fixtures":list(fixtures),"rev7_read":False},"source":{"repository":"https://github.com/Distrotech/libmcrypt","commit":PIN,"commit_context":"2013-01-27 import of libmcrypt 2.5.8","ofb_url":f"https://github.com/Distrotech/libmcrypt/blob/{PIN}/modules/modes/ofb.c","ofb_sha256":SOURCE_SHA256,"nofb_url":f"https://github.com/Distrotech/libmcrypt/blob/{PIN}/modules/modes/nofb.c","nofb_sha256":"d0df49d847478c83fa9a1cbf21686623e390a80fbbd558d2640aa4e4d8c246e9","compiled_source_unmodified":True},"convention":{"ofb":"For each byte: E(register)[0] is XORed with data; shift register left one byte and append that keystream byte.","nofb_distinction":"nOFB consumes successive bytes of E(register), replacing the entire register with E(register) at block boundaries.","full_block_ofb_distinction":"Standard full-block OFB agrees at byte zero, then generally differs because it retains all bytes of E(register)."},"environment":{"python":sys.version,"platform":platform.platform(),"pycryptodome":Crypto.__version__,"compiler_version":compiler_version,"compile_command":command,"ctypes_abi":{"pointer_size":ctypes.sizeof(ctypes.c_void_p),"ofb_buffer_size":ctypes.sizeof(OFBBuffer)}},"rows":rows}
    RESULTS.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n",encoding="utf-8")
    print(json.dumps({"rows":len(rows),"results_sha256":sha256(RESULTS.read_bytes()),"all_actual_c_match_independent":all(r["actual_c_matches_independent_recurrence"] for r in rows),"all_roundtrip":all(r["actual_c_decrypt_roundtrip"] for r in rows),"all_full_block_first_only":all(r["full_block_ofb_matches_first_byte"] and r["full_block_ofb_differs_after_first_byte"] for r in rows)},sort_keys=True))
if __name__=="__main__": main()

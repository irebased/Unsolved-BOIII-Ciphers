#!/usr/bin/env python3
from __future__ import annotations
import base64,ctypes,hashlib,json,platform,re,subprocess,sys
from pathlib import Path
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent
REPO=HERE.parents[3]
KEY=b"Zombies";DES_KEY=KEY+b"\0";IV8=b"0"*8;IV16=b"0"*16
IDENTITY="ASTRA"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
class TwofishSource:
 block=16
 def __init__(self,key=KEY,declared=None):
  self.lib=ctypes.CDLL(str(HERE/"source_build/libtwofish.so"));p="twofish_LTX_"
  gs=getattr(self.lib,p+"_mcrypt_get_size");gs.restype=ctypes.c_int
  self.sk=getattr(self.lib,p+"_mcrypt_set_key");self.en=getattr(self.lib,p+"_mcrypt_encrypt");self.de=getattr(self.lib,p+"_mcrypt_decrypt");self.st=getattr(self.lib,p+"_mcrypt_self_test")
  self.sk.argtypes=[ctypes.c_void_p,ctypes.c_void_p,ctypes.c_uint];self.sk.restype=ctypes.c_int
  self.en.argtypes=self.de.argtypes=[ctypes.c_void_p,ctypes.c_void_p];self.st.restype=ctypes.c_int
  self.context_bytes=gs();self.ctx=ctypes.create_string_buffer(self.context_bytes)
  selected=declared if declared is not None else next(x for x in (16,24,32) if len(key)<=x);memory=key+b"\0"*(32-len(key));self.kbuf=ctypes.create_string_buffer(memory,32);self.selected_key_length=selected
  assert self.sk(self.ctx,self.kbuf,selected)==0
 def _block(self,value,fn):
  assert len(value)==16;b=ctypes.create_string_buffer(value,16);fn(self.ctx,b);return b.raw
 def encrypt(self,value):return self._block(value,self.en)
 def decrypt(self,value):return self._block(value,self.de)
class DESECB:
 block=8
 def __init__(self):self.c=DES.new(DES_KEY,DES.MODE_ECB)
 def encrypt(self,value):return self.c.encrypt(value)
def cfb8(data,ecb,iv,decrypt):
 reg=iv;out=bytearray()
 for value in data:
  transformed=value^ecb.encrypt(reg)[0];ct=value if decrypt else transformed
  out.append(transformed);reg=reg[1:]+bytes([ct])
 return bytes(out)
def main():
 assert sha(HERE/"source/twofish.c")=="20e72e38b445868fe71a0274e0b9bd658c6f30cb1ad731eb3364d82e319af598"
 assert sha(HERE/"source/twofish.h")=="c233e43572b5837f9eddc3b6c3f495d91eaa858ade2f9eaf3bc2f959fe721a6b"
 tf=TwofishSource();assert tf.st()==0
 kat_key=bytes.fromhex("9f589f5cf6122c32b6bfec2f2ae8c35a");kat=TwofishSource(kat_key);kat_plain=bytes.fromhex("d491db16e7b1c39e86cb086b789f5419");kat_ct=kat.encrypt(kat_plain)
 assert kat.selected_key_length==16 and kat_ct.hex()=="019f9809de1711858faac3a3ba20fbc3" and kat.decrypt(kat_ct)==kat_plain
 records=json.loads((REPO/"lavender/src/data/ciphers/revelations.json").read_text());rec=next(x for x in records if x["id"]=="rev9")
 outer=base64.b64decode(re.sub(r"\s+","",rec["ciphertext"]));des=DESECB();step1=cfb8(outer,des,IV8,True)
 assert step1.decode("ascii",errors="strict");tokens=re.findall(rb"[0-9]{3}",step1);assert len(tokens)==202
 decimal_decoded=bytes(int(x) for x in tokens);reversed_base64=decimal_decoded[::-1].strip();twofish_input=base64.b64decode(reversed_base64+b"===")
 assert base64.b64encode(twofish_input)==reversed_base64
 final=cfb8(twofish_input,tf,IV16,True);text=final.decode("utf-8",errors="strict")
 assert text.strip()==rec["plaintext"] and final.count(bytes.fromhex("e280a6"))==1
 ellipsis_at=final.index(bytes.fromhex("e280a6"));assert text.index("…")==134
 assert cfb8(final,TwofishSource(),IV16,False)==twofish_input
 assert cfb8(step1,DESECB(),IV8,False)==outer
 full=bytes(range(256))+b" Twofish source CFB8"
 full_ct=cfb8(full,TwofishSource(),IV16,False);assert cfb8(full_ct,TwofishSource(),IV16,True)==full
 result={"identity":IDENTITY,"target_evaluated":False,"rev7_file_read":False,"scope":"Pinned-source Twofish controls and complete solved Rev9 replay only","source":{"repository":"https://github.com/Distrotech/libmcrypt","commit":"3bd338e2f808e985f5b229a7642d48c26615993f","paths":{"twofish.c":"modules/algorithms/twofish.c","twofish.h":"modules/algorithms/twofish.h"},"sha256":{"twofish.c":sha(HERE/"source/twofish.c"),"twofish.h":sha(HERE/"source/twofish.h"),"COPYING.LIB":sha(HERE/"source/COPYING.LIB")},"compiled_source_unmodified":True},"twofish_key_convention":{"input_key_hex":KEY.hex(),"input_bytes":7,"supported_lengths":[16,24,32],"selected_length":16,"allocated_zeroed_backing_bytes":32,"back":"Zombies followed by 25 NUL bytes","source_set_key_reads":16,"note":"Twofish uses selected 128-bit key material; the maximum-size backing buffer reproduces libmcrypt allocation."},"des_key_convention":{"key_hex":DES_KEY.hex(),"input_password_bytes":7,"selected_bytes":8,"iv_hex":IV8.hex(),"mode":"CFB8"},"source_embedded_kat":{"self_test_return":0,"key_bytes":16,"key_hex":kat_key.hex(),"set_key_length":16,"plaintext_hex":kat_plain.hex(),"ciphertext_hex":kat_ct.hex(),"expected_ciphertext_hex":"019f9809de1711858faac3a3ba20fbc3","decrypt_roundtrip":True},"full_byte_twofish_cfb8":{"key_hex":KEY.hex(),"iv_hex":IV16.hex(),"plaintext_bytes":len(full),"plaintext_sha256":hashlib.sha256(full).hexdigest(),"ciphertext_hex":full_ct.hex(),"ciphertext_sha256":hashlib.sha256(full_ct).hexdigest(),"roundtrip":True},"rev9_full_chain":{"input_source":"lavender/src/data/ciphers/revelations.json rev9","outer_base64_decoded_bytes":len(outer),"des_output_bytes":len(step1),"decimal_token_count":len(tokens),"decimal_decoded_bytes":len(decimal_decoded),"operation":"decode three-digit decimals, reverse the resulting base64 byte string, strip outer whitespace, base64 decode","twofish_input_bytes":len(twofish_input),"final_bytes":len(final),"final_hex":final.hex(),"final_text":text,"outputs_hex":{"outer":outer.hex(),"des_output":step1.hex(),"decimal_decoded":decimal_decoded.hex(),"reversed_base64":reversed_base64.hex(),"twofish_input":twofish_input.hex(),"final":final.hex()},"hashes":{"outer":hashlib.sha256(outer).hexdigest(),"des_output":hashlib.sha256(step1).hexdigest(),"decimal_decoded":hashlib.sha256(decimal_decoded).hexdigest(),"reversed_base64":hashlib.sha256(reversed_base64).hexdigest(),"twofish_input":hashlib.sha256(twofish_input).hexdigest(),"final":hashlib.sha256(final).hexdigest()},"strict_utf8":True,"complete_record_match_after_outer_whitespace_strip":True,"raw_ellipsis":{"utf8_hex":"e280a6","byte_offset":ellipsis_at,"character_index":134,"count":1,"present_in_decrypted_bytes":True},"exact_reencryptions":{"twofish_cfb8":True,"des_cfb8":True}},"build":{"command":"clang -shared -fPIC -O2 -Isource_build -Isource source/twofish.c -o source_build/libtwofish.so","compiler":subprocess.check_output(["clang","--version"],text=True).splitlines()[0],"python":sys.version,"platform":platform.platform(),"library_sha256":sha(HERE/"source_build/libtwofish.so"),"minimal_header_sha256":{"libdefs.h":sha(HERE/"source_build/libdefs.h"),"mcrypt_modules.h":sha(HERE/"source_build/mcrypt_modules.h")}},"assertions":{"all_passed":True,"source_embedded_kat":True,"full_byte_cfb8_roundtrip":True,"rev9_complete_strict_utf8_match":True,"rev9_both_cipher_layers_reencrypt_exactly":True,"ellipsis_is_original_decrypted_utf8":True},"limitations":"Solved control only. It establishes the tested source/key/mode/representation path and the original ellipsis bytes for Rev9; it does not evaluate Rev7 or make the four-sequence Rev7 endpoint exhaustive for other punctuation."}
 out=HERE/"controls.json"
 if out.exists():raise SystemExit("refusing existing controls.json")
 out.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n");print(json.dumps({"identity":IDENTITY,"controls_sha256":sha(out),"ellipsis":result["rev9_full_chain"]["raw_ellipsis"],"hashes":result["rev9_full_chain"]["hashes"]},indent=2))
if __name__=="__main__":main()

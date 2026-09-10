#!/usr/bin/env python3
from __future__ import annotations
import hashlib,json
from pathlib import Path
IDENTITY="ASTRA"; HERE=Path(__file__).resolve().parent; HEX=HERE.parent; REPO=HERE.parents[3]
REV7=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
DEPENDENCIES={
"native_text5/README.md":"092c8bd4d290f01ee5d4b76fca61478f8b96d36b2b7db32bbc63523db06a9db5","native_text5/controls.py":"fb1194f4e577a7e5b23e66693c87d212ac6554df4d7e1299dada37ec69c54859","native_text5/controls.json":"5bc6fda80e29a9d723cc4a72436406dc0275b456635a484a2d394a6553e77891","native_text5/endpoint5.py":"64516c9730f7d4381d166888b19eda612873e9edee3a2f02f8a1091e50d2529e","native_text5/native_text5.cpp":"81bd9902f3f5fb0585214c2c93117523426cdc61edb524334d64412d4a5d724f","native_text5/native_text5":"3b84a08161e1dde80ad5b12613e7cd6e6a0905411e4f7e9098cd5f55792fbd0d","native_text5/source/rc2.c":"37c9398507cea1685255da9550f5a3a55b529b66e1bbc9a35e1996fecae7dc19","native_text5/source/rc2.h":"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855","native_text5/source/loki97.c":"4e18d184ec55776edab065cee35ac44a9269b4160d7d35ad4ea277da55ae3308","native_text5/source/COPYING.LIB":"ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532","native_text5/source_build/libdefs.h":"556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e","native_text5/source_build/mcrypt_modules.h":"2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180","native_text5/source_build/rc2.o":"022a0517d79e7dfc9566ca3cf04462a7ffb62aaf9f2d4d0d8edb2ca0a2803b4e","native_text5/source_build/loki97.o":"2c417e8b2b6f70e2f175d58dbb8b011be234b2fbc4c8c838960817fec13ddc06","native_text5/source_build/librc2.so":"83dd446b5453e47252e8803d1143b4d235d39b1cba6efe557a94b273d318b2d6","native_text5/source_build/libloki97.so":"297b73e3926d82cc52c1023c9bba53a3d1102470f3633ea2c8ed6f243347c175","native_siblings/LIBRARY_KEY_MEMORY.md":"ece2567f8c53ea383fa8a9662843c822c9f1ba98a1ce7acf53b3a6638e545e3e","prototype.py":"416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b","rev7_mdx":"085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"}
TEXT_SHA256="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def paths():
 d={k:HEX/k for k in DEPENDENCIES if k!="rev7_mdx"};d["rev7_mdx"]=REV7;return d
def validate():
 got={k:sha(p) for k,p in paths().items()};assert got==DEPENDENCIES
 c=json.loads((HEX/"native_text5/controls.json").read_text());assert c["identity"]==IDENTITY and c["target_evaluated"] is False and c["rev7_file_read"] is False
 assert c["assertions"]["all_passed"] and c["assertions"]["all_byte_cfb8_native_python_roundtrip"] and c["assertions"]["seeded_all24_exact"]
 rows={x["cipher"]:x for x in c["full_byte_cfb8"]};assert rows["rc2"]["key_convention"]=="raw7 source";assert rows["loki97"]["key_convention"]=="selected16 in zeroed32 source backing"
 return {"identity":IDENTITY,"target_evaluated":False,"rev7_handling":"MDX bytes hashed only; ciphertext not extracted, parsed, oriented, or evaluated","dependency_hashes":got,"canonical_text_sha256_expected":TEXT_SHA256}
if __name__=="__main__":print(json.dumps(validate(),indent=2,sort_keys=True))

#!/usr/bin/env python3
"""Synthetic controls for the Rijndael-256 native text-five bijection engine."""
from pathlib import Path
import argparse,hashlib,importlib.util,itertools,json,math,random,subprocess,tempfile,sys
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];LEDGER=HERE/'controls.json';IDENTITY='ASTRA';KEY=b'Zombies'+b'\0'*9;IV=b'0'*32
PINS={'hex_cfb/native_text5/native_text5.cpp':'81bd9902f3f5fb0585214c2c93117523426cdc61edb524334d64412d4a5d724f','hex_cfb/native_text5/endpoint5.py':'64516c9730f7d4381d166888b19eda612873e9edee3a2f02f8a1091e50d2529e','hex_cfb/prototype.py':'416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b','rijndael256_controls/build_source.py':'d32cac36412340865b2fd28d8b6437f9c2f508cd229c58881c3285d3e3039961','rijndael256_controls/controls.json':'2e164a7b6091f5a1c76a1863cd45ddb2c919597350ff20e3ce52c131ed9c804c','rijndael256_controls/controls.py':'c35dde4e66b4a5633c0b0d14086bb1011ae313448d4e460ef405dd53d29f6cb2','rijndael256_controls/js_blocks.js':'ceefc2c2c15b7cb60b07ba14539c1ec99bda682409a728bc2fa04ee4df292f52','rijndael256_controls/source/aes.js':'c8d6903ff7d6b090b2050f1c59dcf63ee08ac0c084caa11f9912bf5b20f90a8a','rijndael256_controls/source/COPYING.LIB':'ca0061fc1381a3ab242310e4b3f56389f28e3d460eb2fd822ed7a21c6f030532','rijndael256_controls/source/rijndael-256.c':'fa16b72832a4cda8fd9909d88c8a7b779d352bbfb13acf76d57391dfe9219821','rijndael256_controls/source/rijndael.h':'57142416d7b11f6788a10ded626ad426aca430ed5bff34d60b87868feb3fe0e2','rijndael256_controls/source/libdefs.h':'556ec4fcebae614cd90d05a2fead50d9355ff39f65b44c8f4044c7f209074c6e','rijndael256_controls/source/mcrypt_modules.h':'2fefe3d60795fb19e7a7be1c4cec18a97c069e2471ae61c951706020dcb6c180','rijndael256_cfb/runtime.py':'115ea9b644a8fa3f62d2ea17afb85434966cea5c76ebdeb3582697d2d176bae0','rijndael256_cfb/js_cfb8.js':'024eecdebb48bb17c925caf42fb47e90eb8371479ff315cceee1d936edfa9c0b','rijndael256_cfb/controls.json':'511aad6d309c05b16a8b2281f69bc748f180af499988016659554324b7f135d3'}
FIELDS=('nodes','rejected_plaintext','complete','maximum_depth','aborted_at_node_limit','rejected_completion_weight','terminal_completion_weight','rejected_unterminated_endpoint')
def hb(x):return hashlib.sha256(x).hexdigest()
def sha(p):return hb(Path(p).read_bytes())
def load(name,path):
 spec=importlib.util.spec_from_file_location(name,path);m=importlib.util.module_from_spec(spec);sys.modules[name]=m;spec.loader.exec_module(m);return m
def verify_pins():
 for rel,want in PINS.items():assert sha(ROOT/'research/rev7-20260909-codex'/rel)==want,(rel,sha(ROOT/'research/rev7-20260909-codex'/rel),want)
def build(temp):
 primitive=ROOT/'research/rev7-20260909-codex/rijndael256_controls';builder=load('astra_r256_builder',primitive/'build_source.py');dylib=temp/'rijndael256.dylib';bcmd=builder.build(dylib);obj=temp/'rijndael.o';binary=temp/'native';cc=['clang','-std=c99','-O2','-I',str(primitive/'source'),'-c',str(primitive/'source/rijndael-256.c'),'-o',str(obj)];cxx=['clang++','-std=c++17','-O3',str(HERE/'native.cpp'),str(obj),'-o',str(binary)];subprocess.run(cc,check=True,capture_output=True);subprocess.run(cxx,check=True,capture_output=True);return dylib,binary,{'dylib_command':bcmd,'object_command':cc,'native_command':cxx}
def cfb(data,backend,decrypt):
 reg=IV;out=bytearray()
 for value in data:
  transformed=value^backend.encrypt_block(reg)[0];cipher=value if decrypt else transformed;out.append(transformed);reg=reg[1:]+bytes((cipher,))
 return bytes(out)
def native(binary,cap,display,seed=None):
 cmd=[str(binary),str(cap),display,'-' if seed is None else ','.join(f'{k}:{v}' for k,v in sorted(seed.items()))];return json.loads(subprocess.check_output(cmd,text=True))
def pyrow(core,endpoint,backend,cap,display,seed=None):
 class E:
  def encrypt(self,b):return backend.encrypt_block(b)
 sols,stats=core.backtrack(display,E(),IV,endpoint.transition,node_limit=cap,seed_mapping=seed);return {**{k:getattr(stats,k) for k in FIELDS},'solutions':[{'mapping':list(x['mapping']),'plaintext_hex':x['plaintext'].hex()} for x in sols]}
def compare(core,endpoint,backend,binary,cap,display,seed=None):
 py=pyrow(core,endpoint,backend,cap,display,seed);n=native(binary,cap,display,seed);assert all(py[k]==n[k] for k in FIELDS) and py['solutions']==n['solutions'];expected=math.factorial(16-len(seed or {}));assert n['expected_completion_weight']==expected and n['certificate_weight']==n['rejected_completion_weight']+n['terminal_completion_weight'];
 if not n['aborted_at_node_limit']:assert n['certificate_weight']==expected
 return {'node_limit':cap,'stats':{k:n[k] for k in FIELDS},'solutions':n['solutions'],'expected_completion_weight':expected,'certificate_weight':n['certificate_weight'],'certificate_complete':n['certificate_weight']==expected,'native_python_exact':True}
def naive(core,endpoint,backend,display,seed):
 unknown=sorted(set(range(16))-set(seed));remaining=sorted(set(range(16))-set(seed.values()));out=[]
 for perm in itertools.permutations(remaining):
  m=[None]*16
  for k,v in seed.items():m[k]=v
  for k,v in zip(unknown,perm):m[k]=v
  ct=bytes((m[core.HEX.index(display[i])]<<4)|m[core.HEX.index(display[i+1])] for i in range(0,len(display),2));pt=cfb(ct,backend,True)
  if endpoint.accepts(pt):out.append({'mapping':m,'plaintext_hex':pt.hex()})
 return out
def js(path,jobs):return json.loads(subprocess.run(['node',str(path)],input=json.dumps({'jobs':jobs}).encode(),capture_output=True,check=True).stdout)
def generate():
 verify_pins();core=load('astra_r256_hex_core',ROOT/'research/rev7-20260909-codex/hex_cfb/prototype.py');endpoint=load('astra_r256_endpoint',ROOT/'research/rev7-20260909-codex/hex_cfb/native_text5/endpoint5.py');rt=load('astra_r256_runtime',ROOT/'research/rev7-20260909-codex/rijndael256_cfb/runtime.py')
 with tempfile.TemporaryDirectory(prefix='astra-r256-native-') as td:
  temp=Path(td);dylib,binary,commands=build(temp);backend=rt.Rijndael256Backend('rijndael256_key16',dylib);assert backend.block_size==32 and backend.key==KEY
  blocks=[bytes(range(32)),bytes(reversed(range(32))),hashlib.sha256(b'ASTRA R256 block 0').digest(),hashlib.sha256(b'ASTRA R256 block 1').digest()]
  ops=[{'op':'encrypt','key_hex':KEY.hex(),'data_hex':b.hex()} for b in blocks];jsblocks=json.loads(subprocess.run(['node',str(ROOT/'research/rev7-20260909-codex/rijndael256_controls/js_blocks.js')],input=json.dumps({'operations':ops}).encode(),capture_output=True,check=True).stdout);primitive=[]
  for b,j in zip(blocks,jsblocks):
   got=backend.encrypt_block(b);assert got.hex()==j;primitive.append({'input_hex':b.hex(),'c_output_hex':got.hex(),'untouched_js_output_hex':j,'independent_equal':True})
  raw=bytes(range(256))+b' R256 ALL BYTE CFB8';pyct=cfb(raw,backend,False);native_ct=bytes.fromhex(subprocess.check_output([str(binary),'--cfb-encrypt',raw.hex()],text=True).strip());assert native_ct==pyct and bytes.fromhex(subprocess.check_output([str(binary),'--cfb-decrypt',pyct.hex()],text=True).strip())==raw and cfb(pyct,backend,True)==raw
  jsrow=js(ROOT/'research/rev7-20260909-codex/rijndael256_cfb/js_cfb8.js',[{'key_hex':KEY.hex(),'iv_hex':IV.hex(),'data_hex':raw.hex(),'operation':'roundtrip'}])[0];assert jsrow['ciphertext_hex']==pyct.hex() and jsrow['decrypted_hex']==raw.hex()
  allbyte={'plaintext_hex':raw.hex(),'plaintext_sha256':hb(raw),'ciphertext_hex':pyct.hex(),'ciphertext_sha256':hb(pyct),'native_equals_python_same_c_recurrence':True,'native_decrypt_roundtrip':True,'python_same_c_decrypt_roundtrip':True,'untouched_js_cfb8_independent_equal':True,'untouched_js_roundtrip':True}
  rng=random.Random(20260910);mapping=list(range(16));rng.shuffle(mapping);mixed=(b'R256 ASCII\tLINE\r\n'+bytes.fromhex('e28093e28094e28098e28099e280a6')+b' END ')*3;ct=cfb(mixed,backend,False);display=core.display_encode(ct,mapping);assert len(set(display))==16;unknown=sorted(set(core.HEX.index(x) for x in display))[-4:];seed={i:v for i,v in enumerate(mapping) if i not in unknown};seeded=compare(core,endpoint,backend,binary,100000,display,seed);nv=naive(core,endpoint,backend,display,seed);assert seeded['certificate_complete'] and seeded['expected_completion_weight']==24 and seeded['solutions']==nv and any(x['mapping']==mapping and x['plaintext_hex']==mixed.hex() for x in nv);seeded.update({'unknown_symbols':unknown,'naive_permutations':24,'naive_exact':True,'plant_mapping_and_plaintext_recovered':True})
  full=(b'R256 FULL SIXTEEN SYMBOL PREFIX CONTROL WITH STRICT ASCII ENDPOINT. '*10)[:546];assert len(full)==546;fd=core.display_encode(cfb(full,backend,False),mapping);assert len(set(fd))==16;prefixes=[]
  for cap in (250000,1000000):
   row=compare(core,endpoint,backend,binary,cap,fd);assert row['stats']['aborted_at_node_limit'] and not row['certificate_complete'];prefixes.append(row)
  normalized={k:[x.replace(str(temp.resolve()),'<temporary-build>').replace(str(temp),'<temporary-build>').replace(str(ROOT),'<worktree>') for x in v] if isinstance(v,list) else v for k,v in commands.items()}
 return {'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'crypto_evaluated':True,'scope':{'cipher':'Rijndael-256 block primitive','block_size':32,'key':'Zombies+9NUL (16 bytes only)','iv':'ASCII 0 repeated 32 bytes','mapping':'global bijection of 16 displayed hex symbols to nibble values','endpoint':'TAB/LF/CR, ASCII32..126, and UTF-8 E280 93/94/98/99/A6 with terminal state0','full16_caps':[250000,1000000],'cap_runs':'fresh roots; nonadditive'},'primitive_independence':primitive,'all_256_byte_cfb8':allbyte,'seeded_four_unknown':seeded,'full16_fresh_prefixes':prefixes,'provenance':{'c_source':'Distrotech/libmcrypt commit 3bd338e2f808e985f5b229a7642d48c26615993f','independent_js':'untouched JavaScrypt aes.js','python_parity':'accepted Rijndael256Backend uses the same pinned C primitive; it independently exercises Python search/CFB control flow but is not a second primitive','parent_native_diff_sha256':sha(HERE/'PARENT_DIFF.patch'),'pins':PINS,'build_commands':normalized},'source_sha256':sha(Path(__file__)),'native_source_sha256':sha(HERE/'native.cpp'),'assertions':{'all_source_pins_verified_before_build':True,'four_c_blocks_equal_independent_js':True,'all_byte_native_python_and_js_cfb8_exact':True,'seeded_exact24_native_python_naive':True,'full16_250k_then_1m_native_python_prefixes_exact':True,'caps_not_completeness_claims':True,'no_target':True}}
def verify_saved(x):
 assert x['identity']==IDENTITY and x['target_evaluated'] is False and x['rev7_read'] is False and x['source_sha256']==sha(Path(__file__)) and x['native_source_sha256']==sha(HERE/'native.cpp') and x['provenance']['parent_native_diff_sha256']==sha(HERE/'PARENT_DIFF.patch') and x['provenance']['pins']==PINS and all(x['assertions'].values());assert len(x['primitive_independence'])==4 and x['seeded_four_unknown']['expected_completion_weight']==24 and x['seeded_four_unknown']['certificate_complete'];assert [r['node_limit'] for r in x['full16_fresh_prefixes']]==[250000,1000000] and all(r['stats']['aborted_at_node_limit'] and not r['certificate_complete'] for r in x['full16_fresh_prefixes'])
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();verify_pins()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  out=generate();a.regenerate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:
  x=json.loads(LEDGER.read_text());verify_saved(x);print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(LEDGER),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

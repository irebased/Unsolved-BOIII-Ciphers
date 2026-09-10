#!/usr/bin/env python3
"""ASTRA source-backed XXTEA serialization length audit; no Rev7 evaluation."""
from __future__ import annotations
import argparse, ast, ctypes, hashlib, json, platform, re, subprocess, tempfile
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCE=HERE/'source'/'xxtea.c'
APP=HERE/'source'/'app.js'
WRAPPER=HERE/'source'/'mcrypt_wrapper.c'
LEDGER=HERE/'controls.json'
PINS={
 'xxtea.c':'1eba7c9a7da40a1030842195a4c5cdafebca6106000b167c00e8c82cce3efb2d',
 'app.js':'c8aa498de890039bab86af507e49b89d382c67594f463691deda427b04059113',
 'mcrypt_wrapper.c':'ae134769f33ea4f6f1e42599706d7050670ad33669ce9c8c3fc22d1496f38982',
 'fable_xxtea.js':'4f3264f7c9d7715e0c21c7eef615bf053ee0410a989e7b9ae2f49f28dd8bfeea',
 'fable_scan_xxtea.js':'7b86882d277601966533e79f52f745a7aca047d72f7db9059155bc296eb14067',
 'fable_results_xxtea.json':'f53430c0cd6e72abe2a0904a6fbe191fd871e863aa8a589fc2f47a5b7160940f',
 'fable_survivors_xxtea.json':'4f53cda18c2baa0c0354bb5f9a3ecbe5ed12ab4d8e11ba873c2f11161202b945',
}
COMMIT='7c43c6ae65f49bd7504494d9ca3c55ce2e2496b6'

def sha(p:Path)->str:return hashlib.sha256(p.read_bytes()).hexdigest()
def pecl_len(n:int)->int:return 4*((n+3)//4+1)
def raw_len(n:int)->int:return 4*max(2,(n+3)//4)

def scan_control_plaintext_length(scan_source:str)->int:
    # Parse only the parenthesized literal concatenation assigned to englishText;
    # never load or execute the target-running scan module.
    m=re.search(r"const englishText = \((.*?)\)\s*\.slice\(0, 544\);",scan_source,re.S)
    assert m
    literals=re.findall(r"'(?:\\.|[^'\\])*'",m.group(1))
    assert len(literals)==3
    values=[ast.literal_eval(token) for token in literals]
    assert all(isinstance(value,str) for value in values)
    return len((''.join(values))[:544].encode('ascii'))

def compile_lib(td:Path)->tuple[Path,str,list[str]]:
    out=td/'libxxtea.so'
    cmd=['cc','-shared','-fPIC','-O2',str(SOURCE),'-o',str(out)]
    subprocess.run(cmd,check=True,capture_output=True,text=True,timeout=60)
    ver=subprocess.run(['cc','--version'],check=True,capture_output=True,text=True,timeout=10).stdout.splitlines()[0]
    return out,ver,cmd

def actual_vectors():
    with tempfile.TemporaryDirectory(prefix='astra-xxtea-') as s:
        libpath,ccver,cmd=compile_lib(Path(s)); lib=ctypes.CDLL(str(libpath))
        enc=lib.xxtea_encrypt_bytes; dec=lib.xxtea_decrypt_bytes
        U8=ctypes.POINTER(ctypes.c_uint8); SZ=ctypes.POINTER(ctypes.c_size_t)
        enc.argtypes=[U8,ctypes.c_size_t,U8,ctypes.c_size_t,SZ];enc.restype=U8
        dec.argtypes=enc.argtypes;dec.restype=U8
        libc=ctypes.CDLL(None);libc.free.argtypes=[ctypes.c_void_p]
        key=b'Zombies'; ka=(ctypes.c_uint8*len(key)).from_buffer_copy(key)
        rows=[]
        for n in [1,2,3,4,5,7,8,9,15,16,17,31,32,33,545,546,547]:
            plain=bytes((i*73+n)&255 for i in range(n)); pa=(ctypes.c_uint8*n).from_buffer_copy(plain)
            olen=ctypes.c_size_t(); ptr=enc(pa,n,ka,len(key),ctypes.byref(olen)); assert ptr
            cipher=ctypes.string_at(ptr,olen.value);libc.free(ptr)
            ca=(ctypes.c_uint8*len(cipher)).from_buffer_copy(cipher)
            plen=ctypes.c_size_t(); pptr=dec(ca,len(cipher),ka,len(key),ctypes.byref(plen)); assert pptr
            recovered=ctypes.string_at(pptr,plen.value);libc.free(pptr)
            assert recovered==plain and olen.value==pecl_len(n) and olen.value%4==0
            rows.append({'input_length':n,'pecl_cipher_length':olen.value,'raw_cipher_length':raw_len(n),
              'cipher_sha256':hashlib.sha256(cipher).hexdigest(),'roundtrip':True})
        return rows,ccver,['cc','-shared','-fPIC','-O2','source/xxtea.c','-o','TEMP/libxxtea.so']

def produce():
    for name,want in PINS.items(): assert sha(HERE/'source'/name)==want
    c=SOURCE.read_text(); app=APP.read_text(); wrap=WRAPPER.read_text()
    prior_scan=(HERE/'source'/'fable_scan_xxtea.js').read_text()
    prior_result=json.loads((HERE/'source'/'fable_results_xxtea.json').read_text())
    prior_survivors=json.loads((HERE/'source'/'fable_survivors_xxtea.json').read_text())
    required_c=['n = (((len & 3) == 0)', 'out[n] = (uint32_t)len;', 'n = len << 2;',
                'data_array = xxtea_to_uint_array(data, data_len, 1',
                'data_array_len, 0, out_len)',
                'data_array = xxtea_to_uint_array(data, data_len, 0',
                'data_array_len, 1, out_len)']
    required_app=['Math.max(2, Math.ceil(bytes.length / 4))','new Uint8Array(words.length * 4)',
                  'Plain XXTEA (btea), no embedded length header']
    required_wrap=['XXTEA — variable-length block cipher, no IV.','xxtea_encrypt_bytes','xxtea_decrypt_bytes']
    assert all(x in c for x in required_c) and all(x in app for x in required_app) and all(x in wrap for x in required_wrap)
    assert 'main();' in prior_scan and 'buildTrims4' in prior_scan and 'xxteaPeclDecrypt' in prior_scan and 'xxteaRawDecrypt' in prior_scan
    assert prior_result['trimCount']==10 and prior_result['loreArtifacts']['keysTested']==1422
    assert prior_result['loreArtifacts']['jobs']==113760 and prior_result['loreArtifacts']['survivorCount']==0 and prior_survivors==[]
    prior_control_length=scan_control_plaintext_length(prior_scan)
    assert prior_control_length==313
    rows,ccver,cmd=actual_vectors()
    chain=[]
    for n in [8,12,548,552]:
        b=bytes(range(256))*(n//256)+bytes(range(n%256))
        stages=[b,b[::-1],bytes(x^0x5a for x in b),bytes(x^0x5a for x in b)[::-1]]
        assert all(len(x)==n and len(x)%4==0 for x in stages)
        chain.append({'serialized_length':n,'stage_lengths':[len(x) for x in stages]})
    return {
      'identity':'ASTRA','schema':'astra-xxtea-mixed-length-audit-v1','target_evaluated':False,
      'canonical_final_binary_length':546,'canonical_length_mod4':2,
      'theorem':{'premise':'A complete whole-buffer XXTEA word serialization occurs, and every later binary operation preserves byte length before the final hex is decoded.',
        'conclusion':'The final decoded binary length is divisible by 4, so it cannot be 546 bytes.',
        'pecl_encryption_length':'4*(ceil(n/4)+1)','raw_btea_length':'4*max(2,ceil(n/4))'},
      'source':{'repository':'https://github.com/irebased/old-ciphers','commit':COMMIT,'commit_date':'2026-09-07T18:32:30Z',
        'urls':{n:f'https://github.com/irebased/old-ciphers/blob/{COMMIT}/'+path for n,path in {'xxtea.c':'wasm/xxtea.c','app.js':'js/app.js','mcrypt_wrapper.c':'wasm/mcrypt_wrapper.c'}.items()},
        'sha256':PINS,
        'historical_context':{'official_pecl_url':'https://pecl.php.net/package/xxtea/1.0.11','official_pecl_index_url':'https://pecl.php.net/package/xxtea',
          'official_release_date':'2016-01-05','official_description':'String-oriented XXTEA extension, distinct from the original uint32-array interface.',
          'note':'The executed C is the pinned 2026 old-ciphers port whose header names xxtea-pecl as its source; this audit does not claim byte identity with the 2016 PECL tarball.'}},
      'prior_fable_saved_scan':{'evidence_only_not_reexecuted':True,'trim_count':10,'keys_tested':1422,
        'jobs':113760,'variants':['pecl','raw'],'orientations':4,'survivor_count':0,
        'control_declared_544_but_actual_plaintext_bytes':prior_control_length,
        'limitations':['The saved result is checked against its pinned source and ledger, but the target scan is not rerun.',
          'The scan decrypts selected modulo-4 trims; it is not the impossible direct 546-byte producer framing.',
          'Its comment calls the plant 544 bytes, but the sliced source string contains only 313 bytes.']},
      'source_assertions':{'pecl_length_word_and_word_output':True,'raw_minimum_two_words_and_word_output':True,'wrapper_variable_length_no_iv':True},
      'actual_c_vectors':rows,'length_preserving_chain_controls':chain,
      'compiler_evidence':{'version':ccver,'command':cmd,'python':platform.python_version()},
      'escape_conditions':['XXTEA used only as an 8-byte feedback primitive rather than whole-buffer serialization',
        'serialized bytes encoded or expanded and the final 546 bytes are that text encoding rather than the decoded serialization',
        'truncation, header removal, insertion, or other length-changing framing after XXTEA',
        'only a prefix/suffix of a serialized value survives','a different non-word serialization implementation'],
      'limits':['The serialization formulas and compiled C controls cover positive input lengths; the pinned C wrapper rejects empty input.',
        'The proof does not test keys, modes, plaintext plausibility, or any Rev7 ciphertext.',
        'A length contradiction identifies an incompatible framing chain; it does not exclude every algorithm called XXTEA.',
        'Adding a plaintext-length uint32 word changes the number of words but never the modulo-4 invariant.',
        'The saved raw decryptor zero-fills a partial final input word and strips trailing zero plaintext; this permissive decoder behavior does not make a 546-byte value an output of raw word serialization.']}

def main():
    ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args()
    got=produce()
    if a.regenerate:
        if a.regenerate.exists(): raise SystemExit('refusing existing output')
        a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n')
        print(json.dumps({'identity':'ASTRA','written':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True));return
    saved=json.loads(LEDGER.read_text())
    # Compiler strings and temporary-machine evidence may differ; deterministic scientific fields must match.
    for x in (saved,got): x.pop('compiler_evidence',None)
    assert saved==got
    print(json.dumps({'identity':'ASTRA','verified':True,'ledger_sha256':sha(LEDGER),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

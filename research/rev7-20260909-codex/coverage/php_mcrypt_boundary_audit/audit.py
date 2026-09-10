#!/usr/bin/env python3
"""ASTRA source-only audit of PHP mcrypt partial-block boundary behavior."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

HERE=Path(__file__).resolve().parent
SOURCES={
 "php-src-PHP-5.6.25-ext-mcrypt-mcrypt.c":"340fa4d3282823c7072c820704e0e544f0d863b12641a3b748d99cd9d3d7956d",
 "php-doc-en-1d391575-mcrypt-decrypt.xml":"8a89860b7c94acb9ca643a309ba04c66d7e17d517cf827a54e63c20d35086d40",
 "captured-wasm-mcrypt_wrapper.c":"ae134769f33ea4f6f1e42599706d7050670ad33669ce9c8c3fc22d1496f38982",
 "tools4noobs-encrypt-20150910.html":"5a86122f5680a1974624beca07aeb3cc9bc20978b506912ab3cbdfb93b9fa3cd",
 "tools4noobs-decrypt-2014.html":"4cd8d597c517e25250a9d294885cd9abdb425a925eaaf3d9e928d631a4b9054d",
}
def sha(b:bytes)->str:return hashlib.sha256(b).hexdigest()
def lineno(text:str,needle:str)->int:
    assert text.count(needle)>=1, needle
    return text[:text.index(needle)].count("\n")+1

def build():
    texts={}
    files={}
    for name,want in SOURCES.items():
        raw=(HERE/'source'/name).read_bytes()
        assert sha(raw)==want,(name,sha(raw))
        texts[name]=raw.decode('utf-8',errors='strict')
        files[name]={"bytes":len(raw),"sha256":want}
    php=texts['php-src-PHP-5.6.25-ext-mcrypt-mcrypt.c']
    doc=texts['php-doc-en-1d391575-mcrypt-decrypt.xml']
    wasm=texts['captured-wasm-mcrypt_wrapper.c']
    enc=texts['tools4noobs-encrypt-20150910.html']
    dec=texts['tools4noobs-decrypt-2014.html']
    php_needles={
      "round_up":"data_size = (((data_len - 1) / block_size) + 1) * block_size;",
      "zero_fill":"memset(data_s, 0, data_size);",
      "copy_input":"memcpy(data_s, data, data_len);",
      "decrypt":"mdecrypt_generic(td, data_s, data_size);",
      "return_rounded":"RETVAL_STRINGL(data_s, data_size, 0);",
    }
    for x in php_needles.values(): assert x in php
    doc_needle="the data will be padded with '<literal>\\0</literal>'."
    assert doc_needle in doc
    assert 'Returns the decrypted data as a string' in doc
    wasm_needles={
      "ecb_reject":"if (dlen % bs != 0) return -1; \\",
      "zero_unpad":"return zero_unpad(data, dlen); \\",
    }
    for x in wasm_needles.values(): assert x in wasm
    assert enc.count('<strong>mcrypt_encrypt()</strong>')==1
    # The archived decrypt page repeats mcrypt_encrypt wording and exposes no PHP handler body.
    assert dec.count('<strong>mcrypt_encrypt()</strong>')==1
    sizes=[]
    for n in (1,7,8,9,546):
      for b in (8,16,32): sizes.append({"input":n,"block":b,"php_return_length":((n-1)//b+1)*b})
    return {
      "identity":"ASTRA","target_evaluated":False,"source_only":True,
      "source_files":files,
      "version_binding":{"php_version":"5.6.25","php_tag_commit":"e37064dae4a80c70405899bb591969bbe6aad9a8","php_commit_date":"2016-08-18T11:07:46Z","doc_commit":"1d391575445598c99175a17eb012f1c658febaa4","doc_commit_date":"2014-10-15T20:01:03Z"},
      "anchors":{
        "php_src":{k:{"line":lineno(php,v),"text":v} for k,v in php_needles.items()},
        "php_doc":{"padding_line":lineno(doc,doc_needle),"text":doc_needle},
        "captured_c_port":{k:{"line":lineno(wasm,v),"text":v} for k,v in wasm_needles.items()},
        "tools4noobs_frontend":{"encrypt_mcrypt_claim_line":lineno(enc,'<strong>mcrypt_encrypt()</strong>'),"decrypt_page_same_wording_line":lineno(dec,'<strong>mcrypt_encrypt()</strong>')},
      },
      "rounded_length_examples":sizes,
      "canonical_length_546":{"block8":552,"block16":560,"block32":576},
      "findings":{
        "php_wrapper_nonaligned_block_input":"zero_extend_then_decrypt_and_return_rounded_length",
        "captured_c_port_nonaligned_ecb_cbc_decrypt":"hard_reject",
        "captured_c_port_aligned_decrypt_postprocessing":"strip_trailing_zero_bytes",
        "php_wrapper_postprocessing":"no_unpad_or_trim_in_php_mcrypt_do_crypt",
        "tools4noobs_backend_postprocessing":"unknown_from_captured_frontend",
      },
      "critical_nuance":"For decryption, PHP appends zero bytes to ciphertext before block decryption. The added output plaintext bytes are generally not zero; only the returned length is fixed by this source audit.",
      "conclusion":"The captured C-port reject/zero_unpad behavior is not historical PHP 5.6.25 mcrypt_decrypt behavior and cannot establish tools4noobs behavior without its server-side handler source.",
    }

def main():
    ap=argparse.ArgumentParser(); ap.add_argument('--generate',type=Path); a=ap.parse_args()
    got=build()
    if a.generate:
      if a.generate.exists(): raise SystemExit('refusing existing output')
      a.generate.write_text(json.dumps(got,indent=2,sort_keys=True)+'\n')
    else:
      want=json.loads((HERE/'audit.json').read_text())
      assert got==want
    print(json.dumps({"identity":"ASTRA","status":"PASS","source_files":len(SOURCES),"conclusion":got['conclusion']},sort_keys=True))
if __name__=='__main__':main()

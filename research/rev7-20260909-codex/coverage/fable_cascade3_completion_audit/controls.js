#!/usr/bin/env node
'use strict';
const fs=require('fs');const path=require('path');const crypto=require('crypto');
const HERE=__dirname;const U=path.join(HERE,'upstream');
const C=require(path.join(U,'cascade','cascade_lib.js'));const S=require(path.join(U,'cascade','scan.js'));
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
async function main(){
 const hexRaw=fs.readFileSync(path.join(U,'cascade3','plant3_hex.txt'));
 const plainRaw=fs.readFileSync(path.join(U,'cascade3','plant3_plaintext.txt'));
 const hex=hexRaw.toString('utf8').trim().replace(/\s+/g,'').toUpperCase();
 if(hex.length!==664||!/^([0-9A-F]{2})+$/.test(hex))throw Error('plant hex');
 const ct=Buffer.from(hex,'hex');if(ct.length!==332||plainRaw.length!==332)throw Error('plant lengths');
 if(S.LAYER_OPTS.length!==46)throw Error('layer options');
 const labels=S.LAYER_OPTS.map(x=>x.label);if(new Set(labels).size!==46)throw Error('duplicate labels');
 const expected=[];for(const c of C.ALL_CIPHERS)for(const k of C.KEYS)expected.push(`decrypt:${c}:${k}`);
 if(JSON.stringify(labels)!==JSON.stringify(expected))throw Error('option order');
 if(C.ALL_CIPHERS.length!==23||JSON.stringify(C.KEYS)!==JSON.stringify(['Zombies','ZOMBIES']))throw Error('registry');
 if(C.MODE_CFB8!==0)throw Error('mode');
 if(C.loki97Key('Zombies').length!==32||C.loki97Key('Zombies').subarray(0,7).toString()!=='Zombies'||!C.loki97Key('Zombies').subarray(7).every(x=>x===0))throw Error('loki key');
 const ctx=await C.loadMcrypt();
 const after1=C.decryptWith(ctx,'serpent','Zombies',ct);
 const afterReverse=C.reverseBuf(after1);
 const after2=C.decryptWith(ctx,'blowfish','Zombies',afterReverse);
 const recovered=C.decryptWith(ctx,'twofish','Zombies',after2);
 if(!recovered.equals(plainRaw))throw Error('planted decrypt mismatch');
 const step3=C.encryptWith(ctx,'twofish','Zombies',plainRaw);
 const step2=C.encryptWith(ctx,'blowfish','Zombies',step3);
 const reversedMid=C.reverseBuf(step2);
 const rebuilt=C.encryptWith(ctx,'serpent','Zombies',reversedMid);
 if(!rebuilt.equals(ct))throw Error('planted encrypt mismatch');
 const arrays=[ct,after1,afterReverse,after2,recovered,step3,step2,reversedMid,rebuilt];if(arrays.some(x=>x.length!==332))throw Error('length changed');
 const score=C.scoreTail(recovered,S.blockSizeFor('twofish'));if(JSON.stringify(score)!==JSON.stringify({longestRun:316,validCount:316,tailLen:316}))throw Error('score');
 const info={};for(const c of C.ALL_CIPHERS)info[c]={blockSize:C.CIPHER_INFO[c].blockSize||0,stream:!!C.CIPHER_INFO[c].stream,keySizes:C.CIPHER_INFO[c].keySizes};
 const result={identity:'ASTRA',target_evaluated:false,full_sweep_run:false,node:process.version,registry:{ciphers:C.ALL_CIPHERS,keys:C.KEYS,layer_options:labels,layer_option_count:46,cipher_info:info},plant:{hex_file_bytes:hexRaw.length,hex_symbols:hex.length,ciphertext_bytes:ct.length,plaintext_bytes:plainRaw.length,hex_sha256:sha(hexRaw),plaintext_sha256:sha(plainRaw),ciphertext_sha256:sha(ct),true_path:['decrypt:serpent:Zombies','reverse','decrypt:blowfish:Zombies','decrypt:twofish:Zombies'],decrypt_intermediate_sha256:{after_serpent:sha(after1),after_reverse:sha(afterReverse),after_blowfish:sha(after2),recovered:sha(recovered)},encrypt_intermediate_sha256:{after_twofish:sha(step3),after_blowfish:sha(step2),after_reverse:sha(reversedMid),rebuilt:sha(rebuilt)},all_stage_lengths:arrays.map(x=>x.length),exact_decrypt_recovery:true,exact_encrypt_rebuild:true,score_after_skip_last_block:score},conventions:{block_mode:'CFB8 integer 0',block_iv:'ASCII 0 repeated to block size',keys:['literal ASCII Zombies','literal ASCII ZOMBIES'],loki97:'explicit 32-byte zero-backed key with literal prefix',reverse:'valid UTF-8 codepoint reverse, otherwise raw byte reverse'}};
 process.stdout.write(JSON.stringify(result,null,2)+'\n');
}
main().catch(e=>{console.error(e);process.exit(1)});

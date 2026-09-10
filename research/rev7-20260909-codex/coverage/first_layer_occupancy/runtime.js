#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');
const ROOT=path.resolve(__dirname,'../../../..');
const DEP=path.join(ROOT,'research/rev7-20260909-codex/coverage/fable_b64read_source_audit');
const LIB_PATH=path.join(DEP,'upstream/dictkey2/lib.js');
const MCRYPT_JS=path.join(DEP,'old-ciphers/js/mcrypt.js');
const MCRYPT_WASM=path.join(DEP,'old-ciphers/js/mcrypt.wasm');
const PINS={
 [LIB_PATH]:'ffba90a95de78bdeef64c8d2b5602c61d3271e7780914d8322cc5bb9b912ec1d',
 [MCRYPT_JS]:'8998b6dd50ebc24aede3df84228826951f2143fde393e15f95d1455e074d5061',
 [MCRYPT_WASM]:'60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7'};
function shaFile(f){return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');}
function verifySources(){for(const [f,w] of Object.entries(PINS))if(shaFile(f)!==w)throw Error('source hash mismatch '+f);}
verifySources();
const lib=require(LIB_PATH);
const MODES=Object.freeze([{name:'cfb8',code:0},{name:'ncfb',code:3},{name:'ofb',code:4},{name:'ctr',code:5}]);
const KEYS=Object.freeze(['Zombies','ZOMBIES']);
const BLOCK_CIPHERS=Object.freeze(lib.BLOCK_CIPHERS.slice());
const STREAM_CIPHERS=Object.freeze(lib.ALL_CIPHERS.filter(c=>lib.CIPHER_INFO[c].stream));
if(BLOCK_CIPHERS.length!==19||STREAM_CIPHERS.length!==4)throw Error('registry count');
function keyBytes(cipher,keyText){
 if(!KEYS.includes(keyText))throw Error('key text');
 const raw=Buffer.from(keyText,'ascii');
 if(cipher==='loki97'){const k=Buffer.alloc(32);raw.copy(k);return k;}
 return raw;
}
function ivBytes(blockSize,ivName){
 if(ivName==='zero')return Buffer.alloc(blockSize,0);
 if(ivName==='ascii0')return Buffer.alloc(blockSize,0x30);
 throw Error('iv name');
}
async function load(){verifySources();const ctx=await lib.loadMcrypt();ctx.metrics={calls:0,key_clears:0,iv_clears:0};return ctx;}
function crypt(ctx,cipher,keyText,ivName,data,mode,direction){
 const info=lib.CIPHER_INFO[cipher];if(!info)throw Error('cipher');if(!Buffer.isBuffer(data))data=Buffer.from(data);
 const key=keyBytes(cipher,keyText),{mcrypt,bufPtr,ivPtr,keyPtr}=ctx;
 mcrypt.HEAPU8.fill(0,keyPtr,keyPtr+256);ctx.metrics.key_clears++;mcrypt.HEAPU8.set(key,keyPtr);
 mcrypt.HEAPU8.set(data,bufPtr);let outLen;
 if(info.stream){if(mode!==null||ivName!==null)throw Error('stream has no mode/iv');mcrypt['_'+info.fn](key.length,data.length,direction);outLen=data.length;}
 else{
  const mr=MODES.find(x=>x.name===mode);if(!mr)throw Error('mode');const iv=ivBytes(info.blockSize,ivName);
  mcrypt.HEAPU8.fill(0,ivPtr,ivPtr+32);ctx.metrics.iv_clears++;mcrypt.HEAPU8.set(iv,ivPtr);
  outLen=mcrypt['_'+info.fn](key.length,iv.length,data.length,direction,mr.code);
 }
 if(outLen<0)throw Error('process failed '+outLen);ctx.metrics.calls++;
 return Buffer.from(new Uint8Array(mcrypt.HEAPU8.buffer,bufPtr,outLen));
}
const encrypt=(ctx,c,k,i,d,m)=>crypt(ctx,c,k,i,d,m,1);
const decrypt=(ctx,c,k,i,d,m)=>crypt(ctx,c,k,i,d,m,0);
module.exports={PINS,MODES,KEYS,BLOCK_CIPHERS,STREAM_CIPHERS,CIPHER_INFO:lib.CIPHER_INFO,shaFile,verifySources,keyBytes,ivBytes,load,crypt,encrypt,decrypt};

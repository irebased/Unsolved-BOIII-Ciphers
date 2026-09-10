#!/usr/bin/env node
'use strict';
// Synthetic-only Loki97 key-tail probe. Never reads Rev7 data.
const fs = require('fs');
const crypto = require('crypto');
const path = require('path');
const MCRYPT = '/private/tmp/rev7-fable-20260909/old-ciphers/js/mcrypt.js';
const LOKI_SOURCE = path.resolve(__dirname, '../iv_independent/cascade/runtime/source/loki97/loki97.c');
const WASM = '/private/tmp/rev7-fable-20260909/old-ciphers/js/mcrypt.wasm';
const sha256 = p => crypto.createHash('sha256').update(fs.readFileSync(p)).digest('hex');
const EXPECTED={source:'4e18d184ec55776edab065cee35ac44a9269b4160d7d35ad4ea277da55ae3308', wasm:'60a8215b8f6f7774511004ec51528b60e781ca8c260d0b1cf1baad0dfc932be7'};
const hex = u => Buffer.from(u).toString('hex');
const eq = (a,b) => Buffer.compare(Buffer.from(a),Buffer.from(b)) === 0;
async function main() {
  if (sha256(LOKI_SOURCE)!==EXPECTED.source || sha256(WASM)!==EXPECTED.wasm) throw new Error('pinned source/runtime hash mismatch');
  const McryptModule = require(MCRYPT);
  const m = await McryptModule();
  const keyPtr=m._get_key(), ivPtr=m._get_iv(), bufPtr=m._get_buf();
  const key = Buffer.from('Zombies','ascii');
  const input = Buffer.from(Array.from({length:64}, (_,i)=>i));
  const iv = Buffer.alloc(16);
  function clear(n=256) { m.HEAPU8.fill(0,keyPtr,keyPtr+n); }
  function write(b) { m.HEAPU8.set(b,keyPtr); }
  function run(keylen=7) {
    m.HEAPU8.set(input,bufPtr); m.HEAPU8.set(iv,ivPtr);
    const n=m._loki97_process(keylen,16,input.length,0,0);
    if(n!==64) throw new Error('unexpected output length '+n);
    return {output:Buffer.from(m.HEAPU8.subarray(bufPtr,bufPtr+64)), key32:Buffer.from(m.HEAPU8.subarray(keyPtr,keyPtr+32))};
  }
  clear(); write(key); const A=run();
  clear(); write(Buffer.from(Array.from({length:32},(_,i)=>0xA0+i))); run(32); write(key); const B=run();
  clear(); write(key); const C=run();
  clear(); write(key); m.HEAPU8[keyPtr+31]=0x5A; const D=run();
  const rows={A,B,C,D};
  const same={A_eq_C:eq(A.output,C.output), B_eq_C:eq(B.output,C.output), C_eq_D:eq(C.output,D.output), A_eq_B:eq(A.output,B.output)};
  const result={identity:'ASTRA',target_evaluated:false,rev7_read:false,crypto_evaluated:true,scope:'Synthetic Loki97 wrapper key-buffer tail/state probe only; fixed 7-byte Zombies key, 64-byte synthetic input, zero IV, CFB8 decrypt.',backend:{module:MCRYPT,wasm:WASM,source:LOKI_SOURCE,node:process.version,source_sha256:sha256(LOKI_SOURCE),wasm_sha256:sha256(WASM),script_sha256:sha256(__filename)},cases:{A:'clear256 then write Zombies7',B:'seed32 nonzero via actual Loki97 call then write Zombies7',C:'clear256 then write Zombies7',D:'clear256 write Zombies7 then alter only key byte31'},input_hex:hex(input),input_sha256:crypto.createHash('sha256').update(input).digest('hex'),rows:Object.fromEntries(Object.entries(rows).map(([k,v])=>[k,{output_hex:hex(v.output),key32_hex:hex(v.key32),output_sha256:crypto.createHash('sha256').update(v.output).digest('hex')} ])),comparisons:same,interpretation:'A/B/C/D comparisons test history and backing-tail influence; no conclusion is inferred until execution.'};
  process.stdout.write(JSON.stringify(result,null,2)+'\n');
}
main().catch(e=>{console.error(e.stack||e);process.exitCode=1});

#!/usr/bin/env node
"use strict";
const fs=require("fs"), vm=require("vm"), path=require("path");
const sourcePath=path.join(__dirname,"source","aes.js");
const source=fs.readFileSync(sourcePath,"utf8");
const ctx={}; vm.createContext(ctx); vm.runInContext(source,ctx,{filename:sourcePath});
const request=JSON.parse(fs.readFileSync(0,"utf8"));
function hexToBytes(s){ if(!/^(?:[0-9a-f]{2})*$/i.test(s)) throw Error("bad hex"); return Array.from(Buffer.from(s,"hex")); }
function block(op,keyHex,dataHex){
  const key=hexToBytes(keyHex), data=hexToBytes(dataHex);
  if(![16,24,32].includes(key.length)||data.length!==32) throw Error("bad size");
  ctx.blockSizeInBits=256; ctx.keySizeInBits=key.length*8;
  const expanded=ctx.keyExpansion(key.slice());
  const out=(op==="encrypt"?ctx.encrypt:ctx.decrypt)(data.slice(),expanded);
  return Buffer.from(out).toString("hex");
}
process.stdout.write(JSON.stringify(request.operations.map(x=>block(x.op,x.key_hex,x.data_hex))));

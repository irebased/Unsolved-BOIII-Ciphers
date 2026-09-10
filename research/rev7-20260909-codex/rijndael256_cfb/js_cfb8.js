#!/usr/bin/env node
"use strict";
const fs=require("fs"),vm=require("vm"),path=require("path");
const sourcePath=path.join(__dirname,"..","rijndael256_controls","source","aes.js");
const source=fs.readFileSync(sourcePath,"utf8");
const ctx={};vm.createContext(ctx);vm.runInContext(source,ctx,{filename:sourcePath});
function bytes(hex){if(!/^(?:[0-9a-f]{2})*$/i.test(hex))throw Error("bad hex");return Array.from(Buffer.from(hex,"hex"));}
function hx(values){return Buffer.from(values).toString("hex");}
function job(row){
 const key=bytes(row.key_hex),iv=bytes(row.iv_hex),input=bytes(row.data_hex);
 if(![16,24,32].includes(key.length)||iv.length!==32)throw Error("bad sizes");
 ctx.blockSizeInBits=256;ctx.keySizeInBits=key.length*8;
 const expanded=ctx.keyExpansion(key.slice());
 function block(reg){return ctx.encrypt(reg.slice(),expanded);}
 function crypt(data,decrypt){let reg=iv.slice(),out=[];for(const value of data){const z=value^block(reg)[0];const cipher=decrypt?value:z;out.push(z);reg=reg.slice(1);reg.push(cipher);}return out;}
 if(row.operation==="encrypt"){const cipher=crypt(input,false);return {ciphertext_hex:hx(cipher)};}
 if(row.operation==="roundtrip"){const cipher=crypt(input,false);const plain=crypt(cipher,true);return {ciphertext_hex:hx(cipher),decrypted_hex:hx(plain)};}
 if(row.operation==="decrypt"){return {plaintext_hex:hx(crypt(input,true))};}
 throw Error("bad operation");
}
const request=JSON.parse(fs.readFileSync(0,"utf8"));
process.stdout.write(JSON.stringify(request.jobs.map(job)));

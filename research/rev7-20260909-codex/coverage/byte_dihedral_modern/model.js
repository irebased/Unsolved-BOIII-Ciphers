#!/usr/bin/env node
'use strict';
const crypto=require('crypto');
const BASE=require('../first_layer_occupancy/model.js');
const R=require('../first_layer_occupancy/runtime.js');
function assert(x,m){if(!x)throw Error(m);}
function sha(b){return crypto.createHash('sha256').update(b).digest('hex');}
function rol8(x,k){k&=7;return ((x<<k)|(x>>(8-k)))&255;}
function ror8(x,k){k&=7;return ((x>>k)|(x<<(8-k)))&255;}
function bitReverse8(x){x=((x&0x55)<<1)|((x>>1)&0x55);x=((x&0x33)<<2)|((x>>2)&0x33);return ((x&15)<<4)|(x>>4);}
function transformByte(x,reflect,k){return rol8(reflect?bitReverse8(x):x,k);}
function inverseByte(y,reflect,k){const x=ror8(y,k);return reflect?bitReverse8(x):x;}
function transform(buf,reflect,k){return Buffer.from(Array.from(buf,x=>transformByte(x,reflect,k)));}
function inverse(buf,reflect,k){return Buffer.from(Array.from(buf,x=>inverseByte(x,reflect,k)));}
function transformId(reflect,k){return `${reflect?'reflect':'rotate'}:${k}`;}
function transforms(){const a=[];for(const reflect of [false,true])for(let k=0;k<8;k++)a.push({reflect,k,id:transformId(reflect,k)});return a;}
function asciiRatio(buf){let n=0;for(const x of buf)if(x===9||x===10||x===13||(x>=32&&x<=126))n++;return {allowed:n,total:buf.length,ratio:buf.length?n/buf.length:0,hit:buf.length>0&&n/buf.length>=.75};}
function screen(output,c){const base=BASE.screenOutput(output,c),af=asciiRatio(output),at=c.kind==='block'?asciiRatio(output.subarray(c.block_size)):null;const flags=[...base.flagged_windows.map(x=>'occupancy:'+x)];if(af.hit)flags.push('ascii:full');if(at&&at.hit)flags.push('ascii:tail');return {...base,ascii:{full:af,tail:at},flagged_windows:flags};}
function descriptorId(inputId,c){return [inputId,c.cipher,c.mode===null?'stream':c.mode,c.key,c.iv===null?'none':c.iv].join('|');}
function deduplicate(orientedHex){const groups=new Map();for(const orientation of BASE.ORIENTATIONS){const b=Buffer.from(orientedHex[orientation],'hex');for(const t of transforms()){const out=transform(b,t.reflect,t.k),h=sha(out),alias={orientation,transform:t.id};if(!groups.has(h))groups.set(h,{input_sha256:h,input:out,aliases:[]});groups.get(h).aliases.push(alias);}}
 return [...groups.values()].sort((a,b)=>a.input_sha256.localeCompare(b.input_sha256));}
module.exports={BASE,R,rol8,ror8,bitReverse8,transformByte,inverseByte,transform,inverse,transformId,transforms,asciiRatio,screen,descriptorId,deduplicate,sha,assert};

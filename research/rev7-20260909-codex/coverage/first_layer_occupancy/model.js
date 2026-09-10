#!/usr/bin/env node
'use strict';
const fs=require('fs'),path=require('path'),crypto=require('crypto');const R=require('./runtime.js');
const ROOT=path.resolve(__dirname,'../../../..');
const SCORE_PATH=path.join(ROOT,'research/rev7-20260909-codex/coverage/occupancy_screen_controls/score.js');
const TABLE_PATH=path.join(ROOT,'research/rev7-20260909-codex/coverage/occupancy_screen_controls/threshold_table.json');
const SCORE_SHA='6ff228f71ef8e9441c3ba12418d8b49c7238ff4e66ed0eef0f24471a3573ae27',TABLE_SHA='2d084a536141c8e51045b1fa1052ddfc713e0e5f7a869fd62676cf788dfbb447';
function shaFile(f){return crypto.createHash('sha256').update(fs.readFileSync(f)).digest('hex');}
if(shaFile(SCORE_PATH)!==SCORE_SHA||shaFile(TABLE_PATH)!==TABLE_SHA)throw Error('occupancy dependency hash');
const S=require(SCORE_PATH),TABLE=S.loadTable(TABLE_PATH);
const ORIENTATIONS=Object.freeze(['forward','full_hex_reverse','byte_pair_reverse','nibble_swap','visible_token_reverse']);
function orientations(hex,tokens){
 if(typeof hex!=='string'||hex.length%2||!/^[0-9A-F]+$/.test(hex))throw Error('uppercase even hex');
 if(!Array.isArray(tokens)||tokens.join('')!==hex||tokens.some(x=>!x.length||!/^[0-9A-F]+$/.test(x)))throw Error('tokens');
 const pairs=hex.match(/../g);
 const out={forward:hex,full_hex_reverse:[...hex].reverse().join(''),byte_pair_reverse:pairs.slice().reverse().join(''),nibble_swap:pairs.map(x=>x[1]+x[0]).join(''),visible_token_reverse:tokens.slice().reverse().join('')};
 for(const x of ORIENTATIONS)if(out[x].length!==hex.length||!/^[0-9A-F]+$/.test(out[x]))throw Error('orientation');
 return out;
}
function contexts(){const rows=[];
 for(const cipher of R.BLOCK_CIPHERS)for(const mode of R.MODES)for(const key of R.KEYS)for(const iv of ['zero','ascii0'])rows.push({kind:'block',cipher,mode:mode.name,mode_code:mode.code,key,iv,block_size:R.CIPHER_INFO[cipher].blockSize});
 for(const cipher of R.STREAM_CIPHERS)for(const key of R.KEYS)rows.push({kind:'stream',cipher,mode:null,mode_code:null,key,iv:null,block_size:0});
 if(rows.length!==312)throw Error('context grid');return rows;
}
function descriptorId(orientation,c){return [orientation,c.cipher,c.mode===null?'stream':c.mode,c.key,c.iv===null?'none':c.iv].join('|');}
function screenOutput(output,c){
 const full=S.scoreBytes(output,TABLE);const tail=c.kind==='block'?S.scoreBytes(output.subarray(c.block_size),TABLE):null;
 return {output_length:output.length,output_sha256:crypto.createHash('sha256').update(output).digest('hex'),full,tail,flagged_windows:[...(full.screen_hit===true?['full']:[]),...(tail&&tail.screen_hit===true?['tail']:[])]};
}
function evaluate(ctx,orientation,c,ciphertext){const output=R.decrypt(ctx,c.cipher,c.key,c.iv,ciphertext,c.mode);return {id:descriptorId(orientation,c),orientation,...c,...screenOutput(output,c),output};}
module.exports={SCORE_PATH,TABLE_PATH,SCORE_SHA,TABLE_SHA,TABLE,ORIENTATIONS,shaFile,orientations,contexts,descriptorId,screenOutput,evaluate};

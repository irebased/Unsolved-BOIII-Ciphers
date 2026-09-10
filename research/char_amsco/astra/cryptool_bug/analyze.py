#!/usr/bin/env python3
"""Exact bounded model of the CrypTool legacy AMSCO key-label bug."""
from __future__ import annotations
from pathlib import Path
import argparse,base64,hashlib,importlib.util,itertools,json
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'evidence.json';IDENTITY='ASTRA'
PINS={'source/class.amsco.php':'132d61ff8b794ab9717a0ce284d7bf21f82c8dbfe39bf9f1a3b5f7aa7eb91e4f','source/class.amsco.php.base64':'25143ebd1a720d9fe35ac3aa2579be722a8ded03b67d6ff2da0f071e40f8c3ac','source/default_tool.php':'e71bcfe75ae9250b00f8adf38eaec4547b854bfafd23a559cfef482d0f81a7d6','source/infobox.template':'0e6f9a9f73a2aee868567fe082a342a75334a3944ca050599da6bfcb97c040af','../amsco_geometry.py':'c43e6412cbf2ac34e137801e1fd9c13e8c46bb89296bb89484c01d28a505cae6'}
def source_bytes(p):
 p=Path(p)
 if p==HERE/'source/class.amsco.php' and not p.exists():
  encoded=(HERE/'source/class.amsco.php.base64').read_bytes();assert len(encoded)==7641
  compact=b''.join(encoded.split());raw=base64.b64decode(compact,validate=True)
  assert base64.b64encode(raw)==compact and len(raw)==5730 and hashlib.sha256(raw).hexdigest()=='132d61ff8b794ab9717a0ce284d7bf21f82c8dbfe39bf9f1a3b5f7aa7eb91e4f'
  return raw
 return p.read_bytes()
def sha(p):return hashlib.sha256(source_bytes(p)).hexdigest()
def verify_pins():
 for rel,want in PINS.items():assert sha(HERE/rel)==want,(rel,sha(HERE/rel),want)
def php_char_trim(data:bytes)->bytes:
 # encode/decode loops call trim() separately on each str_split byte.
 return bytes(x for x in data if x not in {0,9,10,11,13,32})
def cells(data:bytes,width:int):
 out=[];pos=0;index=0;size=2
 while pos<len(data):
  piece=data[pos:pos+size];out.append({'row':index//width,'column':index%width,'positions':list(range(pos,pos+len(piece))),'value':piece});pos+=len(piece);index+=1;size=3-size
 return out
def frontend_key(value:str)->str:
 # Relevant decimal-integer inputs: default_tool.php is_numeric then (int).
 return str(int(value,10))
def legacy_encode(data:bytes,key:str):
 clean=php_char_trim(data.upper());width=len(key);assert width>0 and all('0'<=x<='9' for x in key)
 rows={}
 for cell in cells(clean,width):
  # PHP numeric-string array labels become integer keys. Later duplicate assignment overwrites.
  rows.setdefault(cell['row'],{})[int(key[cell['column']])]=cell
 emitted=[];positions=[]
 for label in range(1,width+1):
  for row in range(max(rows.keys(),default=-1)+1):
   cell=rows.get(row,{}).get(label)
   if cell:emitted.append(cell['value']);positions.extend(cell['positions'])
 raw=b''.join(emitted);grouped=b' '.join(raw[i:i+5] for i in range(0,len(raw),5))
 return {'preprocessed':clean,'raw':raw,'grouped':grouped,'emitted_positions':positions,'lost_positions':[x for x in range(len(clean)) if x not in positions]}
def legacy_decode(cipher:bytes,key:str)->bytes:
 clean=php_char_trim(cipher.upper());width=len(key);shape=cells(clean,width);rows=max((x['row'] for x in shape),default=-1)+1;dummy={(x['row'],x['column']):len(x['value']) for x in shape};new={};cursor=0
 for label in range(1,width+1):
  try:column=next(i for i,ch in enumerate(key) if int(ch)==label)
  except StopIteration:column=0 # PHP compares one key character to the integer rank; no character can equal 10.
  for row in range(rows):
   length=dummy.get((row,column),0);new[(row,column)]=clean[cursor:cursor+length];cursor+=length
 return b''.join(new.get((row,column),b'') for row in range(rows) for column in range(width))
def ideal(data,key):
 width=len(key);order=[key.index(str(rank)) for rank in range(1,width+1)];columns=[[] for _ in range(width)]
 for x in cells(data,width):columns[x['column']].append(x['value'])
 return b''.join(piece for col in order for piece in columns[col])
def case(name,plaintext,key,frontend=False):
 actual_key=frontend_key(key) if frontend else key;e=legacy_encode(plaintext,actual_key);decoded=legacy_decode(e['raw'],actual_key)
 return {'name':name,'submitted_key':key,'effective_key':actual_key,'plaintext_ascii':plaintext.decode('ascii'),'preprocessed_ascii':e['preprocessed'].decode('ascii'),'ciphertext_ungrouped_ascii':e['raw'].decode('ascii'),'ciphertext_grouped_ascii':e['grouped'].decode('ascii'),'decoded_ascii':decoded.decode('ascii'),'input_bytes_after_preprocess':len(e['preprocessed']),'output_bytes':len(e['raw']),'emitted_positions':e['emitted_positions'],'lost_positions':e['lost_positions']}
def generate():
 verify_pins();examples=[case('valid_control_12',b'ABC','12'),case('valid_control_21',b'ABC','21'),case('duplicate_label_overwrite',b'ABC','11'),case('zero_label_dropped',b'ABC','10'),case('out_of_range_label_dropped',b'ABC','13'),case('duplicate_longer_decode',b'ABCDE','11'),case('leading_zero_frontend_width_change',b'ABCDEFGHI','012',True),case('partial_row_duplicate_fallback',b'ABCDEFGH','121'),case('width10_missing_rank10',b'ABCDEFGHIJKLMNO','1234567890'),case('per_character_trim_preprocessing',b'A B\tC\nD0','12')]
 assert examples[0]['ciphertext_ungrouped_ascii']=='ABC' and examples[0]['decoded_ascii']=='ABC' and not examples[0]['lost_positions']
 assert examples[1]['ciphertext_ungrouped_ascii']=='CAB' and examples[1]['decoded_ascii']=='ABC'
 assert examples[2]['ciphertext_ungrouped_ascii']=='C' and examples[2]['lost_positions']==[0,1] and examples[2]['decoded_ascii']==''
 assert examples[3]['ciphertext_ungrouped_ascii']=='AB' and examples[3]['lost_positions']==[2] and examples[3]['decoded_ascii']==''
 assert examples[4]['ciphertext_ungrouped_ascii']=='AB' and examples[4]['lost_positions']==[2] and examples[4]['decoded_ascii']==''
 assert examples[5]['ciphertext_ungrouped_ascii']=='CDE' and examples[5]['lost_positions']==[0,1] and examples[5]['decoded_ascii']=='E'
 assert examples[6]['effective_key']=='12' and examples[6]['ciphertext_ungrouped_ascii']=='ABDEGHCFI' and examples[6]['decoded_ascii']=='ABCDEFGHI'
 assert examples[7]['ciphertext_ungrouped_ascii']=='DEFCGH' and examples[7]['lost_positions']==[0,1] and examples[7]['decoded_ascii']=='GHC'
 assert examples[8]['ciphertext_ungrouped_ascii']=='ABCDEFGHIJKLMN' and examples[8]['lost_positions']==[14] and examples[8]['decoded_ascii']=='CDEFGHIJKLMN'
 assert examples[9]['preprocessed_ascii']=='ABCD0'
 # Every valid single-character rank permutation at widths 2..9 has an exact one-to-one rank/column order.
 valid=0
 for width in range(2,10):
  digits='123456789'[:width]
  for key_tuple in itertools.permutations(digits):
   key=''.join(key_tuple);order=[key.index(str(rank)) for rank in range(1,width+1)]
   assert sorted(order)==list(range(width));valid+=1
 assert valid==409112
 # Direct comparison to the accepted generic geometry for fixed historical start 21.
 spec=importlib.util.spec_from_file_location('generic',HERE/'../amsco_geometry.py');generic=importlib.util.module_from_spec(spec);spec.loader.exec_module(generic)
 source=('0123456789ABCDEF'*69)[:1092];comparisons=[]
 for width in range(2,10):
  for key in (''.join(str(x) for x in range(1,width+1)),''.join(str(x) for x in range(width,0,-1))):
   order=[key.index(str(rank)) for rank in range(1,width+1)];legacy=legacy_encode(source.encode(),key)['raw'];model=''.join(generic.forward(list(source),order,'21')[0]).encode();assert legacy==model
   comparisons.append({'width':width,'key':key,'order':order,'n':1092,'equal':True,'sha256':hashlib.sha256(legacy).hexdigest()})
 result={'identity':IDENTITY,'target_evaluated':False,'rev7_read':False,'finding':{'primary':'default_tool.php accepts any numeric integer key; class.amsco.php uses each key digit as an array label without validating a permutation. Duplicate labels overwrite earlier cells in the same row; label 0 and labels outside 1..width are never emitted. Encryption can therefore delete plaintext bytes.','encryption_effect':'lossy and noninvertible for malformed effective keys once affected columns contain data','decryption_effect':'cannot recover deleted bytes; missing ranks alias natural column 1 under historical null arithmetic and duplicate ranks address only the first occurrence, so malformed-key decode is not an inverse','valid_key_limit':'For exact permutations of characters 1..width, widths 2..9, no mapping defect was found. Width 10 cannot express rank 10 as one key character.','historical_start':'The code begins with a two-character cell because n=1 makes 1+(n%2)=2; it has no start-pattern option.'},'source_provenance':{'repository':'cryptool-org/cto','commit':'4fc443f0d87c0e86815695a47ab2d6174c725f82','commit_context':'legacy tools added 2016-08-12','class_url':'https://github.com/cryptool-org/cto/blob/4fc443f0d87c0e86815695a47ab2d6174c725f82/_ctoLegacy/tools/amsco/class.amsco.php#L191','class_git_blob_sha1':'33eccb9a91008386fbcc24fecb690d7589aa66e0','default_tool_git_blob_sha1':'a1e07baad71ae378707b888890edd81a7ecd37aa','source_hashes':{k:sha(HERE/k) for k in PINS}},'reproducers':examples,'valid_permutation_check':{'widths':[2,3,4,5,6,7,8,9],'keys_structurally_enumerated':valid,'all_bijective':True,'full_1092_model_comparisons':comparisons,'all_equal_to_generic_start21':True},'length_geometry':{'historical_unit':'one byte/character; uppercase hexadecimal therefore has 1092 units, not 546','n1092':{'cells':728,'final_cell_truncated':False,'full_row_widths_2_to_9':[2,4,7,8],'partial_row_widths_2_to_9':[3,5,6,9]},'byte_analogue_n546':{'cells':364,'final_cell_truncated':False,'full_row_widths_2_to_9':[2,4,7],'partial_row_widths_2_to_9':[3,5,6,8,9]},'partial_duplicate_rule':'Within each row, the last populated natural column carrying a repeated label wins. If that later duplicate column is absent in a partial final row, an earlier occurrence survives there; the selected natural column can therefore differ in the final row.'},'coverage_conclusion':'The generic character model covers valid CrypTool keys at widths 2..9 when start=21 is included. It deliberately rejects malformed keys and therefore does not cover this lossy implementation bug. The byte-unit AMSCO model is a distinct analogue, not the historical PHP geometry.','limits':['No claim that Rev7 used a malformed key or this tool.','A malformed-key ciphertext may be shorter than its pre-AMSCO input; deleted bytes cannot be inferred by inverse permutation alone.','Per-character trim removes space, TAB, LF, VT, CR, and NUL before matrix construction; for already whitespace-free uppercase hexadecimal this does not change bytes.','No PHP runtime was available; the harness models the cited assignment/read loops and historical scalar/null behavior directly. No target ciphertext was read or evaluated.'],'source_hashes':{'analyze.py':sha(Path(__file__))},'assertions':{'all_passed':True,'minimal_duplicate_loses_AB':True,'minimal_zero_and_out_of_range_lose_C':True,'partial_row_last_duplicate_rule':True,'width10_single_character_rank10_missing':True,'valid_permutations_bijective':True,'valid_start21_matches_generic_model':True,'no_target_read_or_evaluation':True}}
 return result
def verify(path=LEDGER):
 d=json.loads(path.read_text());fresh=generate();assert d==fresh;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(path),'finding':'malformed numeric keys can make original CrypTool AMSCO encryption lossy','target_evaluated':False},sort_keys=True))
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args()
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  d=generate();a.regenerate.write_text(json.dumps(d,indent=2,sort_keys=True)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate)},sort_keys=True))
 else:verify()
if __name__=='__main__':main()

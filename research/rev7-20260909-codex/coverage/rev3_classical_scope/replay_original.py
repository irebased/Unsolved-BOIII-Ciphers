#!/usr/bin/env python3
"""ASTRA exact replay of Rev3's original published checkerboard recipe."""
from pathlib import Path
import argparse,hashlib,json,re
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
MDX=ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev3.mdx'
DATA=ROOT/'lavender/src/data/ciphers/revelations.json'
MDX_SHA='0185f674db09dfe542de8ecf2880cf83690cc8331001ebfefa65ddc4f965a243'
DATA_SHA='68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'
EXPECTED='OCTOBERNSAREPORTTTHEYFOUNDTHESOURCEONVENUSBEGINNINGEXTRACTION'
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--write',type=Path);a=ap.parse_args()
 assert sha(MDX)==MDX_SHA and sha(DATA)==DATA_SHA
 text=MDX.read_text();cipher=re.search(r'code=\{\s*`([^`]+)`',text).group(1)
 key=re.search(r'straddling checkerboard with key `([^`]+)`',text).group(1).upper()
 assert 'spare positions 3 and 7' in text and len(key)==len(set(key))==26
 glyphs={ch:chr(int(str(ord(ch)),8)) for ch in sorted(set(cipher))}
 assert set(glyphs.values())==set('0123456789')
 digits=''.join(glyphs[ch] for ch in cipher[::-1])
 codes=[str(i) for i in range(10) if i not in(3,7)]+['3'+str(i) for i in range(10)]+['7'+str(i) for i in range(10)]
 board=dict(zip(codes,key));tokens=[];i=0
 while i<len(digits):
  n=2 if digits[i] in '37' else 1;tok=digits[i:i+n]
  assert len(tok)==n and tok in board,(i,tok)
  tokens.append(tok);i+=n
 plain=''.join(board[t] for t in tokens);assert plain==EXPECTED
 encode={ch:code for code,ch in board.items()};reverse_glyphs={v:k for k,v in glyphs.items()}
 reconstructed_digits=''.join(encode[ch] for ch in plain)
 reconstructed=''.join(reverse_glyphs[d] for d in reconstructed_digits)[::-1]
 assert reconstructed_digits==digits and reconstructed==cipher
 row=next(x for x in json.loads(DATA.read_text()) if x['id']=='rev3');assert row['ciphertext']==cipher
 out={'identity':'ASTRA','cipher':'Rev3 sibling control','rev7_evaluated':False,'source_sha256':sha(Path(__file__)),'mdx_sha256':MDX_SHA,'dataset_sha256':DATA_SHA,'original_recipe_url':'https://irebased.github.io/Unsolved-BOIII-Ciphers/ciphers/bo3/rev/rev3/','key':key,'spare_digits':[3,7],'glyph_to_digit':glyphs,'ciphertext':cipher,'ciphertext_length':len(cipher),'reversed_digit_string':digits,'digit_sha256':hashlib.sha256(digits.encode()).hexdigest(),'board':board,'tokens':tokens,'token_count':len(tokens),'plaintext':plain,'plaintext_sha256':hashlib.sha256(plain.encode()).hexdigest(),'original_expected_exact':True,'reconstructed_ciphertext_exact':True,'dataset_alternate_plaintext':row['plaintext'],'dataset_alternate_matches_original':row['plaintext']==plain,'differences_from_dataset_alternate':[{'offset':j,'original':x,'alternate':y} for j,(x,y) in enumerate(zip(plain,row['plaintext'])) if x!=y]}
 if a.write:
  if a.write.exists():raise SystemExit('refusing existing output')
  a.write.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
 print(json.dumps(out,indent=2,sort_keys=True))
if __name__=='__main__':main()

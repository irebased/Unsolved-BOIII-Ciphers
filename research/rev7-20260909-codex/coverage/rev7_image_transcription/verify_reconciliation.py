#!/usr/bin/env python3
"""Read-only replay of the three-stage image transcription reconciliation."""
import hashlib,json,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent;REPO=HERE.parents[3]
PINS={"transcription.txt":"8eaa8bd0156fa523a696ce8a22cdde677d2a3621bc54367ae71002d0e375024a","transcription.json":"058a71fb00c0dc3585141cf6a7258b656ea67c0f6b83e8637d37a616055b6ccf","adjudication.json":"b815d33176318d5abf22124ebbb2abaddf59afb35e791bf9798557bcd52ea749","adjudicated_transcription.txt":"1702381306e7a543ceafad11343fc3432e19914001168f9f02fe7e019a17e215","reconciliation.json":"d4d8518c3b407c8fff2d13585db988f6dcc05725767642f591e1e9fa7f4fc964"}
IMAGE=REPO/"lavender/src/assets/revelations_7.png";MDX=REPO/"lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx";DATASET=REPO/"lavender/src/data/ciphers/revelations.json"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def joined(lines):return "".join("".join(x.split()) for x in lines)
def main():
 for rel,h in PINS.items():assert sha(HERE/rel)==h,(rel,sha(HERE/rel),h)
 assert sha(IMAGE)=="36a1883ede6abadcf4d4420f26484ca81134f3b62fe0ac7521352c682bf0b3b7" and struct.unpack(">II",IMAGE.read_bytes()[16:24])==(981,412)
 original=(HERE/"transcription.txt").read_text().splitlines();corrected=(HERE/"adjudicated_transcription.txt").read_text().splitlines();assert len(original)==len(corrected)==16
 expected=list(original);changes=[(5,6,3,"4","A"),(13,6,2,"E","F")]
 for li,gi,ci,old,new in changes:
  groups=expected[li].split();assert groups[gi][ci]==old;groups[gi]=groups[gi][:ci]+new+groups[gi][ci+1:];expected[li]=" ".join(groups)
 assert expected==corrected
 diffs=[i+1 for i,(a,b) in enumerate(zip(joined(original),joined(corrected))) if a!=b];assert diffs==[381,935]
 corr=joined(corrected);assert len(corr)==1092 and hashlib.sha256(corr.encode()).hexdigest()=="5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
 mdx=MDX.read_text();tick=chr(96);start=mdx.index(tick+"83 B57B2")+1;end=mdx.index(tick,start);m="".join(mdx[start:end].split()).upper()
 records=json.loads(DATASET.read_text());d="".join(next(x for x in records if x["id"]=="rev7")["ciphertext"].split()).upper()
 assert sha(MDX)=="085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91";assert sha(DATASET)=="68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e"
 assert corr==m==d
 ledger=json.loads((HERE/"reconciliation.json").read_text());assert ledger["identity"]=="ASTRA" and ledger["target_evaluated"] is False and ledger["stages"][2]["mdx_exact_match"] and ledger["stages"][2]["dataset_exact_match"]
 print(json.dumps({"ok":True,"identity":"ASTRA","verification":"image adjudication application and repository-record equality; no cipher run","glyphs":1092,"applied_changes":2,"joined_sha256":hashlib.sha256(corr.encode()).hexdigest(),"mdx_exact_match":True,"dataset_exact_match":True},indent=2,sort_keys=True))
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Inventory local tools4noobs HTML forms and provenance strings; no network."""
import argparse, hashlib, json, re
from html.parser import HTMLParser
from pathlib import Path
class P(HTMLParser):
 def __init__(self): super().__init__(); self.forms=[]; self.cur=None; self.sel=None
 def handle_starttag(self,t,a):
  d=dict(a)
  if t=="form": self.cur={"attrs":d,"inputs":[],"selects":[]}; self.forms.append(self.cur)
  elif self.cur and t=="select": self.sel={"attrs":d,"options":[]}; self.cur["selects"].append(self.sel)
  elif self.cur and t=="option" and self.sel: self.sel["options"].append(d)
  elif self.cur and t in ("input","textarea"): self.cur["inputs"].append({"tag":t,"attrs":d})
 def handle_endtag(self,t):
  if t=="select": self.sel=None
EXPECTED={"encrypt_2014-01.html":"82d984d7c57eacda0c44caeebd6c1fae063f6eecca1d5e5cfdeea27a1f715fb7","encrypt_capture_20150910.html":"5a86122f5680a1974624beca07aeb3cc9bc20978b506912ab3cbdfb93b9fa3cd","encrypt_20171028.html":"f850ddd38f398554cb0b1640ebb0a3bb346301cc71ecd04898d08cc480a13c52","base_convert.html":"bc00bbde98b3211491f5fdc60fe2c18b8b5fc050b62269bcc78596fd57ea9513"}
def main():
 ap=argparse.ArgumentParser(); ap.add_argument("input_directory",nargs="?",default="/private/tmp/rev7-fable-20260909/t4n"); ap.add_argument("-o","--output",default="-"); args=ap.parse_args(); base=Path(args.input_directory); out={"identity":"ASTRA","directory":str(base),"files":{},"capture_evidence":{}}
 for f in EXPECTED:
  b=(base/f).read_bytes(); txt=b.decode("utf8","replace"); p=P(); p.feed(txt); h=hashlib.sha256(b).hexdigest()
  out["files"][f]={"size":len(b),"sha256":h,"expected_sha256":EXPECTED[f],"hash_match":h==EXPECTED[f],"forms":p.forms,"archive_date_strings":sorted(set(re.findall(r"(?:19|20)\d{2}[01]\d[0-3]\d(?:[01]\d)?",txt))),"timestamp_context":sorted(set(re.findall(r".{0,35}(?:capture|timestamp|archive|2016-09-01|20160901).{0,55}",txt,re.I)))[:20],"precision_context":sorted(set(re.findall(r".{0,55}(?:precision|large number|arbitrary|warning).{0,85}",txt,re.I)))[:20]}
 for evidence in ("hdr_exact.txt","cdx_encrypt_2014_2017.txt"):
  ep=base/evidence
  if ep.exists():
   et=ep.read_text(errors="replace")
   out["capture_evidence"][evidence]={"sha256":hashlib.sha256(ep.read_bytes()).hexdigest(),"memento_datetime":sorted(set(re.findall(r"memento-datetime:\s*([^\r\n]+)",et,re.I))),"archive_orig_date":sorted(set(re.findall(r"x-archive-orig-date:\s*([^\r\n]+)",et,re.I))),"status_lines":[x for x in et.splitlines() if re.match(r"^HTTP/|^Date:|^location:|^Link:|^20\d{12}\s",x,re.I)]}
 data=json.dumps(out,indent=2,sort_keys=True)+"\n"
 if args.output=="-": print(data,end="")
 else: Path(args.output).write_text(data)
if __name__=="__main__": main()

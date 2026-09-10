#!/usr/bin/env python3
"""ASTRA exact D-threshold table derived from the published occupancy recurrence."""
from __future__ import annotations
import argparse,hashlib,json
from decimal import Decimal,localcontext
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];OUT=HERE/'threshold_table.json'
OCC=ROOT/'research/rev7-20260909-codex/coverage/distinct_byte_occupancy/occupancy.py'
OCC_SHA='2506d407801a6f581ecfe01b91d71bf6e9a4a0524104ec582f5ef22cb2df3cd9';SCALE=10**15
N_MIN=128;N_MAX=1092;M=256
def sha(path):return hashlib.sha256(Path(path).read_bytes()).hexdigest()
def dec_log(num,den):
 if not num:return '0E+0','-Infinity'
 with localcontext() as c:
  c.prec=70;x=Decimal(num)/Decimal(den)
  return format(x,'.30E'),format(x.log10(),'.24f')
def generate():
 assert sha(OCC)==OCC_SHA
 c=[1]+[0]*M;rows=[]
 for n in range(1,N_MAX+1):
  old=c;c=[0]*(M+1)
  for k in range(1,min(n,M)+1):c[k]=k*old[k]+(M-k+1)*old[k-1]
  den=M**n;assert sum(c)==den
  if n<N_MIN:continue
  total=0;d=-1
  for k,v in enumerate(c):
   total+=v
   if total*SCALE<=den:d=k
   else:break
  assert 0<=d<M
  lo=sum(c[:d+1]);hi=lo+c[d+1]
  assert lo*SCALE<=den<hi*SCALE
  lp,ll=dec_log(lo,den);hp,hl=dec_log(hi,den)
  rows.append({'n':n,'d':d,'tail_decimal':lp,'tail_log10':ll,'tail_numerator_sha256':hashlib.sha256(str(lo).encode()).hexdigest(),'next_d':d+1,'next_tail_decimal':hp,'next_tail_log10':hl,'next_tail_numerator_sha256':hashlib.sha256(str(hi).encode()).hexdigest()})
 assert len(rows)==N_MAX-N_MIN+1 and rows[0]['n']==N_MIN and rows[-1]['n']==N_MAX
 return {'identity':'ASTRA','target_evaluated':False,'model':{'labels':M,'n_min':N_MIN,'n_max':N_MAX,'threshold_probability':'1/10^15','recurrence':'C[n,k]=k*C[n-1,k]+(256-k+1)*C[n-1,k-1]','threshold':'largest d with sum(C[n,0..d])*10^15 <= 256^n'},'exact_assertions':{'every_d_tail_times_10pow15_le_256powN':True,'every_next_tail_times_10pow15_gt_256powN':True},'rows':rows,'source_pins':{'published_occupancy.py':OCC_SHA,'build_table.py':sha(Path(__file__))},'limits':'Provisional iid-uniform per-output occupancy screen only. No actual comparison count, cipher-output probability, encoding membership, or target conclusion.'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',metavar='NEW_PATH');a=ap.parse_args();got=generate()
 if a.generate:
  q=Path(a.generate);assert not q.exists(),'refuse overwrite';q.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':'ASTRA','generated':str(q),'sha256':sha(q),'rows':len(got['rows'])},sort_keys=True));return
 assert OUT.exists();assert json.loads(OUT.read_text())==got
 print(json.dumps({'identity':'ASTRA','verified':True,'table_sha256':sha(OUT),'rows':len(got['rows']),'range':[N_MIN,N_MAX]},sort_keys=True))
if __name__=='__main__':main()

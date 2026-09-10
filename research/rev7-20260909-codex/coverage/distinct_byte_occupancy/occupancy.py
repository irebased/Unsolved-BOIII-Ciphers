#!/usr/bin/env python3
"""Exact occupancy distribution for n independent uniform draws over m labelled values."""
from __future__ import annotations
import argparse,hashlib,itertools,json,math
from decimal import Decimal,localcontext
from fractions import Fraction
from pathlib import Path
HERE=Path(__file__).resolve().parent;LEDGER=HERE/'evidence.json';IDENTITY='ASTRA';M_TRIALS=2_080_899_072
THRESHOLDS=(64,95,128,160,192,200,213,226);LENGTHS=(90,128,256,546)
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def distribution(n,m):
 if n<0 or m<1:raise ValueError((n,m))
 c=[0]*(min(n,m)+1);c[0]=1
 for draws in range(1,n+1):
  old=c;c=[0]*(min(draws,m)+1)
  for k in range(1,len(c)):
   c[k]=k*(old[k] if k<len(old) else 0)+(m-k+1)*old[k-1]
 assert sum(c)==m**n
 return c
def moments_formula(n,m):
 # Exact rational occupancy moments from indicator variables.
 den=m**n;a=(m-1)**n;b=(m-2)**n if m>=2 else 0
 p=Fraction(den-a,den);both=Fraction(den-2*a+b,den)
 mean=m*p;variance=m*p*(1-p)+m*(m-1)*(both-p*p)
 return mean,variance
def moments_distribution(c,m,n):
 den=m**n;mean=sum(k*v for k,v in enumerate(c));second=sum(k*k*v for k,v in enumerate(c))
 return Fraction(mean,den),Fraction(second,den)-Fraction(mean,den)**2
def dec(fr,precision=60):
 with localcontext() as ctx:
  ctx.prec=precision;x=Decimal(fr.numerator)/Decimal(fr.denominator)
  return format(x,'.30E'),format(x.log10(),'.24f') if x else '-Infinity'
def tail_record(c,n,m,t):
 num=sum(c[:min(t,len(c)-1)+1]);den=m**n;f=Fraction(num,den);prob,log10=dec(f)
 mean,var=moments_formula(n,m)
 with localcontext() as ctx:
  ctx.prec=60;z=(Decimal(t)-Decimal(mean.numerator)/Decimal(mean.denominator))/(Decimal(var.numerator)/Decimal(var.denominator)).sqrt()
 ub=min(Fraction(1),f*M_TRIALS);ubp,ublog=dec(ub);expected=f*M_TRIALS;exp_p,exp_log=dec(expected)
 return {'threshold_le':t,'sequence_count':str(num),'total_sequences':str(den),'reduced_numerator':str(f.numerator),'reduced_denominator':str(f.denominator),'probability_decimal':prob,'log10_probability':log10,'normal_distance_z_at_threshold':format(z,'.12f'),'hypothetical_comparisons':M_TRIALS,'expected_hits_under_iid_model_decimal':exp_p,'log10_expected_hits':exp_log,'union_bound_decimal':ubp,'log10_union_bound':ublog}
def tiny_controls():
 rows=[]
 for m in range(1,6):
  for n in range(0,8):
   c=distribution(n,m);brute=[0]*(min(n,m)+1)
   for x in itertools.product(range(m),repeat=n):brute[len(set(x))]+=1
   assert c==brute
   mf,vf=moments_formula(n,m);md,vd=moments_distribution(c,m,n);assert (mf,vf)==(md,vd)
   rows.append({'m':m,'n':n,'counts':c,'total':sum(c),'mean':str(mf),'variance':str(vf)})
 return rows
def generate():
 controls=tiny_controls();c=distribution(546,256);mean,var=moments_formula(546,256);md,vd=moments_distribution(c,256,546);assert (mean,var)==(md,vd)
 pmean,_=dec(mean);pvar,_=dec(var)
 with localcontext() as ctx:ctx.prec=60;sd=(Decimal(var.numerator)/Decimal(var.denominator)).sqrt()
 tails=[tail_record(c,546,256,t) for t in THRESHOLDS]
 scaling=[]
 for n in LENGTHS:
  d=distribution(n,256);mu,va=moments_formula(n,256);pr=tail_record(d,n,256,64)
  with localcontext() as ctx:ctx.prec=60;s=(Decimal(va.numerator)/Decimal(va.denominator)).sqrt()
  scaling.append({'n':n,'mean_decimal':dec(mu)[0],'sd_decimal':format(s,'.15f'),'threshold_le':64,'tail_probability_decimal':pr['probability_decimal'],'log10_tail_probability':pr['log10_probability']})
 return {'identity':IDENTITY,'target_evaluated':False,'model':{'draws':546,'labels':256,'assumption':'iid uniform labelled bytes','recurrence':'C[n,k]=k*C[n-1,k]+(m-k+1)*C[n-1,k-1]','denominator':'m**n'},'distribution_sha256':hashlib.sha256(json.dumps([str(x) for x in c],separators=(',',':')).encode()).hexdigest(),'mean_exact':str(mean),'variance_exact':str(var),'mean_decimal':pmean,'variance_decimal':pvar,'sd_decimal':format(sd,'.15f'),'tails':tails,'length_scaling_at_D_le_64':scaling,'tiny_exhaustive_controls':controls,'control_cases':len(controls),'assertions':{'distribution_total_equals_256_pow_546':sum(c)==256**546,'formula_and_distribution_moments_equal':True,'tiny_exhaustive_counts_equal':True},'caveats':['Normal z is descriptive and is not used as a Gaussian tail probability.','The union bound uses a hypothetical 2,080,899,072 comparisons; it is not a retained-output count or an independence correction.','Threshold, length, iid-uniform model validity, and multiple-comparison accounting remain analysis choices.','A byte occupancy statistic cannot detect structure that remains binary or has not yet been decoded into the tested byte alphabet.'],'source_sha256':sha(Path(__file__))}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();out=generate()
 if a.generate:
  assert not a.generate.exists(),'refuse overwrite';a.generate.write_text(json.dumps(out,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'status':'GENERATED','path':str(a.generate),'sha256':sha(a.generate)},sort_keys=True));return
 saved=json.loads(LEDGER.read_text());assert out==saved;print(json.dumps({'identity':IDENTITY,'status':'PASS','ledger_sha256':sha(LEDGER),'tiny_controls':len(out['tiny_exhaustive_controls']),'tails':len(out['tails'])},sort_keys=True))
if __name__=='__main__':main()

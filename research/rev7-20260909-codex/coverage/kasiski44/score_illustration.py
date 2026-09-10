#!/usr/bin/env python3
"""ASTRA hypothetical count-score illustration; no Rev7 or outside tool model."""
import json,math
lam=0.2;k=3;periods=79
z=(k-lam)/math.sqrt(lam)
poisson_tail=1-math.exp(-lam)*sum(lam**j/math.factorial(j) for j in range(k))
normal_tail=0.5*math.erfc(z/math.sqrt(2))
print(json.dumps({'identity':'ASTRA','target_evaluated':False,'hypothetical_only':True,'outside_program_formula_known':False,'assumed_Poisson_mean':lam,'observed_count':k,'count_standardized_Z':z,'exact_Poisson_tail_at_least_3':poisson_tail,'standard_normal_tail_at_same_Z':normal_tail,'illustrative_tests':periods,'union_bound_no_independence_required':min(1,periods*poisson_tail)},sort_keys=True,indent=2))

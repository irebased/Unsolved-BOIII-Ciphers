# Exact distinct-byte occupancy under an iid-uniform model

Identity: ASTRA. Let `D` be the number of distinct labels seen in `n` independent uniform draws from `m` labelled values. The number of length-`n` sequences with exactly `k` occupied labels obeys

```
C[n,k] = k C[n-1,k] + (m-k+1) C[n-1,k-1],   C[0,0]=1.
```

The ledger retains the exact integer sequence count and the unreduced denominator `m**n`, as well as the reduced rational and a high-precision decimal. Exhaustive enumeration for all `m=1..5`, `n=0..7` matches the recurrence. Exact moments from the distribution match the independent indicator-variable formulas.

For `n=546`, `m=256`, the exact mean is approximately **225.7895341660**, the variance **19.0436769729**, and the standard deviation **4.3639061600**. This reproduces the scale of the proposed 225.79/4.36 figures.

| D threshold | Exact-tail decimal P(D≤threshold) | log10 tail | Raw distance `(threshold-mean)/sd` |
|---:|---:|---:|---:|
| 64 | 3.54728754919e-268 | -267.4501 | -37.0745 |
| 95 | 7.06057362185e-164 | -163.1512 | -29.9707 |
| 128 | 4.05373244176e-90 | -89.3921 | -22.4087 |
| 160 | 2.45562367942e-42 | -41.6098 | -15.0758 |
| 192 | 4.86647791308e-13 | -12.3128 | -7.7430 |
| 200 | 2.04598503781e-8 | -7.6891 | -5.9097 |
| 213 | 3.07218625311e-3 | -2.5126 | -2.9308 |
| 226 | 5.59361396140e-1 | -0.2523 | 0.0482 |

The last column is a descriptive distance using the exact mean and variance. It is not a Gaussian tail probability; the exact DP tail is the probability reported here. At the fixed threshold `D≤64`, exact tail probabilities change from `1.0940e-4` at length 90 to `2.4192e-21` at 128, `4.3504e-94` at 256, and `3.5473e-268` at 546.

The ledger also multiplies each exact tail by the hypothetical comparison count `M=2,080,899,072` and records `min(1,Mp)` as a union-bound illustration. This is not an assertion that FABLE retained that many outputs, that its trials are iid uniform, or that the comparisons are independent. A defensible detection threshold still requires a declared length, null model, calibration rule, and accounting for the comparisons actually made.

This oracle concerns occupancy in a fixed byte alphabet after decoding. It cannot see structure that remains binary, lies in another encoding, or emerges only after later fractionation/decoding layers. A low distinct-byte count can be strong evidence against the iid-uniform model without being a mathematical exclusion of a cryptographic or classical pipeline.

Default verification is read-only:

```sh
python3 -B research/rev7-20260909-codex/coverage/distinct_byte_occupancy/occupancy.py
```

Explicit generation refuses an existing destination:

```sh
python3 -B research/rev7-20260909-codex/coverage/distinct_byte_occupancy/occupancy.py --generate /tmp/new-occupancy-evidence.json
```

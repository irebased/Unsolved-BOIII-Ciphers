# ASTRA independent audit: bounded numeral probes

```json
{
  "identity": "ASTRA",
  "status": "No plaintext or validated intermediate layer recovered",
  "scope": "Independent audit of the periodic base-26/27 scan, fixed hexadecimal chunk to decimal endpoints, and visible-group hexadecimal to octal endpoints",
  "canonical_ciphertext_sha256": "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
}
```

The SHA-256 domain above is the 1,092-character repository transcription after removing whitespace and converting letters to uppercase, encoded as ASCII. The earlier octal draft's `bb530000...` digest is the same text lowercased; it did not state that domain clearly.

## Periodic base-26/27 scan

An independent implementation reproduced all 1,920 saved target rows exactly: two bases, four direct hex orientations, three restored-zero counts, two rendered-stream directions, and periods 1 through 40. The target maxima are:

| Base | Maximum pooled within-column IoC | Parameters |
|---:|---:|---|
| 26 | 0.04257224257224257 | byte reverse; one restored zero; period 34 |
| 27 | 0.041809940606439513 | nibble swap; two restored zeros; period 32 |

Conversion and boundary checks cover all four distinct 1,092-symbol orientations. Each orientation is read as one base-16 integer and converted canonically to base 26 or 27. A restored zero is prepended to that canonical digit stream. The `reverse` label reverses the resulting coordinate stream after zero restoration. Removing that reversal and the exact declared zero prefix reconstructs the starting orientation's integer in every case.

The pooled statistic is exactly invariant under full stream reversal because reversal only permutes residue columns. The 960 reversal-labelled target rows are therefore duplicate statistic values, although reversal can remain a meaningful label for later position-sensitive operations.

The original null comparison needs correction. Its reported 99.49% and 99.88% figures are the fractions of individual null rows **at or below** the target-grid maximum; the table labels the inequality in the other direction. A single target maximum should be compared with one full-grid maximum per null replicate, not with a bag of 192,000 individual period values.

The corrected audit uses 200 deterministic Monte Carlo replicates. Within each replicate and base, it independently shuffles each orientation's canonical converted digit stream once, then derives the three zero-prefix cases. Reversal is omitted from computation because its pooled IoC is identical. The replicate statistic is the maximum over the same complete target grid. This null is conditional on each base/orientation symbol multiset and treats the four orientations as independent conditioned streams; it is not a generative model of ciphertext orientations.

| Base | Null grid-max median | Null grid-max range | Replicates ≥ target | Plus-one Monte Carlo p |
|---:|---:|---:|---:|---:|
| 26 | 0.0427128757334707 | 0.04116022099447514–0.0455072463768116 | 113/200 | 0.5671641791044776 |
| 27 | 0.0409874221006232 | 0.03941947565543071–0.043859649122807015 | 42/200 | 0.21393034825870647 |

Under this explicitly stated conditional null, neither aggregate maximum is unusual. This supports the narrow statement that the completed grid shows no unusual periodic-column concentration. It does not exclude a periodic cipher: IoC is only a detector, the periods and restored-zero range are bounded, and preprocessing or another layer can flatten frequencies.

The corrected numeric controls test modular decryption directly, include symbol 26 in base 27, and demonstrate that whole-integer conversion loses an actual leading zero unless it is restored. This avoids the original base-27 text-rendering bug, where the pre-modulo condition could emit `[` in noncanonical rows.

## Fixed hexadecimal chunks to decimal

The independent dynamic program reproduced the declared 480 labelled decimal streams, 352 unique streams, and 1,440 parser records. It found zero complete endpoints under canonical minimal one-to-three-digit decimal tokens, fixed two-digit tokens, or fixed three-digit tokens, with the exact allowed byte set TAB (9), LF (10), CR (13), and printable ASCII 32 through 126. Every saved target record matched. The audit also performed 240 exact chunk serialization/inverse checks and positive controls for all three parsers.

This result applies only to hexadecimal chunk widths 2 through 16, both ragged-edge alignments, minimal or full-chunk-width padded decimal, the four direct orientations, and whole decimal-stream reversal. It does not cover arbitrary token boundaries, other character sets, whole-integer conversion, or another layer.

## Visible-group hexadecimal to octal

The corrected independent scan covers 32 rows: four orientations, left or right placement of the two-symbol ragged group, minimal or maximum-width per-group octal, and whole octal-stream reversal. Neither fixed three-octal-digit parsing nor canonical variable two/three-octal-digit parsing reaches a complete allowed-text endpoint. Sixteen serializer/inverse checks reconstruct every oriented hex string exactly.

The earlier draft incorrectly allowed VT (11) and FF (12) and omitted CR (13). Its synthetic checks did not assert the corrected endpoint. The audit uses the exact allowed set and asserts variable and fixed parser positives, CR acceptance, VT/FF rejection, and minimal/fixed group round trips.

## Reproduction

Run from the repository root with Python 3.9 or newer; the scripts use only the standard library:

```sh
python3 research/rev7-20260909-codex/audit/periodic_audit.py --repetitions 200
python3 research/rev7-20260909-codex/audit/decimal_audit.py
python3 research/rev7-20260909-codex/audit/octal_audit.py
```

The periodic seed is `20260910`. Its compact result includes all target rows and 200 grid maxima per base, so the 73 MB exploratory null-row file is not required for regeneration or review. If the exploratory target file is locally present, the script additionally reports the exact comparison; if absent, it runs standalone.

A publication-layout portability check copied only the three audit scripts and `rev7.mdx` into a temporary repository-shaped directory. The periodic script completed with one null replicate and reported the owner comparison unavailable; the decimal script completed with the same 480/352/1,440/zero target summary. This confirms that the large exploratory artifacts are optional.

| Artifact | SHA-256 |
|---|---|
| `periodic_audit.py` | `43fa9485f608f1d7de1864a4a33d6d4f32d5efd3fbc4d774b210e517511ce7df` |
| `periodic_audit_results.json` | `83f72743c7ffba3f2db67ff1f0cf6c4d5c0ffc4472fd301a0915c493cf72ab47` |
| `decimal_audit.py` | `2db4af348ad3f8a691a74854d0b14ed45b74c2a61b7ae364c587a0ff681c56f4` |
| `decimal_audit_results.json` | `facb97e0458c8e32e34c5a03bb2f1329f88513ed814255517cf84fbd3696cf2f` |
| `octal_audit.py` | `e25cfe75323e941a0fc951b518b43f6dfc5c4473c0bb125048d227c8e40e05a0` |
| `octal_audit_results.json` | `8b6f059370dc9e6cdbe427f76e7fedd5cdbb3df4e3d5eff93c8b27122637fddd` |

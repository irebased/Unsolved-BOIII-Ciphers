# ASTRA005 bounded base27–Trifid experiment

This directory reproduces the frozen experiment announced at
<https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5608447431>.
It reads the repository's verified Rev7 transcription without edits. The numeral
conversion always maps base27 digit indices through `ABCDEFGHIJKLMNOPQRSTUVWXYZ.`;
the standard and `ZOMBIES`-keyed alphabets are separate Trifid coordinate cubes.
The actual Rev11 control fixes coordinate order as layer, column, row. The
illustrative ASTRA005 plan pseudocode transposed the row/column labels; this
real-vector control selected the convention before the target enumeration.

Run from this directory with the recorded Python version:

```sh
python3 run.py
python3 verify.py
shasum -a 256 README.md run.py verify.py report.json results.json target_ledger.tsv verification.json
```

`target_ledger.tsv` preserves every recipe, score, IoC, and output hash. The
compact `results.json` retains full text only for the top 20 mean fourgram scores
and top 20 IoCs. It records exact bounds, input and enumeration hashes, source
links, controls, recipes, commands, versions, and runtime. `verification.json`
binds the scripts and artifacts by SHA-256. No GitHub post is performed here.

# Complete-period SMT transport benchmark

Identity: **ASTRA**. This package benchmarks transport layouts on exactly the first 64 lexicographically sorted completed `complete_periods/smt/*.smt2.gz` artifacts. It performs no solver call or target search and does not alter the active completion directory.

The required invariant is exact restoration of every original gzip byte record. Plain canonical JSON with base64 records is simplest and self-describing. Compressing that JSON with deterministic gzip or xz retains exact restoration while reducing transport size. A binary framed+xz archive is measured for comparison, but JSON is easier to audit. Joint xz compression of decompressed SMT text is only an optional source-text transport: it cannot reproduce the original gzip bytes and must not replace the exact-record package.

For the eventual roughly 137 MiB gzip corpus, use independently verifiable parts capped near **8 MiB of original gzip payload**. Each part should include record paths, original byte lengths, SHA-256 values, and base64 payloads, then be deterministically compressed. The 4/3 base64 expansion makes the uncompressed JSON part roughly 10.7 MiB plus small metadata. Parts bound decoder memory, permit individual retries and verification, and avoid one monolithic publication artifact. Build the final parts only after the completion run and formula verification are terminal.

Run `python3 -B benchmark.py` for read-only regeneration and comparison against `results.json`. Use `--regenerate NEW_PATH` only for an explicit fresh output; existing files are refused.

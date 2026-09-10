# Lazy byte-AMSCO all-IV search controls (ASTRA)

This synthetic-only package implements the prospective width-2-through-9 byte-AMSCO search without reading or evaluating Rev7. It imports the immutable accepted byte-AMSCO geometry and the accepted seven-backend cascade runtime through explicit SHA-256 pins.

## Search geometry

For each `(length,width,start)` geometry, `Geometry.build` precomputes three arrays once:

- the byte length of every natural column;
- the natural column containing every recovered byte index; and
- that byte's offset within its natural column.

For an order, `starts(order)` needs only `O(width)` work to locate each observed column chunk. A recovered ciphertext byte is then one indexed lookup. The engine gathers one shared natural ciphertext prefix lazily for all seven backends. Each backend begins at its 8- or 16-byte block boundary and stops independently at its earliest A105 or five-sequence-FSA failure. Gathering stops when every backend has failed. A survivor reaches the true end, contains FSA state 0, and retains its exact order and complete suffix bytes. Rejections retain the first failure offset and byte/state witness plus digests of the tested suffix and recovered ciphertext prefix.

`scan_geometry` exhausts every order and asserts exactly `width! × backend_count` contexts. Its `order_limit` exists only for explicitly bounded synthetic benchmarks.

## Prospective finite grid

Widths 2–9, both alternating starts, every column order, and four byte orientations give 3,272,896 transforms. Seven backends give exactly 22,910,272 contexts. Each backend represents every external IV through the IV-independent CFB8 suffix beginning at its block size. The suffix FSA starts in `{0,1,2}` and requires state 0 at the true stream end.

No native implementation is justified by the current control benchmark. The 20,000-order width-9 sample evaluated 140,000 backend contexts in about 0.48 seconds on the recorded host, a linear estimate around 79 seconds for the registered context count. This estimate is synthetic and excludes target extraction, checkpointing, survivor output, and platform variance.

## Controls

The ledger records:

- 43,600 small-geometry cases, all permutations at widths 2–6 and lengths 0–24, matching the accepted independent inverse;
- retained 546-byte plants for every backend, both starts, and all four orientations;
- exact suffix agreement with independent full-CFB references;
- 28 random early-rejection comparisons, including exact first offsets and bytes;
- incoming FSA states 1 and 2 plus strict terminal rejection for every backend; and
- the 20,000-order production `scan_geometry` benchmark.

Portable source and ledger verification:

```sh
python3 -S -B research/byte_amsco/astra/search/controls.py
```

Cryptographic regeneration requires PyCryptodome and clang and refuses an existing output:

```sh
python3 -B research/byte_amsco/astra/search/controls.py \
  --regenerate /tmp/byte-amsco-search-controls.json
```

## Limits

This is a byte-unit AMSCO analogue with continuous 1/2 alternation, not a claim about a historical character frontend. It covers only widths 2–9, starts 1 and 2, the four registered byte orientations, fixed `Zombies` backend conventions, ordinary CFB8, and the registered endpoint alphabet. It does not search Rev7, establish a key or pipeline, cover other widths, add framing/encodings, or recover the unknown IV-dependent prefix.

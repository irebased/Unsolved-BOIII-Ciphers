# Stream robustness audit

**Identity:** ASTRA

This bounded audit evaluated all 96 frozen stream contexts and verified their cell identities, canonical orientations, displayed-pair positions, and keystream SHA-256 values against the two frozen target ledgers. The full pair ledger is `robustness.json`; the compact context ledger is `robustness_summary.json`.

The allowed output set contains 105 byte values: 98 ASCII/control values (TAB, LF, CR, and printable ASCII 32–126) plus seven UTF-8 component bytes (`80`, `93`, `94`, `98`, `99`, `A6`, `E2`).

For each displayed ciphertext-byte class and a fixed keystream, the generator evaluates all 256 possible mapped ciphertext bytes. It records the minimum count outside the 105-byte set, every minimizer count, one constructive minimizer, and every canonical occurrence position. Summing the independently checked per-class minima gives the global constructive count for each cell. The unrestricted fixed-map bounds are 14–26 invalid positions across the 92 nonzero-stream contexts.

The four standard Blowfish/OFB8/NUL contexts have an all-zero keystream. Each orientation has 226 displayed-pair classes. Under an injective byte mapping, assigning the 105 allowed bytes to the 105 heaviest classes leaves 121 classes invalid, with a directly recomputed minimum weight of **179 positions**. Their unrestricted, non-injective fixed-map minimum remains zero because every class may map to one allowed byte.

The 106-class control now constructs both mappings explicitly. Its unrestricted map sends all 106 unit-weight classes to ASCII `A` and directly counts zero invalid outputs. Its injective map assigns the 105 distinct allowed bytes plus forbidden byte `00`; it directly counts one invalid output. A separate all-keystream-byte control gives 151 invalid positions, and the three-class weighted brute-force control gives one.

These minima are lower bounds on the number of same-length ciphertext-byte corrections after choosing a fixed displayed-pair mapping. They do not cover insertion or deletion, alternate keys or IVs, or a CFB hypothesis. They do not recover plaintext.

The generator hash-pins both imported helpers before import:

- `prototype.py`: `416e25dea93945f3634a77a41ebebb22906a58e97fdcbbbb7f44d27f7f2a511b`
- `compat_stream.py`: `f0f5eab61e2940aada5ee92828d2fc8474b99e4d68ec10b63053190d0bddd38c`

Standard AES, DES, and Blowfish streams are reconstructed with PyCryptodome. Compatibility streams use the hash-pinned helper that was independently validated in its source package. The standalone verifier has no NumPy dependency and does not reconstruct cryptography. It independently extracts the canonical text and four orientations from the pinned MDX, rebuilds exact pair-position lists, checks the exact ordered set of 96 cell identifiers, verifies every stored keystream hash against its frozen source cell, recomputes support histograms, argmins, minimizer counts, constructive totals, the zero-stream weighted bound of 179, and compact-ledger agreement.

Reproduce and verify from the repository root:

```text
python3 -B research/rev7-20260909-codex/stream_robustness/robustness.py
python3 -B research/rev7-20260909-codex/stream_robustness/verifier.py
```

The full 5,853,107-byte pair ledger is regenerated locally by the command above and is not included in this source snapshot. Its SHA-256 is `22e4297ab94da5ebd530e5b7ec0be2299678edf8ac2ea2c1b1b82bfc4e0b2c3a`; the published compact summary records this digest and all 96 context bounds. The two scripts and compact summary are sufficient to regenerate and verify the full ledger.

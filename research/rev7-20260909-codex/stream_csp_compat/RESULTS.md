# Blowfish-compat OFB stream-CSP target results

Identity: ASTRA. Completed 2026-09-10 with the registered command:

    cd /private/tmp/rev7-astra-20260909
    python3 -B research/rev7-20260909-codex/stream_csp_compat/run_target.py --run-target

## Result

All 24 cells completed below the 1,000,000 accepted-node cap. Every cell was
unsatisfiable during root support propagation and therefore visited zero
accepted CSP nodes. In each cell, rejected plus relaxed-terminal bijection
weight is exactly 16! = 20,922,789,888,000. There were zero relaxed survivors
and zero final endpoint-FSA survivors.

All 24 cells also carry a stronger repeated-pair witness. The witness assumes a
displayed pair receives one fixed ciphertext byte at every occurrence. It
directly exhausts all 256 choices for that byte and finds none that makes every
listed occurrence pass the relaxed predicate. It therefore excludes every
fixed global byte mapping for the witnessed pair, including nonbijective byte
mappings, and is stronger than the hexadecimal-nibble bijection result.

Representative exact witnesses:

- Historical OFB8, ASCII-zero IV, forward: displayed pair 0E at byte positions
  144, 212, 215, 281, and 487; keystream bytes 2d, 3b, 1b, f2, and 79.
  Checking all 256 ciphertext bytes leaves an empty set. The keystream SHA-256
  is 1ee81d2ab737d2c264ffc74c4a9cae05a208267a8ac93bbdc35fab2bdabbd37c.
- Full-block OFB, SHA-1-prefix IV 4711f7565028433a, forward: displayed pair 00
  at byte positions 18, 192, 198, 309, and 342; keystream bytes 35, be, 78, 1e,
  and ee. Checking all 256 ciphertext bytes leaves an empty set. The keystream
  SHA-256 is
  7f697cce6439e3dec4364e23ea73208b79f6c29e99f9c72309ce4c53d7b5da20.

Summed CSP time was 0.327613 seconds, with individual cells between 0.012598
and 0.015738 seconds. The complete process wall time was about 0.387 seconds.

## Independent verification

verify_witnesses.py imports none of the CSP core, compatibility stream helper,
or target driver. It independently extracts and orients the canonical
ciphertext, uses PyCryptodome standard Blowfish with raw seven-byte Zombies,
applies the source-proven word-reversal conjugation, reconstructs both stream
modes, verifies every stored keystream hash and witness position, and directly
enumerates all 256 ciphertext bytes for every one of the 24 witnesses. It also
checks every full 16! certificate and zero-survivor record.

    cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/stream_csp_compat
    python3 -B verify_witnesses.py

All 24 rows passed. Artifact hashes:

- verify_witnesses.py: 341e8b3e30a9e72f773075a30de243c861058c627176e52c6388ae28fd57b5f0
- verification.json: 1937e53cdbb0487e8ff95326f3a1a131d7402eb3374d0556030f2508ef2d35d6
- target_results.json:
  598dfa8ec497321f62f1b4f445de4f642f755ef0fb51c9d2164c708145aad7f2

## Source and build provenance

The target result is bound to raw key 5a6f6d62696573, the compiled pinned
libmcrypt Blowfish-compat primitive, the actual historical OFB8 mode controls,
the frozen stream CSP, and the canonical Rev7 MDX hash.

This command checks the frozen source-check ledger's identity, expected rows,
and file hash. It does not recreate or rebuild the source result:

    cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/stream_csp_compat
    python3 -B ../hex_cfb/native_compat/source_check.py --verify-existing --output ../hex_cfb/native_compat/source_check_reproduction.json

The source-check reproduction SHA-256 is
123724d5575fa7c2be2868d8218f774f775a395eae693e2049caa703eee47295.
To rebuild the pinned standard and compatibility libraries, first copy the
native_compat source-check directory, then run these commands inside that copy:

    cd /path/to/copied/native_compat
    clang -shared -fPIC -O2 -Isource_build -Isource source/blowfish.c -o source_build/libblowfish.so
    clang -shared -fPIC -O2 -Isource_build -Isource source/blowfish-compat.c -o source_build/libblowfish_compat.so

Using a copy preserves the frozen gated binary. That binary's SHA-256 is
62ba2b2d1d104aa16c8a855b8bd29af3f6ed987c0008b3a8ba20c22f12e0a319.
The raw-seven-byte actual-C source reproduction establishes the compatibility
conjugation used by the independent verifier. The separate 200-vector control
also confirms word reversal for its supplied 16-byte-key upstream vectors.

## Finite limits

For all 24 registered streams, the direct witnesses exclude every fixed global
displayed-pair-to-byte mapping under the documented relaxed endpoint, including
nonbijective mappings. The CSP certificates separately exhaust all 16-symbol
hexadecimal bijections.

The result is limited to the pinned Blowfish-compat raw-key primitive,
historical OFB8 and compatibility full-block OFB, the three registered IVs,
four orientations, and the documented ASCII-plus-four-UTF-8-punctuation
endpoint. It does not cover standard Blowfish semantics, CTR, other feedback
recurrences, keys, IVs, orientations, position-dependent mappings, or endpoint
alphabets.

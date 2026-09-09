# Blowfish-compat OFB stream-CSP controls

Identity: ASTRA. This directory is synthetic-only; no Rev7 input is read or
evaluated. It prepares the historical Blowfish-compat stream convention for a
future 24-cell grid: one raw-seven-byte Zombies cipher, two OFB modes, three
IVs, and four orientations.

The block primitive is the compiled pinned libmcrypt blowfish-compat source
validated by source_check.py and source_check_reproduction.json. The OFB8
control calls the actual compiled historical OFB8 C mode through a module
adapter backed by that block primitive, and compares the complete stream with
an independent recurrence.

For full-block OFB, let W reverse the bytes within each 32-bit half of an
eight-byte block. The compatibility primitive satisfies

    E_compat(x) = W(E_standard(W(x))).

Therefore compatibility full-block OFB starts standard Blowfish OFB with W(IV)
and applies W to every complete standard keystream block. Controls generate
ceil(length/8)*8 standard bytes, transform each complete eight-byte block, and
only then clip to the requested length. This explicitly covers the
partial-final-block pitfall.

Reproduce:

    cd /private/tmp/rev7-astra-20260909/research/rev7-20260909-codex/stream_csp_compat
    python3 -B controls.py

The script refuses to overwrite controls.json. The frozen checks cover every
combination of three IVs and lengths 1, 7, 8, 9, 15, 16, 17, and 546. Each row
validates actual historical-C OFB8 and roundtrip, plus compatibility-C-block
full-OFB recurrence against the independently conjugated PyCryptodome stream
and roundtrip.

Both modes also recover a full-16-symbol, 546-byte mixed-UTF8 planted map with
a complete 16! CSP certificate. Separate four-unknown controls exactly match
independent direct-XOR enumeration of all 24 remaining bijections.

This controls artifact does not authorize or implement a target run.

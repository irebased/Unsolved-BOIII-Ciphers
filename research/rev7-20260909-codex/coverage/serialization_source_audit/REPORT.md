# Numeric code values versus serialized bytes

Identity: ASTRA. This is a source audit, not a Rev7 experiment.

The local repository does contain both examples cited in FABLE messages 417–420. Their documented cipher families do not establish that the author fed raw numeric code bytes into another cipher.

## Zetsubou No Shima 5

The MDX page selects CipherPage id zns5. The dataset labels its sole step numbers_to_letters, leaves ciphertext null, and links the source image bo3/zns/zns_5.webp. ASTRA inspected that existing image directly with view_image: it visibly contains written decimal digits, grouped into words. The opening 050423011804 splits as 05 04 23 01 18 04, which maps to EDWARD and agrees with the documented plaintext opening.

Thus the visible source demonstrates decimal digit pairs. If those digits were submitted as text to a subsequent cipher, the byte representation would use printable digits (for example, ASCII “01” is 0x30 0x31). Reinterpreting the same numeric code as raw byte 0x01 is an additional serialization hypothesis. This audit does not determine which representation an unobserved Rev7 chain uses.

## Gorod Krovi 8

The MDX page selects CipherPage id gk8. The dataset labels its sole step baudot_code, leaves ciphertext null, and links bo3/gk/gk_8.webp. ASTRA inspected the image directly with view_image: it is a drawing of punched tape, with five data-hole positions around a regularly spaced smaller feed-hole row.

The displayed five-bit code values can be represented by individual low-valued bytes, text digits, or packed five-bit units. The repository entry and image do not specify a byte serialization as input to a further modern cipher. No full hole transcription or end-to-end Baudot replay was performed in this audit.

## What follows for Rev7

The small-byte endpoint experiment is a reasonable distinct hypothesis, but these examples do not prove that every prior printable-byte test missed an author-demonstrated byte serialization. ASCII decimal or binary digits are already printable; raw values 0–31 and packed five-bit codes require separate definitions. Existing cardinality proofs depend only on the size of a byte alphabet and can apply to a small nonprintable alphabet even when particular membership tests do not.

Source metadata and the manually read six-pair example are reproducible with:

```sh
python3 -B research/rev7-20260909-codex/coverage/serialization_source_audit/audit.py
```

The image inspection itself used view_image on the two local assets below. File hashes bind the exact inspected artifacts; the image is not reconstructed or modified.

- `lavender/src/content/docs/ciphers/bo3/zns/zns5.mdx` — SHA-256 `4b125343323a4e8e817c1aa0d6bea38ed6512f153a8e7ec3aa1c6730cae75696`
- `lavender/src/content/docs/ciphers/bo3/gk/gk8.mdx` — SHA-256 `2326f36425b3507d39d6a4f0c734783d0c32c94b8865fe92b3aa97c0a50ef160`
- `lavender/src/data/ciphers/zetsubou.json` — SHA-256 `5714592132cb97223180e5b786e6b9239fe76136d92d885a9a21f629698415d3`
- `lavender/src/data/ciphers/gorod_krovi.json` — SHA-256 `f05703ae5173e02187e4840593cf9137048a60e5dec13898961ec606ddef0d3d`
- `lavender/src/assets/bo3/zns/zns_5.webp` — SHA-256 `d66661148b93f934075ee4e6ef9fb19c1f7ed39d4f73d853b29db02ed873d8ad`
- `lavender/src/assets/bo3/gk/gk_8.webp` — SHA-256 `6aaa50753c84a9e0209915af38102b18cf02841b5e8cc8aced50fd4b18c241b1`

# Rev 7 conversion coverage and gaps

```json
{
  "identity": "ASTRA",
  "source": "research/rev7-20260909-codex/notebook-snapshot.json",
  "scope": "Issue #20 body, its 67 comments, and the #21 message-format definition",
  "conclusion": "The public checkpoint records whole-number arbitrary-precision conversions and decimal-stream classical probes. It does not record a fixed-size chunk/limb conversion, nor a bytewise decimal serialization explicitly fed into a classical stage. These are untested in the public record; absence of a comment is not proof that no private run exists."
}
```

## Coverage matrix

| Path or representation | Evidence actually recorded | Status | Gap that remains |
|---|---|---|---|
| Whole ciphertext as one base-16 integer, rendered in bases 3/9/10 or decimal | `R7-20260909-root-004`, `-005`, `-016`, `-022`; 168/256/30,240-row scans and later checkerboard, Morse, arithmetic and column branches | Tested, with exact finite scopes | Does not test segmentation before conversion or machine-word overflow semantics |
| Whole integer → base-26/27 or base-5/6 coordinate symbols | `R7-20260909-root-006`, `-021`; `R7-20260909-columnsource-001`; issue body’s 6,657,408-cell Polybius grid | Tested conditionally | Other coordinate widths/layouts and post-conversion fractionation remain open |
| Whole-integer decimal stream → checkerboard / ZOMBIES columns | `R7-20260909-root-005`, `-032`, `-033`, `R7-20260909-columnsource-001`, `-columnaudit-001`, `-columndirect-002` | Tested in stated bases (16–36), zeros (0–14), reversals, columns and selected boards | No fixed-size chunk serializer; unknown boards and other layer placement remain open |
| Periodic digit arithmetic on whole-integer decimal stream | `R7-20260909-root-045`, `R7-20260909-digitaudit-001/-002`; `R7-20260909-layersource-001`, `-layerdirect-003` | Tested for A=0 `ZOMBIES` and periods 1–5 / 11, selected signs and placements | Does not cover bytewise decimal values or limb-local arithmetic |
| Fixed-size hex chunks/limbs converted independently to decimal (e.g. 4/5/8 hex symbols, 16/32-bit limbs, zero-padded decimal chunks) | No comment reports this operation or an equivalent bounded target scan. Issue body explicitly says “whole-number conversion” and warns that “546 bytes” is only an ordinary paired-hex interpretation (`5600939380`; issue body). | **Untested in public record** | Chunk width, limb endianness, per-chunk decimal width, chunk order and handling of leading zeros |
| Paired bytes → per-byte decimal (`000`–`255`, minimal decimal, delimited or concatenated) → classical transform | Modern branches discuss binary/byte boundaries, but no event identifies this byte-to-decimal serialization followed by a classical stage. The inventory calls per-character and variable-width boundaries open (`5600941685`). | **Untested in public record** | Byte order, delimiter policy, fixed 3-digit padding, concatenation parser, and whether classical operation sees digits or tokens |
| Historical serialization evidence | `5600942737` records Veness UTF-8 expansion, CryptoJS byte/string distinctions, and hex auto-detection; these are modern-wrapper investigations, not a Rev 7 byte-to-decimal classical run | Source evidence only; not target coverage | A source-backed historical serializer plus a concrete Rev 7 endpoint is still needed |
| Source-defined odd-length/padding behavior after fractionation | `R7-20260909-paddingsource-002`, `R7-20260909-paddingtheory-003`, and parity/row-fill branches through `R7-20260909-root-118` | Tested as separate terminal hypotheses | These operate on already-produced decimal/checkerboard streams; they do not test chunk/byte serialization |

## Interpretation and uncertainty

The strongest justified statement is “not reported as tested in the 67-comment public snapshot.” The whole-integer wording is materially different from fixed-size limbs: arbitrary-precision conversion preserves one integer and then emits one radix representation, whereas chunking converts many independently bounded values and can introduce regular decimal widths, local endianness, and repeated boundaries. None of the recorded counts (including the 20,160-row decimal-to-column grid in `R7-20260909-columnaudit-001` and the 84,480 arithmetic-plus-column compositions in `R7-20260909-layerdirect-003`) demonstrates that chunking was included.

Likewise, “decimal stream” in the checkpoint means digits rendered from a whole integer or modified by periodic arithmetic. It should not be silently read as `bytes.map(str).join(...)`. The historical serialization note (`5600942737`) establishes that representation boundaries matter, but its reported scans concern CryptoJS/Rabbit, XXTEA and other modern wrappers and do not prove a byte-to-decimal classical experiment.

The direct classical branches also do not close this gap: `R7-20260909-coverage-001` explicitly leaves checkerboard/fractionation paths open, while the later column events test particular whole-integer decimal rows. Negative results remain conditional on their declared input representation.

## Three bounded next experiments

1. **32-bit limb decimalization before a known classical endpoint.** For the four recorded orientations, decode paired hex into bytes, partition into 32-bit limbs, test big- and little-endian limb interpretation and normal/reversed limb order, then emit each limb as a fixed-width 10-digit unsigned decimal value. Feed the resulting digit stream to the already implemented direct ZOMBIES two-header checkerboard (offsets 0/1/2, both plaintext directions) and retain only complete parses. This is 16 input serializers × the existing 540 board profiles, with exact hash deduplication. Controls: planted messages through the full serializer/inverse and a non-chunk whole-integer negative control. A hit requires coherent complete text and exact reconstruction.

2. **Visible-group / small-chunk decimalization.** Treat the display’s initial 2-symbol group plus 5-symbol groups as boundaries, and separately test uniform 4- and 5-hex-symbol chunks. For each, use minimal decimal and fixed-width decimal (width equal to the chunk’s maximum value width), with normal/reversed chunk order; do not mix chunk widths in one run. Apply only the existing source-supported column ranks `ZOMBIES`/`Zombies`, then the known-board checkerboard decoder. This is a small serializer matrix (four boundary schemes × two decimal policies × two orders × two column directions), with content-hash deduplication against `R7-20260909-columndirect-002`. Controls include the Rev 4 recipe and planted decimal chunks.

3. **Byte-to-decimal token boundary test.** Decode each orientation as 546 bytes, serialize each byte as either fixed `000`–`255` or minimal decimal with an explicit separator (two policies), and test both byte order and stream reversal. Interpret tokens as decimal digits only after serialization; test the existing ZOMBIES column operation at widths 2–8 and the fixed known-board decoder. Keep delimited and fixed-width streams separate so token boundaries are never guessed. This is 16 serializer variants × 7 widths × two column directions, with a key-independent complete-token count before language scoring. Controls: round-trip byte fixtures, a synthetic English plaintext, and the ordinary whole-integer decimal path as a negative control. A language score alone is insufficient.

All three experiments change the input representation before a classical layer, which is the specific uncovered dimension. They should not be merged with the already completed whole-integer, periodic-arithmetic, row-fill, or parity-removal ledgers.


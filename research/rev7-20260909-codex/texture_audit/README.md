# Saved Rev7 texture transcription check

Identity: **ASTRA**. This compares the repository's saved texture with its canonical transcript; it does not decrypt or edit the target.

Apple Vision accurate OCR, with language correction disabled, recovered all 16 text rows. The saved raw output contains 1,093 non-whitespace characters because it inserted a punctuation dot. Row clustering restores horizontal order for fragments returned separately. OCR-only normalization removes that dot and maps its non-hex O/S/Cyrillic-ZE recognitions to 0/5/3, leaving 1,092 symbols.

Three valid-hex differences remain: zero-based symbol offsets 276, 366 and 595. OCR reads 4 where the transcript records A, in groups `6272A` (row 4), `2D87A` (row 6), and `6B9A4` (row 9). Visual review of the saved texture supports A at these positions; the adjacent A and 4 in `6B9A4` provide a useful local comparison. The raw OCR differences remain recorded for others to inspect. OCR confidence was 1 even for these errors and is not used as proof.

No transcription discrepancy was found in this saved texture. The canonical MDX and all target bytes remain unchanged. This is an image/transcript check, not a separately acquired game texture or a mathematical guarantee against a source-image error.

The image SHA-256 is `36a1883ede6abadcf4d4420f26484ca81134f3b62fe0ac7521352c682bf0b3b7`. Source image: `lavender/src/assets/revelations_7.png`. The comparison script pins both image and MDX hashes and preserves every raw OCR line and unresolved machine difference.

From the checkout root, reproduce the read-only comparison:

```sh
python3 -S -B research/rev7-20260909-codex/texture_audit/compare.py
```

To obtain a fresh OCR record on macOS with Swift and Apple Vision:

```sh
swift -module-cache-path /tmp/astra-vision-module-cache research/rev7-20260909-codex/texture_audit/recognize.swift lavender/src/assets/revelations_7.png > /tmp/rev7-vision.json
python3 -S -B research/rev7-20260909-codex/texture_audit/compare.py --ocr /tmp/rev7-vision.json
```

The recorded run used Swift 6.3.3 and CPU inference. The first sandboxed Vision request failed; a local CPU-only request outside that sandbox completed. No external OCR service or image modification was used. `usesCPUOnly` is deprecated by the SDK but functioned in this recorded run. Different Vision versions may recognize text differently, so the raw saved JSON is included separately from the comparison.

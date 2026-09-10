# Findings

Identity: ASTRA.

The frozen gist has two revisions, both dated 2020-01-09; the current revision is `cc559bba7406ed8489eaaf2f9a5481d5fd500bc2`, and `base64_rot13.py` is 8,830 bytes.

Its active Rev7 value is Base64 transport for the **spaced ASCII hex display**. Base64 decoding produces 1,310 ASCII bytes. Whitespace removal produces exactly the canonical 1,092 glyphs, and only a subsequent hex decode produces 546 binary bytes. The token sequence, including the initial two-glyph `83` and all 218 five-glyph groups, matches the repository dataset exactly.

The gist is dated corroborating community source material, but the available provenance does not establish an independent transcription: it links the community wiki and gives no image-read method. The `Origins_Trench` alias was not present in the six reviewed prior local sources. The broader location `By the Origins mound` was already documented locally, so the alias refines community naming rather than discovering that the cipher is in an Origins-themed area. It should not be promoted to verified physical coordinates without a game image, asset map, or other location source.


## Origins key spelling

The source-backed key is `wewerethereatthebeginningandattheend` (36 characters), not the proposed `wewerehereatthebeginningandattheend` (35). Three dated community sources use `there`, and the local solved Origins dataset agrees. FABLE’s “35-character phrase” is therefore a counting error. Four available prior FABLE keylists contain the 36-character spelling three times each and contain no exact `here` spelling; this does not establish the contents of the still-unsynced 70,656-combination run.

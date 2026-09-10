# ASTRA community gist and location audit

This audit freezes revision `cc559bba7406ed8489eaaf2f9a5481d5fd500bc2` of redknight99’s 2020 gist and checks its active `Origins_Trench / Cipher #6` value without running its ROT/Base64 loop.

The active value contains 1,748 Base64 characters. Base64 decoding yields **1,310 bytes of spaced ASCII hex**, beginning `83 B57B2`; it does not directly yield 546 binary bytes. Splitting whitespace gives 219 tokens: the first has two hex glyphs and the remaining 218 have five. Removing whitespace gives 1,092 uppercase hex glyphs with SHA-256 `5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c`, exactly matching the repository dataset token-for-token. A further hex decode yields 546 binary bytes.

This is useful dated corroboration of the exact token sequence. It is not established as a fourth independent transcription. The gist description links the community Revelations wiki and does not document an independent image read or capture chain, so shared lineage remains possible.

The alias adds nomenclature, but its physical precision is limited. `Origins_Trench` is reported by the gist author. The reviewed local corpus had no occurrence of that exact alias or gist ID, while the repository already said `By the Origins mound`; Git history dates that local wording to 2025-12-18. The gist alone does not verify exact game coordinates.

The local history inventory also confirms that the three suggested key strings were already present in solved sibling-map data. The documented Origins Vigenère key is `wewerethereatthebeginningandattheend`, which is **36** characters. A July 2016 community guide and 2016/2018 Reddit catalogs all use `there`; the proposed 35-character `wewerehere...` correction is unsupported. Four captured FABLE keylists contain the 36-character form and omit the 35-character alternative, although they are not proven to be the exact unsynced follow-up list. `INFERNO` appears in `origins.json`, and `MOBOFTHEDEADABCD` in `motd.json`. Their appearance is not new key provenance for Rev7. FABLE’s reported 70,656-combination follow-up is outside the gist and is not rerun here.

Reproduce with:

```sh
python3 -B research/rev7-20260909-codex/coverage/community_gist_location_audit/audit.py
```

Identity: ASTRA.

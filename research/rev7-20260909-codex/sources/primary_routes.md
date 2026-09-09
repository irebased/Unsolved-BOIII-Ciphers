# Primary-source routes for Revelations assets and historical cipher frontends

- **Research date:** 2026-09-10
- **Identity:** ASTRA
- **Scope:** source research only; no cipher experiment or target run
- **Map identity fixed by the depot listing:** Revelations is `zm_genesis`. `zm_stalingrad` is Gorod Krovi.

## Result

I did not find accessible pre-September-2016 source code or a contemporaneous technical record that fixes the Tools4Noobs or Online-Domain-Tools XXTEA wrapper. In particular, the available evidence does **not** establish byte order, whether a length word was appended, data padding, key padding/truncation, string encoding, or the binary-to-text encoding used by the September 2016 frontend.

I found a genuine outer asset-container listing for Revelations. It establishes the package stem `zm_genesis`, but it does not expose internal XPAK texture names or identify which asset contains the ciphertext.

## Revelations asset route

### Steam depot manifest rendered by SteamDB

- URL: https://steamdb.info/depot/830461/
- Page context: depot 830461, titled `Call of Duty: Black Ops III - Revelations Zombies Map`.
- Visible manifest context: manifest `1301210203620557458`, dated 2019-12-16. This is later than the September 2016 puzzle, so it proves the package identity and later container names, not that every filename was unchanged at launch.
- Short quote: "Call of Duty: Black Ops III - Revelations Zombies Map (830461) Depot"
- Outer files shown include:
  - `zone/zm_genesis.fd`
  - `zone/zm_genesis.ff`
  - `zone/zm_genesis.xpak`
  - `zone/zm_genesis_d.xpak`
  - `zone/zm_genesis_patch.ff`
  - `zone/zm_genesis_patch.xpak`

**Established:** the Revelations depot is associated with `zm_genesis`, and the visible manifest has FF/XPAK containers under that stem.

**Not established:** an internal cipher texture/material/image filename, the September 2016 manifest contents, or any encryption workflow.

**Download-free inspection route:** the SteamDB page exposes the outer manifest file list in a browser. Older manifests may require SteamDB sign-in. It does not expose the XPAK member list.

## Download-free extracted-source indexes

These are community extraction/search routes, not publisher source and not evidence of an asset filename.

- BO3 source dump: https://github.com/ate47/bo3-source
  Short quote: "Dump of some parts of BO3 using Atian Call of Duty Tools."
- Atian Call of Duty Tools: https://github.com/ate47/atian-cod-tools
  Short quote: "Fast Files are archives containing compressed assets."
- BO3 Explorer: https://bo3explorer.zeroy.com/files.html

**Established:** these routes permit browser searches over already-extracted script/raw-file material and document the container/extraction tooling.

**Not established:** a complete Revelations texture index. The current BO3 fast-file reader documentation lists limited supported pools and does not make this a primary XPAK texture listing.

## Historical Online-Domain-Tools evidence

### Archived frontend route

- Exact capture URL: https://web.archive.org/web/20160729190110id_/http://symmetric-ciphers.online-domain-tools.com/
- Capture timestamp encoded in the URL: 2016-07-29 19:01:10 UTC.
- The archived body was not retrievable through the available browser path during this bounded check. The URL is therefore a route for human inspection, not evidence for an XXTEA convention by itself.

### Contemporary independent comparison

- Paper PDF: https://journals.theired.org/assets/pdf/20151031_105748.pdf
- Title: *Secure PHP OpenSSL Crypto Online Tool*
- Context: September 2015 conference paper comparing several online cryptography frontends; it labels Tools4Noobs as tool B and Online-Domain-Tools as tool D.
- Short quote about tool D: "the encrypted text is shown in hex and binary format separated by a white space"

**Established:** by 2015 the Online-Domain-Tools symmetric-cipher frontend existed, exposed only partial configuration according to the comparison, and displayed cipher output in spaced hex/binary forms.

**Not established:** XXTEA-specific key normalization, data framing, length-word handling, or whether literal hexadecimal input was decoded before encryption. This is a contemporaneous secondary evaluation, not the frontend source.

## Tools4Noobs XXTEA evidence

### Post-cutoff user observation

- URL: https://github.com/alessandro1105/XXTEA_Arduino_Library/issues/2
- Date: 2017-07-27.
- Short quote: "DECRYPT with 8877 key"
- Context: a user reports that the Tools4Noobs XXTEA page accepted the short textual key `8877` and a Base64-looking ciphertext. The report is ten months after Revelations and contains no frontend source.

### Post-cutoff maintainer warning

- URL: https://github.com/ardlib/bosejis_xxtea
- Dated changelog entry: 2017-05-08.
- Short quote: "This online implementation is for an older version of XXTEA with bugs"

**Established:** the Tools4Noobs endpoint still existed in 2017; a user could submit a short key, and an independent library maintainer regarded the implementation as an older, buggy variant.

**Not established:** that the same implementation or wrapper was deployed before September 2016, which historical variant it used, or its exact padding/length/key rules. The Arduino library's own key and padding code must not be attributed to Tools4Noobs.

## What can safely parameterize a future test

The source record supports using `zm_genesis` when searching legitimate Revelations package/container indexes. It does not support selecting one "historical Tools4Noobs XXTEA" recipe. Any future XXTEA run must label byte order, length word, padding, key treatment, and output decoding as explicit hypotheses rather than recovered frontend behavior.

For a primary-source-grade frontend reconstruction, the missing evidence is one of:

1. archived page JavaScript/PHP source or a downloadable frontend bundle from before September 2016;
2. a pre-cutoff request/response capture with exact raw input bytes, key, and output;
3. an operator-authored description of the wrapper;
4. an original 2016 Steam manifest plus an XPAK member index for `zm_genesis`.

No internal asset name was inferred or invented in this research.


## Follow-up retrieval limits

The two exact archived Online-Domain-Tools JS URLs supplied by FABLE were not retrieved in this bounded audit:

- https://web.archive.org/web/20150315143526id_/http://symmetric-ciphers.online-domain-tools.com/temp/Tools.SymmetricCiphers.default.2015.03.14-13-30.js?2015.02.23.02
- https://web.archive.org/web/20160404153722id_/http://symmetric-ciphers.online-domain-tools.com/temp/Tools.SymmetricCiphers.default.2015.12.03-19-09.js?2015.12.03.01

The web tool rejected the nested archive URLs and a browser request stalled without yielding content. No claim about the actual SHA-1 IV handling can be established by this retrieval. Computing the SHA-1 digest of the password verifies a numerical correspondence only. No pinned libmcrypt OFB8 source or OFB8 known-answer vector was retrieved in this subtask.

FABLE separately supplied locally retrieved Tools4Noobs HTML. The reusable `t4n_html_inventory.py` and frozen `t4n_html_inventory.json` record matching hashes and observed form options from three supplied files. Both encryption pages have 19 algorithm options and 8 modes; the converter offers bases 2–30. The files do not contain an embedded archive-capture timestamp. The inventory is a local HTML inspection, not a reconstruction of the backend or independent retrieval provenance.

## Capture correction

The local source set now contains three encryption HTML captures plus one base-converter HTML artifact. The Tools4Noobs encryption HTML previously labeled `encrypt_2016.html` is now canonicalized as `encrypt_capture_20150910.html`. Its Memento response header records `memento-datetime: Thu, 10 Sep 2015 01:46:01 GMT`, and the redirect states capture `20150910014601`; this is direct capture evidence from `t4n/hdr_exact.txt`, not an inference from a requested URL. The file SHA-256 is `5a86122f5680a1974624beca07aeb3cc9bc20978b506912ab3cbdfb93b9fa3cd`. A separate local `encrypt_20171028.html` artifact has SHA-256 `f850ddd38f398554cb0b1640ebb0a3bb346301cc71ecd04898d08cc480a13c52`. This correction concerns capture dating only and does not establish backend behavior.

## Historical OFB source note

The historical OFB source was later retrieved by root at pinned libmcrypt mirror commit [`3bd338e2f808e985f5b229a7642d48c26615993f`](https://github.com/Distrotech/libmcrypt/tree/3bd338e2f808e985f5b229a7642d48c26615993f), including `ofb.c` and `nofb.c`. This source pointer documents separate files; it does not by itself establish a complete runtime or Rev7 attribution.

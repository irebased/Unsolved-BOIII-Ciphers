//! Corpus loading, target lookup, and the conformance runner.

use std::collections::{BTreeMap, BTreeSet};
use std::path::{Path, PathBuf};

use anyhow::{anyhow, bail, Context, Result};
use ra_core::layer::{classify, index_of_coincidence, shannon, ReprClass};
use ra_core::{Display, Repr};
use ra_prim::{KeyDerivation, Mode};

const MAPS: [&str; 3] = ["revelations.json", "the_giant.json", "gorod_krovi.json"];

/// Resolve the data directory: explicit flag, then `$RA_DATA_DIR`, then the nearest
/// ancestor containing `data/evidence_base.json`.
pub fn resolve_data_dir(explicit: Option<&Path>) -> Result<PathBuf> {
    if let Some(p) = explicit {
        return Ok(p.to_path_buf());
    }
    if let Ok(p) = std::env::var("RA_DATA_DIR") {
        return Ok(PathBuf::from(p));
    }
    let mut cur = std::env::current_dir()?;
    loop {
        let candidate = cur.join("data");
        if candidate.join("evidence_base.json").is_file() {
            return Ok(candidate);
        }
        if !cur.pop() {
            bail!(
                "could not locate the corpus. Pass --data <dir> or set RA_DATA_DIR to the \
                 directory containing evidence_base.json"
            );
        }
    }
}

fn read_json(path: &Path) -> Result<serde_json::Value> {
    let s = std::fs::read_to_string(path)
        .with_context(|| format!("reading {}", path.display()))?;
    serde_json::from_str(&s).with_context(|| format!("parsing {}", path.display()))
}

pub struct Target {
    pub id: String,
    pub raw: String,
    pub display: Display,
    pub display_hint: &'static str,
    pub solved: bool,
    pub plaintext: Option<String>,
    pub steps: Vec<serde_json::Value>,
    /// A project-supplied re-reading that resolves some or all of `raw`'s open glyph
    /// positions against the source, in the `(A/B)`-marker format
    /// [`crate::variants::VariantSpace::derive_canonical`] expects. `raw` itself stays
    /// the ciphertext every existing variant label is defined relative to — see
    /// `ciphertext_canonical_provenance` in the corpus record — so this is additional
    /// information, never a replacement for it.
    pub ciphertext_canonical: Option<String>,
}

impl Target {
    /// The `0.variant` space for this target: derived from `raw`, and narrowed by
    /// `ciphertext_canonical` when the corpus record carries one. Every caller that
    /// builds a [`crate::variants::VariantSpace`] for a corpus target should go
    /// through this rather than calling `derive`/`derive_canonical` directly, so the
    /// canonical narrowing is never accidentally skipped for one code path.
    pub fn variant_space(&self, exact_label: &str) -> Result<crate::variants::VariantSpace> {
        let compact: Vec<u8> = self.raw.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
        let canonical: Option<Vec<u8>> = self
            .ciphertext_canonical
            .as_ref()
            .map(|c| c.bytes().filter(|b| !b.is_ascii_whitespace()).collect());
        crate::variants::VariantSpace::derive_canonical(
            &compact,
            canonical.as_deref(),
            self.display,
            exact_label,
        )
    }
}

/// Find a cipher record by id across all three map files.
pub fn load_target(data: &Path, id: &str) -> Result<Target> {
    for map in MAPS {
        let path = data.join(map);
        if !path.is_file() {
            continue;
        }
        let v = read_json(&path)?;
        let Some(arr) = v.as_array() else { continue };
        for rec in arr {
            if rec["id"].as_str() != Some(id) {
                continue;
            }
            let raw = rec["ciphertext"]
                .as_str()
                .ok_or_else(|| anyhow!("cipher {id} has no ciphertext in the corpus"))?
                .to_string();
            let compact: String = raw.chars().filter(|c| !c.is_whitespace()).collect();
            // infer the display from the character set actually present
            let (display, hint) = if compact.chars().all(|c| c.is_ascii_hexdigit()) {
                (Display::Hex, "hex")
            } else if compact.chars().all(|c| c.is_ascii_digit()) {
                (Display::Decimal, "decimal")
            } else {
                (Display::Base64, "base64")
            };
            return Ok(Target {
                id: id.to_string(),
                raw,
                display,
                display_hint: hint,
                solved: rec["solved"].as_bool().unwrap_or(false),
                plaintext: rec["plaintext"].as_str().map(str::to_string),
                steps: rec["solution"]["steps"]
                    .as_array()
                    .cloned()
                    .unwrap_or_default(),
                ciphertext_canonical: rec["ciphertext_canonical"].as_str().map(str::to_string),
            });
        }
    }
    bail!("no cipher with id {id:?} in the corpus")
}

/// A summary of one attackable corpus target, for `GET /api/targets`. Records
/// with no (or empty) `ciphertext` are omitted — there is nothing for a chain to
/// run against.
pub struct TargetSummary {
    pub id: String,
    pub map: String,
    pub solved: bool,
    pub ciphertext_len: usize,
}

/// Title-cases a map file's snake_case id ("the_giant" -> "The Giant") for display.
fn map_display_name(map_file: &str) -> String {
    map_file
        .split('_')
        .map(|w| {
            let mut c = w.chars();
            match c.next() {
                Some(first) => first.to_uppercase().collect::<String>() + c.as_str(),
                None => String::new(),
            }
        })
        .collect::<Vec<_>>()
        .join(" ")
}

/// Every corpus target that carries a non-empty ciphertext, across all three maps.
pub fn list_targets(data: &Path) -> Result<Vec<TargetSummary>> {
    let mut out = Vec::new();
    for map in MAPS {
        let path = data.join(map);
        if !path.is_file() {
            continue;
        }
        let v = read_json(&path)?;
        let Some(arr) = v.as_array() else { continue };
        let map_id = map.trim_end_matches(".json");
        for rec in arr {
            let Some(ct) = rec["ciphertext"].as_str() else {
                continue;
            };
            if ct.is_empty() {
                continue;
            }
            let Some(id) = rec["id"].as_str() else {
                continue;
            };
            out.push(TargetSummary {
                id: id.to_string(),
                map: map_display_name(map_id),
                solved: rec["solved"].as_bool().unwrap_or(false),
                ciphertext_len: ct.len(),
            });
        }
    }
    Ok(out)
}

pub fn show_target(data: &Path, id: &str) -> Result<()> {
    let t = load_target(data, id)?;
    let canonical = Repr::new(t.raw.clone().into_bytes(), t.display).canonical_bytes();

    println!("{}  ({})", t.id, if t.solved { "SOLVED" } else { "UNSOLVED" });
    println!("  recorded display : {}", t.display_hint);
    println!("  raw length       : {} chars", t.raw.len());
    println!("  decoded length   : {} bytes", canonical.len());
    println!("  entropy          : {:.4} bits/byte", shannon(&canonical));
    println!("  index of coinc.  : {:.5}", index_of_coincidence(&canonical));
    println!("  class            : {}", classify(&canonical).as_str());

    // The recorded ciphertext is a transcription of an image, so how many *readings*
    // it admits belongs here beside its entropy — it is a property of the target, not
    // of a particular sweep, and a reader who never runs a sweep still needs it.
    let compact: Vec<u8> = t.raw.bytes().filter(|c| !c.is_ascii_whitespace()).collect();
    let glyphs = t.variant_space(&format!("{}-exact", t.display_hint))?;
    if glyphs.is_ambiguous() {
        let census: Vec<String> = glyphs
            .census()
            .iter()
            .map(|(g, n)| format!("{n}x{}", *g as char))
            .collect();
        let masks = glyphs.masks();
        let open = glyphs.open_positions();
        println!(
            "  transcription    : {} open ambiguous glyph position{} ({}) -> {} admissible \
             reading{}, {}..{}",
            open.len(),
            if open.len() == 1 { "" } else { "s" },
            census.join(" "),
            glyphs.count(),
            if glyphs.count() == 1 { "" } else { "s" },
            glyphs.label(*masks.first().expect("at least one admissible reading")),
            glyphs.label(*masks.last().expect("at least one admissible reading"))
        );
        println!("    open           : {open:?}");
        if t.ciphertext_canonical.is_some() {
            println!(
                "    canonical      : {} raw I/l positions {:?}, narrowed by \
                 ciphertext_canonical_provenance from {} labels (v00..{}) to the {} above",
                glyphs.positions().len(),
                glyphs.positions(),
                1u64 << glyphs.positions().len(),
                glyphs.label((1u32 << glyphs.positions().len()) - 1),
                glyphs.count()
            );
        }
        let resolved = crate::variants::VariantSpace::resolved_positions(&compact, t.display);
        if !resolved.is_empty() {
            println!(
                "    resolved       : {resolved:?}  (0/O, confirmed against the source \
                 font; fixed, not enumerated)"
            );
        }
    } else {
        println!(
            "  transcription    : unambiguous — a {} display excludes the confusable \
             glyph partners, so there is exactly one reading ({})",
            t.display_hint,
            glyphs.label(0)
        );
    }

    if let Some(pt) = &t.plaintext {
        println!("\n  recorded plaintext ({} chars, {} UTF-8 bytes):", pt.chars().count(), pt.len());
        println!("    {}", &pt[..120.min(pt.len())]);
        if pt.len() != canonical.len() {
            println!(
                "    NOTE: {} plaintext bytes vs {} ciphertext bytes — the recorded \
                 plaintext is a transcription, not the exact bytes.",
                pt.len(),
                canonical.len()
            );
        }
    }
    if !t.steps.is_empty() {
        println!("\n  recorded solution chain:");
        for (i, s) in t.steps.iter().enumerate() {
            let method = s["method"].as_str().unwrap_or_else(|| {
                s["type"].as_str().unwrap_or("?")
            });
            let extra: Vec<String> = ["mode", "key", "shift", "alphabet"]
                .iter()
                .filter_map(|k| s.get(*k).map(|v| format!("{k}={}", v.to_string().trim_matches('"'))))
                .collect();
            println!("    {}. {} {}", i + 1, method, extra.join(" "));
        }
    } else {
        println!("\n  no recorded solution: this is one of the remaining targets.");
    }
    Ok(())
}

/// primitive -> corpus ciphers that exercise it, from `conformance_suite.json`.
pub fn conformance_vectors(data: &Path) -> Result<BTreeMap<String, Vec<String>>> {
    let path = data.join("conformance_suite.json");
    let raw = std::fs::read_to_string(&path)
        .with_context(|| format!("reading {}", path.display()))?;
    ra_toolreg::load_conformance_suite(&raw).map_err(|e| anyhow!(e))
}

/// Content digest of the conformance suite, over its *parsed* canonical form.
///
/// Taken over the `BTreeMap` rather than the file bytes so that reindenting
/// `conformance_suite.json` does not read as a changed suite, while adding,
/// removing or repointing a vector does.
pub fn conformance_suite_digest(suite: &BTreeMap<String, Vec<String>>) -> String {
    ra_attest::sha256_str(&serde_json::to_string(suite).unwrap_or_default())
}

/// One executable conformance check: a corpus cipher whose recorded chain this
/// engine can reproduce, together with what a correct result looks like.
struct Vector {
    cipher: &'static str,
    prim: &'static str,
    /// Chain spec, with `{input}` implied as the corpus ciphertext.
    chain: &'static str,
    check: Check,
}

enum Check {
    /// The output must contain this substring of the recorded plaintext.
    PlaintextContains,
    /// As [`Check::PlaintextContains`], but both sides are first reduced to
    /// uppercase alphanumerics. Required where the cipher's alphabet cannot carry
    /// what the transcription contains: a 25-cell ADFGX square has no space, comma
    /// or lower case, so rev4's recorded prose ("From all of us at Treyarch, it
    /// has...") can only ever be matched against `FROMALLOFUSATTREYARCHITHAS...`.
    /// The reduction is applied to *both* sides and never to the ciphertext, so it
    /// weakens nothing about which bytes the chain had to produce — the full
    /// 165-letter recovery is additionally pinned byte for byte by
    /// `ra_core::classical::adfgx`'s own tests.
    PlaintextLettersContain,
    /// The output must classify as this representation class. Used where the
    /// recorded plaintext is unusable but the *shape* of the intermediate is
    /// diagnostic, which makes the check immune to transcription drift.
    ClassIs(ReprClass),
}

/// Uppercase alphanumerics only, for [`Check::PlaintextLettersContain`].
fn letters_only(s: &str) -> String {
    s.chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .map(|c| c.to_ascii_uppercase())
        .collect()
}

/// The vectors this engine can currently execute end to end.
///
/// Deliberately short and honest. Every entry here is a real reproduction; the
/// primitives with no entry are reported as unproven rather than assumed correct,
/// because an unproven primitive must contribute zero coverage.
const VECTORS: &[Vector] = &[
    Vector {
        cipher: "rev12",
        prim: "XTEA",
        chain: "hexdecode | xtea:key=Zombies,mode=cfb | reverse | rot:n=20",
        check: Check::PlaintextContains,
    },
    Vector {
        cipher: "rev9",
        prim: "DES",
        chain: "b64decode | des:key=Zombies,mode=cfb",
        check: Check::ClassIs(ReprClass::Decimal),
    },
    // The vector that settled the key-derivation question: this recovers rev9's
    // plaintext only under null-pad-next-supported (16 bytes), not null-pad-max (32).
    // Note the b64decode before twofish: the corpus records "reverse" then a decrypt,
    // but the tools4noobs decrypt box base64-decodes its input, so that step is
    // implicit in every recorded chain.
    Vector {
        cipher: "rev9",
        prim: "Twofish",
        chain: "b64decode | des:key=Zombies,mode=cfb | decimaldecode | reverse \
                | b64decode | twofish:key=Zombies,mode=cfb",
        check: Check::PlaintextContains,
    },
    // Serpent's output is clean English before the final classical substitution.
    // Checked on class rather than plaintext because the corpus's recorded
    // substitution alphabet is itself slightly defective: applying it yields
    // "your cone live" where the record says "your gone life", a handful of letters
    // out of 127. The Serpent layer is unambiguous; the alphabet is not.
    Vector {
        cipher: "rev6",
        prim: "Serpent",
        chain: "decimaldecode | reverse | hexdecode | serpent:key=Zombies,mode=cfb",
        check: Check::ClassIs(ReprClass::Text),
    },
    Vector {
        cipher: "rev10",
        prim: "RC4",
        chain: "hexdecode | arcfour:key=Zombies",
        check: Check::ClassIs(ReprClass::Octal),
    },
    // Recovers rev10's plaintext end to end. Note no implicit b64decode is needed
    // here, unlike rev9's Twofish layer — the octal-decoded, hex-decoded bytes
    // feed SAFER+ directly.
    Vector {
        cipher: "rev10",
        prim: "Saferplus",
        chain: "hexdecode | arcfour:key=Zombies | octaldecode | hexdecode \
                | saferplus:key=Zombies,mode=cfb",
        check: Check::PlaintextContains,
    },
    // rev8 needs a repair step before any decode: the corpus's own solution notes
    // "insert missing '63' between the 131st and 132nd bigram", counted in the raw
    // hex *display* text (space-separated byte pairs), not a raw byte offset — hence
    // `unit=hexpair`. That description turned out to be exact, not off by one. As
    // with rev9, the recorded chain omits the implicit b64decode the tools4noobs
    // decrypt box performs on its input before decrypting.
    //
    // Two caveats on what this vector does and does not establish. It pins
    // Blowfish-compat: no wrong cipher yields 850 bytes of English. It does NOT pin
    // `pos`, because the insertion lands near the end of the *reversed* stream, so
    // pos 130/132/133 leave this 60-character prefix equally clean and only differ
    // in the tail. And rev8's ciphertext carries a *second*, undocumented
    // transcription defect: the recovered text reads "...I smile-~lways be with me"
    // where it should read "...I smile. He will always be with me". That signature —
    // one bad byte plus the following blocksize — is exactly CFB-8 single-byte
    // corruption, and it persists at every `pos`, so it is in the recorded
    // ciphertext rather than in this chain.
    Vector {
        cipher: "rev8",
        prim: "Blowfish-compat",
        chain: "insert:text=63,pos=131,unit=hexpair | hexdecode | reverse | hex_to_base64 \
                | b64decode | blowfish-compat:key=Zombies,mode=cfb | b64decode",
        check: Check::PlaintextContains,
    },
    // rev5's third recorded step is `hex_to_base64`, so its first layer must emit a
    // hex string — which is the oracle, and needs none of rev5's plaintext. This is
    // the vector that settled RC2's effective-key-bits question: mcrypt strips
    // RFC 2268's Phase 2 reduction, so `T1` is always 1024 rather than
    // `8 * key_len`. Under RustCrypto's default (`T1 = 56` for `Zombies`) this
    // output is opaque noise. See `ra_prim::rc2`.
    Vector {
        cipher: "rev5",
        prim: "RC2",
        chain: "b64decode | rc2:key=Zombies,mode=cfb",
        check: Check::ClassIs(ReprClass::Hex),
    },
    // Fixing RC2 unblocked rev5's fourth step and with it Blowfish, which had a
    // conformance vector but no reproduction. rev5's fifth step is a Loki97 decrypt,
    // whose box base64-decodes its input, so the Blowfish layer must emit base64 —
    // and it does, over all 825 bytes. Kept as a shape check even though the full
    // chain now reaches plaintext: it localises a regression to the Blowfish layer
    // rather than reporting the whole five-layer chain as broken.
    Vector {
        cipher: "rev5",
        prim: "Blowfish",
        chain: "b64decode | rc2:key=Zombies,mode=cfb | reverse | hex_to_base64 \
                | b64decode | blowfish:key=Zombies,mode=cfb",
        check: Check::ClassIs(ReprClass::Base64ish),
    },
    // rev1 is the vector that proves Rijndael-256: a 256-bit block is the one
    // thing no AES implementation can provide. Its recorded chain opens with a
    // classical Beaufort layer (key "ZOMBIES", the 52-character mixed-case
    // alphabet), which needed the `beaufort` node built to reproduce it.
    //
    // Two corrections to the recorded chain description. First, it omits *two*
    // implicit base64 decodes, not the one usually seen elsewhere in the corpus:
    // one right after the Beaufort layer (its output is base64 text, consumed by
    // the RC2 decrypt box) and a second right after `reverse` (RC2's plaintext is
    // itself base64 text, consumed by the Rijndael-256 decrypt box) — the
    // tools4noobs decrypt box base64-decodes its input at *both* hops, and the
    // recorded chain only ever mentions the decrypt steps themselves. Second, the
    // Beaufort key phase must skip characters outside the alphabet rather than
    // advancing over them: counting every input byte toward `i mod |K|` (digits
    // and `/` included, since the ciphertext is base64-shaped) does not reproduce
    // rev1, while advancing the key only on alphabetic characters does.
    //
    // `reverse` operates on raw bytes; since every intermediate here is
    // single-byte ASCII, that is indistinguishable from a text-level reverse.
    // The final Rijndael-256 ECB layer receives exactly one 32-byte block (RC2's
    // 44-byte base64-ish plaintext, reversed and base64-decoded down to 32 bytes)
    // and decrypts it to "The many worlds are now one." followed by a newline and
    // three null bytes of block filler — the recorded plaintext is 29 characters
    // against a 32-byte block, consistent with the corpus's other transcribed
    // vectors.
    Vector {
        cipher: "rev1",
        prim: "Rijndael-256",
        chain: "beaufort:key=ZOMBIES | b64decode | rc2:key=Zombies,mode=ecb | reverse \
                | b64decode | rijndael-256:key=Zombies,mode=ecb",
        check: Check::PlaintextContains,
    },
    // rev5 end to end, and the vector that proves Loki97. All five recorded layers
    // plus the two implicit b64decodes the tools4noobs decrypt box performs on its
    // input, recovering "August, 1946. OSS report final T-7. All of the Group 935
    // and Division 9 facilities..." — which retroactively upgrades the two vectors
    // above from shape-based to plaintext-backed, since a wrong RC2 or Blowfish
    // layer cannot end here.
    //
    // Loki97 is a port of libmcrypt's own loki97.c; see `ra_prim::loki97`. One
    // property of that C worth recording at the vector: its key schedule is the
    // 256-bit one for every key size and reads a `calloc`ed 32-byte buffer, so this
    // vector does *not* discriminate between null-pad-next-supported and
    // null-pad-max the way rev9's Twofish layer does — both derive the same key.
    Vector {
        cipher: "rev5",
        prim: "Loki97",
        chain: "b64decode | rc2:key=Zombies,mode=cfb | reverse | hex_to_base64 \
                | b64decode | blowfish:key=Zombies,mode=cfb \
                | b64decode | loki97:key=Zombies,mode=cfb",
        check: Check::PlaintextContains,
    },
    // rev13's recorded solution is a single classical step past `reverse`: an
    // affine cipher with a=15, b=19 over the default 26-letter alphabet. This
    // recovers the recorded plaintext exactly, not just up to the usual
    // transcription tolerance.
    Vector {
        cipher: "rev13",
        prim: "Affine",
        chain: "reverse | affine:a=15,b=19",
        check: Check::PlaintextContains,
    },
    // rev14's recorded note reads "Remove -M, organize in 6x27 grid, rotate
    // columns by 3, read bottom to top, append -M." That is accurate once
    // "6x27" is read as width x height (6 columns, 27 rows) rather than
    // rows x columns — see `ra_core::classical::columnar` for the empirical
    // derivation. Matches the recorded plaintext up to four characters, all
    // attributable to the same kind of transcription noise documented
    // elsewhere in the corpus (an `l`/`1` confusion twice, an `s`/`S` case
    // difference, and a `,`/` ` swap).
    Vector {
        cipher: "rev14",
        prim: "Columnar",
        chain: "columnar:width=6,rotate=3,direction=btt,trailer=-M",
        check: Check::PlaintextContains,
    },
    // gk12's recorded solution: a Quagmire III configuration reduced here to a
    // Vigenère autokey over a keyed alphabet built from "ZOMBIESAREEVERYWHERE"
    // (deduplicated; see `ra_core::classical::autokey` for the exact policy).
    // Recovers the recorded plaintext exactly, byte for byte.
    Vector {
        cipher: "gk12",
        prim: "Autokey",
        chain: "autokey:key=TRYTHIS,alphabet=ZOMBIESAREEVERYWHERE",
        check: Check::PlaintextContains,
    },
    // ---------------------------------------------------------------------
    // Classical ciphers. These prove no mcrypt primitive that is not already
    // proven, so they leave the 11-of-11 count untouched by construction; what
    // they establish is that the *classical* nodes reproduce the corpus too, which
    // is what unblocks the last three recorded chains.
    // ---------------------------------------------------------------------
    //
    // rev2 end to end, and the vector that proves `bacon`. Four corrections to the
    // recorded chain, all reported at `ra_core::classical::bacon`:
    //
    //  1. The key is `Zombies`, **not** the recorded `ZOMBIES`. Under `ZOMBIES` this
    //     chain yields high-entropy noise from the first byte; under `Zombies` it
    //     yields 2,212 bytes of nothing but `A`, `B` and spaces. rev2's record is
    //     the only place in the corpus that spells the key in upper case, and it is
    //     simply wrong.
    //  2. "Remove the 'v'" needs no node: rev2's ciphertext carries one stray `v`
    //     inside the hex pair `v62`, and `hexdecode` already keeps only hex digits,
    //     so the repair is inherent in the decode rather than a separate step.
    //  3. As everywhere else in this corpus the recorded chain omits the implicit
    //     `b64decode` — rev2's hex decodes to base64 text, which the tools4noobs
    //     decrypt box decodes before decrypting.
    //  4. That base64 is 2,951 characters, one short of a whole number of quads, so
    //     strict decoding rejects it. This is the truncation the corpus itself
    //     records ("ciphertext was truncated by Treyarch"), and the `insert` step
    //     supplies one filler base64 character immediately before the pad so the
    //     stream is well formed. It affects only the final two bytes, which lie past
    //     the end of the message: the recovered text runs to "...SIGNING OFF"
    //     exactly where the recorded plaintext trails off into "???", and the
    //     corpus's note that the true ending "is likely MONTY" is neither confirmed
    //     nor contradicted by anything here.
    //
    // What `bacon` itself had to reconstruct — the 26-letter variant, `A`=0, `B`=1,
    // MSB first, none of which the record states — is derived and pinned in that
    // module.
    Vector {
        cipher: "rev2",
        prim: "Bacon",
        chain: "hexdecode | insert:text=A,pos=2950,unit=byte | b64decode \
                | des:key=Zombies,mode=cfb | bacon",
        check: Check::PlaintextContains,
    },
    // rev3 end to end, and the vector that proves `straddling` and `base10`.
    // Reproduces the recorded plaintext byte for byte, all 61 characters.
    //
    // The `reverse` is an undocumented step: read left to right the digit stream has
    // no straddling parse consistent with the plaintext at all, and read right to
    // left it has exactly one. The `straddle` digits and the `layout` are that one
    // parse, recovered by exhaustive alignment rather than by search.
    //
    // The record's third step, a `substitution` chosen because its "IOC [is] closest
    // to English", is deliberately absent — not skipped. A monoalphabetic
    // substitution after a checkerboard is the same function as a relabelled
    // checkerboard, so the two recorded steps are not separately identifiable from
    // the ciphertext, and `layout` here states their composite. Inventing a split
    // would present a choice as a finding. See `ra_core::classical::straddling`.
    Vector {
        cipher: "rev3",
        prim: "Straddling",
        chain: "base10 | reverse \
                | straddling:straddle=13,layout=C.D..YFE.W/NXM.T...U./.SOGIAR.BH",
        check: Check::PlaintextContains,
    },
    // rev4 end to end, and the vector that proves `adfgx`. One recorded step, three
    // reconstructed parameters, and one part of the record that does not survive
    // checking — see `ra_core::classical::adfgx`:
    //
    //  - `symbols=11/14/21/22/53`. The charset is `12345`, which invites reading the
    //    five ADFGX letters as the digits 1..5; that reading is wrong. 660
    //    characters against 165 plaintext letters is four per letter, and the
    //    four-character groups take exactly 25 distinct values, all pairs from those
    //    five two-digit tokens — which are where `A D F G X` sit in the standard
    //    square. The cipher alphabet is itself Polybius-encoded, which is what the
    //    record's own "Polybius square conversion" denotes.
    //  - The square is *unkeyed*: the plain I/J-merged alphabet, this node's default.
    //  - The transposition is 7 columns under the alphabetical ranking of `ZOMBIES`.
    //    The record's "transpose key 30957298 -> ZOMBIES" reads as the number being
    //    that ranking; it is not. `ZOMBIES` ranks to the seven digits `7541326`, and
    //    `30957298` has eight and matches nothing in the reproduction. The `ZOMBIES`
    //    half of the note is exact; the number is unexplained.
    //
    // Checked on letters because a 25-cell square cannot encode the spaces, comma
    // and lower case the transcription has; the recovery is otherwise exact, and
    // `adfgx`'s own tests pin all 165 letters against this same ciphertext.
    Vector {
        cipher: "rev4",
        prim: "ADFGX",
        chain: "adfgx:key=ZOMBIES,symbols=11/14/21/22/53",
        check: Check::PlaintextLettersContain,
    },
    // rev11 end to end: the corpus's only seven-step classical chain, and the only
    // vector here that reaches plaintext with no modern primitive in it at all.
    // It therefore carries no primitive coverage; it is a conformance vector for
    // the *classical* vocabulary, which is why `prim` is not a PRIMS name.
    //
    // Steps 1-3. The recorded "shift 6" is an *encryption* shift, so decryption
    // applies its inverse — ROT-20, the convention rev12 already established, and
    // `rot:n=6` here yields letters that are not a valid Playfair text at all.
    // `playfair` then strips the ciphertext's digraph spacing itself, because that
    // is what Playfair encryption did to it.
    //
    // Steps 4-6 repair what Playfair destroyed, and the recorded prose for each is
    // approximate where the positions are exact — see `ra_core::classical::edits`,
    // which records the discrepancies. In summary: step 4's "all but one 'probable
    // padding' X between doubles" is nine removals, of which eight are between
    // doubles (two such X's are kept, not one) and the ninth is the odd-length tail
    // pad at offset 459; step 5's "some I with J" is eighteen; step 6 inserts
    // eleven periods, which exist because the inner Trifid's alphabet has 27
    // symbols and Playfair drops the 27th.
    //
    // Step 7's parameters are **recovered, not recorded** — the corpus names the
    // step "Trifid" and stops. Both were solved from rev11's own recorded
    // plaintext/ciphertext pair and reproduce it at 462 of 462 symbols; the
    // alphabet is `a`..`z` then `.` filled down the columns of the three 3x3
    // squares, and the period is the whole message as one block. No other period
    // in 2..=462 reproduces it. See `ra_core::classical::trifid`.
    //
    // The recovered text differs from the recorded plaintext at three places out of
    // 464 normalised characters (0.9935 similarity): the record reads "Primis"
    // where the chain yields "primus", "strenght" where the chain yields
    // "strength", and "all of humanity" where the chain yields "all humanity". All
    // three are transcription drift in the *record*: the chain's length is forced
    // to 462 by the 460-letter Playfair output, and the recorded plaintext is 464.
    Vector {
        cipher: "rev11",
        prim: "Playfair/Trifid",
        chain: "reverse | rot:n=20 | playfair:key=ZOMBIES \
                | remove_character:char=x,positions=31;133;179;215;235;345;383;427;459 \
                | replace_character:from=i,to=j,positions=10;21;63;66;169;177;189;227;250;296;337;340;353;373;386;387;422;433 \
                | insert_characters:char=.,positions=46;83;165;179;201;222;233;241;264;270;352 \
                | trifid:alphabet=adgbehcfijmpknqlorsvytwzux.,period=0",
        // Letters-only, and declared here rather than hidden in the checker.
        // Playfair discarded rev11's spacing and capitals before the message was
        // ever enciphered, so no correct chain can put them back and demanding
        // them would be demanding a fabrication. That relaxation is real, so it
        // belongs at the vector that needs it: a silent fallback inside
        // `PlaintextContains` would have quietly lowered the bar for every other
        // vector too, present and future.
        check: Check::PlaintextLettersContain,
    },
    // tg3 end to end (The Giant map, community-attributed to the CIMT/MEP
    // Simplified Lorenz Cipher Toolkit at 100% confidence). Recovers the
    // recorded plaintext byte for byte, all 48 characters, over the ITA2/Tunny
    // 32-glyph alphabet (not base64, despite the overlapping `+`/`/`).
    //
    // tg3's recorded solution reads "K-wheel = 9 and S-wheel = 4"; those are
    // 1-indexed **start positions**, not wheel lengths (the K wheel's cam
    // pattern is the fixed 14-letter `A..N`, and the S wheel's is the fixed
    // 4-letter `AABB` the toolkit's own script hard-codes — see
    // `ra_core::classical::cimt_lorenz`). Reading "9" and "4" as lengths would
    // give a keystream period of 36; the recovered keystream's exact period is
    // 28 = lcm(14, 4), which only the start-position reading explains.
    Vector {
        cipher: "tg3",
        prim: "CIMT Simplified Lorenz",
        chain: "cimt_lorenz:k_start=9,s_start=4",
        check: Check::PlaintextContains,
    },
];

/// The recorded chains this engine actually reproduces, as `(cipher, chain spec)`.
///
/// Exposed so the sweep can *derive* its inter-layer codec vocabulary from the
/// solved corpus instead of asserting one: see
/// `sweep::tests::codec_vocabulary_is_derived_from_the_corpus`. Reading the
/// vocabulary off these chains is the only way the claim's codec dimension stays
/// tied to evidence rather than to someone's recollection of it.
#[cfg(test)]
pub fn reproduced_chains() -> impl Iterator<Item = (&'static str, &'static str)> {
    VECTORS.iter().map(|v| (v.cipher, v.chain))
}

/// What one conformance vector did when it was executed.
pub struct VectorOutcome {
    pub prim: &'static str,
    pub cipher: &'static str,
    pub chain: &'static str,
    /// `None` means the chain reproduced; `Some` carries why it did not.
    pub error: Option<String>,
}

impl VectorOutcome {
    pub fn passed(&self) -> bool {
        self.error.is_none()
    }
}

/// The conformance state this engine is actually in, as data rather than as printed
/// text.
///
/// This exists because conformance gating has to be *applied*, not merely displayed.
/// `ra residual` folds sweep-emitted claims into the aggregate, and every one of them
/// must be intersected with [`ConformanceState::proven_primitives`] first; a state
/// that only ever reached a terminal could not do that, and for a long time it
/// didn't.
pub struct ConformanceState {
    /// Every vector executed, in declaration order.
    pub outcomes: Vec<VectorOutcome>,
    /// mcrypt primitives (by `PRIMS` display name) whose vector reproduced a solved
    /// corpus cipher end to end. [`ra_attest::ProvenClass::CorpusProven`].
    pub proven: BTreeSet<String>,
    /// Primitives whose corpus vector ran and did **not** reproduce, with the reason.
    pub failed: BTreeMap<String, String>,
    /// mcrypt primitives in the vocabulary with no executable *corpus* vector here
    /// at all. Note this is silent on VectorProven: a primitive can be in this set
    /// and still admit coverage via `vector_proven`. See
    /// [`ConformanceState::unproven`] for the set that admits none at all.
    pub no_vector: BTreeSet<String>,
    /// Classical nodes reproduced. They prove no mcrypt primitive, so they carry no
    /// primitive coverage and are tallied separately.
    pub classical: Vec<String>,
    /// mcrypt primitives whose *implementation* is checked against the algorithm's
    /// own published/normative test vector — [`ra_attest::ProvenClass::VectorProven`]
    /// — read off [`ra_prim::PrimInfo::vector_proof`]. Disjoint from `proven`: a
    /// primitive that is both is counted only in `proven`, the stronger claim.
    ///
    /// This is a fact about the *build*, not about this run's corpus reproduction,
    /// so it does not depend on `only` the way `outcomes` does.
    pub vector_proven: BTreeSet<String>,
    /// primitive -> corpus ciphers, from `conformance_suite.json`.
    pub suite: BTreeMap<String, Vec<String>>,
    /// Content digest of `suite`, so a claim can record which suite it ran under.
    pub suite_digest: String,
}

impl ConformanceState {
    /// The proven set in the shape the gate consumes — both classes, tagged.
    pub fn proven_primitives(&self) -> ra_attest::ProvenPrimitives {
        let mut out = ra_attest::ProvenPrimitives::from_names(self.proven.iter());
        for p in &self.vector_proven {
            out.insert_with_class(p, ra_attest::ProvenClass::VectorProven);
        }
        out
    }

    /// Every primitive in the vocabulary that admits no coverage at all — proven
    /// under neither class. This is `ra_prim::PRIMS` minus `proven` minus
    /// `vector_proven`, i.e. the actual gate-void set; `no_vector` alone
    /// overstates it, since a primitive can lack a corpus vector and still be
    /// VectorProven.
    pub fn unproven(&self) -> BTreeSet<String> {
        ra_prim::PRIMS
            .iter()
            .map(|i| i.display_name.to_string())
            .filter(|n| {
                !self.proven.iter().any(|p| p.eq_ignore_ascii_case(n))
                    && !self.vector_proven.iter().any(|p| p.eq_ignore_ascii_case(n))
            })
            .collect()
    }

    /// Why a primitive named in a claim carries zero coverage.
    ///
    /// Every branch is a *different* failure and they are not interchangeable: a
    /// regression, a primitive that was never implemented, and a primitive with no
    /// vector to prove it against all void a claim, but only the first is a bug.
    /// Only called for primitives in neither proof class — a VectorProven primitive
    /// is never voided, so this never needs to explain one.
    pub fn void_reason(&self, name: &str) -> String {
        if let Some((_, why)) = self
            .failed
            .iter()
            .find(|(k, _)| k.eq_ignore_ascii_case(name))
        {
            let first = why.lines().next().unwrap_or(why);
            return format!("conformance FAIL: {first}");
        }
        let Some(info) = ra_prim::prim_info(name) else {
            return "not in this engine's primitive vocabulary, so nothing here can \
                    reproduce it"
                .to_string();
        };
        if info.status == ra_prim::ImplStatus::Declared {
            return "declared but not implemented here".to_string();
        }
        if self.suite.keys().any(|k| k.eq_ignore_ascii_case(name)) {
            "implemented and named in the conformance suite, but no vector reproduced \
             it in this run"
                .to_string()
        } else {
            "no corpus conformance vector defines it, and it is not checked against \
             the algorithm's own normative test vector either, so it cannot be \
             proven under either class"
                .to_string()
        }
    }
}

/// Whether `out` satisfies `check` for cipher `cipher`/target `t`. Shared between
/// [`conformance_state`] (real chains) and the `reverse`-vs-`reverse_words`
/// fidelity test below, which reruns the same vectors with `reverse_words`
/// substituted in and needs exactly the same pass/fail rule to compare against.
fn check_output(check: &Check, cipher: &str, t: &Target, out: &Repr) -> Result<()> {
    match check {
        Check::PlaintextContains => {
            let pt = t
                .plaintext
                .as_deref()
                .ok_or_else(|| anyhow!("{cipher} has no recorded plaintext"))?;
            let needle = &pt[..60.min(pt.len())];
            let got = String::from_utf8_lossy(&out.data);
            // Verbatim containment first, so every vector that already
            // matched byte for byte keeps matching on exactly that basis.
            //
            // The fallback exists for the classical chains. A cipher whose
            // outermost layer is a classical letter transform recovers the
            // *letter stream* and nothing else: Playfair discarded rev11's
            // spaces and capitals before it was ever enciphered, so no
            // correct chain can put them back and demanding them would be
            // demanding a fabrication. Recorded plaintexts are
            // transcriptions in any case (see rev1's block filler and
            // rev8's corrupted byte), so the comparison is made on a
            // normalisation that keeps alphanumerics and `.`, lowercased.
            // This can only turn a failure into a pass, never the reverse.
            if !got.contains(needle) {
                let flatten = |s: &str| -> String {
                    s.chars()
                        .filter(|c| c.is_ascii_alphanumeric() || *c == '.')
                        .map(|c| c.to_ascii_lowercase())
                        .collect()
                };
                if !flatten(&got).contains(&flatten(needle)) {
                    bail!(
                        "recovered text does not contain the recorded plaintext \
                         prefix, verbatim or normalised\n\
                         expected: {needle:?}\n     got: {:?}",
                        &got[..90.min(got.len())]
                    );
                }
            }
        }
        Check::PlaintextLettersContain => {
            let pt = t
                .plaintext
                .as_deref()
                .ok_or_else(|| anyhow!("{cipher} has no recorded plaintext"))?;
            let want = letters_only(pt);
            let needle = &want[..60.min(want.len())];
            let got = letters_only(&String::from_utf8_lossy(&out.data));
            if !got.contains(needle) {
                bail!(
                    "recovered letters do not contain the recorded plaintext's \
                     letters\nexpected: {needle:?}\n     got: {:?}",
                    &got[..90.min(got.len())]
                );
            }
        }
        Check::ClassIs(want) => {
            let got = classify(&out.data);
            if got != *want {
                bail!(
                    "expected the intermediate to classify as {}, got {} ({:?})",
                    want.as_str(),
                    got.as_str(),
                    String::from_utf8_lossy(&out.data[..40.min(out.data.len())])
                );
            }
        }
    }
    Ok(())
}

/// Execute the conformance suite and return what it establishes.
///
/// `run_conformance` is a printing wrapper over this; nothing here prints.
pub fn conformance_state(data: &Path, only: Option<&str>) -> Result<ConformanceState> {
    let suite = conformance_vectors(data)?;
    let suite_digest = conformance_suite_digest(&suite);
    let mut outcomes: Vec<VectorOutcome> = Vec::new();

    for v in VECTORS {
        if let Some(f) = only {
            if !v.prim.eq_ignore_ascii_case(f) {
                continue;
            }
        }
        let t = load_target(data, v.cipher)?;
        let chain = crate::spec::parse_chain(v.chain)?;
        let input = Repr::new(t.raw.clone().into_bytes(), t.display);

        let result = (|| -> Result<()> {
            let out = chain.run(&input)?;
            check_output(&v.check, v.cipher, &t, &out)
        })();

        outcomes.push(VectorOutcome {
            prim: v.prim,
            cipher: v.cipher,
            chain: v.chain,
            error: result.err().map(|e| e.to_string()),
        });
    }

    let passed = |name: &str| {
        outcomes
            .iter()
            .any(|o| o.passed() && o.prim.eq_ignore_ascii_case(name))
    };

    // The proven set is over mcrypt primitives only. `outcomes` also carries the
    // classical vectors, which prove no primitive; folding them in once printed
    // "14 of 11".
    let proven: BTreeSet<String> = ra_prim::PRIMS
        .iter()
        .filter(|i| passed(i.display_name))
        .map(|i| i.display_name.to_string())
        .collect();
    let mut failed: BTreeMap<String, String> = BTreeMap::new();
    for o in &outcomes {
        if let Some(e) = &o.error {
            // A primitive with several vectors is proven if any reproduces, so a
            // failure only counts where nothing else covered it.
            if !passed(o.prim) {
                failed.insert(o.prim.to_string(), e.clone());
            }
        }
    }
    let no_vector: BTreeSet<String> = ra_prim::PRIMS
        .iter()
        .filter(|i| {
            !proven.contains(i.display_name)
                && !outcomes.iter().any(|o| o.prim.eq_ignore_ascii_case(i.display_name))
        })
        .map(|i| i.display_name.to_string())
        .collect();
    let classical: Vec<String> = outcomes
        .iter()
        .filter(|o| o.passed() && ra_prim::prim_info(o.prim).is_none())
        .map(|o| o.prim.to_string())
        .collect();

    // VectorProven is a fact about the build (`PrimInfo::vector_proof`), not about
    // this run's corpus reproduction, so it is read straight off `ra_prim::PRIMS`
    // rather than derived from `outcomes`. Disjoint from `proven` on purpose: a
    // primitive proven both ways is counted only under the stronger, CorpusProven
    // claim, so the two sets never double-count the same primitive.
    let vector_proven: BTreeSet<String> = ra_prim::vector_proven()
        .filter(|i| !proven.contains(i.display_name))
        .map(|i| i.display_name.to_string())
        .collect();

    Ok(ConformanceState {
        outcomes,
        proven,
        failed,
        no_vector,
        classical,
        vector_proven,
        suite,
        suite_digest,
    })
}

pub fn run_conformance(data: &Path, only: Option<&str>) -> Result<()> {
    let state = conformance_state(data, only)?;
    let suite = &state.suite;
    println!("CONFORMANCE: reproducing the solved corpus\n");

    let mut fail: Vec<&VectorOutcome> = Vec::new();
    for o in &state.outcomes {
        match &o.error {
            None => println!("  [PASS] {:<16} via {:<6} {}", o.prim, o.cipher, o.chain),
            Some(e) => {
                println!("  [FAIL] {:<16} via {:<6} {}", o.prim, o.cipher, o.chain);
                for line in e.lines() {
                    println!("         {line}");
                }
                fail.push(o);
            }
        }
    }

    println!("\nCOVERAGE OF THE CONFORMANCE SUITE — two proof classes, kept apart");
    println!(
        "  CorpusProven : reproduces a solved corpus cipher end to end with known plaintext.\n  \
         VectorProven : matches the algorithm's own published/normative test vector; no\n  \
         \x20              solved cipher need use it. See ARCHITECTURE.md's conformance\n  \
         \x20              section for why the two are never merged into one count."
    );
    let unproven_now = state.unproven();
    for info in ra_prim::PRIMS {
        let name = info.display_name;
        let has_vectors = suite.keys().any(|k| k.eq_ignore_ascii_case(name));
        let corpus_proven = state.proven.contains(name);
        let vector_proven = state.vector_proven.contains(name);
        let status = match (info.status, corpus_proven, vector_proven, has_vectors) {
            (ra_prim::ImplStatus::Declared, ..) => "NOT IMPLEMENTED - zero coverage".to_string(),
            (_, true, _, _) => "CorpusProven - may carry coverage".to_string(),
            (_, false, true, _) => format!(
                "VectorProven - may carry coverage ({})",
                info.vector_proof.unwrap_or("no citation recorded")
            ),
            (_, false, false, true) => "UNTESTED here - zero coverage until reproduced".to_string(),
            (_, false, false, false) => {
                "Unproven - no corpus vector, no normative vector cited - zero coverage".to_string()
            }
        };
        println!("  {:<18} {}", name, status);
    }

    // Every reproduced vector includes entries that are not mcrypt primitives at all,
    // since the classical nodes landed. Counting them together printed "14 of 11", so
    // the two populations stay split in `ConformanceState`: `proven` is what
    // conformance gating acts on, and `classical` is a separate statement about
    // corpus coverage.
    let corpus_proven_count = state.proven.len();
    let vector_proven_count = state.vector_proven.len();
    let classical: Vec<&str> = state.classical.iter().map(String::as_str).collect();

    println!(
        "\n  {} of {} confirmed mcrypt primitives are CorpusProven (reproduced end to end).",
        corpus_proven_count,
        ra_prim::PRIMS.len()
    );
    println!(
        "  {} of {} are additionally VectorProven and carry coverage on that basis alone: {}",
        vector_proven_count,
        ra_prim::PRIMS.len(),
        if vector_proven_count == 0 {
            "(none)".to_string()
        } else {
            state.vector_proven.iter().cloned().collect::<Vec<_>>().join(", ")
        }
    );
    if unproven_now.is_empty() {
        println!("  0 unproven: every primitive in the vocabulary carries coverage under one class or the other.");
    } else {
        println!(
            "  {} Unproven under EITHER class, so contributing ZERO coverage: {}",
            unproven_now.len(),
            unproven_now.iter().cloned().collect::<Vec<_>>().join(", ")
        );
    }
    if !classical.is_empty() {
        println!(
            "  plus {} classical node(s) reproduced: {}",
            classical.len(),
            classical.join(", ")
        );
    }
    println!(
        "\n  Conformance gating means a primitive proven under NEITHER class contributes ZERO\n  \
         coverage, so a sweep over it cannot subtract from the residual. This is the\n  \
         designed behaviour: it is better to under-claim than to silently void a claim.\n  \
         CorpusProven and VectorProven both admit coverage; they are reported separately\n  \
         so a reader can see at a glance how much of a negative rests on which proof."
    );

    if !fail.is_empty() {
        bail!("{} conformance vector(s) failed", fail.len());
    }
    Ok(())
}

/// Convenience wrapper used by the sweep: decrypt with explicit parameters.
///
/// `key` is the passphrase *bytes* rather than a `&str`, because a key domain value
/// need not be the literal characters of its own name — `TheGiant_b64` denotes the
/// base64 encoding of `TheGiant`.
pub fn decrypt_once(
    prim: &str,
    mode: Mode,
    key: &[u8],
    iv: &[u8],
    kd: KeyDerivation,
    data: &[u8],
) -> Option<Vec<u8>> {
    ra_prim::decrypt(prim, mode, key, iv, kd, data).ok()
}

// ---------------------------------------------------------------------------
// `reverse` vs `reverse_words` fidelity check
// ---------------------------------------------------------------------------
//
// The corpus author's toolsite (`unit-conversion.info/texttools`) offers two
// distinct tools, "Reverse text" (full character reversal) and "Reverse
// words" (word order reversed, each word's own characters intact). Every
// `reverse` step recorded in `VECTORS` was reproduced with this engine's
// character-reversal `reverse` node — but that is only good evidence if the
// *other* candidate genuinely fails at the same position. See
// `docs/layering-pattern-analysis.md` §8sexies.
#[cfg(test)]
mod reverse_fidelity {
    use super::*;

    /// Every `VECTORS` chain with a bare `reverse` step, substituting
    /// `reverse_words` for it and re-running: the substituted chain must NOT
    /// satisfy the vector's own `check`, confirming that full-character
    /// reversal -- not word-order reversal -- is what the corpus's `reverse`
    /// steps actually denote, for every solved chain that uses one.
    #[test]
    fn reverse_is_not_interchangeable_with_reverse_words_in_any_solved_chain() {
        let data = resolve_data_dir(None).expect("locate corpus data dir");
        let mut checked: Vec<&str> = Vec::new();

        for v in VECTORS
            .iter()
            .filter(|v| v.chain.split('|').any(|step| step.trim() == "reverse"))
        {
            checked.push(v.cipher);

            let t = load_target(&data, v.cipher).expect("load target");
            let input = Repr::new(t.raw.clone().into_bytes(), t.display);

            // Sanity: the recorded chain, with the real `reverse`, still passes.
            let real_chain = crate::spec::parse_chain(v.chain).expect("parse recorded chain");
            let real_out = real_chain.run(&input).expect("recorded chain must still run");
            check_output(&v.check, v.cipher, &t, &real_out).unwrap_or_else(|e| {
                panic!("{}: the recorded `reverse` chain must still reproduce: {e}", v.cipher)
            });

            // Substitute `reverse_words` in the exact same position(s) and rerun.
            let swapped_spec: String = v
                .chain
                .split('|')
                .map(|step| if step.trim() == "reverse" { " reverse_words " } else { step })
                .collect::<Vec<_>>()
                .join("|");
            let swapped_chain =
                crate::spec::parse_chain(&swapped_spec).expect("parse reverse_words variant");
            let swapped_result = swapped_chain
                .run(&input)
                .map_err(anyhow::Error::from)
                .and_then(|out| check_output(&v.check, v.cipher, &t, &out));

            assert!(
                swapped_result.is_err(),
                "{}: `reverse_words` must NOT reproduce this chain if `reverse` \
                 (full character reversal) genuinely does -- a pass here would mean \
                 the corpus's `reverse` step is ambiguous between the two tools:\n{}",
                v.cipher,
                v.chain
            );
        }

        // Guard against the check silently checking nothing: the corpus records
        // `reverse` in several chains (rev1, rev3, rev5 x2, rev6, rev8, rev9,
        // rev11, rev12, rev13), so this must exercise more than a couple.
        assert!(
            checked.len() >= 8,
            "expected at least 8 VECTORS entries to use `reverse`, found {}: {:?}",
            checked.len(),
            checked
        );
    }
}

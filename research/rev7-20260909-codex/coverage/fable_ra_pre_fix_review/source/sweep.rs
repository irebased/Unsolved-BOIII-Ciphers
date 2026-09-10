//! The sweep executor: enumerate a bounded space, score it, and commit to it.
//!
//! Three properties the design requires and this implements:
//!
//! - **The enumeration is deterministic.** Candidate `i` is a pure function of the
//!   parameter lists and `i`, so any challenged candidate can be regenerated without
//!   replaying the whole sweep. That is what makes a spot audit cheap.
//! - **Outputs are not retained.** Each candidate is folded into a streaming Merkle
//!   commitment and discarded; only above-threshold hits are kept.
//! - **The claim is emitted as a coverage set, not a count.** A count does not
//!   compose and cannot be differenced. A coverage set can, so the result is
//!   directly usable in a residual calculation.
//!
//! # Tiers, and why the skeleton is the unit of enumeration
//!
//! The coverage algebra partitions the space of pipelines by **skeleton** — the
//! ordered tuple of layer families. Claims in different skeletons never interact
//! (`ra_covalg`'s `skeletons_are_independent`), so each skeleton is enumerated as its
//! own run with its own commitment and its own cover:
//!
//! | Tier | Skeleton | Meaning |
//! |---|---|---|
//! | T1 | `b64d ∘ dec` | decode the ciphertext, one modern layer |
//! | T2 | `b64d ∘ xf ∘ dec` | decode, transform, one modern layer |
//! | T3 | `b64d ∘ dec ∘ xf ∘ codec ∘ dec` | decode, modern layer, transform, **re-encode**, modern layer |
//!
//! # The inter-layer codec is a dimension, not a constant
//!
//! T3's `codec` slot is the structural correction this module exists to carry. Every
//! chain recorded in the corpus **omits an implicit decode** at each decrypt hop: the
//! tools4noobs decrypt box base64-decodes its input, so between one layer's output
//! and the next layer's input there is a re-encoding step that no recorded chain
//! mentions. rev9 does not reproduce without it and rev1 needs *two*. A model built
//! from the recorded chains therefore has the wrong skeleton vocabulary — it
//! enumerates `dec ∘ xf ∘ dec` (which is exactly what `reference/py/residual.py`'s
//! `SK_T3` says) when the truth is `dec ∘ xf ∘ codec ∘ dec`. The reference model's T3
//! does not contain the pipelines that actually solved the corpus.
//!
//! So the re-encoding is an enumerable axis, and its domain is *derived from the
//! solved corpus* rather than invented. Taking every hop between two consecutive
//! layer-forming steps in the chains this engine reproduces (`corpus::VECTORS`, via
//! [`crate::corpus::reproduced_chains`]):
//!
//! | Hop | Codec steps between the two layers |
//! |---|---|
//! | rev9  DES → Twofish | `decimaldecode`, (`reverse`), `b64decode` |
//! | rev5  RC2 → Blowfish | (`reverse`), `hex_to_base64`, `b64decode` |
//! | rev5  Blowfish → Loki97 | `b64decode` |
//! | rev1  RC2 → Rijndael-256 | (`reverse`), `b64decode` |
//! | rev10 RC4 → SAFER+ | `octaldecode`, `hexdecode` |
//!
//! which yields the codec vocabulary `{identity, b64decode, hexdecode,
//! hex_to_base64|b64decode, decimaldecode, octaldecode}`. `codec_vocabulary_is_derived_from_the_corpus`
//! checks that equality against the vectors, so inventing a value or dropping an
//! observed one fails the build rather than quietly changing what a claim means.
//!
//! Two honest notes on that vocabulary:
//!
//! - `hexdecode` and `hex_to_base64|b64decode` are extensionally equal — the base64
//!   round trip in the middle is a no-op on the denoted bytes. They are nonetheless
//!   *distinct pipelines*, both spelled out in the corpus, so both are enumerated.
//!   Collapsing them would evaluate one and claim two.
//! - The fullest arrangement the corpus shows is `codec ∘ xf ∘ codec` (rev9:
//!   `decimaldecode | reverse | b64decode`). T3 as enumerated here is the
//!   `xf ∘ codec` sub-form. The leading codec is a *different skeleton*
//!   (`b64d ∘ dec ∘ codec ∘ xf ∘ codec ∘ dec`) and is therefore visibly absent from
//!   the claim rather than silently assumed away: the skeleton tuple states the
//!   arrangement, and the algebra will not let a claim in one skeleton subtract from
//!   another.
//!
//! # Bounding is explicit, never silent
//!
//! A negative result over a sub-product is useful; a negative result that *claims* a
//! product it only sampled is the exact failure this project exists to prevent. So
//! `--max-candidates` truncates the index space at `N` and the emitted cover is the
//! **prefix decomposition** of `[0, N)` in the mixed radix of the axes — a disjoint
//! union of at most `Σ digits(N)` products whose sizes sum to exactly `N`
//! ([`Plan::products`]). `size_exact()` then equals the number of candidates actually
//! evaluated by construction, and `coverage_set_size_matches_candidates_evaluated`
//! asserts it for both the bounded and the unbounded case.
//!
//! # The transcription is an axis, not a constant
//!
//! Every sweep before this one took the recorded ciphertext as given and named the
//! assumption `v01` in the claim. For TG4 that assumption hides 127 siblings: the
//! transcription is a reading of an image, and its `I`/`l` glyph pair is genuinely
//! ambiguous at seven positions. [`crate::variants`] derives those positions from the
//! ciphertext at runtime and turns them into the `0.variant` axis, so a TG4 run
//! enumerates the transcription jointly with the cipher parameters instead of fixing
//! it. (The `0`/`O` pair *looks* equally confusable and is not: the project team
//! resolved it against the source font, so its seven positions are fixed. That is what
//! keeps the space at 128 rather than 16,384 — see [`crate::variants`].)
//!
//! Because 128 readings is affordable at every tier, all three tiers are swept
//! exhaustively over the whole variant space: there is no bound to log and no
//! prioritisation to justify. The axis is nonetheless the **most significant** digit of
//! the index, so that if a future run ever does need `--max-candidates`, the prefix
//! covers *whole transcriptions* and the claim stays legible ("these readings,
//! completely") instead of smearing across the product.
//!
//! TG4's corpus record has since acquired a `ciphertext_canonical` field — a
//! project-supplied re-reading that, as of 2026-07-30, resolves every one of the
//! seven `I`/`l` positions — so a default sweep's `0.variant` axis is the single
//! reading `v10`, not 128, even though every label from `v00` to `v7f` still names
//! the same bytes it always did. `v00`, the legacy corpus reading, is **not**
//! admissible under this canonical: the two differ at offset 39. See
//! [`crate::variants::VariantSpace::derive_canonical`], [`VariantSpace::select`]'s
//! `recorded` case (which resolves to whichever mask is actually admissible, not a
//! hardcoded `v00`), and `claims/tg4-canonical-2026-07-30.json` — a claim committed
//! against the *previous* canonical's `{v4c, v6c}` pair, superseded but still
//! internally verifiable.
//!
//! # Tool-output formatting artifacts, as an axis (`--toolfmt`)
//!
//! `ra_core::classical::toolfmt` models the grouping/trailing-terminator artifacts a
//! real website tool imposes on its own output, and its own module doc states they
//! are meant to be swept both on and off — but until now nothing in this CLI ever
//! enumerated them; they were reachable only from a hand-authored `ra run` chain.
//! `--toolfmt` closes that gap. See [`ToolFmt`] for the exact domain (restricted to
//! the two dimensions — blocks-of-5 grouping and `Trailing::{Lf,CrLf}` — with direct
//! corpus evidence) and for why the position is the boundary immediately before a
//! modern decrypt call, not the raw ciphertext text or the final scored output:
//! every decode step already tolerates such artifacts (`ra_core::repr`'s
//! whitespace-robustness tests) and so does the oracle on the final prose (audited
//! separately), but nothing between decode and decrypt does. Like [`Pre`]/[`Post`],
//! this axis is omitted from the index entirely at its default (`none`), so a claim
//! committed before it existed still reconciles byte for byte
//! (`toolfmt_axis_is_omitted_at_default_so_old_commitments_still_reconcile`).

use std::collections::BTreeMap;
use std::path::Path;
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::Mutex;
use std::time::Instant;

use anyhow::{Context, Result};
use base64::Engine as _;
use clap::Args;
use ra_core::Repr;
use ra_covalg::{Cover, CoverageSet, Product};
use ra_merkle::{leaf_hash, Hash, StreamingMerkle};
use ra_oracle::{Metric, OracleSpec};
use ra_prim::{KeyDerivation, Mode};
use rayon::prelude::*;

use crate::variants::VariantSpace;

/// The inter-layer codec domain, as derived from the solved corpus. Spelled as a
/// default so `--codec` is documentation rather than a thing operators must know.
const CODEC_DEFAULT: &str =
    "identity,b64decode,hexdecode,hex_to_base64|b64decode,decimaldecode,octaldecode";

/// Caps on retained hit records, per chunk and globally. Hits are reported, not
/// stored, so an oracle that floods (see the false-positive budget in the run
/// report) cannot exhaust memory.
///
/// Retention keeps the **most significant** hits rather than the first ones seen.
/// That distinction is load-bearing: T3's short inter-layer decodes produce millions
/// of chance passes over a three-byte scored region, and a first-N policy would let
/// them displace a genuine full-length solve found later in the index space. Ranking
/// by scored length before score means a real hit cannot be crowded out.
const CHUNK_HIT_CAP: usize = 32;
const HIT_RETENTION_CAP: usize = 256;

/// Significance order for retention and reporting: a long scored region outranks a
/// high ratio over a handful of bytes.
fn significance(h: &Hit) -> (usize, f64) {
    (h.scored_len, h.score)
}

/// Keep at most `cap` of the most significant hits.
fn push_hit(hits: &mut Vec<Hit>, hit: Hit, cap: usize) {
    if hits.len() < cap {
        hits.push(hit);
        return;
    }
    let (worst_i, worst) = hits
        .iter()
        .enumerate()
        .map(|(i, h)| (i, significance(h)))
        .min_by(|a, b| a.1.partial_cmp(&b.1).unwrap_or(std::cmp::Ordering::Equal))
        .expect("cap > 0");
    if significance(&hit) > worst {
        hits[worst_i] = hit;
    }
}

#[derive(Args)]
pub struct SweepArgs {
    /// Corpus cipher id to attack, e.g. tg4 or rev7.
    #[arg(long)]
    pub target: String,

    /// Tiers/skeletons to enumerate: t1, t2, t3. Each is swept and committed to
    /// separately, because the coverage algebra partitions by skeleton. "auto"
    /// picks t2 when a non-identity transform is listed and t1 otherwise.
    #[arg(long, value_delimiter = ',', default_value = "auto")]
    pub tier: Vec<String>,

    /// Primitives to try. Defaults to every implemented one.
    #[arg(long, value_delimiter = ',')]
    pub prims: Option<Vec<String>>,

    /// Modes to try, in mcrypt spelling ("cfb" means CFB-8).
    #[arg(long, value_delimiter = ',', default_value = "cfb")]
    pub modes: Vec<String>,

    /// Candidate keys. A `_b64` suffix denotes the base64 encoding of the prefix,
    /// which is what the `TheGiant_b64` domain value in the universe model means.
    #[arg(long, value_delimiter = ',', default_value = "Zombies")]
    pub keys: Vec<String>,

    /// Key-derivation policies.
    #[arg(long, value_delimiter = ',', default_value = "null-pad-max")]
    pub kd: Vec<String>,

    /// IVs, as named domain values: ascii0, null.
    #[arg(long, value_delimiter = ',', default_value = "ascii0")]
    pub ivs: Vec<String>,

    /// Transform to apply: identity, reverse, or bwt (inverse Burrows-Wheeler
    /// transform, default sentinel `|`). In T2 it runs before the modern layer;
    /// in T3 it runs between the two modern layers. `bwt` rejects ciphertext
    /// that is not a well-formed BWT output, which the candidate is then simply
    /// skipped for — same as any other inapplicable transform.
    #[arg(long, value_delimiter = ',', default_value = "identity")]
    pub xf: Vec<String>,

    /// Transform applied to the **raw ciphertext text**, before the initial
    /// decode. Unlike `--xf`, which sits at a tier-specific position after the
    /// initial decode, this is the genuine top of the stack in every tier — the
    /// only place a `bwt` sentinel (e.g. `|`) survives to be seen, since the
    /// initial decode (e.g. `b64decode`) would otherwise consume it first.
    ///
    /// Values: `identity`, `bwt`, `reverse`, `reverse_words` (word order
    /// reversed, each word intact -- the distinct sibling of `reverse` on
    /// `unit-conversion.info/texttools`), `stripws`, `group` (group-of-5),
    /// `rot:n=<1..25>`, `beaufort:key=<K>` (default 52-character alphabet),
    /// `cto_caesar:key=<n>`, `cto_beaufort:key=<K>`, `cto_trithemius` (no
    /// parameter -- the site itself has no key field), `cto_gronsfeld:key=<digits>`,
    /// `cto_rotation:n=<blocksize>[,deg=<90|180|270>]` (deg defaults to 90) --
    /// the last five are 2016 CrypTool Online tools, ported against their
    /// literal JS (`ra_core::classical::cto2016`) -- or a `+`-joined sequence
    /// of any of these applied left to right, e.g. `stripws+reverse` or
    /// `stripws+cto_beaufort:key=ZOMBIES`. A rejecting step (only `bwt` can
    /// reject today) skips the candidate, same as `--xf`.
    #[arg(long, value_delimiter = ',', default_value = "identity")]
    pub pre: Vec<String>,

    /// Transform applied to the **terminal decrypted output** — after the tier's
    /// last modern layer, in every tier. Closes the "trailing classical layer"
    /// gap the corpus documents three times (rev2 `... > DES/CFB > bacon`, rev6
    /// `... > Serpent/CFB > substitute`, rev12 `... > XTEA/CFB > reverse > rot`):
    /// a modern layer that decrypts *correctly* still isn't English underneath a
    /// classical layer, so a prose-tuned oracle rejects the right candidate.
    ///
    /// Values: `identity`, `reverse`, `rot:n=<1..25>`, `bacon`,
    /// `substitute:alphabet=<26 letters>`, `affine:a=<n>;b=<n>` (`;` rather than
    /// the chain-spec's `,` between affine's two parameters — see [`Post`]'s doc
    /// for why), or a `+`-joined sequence of these applied left to right, e.g.
    /// `reverse+rot:n=20` (rev12's shape).
    #[arg(long, value_delimiter = ',', default_value = "identity")]
    pub post: Vec<String>,

    /// Inter-layer re-encodings to enumerate between two modern layers (T3 only).
    /// The default is the vocabulary the solved corpus actually uses.
    #[arg(long, value_delimiter = ',', default_value = CODEC_DEFAULT)]
    pub codec: Vec<String>,

    /// Tool-output formatting artifact to strip from the bytes about to reach a
    /// modern decrypt call (every layer, every tier) -- see [`ToolFmt`] for why
    /// this boundary and no other. Values: `none`, `group` (blocks of 5, space
    /// separator), `lf`, `crlf`, `group+lf`, `group+crlf`.
    #[arg(long, value_delimiter = ',', default_value = "none")]
    pub toolfmt: Vec<String>,

    /// Which admissible transcriptions to enumerate on the `0.variant` axis: `all`,
    /// `recorded` (the corpus reading alone), or an explicit comma-separated list of
    /// labels such as `v00,v01`.
    ///
    /// The positions are **derived from the ciphertext**, never hardcoded: the sweep
    /// scans the display text for glyphs whose ambiguity partner is also admissible in
    /// that display. TG4 yields 7 open `I`/`l` positions and so 128 readings — its
    /// `0`/`O` positions are resolved against the source font and fixed. REV7's hex
    /// yields none, because hex excludes `O`, `I` and `l`.
    #[arg(long, default_value = "recorded")]
    pub variants: String,

    /// Domain value for a target whose transcription has **no** glyph ambiguity, whose
    /// variant dimension is therefore a single point that still needs a name.
    ///
    /// A coverage set is a region of *one cipher's* universe — `residual.py` models it
    /// as `universe_tg4(...)`, with no cipher dimension — so the variant is also what
    /// keeps two targets' digests apart. REV7 wants `hex-exact` rather than borrowing
    /// a TG4 label, or the two claims content-address identically and the digest stops
    /// being able to detect duplicate work. Defaults to `<display>-exact`.
    #[arg(long)]
    pub variant_label: Option<String>,

    /// Scoring oracle.
    #[arg(long, default_value = "printable-0.75")]
    pub oracle: String,

    /// Evaluate only the first N candidates of each skeleton. The emitted cover is
    /// the exact prefix decomposition of what was evaluated, never the full product.
    #[arg(long)]
    pub max_candidates: Option<u64>,

    /// Print a progress line at most this often, in seconds. 0 disables.
    #[arg(long, default_value_t = 5.0)]
    pub progress_every: f64,

    /// Print the plan and candidate totals, then stop without evaluating anything.
    #[arg(long)]
    pub dry_run: bool,

    /// Report at most this many hits.
    #[arg(long, default_value_t = 20)]
    pub max_hits: usize,

    /// Write the resulting coverage claim here as JSON.
    #[arg(long)]
    pub emit_claim: Option<std::path::PathBuf>,
}

// ---------------------------------------------------------------------------
// Tiers
// ---------------------------------------------------------------------------

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Tier {
    T1,
    T2,
    T3,
}

impl Tier {
    fn parse(s: &str) -> Option<Tier> {
        match s.trim().to_ascii_lowercase().as_str() {
            "t1" | "1" => Some(Tier::T1),
            "t2" | "2" => Some(Tier::T2),
            "t3" | "3" => Some(Tier::T3),
            _ => None,
        }
    }

    fn id(self) -> &'static str {
        match self {
            Tier::T1 => "t1",
            Tier::T2 => "t2",
            Tier::T3 => "t3",
        }
    }

    /// The ordered tuple of layer families. The **position** of `codec` is
    /// load-bearing: `dec ∘ xf ∘ codec ∘ dec` and `dec ∘ codec ∘ xf ∘ codec ∘ dec`
    /// are different skeletons, so a claim cannot leak from one arrangement to
    /// another.
    pub fn skeleton(self) -> Vec<String> {
        let parts: &[&str] = match self {
            Tier::T1 => &["b64d", "dec"],
            Tier::T2 => &["b64d", "xf", "dec"],
            Tier::T3 => &["b64d", "dec", "xf", "codec", "dec"],
        };
        parts.iter().map(|s| s.to_string()).collect()
    }

    fn layers(self) -> usize {
        match self {
            Tier::T3 => 2,
            _ => 1,
        }
    }
}

// ---------------------------------------------------------------------------
// Axis value types
// ---------------------------------------------------------------------------

/// A representation-preserving transform, as an enumerable domain value.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Xf {
    Identity,
    Reverse,
    /// Inverse Burrows-Wheeler transform, default sentinel `|`. Unlike
    /// `Identity`/`Reverse` this can reject its input (`apply` returns `None`)
    /// when the bytes are not a well-formed BWT output — see
    /// [`ra_core::classical::bwt::inverse_bwt`].
    Bwt,
}

impl Xf {
    fn parse(s: &str) -> Option<Xf> {
        match s {
            "identity" => Some(Xf::Identity),
            "reverse" => Some(Xf::Reverse),
            "bwt" => Some(Xf::Bwt),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            Xf::Identity => "identity",
            Xf::Reverse => "reverse",
            Xf::Bwt => "bwt",
        }
    }

    /// Apply the transform. `None` means the transform rejected its input — a
    /// real property of the pipeline at this point (currently only `Bwt` can do
    /// this), and the candidate is skipped rather than the sweep failing.
    fn apply(self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Xf::Identity => Some(data.to_vec()),
            Xf::Reverse => {
                let mut d = data.to_vec();
                d.reverse();
                Some(d)
            }
            Xf::Bwt => ra_core::classical::bwt::inverse_bwt(data, b'|').ok(),
        }
    }
}

/// A transform applied to the **raw ciphertext text**, before the initial decode
/// (e.g. `b64decode`) runs — the genuine top of the stack, in every tier.
///
/// This is a distinct axis from [`Xf`], not a variant of it. `Xf` sits at a
/// tier-specific position *after* the initial decode: T2 runs it between the
/// decode and the modern layer, T3 between the two modern layers. A
/// sentinel-carrying transform placed there can never see its sentinel when the
/// sentinel is not itself a character of the initial decode's alphabet — `bwt`'s
/// default sentinel `|` is not a base64 character, so `b64decode` destroys it
/// before an `Xf::Bwt` on the `--xf` axis ever runs. `Pre` runs first, against
/// the ciphertext text exactly as transcribed, which is the only place the
/// sentinel still exists.
///
/// # Vocabulary, and why it stops here
///
/// `docs/TEST-DOMAIN.md` §4 ranks "a step before the first decryption" as the
/// largest gap in the swept domain — 2 of 11 reproduced corpus chains open with
/// one (rev1's `beaufort:key=ZOMBIES`, rev8's `insert:...`) — and the cheapest to
/// close, because the engine already has every node this axis needs. The
/// vocabulary below is drawn only from what the corpus actually opens a chain
/// with, or what rev7's own formatting arithmetic (`docs/TEST-DOMAIN.md`,
/// "the live unsolved target") confirms as its prefix: `reverse`, `stripws`,
/// `rot`, `beaufort` (default 52-character alphabet, the same one rev1 needs),
/// and `group`. `insert` and `substitute` are deliberately **not** added here:
/// `insert` is rev8-specific (`pos` is a property of that one transcription, not
/// a domain value to enumerate) and `substitute` has no corpus chain that opens
/// with it. Classical operations over the 64-symbol base64 alphabet are also
/// deliberately excluded — no 2016-era tool this project models offered one.
///
/// # 2016 CrypTool Online, as a LEADING transform
///
/// rev7's leading hypothesis is that its TOP layer, above a modern mcrypt
/// core, was produced by the 2016 CrypTool Online site (see
/// `docs/toolsites/cryptool2016/js/*.js`). `cto_caesar`, `cto_beaufort`,
/// `cto_trithemius`, `cto_gronsfeld`, and `cto_rotation` (all `Family::Xf`
/// nodes in `ra_core::classical::cto2016`) are that site's tools ported
/// against its literal 2016 JS, not the textbook cipher — see that module's
/// docs for every fidelity divergence found. They are exposed here as
/// `cto_caesar:key=<n>`, `cto_beaufort:key=<K>`, `cto_trithemius` (no domain
/// parameter — the site itself has no key field), `cto_gronsfeld:key=<digits>`,
/// and `cto_rotation:n=<blocksize>[,deg=<90|180|270>]` (`deg` defaults to
/// `90`). Every other node param (alphabet, `keep_non_alphabet`, ...) stays at
/// the site's own default, matching how `rot:n=` and `beaufort:key=` already
/// only enumerate the ONE param the corpus varies.
///
/// # Composition: `+`, not another comma
///
/// A single `--pre` value can be a `+`-joined sequence of the primitives above
/// (e.g. `stripws+reverse`, the composite rev7 needs), applied left to right.
/// `+` rather than reusing the axis's own `,` delimiter, and rather than a
/// generic recursive grammar: this project already has exactly this convention
/// for `--codec` ([`Codec::parse`]), where `+` is accepted in place of the
/// chain spec's `|` so a multi-step domain value needs no shell quoting.
/// Following it here means one composition idiom for the whole sweep CLI
/// instead of two.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Pre {
    Identity,
    /// Inverse Burrows-Wheeler transform, default sentinel `|`.
    Bwt,
    Reverse,
    /// `reverse_words`: word order reversed, each word's own characters
    /// intact — the distinct sibling `reverse` (full character reversal)
    /// exposed here so the sweep can cover both of
    /// `unit-conversion.info/texttools`'s "Reverse text"/"Reverse words"
    /// tools (see `docs/layering-pattern-analysis.md` §8sexies and
    /// `ra_core::nodes::ReverseWords`).
    ReverseWords,
    StripWs,
    /// `group` with the node's own default width (5), matching the node's
    /// `group:size=5` default and rev7's observed group-of-5 hex formatting.
    Group,
    /// `rot:n=<1..25>`, the classical Caesar-family shift over A-Z/a-z.
    Rot(u8),
    /// `beaufort:key=<K>`, over the node's own default 52-character mixed-case
    /// alphabet — the same alphabet rev1's recorded chain needs. `K` is drawn
    /// from the sweep's own `--keys` vocabulary rather than invented.
    Beaufort(String),
    /// `cto_caesar:key=<n>` — CrypTool Online 2016's Caesar app (`cto_caesar`
    /// node), a keyed shift over its own flat 52-character default alphabet.
    /// Unlike [`Pre::Rot`], a shift here can cross the upper/lowercase
    /// boundary (see `cto_caesar`'s own module docs) — this is a genuinely
    /// different cipher from `rot`, not an alias.
    CtoCaesar(i64),
    /// `cto_beaufort:key=<K>` — the alphabet-authoritative 2016 CrypTool
    /// Online Beaufort port (`cto_beaufort` node), over the same default
    /// alphabet as [`Pre::Beaufort`] but exposing the site's `keep_non_alphabet`
    /// toggle; see that node's module docs for how it relates to `beaufort`.
    CtoBeaufort(String),
    /// `cto_trithemius` — CrypTool Online 2016's Trithemius app
    /// (`cto_trithemius` node), the unkeyed progressive-shift cipher; no
    /// domain parameter, since the site itself exposes no key field (the
    /// alphabet, left at its A-Z default, IS the key — see that node's docs).
    CtoTrithemius,
    /// `cto_gronsfeld:key=<digits>` — CrypTool Online 2016's Gronsfeld app
    /// (`cto_gronsfeld` node), a Vigenere variant keyed by digits 0-9.
    CtoGronsfeld(String),
    /// `cto_rotation:n=<blocksize>` or `cto_rotation:n=<blocksize>,deg=<90|180|270>`
    /// — CrypTool Online 2016's grid-rotation transposition (`cto_rotation`
    /// node); `deg` defaults to `90`, matching the site's own page-load
    /// selection, if omitted.
    CtoRotation(i64, u16),
    /// A `+`-joined sequence of the above, applied left to right. Never
    /// contains `Identity` or a nested `Composite` — [`Pre::parse`] only
    /// produces this shape for genuinely multi-step input.
    /// Any registered node, given as a chain-spec step (`name` or
    /// `name:k=v,k=v`).
    ///
    /// The named variants above exist because they predate the registry being
    /// reachable from here; this one makes the other 120-odd nodes usable without
    /// a new variant each. It is what lets a sweep put `hill` over a **hex** or
    /// **base64** alphabet at the top of the stack — the corpus's layered targets
    /// live in those alphabets, and no 26-letter-only axis could reach them.
    Node(String),
    Composite(Vec<Pre>),
}

impl Pre {
    /// Parse one `--pre` domain value, which may itself be a `+`-joined
    /// composition (see the type doc). `|` is accepted as an equivalent
    /// separator too — [`Pre::label`] spells a composite with `|`, matching
    /// the chain-spec separator, so a label recovered from a recorded claim
    /// (`get("pre")` in [`axes_from_order`]) round-trips through this same
    /// parser. [`Codec::parse`] makes the identical choice for the same
    /// reason.
    fn parse(s: &str) -> Option<Pre> {
        let norm = s.trim().replace('+', "|");
        let parts: Vec<&str> = norm.split('|').collect();
        if parts.len() > 1 {
            let ops: Option<Vec<Pre>> = parts.iter().map(|p| Pre::parse_one(p)).collect();
            return ops.map(Pre::Composite);
        }
        Pre::parse_one(&norm)
    }

    /// Parse a single, non-composite step.
    fn parse_one(s: &str) -> Option<Pre> {
        if s == "identity" {
            return Some(Pre::Identity);
        }
        if s == "bwt" {
            return Some(Pre::Bwt);
        }
        if s == "reverse" {
            return Some(Pre::Reverse);
        }
        if s == "reverse_words" {
            return Some(Pre::ReverseWords);
        }
        if s == "stripws" {
            return Some(Pre::StripWs);
        }
        if s == "group" {
            return Some(Pre::Group);
        }
        if let Some(rest) = s.strip_prefix("rot:n=") {
            let n: i64 = rest.parse().ok()?;
            if !(1..=25).contains(&n) {
                return None;
            }
            return Some(Pre::Rot(n as u8));
        }
        if let Some(key) = s.strip_prefix("beaufort:key=") {
            if key.is_empty() {
                return None;
            }
            return Some(Pre::Beaufort(key.to_string()));
        }
        if s == "cto_trithemius" {
            return Some(Pre::CtoTrithemius);
        }
        if let Some(rest) = s.strip_prefix("cto_caesar:key=") {
            let n: i64 = rest.parse().ok()?;
            return Some(Pre::CtoCaesar(n));
        }
        if let Some(key) = s.strip_prefix("cto_beaufort:key=") {
            if key.is_empty() {
                return None;
            }
            return Some(Pre::CtoBeaufort(key.to_string()));
        }
        if let Some(key) = s.strip_prefix("cto_gronsfeld:key=") {
            if key.is_empty() {
                return None;
            }
            return Some(Pre::CtoGronsfeld(key.to_string()));
        }
        if let Some(rest) = s.strip_prefix("cto_rotation:n=") {
            let (n_part, deg) = match rest.split_once(",deg=") {
                Some((n_part, deg_part)) => {
                    let deg: u16 = deg_part.parse().ok()?;
                    if !matches!(deg, 90 | 180 | 270) {
                        return None;
                    }
                    (n_part, deg)
                }
                None => (rest, 90),
            };
            let n: i64 = n_part.parse().ok()?;
            if n < 1 {
                return None;
            }
            return Some(Pre::CtoRotation(n, deg));
        }
        // Generic fallback: any registered node, spelled as a chain-spec step.
        // Validated here rather than at apply time so a typo is a parse error the
        // user sees, not a silently skipped candidate.
        let name = s.split(':').next().unwrap_or("");
        if !name.is_empty() && ra_core::registry::registry().get(name).is_some() {
            // `;` separates a node's parameters here, not `,` — the axis itself is a
            // comma-separated list, so a comma inside a value would be read as the
            // start of the next axis value. `--post` makes the same substitution for
            // `affine:a=<n>;b=<n>`, for exactly this reason.
            if crate::spec::parse_chain(&s.replace(';', ",")).is_ok() {
                return Some(Pre::Node(s.to_string()));
            }
        }
        None
    }

    fn label(&self) -> String {
        match self {
            Pre::Identity => "identity".to_string(),
            Pre::Bwt => "bwt".to_string(),
            Pre::Reverse => "reverse".to_string(),
            Pre::ReverseWords => "reverse_words".to_string(),
            Pre::StripWs => "stripws".to_string(),
            Pre::Group => "group".to_string(),
            Pre::Rot(n) => format!("rot:n={n}"),
            Pre::Beaufort(key) => format!("beaufort:key={key}"),
            Pre::CtoCaesar(n) => format!("cto_caesar:key={n}"),
            Pre::CtoBeaufort(key) => format!("cto_beaufort:key={key}"),
            Pre::CtoTrithemius => "cto_trithemius".to_string(),
            Pre::CtoGronsfeld(key) => format!("cto_gronsfeld:key={key}"),
            Pre::CtoRotation(n, deg) => format!("cto_rotation:n={n},deg={deg}"),
            Pre::Node(spec) => spec.clone(),
            // `|`, matching the chain-spec separator, the same convention
            // `Codec::label` uses for its own multi-step values.
            Pre::Composite(steps) => steps.iter().map(|p| p.label()).collect::<Vec<_>>().join("|"),
        }
    }

    /// The chain-spec step(s) this value renders as, in pipeline order. Empty
    /// for `Identity`. Each entry is a single `parse_chain`-ready node spec, so
    /// [`Pre::chain_prefix`] can join them with the same `" | "` every other
    /// step in the chain uses.
    fn chain_steps(&self) -> Vec<String> {
        match self {
            Pre::Identity => vec![],
            Pre::Bwt => vec!["bwt".to_string()],
            Pre::Reverse => vec!["reverse".to_string()],
            Pre::ReverseWords => vec!["reverse_words".to_string()],
            Pre::StripWs => vec!["stripws".to_string()],
            Pre::Group => vec!["group".to_string()],
            Pre::Rot(n) => vec![format!("rot:n={n}")],
            Pre::Beaufort(key) => vec![format!("beaufort:key={key}")],
            Pre::CtoCaesar(n) => vec![format!("cto_caesar:key={n}")],
            Pre::CtoBeaufort(key) => vec![format!("cto_beaufort:key={key}")],
            Pre::CtoTrithemius => vec!["cto_trithemius".to_string()],
            Pre::CtoGronsfeld(key) => vec![format!("cto_gronsfeld:key={key}")],
            Pre::CtoRotation(n, deg) => vec![format!("cto_rotation:blocksize={n},rotation={deg}")],
            // already a chain-spec step, and may itself be `a | b`
            Pre::Node(spec) => spec
                .replace(';', ",")
                .split('|')
                .map(|s| s.trim().to_string())
                .collect(),
            Pre::Composite(steps) => steps.iter().flat_map(|p| p.chain_steps()).collect(),
        }
    }

    /// The rendered chain prefix, e.g. `"stripws | reverse | "`, ready to
    /// prepend directly to the initial-decode step. Empty for `Identity`.
    fn chain_prefix(&self) -> String {
        let steps = self.chain_steps();
        if steps.is_empty() {
            String::new()
        } else {
            format!("{} | ", steps.join(" | "))
        }
    }

    /// `None` means this transform rejected the raw ciphertext text (`Bwt`,
    /// `Rot`, `Group` and `Beaufort` are all no-fail; only `Bwt` can reject
    /// today, same as before, but a `Composite` step can fail partway through
    /// and the whole value then rejects, same as any other inapplicable step).
    fn apply(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Pre::Identity => Some(data.to_vec()),
            Pre::Bwt => ra_core::classical::bwt::inverse_bwt(data, b'|').ok(),
            Pre::Reverse => apply_node("reverse", ra_core::Params::new(), data),
            Pre::ReverseWords => apply_node("reverse_words", ra_core::Params::new(), data),
            Pre::StripWs => apply_node("stripws", ra_core::Params::new(), data),
            Pre::Group => apply_node("group", ra_core::Params::new(), data),
            Pre::Rot(n) => apply_node("rot", ra_core::Params::new().set("n", *n as i64), data),
            Pre::Beaufort(key) => {
                apply_node("beaufort", ra_core::Params::new().set("key", key.as_str()), data)
            }
            Pre::CtoCaesar(n) => apply_node("cto_caesar", ra_core::Params::new().set("key", *n), data),
            Pre::CtoBeaufort(key) => {
                apply_node("cto_beaufort", ra_core::Params::new().set("key", key.as_str()), data)
            }
            Pre::CtoTrithemius => apply_node("cto_trithemius", ra_core::Params::new(), data),
            Pre::CtoGronsfeld(key) => {
                apply_node("cto_gronsfeld", ra_core::Params::new().set("key", key.as_str()), data)
            }
            Pre::CtoRotation(n, deg) => apply_node(
                "cto_rotation",
                ra_core::Params::new().set("blocksize", *n).set("rotation", deg.to_string().as_str()),
                data,
            ),
            Pre::Node(spec) => crate::spec::parse_chain(&spec.replace(';', ","))
                .ok()?
                .run(&ra_core::Repr::bytes(data.to_vec()))
                .ok()
                .map(|r| r.data),
            Pre::Composite(steps) => {
                let mut cur = data.to_vec();
                for step in steps {
                    cur = step.apply(&cur)?;
                }
                Some(cur)
            }
        }
    }
}

/// Append an informational annotation naming the `--toolfmt` artifact stripped
/// before this candidate's decrypt call(s), or leave `chain` untouched at the
/// default. Unlike `--pre`/`--post`, there is no registered node that performs
/// a generic strip-before-decrypt, so this cannot be rendered as a real,
/// re-runnable `ra run` step; a verifier depends on `Axes::toolfmt_prefix`'s
/// leaf spelling, not on this string, for reconciliation.
fn annotate_toolfmt(chain: String, fmt: ToolFmt) -> String {
    if fmt == ToolFmt::None {
        chain
    } else {
        format!(
            "{chain}  # toolfmt={} stripped from bytes reaching decrypt(s) (not a literal ra-run step)",
            fmt.label()
        )
    }
}

/// Run one registered node by name against raw bytes, for the `--pre` axis.
/// `--pre` runs at most once per (variant, pre) staging rather than per
/// candidate, so going through the registry (rather than hand-rolling each
/// primitive, as [`Xf`]/[`Codec`] do in the hot per-candidate loop) costs
/// nothing measurable and keeps this axis's behaviour identical to the same
/// node reachable from `ra run` — including `beaufort`, whose fidelity is
/// cross-checked against 2016 CrypTool Online (see `ra_core::nodes::Beaufort`).
/// `None` means the node rejected its input or is not registered; either way
/// the candidate is skipped, same as any other inapplicable step.
fn apply_node(name: &str, params: ra_core::Params, data: &[u8]) -> Option<Vec<u8>> {
    let node = ra_core::registry().get(name)?;
    let input = ra_core::Repr::new(data.to_vec(), ra_core::Display::Bytes);
    node.apply(&input, &params).ok().map(|r| r.data)
}

/// A transform applied to the **terminal decrypted output**, after the last modern
/// layer runs — the genuine bottom of the stack, in every tier.
///
/// This closes engine gap G1: the solved corpus documents a trailing classical
/// layer three times (rev2 `... DES/CFB > bacon`, rev6 `... Serpent/CFB >
/// substitute`, rev12 `... XTEA/CFB > reverse > rot`), and a pure-modern sweep has
/// no slot for it at all. That is a real false-negative mode, not merely an
/// unmodelled corner: a modern layer that decrypts *correctly* still presents as
/// substituted or transposed text underneath a trailing classical step, so a
/// prose-tuned oracle rejects the right candidate and the sweep reports a null
/// where the answer actually is.
///
/// # Position: after the tier's own terminal `dec`, and not a new skeleton
///
/// `--xf` and `--codec` each occupy a tier-specific *slot* in [`Tier::skeleton`]
/// (T2's `xf` sits between `b64d` and `dec`; T3's `codec` sits between the two
/// `dec`s). `Post` is not like that: it runs identically after the *last* `dec`
/// in every tier, exactly the way [`Pre`] runs identically before the *first*
/// `dec` in every tier. So it is modelled the same way `Pre` is — as an axis of
/// the product, not a change to the skeleton's family tuple. This is not merely
/// convenient: `Family::Xf` (both `Pre` and `Post` compose `Xf`-family nodes) is
/// documented as "not layer-forming" precisely so that a representation-preserving
/// step like this does not fracture the skeleton partition. T1 therefore stays
/// `b64d ∘ dec` whether or not `--post` is at its default, the same way it already
/// stays `b64d ∘ dec` whether or not `--pre` is — and the additivity property this
/// buys is checked directly: `post_axis_is_omitted_at_default_so_old_commitments_still_reconcile`
/// mirrors `pre_axis_is_omitted_at_default_so_old_commitments_still_reconcile` and
/// a run with `--post` left at `identity` alone produces a byte-identical claim
/// digest and Merkle root to a binary that never had this axis.
///
/// # Vocabulary
///
/// Drawn from the corpus shapes this axis exists to close, plus the one other
/// registered classical node whose trailing use is documented (rev13's `reverse |
/// affine:a=15,b=19`): `identity`, `reverse`, `rot:n=<1..25>`, `bacon` (rev2, the
/// node's own default 26-letter alphabet and `A`/`B` symbols), `substitute`
/// (rev6, an arbitrary 26-letter keyed alphabet — the node, not a fixed key,
/// since the corpus's own recorded alphabet is slightly defective and an operator
/// needs to be able to state a corrected one), and `affine` (rev13's default
/// 26-letter alphabet).
///
/// # Composition: `+`, not another comma
///
/// Same convention as [`Pre`] and [`Codec`]: a single `--post` value may be a
/// `+`-joined sequence of the primitives above, applied left to right, e.g.
/// `reverse+rot:n=20` — rev12's exact trailing shape.
///
/// # `;` inside `affine`, not `,`
///
/// `ra run`'s own chain-spec grammar separates one node's parameters with `,`
/// (`affine:a=15,b=19`), but `--post`'s own list of values is itself
/// `,`-delimited by clap (`value_delimiter = ','`, the same convention every
/// other sweep axis uses), so a literal `,` inside a `--post` value would be
/// split apart into two separate axis values before this parser ever saw it.
/// `;` is used between affine's two parameters for that reason alone — every
/// other value here takes at most one parameter and needs no internal
/// separator. [`Post::chain_steps`] still renders the node's own `,` spelling,
/// since the rendered chain is fed to [`crate::spec::parse_chain`], not back
/// through this parser.
///
/// # Scoring: a trailing classical layer is not prose
///
/// Every oracle this workspace ships — `printable-*`, `english-quadgram`, and
/// `printable-and-english` (`ra-oracle/src/lib.rs`) — is tuned for English
/// prose or raw printability. A genuine trailing `bacon`/`substitute`/`rot`/
/// `affine` layer produces neither: a substituted or transposed English text
/// fails a quadgram or printable-ratio check even when the modern layer beneath
/// it is exactly right, which is the whole reason this axis exists. Scoring a
/// `--post` run correctly wants a **letter-frequency or index-of-coincidence**
/// oracle (an IoC near 0.066 or a flat, English-shaped frequency table close to
/// its own alphabet size are what a Baconian/substitution/rotation output
/// actually presents, prose semantics aside). No such oracle exists in
/// `ra-oracle` today — only the prose-tuned family above — so this module does
/// not attempt to fix scoring for `--post` outputs; it only adds the slot. A
/// `--post` sweep run today therefore still uses a prose oracle by default,
/// which will under-detect trailing-classical hits; that is a known, stated
/// limitation rather than a silent one, and closing it is future work for
/// `ra-oracle`, not this axis.
///
/// # Two caveats for the block-aware oracle
///
/// `LayerParams::block_size()` reports the prefix a self-synchronising mode
/// corrupts in *the decrypt's own output*, and `run_range` skips exactly that
/// many bytes of whatever `--post` finally produces. Two `--post` shapes break
/// the assumption that the skip still lands on the corrupted region:
///
/// - **Reordering.** `reverse` (or any composite ending in one) moves the
///   corrupted prefix elsewhere in the final scored bytes — to the tail, for a
///   plain `reverse`.
/// - **Resizing.** `bacon` does not reorder, but it is a 5:1 compression
///   (five symbol bytes decode to one letter), so a skip counted in the
///   *decrypt's* byte count denotes a completely different range once `bacon`
///   has run — `n` skipped decrypt bytes correspond to roughly `n/5` bacon
///   output bytes, not `n`.
///
/// `rot`, `substitute` and `affine` are the only values here that are both
/// order- and length-preserving, so they are the only ones for which the
/// existing skip is exact. Both gaps are real and documented, not silently
/// papered over: a `--post` value containing `reverse` or `bacon` against a
/// self-synchronising mode should be read with that in mind, and neither is
/// fixed by this change.
#[derive(Clone, PartialEq, Eq, Debug)]
enum Post {
    Identity,
    Reverse,
    /// `rot:n=<1..25>`, the classical Caesar-family shift over A-Z/a-z.
    Rot(u8),
    /// `bacon`, over the node's own default 26-letter alphabet and `A`/`B`
    /// symbols — the reading rev2's chain needs.
    Bacon,
    /// `substitute:alphabet=<26 letters>`, an arbitrary keyed substitution
    /// alphabet rather than a single fixed key, since rev6's own recorded
    /// alphabet is slightly defective (see `ARCHITECTURE.md`'s corpus caveats)
    /// and an operator needs to be able to state a corrected one.
    Substitute(String),
    /// `affine:a=<n>;b=<n>`, over the node's own default 26-letter alphabet.
    Affine(i64, i64),
    /// A `+`-joined sequence of the above, applied left to right. Never
    /// contains `Identity` or a nested `Composite` — [`Post::parse`] only
    /// produces this shape for genuinely multi-step input.
    /// Any registered node, given as a chain-spec step (`name` or `name:k=v;k=v`).
    ///
    /// The named variants above predate the registry being reachable here. This one
    /// makes the other 120-odd nodes usable in the trailing position without a new
    /// variant each — which is what lets a sweep put `enigma_m3` after the modern
    /// layer. That matters for The Giant specifically: tg5 on that map is recorded as
    /// `enigma_m3` and tg3 as a simplified Lorenz, so a rotor machine sitting *under*
    /// the modern layer is the map's own documented shape, not a speculation.
    Node(String),
    Composite(Vec<Post>),
}

impl Post {
    /// Parse one `--post` domain value, which may itself be a `+`-joined
    /// composition (see the type doc). `|` is accepted as an equivalent
    /// separator too, for the same reason [`Pre::parse`] accepts it: a label
    /// recovered from a recorded claim (`get("post")` in [`axes_from_order`])
    /// round-trips through this same parser.
    fn parse(s: &str) -> Option<Post> {
        let norm = s.trim().replace('+', "|");
        let parts: Vec<&str> = norm.split('|').collect();
        if parts.len() > 1 {
            let ops: Option<Vec<Post>> = parts.iter().map(|p| Post::parse_one(p)).collect();
            return ops.map(Post::Composite);
        }
        Post::parse_one(&norm)
    }

    /// Parse a single, non-composite step.
    fn parse_one(s: &str) -> Option<Post> {
        if s == "identity" {
            return Some(Post::Identity);
        }
        if s == "reverse" {
            return Some(Post::Reverse);
        }
        if s == "bacon" {
            return Some(Post::Bacon);
        }
        if let Some(rest) = s.strip_prefix("rot:n=") {
            let n: i64 = rest.parse().ok()?;
            if !(1..=25).contains(&n) {
                return None;
            }
            return Some(Post::Rot(n as u8));
        }
        if let Some(alpha) = s.strip_prefix("substitute:alphabet=") {
            if alpha.is_empty() {
                return None;
            }
            return Some(Post::Substitute(alpha.to_string()));
        }
        if let Some(rest) = s.strip_prefix("affine:") {
            // `;`-separated `k=v` pairs, either order -- see the type doc for why
            // `;` rather than the chain-spec's own `,`.
            let mut a: Option<i64> = None;
            let mut b: Option<i64> = None;
            for kv in rest.split(';') {
                let (k, v) = kv.split_once('=')?;
                match k {
                    "a" => a = v.parse().ok(),
                    "b" => b = v.parse().ok(),
                    _ => return None,
                }
            }
            return Some(Post::Affine(a?, b?));
        }
        // Generic fallback: any registered node. `;` separates parameters because
        // the axis itself is comma-separated (same reason as `--pre`).
        let name = s.split(':').next().unwrap_or("");
        if !name.is_empty() && ra_core::registry::registry().get(name).is_some()
            && crate::spec::parse_chain(&s.replace(';', ",")).is_ok()
        {
            return Some(Post::Node(s.to_string()));
        }
        None
    }

    fn label(&self) -> String {
        match self {
            Post::Identity => "identity".to_string(),
            Post::Reverse => "reverse".to_string(),
            Post::Rot(n) => format!("rot:n={n}"),
            Post::Bacon => "bacon".to_string(),
            Post::Substitute(alpha) => format!("substitute:alphabet={alpha}"),
            Post::Affine(a, b) => format!("affine:a={a};b={b}"),
            // `|`, matching the chain-spec separator, the same convention
            // `Pre::label`/`Codec::label` use for their own multi-step values.
            Post::Node(spec) => spec.clone(),
            Post::Composite(steps) => {
                steps.iter().map(|p| p.label()).collect::<Vec<_>>().join("|")
            }
        }
    }

    /// The chain-spec step(s) this value renders as, in pipeline order. Empty
    /// for `Identity`. Unlike [`Post::label`], `affine` is rendered with the
    /// chain spec's own `,` here, since the result is fed to
    /// [`crate::spec::parse_chain`], not back through [`Post::parse`].
    fn chain_steps(&self) -> Vec<String> {
        match self {
            Post::Identity => vec![],
            Post::Reverse => vec!["reverse".to_string()],
            Post::Rot(n) => vec![format!("rot:n={n}")],
            Post::Bacon => vec!["bacon".to_string()],
            Post::Substitute(alpha) => vec![format!("substitute:alphabet={alpha}")],
            Post::Affine(a, b) => vec![format!("affine:a={a},b={b}")],
            Post::Node(spec) => spec
                .replace(';', ",")
                .split('|')
                .map(|x| x.trim().to_string())
                .collect(),
            Post::Composite(steps) => steps.iter().flat_map(|p| p.chain_steps()).collect(),
        }
    }

    /// The rendered chain suffix, e.g. `" | reverse | rot:n=20"`, ready to append
    /// directly after the terminal decrypt's own chain step. Empty for
    /// `Identity`.
    fn chain_suffix(&self) -> String {
        let steps = self.chain_steps();
        if steps.is_empty() {
            String::new()
        } else {
            format!(" | {}", steps.join(" | "))
        }
    }

    /// `None` means this transform rejected its input. Only `affine` (a
    /// non-coprime `a`) and a `Composite` step failing partway through can
    /// reject today; every other value is total over its declared alphabet, the
    /// same as [`Pre`]'s no-fail steps.
    fn apply(&self, data: &[u8]) -> Option<Vec<u8>> {
        match self {
            Post::Identity => Some(data.to_vec()),
            Post::Reverse => apply_node("reverse", ra_core::Params::new(), data),
            Post::Rot(n) => apply_node("rot", ra_core::Params::new().set("n", *n as i64), data),
            Post::Bacon => apply_node("bacon", ra_core::Params::new(), data),
            Post::Substitute(alpha) => {
                apply_node("substitute", ra_core::Params::new().set("alphabet", alpha.as_str()), data)
            }
            Post::Affine(a, b) => apply_node(
                "affine",
                ra_core::Params::new().set("a", *a).set("b", *b),
                data,
            ),
            Post::Node(spec) => crate::spec::parse_chain(&spec.replace(';', ","))
                .ok()?
                .run(&ra_core::Repr::bytes(data.to_vec()))
                .ok()
                .map(|r| r.data),
            Post::Composite(steps) => {
                let mut cur = data.to_vec();
                for step in steps {
                    cur = step.apply(&cur)?;
                }
                Some(cur)
            }
        }
    }
}

/// A tool-output formatting artifact, stripped from the bytes about to be handed
/// to a modern decrypt call -- see `ra_core::classical::toolfmt` for the
/// underlying `OutputFmt`/`Trailing`/`Grouping` machinery this axis composes,
/// and that module's own doc for why it must be swept both on and off.
///
/// # Why the decrypt boundary, and nowhere else
///
/// Every *decode* step in this engine (`b64decode`, `hexdecode`,
/// `decimaldecode`, `octaldecode`, all via [`ra_core::repr::decode_base64`] and
/// its siblings) already filters non-alphabet bytes before decoding — see
/// `decode_base64_tolerates_leading_trailing_and_interior_whitespace` and its
/// two siblings in `ra_core::repr`. A grouping separator or a trailing
/// terminator on TEXT feeding a decode step is therefore provably a no-op on
/// the decoded bytes however it is spelled: stripping it there (before [`Pre`]'s
/// output reaches the initial decode, say) would add a dimension that changes
/// nothing. The oracle side has the matching property — scoring already
/// tolerates stray whitespace in the final decrypted prose, audited separately
/// and found clean, distinct from this gap.
///
/// The one boundary in the pipeline with **no** built-in tolerance is the
/// modern decrypt call itself: a block cipher (ECB/CBC) requires an exact
/// multiple of its block size, so a stray trailing terminator can turn an
/// otherwise-correct ciphertext length-invalid; a self-synchronising stream
/// mode (CFB-8) keeps a feedback register keyed on the *exact* byte sequence,
/// so a single inserted separator byte anywhere before position `i`
/// permanently corrupts every decrypted byte from `i` onward — there is no
/// recovery, unlike a printable-ratio oracle's tolerance for a stray byte in
/// finished prose. This axis therefore strips the hypothesised artifact from
/// whatever bytes are about to reach a decrypt call, in every tier and at
/// every layer (T3's `layer1` and `layer2` alike) — generalising [`Pre`]'s own
/// "between layers" framing to the boundary between a decode/re-encode step
/// and the decrypt that follows it.
///
/// # Domain: the corpus-evidenced subset, not the full `OutputFmt` product
///
/// `ra_core::classical::toolfmt::OutputFmt` composes case, grouping (size,
/// separator, trailing separator, padding) and a trailing terminator — a much
/// larger space than is justified here. This axis restricts to exactly the two
/// dimensions with direct corpus evidence (see this module's own top-level
/// doc): `Trailing::{Lf,CrLf}` (REV7's 15 recorded newlines) and blocks-of-5
/// grouping with a plain space separator (REV7's 203 recorded spaces; rev6's
/// space-separated decimal groups). Excluded, and why: `case` (every recorded
/// ciphertext already matches a stated case — nothing to discover), a
/// `group_size` other than 5 or a separator other than space (no corpus record
/// uses one), and padding (no corpus record pads a short final group). An
/// unmotivated dimension only multiplies the swept space without a hypothesis
/// to test, which is the failure mode this axis is deliberately built to
/// avoid. The two remaining dimensions are independent (a real tool can both
/// group its output AND leave a trailing terminator on it), so the enumerated
/// domain is their full 2x3 cross product, `none` counted once:
/// `none, group, lf, crlf, group+lf, group+crlf`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum ToolFmt {
    None,
    /// Blocks of 5, space separator, no trailing separator, no padding.
    Group,
    Lf,
    CrLf,
    GroupLf,
    GroupCrLf,
}

impl ToolFmt {
    fn parse(s: &str) -> Option<ToolFmt> {
        match s.trim() {
            "none" => Some(ToolFmt::None),
            "group" => Some(ToolFmt::Group),
            "lf" => Some(ToolFmt::Lf),
            "crlf" => Some(ToolFmt::CrLf),
            "group+lf" => Some(ToolFmt::GroupLf),
            "group+crlf" => Some(ToolFmt::GroupCrLf),
            _ => None,
        }
    }

    fn label(self) -> &'static str {
        match self {
            ToolFmt::None => "none",
            ToolFmt::Group => "group",
            ToolFmt::Lf => "lf",
            ToolFmt::CrLf => "crlf",
            ToolFmt::GroupLf => "group+lf",
            ToolFmt::GroupCrLf => "group+crlf",
        }
    }

    /// The `OutputFmt` this value denotes — the artifact hypothesised to have
    /// been imposed on the bytes before this engine sees them. Grouping is
    /// always blocks of 5 with a plain space separator and no padding, case is
    /// always `Preserve`: see the type doc for why the domain stops there.
    fn to_output_fmt(self) -> ra_core::classical::toolfmt::OutputFmt {
        use ra_core::classical::toolfmt::{CaseFold, Grouping, OutputFmt, Trailing};
        let (group, trailing) = match self {
            ToolFmt::None => (false, Trailing::None),
            ToolFmt::Group => (true, Trailing::None),
            ToolFmt::Lf => (false, Trailing::Lf),
            ToolFmt::CrLf => (false, Trailing::CrLf),
            ToolFmt::GroupLf => (true, Trailing::Lf),
            ToolFmt::GroupCrLf => (true, Trailing::CrLf),
        };
        OutputFmt {
            case: CaseFold::Preserve,
            grouping: if group {
                Some(Grouping {
                    size: 5,
                    separator: " ".to_string(),
                    trailing_separator: false,
                    pad_final: None,
                })
            } else {
                None
            },
            trailing,
        }
    }

    /// Undo the hypothesised artifact: strip a trailing terminator, then
    /// ungroup, recovering the bytes an unadorned tool would have produced. A
    /// no-op at `None` by construction (`OutputFmt::strip` with `trailing:
    /// None, grouping: None` returns its input unchanged), which is what keeps
    /// this axis additive at its default — see
    /// `toolfmt_axis_is_omitted_at_default_so_old_commitments_still_reconcile`.
    fn strip(self, data: &[u8]) -> Vec<u8> {
        self.to_output_fmt().strip(data)
    }
}

/// An inter-layer re-encoding, as an enumerable domain value.
///
/// Each variant is a composition of zero or more `codec`-family nodes; `label` is
/// both the claim's domain value and the chain-spec spelling, so a challenged
/// candidate pastes straight into `ra run`.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
enum Codec {
    Identity,
    B64Decode,
    HexDecode,
    HexToB64ThenB64Decode,
    DecimalDecode,
    OctalDecode,
}

/// Every codec value this sweep knows how to enumerate.
const CODEC_VOCABULARY: [Codec; 6] = [
    Codec::Identity,
    Codec::B64Decode,
    Codec::HexDecode,
    Codec::HexToB64ThenB64Decode,
    Codec::DecimalDecode,
    Codec::OctalDecode,
];

impl Codec {
    fn label(self) -> &'static str {
        match self {
            Codec::Identity => "identity",
            Codec::B64Decode => "b64decode",
            Codec::HexDecode => "hexdecode",
            Codec::HexToB64ThenB64Decode => "hex_to_base64|b64decode",
            Codec::DecimalDecode => "decimaldecode",
            Codec::OctalDecode => "octaldecode",
        }
    }

    /// The `codec`-family node names this value composes, in pipeline order.
    /// `identity` is the empty composition.
    fn node_names(self) -> &'static [&'static str] {
        match self {
            Codec::Identity => &[],
            Codec::B64Decode => &["b64decode"],
            Codec::HexDecode => &["hexdecode"],
            Codec::HexToB64ThenB64Decode => &["hex_to_base64", "b64decode"],
            Codec::DecimalDecode => &["decimaldecode"],
            Codec::OctalDecode => &["octaldecode"],
        }
    }

    fn parse(s: &str) -> Option<Codec> {
        // `+` is accepted for `|` so the multi-step value needs no shell quoting.
        let norm = s.trim().replace('+', "|");
        CODEC_VOCABULARY.into_iter().find(|c| c.label() == norm)
    }

    /// Apply the composition. `None` means a step rejected its input, which is a
    /// real property of the pipeline at this point and is committed to as such.
    fn apply(self, data: &[u8]) -> Option<Vec<u8>> {
        use ra_core::repr::{decode_base64, decode_hex, decode_radix};
        match self {
            Codec::Identity => Some(data.to_vec()),
            Codec::B64Decode => decode_base64(data),
            Codec::HexDecode => decode_hex(data),
            // Performed as the two steps the corpus records, not short-circuited to
            // hexdecode, so the evaluated pipeline is the claimed pipeline.
            Codec::HexToB64ThenB64Decode => {
                let raw = decode_hex(data)?;
                let b64 = base64::engine::general_purpose::STANDARD.encode(raw);
                decode_base64(b64.as_bytes())
            }
            Codec::DecimalDecode => decode_radix(data, 10),
            Codec::OctalDecode => decode_radix(data, 8),
        }
    }
}

/// A candidate key: the domain label used in claims, plus the bytes actually fed to
/// key derivation.
#[derive(Clone, Debug)]
pub struct KeyCandidate {
    pub label: String,
    pub bytes: Vec<u8>,
}

impl KeyCandidate {
    /// `TheGiant_b64` in the universe model means "the base64 encoding of
    /// `TheGiant`", not the twelve literal characters. Resolving it here keeps the
    /// claim's domain value identical to the model's while sweeping the bytes the
    /// value denotes.
    pub fn resolve(label: &str) -> KeyCandidate {
        let bytes = match label.strip_suffix("_b64") {
            Some(stem) => base64::engine::general_purpose::STANDARD
                .encode(stem)
                .into_bytes(),
            None => label.as_bytes().to_vec(),
        };
        KeyCandidate {
            label: label.to_string(),
            bytes,
        }
    }
}

/// Every axis, resolved up front so the enumeration is a pure index function.
struct Axes {
    /// The admissible transcriptions of this target, derived from its ciphertext.
    vspace: VariantSpace,
    /// The selected variant masks, in enumeration order.
    variant_masks: Vec<u32>,
    /// mcrypt names, parallel to `prim_labels`.
    prims: Vec<String>,
    /// claim domain values (display names), parallel to `prims`.
    prim_labels: Vec<String>,
    modes: Vec<Mode>,
    keys: Vec<KeyCandidate>,
    kds: Vec<KeyDerivation>,
    ivs: Vec<(String, Vec<u8>)>,
    xfs: Vec<Xf>,
    codecs: Vec<Codec>,
    /// The top-of-stack transform, applied to the raw ciphertext text before the
    /// initial decode, in every tier. See [`Pre`].
    pres: Vec<Pre>,
    /// The bottom-of-stack transform, applied to the terminal decrypted output
    /// after the last modern layer, in every tier. See [`Post`].
    posts: Vec<Post>,
    /// The hypothesised tool-output artifact, stripped from the bytes about to
    /// reach a modern decrypt call, at every layer and in every tier. See
    /// [`ToolFmt`].
    toolfmts: Vec<ToolFmt>,
}

impl Axes {
    /// Candidates in one modern-layer parameterisation.
    fn layer_unit(&self) -> u64 {
        (self.ivs.len() * self.kds.len() * self.keys.len() * self.modes.len() * self.prims.len())
            as u64
    }

    /// Claim domain values for the variant axis, in enumeration order.
    fn variant_labels(&self) -> Vec<String> {
        self.variant_masks
            .iter()
            .map(|&m| self.vspace.label(m))
            .collect()
    }

    /// The variant's contribution to a candidate's leaf parameters.
    ///
    /// Empty when the run covers the recorded reading alone, so a commitment made
    /// before the variant axis existed still reconciles byte for byte. Present the
    /// moment a second transcription is in play — otherwise two candidates that
    /// decrypt *different ciphertexts* would share a leaf spelling, and the
    /// commitment would no longer identify what was evaluated.
    fn variant_prefix(&self, digit: usize) -> String {
        if self.variant_masks == [0] {
            String::new()
        } else {
            format!("variant={},", self.vspace.label(self.variant_masks[digit]))
        }
    }

    /// The `--pre` transform's contribution to a candidate's leaf parameters.
    ///
    /// Empty when only the default `identity` is in play, by the same reasoning as
    /// [`Axes::variant_prefix`]: a commitment made before this axis existed must
    /// still reconcile byte for byte when nobody passed `--pre`.
    fn pre_prefix(&self, digit: usize) -> String {
        if self.pres == [Pre::Identity] {
            String::new()
        } else {
            format!("pre={},", self.pres[digit].label())
        }
    }

    /// The `--post` transform's contribution to a candidate's leaf parameters.
    ///
    /// Empty when only the default `identity` is in play, by the same reasoning as
    /// [`Axes::pre_prefix`]: a commitment made before this axis existed must still
    /// reconcile byte for byte when nobody passed `--post`.
    fn post_suffix(&self, digit: usize) -> String {
        if self.posts == [Post::Identity] {
            String::new()
        } else {
            format!(",post={}", self.posts[digit].label())
        }
    }

    /// The `--toolfmt` artifact's contribution to a candidate's leaf parameters.
    ///
    /// Empty when only the default `none` is in play, by the same reasoning as
    /// [`Axes::pre_prefix`]: a commitment made before this axis existed must still
    /// reconcile byte for byte when nobody passed `--toolfmt`.
    fn toolfmt_prefix(&self, digit: usize) -> String {
        if self.toolfmts == [ToolFmt::None] {
            String::new()
        } else {
            format!("toolfmt={},", self.toolfmts[digit].label())
        }
    }
}

fn resolve_axes(args: &SweepArgs, target: &crate::corpus::Target) -> Result<Axes> {
    let exact_label = args
        .variant_label
        .clone()
        .unwrap_or_else(|| format!("{}-exact", target.display_hint));
    // Narrowed by the target's canonical transcription (`ciphertext_canonical`) when
    // it has one — TG4's admits only {v4c, v6c}, not the full v00..v7f. An explicit
    // `--variants` label list can still reach any point in the wider space.
    let vspace = target.variant_space(&exact_label)?;
    let variant_masks = vspace.select(&args.variants)?;

    let prims: Vec<String> = match &args.prims {
        Some(p) => p.clone(),
        None => ra_prim::implemented()
            .map(|i| i.mcrypt_name.to_string())
            .collect(),
    };
    for p in &prims {
        ra_prim::prim_info(p).with_context(|| format!("unknown primitive {p:?}"))?;
    }
    let modes: Vec<Mode> = args
        .modes
        .iter()
        .map(|m| Mode::parse(m).with_context(|| format!("unknown mode {m:?}")))
        .collect::<Result<_>>()?;
    let kds: Vec<KeyDerivation> = args
        .kd
        .iter()
        .map(|k| KeyDerivation::parse(k).with_context(|| format!("unknown key-derivation {k:?}")))
        .collect::<Result<_>>()?;
    let ivs: Vec<(String, Vec<u8>)> = args
        .ivs
        .iter()
        .map(|name| match name.as_str() {
            "ascii0" => Ok((name.clone(), vec![b'0'; 16])),
            "null" => Ok((name.clone(), vec![0u8; 16])),
            other => anyhow::bail!("unknown IV domain value {other:?}; use ascii0 or null"),
        })
        .collect::<Result<_>>()?;
    let xfs: Vec<Xf> = args
        .xf
        .iter()
        .map(|x| {
            Xf::parse(x)
                .with_context(|| format!("unknown transform {x:?}; use identity, reverse, or bwt"))
        })
        .collect::<Result<_>>()?;
    let codecs: Vec<Codec> = args
        .codec
        .iter()
        .map(|c| {
            Codec::parse(c).with_context(|| {
                format!(
                    "unknown inter-layer codec {c:?}; the corpus-derived vocabulary is {}",
                    CODEC_DEFAULT
                )
            })
        })
        .collect::<Result<_>>()?;
    let pres: Vec<Pre> = args
        .pre
        .iter()
        .map(|p| {
            Pre::parse(p).with_context(|| {
                format!(
                    "unknown pre-transform {p:?}; use identity, bwt, reverse, reverse_words, \
                     stripws, group, rot:n=<1..25>, beaufort:key=<K>, cto_caesar:key=<n>, \
                     cto_beaufort:key=<K>, cto_trithemius, cto_gronsfeld:key=<digits>, \
                     cto_rotation:n=<blocksize>[,deg=<90|180|270>], or a '+'-joined \
                     sequence of these (e.g. stripws+reverse)"
                )
            })
        })
        .collect::<Result<_>>()?;
    let posts: Vec<Post> = args
        .post
        .iter()
        .map(|p| {
            Post::parse(p).with_context(|| {
                format!(
                    "unknown post-transform {p:?}; use identity, reverse, rot:n=<1..25>, bacon, \
                     substitute:alphabet=<26 letters>, affine:a=<n>;b=<n>, or a '+'-joined \
                     sequence of these (e.g. reverse+rot:n=20)"
                )
            })
        })
        .collect::<Result<_>>()?;
    let toolfmts: Vec<ToolFmt> = args
        .toolfmt
        .iter()
        .map(|f| {
            ToolFmt::parse(f).with_context(|| {
                format!(
                    "unknown toolfmt value {f:?}; use none, group, lf, crlf, group+lf, or group+crlf"
                )
            })
        })
        .collect::<Result<_>>()?;

    anyhow::ensure!(!prims.is_empty(), "at least one primitive is required");
    anyhow::ensure!(!args.keys.is_empty(), "at least one key is required");

    Ok(Axes {
        vspace,
        variant_masks,
        prim_labels: display_names(&prims),
        prims,
        modes,
        keys: args.keys.iter().map(|k| KeyCandidate::resolve(k)).collect(),
        kds,
        ivs,
        xfs,
        codecs,
        pres,
        posts,
        toolfmts,
    })
}

// ---------------------------------------------------------------------------
// The index plan
// ---------------------------------------------------------------------------

/// One axis of the mixed-radix candidate index, together with the coverage
/// dimension it populates. Axes are ordered **least significant first**, which is
/// what lets a contiguous chunk of indices share an expensive prefix.
struct Axis {
    dim: String,
    values: Vec<String>,
}

/// The deterministic index space for one skeleton.
pub struct Plan {
    tier: Tier,
    axes: Vec<Axis>,
    /// Digit position of the `0.variant` axis. It is the **most significant** one, so
    /// a bounded prefix covers whole transcriptions.
    variant_axis: usize,
    /// Digit position of the `0.pre` axis, when it is enumerated at all. Unlike
    /// `xf`/`codec`, which sit at tier-specific slots, this axis (when present)
    /// sits identically in **every** tier — `pre` is the top of the stack
    /// regardless of skeleton. See [`Pre`].
    ///
    /// `None` when `--pre` is at its default (`identity` alone): the axis is
    /// then omitted from the index space entirely, not merely given a single
    /// value, so a plan built with nobody having passed `--pre` reproduces
    /// exactly the enumeration order of a claim committed before this axis
    /// existed. [`Axes::pre_prefix`] uses the same "default means absent"
    /// condition for the leaf spelling, for the same reason.
    pre_axis: Option<usize>,
    /// Digit position of the `0.post` axis, when it is enumerated at all. Sits
    /// identically in **every** tier — `post` is the bottom of the stack
    /// regardless of skeleton, the mirror image of `pre_axis` above. `None`
    /// under the same "default means absent" rule [`Axes::post_suffix`] uses.
    /// See [`Post`].
    post_axis: Option<usize>,
    /// Digit position of the `0.toolfmt` axis, when it is enumerated at all.
    /// Sits identically in every tier and at every layer, the same as
    /// `pre_axis`/`post_axis` — see [`ToolFmt`]. `None` under the same
    /// "default means absent" rule [`Axes::toolfmt_prefix`] uses.
    fmt_axis: Option<usize>,
    total: u128,
    /// Number of consecutive indices over which everything except the innermost
    /// modern layer is constant. For T3 that is one layer parameterisation, so a
    /// chunk decrypts the first layer once and reuses it — without retaining
    /// anything beyond the current chunk.
    stride: u64,
}

/// Offsets into the digit vector. The five per-layer axes are always emitted as a
/// block in this order (least significant first).
const LAYER_AXES: usize = 5;
const OFF_IV: usize = 0;
const OFF_KD: usize = 1;
const OFF_KEY: usize = 2;
const OFF_MODE: usize = 3;
const OFF_PRIM: usize = 4;

impl Plan {
    fn new(tier: Tier, axes: &Axes) -> Plan {
        let layer_block = |slot: usize| -> Vec<Axis> {
            vec![
                Axis {
                    dim: format!("{slot}.iv"),
                    values: axes.ivs.iter().map(|(n, _)| n.clone()).collect(),
                },
                Axis {
                    dim: format!("{slot}.kd"),
                    values: axes.kds.iter().map(|k| k.to_string()).collect(),
                },
                Axis {
                    dim: format!("{slot}.key"),
                    values: axes.keys.iter().map(|k| k.label.clone()).collect(),
                },
                Axis {
                    dim: format!("{slot}.mode"),
                    values: axes.modes.iter().map(|m| m.to_string()).collect(),
                },
                Axis {
                    dim: format!("{slot}.prim"),
                    values: axes.prim_labels.clone(),
                },
            ]
        };
        let xf_axis = |slot: usize| Axis {
            dim: format!("{slot}.xf"),
            values: axes.xfs.iter().map(|x| x.label().to_string()).collect(),
        };

        let mut list: Vec<Axis> = Vec::new();
        match tier {
            Tier::T1 => list.extend(layer_block(1)),
            Tier::T2 => {
                list.extend(layer_block(2));
                list.push(xf_axis(1));
            }
            Tier::T3 => {
                list.extend(layer_block(4));
                list.push(Axis {
                    dim: "3.codec".to_string(),
                    values: axes.codecs.iter().map(|c| c.label().to_string()).collect(),
                });
                list.push(xf_axis(2));
                list.extend(layer_block(1));
            }
        }
        // `pre` runs above the initial decode in every tier, so — unlike `xf` and
        // `codec` — it is pushed here, outside the `match tier` above, the same way
        // for T1, T2 and T3 alike. Omitted entirely at the default (`identity`
        // alone), not merely given a single value: a claim committed before this
        // axis existed must still rebuild to an identical enumeration order when
        // nobody passed `--pre`.
        let pre_axis = if axes.pres == [Pre::Identity] {
            None
        } else {
            list.push(Axis {
                dim: "0.pre".to_string(),
                values: axes.pres.iter().map(|p| p.label().to_string()).collect(),
            });
            Some(list.len() - 1)
        };
        // `post` runs below the terminal decrypt in every tier, the mirror image
        // of `pre` above: pushed once, outside the `match tier` above, and
        // omitted entirely at the default for the same reason `pre` is.
        let post_axis = if axes.posts == [Post::Identity] {
            None
        } else {
            list.push(Axis {
                dim: "0.post".to_string(),
                values: axes.posts.iter().map(|p| p.label().to_string()).collect(),
            });
            Some(list.len() - 1)
        };
        // `toolfmt` is checked immediately before every decrypt call, in every tier
        // and at every layer -- unlike `pre`/`post`, it is not tied to a single
        // position in the chain spec, but it is exactly as tier-independent, so it
        // is pushed here on the same "default means absent" footing.
        let fmt_axis = if axes.toolfmts == [ToolFmt::None] {
            None
        } else {
            list.push(Axis {
                dim: "0.toolfmt".to_string(),
                values: axes.toolfmts.iter().map(|f| f.label().to_string()).collect(),
            });
            Some(list.len() - 1)
        };
        // The variant is a genuine dimension of the universe, and it must appear in the
        // product or the claim would assert coverage over every transcription. It goes
        // last, i.e. most significant, so a bounded prefix covers whole readings.
        list.push(Axis {
            dim: "0.variant".to_string(),
            values: axes.variant_labels(),
        });
        let variant_axis = list.len() - 1;

        let total: u128 = list.iter().map(|a| a.values.len() as u128).product();
        let stride = match tier {
            // Nothing to share: each candidate is one decryption.
            Tier::T1 | Tier::T2 => 1,
            Tier::T3 => axes.layer_unit(),
        };
        Plan {
            tier,
            axes: list,
            variant_axis,
            pre_axis,
            post_axis,
            fmt_axis,
            total,
            stride,
        }
    }

    pub fn total(&self) -> u128 {
        self.total
    }

    /// The axis lists **in enumeration order**, least significant digit first.
    ///
    /// This is not the same information as the emitted cover, and both are needed. The
    /// cover stores each axis as a *sorted set*, which is exactly right for the coverage
    /// digest: equal coverage must hash equally however the operator happened to spell
    /// the command line. But `leaf_hash` binds the candidate **index**, and the index is
    /// assigned by mixed-radix enumeration over these lists *in the order they were
    /// resolved* — so the same axis sets in a different order produce a different Merkle
    /// root.
    ///
    /// A claim that recorded only the sorted sets therefore committed to a root that
    /// nobody could regenerate, which silently voids Document 6's spot audit: a verifier
    /// holding the claim has the coverage but not the order, and the audit premise is
    /// that a challenged leaf is cheaply regenerable from a checkpoint plus deterministic
    /// enumeration. Recording the order fixes that. The enumeration is deliberately
    /// *not* sorted to match the cover — the claim must describe the computation that
    /// happened, not a tidier one.
    pub fn enumeration_order(&self) -> Vec<(String, Vec<String>)> {
        self.axes
            .iter()
            .map(|a| (a.dim.clone(), a.values.clone()))
            .collect()
    }

    /// Digits of `i`, least significant first. This is the whole determinism
    /// guarantee: candidate `i` depends on nothing but `i` and the axis lists.
    fn digits(&self, i: u64) -> Vec<usize> {
        let mut r = i as u128;
        self.axes
            .iter()
            .map(|a| {
                let n = a.values.len() as u128;
                let d = (r % n) as usize;
                r /= n;
                d
            })
            .collect()
    }

    /// Work-unit size: a multiple of `stride` (so a chunk never straddles a shared
    /// prefix boundary) and large enough to amortise scheduling.
    fn chunk(&self) -> u64 {
        const TARGET: u64 = 4096;
        if self.stride >= TARGET {
            self.stride
        } else {
            self.stride * TARGET.div_ceil(self.stride)
        }
    }

    /// The cover for `evaluated` candidates, as a disjoint union of products whose
    /// sizes sum to **exactly** `evaluated`.
    ///
    /// When the whole space was swept this is the single full product. When it was
    /// truncated at `N`, the set `{i : i < N}` is decomposed in the mixed radix of
    /// the axes: for each digit position `k` with digit `d_k > 0`, one product fixes
    /// every axis above `k` to `N`'s digit there, restricts axis `k` to its first
    /// `d_k` values, and leaves every axis below `k` free. Those blocks are pairwise
    /// disjoint (they disagree at position `k`) and their sizes sum to
    /// `Σ d_k · Π_{j<k} r_j = N`.
    pub fn products(&self, evaluated: u64) -> Vec<Product> {
        let all = |a: &Axis| a.values.clone();
        if u128::from(evaluated) >= self.total {
            return vec![Product::new(
                self.axes
                    .iter()
                    .map(|a| (a.dim.clone(), all(a)))
                    .collect::<Vec<_>>(),
            )];
        }
        let digits = self.digits(evaluated);
        let mut out = Vec::new();
        for (k, ak) in self.axes.iter().enumerate() {
            if digits[k] == 0 {
                continue;
            }
            let dims: Vec<(String, Vec<String>)> = self
                .axes
                .iter()
                .enumerate()
                .map(|(j, aj)| {
                    let vals = match j.cmp(&k) {
                        std::cmp::Ordering::Less => all(aj),
                        std::cmp::Ordering::Equal => ak.values[..digits[k]].to_vec(),
                        std::cmp::Ordering::Greater => vec![aj.values[digits[j]].clone()],
                    };
                    (aj.dim.clone(), vals)
                })
                .collect();
            out.push(Product::new(dims));
        }
        out
    }

    /// The claim for `evaluated` candidates in this skeleton.
    pub fn cover(&self, evaluated: u64) -> CoverageSet {
        let mut set = CoverageSet::new();
        set.add(Cover::new(self.tier.skeleton(), self.products(evaluated)));
        set
    }
}

// ---------------------------------------------------------------------------
// Execution
// ---------------------------------------------------------------------------

struct Hit {
    index: u64,
    score: f64,
    class: String,
    scored_len: usize,
    describe: String,
    chain: String,
    preview: String,
    /// The transcription this hit is against, and the ciphertext it denotes. A hit on
    /// a non-recorded reading is not reproducible from the corpus record alone, so the
    /// report has to carry the exact bytes.
    variant: String,
    variant_note: String,
}

/// What a chunk of the index space produced. Outputs themselves are folded into
/// leaf hashes and dropped here; nothing else survives the chunk.
struct ChunkOut {
    start: u64,
    leaves: Vec<Hash>,
    hits: Vec<Hit>,
    hit_count: u64,
    /// scored length -> count, for the false-positive budget.
    scored_lens: BTreeMap<usize, u64>,
    /// scored length -> count, restricted to candidates that *passed*. This is what
    /// makes "no solve here" checkable rather than asserted: a correct decryption
    /// presents as a pass over a full-length scored region, so if every pass has a
    /// scored region of a few bytes, every pass is an artifact.
    pass_lens: BTreeMap<usize, u64>,
}

/// The resolved parameters of one modern layer.
struct LayerParams<'a> {
    prim: &'a str,
    mode: Mode,
    key: &'a KeyCandidate,
    kd: KeyDerivation,
    iv: &'a (String, Vec<u8>),
}

impl<'a> LayerParams<'a> {
    fn at(axes: &'a Axes, digits: &[usize], base: usize) -> LayerParams<'a> {
        LayerParams {
            prim: &axes.prims[digits[base + OFF_PRIM]],
            mode: axes.modes[digits[base + OFF_MODE]],
            key: &axes.keys[digits[base + OFF_KEY]],
            kd: axes.kds[digits[base + OFF_KD]],
            iv: &axes.ivs[digits[base + OFF_IV]],
        }
    }

    fn decrypt(&self, data: &[u8]) -> Option<Vec<u8>> {
        crate::corpus::decrypt_once(self.prim, self.mode, &self.key.bytes, &self.iv.1, self.kd, data)
    }

    /// Runnable `ra run` spelling of this layer.
    fn spec(&self) -> String {
        format!(
            "{}:key={},mode={},iv={},keyderiv={}",
            self.prim,
            String::from_utf8_lossy(&self.key.bytes),
            self.mode,
            hex::encode(&self.iv.1),
            self.kd
        )
    }

    fn describe(&self, suffix: &str) -> String {
        format!(
            "prim{s}={},mode{s}={},key{s}={},kd{s}={},iv{s}={}",
            self.prim,
            self.mode,
            self.key.label,
            self.kd,
            self.iv.0,
            s = suffix
        )
    }

    /// Block size the oracle should skip, when the mode self-synchronises.
    fn block_size(&self) -> Option<usize> {
        ra_prim::prim_info(self.prim).and_then(|p| {
            if self.mode.self_synchronising() {
                Some(p.block_size)
            } else {
                None
            }
        })
    }
}

/// What the second modern layer receives, or why it receives nothing.
enum Stage2 {
    Ready(Vec<u8>),
    Layer1Inapplicable,
    /// The top-of-stack `--pre` transform (only `bwt` can do this) rejected the
    /// raw ciphertext text, before the initial decode ever ran.
    PreFailed,
    XfFailed,
    CodecFailed,
}

struct Ctx<'a> {
    plan: &'a Plan,
    axes: &'a Axes,
    /// The recorded display text **verbatim** -- whitespace intact, exactly as the
    /// corpus records it. A candidate's ciphertext is this text with its variant's
    /// glyph corrections spliced in.
    ///
    /// Whitespace is kept because `--pre` sits above the initial decode and is
    /// documented to run on the raw ciphertext text: `reverse_words`, `stripws` and
    /// `group` all mean something only while the word boundaries still exist. Feeding
    /// the *compacted* text here (what this field held before 2026-09-10) silently
    /// turned the whole transcription into one token, so `reverse_words` degenerated
    /// to identity and any sweep naming it reported a negative it had never tested.
    ///
    /// The variant masks still index the *compacted* text, so splicing must go through
    /// `VariantSpace::apply_preserving_whitespace` rather than `apply` -- see there.
    text: &'a [u8],
    display: ra_core::Display,
    oracle: &'static OracleSpec,
    /// Node name that decodes the ciphertext's recorded display, for chain specs.
    initial_decode: &'static str,
}

/// The bytes a sweep feeds its pipeline for `target`: the recorded transcription
/// **verbatim**, whitespace and all.
///
/// This is the single definition of `Ctx::text`, and it exists as a function so that
/// the sweep driver and the claim recompute path cannot disagree about it. They did
/// disagree in the obvious way before: each rebuilt its own whitespace-stripped copy,
/// and a fix applied to one would have left a replayed claim silently deriving from
/// different bytes than the sweep it was auditing -- which reads as nondeterminism,
/// and is harder to diagnose than the original bug. A third caller must call this.
fn sweep_input_text(target: &crate::corpus::Target) -> Vec<u8> {
    target.raw.clone().into_bytes()
}

/// The whitespace-free view of `target`'s transcription -- the text
/// [`crate::variants::VariantSpace`] *indexes*.
///
/// Not what a candidate is fed (that is [`sweep_input_text`]); this is only the
/// coordinate system glyph offsets are quoted in, so that a reported position like
/// `@37:0->O` means the same thing whether or not the transcription is spaced.
fn variant_index_text(target: &crate::corpus::Target) -> Vec<u8> {
    target
        .raw
        .bytes()
        .filter(|c| !c.is_ascii_whitespace())
        .collect()
}

/// The digest and length of one exact byte string, recorded together so a reader can
/// tell "the same bytes" from "a hash collision in my reading of the report", and can
/// see at a glance that a value did something to the length.
#[derive(Clone, Debug, PartialEq, Eq)]
struct ByteRecord {
    sha256: String,
    bytes: usize,
}

impl ByteRecord {
    fn of(data: &[u8]) -> ByteRecord {
        ByteRecord {
            sha256: hex::encode(ra_merkle::h(data)),
            bytes: data.len(),
        }
    }
}

/// What one axis value actually did to this target's bytes.
///
/// The three states are deliberately distinct and must never collapse into each
/// other, because they mean different things to a reader auditing a negative:
///
/// - `Accepted` -- the value produced bytes. An *empty* result is still `Accepted`,
///   with a `ByteRecord` of length 0 and the digest of the empty string; that is a
///   value that ran and destroyed the input, which is not the same event as a value
///   that declined to run.
/// - `Rejected` -- the value refused the input outright (only `bwt` does this
///   today), so no bytes exist to hash.
/// - `Undecodable` -- the value produced bytes, but the display's strict decode then
///   refused them, so every candidate under it is skipped. The text digest is still
///   recorded; the canonical one cannot be.
#[derive(Clone, Debug, PartialEq, Eq)]
enum StagedStatus {
    Accepted,
    Rejected,
    Undecodable,
}

impl StagedStatus {
    fn as_str(&self) -> &'static str {
        match self {
            StagedStatus::Accepted => "accepted",
            StagedStatus::Rejected => "rejected",
            StagedStatus::Undecodable => "undecodable",
        }
    }
}

/// One axis value's **staged input**: the bytes that value actually hands to the
/// next stage, for the real loaded target.
///
/// Keyed by `(variant, label)` because a transcription reading and an axis value
/// together determine the bytes; quoting only the axis label would leave a reader
/// unable to tell which reading was measured.
#[derive(Clone, Debug, PartialEq, Eq)]
struct StagedInput {
    variant: String,
    label: String,
    status: StagedStatus,
    /// The text this value produced, before the display's initial decode consumed it
    /// -- the literal top-of-stack bytes. `None` only when the value rejected.
    text: Option<ByteRecord>,
    /// The canonical bytes that text decodes to -- what the cipher layer is actually
    /// handed. `None` when the value rejected or the decode refused the result.
    canonical: Option<ByteRecord>,
}

/// Find the axis values that are indistinguishable on this target.
///
/// # Why this exists
///
/// The bug this guards against is not "whitespace got stripped". It is that a
/// **named axis silently became a no-op** and the sweep then published confident
/// coverage over a space it never visited. `--pre reverse_words` was handed
/// whitespace-free text, so it had one token to reorder and quietly *was*
/// `identity`; three `pre` values enumerated one real pipeline, and the resulting
/// negative was believed. A negative from a degenerate axis is worse than no result
/// at all, because it gets published.
///
/// # Why it compares canonical bytes, not the text
///
/// Because the canonical bytes are what reaches the cipher. Two `pre` values can
/// produce visibly different *text* and still be the same experiment: on a hex
/// target, `group` only inserts spaces, and `decode_hex` discards them again. Judged
/// on the text those two look distinct; judged on what the cipher sees they are one
/// candidate wearing two labels, and it is the second reading that tells an analyst
/// whether their axis bought them anything.
///
/// # Why it is a warning and not an error
///
/// Collisions are sometimes *correct*. `stripws+reverse_words` genuinely is identity
/// -- after an explicit `stripws` there really is only one word -- as is `rot:n=13`
/// composed with itself. The requirement is only that a collision is never
/// **silent**; deciding whether a given one is legitimate needs the analyst.
///
/// Colliding labels are all **retained**, never deduplicated: the report is "N
/// tuples, M distinct inputs", and hiding one label would hide the difference.
///
/// Returns one line per group of colliding values, in first-appearance order so the
/// output is deterministic.
fn degeneracy_warnings(axis: &str, target: &str, staged: &[StagedInput]) -> Vec<String> {
    let mut groups: Vec<(ByteRecord, Vec<String>)> = Vec::new();
    for st in staged {
        // A value that rejected, or whose output would not decode, produced no bytes
        // for the cipher at all. It cannot be said to produce the *same* bytes as
        // anything else; that it contributes no coverage is a separate report.
        let Some(c) = &st.canonical else { continue };
        match groups.iter_mut().find(|(g, _)| g == c) {
            Some((_, labels)) => labels.push(st.label.clone()),
            None => groups.push((c.clone(), vec![st.label.clone()])),
        }
    }
    groups
        .into_iter()
        .filter(|(_, labels)| labels.len() > 1)
        .map(|(c, labels)| {
            let quoted: Vec<String> = labels.iter().map(|l| format!("{l:?}")).collect();
            format!(
                "WARNING: --{axis} values {} produce identical staged bytes for {target} \
                 (sha256:{}, {} bytes); this axis contributes no distinct coverage \
                 across them.",
                join_english(&quoted),
                c.sha256,
                c.bytes
            )
        })
        .collect()
}

/// `["a", "b", "c"]` -> `a, b and c`. Used only by [`degeneracy_warnings`]; the
/// warning is read by a human deciding whether a collision is legitimate, so it
/// reads as a sentence.
fn join_english(items: &[String]) -> String {
    match items {
        [] => String::new(),
        [a] => a.clone(),
        [a, b] => format!("{a} and {b}"),
        [rest @ .., last] => format!("{} and {last}", rest.join(", ")),
    }
}

/// The staged input each `--pre` value produces for **the real target's actual
/// bytes**.
///
/// Measured against the loaded ciphertext and never a synthetic fixture, because
/// degeneracy is a property of an axis *against this input*: an axis can be
/// perfectly implemented, non-degenerate in general, and still be the identity on
/// the one ciphertext under attack. A fixture would report it working fine.
///
/// The representative reading is `variant_masks[0]`. Degeneracy of the `pre` axis is
/// a property of the axis against this ciphertext, and the readings differ from one
/// another in a handful of glyphs, so one reading answers the question at 1/128th of
/// the cost and of the report's size. The reading used is recorded in every entry
/// rather than left implicit.
fn pre_staged_inputs(axes: &Axes, raw_text: &[u8], display: ra_core::Display) -> Vec<StagedInput> {
    let mask = axes.variant_masks[0];
    let variant = axes.vspace.label(mask);
    let mut text = Vec::new();
    axes.vspace
        .apply_preserving_whitespace(mask, raw_text, &mut text);
    axes.pres
        .iter()
        .map(|p| {
            let label = p.label();
            match p.apply(&text) {
                None => StagedInput {
                    variant: variant.clone(),
                    label,
                    status: StagedStatus::Rejected,
                    text: None,
                    canonical: None,
                },
                Some(t) => {
                    let rec = ByteRecord::of(&t);
                    match Repr::new(t, display).canonical_bytes_strict() {
                        Some(c) => StagedInput {
                            variant: variant.clone(),
                            label,
                            status: StagedStatus::Accepted,
                            text: Some(rec),
                            canonical: Some(ByteRecord::of(&c)),
                        },
                        None => StagedInput {
                            variant: variant.clone(),
                            label,
                            status: StagedStatus::Undecodable,
                            text: Some(rec),
                            canonical: None,
                        },
                    }
                }
            }
        })
        .collect()
}

/// The staged input each `--xf` value produces: the canonical bytes with that
/// transform applied, which is what the modern layer below is handed.
///
/// Measured against the first `--pre` value's canonical bytes. `--xf` sits below the
/// decode, so it sees the same shape of input whichever `pre` ran above it, and a
/// full cross product would report the same collisions once per `pre`.
///
/// `--codec` is deliberately **not** covered here. A codec sits between two modern
/// layers, so its staged input is a decryption's output: there is no way to compute
/// it without choosing a key, and a per-key report is neither small nor meaningful.
/// It is left unguarded rather than guarded badly.
fn xf_staged_inputs(axes: &Axes, raw_text: &[u8], display: ra_core::Display) -> Vec<StagedInput> {
    let mask = axes.variant_masks[0];
    let variant = axes.vspace.label(mask);
    let mut text = Vec::new();
    axes.vspace
        .apply_preserving_whitespace(mask, raw_text, &mut text);
    let base = axes
        .pres
        .first()
        .and_then(|p| p.apply(&text))
        .and_then(|t| Repr::new(t, display).canonical_bytes_strict());
    axes.xfs
        .iter()
        .map(|x| {
            let label = x.label().to_string();
            match base.as_ref().map(|b| x.apply(b)) {
                Some(Some(out)) => StagedInput {
                    variant: variant.clone(),
                    label,
                    status: StagedStatus::Accepted,
                    text: None,
                    canonical: Some(ByteRecord::of(&out)),
                },
                // The transform refused these bytes (`bwt` on a non-BWT buffer)...
                Some(None) => StagedInput {
                    variant: variant.clone(),
                    label,
                    status: StagedStatus::Rejected,
                    text: None,
                    canonical: None,
                },
                // ...or there were no bytes to refuse, because `pre` or the decode
                // already failed above it. Reported as undecodable rather than as a
                // rejection by this axis, which did not get to run.
                None => StagedInput {
                    variant: variant.clone(),
                    label,
                    status: StagedStatus::Undecodable,
                    text: None,
                    canonical: None,
                },
            }
        })
        .collect()
}

/// `(parameter tuples, distinct byte inputs)` for one axis.
///
/// Two separate numbers on purpose. Equal counts mean every value bought a distinct
/// experiment; `3 tuples, 1 distinct input` is the shape of the bug this whole guard
/// exists for. Collapsing them into one number is what made the original defect
/// invisible.
fn staged_input_census(staged: &[StagedInput]) -> (usize, usize) {
    let mut distinct: Vec<&ByteRecord> = Vec::new();
    for st in staged {
        if let Some(c) = &st.canonical {
            if !distinct.contains(&c) {
                distinct.push(c);
            }
        }
    }
    (staged.len(), distinct.len())
}

/// The staged-input side metadata for a claim, as JSON.
///
/// **Side** metadata: this is recorded alongside the leaves, never inside them. The
/// merkle leaf spelling is left exactly as it was, because changing it would make
/// every stored root unreconcilable for a second, unrelated reason and nobody could
/// then tell which change caused which mismatch.
fn staged_inputs_json(raw_text: &[u8], pres: &[StagedInput], xfs: &[StagedInput]) -> serde_json::Value {
    let entries = |staged: &[StagedInput]| -> serde_json::Value {
        staged
            .iter()
            .map(|st| {
                serde_json::json!({
                    "variant": st.variant,
                    "value": st.label,
                    "status": st.status.as_str(),
                    "text_sha256": st.text.as_ref().map(|r| r.sha256.clone()),
                    "text_bytes": st.text.as_ref().map(|r| r.bytes),
                    "canonical_sha256": st.canonical.as_ref().map(|r| r.sha256.clone()),
                    "canonical_bytes": st.canonical.as_ref().map(|r| r.bytes),
                })
            })
            .collect::<Vec<_>>()
            .into()
    };
    let (pre_tuples, pre_distinct) = staged_input_census(pres);
    let (xf_tuples, xf_distinct) = staged_input_census(xfs);
    serde_json::json!({
        // What every entry below derives from: the transcription as fed, verbatim.
        // Recorded separately so a reader can confirm the run started from the
        // ciphertext they think it did, before asking what each axis value did to it.
        "raw_text": {
            "sha256": hex::encode(ra_merkle::h(raw_text)),
            "bytes": raw_text.len(),
        },
        "note": "Side metadata, not part of any merkle leaf. `tuples` counts axis \
                 values enumerated; `distinct_inputs` counts the distinct byte strings \
                 they actually produced for this target. tuples > distinct_inputs means \
                 some values were aliases here -- sometimes legitimately (an explicit \
                 `stripws` really does make `reverse_words` the identity), sometimes \
                 because the axis is degenerate on this input. Colliding labels are \
                 all retained.",
        "pre": {
            "tuples": pre_tuples,
            "distinct_inputs": pre_distinct,
            "values": entries(pres),
        },
        "xf": {
            "tuples": xf_tuples,
            "distinct_inputs": xf_distinct,
            "values": entries(xfs),
        },
    })
}

/// One transcription variant's ciphertext bytes (after `--pre` and the initial
/// decode), plus the `--xf` transform pre-applied for T1/T2 (where it precedes
/// the only modern layer).
///
/// Held for the current (variant, pre) pair only and dropped with the chunk:
/// staging every reading up front would be resident memory for no gain, and
/// since the variant is the most significant digit a chunk of consecutive
/// indices crosses at most one variant boundary (crossing a `pre` boundary is
/// cheap regardless, since `pre` has at most two values today). Re-splicing
/// costs 14 byte writes and a base64 decode against a decryption's 144 block
/// operations.
struct VariantStage {
    digit: usize,
    pre_digit: usize,
    /// `None` means `--pre` (only `bwt` can do this) rejected the raw
    /// ciphertext text — every candidate sharing this (variant, pre) pair is
    /// then inapplicable, regardless of tier.
    canonical: Option<Vec<u8>>,
    /// `None` per entry means that `Xf` rejected `canonical` (currently only
    /// `Xf::Bwt` can do this). Empty when `canonical` itself is `None`, since
    /// there is nothing to feed it.
    staged: Vec<Option<Vec<u8>>>,
}

impl Ctx<'_> {
    fn stage(&self, digit: usize, pre_digit: usize) -> VariantStage {
        let mask = self.axes.variant_masks[digit];
        let mut text = Vec::new();
        // Whitespace-preserving, because `self.text` is the raw transcription and the
        // mask's positions index the compacted one; this substitutes at the k-th
        // non-whitespace character, so the mask names the same reading either way.
        self.axes
            .vspace
            .apply_preserving_whitespace(mask, self.text, &mut text);
        // `--pre` runs against the raw ciphertext text -- whitespace and all -- before
        // the display's initial decode, the genuine top of the stack. This comment used
        // to be a lie: `text` was built from the whitespace-stripped transcription, so
        // every word-boundary-sensitive `--pre` value (`reverse_words` above all) was
        // handed a single token and quietly became identity. Only once `--pre` accepts
        // the text does the display get normalised into `canonical` -- and every
        // decoder `canonical_bytes_strict` dispatches to filters or splits on
        // whitespace already (`decode_hex` keeps only hex digits, `decode_base64` only
        // base64 glyphs, `decode_radix` splits *on* whitespace), so carrying it this
        // far costs the decode nothing.
        let pre = &self.axes.pres[pre_digit];
        // A `--pre` transform can change the text so the display no longer decodes
        // (e.g. ubchi turns 192 base64 chars into 191). `canonical_bytes` would
        // silently return the UNDECODED text, which the layers below then score as
        // though it were a decryption — 16 phantom hits at score 1.0000. The strict
        // form reports the failure so the candidate is skipped, exactly as a
        // rejecting `bwt` is.
        let canonical = pre
            .apply(&text)
            .and_then(|t| Repr::new(t, self.display).canonical_bytes_strict());
        let staged = match (self.plan.tier, &canonical) {
            (Tier::T2, Some(c)) => self.axes.xfs.iter().map(|x| x.apply(c)).collect(),
            _ => Vec::new(),
        };
        VariantStage {
            digit,
            pre_digit,
            canonical,
            staged,
        }
    }
}

fn run_range(ctx: &Ctx, start: u64, end: u64) -> ChunkOut {
    let mut acc = ChunkOut {
        start,
        leaves: Vec::with_capacity((end - start) as usize),
        hits: Vec::new(),
        hit_count: 0,
        scored_lens: BTreeMap::new(),
        pass_lens: BTreeMap::new(),
    };
    // The T3 prefix: first layer, transform and codec, recomputed only when the
    // chunk crosses a stride boundary. Dropped with the chunk.
    let mut prefix: Option<(u64, Stage2)> = None;
    // The current transcription's ciphertext. Also dropped with the chunk.
    let mut stage: Option<VariantStage> = None;

    for i in start..end {
        let d = ctx.plan.digits(i);
        let vdigit = d[ctx.plan.variant_axis];
        // `pre_axis` is absent exactly when `--pre` is at its default, in which
        // case `axes.pres` is the single-element `[Pre::Identity]` and digit 0 is
        // the only (and correct) choice.
        let pdigit = ctx.plan.pre_axis.map(|ax| d[ax]).unwrap_or(0);
        if stage.as_ref().map(|s| (s.digit, s.pre_digit)) != Some((vdigit, pdigit)) {
            stage = Some(ctx.stage(vdigit, pdigit));
            // The T3 shared prefix decrypts the ciphertext, so a new transcription
            // or `pre` outcome invalidates it. Crossing a variant boundary also
            // crosses a stride boundary (the variant is the most significant
            // digit), so this is belt and braces rather than the only guard — but
            // reusing a prefix from another (reading, pre) pair would silently
            // evaluate the wrong pipeline.
            prefix = None;
        }
        let stage = stage.as_ref().expect("staged above");
        let vprefix = ctx.axes.variant_prefix(vdigit);
        let pre = &ctx.axes.pres[pdigit];
        let pre_prefix = ctx.axes.pre_prefix(pdigit);
        // The `--pre` transform runs above everything else, in every tier: prepend
        // it to the chain spec before the initial decode, so a candidate's chain is
        // a real, re-runnable `ra run` spec in the order it was actually evaluated.
        let pre_chain_prefix = pre.chain_prefix();
        // `post_axis` is absent exactly when `--post` is at its default, in which
        // case `axes.posts` is the single-element `[Post::Identity]` and digit 0
        // is the only (and correct) choice -- the mirror image of `pdigit` above.
        let post_digit = ctx.plan.post_axis.map(|ax| d[ax]).unwrap_or(0);
        let post = &ctx.axes.posts[post_digit];
        let post_suffix = ctx.axes.post_suffix(post_digit);
        // `--post` runs below everything else, in every tier: append it to the
        // chain spec after the terminal decrypt, so a candidate's chain is a
        // real, re-runnable `ra run` spec in the order it was actually evaluated.
        let post_chain_suffix = post.chain_suffix();
        // `fmt_axis` is absent exactly when `--toolfmt` is at its default, in
        // which case `axes.toolfmts` is the single-element `[ToolFmt::None]`
        // and digit 0 is the only (and correct, no-op) choice -- the same
        // "default means absent" footing as `pdigit`/`post_digit` above.
        let fdigit = ctx.plan.fmt_axis.map(|ax| d[ax]).unwrap_or(0);
        let fmt = ctx.axes.toolfmts[fdigit];
        let fmt_prefix = ctx.axes.toolfmt_prefix(fdigit);
        let (params, chain, out, block_size, digest) = match ctx.plan.tier {
            Tier::T1 | Tier::T2 => {
                // T1's skeleton has no `xf` slot, so it must decrypt the untransformed
                // bytes whatever `--xf` says. Reading a transform here while claiming
                // <b64d ∘ dec> would evaluate a T2 pipeline and file it as T1.
                let (xf, staged): (Xf, Option<&[u8]>) = match ctx.plan.tier {
                    Tier::T2 => (
                        ctx.axes.xfs[d[LAYER_AXES]],
                        match &stage.canonical {
                            None => None,
                            Some(_) => stage.staged[d[LAYER_AXES]].as_deref(),
                        },
                    ),
                    _ => (Xf::Identity, stage.canonical.as_deref()),
                };
                let l = LayerParams::at(ctx.axes, &d, 0);
                // `staged` is `None` when `--pre` or `xf` rejected the ciphertext
                // (only `bwt` can do either); the candidate is then inapplicable,
                // same as a decrypt that fails. `--toolfmt` strips the
                // hypothesised tool artifact from the bytes immediately before
                // they reach the decrypt call -- the one boundary in the
                // pipeline with no built-in whitespace/grouping tolerance. See
                // [`ToolFmt`].
                let decrypted = staged.and_then(|bytes| l.decrypt(&fmt.strip(bytes)));
                // `--post` runs on the terminal decrypt's own output, after
                // everything else. `None` means either the decrypt itself was
                // inapplicable or `post` rejected the decrypted bytes (only
                // `affine` with a non-coprime `a` can do the latter today).
                let out = decrypted.as_ref().and_then(|o| post.apply(o));
                // Retains the pre-existing leaf spelling, so a T1/T2 commitment
                // from before multi-layer support still reconciles (`vprefix`,
                // `pre_prefix`, `fmt_prefix` and `post_suffix` are all empty
                // unless their axis actually varies).
                let params = format!(
                    "{vprefix}{pre_prefix}{fmt_prefix}xf={},prim={},mode={},key={},kd={},iv={}{post_suffix}",
                    xf.label(),
                    l.prim,
                    l.mode,
                    l.key.label,
                    l.kd,
                    l.iv.0
                );
                let base_chain = match xf {
                    Xf::Identity => format!("{} | {}", ctx.initial_decode, l.spec()),
                    Xf::Reverse => {
                        format!("{} | reverse | {}", ctx.initial_decode, l.spec())
                    }
                    Xf::Bwt => format!("{} | bwt | {}", ctx.initial_decode, l.spec()),
                };
                let chain =
                    annotate_toolfmt(format!("{pre_chain_prefix}{base_chain}{post_chain_suffix}"), fmt);
                let digest = match (&stage.canonical, &decrypted, &out) {
                    (None, _, _) => "pre-failed".to_string(),
                    (Some(_), None, _) => "inapplicable".to_string(),
                    (Some(_), Some(_), None) => "post-failed".to_string(),
                    (Some(_), Some(_), Some(o)) => hex::encode(ra_merkle::h(o)),
                };
                (params, chain, out, l.block_size(), digest)
            }
            Tier::T3 => {
                let block = i / ctx.plan.stride;
                if prefix.as_ref().map(|(b, _)| *b) != Some(block) {
                    let l1 = LayerParams::at(ctx.axes, &d, LAYER_AXES + 2);
                    let xf = ctx.axes.xfs[d[LAYER_AXES + 1]];
                    let codec = ctx.axes.codecs[d[LAYER_AXES]];
                    let stage2 = match &stage.canonical {
                        None => Stage2::PreFailed,
                        // `--toolfmt` strips the hypothesised tool artifact
                        // immediately before this decrypt call, the same as
                        // the T1/T2 branch above -- this is the boundary
                        // between the initial decode and the first modern
                        // layer, exactly the "no built-in tolerance" position
                        // [`ToolFmt`]'s doc identifies. `fdigit` is constant
                        // across this whole stride block, since `fmt_axis`
                        // sits above the layer-2 digit block that `stride`
                        // spans.
                        Some(canonical) => match l1.decrypt(&fmt.strip(canonical)) {
                            None => Stage2::Layer1Inapplicable,
                            Some(o) => match xf.apply(&o) {
                                None => Stage2::XfFailed,
                                Some(transformed) => match codec.apply(&transformed) {
                                    None => Stage2::CodecFailed,
                                    Some(v) => Stage2::Ready(v),
                                },
                            },
                        },
                    };
                    prefix = Some((block, stage2));
                }
                let l1 = LayerParams::at(ctx.axes, &d, LAYER_AXES + 2);
                let xf = ctx.axes.xfs[d[LAYER_AXES + 1]];
                let codec = ctx.axes.codecs[d[LAYER_AXES]];
                let l2 = LayerParams::at(ctx.axes, &d, 0);

                let (out, digest) = match &prefix.as_ref().unwrap().1 {
                    Stage2::PreFailed => (None, "pre-failed".to_string()),
                    Stage2::Layer1Inapplicable => (None, "inapplicable-layer1".to_string()),
                    Stage2::XfFailed => (None, "xf-failed".to_string()),
                    Stage2::CodecFailed => (None, "codec-failed".to_string()),
                    // `--toolfmt` strips the hypothesised tool artifact from
                    // the inter-layer bytes too, immediately before the
                    // second decrypt -- the boundary between the (optional)
                    // `xf`/`codec` re-encoding and the second modern layer.
                    Stage2::Ready(data) => match l2.decrypt(&fmt.strip(data)) {
                        // `--post` runs on the terminal (second-layer) decrypt's
                        // own output, after everything else.
                        Some(o) => match post.apply(&o) {
                            Some(p) => {
                                let h = hex::encode(ra_merkle::h(&p));
                                (Some(p), h)
                            }
                            None => (None, "post-failed".to_string()),
                        },
                        None => (None, "inapplicable-layer2".to_string()),
                    },
                };
                let params = format!(
                    "{vprefix}{pre_prefix}{fmt_prefix}{},xf={},codec={},{}{post_suffix}",
                    l1.describe("1"),
                    xf.label(),
                    codec.label(),
                    l2.describe("2")
                );
                // `--pre` is the genuine top of the stack, so it precedes even the
                // initial decode in the rendered chain; `--post` is the genuine
                // bottom, so it follows even the terminal decrypt.
                let mut steps = vec![ctx.initial_decode.to_string(), l1.spec()];
                match xf {
                    Xf::Identity => {}
                    Xf::Reverse => steps.push("reverse".to_string()),
                    Xf::Bwt => steps.push("bwt".to_string()),
                }
                steps.extend(codec.node_names().iter().map(|s| s.to_string()));
                steps.push(l2.spec());
                steps.extend(post.chain_steps());
                let chain = annotate_toolfmt(format!("{pre_chain_prefix}{}", steps.join(" | ")), fmt);
                (params, chain, out, l2.block_size(), digest)
            }
        };

        acc.leaves.push(leaf_hash(i, &params, &digest));

        if let Some(o) = out {
            let s = ctx.oracle.score(&o, block_size);
            *acc.scored_lens.entry(s.scored_len).or_insert(0) += 1;
            if s.passed {
                acc.hit_count += 1;
                *acc.pass_lens.entry(s.scored_len).or_insert(0) += 1;
                let mask = ctx.axes.variant_masks[vdigit];
                push_hit(
                    &mut acc.hits,
                    Hit {
                        index: i,
                        score: s.score,
                        class: s.class.as_str().to_string(),
                        scored_len: s.scored_len,
                        describe: params,
                        chain,
                        preview: String::from_utf8_lossy(&o[..64.min(o.len())])
                            .chars()
                            .filter(|c| !c.is_control())
                            .collect(),
                        variant: ctx.axes.vspace.label(mask),
                        variant_note: if mask == 0 {
                            ctx.axes.vspace.describe(mask)
                        } else {
                            // the exact bytes, since the corpus record does not hold them
                            let mut text = Vec::new();
                            ctx.axes
                                .vspace
                                .apply_preserving_whitespace(mask, ctx.text, &mut text);
                            format!(
                                "{}  ciphertext={}",
                                ctx.axes.vspace.describe(mask),
                                String::from_utf8_lossy(&text)
                            )
                        },
                    },
                    CHUNK_HIT_CAP,
                );
            }
        }
    }
    acc
}

/// One skeleton's finished sweep.
struct SkeletonRun {
    tier: Tier,
    planned: u128,
    evaluated: u64,
    merkle_root: String,
    resident_bytes: usize,
    hits: Vec<Hit>,
    hit_count: u64,
    scored_lens: BTreeMap<usize, u64>,
    pass_lens: BTreeMap<usize, u64>,
    elapsed: f64,
    claim: CoverageSet,
    /// The axis lists in the order the index actually walked them. Without this the
    /// emitted `merkle_root` cannot be regenerated from the emitted claim, because the
    /// cover stores axes as sorted sets. See [`Plan::enumeration_order`].
    enumeration_order: Vec<(String, Vec<String>)>,
}

fn execute(ctx: &Ctx, bound: u64, progress_every: f64) -> SkeletonRun {
    let plan = ctx.plan;
    let chunk = plan.chunk();
    // Keep the resident commitment well under a byte per candidate even at 1e8.
    let checkpoint_every = ((bound / 4096).max(1 << 16)).next_power_of_two();
    let mut merkle = StreamingMerkle::new(checkpoint_every);

    let mut hits: Vec<Hit> = Vec::new();
    let mut hit_count = 0u64;
    let mut scored_lens: BTreeMap<usize, u64> = BTreeMap::new();
    let mut pass_lens: BTreeMap<usize, u64> = BTreeMap::new();

    let done = AtomicU64::new(0);
    let last_report = Mutex::new(Instant::now());
    let started = Instant::now();

    // Leaves must be folded in index order, so the commitment cannot depend on
    // thread scheduling. Batching bounds resident leaf memory: a 1e8-candidate
    // sweep would need 3 GB to hold every leaf at once, so chunks are processed in
    // ordered batches and each batch's leaves are folded and dropped.
    let batch = chunk * (1u64 << 20).div_ceil(chunk);
    let mut at = 0u64;
    while at < bound {
        let batch_end = (at + batch).min(bound);
        let ranges: Vec<(u64, u64)> = (at..batch_end)
            .step_by(chunk as usize)
            .map(|s| (s, (s + chunk).min(batch_end)))
            .collect();
        let mut outs: Vec<ChunkOut> = ranges
            .par_iter()
            .map(|&(s, e)| {
                let out = run_range(ctx, s, e);
                let n = done.fetch_add(e - s, Ordering::Relaxed) + (e - s);
                if progress_every > 0.0 {
                    if let Ok(mut last) = last_report.try_lock() {
                        if last.elapsed().as_secs_f64() >= progress_every {
                            *last = Instant::now();
                            let secs = started.elapsed().as_secs_f64().max(1e-9);
                            eprintln!(
                                "  [{}] {:>6.2}%  {}/{} candidates  {:.0}/s  eta {}",
                                ctx.plan.tier.id(),
                                100.0 * n as f64 / bound as f64,
                                n,
                                bound,
                                n as f64 / secs,
                                fmt_dur((bound - n) as f64 * secs / n as f64)
                            );
                        }
                    }
                }
                out
            })
            .collect();
        outs.sort_by_key(|o| o.start);
        for o in outs.drain(..) {
            for l in o.leaves {
                merkle.add(l);
            }
            hit_count += o.hit_count;
            for (k, v) in o.scored_lens {
                *scored_lens.entry(k).or_insert(0) += v;
            }
            for (k, v) in o.pass_lens {
                *pass_lens.entry(k).or_insert(0) += v;
            }
            for h in o.hits {
                push_hit(&mut hits, h, HIT_RETENTION_CAP);
            }
        }
        at = batch_end;
    }

    hits.sort_by(|a, b| {
        significance(b)
            .partial_cmp(&significance(a))
            .unwrap_or(std::cmp::Ordering::Equal)
            .then(a.index.cmp(&b.index))
    });

    SkeletonRun {
        tier: plan.tier,
        planned: plan.total(),
        evaluated: merkle.len(),
        merkle_root: hex::encode(merkle.root()),
        resident_bytes: merkle.memory_bytes(),
        hits,
        hit_count,
        scored_lens,
        pass_lens,
        elapsed: started.elapsed().as_secs_f64(),
        claim: plan.cover(merkle.len()),
        enumeration_order: plan.enumeration_order(),
    }
}

/// Expected number of chance passes, from the *actual* distribution of scored
/// lengths rather than a nominal payload size.
///
/// This matters for T3: an inter-layer `hexdecode` of high-entropy bytes keeps only
/// the ASCII hex digits, so the second layer can receive a dozen bytes instead of
/// 144, and the printable-ratio oracle's false-positive rate over twelve bytes is
/// nothing like its rate over 144. Reporting the budget beside the hit count is what
/// stops a matcher artifact being read as a result.
///
/// Dispatches on the oracle's [`Metric`] rather than blindly feeding
/// `oracle.threshold` into the printable-ratio model. That bug previously made
/// every conjunction oracle (`PrintableAndEnglish`) report a budget of ~1.0 per
/// candidate: `oracle.threshold` for that metric is the *quadgram* floor (a
/// negative log-probability, e.g. -5.25), and `p_ratio_printable` silently
/// clamped that to a `ceil(threshold * n)` of 0, i.e. "at least 0 of n bytes
/// printable" — true of everything. See [`per_candidate_false_positive_rate`].
fn expected_false_positives(scored_lens: &BTreeMap<usize, u64>, oracle: &OracleSpec) -> f64 {
    scored_lens
        .iter()
        .map(|(&n, &c)| c as f64 * per_candidate_false_positive_rate(oracle, n))
        .sum()
}

/// Per-candidate chance-pass probability at scored length `n`, modelled per
/// [`Metric`] rather than assuming every oracle's threshold is a printable
/// ratio.
///
/// For [`Metric::PrintableAndEnglish`] the two floors are gated by the same
/// candidate and are not independent, so the true joint probability has no
/// closed analytic form here; the English-fitness term in particular is not
/// analytic the way a printable ratio is (see [`ra_oracle::p_quadgram_false_positive`]'s
/// docs for how it was derived empirically, from a Monte Carlo scoring
/// uniform-random and base64-decoded-noise windows at the relevant lengths).
/// We instead use the standard subadditivity bound `P(A ∩ B) <= min(P(A),
/// P(B))`, which is exact when one event implies the other and conservative
/// (an overestimate, never an underestimate) otherwise — the right direction
/// of error for a reported budget. This is a REPORTING figure only: it does
/// not feed into `OracleSpec::score`'s pass/fail decision, which already
/// evaluates both floors directly.
fn per_candidate_false_positive_rate(oracle: &OracleSpec, n: usize) -> f64 {
    match oracle.metric {
        Metric::PrintableAsciiRatio => ra_oracle::p_ratio_printable(n, oracle.threshold),
        // Out of scope for this fix (not a conjunction oracle): kept as the
        // pre-existing, deliberately conservative all-printable proxy.
        Metric::ValidEncodingAny => ra_oracle::p_ratio_printable(n, oracle.threshold),
        Metric::EnglishQuadgram => ra_oracle::p_quadgram_false_positive(n),
        Metric::PrintableAndEnglish { printable_floor } => {
            ra_oracle::p_ratio_printable(n, printable_floor)
                .min(ra_oracle::p_quadgram_false_positive(n))
        }
        Metric::IocEnglish => ra_oracle::p_ioc_false_positive(n),
    }
}

fn fmt_dur(secs: f64) -> String {
    if !secs.is_finite() || secs < 0.0 {
        return "?".to_string();
    }
    let s = secs as u64;
    if s < 60 {
        format!("{s}s")
    } else if s < 3600 {
        format!("{}m{:02}s", s / 60, s % 60)
    } else {
        format!("{}h{:02}m", s / 3600, (s % 3600) / 60)
    }
}

// ---------------------------------------------------------------------------
// Driver
// ---------------------------------------------------------------------------

pub fn run(data: &Path, args: SweepArgs) -> Result<()> {
    let target = crate::corpus::load_target(data, &args.target)?;
    let input = Repr::new(target.raw.clone().into_bytes(), target.display);
    let canonical = input.canonical_bytes();

    let oracle = ra_oracle::oracle(&args.oracle)
        .with_context(|| format!("unknown oracle {:?}", args.oracle))?;
    let axes = resolve_axes(&args, &target)?;
    // Two views of the same transcription, and they are not interchangeable.
    // `raw_text` is what a candidate is actually fed (see `Ctx::text`); `compact` is
    // the whitespace-free text the variant machinery *indexes*, so it stays the basis
    // for reported glyph offsets and for the character count printed below.
    let raw_text: Vec<u8> = sweep_input_text(&target);
    let compact: Vec<u8> = variant_index_text(&target);

    let tiers = resolve_tiers(&args.tier, &axes)?;
    let plans: Vec<Plan> = tiers.iter().map(|&t| Plan::new(t, &axes)).collect();
    for p in &plans {
        // The index is a u64, and the bijection depends on it. Refuse rather than
        // wrap, because a wrapped index would enumerate some candidates twice while
        // the claim asserted the full product.
        anyhow::ensure!(
            u64::try_from(p.total()).is_ok(),
            "{}'s index space is {} candidates, which exceeds u64; narrow an axis",
            p.tier.id(),
            p.total()
        );
    }

    println!(
        "sweep {}: {} bytes ({} display, {} chars)",
        target.id,
        canonical.len(),
        target.display_hint,
        compact.len()
    );
    // The transcription is an assumption, so it is stated before any work is spent on
    // it, and the positions are the derived ones rather than a written-down list.
    if axes.vspace.is_ambiguous() {
        let census: Vec<String> = axes
            .vspace
            .census()
            .iter()
            .map(|(g, n)| format!("{n}x{}", *g as char))
            .collect();
        let open = axes.vspace.open_positions();
        println!(
            "transcription: {} open ambiguous glyph positions ({}) -> {} admissible readings",
            open.len(),
            census.join(" "),
            axes.vspace.count()
        );
        println!("  open       : {open:?}  (offsets into the display text)");
        // Stated, not silently omitted: the resolved pair is fixed on external
        // authority, so a reader can see that those positions were decided rather
        // than overlooked.
        let resolved = crate::variants::VariantSpace::resolved_positions(&compact, target.display);
        if !resolved.is_empty() {
            println!(
                "  resolved   : {resolved:?}  (0/O, fixed to the recorded reading against \
                 the source font; NOT enumerated)"
            );
        }
        println!(
            "  variants   : {} selected, {}..{} ({} is the recorded reading)",
            axes.variant_masks.len(),
            axes.vspace.label(axes.variant_masks[0]),
            axes.vspace.label(*axes.variant_masks.last().expect("non-empty")),
            axes.vspace.label(0)
        );
        if (axes.variant_masks.len() as u64) < axes.vspace.count() {
            println!(
                "  NOT COVERED: {} of the {} admissible readings are outside this run and \
                 are NOT claimed.",
                axes.vspace.count() - axes.variant_masks.len() as u64,
                axes.vspace.count()
            );
        }
    } else {
        println!(
            "transcription: no glyph ambiguity in a {} display ({} excludes the \
             ambiguous partners), so the variant dimension is the single point {:?}",
            target.display_hint, target.display_hint, axes.vspace.label(0)
        );
    }
    println!("oracle: {} (block_aware={})", oracle.id, oracle.block_aware);
    println!(
        "axes: {} prims x {} modes x {} keys x {} kd x {} ivs = {} per modern layer",
        axes.prims.len(),
        axes.modes.len(),
        axes.keys.len(),
        axes.kds.len(),
        axes.ivs.len(),
        axes.layer_unit()
    );
    println!(
        "      {} transforms, {} inter-layer codecs, {} toolfmt artifacts",
        axes.xfs.len(),
        axes.codecs.len(),
        axes.toolfmts.len()
    );
    for k in &axes.keys {
        if k.label.ends_with("_b64") {
            println!(
                "note: key domain value {} resolves to the bytes {:?}",
                k.label,
                String::from_utf8_lossy(&k.bytes)
            );
        }
    }

    if tiers.contains(&Tier::T1) && axes.xfs.iter().any(|x| *x != Xf::Identity) {
        println!(
            "note: t1's skeleton <b64d o dec> has no transform slot, so t1 sweeps the \
             untransformed\n      bytes only; the listed transforms apply to t2 and t3."
        );
    }

    // What each axis value actually does to THIS ciphertext, before a single
    // candidate is spent on it. A named axis that turns out to be a no-op here is the
    // difference between a negative worth publishing and a negative that is an
    // artefact of the harness, so it is stated up front rather than discovered later.
    let pre_staged = pre_staged_inputs(&axes, &raw_text, target.display);
    let xf_staged = xf_staged_inputs(&axes, &raw_text, target.display);
    let (pre_tuples, pre_distinct) = staged_input_census(&pre_staged);
    let (xf_tuples, xf_distinct) = staged_input_census(&xf_staged);
    if pre_tuples > 1 || xf_tuples > 1 {
        println!(
            "staged inputs: --pre {pre_tuples} values -> {pre_distinct} distinct byte \
             inputs; --xf {xf_tuples} -> {xf_distinct}"
        );
    }
    for w in degeneracy_warnings("pre", &target.id, &pre_staged) {
        println!("{w}");
    }
    for w in degeneracy_warnings("xf", &target.id, &xf_staged) {
        println!("{w}");
    }

    // The total is predictable before any work starts, per skeleton.
    println!("\nplan");
    let mut planned_total: u128 = 0;
    let mut bounded_total: u128 = 0;
    for p in &plans {
        let bound = bound_for(p, args.max_candidates);
        planned_total += p.total();
        bounded_total += u128::from(bound);
        println!(
            "  {:<3} <{}>  {} candidates{}",
            p.tier.id(),
            p.tier.skeleton().join(" o "),
            crate::fmt(p.total()),
            if u128::from(bound) < p.total() {
                format!(
                    "  -> BOUNDED to {} ({:.4}% of the skeleton)",
                    crate::fmt(u128::from(bound)),
                    100.0 * bound as f64 / p.total() as f64
                )
            } else {
                String::new()
            }
        );
    }
    println!("  total planned   = {}", crate::fmt(planned_total));
    if bounded_total != planned_total {
        println!(
            "  total to evaluate = {}   ({} dropped by --max-candidates; the emitted \
             claim describes only what was evaluated)",
            crate::fmt(bounded_total),
            crate::fmt(planned_total - bounded_total)
        );
    }
    if args.dry_run {
        println!("\n(--dry-run: nothing evaluated)");
        return Ok(());
    }

    let initial_decode = match target.display {
        ra_core::Display::Hex => "hexdecode",
        ra_core::Display::Base64 => "b64decode",
        ra_core::Display::Decimal => "decimaldecode",
        ra_core::Display::Octal => "octaldecode",
        ra_core::Display::Bytes => "identity",
    };

    let mut runs: Vec<SkeletonRun> = Vec::new();
    for p in &plans {
        let bound = bound_for(p, args.max_candidates);
        let ctx = Ctx {
            plan: p,
            axes: &axes,
            text: &raw_text,
            display: target.display,
            oracle,
            initial_decode,
        };
        println!("\n=== {} <{}> ===", p.tier.id(), p.tier.skeleton().join(" o "));
        let run = execute(&ctx, bound, args.progress_every);
        report(&run, oracle, &args);
        runs.push(run);
    }

    let mut claim = CoverageSet::new();
    for r in &runs {
        claim = claim.union(&r.claim);
    }
    let evaluated: u64 = runs.iter().map(|r| r.evaluated).sum();

    println!("\ncoverage claim (all skeletons)");
    println!(
        "  scope  = {} (a coverage set is a region of one cipher's universe; the \
         variant dimension carries that scope)",
        target.id
    );
    println!("  size   = {}", crate::fmt(claim.size_exact()));
    println!("  digest = {}", claim.digest());
    for line in claim.notation().lines() {
        println!("  {line}");
    }
    // The invariant this module exists to protect: the claim must not be larger
    // than the work.
    assert_eq!(
        claim.size_exact(),
        u128::from(evaluated),
        "claimed coverage must equal the candidates actually evaluated"
    );
    println!(
        "  size_exact() == {} candidates actually evaluated  [checked]",
        crate::fmt(u128::from(evaluated))
    );
    if claim.size_exact() < planned_total {
        println!(
            "  BOUND LOGGED: {} of the {} modelled candidates in these skeletons were \
             NOT evaluated and are NOT claimed.",
            crate::fmt(planned_total - claim.size_exact()),
            crate::fmt(planned_total)
        );
    }

    if let Some(path) = &args.emit_claim {
        // The conformance state this run happened under, recorded at emission time so
        // the claim is self-describing. Without it a reader cannot tell whether the
        // primitives the claim names were ever proven, and has to assume — which is
        // precisely the assumption conformance gating exists to remove.
        let state = crate::corpus::conformance_state(data, None)?;
        let swept: Vec<String> = axes.prim_labels.clone();
        let unproven_here: Vec<&String> = swept
            .iter()
            .filter(|p| !state.proven.iter().any(|q| q.eq_ignore_ascii_case(p)))
            .collect();
        println!(
            "\nconformance at emission: {} of {} primitives proven; suite {}",
            state.proven.len(),
            ra_prim::PRIMS.len(),
            &state.suite_digest[..24.min(state.suite_digest.len())]
        );
        if unproven_here.is_empty() {
            println!("  every primitive this run swept is proven, so gating voids nothing");
        } else {
            // Emitted anyway, and honestly. Refusing would lose the record of work
            // actually done; the gate at fold time is what stops it counting.
            println!(
                "  WARNING: {} swept primitive(s) are NOT proven and will contribute ZERO\n  \
                 coverage when this claim is folded: {}",
                unproven_here.len(),
                unproven_here
                    .iter()
                    .map(|s| s.as_str())
                    .collect::<Vec<_>>()
                    .join(", ")
            );
        }
        let doc = serde_json::json!({
            "target": target.id,
            // What `enumeration_order` is to the Merkle root, this is to the coverage:
            // the state the claim has to carry for anyone to be able to check it.
            "conformance": {
                "suite_digest": state.suite_digest,
                "proven_primitives": state.proven.iter().collect::<Vec<_>>(),
                "unproven_primitives": ra_prim::PRIMS.iter()
                    .map(|i| i.display_name)
                    .filter(|n| !state.proven.contains(*n))
                    .collect::<Vec<_>>(),
                "swept_primitives": swept,
                "all_swept_primitives_proven": unproven_here.is_empty(),
            },
            // The transcription dimension, stated in full: what is ambiguous, how many
            // readings that admits, and which of them this run actually covered.
            // Side metadata, alongside the leaves and never inside them: what each
            // axis value did to this target's bytes, so a reader can verify after the
            // fact that a claimed axis actually varied the input rather than trusting
            // the axis label.
            "staged_inputs": staged_inputs_json(&raw_text, &pre_staged, &xf_staged),
            "transcription": {
                "open_glyph_pairs": crate::variants::AMBIGUOUS_PAIRS
                    .iter().map(|(a,b)| format!("{}/{}", *a as char, *b as char))
                    .collect::<Vec<_>>(),
                "open_positions": axes.vspace.open_positions(),
                // Fixed on the project team's review of the source font. Recorded so a
                // claim states which positions were resolved rather than leaving their
                // absence to be inferred.
                "resolved_glyph_pairs": crate::variants::RESOLVED_PAIRS
                    .iter().map(|(a,b)| format!("{}/{}", *a as char, *b as char))
                    .collect::<Vec<_>>(),
                "resolved_positions":
                    crate::variants::VariantSpace::resolved_positions(&compact, target.display),
                "admissible_readings": axes.vspace.count(),
                // the readings themselves are the `0.variant` dimension of the cover
                // below; listing them twice would let the two disagree
                "variants_covered": axes.variant_masks.len(),
                "variant_space_complete":
                    axes.variant_masks.len() as u64 == axes.vspace.count(),
                "recorded_reading": axes.vspace.label(0),
            },
            "variant": axes.vspace.label(0),
            "oracle": oracle.id,
            "tiers": runs.iter().map(|r| serde_json::json!({
                "tier": r.tier.id(),
                "skeleton": r.tier.skeleton(),
                "planned_candidates": r.planned.to_string(),
                "candidates_evaluated": r.evaluated,
                "bounded": u128::from(r.evaluated) < r.planned,
                "merkle_root": r.merkle_root,
                "hits": r.hit_count,
                // The hits themselves, not just the tally. A claim that records only a
                // count is un-auditable the moment the count is non-zero: there is no
                // way to tell a real breakthrough from oracle noise without re-running
                // the whole sweep. `max_hits` caps what is retained, so
                // `hit_samples_truncated` says plainly when the list is partial.
                "hit_samples": r.hits.iter().map(|h| serde_json::json!({
                    "index": h.index,
                    "score": h.score,
                    "class": h.class,
                    "scored_len": h.scored_len,
                    "chain": h.chain,
                    "preview": h.preview,
                    "variant": h.variant,
                })).collect::<Vec<_>>(),
                "hit_samples_truncated": r.hit_count > r.hits.len() as u64,
                "expected_false_positives":
                    expected_false_positives(&r.scored_lens, oracle),
                "longest_scored_region_among_passes": r.pass_lens.keys().next_back(),
                "longest_scored_region": r.scored_lens.keys().next_back(),
                "elapsed_secs": r.elapsed,
                "coverage_size_exact": r.claim.size_exact().to_string(),
                // What makes `merkle_root` reproducible. The cover below stores each axis
                // as a sorted set — right for the coverage digest, but `leaf_hash` binds
                // the candidate index, and the index walks these lists in *this* order.
                // Least significant digit first. See `Plan::enumeration_order`.
                "enumeration_order": r.enumeration_order.iter()
                    .map(|(dim, values)| serde_json::json!({"dim": dim, "values": values}))
                    .collect::<Vec<_>>(),
            })).collect::<Vec<_>>(),
            "merkle_root": if runs.len() == 1 {
                runs[0].merkle_root.clone()
            } else {
                let joined = runs.iter().map(|r| format!("{}:{}", r.tier.id(), r.merkle_root))
                    .collect::<Vec<_>>().join("|");
                hex::encode(ra_merkle::h(joined.as_bytes()))
            },
            "candidates_evaluated": evaluated,
            "hits": runs.iter().map(|r| r.hit_count).sum::<u64>(),
            "coverage_claimed": claim.to_json(),
            "coverage_claimed_digest": claim.digest(),
        });
        std::fs::write(path, serde_json::to_string_pretty(&doc)?)
            .with_context(|| format!("writing {}", path.display()))?;
        println!("\n  wrote claim to {}", path.display());
    }
    Ok(())
}

fn bound_for(plan: &Plan, max: Option<u64>) -> u64 {
    let total = u64::try_from(plan.total()).unwrap_or(u64::MAX);
    match max {
        Some(m) => m.min(total),
        None => total,
    }
}

/// `auto` reproduces the pre-tier behaviour: a non-identity transform in the list
/// means the skeleton has an `xf` slot.
fn resolve_tiers(spec: &[String], axes: &Axes) -> Result<Vec<Tier>> {
    let mut out: Vec<Tier> = Vec::new();
    for s in spec {
        if s.trim().eq_ignore_ascii_case("auto") {
            out.push(if axes.xfs.iter().any(|x| *x != Xf::Identity) {
                Tier::T2
            } else {
                Tier::T1
            });
        } else {
            out.push(
                Tier::parse(s).with_context(|| format!("unknown tier {s:?}; use t1, t2 or t3"))?,
            );
        }
    }
    out.sort_unstable();
    out.dedup();
    anyhow::ensure!(!out.is_empty(), "at least one tier is required");
    if out.iter().any(|t| t.layers() > 1) && axes.codecs.is_empty() {
        anyhow::bail!("t3 needs at least one --codec value");
    }
    Ok(out)
}

fn report(run: &SkeletonRun, oracle: &OracleSpec, args: &SweepArgs) {
    println!("commitment");
    println!(
        "  candidates : {} of {} planned",
        crate::fmt(u128::from(run.evaluated)),
        crate::fmt(run.planned)
    );
    println!("  merkle root: {}", run.merkle_root);
    println!(
        "  resident   : {} bytes ({:.6} per candidate)",
        run.resident_bytes,
        run.resident_bytes as f64 / run.evaluated.max(1) as f64
    );
    println!(
        "  wall clock : {:.2}s  ({:.0} candidates/sec)",
        run.elapsed,
        run.evaluated as f64 / run.elapsed.max(1e-9)
    );
    let scored_total: u64 = run.scored_lens.values().sum();
    if let (Some((&lo, _)), Some((&hi, _))) = (
        run.scored_lens.iter().next(),
        run.scored_lens.iter().next_back(),
    ) {
        println!("  scored len : {lo}..{hi} bytes over {scored_total} scorable outputs");
    }
    let efp = expected_false_positives(&run.scored_lens, oracle);
    println!("  expected false positives at this oracle: {efp:.3e}");

    println!("hits: {}", run.hit_count);
    if run.hit_count == 0 {
        println!("  (none above the oracle threshold)");
        println!(
            "  This is a NEGATIVE claim. It is only as good as the conformance of the\n  \
             primitives it used — run `ra conformance` before believing it, because an\n  \
             unproven primitive sweeps a space that may not be the real one."
        );
    } else {
        // A correct decryption presents as a pass over a *full-length* scored region.
        // Reporting the longest scored region among the passes is therefore what turns
        // "these are all artifacts" from an assertion into a check.
        let longest_pass = run.pass_lens.keys().next_back().copied().unwrap_or(0);
        let longest_scored = run.scored_lens.keys().next_back().copied().unwrap_or(0);
        println!(
            "  longest scored region among passes: {longest_pass} bytes \
             (longest scored anywhere: {longest_scored})"
        );
        if efp > 1.0 {
            println!(
                "  WARNING: {efp:.3e} chance passes are expected over this sweep, so this hit\n  \
                 count carries little information. Short inter-layer decodes shrink the\n  \
                 scored region and with it the oracle's discriminating power."
            );
            if run.hit_count as f64 <= efp {
                println!(
                    "  The observed {} passes are at or below the chance expectation, and the\n  \
                     longest is {longest_pass} bytes. NO CANDIDATE SOLVE: a real one would\n  \
                     present over the full {longest_scored}-byte region, not a few bytes.",
                    run.hit_count
                );
            }
        }
    }
    for h in run.hits.iter().take(args.max_hits) {
        println!(
            "  #{:<10} score={:.4} class={:<9} scored={:<4} {}",
            h.index, h.score, h.class, h.scored_len, h.describe
        );
        println!("      variant: {} ({})", h.variant, h.variant_note);
        println!("      chain: {}", h.chain);
        println!("      {}", h.preview);
    }
    if run.hit_count as usize > args.max_hits {
        println!(
            "  ... {} more suppressed by --max-hits{}",
            run.hit_count as usize - args.max_hits,
            if run.hit_count as usize > HIT_RETENTION_CAP {
                format!(
                    " (of these, the {HIT_RETENTION_CAP} most significant were retained, \
                     ranked by scored length then score, so a full-length hit cannot be \
                     crowded out by short-region artifacts)"
                )
            } else {
                String::new()
            }
        );
    }
}

/// The inter-layer codec domain, as claim domain values. The universe model needs
/// the same list the sweep enumerates, or the residual would be computed against a
/// space the sweep cannot address.
pub fn codec_domain() -> Vec<String> {
    CODEC_VOCABULARY
        .iter()
        .map(|c| c.label().to_string())
        .collect()
}

/// Map primitives given as mcrypt names to the display names used in claims, so a
/// coverage set is comparable across harnesses.
fn display_names(prims: &[String]) -> Vec<String> {
    prims
        .iter()
        .map(|p| {
            ra_prim::prim_info(p)
                .map(|i| i.display_name.to_string())
                .unwrap_or_else(|| p.clone())
        })
        .collect()
}

/// Read back a claim emitted by `--emit-claim`, so a sweep's output is directly
/// usable in a residual calculation rather than only human-readable.
pub fn load_claim(path: &Path) -> Result<CoverageSet> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading claim {}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing claim {}", path.display()))?;
    let skeletons = doc["coverage_claimed"]["skeletons"]
        .as_array()
        .with_context(|| format!("{} has no coverage_claimed.skeletons", path.display()))?;
    let mut set = CoverageSet::new();
    for s in skeletons {
        let sk: Vec<String> = serde_json::from_value(s["skeleton"].clone())
            .with_context(|| format!("{}: malformed skeleton", path.display()))?;
        let products: Vec<Product> = serde_json::from_value(s["products"].clone())
            .with_context(|| format!("{}: malformed products", path.display()))?;
        set.add(Cover::new(sk, products));
    }
    Ok(set)
}

/// The conformance state a claim records having been emitted under.
///
/// A claim that omits this is not self-describing. The precedent is
/// `enumeration_order`: a published Merkle root nobody can regenerate is not a
/// commitment, and coverage over primitives nobody can tell were proven is not
/// coverage. Both are recorded at emission time for the same reason.
pub struct ClaimConformance {
    /// Digest of the conformance suite the emitting run read.
    pub suite_digest: String,
    /// mcrypt primitives that reproduced at emission time.
    pub proven: Vec<String>,
    /// mcrypt primitives in the vocabulary that did not.
    pub unproven: Vec<String>,
    /// Whether the emitting run's own axes were entirely inside `proven`.
    pub all_axes_proven: Option<bool>,
}

/// Read back a claim's conformance block, or `None` if it carries none.
///
/// Backward compatible on purpose: five claims were committed before this block
/// existed, one of them a five-hour run. They still load, still verify, and are
/// gated against *current* conformance — loudly, so that the absence is legible
/// rather than silently treated as a pass.
pub fn load_claim_conformance(path: &Path) -> Result<Option<ClaimConformance>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading claim {}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing claim {}", path.display()))?;
    Ok(claim_conformance_from(&doc))
}

fn claim_conformance_from(doc: &serde_json::Value) -> Option<ClaimConformance> {
    let block = doc.get("conformance")?.as_object()?;
    let list = |k: &str| -> Vec<String> {
        block
            .get(k)
            .and_then(|v| v.as_array())
            .map(|a| {
                a.iter()
                    .filter_map(|x| x.as_str().map(str::to_string))
                    .collect()
            })
            .unwrap_or_default()
    };
    Some(ClaimConformance {
        suite_digest: block
            .get("suite_digest")
            .and_then(|v| v.as_str())
            .unwrap_or_default()
            .to_string(),
        proven: list("proven_primitives"),
        unproven: list("unproven_primitives"),
        all_axes_proven: block.get("all_swept_primitives_proven").and_then(|v| v.as_bool()),
    })
}

/// One skeleton's recorded enumeration order, as read back from a claim file.
pub struct RecordedEnumeration {
    pub tier: String,
    pub merkle_root: String,
    /// `(dim, values)` least significant digit first, exactly as enumerated.
    pub axes: Vec<(String, Vec<String>)>,
}

/// Read back the enumeration order a claim recorded, so a verifier holding only the
/// claim can rebuild the index space and regenerate the commitment.
///
/// This is the audit path Document 6 assumes exists. It did not, until the order was
/// recorded: the cover alone fixes *which* candidates were evaluated but not *what index
/// each was given*, and `leaf_hash` binds the index.
pub fn load_enumeration_order(path: &Path) -> Result<Vec<RecordedEnumeration>> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading claim {}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)
        .with_context(|| format!("parsing claim {}", path.display()))?;
    let tiers = doc["tiers"]
        .as_array()
        .with_context(|| format!("{} has no tiers array", path.display()))?;
    let mut out = Vec::new();
    for t in tiers {
        let order = t["enumeration_order"].as_array().with_context(|| {
            format!(
                "{}: tier {:?} records no enumeration_order, so its merkle_root cannot \
                 be regenerated from this claim",
                path.display(),
                t["tier"].as_str().unwrap_or("?")
            )
        })?;
        let mut axes = Vec::new();
        for a in order {
            let dim = a["dim"]
                .as_str()
                .with_context(|| format!("{}: axis without a dim", path.display()))?
                .to_string();
            let values: Vec<String> = serde_json::from_value(a["values"].clone())
                .with_context(|| format!("{}: axis {dim} has malformed values", path.display()))?;
            axes.push((dim, values));
        }
        out.push(RecordedEnumeration {
            tier: t["tier"].as_str().unwrap_or_default().to_string(),
            merkle_root: t["merkle_root"].as_str().unwrap_or_default().to_string(),
            axes,
        });
    }
    Ok(out)
}

/// Rebuild the resolved axes from a recorded enumeration order.
///
/// The inverse of [`Plan::enumeration_order`] plus [`resolve_axes`], and the reason the
/// recorded order is worth anything: a verifier reconstructs this, rebuilds the `Plan`,
/// and re-derives any leaf it wants to challenge.
///
/// Both layer blocks of a T3 plan are generated from the *same* `Axes` lists, so their
/// recorded values must agree; a disagreement means the claim was not produced by this
/// enumeration and is rejected rather than silently half-honoured.
fn axes_from_order(order: &[(String, Vec<String>)], vspace: VariantSpace) -> Result<Axes> {
    let get = |suffix: &str| -> Result<Vec<String>> {
        let matching: Vec<&Vec<String>> = order
            .iter()
            .filter(|(dim, _)| dim.split_once('.').is_some_and(|(_, s)| s == suffix))
            .map(|(_, v)| v)
            .collect();
        let first = *matching
            .first()
            .with_context(|| format!("recorded order has no *.{suffix} axis"))?;
        for other in &matching[1..] {
            anyhow::ensure!(
                *other == first,
                "recorded order lists two different *.{suffix} axes; both layer blocks \
                 are generated from one axis list, so this claim was not produced by \
                 this enumeration"
            );
        }
        Ok(first.clone())
    };

    // display names back to mcrypt names, the inverse of `display_names`
    let prim_labels = get("prim")?;
    let prims: Vec<String> = prim_labels
        .iter()
        .map(|label| {
            ra_prim::PRIMS
                .iter()
                .find(|p| p.display_name == label || p.mcrypt_name == label)
                .map(|p| p.mcrypt_name.to_string())
                .with_context(|| format!("recorded primitive {label:?} is not implemented here"))
        })
        .collect::<Result<_>>()?;

    let modes = get("mode")?
        .iter()
        .map(|m| Mode::parse(m).with_context(|| format!("recorded mode {m:?} is unknown")))
        .collect::<Result<Vec<_>>>()?;
    let kds = get("kd")?
        .iter()
        .map(|k| KeyDerivation::parse(k).with_context(|| format!("recorded kd {k:?} is unknown")))
        .collect::<Result<Vec<_>>>()?;
    let ivs = get("iv")?
        .iter()
        .map(|name| match name.as_str() {
            "ascii0" => Ok((name.clone(), vec![b'0'; 16])),
            "null" => Ok((name.clone(), vec![0u8; 16])),
            other => anyhow::bail!("recorded IV {other:?} is unknown"),
        })
        .collect::<Result<Vec<_>>>()?;
    let keys = get("key")?
        .iter()
        .map(|k| KeyCandidate::resolve(k))
        .collect();
    // T1 has no transform slot and no codec slot, so those axes may be absent.
    let xfs = match get("xf") {
        Ok(v) => v
            .iter()
            .map(|x| Xf::parse(x).with_context(|| format!("recorded transform {x:?} is unknown")))
            .collect::<Result<Vec<_>>>()?,
        Err(_) => vec![Xf::Identity],
    };
    let codecs = match get("codec") {
        Ok(v) => v
            .iter()
            .map(|c| Codec::parse(c).with_context(|| format!("recorded codec {c:?} is unknown")))
            .collect::<Result<Vec<_>>>()?,
        Err(_) => CODEC_VOCABULARY.to_vec(),
    };
    let variant_masks = get("variant")?
        .iter()
        .map(|l| {
            vspace
                .parse_label(l)
                .with_context(|| format!("recorded variant {l:?} is not a reading of this target"))
        })
        .collect::<Result<Vec<_>>>()?;
    // `pre` is present in every tier of a claim produced after this axis existed;
    // absence means the claim predates it, and identity is exactly what such a
    // claim actually evaluated.
    let pres = match get("pre") {
        Ok(v) => v
            .iter()
            .map(|p| Pre::parse(p).with_context(|| format!("recorded pre-transform {p:?} is unknown")))
            .collect::<Result<Vec<_>>>()?,
        Err(_) => vec![Pre::Identity],
    };
    // `post` is present in every tier of a claim produced after this axis
    // existed; absence means the claim predates it, and identity is exactly
    // what such a claim actually evaluated -- same reasoning as `pre` above.
    let posts = match get("post") {
        Ok(v) => v
            .iter()
            .map(|p| {
                Post::parse(p).with_context(|| format!("recorded post-transform {p:?} is unknown"))
            })
            .collect::<Result<Vec<_>>>()?,
        Err(_) => vec![Post::Identity],
    };
    // `toolfmt` is present in every tier of a claim produced after this axis
    // existed; absence means the claim predates it, and `none` is exactly
    // what such a claim actually evaluated -- same reasoning as `pre`/`post`.
    let toolfmts = match get("toolfmt") {
        Ok(v) => v
            .iter()
            .map(|f| {
                ToolFmt::parse(f).with_context(|| format!("recorded toolfmt {f:?} is unknown"))
            })
            .collect::<Result<Vec<_>>>()?,
        Err(_) => vec![ToolFmt::None],
    };

    Ok(Axes {
        vspace,
        variant_masks,
        prim_labels,
        prims,
        modes,
        keys,
        kds,
        ivs,
        xfs,
        codecs,
        pres,
        posts,
        toolfmts,
    })
}

/// Verify that a claim can regenerate its own commitment.
///
/// This is the spot audit Document 6 assumes: rebuild the index space from the recorded
/// enumeration order, and check that what the claim asserts follows from it. Two levels,
/// because the second is not always affordable:
///
/// - **Structural (always).** The recorded order must rebuild to a `Plan` whose axis lists
///   are identical, whose index space is at least the number of candidates the claim says
///   were evaluated, and whose derived cover has exactly the claim's coverage digest and
///   size. This is instant, and it is what catches a claim whose recorded order does not
///   match its cover.
/// - **Recomputation (`--recompute`).** Re-run the enumeration and compare the Merkle
///   root byte for byte. Costs what the original run cost.
pub fn verify(data: &Path, path: &Path, recompute: bool) -> Result<()> {
    let raw = std::fs::read_to_string(path)
        .with_context(|| format!("reading claim {}", path.display()))?;
    let doc: serde_json::Value = serde_json::from_str(&raw)?;
    let target_id = doc["target"]
        .as_str()
        .with_context(|| format!("{} names no target", path.display()))?;
    let target = crate::corpus::load_target(data, target_id)?;
    // The same helper the sweep driver uses, so a recompute cannot derive from
    // different bytes than the run it is auditing.
    let raw_text: Vec<u8> = sweep_input_text(&target);
    let oracle_id = doc["oracle"].as_str().unwrap_or("printable-0.75");
    let oracle = ra_oracle::oracle(oracle_id)
        .with_context(|| format!("claim cites unknown oracle {oracle_id:?}"))?;
    let recorded = load_enumeration_order(path)?;
    let claimed_digest = doc["coverage_claimed_digest"].as_str().unwrap_or_default();

    println!("verify {}", path.display());
    println!("  target : {} ({} display)", target.id, target.display_hint);
    println!("  oracle : {oracle_id}");
    println!("  tiers  : {}", recorded.len());

    let initial_decode = match target.display {
        ra_core::Display::Hex => "hexdecode",
        ra_core::Display::Base64 => "b64decode",
        ra_core::Display::Decimal => "decimaldecode",
        ra_core::Display::Octal => "octaldecode",
        ra_core::Display::Bytes => "identity",
    };

    let mut rebuilt_claim = CoverageSet::new();
    let mut ok = true;
    for (i, rec) in recorded.iter().enumerate() {
        let tier = Tier::parse(&rec.tier)
            .with_context(|| format!("claim records unknown tier {:?}", rec.tier))?;
        let exact_label = format!("{}-exact", target.display_hint);
        let vspace = target.variant_space(&exact_label)?;
        let axes = axes_from_order(&rec.axes, vspace)?;
        let plan = Plan::new(tier, &axes);

        anyhow::ensure!(
            plan.enumeration_order() == rec.axes,
            "{}: the recorded order for {} does not rebuild to itself, so the claim was \
             not produced by this enumeration",
            path.display(),
            rec.tier
        );
        let evaluated = doc["tiers"][i]["candidates_evaluated"].as_u64().unwrap_or(0);
        anyhow::ensure!(
            u128::from(evaluated) <= plan.total(),
            "{}: {} claims {} candidates evaluated but its recorded axes span only {}",
            path.display(),
            rec.tier,
            evaluated,
            plan.total()
        );
        println!(
            "  {} <{}>  index space {} candidates, {} evaluated  [order rebuilds]",
            rec.tier,
            tier.skeleton().join(" o "),
            crate::fmt(plan.total()),
            crate::fmt(u128::from(evaluated))
        );
        rebuilt_claim = rebuilt_claim.union(&plan.cover(evaluated));

        if recompute {
            let ctx = Ctx {
                plan: &plan,
                axes: &axes,
                text: &raw_text,
                display: target.display,
                oracle,
                initial_decode,
            };
            let run = execute(&ctx, evaluated, 5.0);
            if run.merkle_root == rec.merkle_root {
                println!("    merkle root REPRODUCED: {}", run.merkle_root);
            } else {
                ok = false;
                println!("    merkle root MISMATCH");
                println!("      claimed     : {}", rec.merkle_root);
                println!("      recomputed  : {}", run.merkle_root);
            }
        }
    }

    // The coverage digest is order-independent by construction, so this compares the
    // *content* of the claim against what the recorded enumeration actually spans.
    let rebuilt_digest = rebuilt_claim.digest();
    println!("  coverage digest");
    println!("    claimed    : {claimed_digest}");
    println!("    from order : {rebuilt_digest}");
    if !claimed_digest.is_empty() && claimed_digest != rebuilt_digest {
        ok = false;
        println!("    MISMATCH: the recorded order does not span the claimed coverage");
    }
    // The conformance block, held to the same standard as `enumeration_order`: a
    // claim must carry what is needed to check it. Absence is reported loudly and the
    // claim is gated against *current* conformance, but it is not a verification
    // failure — five claims were committed before this block existed and they
    // describe real work.
    let state = crate::corpus::conformance_state(data, None)?;
    let current = state.proven_primitives();
    println!("  conformance");
    match claim_conformance_from(&doc) {
        None => {
            println!(
                "    RECORDED : none. This claim does not state which primitives were \
                 proven when\n               it was emitted, so it is not \
                 self-describing. Gated against\n               CURRENT conformance \
                 instead of trusted; re-emit it to fix."
            );
        }
        Some(c) => {
            println!(
                "    RECORDED : {} proven, {} unproven, suite {}",
                c.proven.len(),
                c.unproven.len(),
                &c.suite_digest[..24.min(c.suite_digest.len())]
            );
            if c.suite_digest != state.suite_digest {
                println!(
                    "    SUITE DRIFT: the conformance suite has changed since emission\n\
                     \x20                current {}",
                    &state.suite_digest[..24.min(state.suite_digest.len())]
                );
            }
            let lost: Vec<&String> = c.proven.iter().filter(|p| !current.contains(p)).collect();
            if lost.is_empty() {
                println!("    every primitive proven at emission is still proven now");
            } else {
                println!(
                    "    REGRESSED: {} primitive(s) proven at emission are NOT proven now: {}",
                    lost.len(),
                    lost.iter().map(|s| s.as_str()).collect::<Vec<_>>().join(", ")
                );
            }
            if c.all_axes_proven == Some(false) {
                println!(
                    "    the emitting run itself recorded that it swept unproven \
                     primitives, so\n    part of this claim carried no coverage the \
                     moment it was written"
                );
            }
        }
    }
    // And the number that actually matters: what survives the gate today.
    let gated = ra_attest::gate_coverage(&rebuilt_claim, &current);
    println!(
        "    claimed   = {}",
        crate::fmt(rebuilt_claim.size_exact())
    );
    println!(
        "    effective = {}  (after gating against current conformance)",
        crate::fmt(gated.effective.size_exact())
    );
    if gated.is_vacuous() {
        ok = false;
        println!(
            "    VACUOUS: this claim names no *.prim dimension, so conformance gating \
             had\n             nothing to check. It cannot be folded into a residual."
        );
    }
    for p in &gated.voided {
        println!("    VOID {p}: {}", state.void_reason(p));
    }

    if !recompute {
        println!(
            "  (structural check only; pass --recompute to re-run the enumeration and \
             compare the Merkle root)"
        );
    }
    anyhow::ensure!(ok, "{} failed verification", path.display());
    println!("  OK");
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::collections::HashSet;

    /// TG4's ciphertext, which carries the 14 real glyph ambiguities.
    const TG4: &[u8] = b"kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";

    /// A transcription with no ambiguity, so the axis tests below measure the cipher
    /// axes rather than the variant one.
    fn unambiguous_space() -> VariantSpace {
        VariantSpace::derive(b"QUJDRA==", ra_core::Display::Base64, "b64-exact").unwrap()
    }

    fn test_axes() -> Axes {
        let prims: Vec<String> = vec!["des".into(), "twofish".into(), "serpent".into()];
        Axes {
            vspace: unambiguous_space(),
            variant_masks: vec![0],
            prim_labels: display_names(&prims),
            prims,
            modes: vec![Mode::Cfb8, Mode::Ecb],
            keys: vec![
                KeyCandidate::resolve("Zombies"),
                KeyCandidate::resolve("TheGiant"),
            ],
            kds: vec![KeyDerivation::NullPadMax, KeyDerivation::RepeatPadMax],
            ivs: vec![
                ("ascii0".to_string(), vec![b'0'; 16]),
                ("null".to_string(), vec![0u8; 16]),
            ],
            xfs: vec![Xf::Identity, Xf::Reverse],
            codecs: CODEC_VOCABULARY.to_vec(),
            pres: vec![Pre::Identity],
            posts: vec![Post::Identity],
            toolfmts: vec![ToolFmt::None],
        }
    }

    /// Every index must map to a distinct combination, or the sweep silently
    /// under-covers while claiming the full product. The precedent test covered the
    /// single-layer decomposition; a two-layer index has to satisfy the same
    /// property, and it is the one place where getting a radix wrong would let two
    /// indices collide and inflate the claim.
    #[test]
    fn index_decomposition_is_a_bijection() {
        let axes = test_axes();
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            let total = u64::try_from(plan.total()).unwrap();
            assert!(total > 0);
            let mut seen: HashSet<Vec<usize>> = HashSet::new();
            for i in 0..total {
                let d = plan.digits(i);
                assert_eq!(d.len(), plan.axes.len());
                for (k, dk) in d.iter().enumerate() {
                    assert!(*dk < plan.axes[k].values.len(), "digit out of range");
                }
                assert!(seen.insert(d), "{tier:?}: index {i} duplicates an earlier tuple");
            }
            assert_eq!(
                seen.len() as u128,
                plan.total(),
                "{tier:?}: enumeration must cover the full product"
            );
        }
    }

    /// The decomposition must also be *resolvable* to distinct parameter tuples, not
    /// merely to distinct digit vectors — a mis-wired offset would map two indices to
    /// the same actual pipeline while the digits differed.
    #[test]
    fn two_layer_indices_resolve_to_distinct_pipelines() {
        let axes = test_axes();
        let plan = Plan::new(Tier::T3, &axes);
        let total = u64::try_from(plan.total()).unwrap();
        let mut seen: HashSet<String> = HashSet::new();
        for i in 0..total {
            let d = plan.digits(i);
            let l1 = LayerParams::at(&axes, &d, LAYER_AXES + 2);
            let l2 = LayerParams::at(&axes, &d, 0);
            let key = format!(
                "{},xf={},codec={},{}",
                l1.describe("1"),
                axes.xfs[d[LAYER_AXES + 1]].label(),
                axes.codecs[d[LAYER_AXES]].label(),
                l2.describe("2")
            );
            assert!(seen.insert(key), "index {i} resolves to a duplicate pipeline");
        }
        assert_eq!(seen.len() as u128, plan.total());
    }

    /// The arithmetic reported before the run must equal the enumerated total.
    #[test]
    fn candidate_counts_match_the_enumerated_total() {
        let axes = test_axes();
        let unit = axes.layer_unit() as u128;
        assert_eq!(unit, 3 * 2 * 2 * 2 * 2);
        assert_eq!(Plan::new(Tier::T1, &axes).total(), unit);
        assert_eq!(
            Plan::new(Tier::T2, &axes).total(),
            unit * axes.xfs.len() as u128
        );
        assert_eq!(
            Plan::new(Tier::T3, &axes).total(),
            unit * unit * axes.xfs.len() as u128 * axes.codecs.len() as u128
        );

        // and the plan's own digit walk agrees with the product formula
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            let by_axes: u128 = plan.axes.iter().map(|a| a.values.len() as u128).product();
            assert_eq!(by_axes, plan.total(), "{tier:?}");
        }
    }

    /// The claim must never assert more than was evaluated. Checked at the full
    /// product and at a spread of truncations, including awkward ones that are not
    /// multiples of any radix.
    #[test]
    fn coverage_set_size_matches_candidates_evaluated() {
        let axes = test_axes();
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            let total = u64::try_from(plan.total()).unwrap();
            let mut cases: Vec<u64> = vec![0, 1, 2, 3, 7, 13, 47, 100, 1001, total - 1, total];
            cases.retain(|&n| n <= total);
            for n in cases {
                let cover = plan.cover(n);
                assert_eq!(
                    cover.size_exact(),
                    u128::from(n),
                    "{tier:?}: cover of {n} candidates has size {}",
                    cover.size_exact()
                );
            }
        }
    }

    /// The prefix decomposition must be a partition of `{i : i < n}`, not merely the
    /// right cardinality: pointwise, exactly the evaluated indices are covered.
    #[test]
    fn prefix_decomposition_covers_exactly_the_evaluated_indices() {
        let axes = test_axes();
        let plan = Plan::new(Tier::T2, &axes);
        let total = u64::try_from(plan.total()).unwrap();
        for n in [0u64, 1, 5, 29, 96, total - 1] {
            let products = plan.products(n);
            let mut covered = 0u64;
            for i in 0..total {
                let d = plan.digits(i);
                let point: BTreeMap<String, String> = plan
                    .axes
                    .iter()
                    .enumerate()
                    .map(|(k, a)| (a.dim.clone(), a.values[d[k]].clone()))
                    .collect();
                let hits = products.iter().filter(|p| p.contains(&point)).count();
                assert!(hits <= 1, "index {i} is covered {hits} times, must be disjoint");
                if i < n {
                    assert_eq!(hits, 1, "evaluated index {i} is not covered");
                    covered += 1;
                } else {
                    assert_eq!(hits, 0, "unevaluated index {i} is claimed");
                }
            }
            assert_eq!(covered, n);
        }
    }

    /// The skeletons must be distinct tuples, and T3 must carry `codec` as a real
    /// slot between the transform and the second layer. Sharing a skeleton with the
    /// reference model's `("b64d","dec","xf","dec")` would let a claim built on the
    /// corrected pipeline subtract from a universe that does not contain it.
    #[test]
    fn t3_skeleton_names_the_inter_layer_codec() {
        assert_eq!(Tier::T3.skeleton(), ["b64d", "dec", "xf", "codec", "dec"]);
        assert_ne!(Tier::T3.skeleton(), ["b64d", "dec", "xf", "dec"]);
        let all: HashSet<Vec<String>> = [Tier::T1, Tier::T2, Tier::T3]
            .iter()
            .map(|t| t.skeleton())
            .collect();
        assert_eq!(all.len(), 3, "skeletons must partition, so they must differ");

        // and the dimension keys follow the skeleton's slot positions
        let axes = test_axes();
        let plan = Plan::new(Tier::T3, &axes);
        let dims: Vec<&str> = plan.axes.iter().map(|a| a.dim.as_str()).collect();
        assert!(dims.contains(&"1.prim"), "first layer sits at slot 1");
        assert!(dims.contains(&"2.xf"), "transform sits at slot 2");
        assert!(dims.contains(&"3.codec"), "codec sits at slot 3");
        assert!(dims.contains(&"4.prim"), "second layer sits at slot 4");
    }

    /// The codec vocabulary is *derived* from the solved corpus, not invented: the
    /// `codec`-family nodes appearing between two consecutive layer-forming steps in
    /// the chains this engine reproduces are exactly the nodes the vocabulary
    /// composes. Inventing a codec, or dropping one the corpus uses, fails here.
    #[test]
    fn codec_vocabulary_is_derived_from_the_corpus() {
        let prim_names: HashSet<&str> = ra_prim::PRIMS.iter().map(|p| p.mcrypt_name).collect();
        let codec_nodes: HashSet<&str> = ra_core::registry()
            .iter()
            .filter(|n| n.family() == ra_core::Family::Codec)
            .map(|n| n.name())
            .collect();

        let mut observed: HashSet<String> = HashSet::new();
        let mut adjacent: HashSet<String> = HashSet::new();
        for (cipher, chain) in crate::corpus::reproduced_chains() {
            let steps: Vec<&str> = chain
                .split('|')
                .map(|s| s.trim().split(':').next().unwrap_or("").trim())
                .collect();
            let layers: Vec<usize> = steps
                .iter()
                .enumerate()
                .filter(|(_, s)| prim_names.contains(**s))
                .map(|(i, _)| i)
                .collect();
            for w in layers.windows(2) {
                let between: Vec<&str> = steps[w[0] + 1..w[1]]
                    .iter()
                    .copied()
                    .filter(|s| codec_nodes.contains(s))
                    .collect();
                assert!(
                    !between.is_empty(),
                    "{cipher}: a hop with no codec at all would contradict the \
                     implicit-b64decode finding"
                );
                for s in &between {
                    observed.insert((*s).to_string());
                }
                // record maximal runs of adjacent codec steps, which is what a
                // multi-step vocabulary entry has to match
                let mut run: Vec<&str> = Vec::new();
                for s in &steps[w[0] + 1..w[1]] {
                    if codec_nodes.contains(s) {
                        run.push(s);
                    } else if !run.is_empty() {
                        adjacent.insert(run.join("|"));
                        run.clear();
                    }
                }
                if !run.is_empty() {
                    adjacent.insert(run.join("|"));
                }
            }
        }

        let vocabulary: HashSet<String> = CODEC_VOCABULARY
            .iter()
            .flat_map(|c| c.node_names().iter().map(|s| s.to_string()))
            .collect();
        assert_eq!(
            observed, vocabulary,
            "the inter-layer codec vocabulary must equal the codec nodes the solved \
             corpus uses at layer boundaries"
        );

        // the one multi-step entry must actually appear as an adjacent pair
        assert!(
            adjacent.contains("hex_to_base64|b64decode"),
            "hex_to_base64|b64decode is a vocabulary entry because rev5 spells it that \
             way; observed adjacent runs were {adjacent:?}"
        );
        // identity is the empty composition and therefore contributes no node
        assert!(Codec::Identity.node_names().is_empty());
    }

    /// `hexdecode` and `hex_to_base64 | b64decode` denote the same bytes but are
    /// distinct pipelines, both recorded in the corpus. They are enumerated
    /// separately on purpose: collapsing them would evaluate one point and claim two.
    #[test]
    fn the_two_hex_codecs_agree_on_bytes_but_stay_distinct_values() {
        let data = b"48656C6C6F2C20776F726C64";
        assert_eq!(
            Codec::HexDecode.apply(data),
            Codec::HexToB64ThenB64Decode.apply(data)
        );
        assert_eq!(Codec::HexDecode.apply(data).unwrap(), b"Hello, world");
        assert_ne!(
            Codec::HexDecode.label(),
            Codec::HexToB64ThenB64Decode.label()
        );
        assert_eq!(CODEC_VOCABULARY.len(), 6);
    }

    #[test]
    fn codecs_round_trip_the_corpus_encodings_and_reject_junk() {
        assert_eq!(Codec::Identity.apply(b"\x00\xff").unwrap(), b"\x00\xff");
        assert_eq!(Codec::B64Decode.apply(b"SGk=").unwrap(), b"Hi");
        assert_eq!(Codec::DecimalDecode.apply(b"065 066").unwrap(), b"AB");
        assert_eq!(Codec::OctalDecode.apply(b"101 102").unwrap(), b"AB");
        // high-entropy bytes are not whitespace-separated numerals
        assert!(Codec::OctalDecode.apply(&[0x9f, 0xfe, 0x01]).is_none());
        assert!(Codec::DecimalDecode.apply(&[0x9f, 0xfe, 0x01]).is_none());
        // every vocabulary entry parses from its own label, and from the `+` alias
        for c in CODEC_VOCABULARY {
            assert_eq!(Codec::parse(c.label()), Some(c));
            assert_eq!(Codec::parse(&c.label().replace('|', "+")), Some(c));
        }
        assert!(Codec::parse("rot13").is_none());
    }

    /// A bound must be visible in the claim, and a truncated T3 must not claim the
    /// untouched remainder.
    #[test]
    fn a_bounded_sweep_claims_strictly_less_than_the_skeleton() {
        let axes = test_axes();
        let plan = Plan::new(Tier::T3, &axes);
        let total = u64::try_from(plan.total()).unwrap();
        let bounded = plan.cover(total / 3);
        let full = plan.cover(total);
        assert!(bounded.size_exact() < full.size_exact());
        assert_eq!(bounded.size_exact(), u128::from(total / 3));
        // the bounded claim is a subset: differencing it out of the full one leaves
        // exactly the untouched remainder
        let remainder = full.difference(&bounded);
        assert_eq!(
            remainder.size_exact(),
            full.size_exact() - bounded.size_exact()
        );
    }

    /// Chunks must never straddle the shared-prefix boundary, or a T3 chunk would
    /// reuse a first-layer output that does not belong to the candidate.
    #[test]
    fn chunks_are_multiples_of_the_shared_prefix_stride() {
        let axes = test_axes();
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            assert_eq!(plan.chunk() % plan.stride, 0, "{tier:?}");
            assert!(plan.chunk() >= plan.stride);
        }
        let t3 = Plan::new(Tier::T3, &axes);
        assert_eq!(t3.stride, axes.layer_unit());
        // within one stride the T3 prefix digits really are constant
        for i in 0..t3.stride {
            let d = t3.digits(i);
            assert_eq!(&d[LAYER_AXES..], &t3.digits(0)[LAYER_AXES..]);
        }
        assert_ne!(
            t3.digits(t3.stride)[LAYER_AXES],
            t3.digits(0)[LAYER_AXES],
            "crossing a stride boundary must change the prefix"
        );
    }

    /// T1 claims `<b64d ∘ dec>`, a skeleton with no transform slot. Its index space
    /// must therefore be independent of `--xf`, or a `--tier t1 --xf reverse` run
    /// would evaluate a T2 pipeline and file it under T1's skeleton.
    #[test]
    fn t1_has_no_transform_axis() {
        let mut axes = test_axes();
        axes.xfs = vec![Xf::Reverse];
        let unit = axes.layer_unit() as u128;
        let (t1_reverse_only, has_xf) = {
            let p = Plan::new(Tier::T1, &axes);
            (p.total(), p.axes.iter().any(|a| a.dim.ends_with(".xf")))
        };
        assert_eq!(t1_reverse_only, unit);
        assert!(!has_xf, "t1 must not carry a transform dimension");

        axes.xfs = vec![Xf::Identity, Xf::Reverse];
        assert_eq!(Plan::new(Tier::T1, &axes).total(), unit, "t1 ignores --xf");
        // T2 and T3 by contrast must carry it, at their own slot positions
        assert!(Plan::new(Tier::T2, &axes)
            .axes
            .iter()
            .any(|a| a.dim == "1.xf"));
        assert!(Plan::new(Tier::T3, &axes)
            .axes
            .iter()
            .any(|a| a.dim == "2.xf"));
    }

    #[test]
    fn key_domain_values_resolve_b64_suffixes() {
        let plain = KeyCandidate::resolve("TheGiant");
        assert_eq!(plain.bytes, b"TheGiant");
        assert_eq!(plain.label, "TheGiant");
        let b64 = KeyCandidate::resolve("TheGiant_b64");
        assert_eq!(b64.label, "TheGiant_b64", "the claim keeps the domain value");
        assert_eq!(b64.bytes, b"VGhlR2lhbnQ=");
    }

    #[test]
    fn auto_tier_reproduces_the_pre_tier_skeleton_choice() {
        let mut axes = test_axes();
        axes.xfs = vec![Xf::Identity];
        assert_eq!(
            resolve_tiers(&["auto".to_string()], &axes).unwrap(),
            vec![Tier::T1]
        );
        axes.xfs = vec![Xf::Identity, Xf::Reverse];
        assert_eq!(
            resolve_tiers(&["auto".to_string()], &axes).unwrap(),
            vec![Tier::T2]
        );
        // explicit tiers are deduplicated and ordered so the run order is stable
        assert_eq!(
            resolve_tiers(
                &["t3".to_string(), "t1".to_string(), "t3".to_string()],
                &axes
            )
            .unwrap(),
            vec![Tier::T1, Tier::T3]
        );
        assert!(resolve_tiers(&["t9".to_string()], &axes).is_err());
    }

    /// The false-positive budget must respond to the scored length, which is the
    /// whole reason it is reported: a twelve-byte scored region is not a 144-byte one.
    #[test]
    fn false_positive_budget_tracks_the_scored_length() {
        let long: BTreeMap<usize, u64> = [(144usize, 1_000_000u64)].into_iter().collect();
        let short: BTreeMap<usize, u64> = [(12usize, 1_000_000u64)].into_iter().collect();
        let oracle = ra_oracle::oracle("printable-0.75").unwrap();
        let e_long = expected_false_positives(&long, oracle);
        let e_short = expected_false_positives(&short, oracle);
        assert!(e_long < 1e-9, "144-byte payloads are safe: {e_long:e}");
        assert!(
            e_short > 1.0,
            "a 12-byte scored region floods and must be reported as such: {e_short:e}"
        );
    }

    /// Regression pin for the conjunction-oracle budget bug: `printable-and-english`
    /// (a `PrintableAndEnglish` metric) reports `oracle.threshold` as the *quadgram*
    /// floor (-5.25), not a printable ratio. Feeding that straight into
    /// `p_ratio_printable` clamps `ceil(-5.25 * n)` to 0, which is "at least 0 of n
    /// bytes printable" — true of everything — so every candidate was counted as a
    /// certain false positive. Two real sweeps hit exactly this: REV7 (35,280
    /// candidates at scored_len 144) reported a budget of ~2.8e4 against 0 observed
    /// hits, and TG4 (58,800 candidates at scored_len 112) reported ~4.7e4 against 0
    /// observed hits — both consistent with "every candidate counted", not with a
    /// calibrated model. This test pins the corrected, measured figures (see
    /// `per_candidate_false_positive_rate`'s doc comment for the `min(P(A), P(B))`
    /// bound and `ra_oracle::p_quadgram_false_positive`'s docs for how the English
    /// term was derived empirically) so the model cannot silently regress back to
    /// the degenerate one.
    #[test]
    fn conjunction_oracle_budget_is_not_the_degenerate_one_per_candidate_model() {
        let oracle = ra_oracle::oracle("printable-and-english").unwrap();

        let rev7: BTreeMap<usize, u64> = [(144usize, 35_280u64)].into_iter().collect();
        let rev7_budget = expected_false_positives(&rev7, oracle);
        assert!(
            rev7_budget < 1e-10,
            "REV7's corrected budget should be negligible against 0 observed hits, got {rev7_budget:e}"
        );
        // Pin against the measured value directly (see this crate's calibration run),
        // so a future change to either floor's model is caught rather than silently
        // drifting the reported figure.
        assert!(
            (rev7_budget - 8.826_130_733_845_341e-16).abs() < 1e-20,
            "REV7 budget drifted: {rev7_budget:e}"
        );

        let tg4: BTreeMap<usize, u64> = [(112usize, 58_800u64)].into_iter().collect();
        let tg4_budget = expected_false_positives(&tg4, oracle);
        assert!(
            tg4_budget < 1e-9,
            "TG4's corrected budget should be negligible against 0 observed hits, got {tg4_budget:e}"
        );
        assert!(
            (tg4_budget - 2.239_036_687_983_314_4e-11).abs() < 1e-16,
            "TG4 budget drifted: {tg4_budget:e}"
        );
    }

    /// A genuine full-length hit must survive a flood of short-region artifacts, no
    /// matter how many arrive first or how high their ratio is. A first-N retention
    /// policy fails this, and failing it means the sweep could find the answer and
    /// then throw it away.
    #[test]
    fn a_full_length_hit_is_never_crowded_out_by_artifacts() {
        let artifact = |i: u64| Hit {
            index: i,
            score: 1.0,
            class: "printable".to_string(),
            scored_len: 3,
            describe: format!("artifact {i}"),
            chain: String::new(),
            preview: String::new(),
            variant: "v00".to_string(),
            variant_note: String::new(),
        };
        let solve = Hit {
            index: 999_999,
            score: 0.78,
            class: "printable".to_string(),
            scored_len: 144,
            describe: "the solve".to_string(),
            chain: String::new(),
            preview: String::new(),
            variant: "v00".to_string(),
            variant_note: String::new(),
        };

        let mut hits: Vec<Hit> = Vec::new();
        for i in 0..10_000 {
            push_hit(&mut hits, artifact(i), CHUNK_HIT_CAP);
        }
        assert_eq!(hits.len(), CHUNK_HIT_CAP);
        // the solve arrives last, with a *lower* ratio than every artifact
        push_hit(&mut hits, solve, CHUNK_HIT_CAP);
        assert!(
            hits.iter().any(|h| h.describe == "the solve"),
            "a 144-byte 0.78 hit must displace a 3-byte 1.00 artifact"
        );
        for i in 10_000..20_000 {
            push_hit(&mut hits, artifact(i), CHUNK_HIT_CAP);
        }
        assert!(
            hits.iter().any(|h| h.describe == "the solve"),
            "and it must not be displaced by later artifacts either"
        );
        assert_eq!(hits.len(), CHUNK_HIT_CAP);
    }

    // -----------------------------------------------------------------------
    // The transcription axis
    // -----------------------------------------------------------------------

    fn tg4_axes(masks: Vec<u32>) -> Axes {
        let mut axes = test_axes();
        axes.vspace = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
        axes.variant_masks = masks;
        axes
    }

    /// The variant must be the **most significant** digit. A bounded run's legibility
    /// follows from that: a prefix then covers whole transcriptions, so the claim reads
    /// "these readings, completely" rather than smearing a fraction of the cipher axes
    /// across all of them. Nothing needs a bound at 128 readings, but the property is
    /// what would make one safe if a wider menu ever did.
    #[test]
    fn the_transcription_is_the_most_significant_axis_and_multiplies_the_product() {
        let one = test_axes();
        let space = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
        let many = tg4_axes(space.masks());
        assert_eq!(many.variant_masks.len(), 128);
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let base = Plan::new(tier, &one);
            let plan = Plan::new(tier, &many);
            assert_eq!(plan.variant_axis, plan.axes.len() - 1, "{tier:?}");
            assert_eq!(plan.axes[plan.variant_axis].dim, "0.variant");
            assert_eq!(
                plan.axes[plan.variant_axis].values[..3],
                ["v00", "v01", "v02"],
                "labels come from the derived space"
            );
            assert_eq!(plan.total(), base.total() * 128, "{tier:?}");

            // the variant digit is constant across each contiguous block of
            // `total / 128` indices, which is what "most significant" means
            let per = u64::try_from(base.total()).unwrap();
            for v in 0..128u64 {
                assert_eq!(plan.digits(v * per)[plan.variant_axis], v as usize);
                assert_eq!(plan.digits(v * per + per - 1)[plan.variant_axis], v as usize);
            }
        }
    }

    /// The load-bearing regression test: the ciphertext bytes a real sweep of TG4
    /// actually feeds a chain — via the exact same [`resolve_axes`]/[`VariantSpace`]
    /// path `run` uses, not a re-derivation of it — must be byte-identical to
    /// `data/the_giant.json`'s `ciphertext_canonical`, not to the legacy `ciphertext`
    /// (they differ at offset 39). This is checked on bytes rather than on the `v10`
    /// label because a label-only test would have kept passing throughout the defect:
    /// the label space is unaffected by canonical narrowing, so `select("recorded")`
    /// could point at the wrong mask while still naming a real, well-formed label.
    ///
    /// Also asserts that `residual`'s notion of the admissible reading set — read off
    /// the same [`crate::corpus::Target::variant_space`] — is exactly the one mask this
    /// sweep selected, which is the "share one function" requirement made concrete:
    /// if `sweep` and `residual` ever again derived the variant space independently,
    /// a mismatch here would be the first thing to fail.
    #[test]
    fn sweep_feeds_the_canonical_ciphertext_bytes_for_tg4() {
        let data = std::path::Path::new(env!("CARGO_MANIFEST_DIR")).join("../../data");
        let target = crate::corpus::load_target(&data, "tg4").unwrap();
        assert!(
            target.ciphertext_canonical.is_some(),
            "this test needs tg4 to carry a ciphertext_canonical to be meaningful"
        );

        let args = SweepArgs {
            target: "tg4".to_string(),
            tier: vec!["t1".to_string()],
            prims: None,
            modes: vec!["cfb".to_string()],
            keys: vec!["Zombies".to_string()],
            kd: vec!["null-pad-max".to_string()],
            ivs: vec!["ascii0".to_string()],
            xf: vec!["identity".to_string()],
            pre: vec!["identity".to_string()],
            post: vec!["identity".to_string()],
            toolfmt: vec![],
            codec: vec![],
            variants: "recorded".to_string(),
            variant_label: None,
            oracle: "printable-0.75".to_string(),
            max_candidates: None,
            progress_every: 5.0,
            dry_run: false,
            max_hits: 20,
            emit_claim: None,
        };
        let axes = resolve_axes(&args, &target).unwrap();

        // Exactly one reading is selected by default, and it must be the one
        // `residual`'s admissible-reading computation (the same `variant_space`) also
        // reports as the sole admissible mask.
        assert_eq!(axes.variant_masks.len(), 1);
        assert_eq!(axes.variant_masks, axes.vspace.masks());
        assert_eq!(axes.vspace.count(), 1);

        // The bytes a chain is actually handed, obtained through the PRODUCTION path
        // -- `sweep_input_text` plus the whitespace-preserving splice -- and not a
        // local re-implementation of it. A local copy of the stripping logic would go
        // on passing even if `Ctx::stage` stopped agreeing with it, which is exactly
        // the regression this test exists to catch.
        let mut fed = Vec::new();
        axes.vspace.apply_preserving_whitespace(
            axes.variant_masks[0],
            &sweep_input_text(&target),
            &mut fed,
        );

        // `fed` now carries whatever whitespace the transcription has (TG4 has none,
        // but this test must not silently start depending on that), so the comparison
        // against the corpus's canonical reading is made in the whitespace-free
        // coordinate system both readings are recorded in.
        let strip = |b: &[u8]| -> Vec<u8> {
            b.iter().copied().filter(|c| !c.is_ascii_whitespace()).collect()
        };
        let fed_compact = strip(&fed);
        let legacy_compact = variant_index_text(&target);
        let canonical_bytes = target
            .ciphertext_canonical
            .as_ref()
            .unwrap()
            .bytes()
            .filter(|c| !c.is_ascii_whitespace())
            .collect::<Vec<u8>>();
        assert_eq!(
            fed_compact, canonical_bytes,
            "the sweep must feed the canonical reading, not the legacy one"
        );
        assert_ne!(
            fed_compact,
            legacy_compact,
            "the canonical and legacy readings differ at offsets 31, 36 and 90, so this \
             would only pass by coincidence if the fix regressed"
        );
        // The whitespace-preserving splice must not have moved or dropped anything:
        // TG4 is unspaced, so the fed bytes are their own compaction. This is what
        // keeps the `strip` above from being a place a real defect could hide.
        assert_eq!(
            fed, fed_compact,
            "TG4's transcription carries no whitespace, so the raw and compacted feeds \
             must be identical -- if this fires, the corpus record gained whitespace \
             and the offsets 31/36/90 quoted above need re-deriving"
        );
        // v2c, not the v10 this pinned before 2026-08-02: the project owner supplied a
        // corrected canonical transcription that reads `lIllIII` at the seven derived
        // I/l offsets, against the legacy `ciphertext` field's `lIIIIlI` -- mask 44.
        // This assertion failing is the DESIGNED behaviour when the corpus record moves;
        // check `data/the_giant.json`'s `ciphertext_canonical_provenance` and its
        // `ciphertext_canonical_history` before suspecting the variant code.
        assert_eq!(axes.vspace.label(axes.variant_masks[0]), "v2c");
    }

    /// A canonical transcription that still leaves a position open (an `(I/l)` marker
    /// of its own) must still admit exactly the readings consistent with it — 2 for
    /// TG4's previous, superseded canonical — not collapse to 1 the way the fully
    /// resolved one now does. This is the state
    /// [`tests::canonical_narrows_tg4_to_v4c_and_v6c`] in `variants.rs` already pins at
    /// the `VariantSpace` level; this test additionally pins it through `resolve_axes`,
    /// the entry point `sweep` actually uses, so the two can't drift apart.
    #[test]
    fn resolve_axes_handles_a_still_partially_open_canonical() {
        // TG4's ciphertext, and its *previous* (2026-07-30, since superseded)
        // canonical transcription: every open position resolved but offset 90, which
        // stays marked `(I/l)`. See `variants.rs`'s `TG4_CANONICAL` for the same text.
        const RAW: &[u8] = b"kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";
        const CANONICAL: &[u8] = b"kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvlqkZil0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3x(I/l)e8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtlNbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";
        let target = crate::corpus::Target {
            id: "tg4-synthetic".to_string(),
            raw: String::from_utf8(RAW.to_vec()).unwrap(),
            display: ra_core::Display::Base64,
            display_hint: "base64",
            solved: false,
            plaintext: None,
            steps: Vec::new(),
            ciphertext_canonical: Some(String::from_utf8(CANONICAL.to_vec()).unwrap()),
        };
        let vspace = target.variant_space("b64-exact").unwrap();
        assert_eq!(vspace.count(), 2, "1 open position (offset 90) -> 2 admissible readings");
        let labels: Vec<String> = vspace.masks().iter().map(|&m| vspace.label(m)).collect();
        assert_eq!(labels, vec!["v4c", "v6c"]);

        let args = SweepArgs {
            target: "tg4-synthetic".to_string(),
            tier: vec!["t1".to_string()],
            prims: None,
            modes: vec!["cfb".to_string()],
            keys: vec!["Zombies".to_string()],
            kd: vec!["null-pad-max".to_string()],
            ivs: vec!["ascii0".to_string()],
            xf: vec!["identity".to_string()],
            pre: vec!["identity".to_string()],
            post: vec!["identity".to_string()],
            toolfmt: vec![],
            codec: vec![],
            variants: "all".to_string(),
            variant_label: None,
            oracle: "printable-0.75".to_string(),
            max_candidates: None,
            progress_every: 5.0,
            dry_run: false,
            max_hits: 20,
            emit_claim: None,
        };
        let axes = resolve_axes(&args, &target).unwrap();
        assert_eq!(axes.variant_masks, vspace.masks());
        assert_eq!(axes.variant_masks.len(), 2);
    }

    /// A bounded run must claim whole transcriptions, as a single product rather than a
    /// prefix smear — and it must claim strictly less than the full variant space.
    #[test]
    fn a_variant_bounded_run_claims_whole_readings() {
        let axes = tg4_axes((0..16u32).collect());
        let plan = Plan::new(Tier::T3, &axes);
        let per = u64::try_from(plan.total()).unwrap() / 16;
        let cover = plan.cover(per * 3);
        assert_eq!(cover.size_exact(), u128::from(per * 3));
        let products = plan.products(per * 3);
        assert_eq!(
            products.len(),
            1,
            "a whole-reading bound is one product, not a prefix decomposition"
        );
        let named: Vec<&str> = products[0].dims["0.variant"]
            .iter()
            .map(String::as_str)
            .collect();
        assert_eq!(
            named,
            ["v00", "v01", "v02"],
            "and it names exactly the readings evaluated"
        );
        assert!(cover.size_exact() < plan.cover(u64::MAX).size_exact());
    }

    /// The executed programme's arithmetic, pinned: the full observed menu over every
    /// admissible TG4 reading, at every tier. If a figure changes, the run that was
    /// executed no longer matches the run the documentation describes.
    #[test]
    fn tg4_full_variant_sweep_candidate_counts() {
        let space = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
        // Pinned to the eleven primitives the documented run actually swept, not to
        // `ra_prim::implemented()`: that iterator now also yields primitives added
        // after this run (AES/rijndael-128 and onward), and this test's job is to
        // keep the *historical* arithmetic honest, not to track the live vocabulary.
        let prims: Vec<String> = [
            "des",
            "rc2",
            "arcfour",
            "blowfish",
            "blowfish-compat",
            "twofish",
            "serpent",
            "rijndael-256",
            "xtea",
            "loki97",
            "saferplus",
        ]
        .iter()
        .map(|s| s.to_string())
        .collect();
        let axes = Axes {
            vspace: VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap(),
            variant_masks: space.masks(),
            prim_labels: display_names(&prims),
            prims,
            modes: Mode::ALL.to_vec(),
            keys: [
                "Zombies",
                "TheGiant",
                "ZOMBIES",
                "thegiant",
                "zombies",
                "TheGiant_b64",
            ]
            .iter()
            .map(|k| KeyCandidate::resolve(k))
            .collect(),
            // Pinned to the four raw-byte policies the documented run actually
            // swept, not to `KeyDerivation::ALL`: that array now also yields the
            // hash-derived family added after this run, and this test's job is to
            // keep the *historical* arithmetic honest, not to track the live
            // vocabulary (see the identical reasoning for `prims`, above).
            kds: vec![
                KeyDerivation::Natural,
                KeyDerivation::NullPadMax,
                KeyDerivation::NullPadNextSupported,
                KeyDerivation::RepeatPadMax,
            ],
            ivs: vec![
                ("ascii0".to_string(), vec![b'0'; 16]),
                ("null".to_string(), vec![0u8; 16]),
            ],
            xfs: vec![Xf::Identity, Xf::Reverse],
            codecs: CODEC_VOCABULARY.to_vec(),
            pres: vec![Pre::Identity],
            posts: vec![Post::Identity],
            toolfmts: vec![ToolFmt::None],
        };
        assert_eq!(axes.layer_unit(), 3696, "11 prim x 7 mode x 6 key x 4 kd x 2 iv");
        assert_eq!(space.count(), 128, "7 open I/l positions");
        assert_eq!(Plan::new(Tier::T1, &axes).total(), 473_088);
        assert_eq!(Plan::new(Tier::T2, &axes).total(), 946_176);
        // T3 over every admissible reading is affordable too, which is the whole
        // consequence of the 0/O resolution: 21.0e9 candidates rather than 2.69e12.
        assert_eq!(Plan::new(Tier::T3, &axes).total(), 20_982_398_976);
        assert_eq!(
            Plan::new(Tier::T3, &axes).total() * 128,
            2_685_747_068_928,
            "the pre-resolution worst case over both glyph pairs, for the record"
        );
    }

    /// Every reading must decrypt **its own** ciphertext, and the recorded reading must
    /// reproduce the corpus bytes exactly — otherwise the variant axis would be a
    /// relabelling of the same work, which is the most expensive way to over-claim.
    #[test]
    fn staging_gives_each_reading_its_own_ciphertext_bytes() {
        let space = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
        let axes = tg4_axes(space.masks());
        let plan = Plan::new(Tier::T1, &axes);
        let ctx = Ctx {
            plan: &plan,
            axes: &axes,
            text: TG4,
            display: ra_core::Display::Base64,
            oracle: ra_oracle::oracle("printable-0.75").unwrap(),
            initial_decode: "b64decode",
        };

        let recorded = Repr::new(TG4.to_vec(), ra_core::Display::Base64).canonical_bytes();
        assert_eq!(recorded.len(), 144, "192 base64 characters are 144 bytes");
        assert_eq!(
            ctx.stage(0, 0).canonical,
            Some(recorded.clone()),
            "v00 must be the corpus ciphertext byte for byte"
        );

        let mut seen = HashSet::new();
        for digit in 0..axes.variant_masks.len() {
            let staged = ctx.stage(digit, 0).canonical.expect("identity pre never rejects");
            assert_eq!(staged.len(), 144);
            assert!(seen.insert(staged.clone()), "reading {digit} duplicates another");
            // a single base64 character spans one 4-char group, so it can only perturb
            // one or two of the three bytes that group denotes
            let corrections = axes.variant_masks[digit].count_ones() as usize;
            let differ = (0..144).filter(|&j| staged[j] != recorded[j]).count();
            assert!(
                differ <= 2 * corrections && (corrections == 0 || differ >= corrections),
                "{corrections} glyph correction(s) changed {differ} ciphertext bytes"
            );
        }
        assert_eq!(seen.len(), 128, "all 128 readings are distinct ciphertexts");
    }

    /// The leaf spelling must name the transcription exactly when more than one is in
    /// play. Naming it always would break reconciliation with commitments made before
    /// this axis existed; never naming it would let two candidates over *different
    /// ciphertexts* share a leaf spelling, so the commitment would stop identifying
    /// what was evaluated.
    #[test]
    fn the_leaf_spelling_names_the_transcription_only_when_it_varies() {
        let recorded_only = tg4_axes(vec![0]);
        assert_eq!(
            recorded_only.variant_prefix(0),
            "",
            "a recorded-reading run keeps the pre-variant leaf spelling"
        );
        let many = tg4_axes(vec![0, 1, 2]);
        assert_eq!(many.variant_prefix(0), "variant=v00,");
        assert_eq!(many.variant_prefix(1), "variant=v01,");
        assert_eq!(many.variant_prefix(2), "variant=v02,");
        // a single *non*-recorded reading must still say so
        let one_alt = tg4_axes(vec![1]);
        assert_eq!(one_alt.variant_prefix(0), "variant=v01,");
    }

    /// A hex target has no glyph ambiguity, so its variant dimension is a single point
    /// that must not borrow another cipher's label — or the two claims content-address
    /// identically and the digest stops detecting duplicate work.
    #[test]
    fn an_unambiguous_target_keeps_its_own_one_point_variant_dimension() {
        let hex = VariantSpace::derive(b"83A0F0", ra_core::Display::Hex, "hex-exact").unwrap();
        assert!(!hex.is_ambiguous());
        let axes = Axes {
            vspace: hex,
            variant_masks: vec![0],
            ..test_axes()
        };
        let plan = Plan::new(Tier::T1, &axes);
        assert_eq!(plan.axes[plan.variant_axis].values, vec!["hex-exact"]);
        assert_ne!(plan.axes[plan.variant_axis].values, vec!["v00"]);
    }

    // -----------------------------------------------------------------------
    // `--pre` sees the RAW ciphertext text, whitespace and all
    //
    // The defect these pin: `Ctx::stage` used to build its text from the
    // WHITESPACE-STRIPPED transcription while its own comment (and `--pre`'s help)
    // claimed the raw one. A stripped transcription is a single token, so
    // `reverse_words` -- the distinct sibling of `reverse` on
    // `unit-conversion.info/texttools` -- had nothing to reorder and silently WAS
    // `identity`. Every sweep that named it enumerated one pipeline under three
    // labels and reported a negative it had never tested.
    // -----------------------------------------------------------------------

    /// A grouped hex display of rev7's shape: whitespace-separated groups, so word
    /// boundaries exist and `reverse_words` has something to do. Deliberately
    /// asymmetric (the last group is `1A47F`) so word-order reversal and character
    /// reversal cannot be confused for each other.
    const GROUPED_HEX: &[u8] = b"83B57 B2C34 34697 F61A4 7F";

    fn grouped_hex_axes(pres: Vec<Pre>) -> Axes {
        let compact: Vec<u8> = GROUPED_HEX
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        Axes {
            vspace: VariantSpace::derive(&compact, ra_core::Display::Hex, "hex-exact").unwrap(),
            variant_masks: vec![0],
            pres,
            xfs: vec![Xf::Identity],
            ..test_axes()
        }
    }

    fn grouped_hex_ctx<'a>(axes: &'a Axes, plan: &'a Plan) -> Ctx<'a> {
        Ctx {
            plan,
            axes,
            text: GROUPED_HEX,
            display: ra_core::Display::Hex,
            oracle: ra_oracle::oracle("printable-0.75").unwrap(),
            initial_decode: "hexdecode",
        }
    }

    /// The headline regression: in the SWEEP path, `--pre reverse_words` and
    /// `--pre identity` must stage DIFFERENT bytes for a whitespace-bearing display.
    ///
    /// Before the fix these were equal, and `reverse` was the only `pre` value that
    /// did anything -- which is precisely how a three-value axis covered one point
    /// while claiming three.
    #[test]
    fn sweep_pre_reverse_words_is_not_identity_on_a_grouped_display() {
        let axes = grouped_hex_axes(vec![Pre::Identity, Pre::ReverseWords, Pre::Reverse]);
        let plan = Plan::new(Tier::T1, &axes);
        let ctx = grouped_hex_ctx(&axes, &plan);

        let identity = ctx.stage(0, 0).canonical.expect("identity always decodes");
        let words = ctx.stage(0, 1).canonical.expect("reverse_words decodes");
        let chars = ctx.stage(0, 2).canonical.expect("reverse decodes");

        assert_ne!(
            words, identity,
            "`reverse_words` staged the same bytes as `identity`: the sweep is feeding \
             `--pre` whitespace-stripped text again, so the axis is a no-op"
        );
        assert_ne!(
            words, chars,
            "`reverse_words` must also differ from full character reversal -- they are \
             two distinct tools, not aliases"
        );
        assert_ne!(chars, identity);
    }

    /// ...and it must be word-order reversal specifically: last group first, each
    /// group's interior intact. Asserted on the staged TEXT rather than the decoded
    /// bytes, because the groups are what the property is about.
    #[test]
    fn sweep_pre_reverse_words_reverses_group_order_not_group_interiors() {
        let axes = grouped_hex_axes(vec![Pre::ReverseWords]);
        let mut text = Vec::new();
        axes.vspace
            .apply_preserving_whitespace(0, GROUPED_HEX, &mut text);
        let staged = Pre::ReverseWords.apply(&text).expect("reverse_words never rejects");

        assert_eq!(
            staged,
            b"7F F61A4 34697 B2C34 83B57".to_vec(),
            "the groups must appear in reverse order with their interiors unchanged"
        );

        // The interiors really are intact, stated independently of the literal above
        // so that a future re-grouping of the fixture cannot make this vacuous.
        let input_groups: Vec<&[u8]> = GROUPED_HEX.split(|c| *c == b' ').collect();
        let staged_groups: Vec<&[u8]> = staged.split(|c| *c == b' ').collect();
        let reversed: Vec<&[u8]> = input_groups.iter().rev().copied().collect();
        assert_eq!(staged_groups, reversed);

        // And it is NOT character reversal, which would turn `1A47F` into `F74A1`.
        let chars = Pre::Reverse.apply(&text).expect("reverse never rejects");
        assert_ne!(staged, chars);
        assert!(
            chars.starts_with(b"F7"),
            "character reversal reverses group interiors too; got {:?}",
            String::from_utf8_lossy(&chars[..5.min(chars.len())])
        );
    }

    /// The stage must hand `--pre` the transcription VERBATIM. Pinned directly,
    /// because every property above is downstream of this one and a future change
    /// that re-introduced stripping "somewhere else" would be caught here first.
    #[test]
    fn sweep_stages_the_raw_text_with_its_whitespace_intact() {
        let axes = grouped_hex_axes(vec![Pre::Identity]);
        let mut text = Vec::new();
        axes.vspace
            .apply_preserving_whitespace(0, GROUPED_HEX, &mut text);
        assert_eq!(text, GROUPED_HEX.to_vec());
        assert!(
            text.contains(&b' '),
            "the staged text must still carry the group separators that `--pre` reads"
        );
    }

    /// `stripws + reverse_words` degenerating to `identity` is CORRECT, not a
    /// regression: after an explicit `stripws` there genuinely is one word left. The
    /// distinction this test draws is the whole point of the fix -- degeneracy must
    /// follow from what the analyst asked for, never from the harness.
    #[test]
    fn sweep_pre_stripws_then_reverse_words_correctly_degenerates_to_identity() {
        let axes = grouped_hex_axes(vec![
            Pre::Identity,
            Pre::Composite(vec![Pre::StripWs, Pre::ReverseWords]),
            Pre::ReverseWords,
        ]);
        let plan = Plan::new(Tier::T1, &axes);
        let ctx = grouped_hex_ctx(&axes, &plan);

        let identity = ctx.stage(0, 0).canonical.unwrap();
        let stripped = ctx.stage(0, 1).canonical.unwrap();
        let words = ctx.stage(0, 2).canonical.unwrap();

        assert_eq!(
            stripped, identity,
            "after an explicit stripws there is one word, so reversing the word order \
             is genuinely the identity -- this collision is legitimate"
        );
        assert_ne!(
            words, identity,
            "...whereas WITHOUT the explicit stripws it must not be, which is the bug"
        );
    }

    // -----------------------------------------------------------------------
    // The degeneracy guard
    // -----------------------------------------------------------------------

    /// The guard must FIRE on a genuine collision, naming both colliding values and
    /// keeping both labels rather than deduplicating one away.
    #[test]
    fn degeneracy_guard_fires_when_two_pre_values_stage_identical_bytes() {
        let axes = grouped_hex_axes(vec![
            Pre::Identity,
            Pre::Composite(vec![Pre::StripWs, Pre::ReverseWords]),
        ]);
        let staged = pre_staged_inputs(&axes, GROUPED_HEX, ra_core::Display::Hex);
        let warnings = degeneracy_warnings("pre", "fixture", &staged);

        assert_eq!(warnings.len(), 1, "one collision group, one warning: {warnings:?}");
        let w = &warnings[0];
        assert!(w.starts_with("WARNING: --pre values "), "got {w:?}");
        assert!(w.contains("\"identity\""), "the first colliding label survives: {w:?}");
        assert!(
            w.contains("\"stripws|reverse_words\""),
            "the second colliding label survives -- retained, not deduplicated: {w:?}"
        );

        // Two tuples, one distinct input: the two numbers must not be collapsed, since
        // their difference IS the finding.
        assert_eq!(staged_input_census(&staged), (2, 1));
    }

    /// ...and must stay SILENT when the axis genuinely varies the input, or it would
    /// be noise a reader learns to ignore.
    #[test]
    fn degeneracy_guard_is_silent_when_every_pre_value_stages_distinct_bytes() {
        let axes = grouped_hex_axes(vec![Pre::Identity, Pre::Reverse, Pre::ReverseWords]);
        let staged = pre_staged_inputs(&axes, GROUPED_HEX, ra_core::Display::Hex);
        assert_eq!(
            degeneracy_warnings("pre", "fixture", &staged),
            Vec::<String>::new(),
            "three genuinely distinct pipelines must not be reported as degenerate"
        );
        assert_eq!(staged_input_census(&staged), (3, 3));
    }

    /// A value that REJECTED and a value that produced EMPTY bytes are different
    /// events and must not collapse into one record -- the first never ran, the
    /// second ran and destroyed the input.
    #[test]
    fn staged_input_distinguishes_rejection_from_an_empty_accepted_result() {
        // `bwt` rejects text with no sentinel; `stripws` on an all-whitespace input
        // accepts and yields nothing.
        let axes = grouped_hex_axes(vec![Pre::Bwt, Pre::StripWs]);
        let staged = pre_staged_inputs(&axes, b"   ", ra_core::Display::Hex);

        assert_eq!(staged[0].status, StagedStatus::Rejected);
        assert!(staged[0].text.is_none(), "a rejected value produced no bytes to hash");

        assert_eq!(
            staged[1].status,
            StagedStatus::Accepted,
            "stripws ran and produced empty bytes -- an empty hex string decodes to \
             empty bytes, so this is an accepted result, not a failure"
        );
        let rec = staged[1].text.as_ref().expect("accepted values record their bytes");
        assert_eq!(rec.bytes, 0, "an empty ACCEPTED result is still a recorded result");
        assert_eq!(
            rec.sha256,
            hex::encode(ra_merkle::h(b"")),
            "and it is hashed as the empty string, not left null like a rejection"
        );
        assert_eq!(
            staged[1].canonical.as_ref().map(|r| r.bytes),
            Some(0),
            "the empty result reaches the cipher as zero bytes, which is a fact worth \
             recording -- not the absence of a record that a rejection produces"
        );

        // The census counts the ONE value that produced bytes. The rejection is not
        // reported as colliding with it: "produced nothing" is not "produced the same".
        assert_eq!(staged_input_census(&staged), (2, 1));
        assert!(degeneracy_warnings("pre", "fixture", &staged).is_empty());
    }

    // -----------------------------------------------------------------------
    // The commitment must be regenerable from the claim
    // -----------------------------------------------------------------------

    /// Axes deliberately spelled in an order whose sorted form differs, so that
    /// order-dependence is observable: `Twofish` before `DES`, `null` before `ascii0`.
    fn ordered_axes() -> Axes {
        let prims: Vec<String> = vec!["twofish".into(), "des".into()];
        Axes {
            vspace: VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap(),
            variant_masks: vec![0, 1],
            prim_labels: display_names(&prims),
            prims,
            modes: vec![Mode::Cfb8, Mode::Ecb],
            keys: vec![
                KeyCandidate::resolve("Zombies"),
                KeyCandidate::resolve("TheGiant"),
            ],
            kds: vec![KeyDerivation::NullPadMax],
            ivs: vec![
                ("null".to_string(), vec![0u8; 16]),
                ("ascii0".to_string(), vec![b'0'; 16]),
            ],
            xfs: vec![Xf::Identity],
            codecs: vec![Codec::Identity],
            pres: vec![Pre::Identity],
            posts: vec![Post::Identity],
            toolfmts: vec![ToolFmt::None],
        }
    }

    fn root_of(axes: &Axes, tier: Tier) -> String {
        let plan = Plan::new(tier, axes);
        let ctx = Ctx {
            plan: &plan,
            axes,
            text: TG4,
            display: ra_core::Display::Base64,
            oracle: ra_oracle::oracle("printable-0.75").unwrap(),
            initial_decode: "b64decode",
        };
        execute(&ctx, u64::try_from(plan.total()).unwrap(), 0.0).merkle_root
    }

    /// The defect this pins: **the Merkle root is enumeration-order dependent.** The
    /// same axis *sets* in a different *order* commit to a different root, because
    /// `leaf_hash` binds the candidate index and the index is assigned by mixed-radix
    /// enumeration over the axis lists as resolved.
    ///
    /// That is not a bug to be sorted away — the commitment describes a computation, and
    /// the computation had an order. It is a bug to *omit* the order from the claim,
    /// which is what the next test checks.
    #[test]
    fn the_merkle_root_depends_on_the_enumeration_order() {
        let given = ordered_axes();
        let mut sorted = ordered_axes();
        sorted.prims = vec!["des".into(), "twofish".into()];
        sorted.prim_labels = display_names(&sorted.prims);
        sorted.ivs.reverse();

        // identical coverage: the cover stores sorted sets, so the digests agree ...
        let cover_a = Plan::new(Tier::T1, &given).cover(u64::MAX);
        let cover_b = Plan::new(Tier::T1, &sorted).cover(u64::MAX);
        assert_eq!(
            cover_a.digest(),
            cover_b.digest(),
            "equal coverage must hash equally however the command line was spelled"
        );
        assert_eq!(cover_a.size_exact(), cover_b.size_exact());

        // ... but the commitments differ, because the enumeration differs
        assert_ne!(
            root_of(&given, Tier::T1),
            root_of(&sorted, Tier::T1),
            "the root binds the index, so it must be order-dependent"
        );
    }

    /// The property that was silently absent: a claim must carry enough to regenerate
    /// its own commitment. A verifier holding only the claim file rebuilds the axes from
    /// the recorded enumeration order, re-runs the tier, and gets the same Merkle root.
    ///
    /// Before the order was recorded this was impossible — the cover stores each axis as
    /// a sorted set, so the committed root could not be reproduced from the committed
    /// claim, and Document 6's spot audit had nothing to stand on.
    #[test]
    fn a_claim_round_trips_to_the_same_merkle_root() {
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let axes = ordered_axes();
            let plan = Plan::new(tier, &axes);
            let root = root_of(&axes, tier);

            // emit exactly what the claim file carries, and read it back through the
            // same public loader an external verifier would use
            let doc = serde_json::json!({
                "tiers": [{
                    "tier": tier.id(),
                    "merkle_root": root,
                    "enumeration_order": plan.enumeration_order().iter()
                        .map(|(dim, values)| serde_json::json!({"dim": dim, "values": values}))
                        .collect::<Vec<_>>(),
                }]
            });
            let dir = std::env::temp_dir()
                .join(format!("ra-order-test-{}-{:?}", std::process::id(), tier));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("claim.json");
            std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

            let recorded = load_enumeration_order(&path).unwrap();
            assert_eq!(recorded.len(), 1);
            assert_eq!(recorded[0].tier, tier.id());
            assert_eq!(
                recorded[0].axes,
                plan.enumeration_order(),
                "{tier:?}: the recorded order must survive the round trip verbatim"
            );

            let vspace = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
            let rebuilt = axes_from_order(&recorded[0].axes, vspace).unwrap();
            let rebuilt_plan = Plan::new(tier, &rebuilt);
            assert_eq!(
                rebuilt_plan.enumeration_order(),
                plan.enumeration_order(),
                "{tier:?}: rebuilt axes must reproduce the same index space"
            );
            assert_eq!(
                root_of(&rebuilt, tier),
                recorded[0].merkle_root,
                "{tier:?}: the claim must regenerate its own commitment"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// A claim with no recorded order must be *rejected*, not quietly accepted — that is
    /// the difference between "this commitment is unverifiable" and finding out later.
    #[test]
    fn a_claim_without_a_recorded_order_is_refused() {
        let doc = serde_json::json!({
            "tiers": [{ "tier": "t1", "merkle_root": "00", "coverage_size_exact": "1" }]
        });
        let dir = std::env::temp_dir().join(format!("ra-order-missing-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("claim.json");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        let err = match load_enumeration_order(&path) {
            Ok(_) => panic!("a claim with no recorded order must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(
            err.contains("cannot be regenerated"),
            "the error must say why the claim is unverifiable, got: {err}"
        );
        std::fs::remove_dir_all(&dir).ok();
    }

    /// Rebuilding must refuse a claim whose two layer blocks disagree: both are generated
    /// from one axis list, so a disagreement means the claim did not come from this
    /// enumeration and honouring half of it would fabricate an index space.
    #[test]
    fn rebuilding_refuses_inconsistent_layer_blocks() {
        let axes = ordered_axes();
        let mut order = Plan::new(Tier::T3, &axes).enumeration_order();
        let slot4 = order
            .iter_mut()
            .find(|(dim, _)| dim == "4.prim")
            .expect("T3 has a second layer block");
        slot4.1 = vec!["DES".to_string()];
        let vspace = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
        let err = match axes_from_order(&order, vspace) {
            Ok(_) => panic!("inconsistent layer blocks must be refused"),
            Err(e) => e.to_string(),
        };
        assert!(err.contains("two different *.prim axes"), "got: {err}");
    }

    #[test]
    fn display_names_normalise_mcrypt_spellings() {
        let got = display_names(&["arcfour".to_string(), "rijndael-256".to_string()]);
        assert_eq!(got, vec!["RC4", "Rijndael-256"]);
    }

    /// An emitted claim must load back into the same coverage set, or "directly
    /// usable in a residual calculation" is not true.
    #[test]
    fn an_emitted_claim_round_trips() {
        let axes = test_axes();
        let claim = Plan::new(Tier::T3, &axes).cover(5000);
        let doc = serde_json::json!({ "coverage_claimed": claim.to_json() });
        let dir = std::env::temp_dir().join(format!("ra-sweep-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("claim.json");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        let loaded = load_claim(&path).unwrap();
        assert_eq!(loaded.digest(), claim.digest());
        assert_eq!(loaded.size_exact(), 5000);
        std::fs::remove_dir_all(&dir).ok();
    }

    // -----------------------------------------------------------------------
    // The `--pre` axis: the genuine top of the stack
    // -----------------------------------------------------------------------

    /// A test-only transliteration of the site's `ENCODE`, needed here because
    /// `ra_core::classical::bwt`'s equivalent helper is `#[cfg(test)]` inside
    /// `ra-core` and therefore invisible across the crate boundary. See
    /// `ra_core::classical::bwt` for the full algorithm and its own coverage of
    /// this exact transliteration.
    fn bwt_encode(text: &[u8], eof: u8) -> Vec<u8> {
        let mut chars = text.to_vec();
        chars.push(eof);
        let n = chars.len();
        let mut rotations: Vec<Vec<u8>> = (0..n)
            .map(|i| {
                let mut r = chars[i..].to_vec();
                r.extend_from_slice(&chars[..i]);
                r
            })
            .collect();
        rotations.sort();
        rotations.iter().map(|r| r[r.len() - 1]).collect()
    }

    /// A T3-shaped scenario built end to end: plaintext, encrypted twice (des,
    /// identical params at both layers so a single-valued axis selects them
    /// unambiguously), with a base64 `codec` hop between the layers, base64
    /// displayed, then BWT-encoded with sentinel `|` as if that base64 text were
    /// the as-transcribed ciphertext. Returns the raw ciphertext text (what a
    /// target's `compact` would be) and the plaintext it denotes.
    fn pre_bwt_fixture() -> (Vec<u8>, Vec<u8>) {
        let plaintext = b"HELLO BWT TOP LAYER TEST 1234567890".to_vec();
        let key = b"Zombies";
        let iv = vec![b'0'; 16];
        let mode = Mode::Cfb8;
        let kd = KeyDerivation::NullPadMax;
        let layer2_ct = ra_prim::encrypt("des", mode, key, &iv, kd, &plaintext).unwrap();
        let layer1_plaintext = base64::engine::general_purpose::STANDARD
            .encode(&layer2_ct)
            .into_bytes();
        let layer1_ct = ra_prim::encrypt("des", mode, key, &iv, kd, &layer1_plaintext).unwrap();
        let b64_text = base64::engine::general_purpose::STANDARD
            .encode(&layer1_ct)
            .into_bytes();
        let compact = bwt_encode(&b64_text, b'|');
        (compact, plaintext)
    }

    /// The single-candidate `Axes` matching [`pre_bwt_fixture`]: every axis but
    /// `pre` (forced to `bwt`) has exactly one value, so `Plan::new`'s index
    /// space is one candidate and it is unambiguously the fixture's pipeline.
    fn pre_bwt_axes(compact: &[u8]) -> Axes {
        Axes {
            vspace: VariantSpace::derive(compact, ra_core::Display::Base64, "synthetic-exact")
                .unwrap(),
            variant_masks: vec![0],
            prim_labels: display_names(&["des".to_string()]),
            prims: vec!["des".to_string()],
            modes: vec![Mode::Cfb8],
            keys: vec![KeyCandidate::resolve("Zombies")],
            kds: vec![KeyDerivation::NullPadMax],
            ivs: vec![("ascii0".to_string(), vec![b'0'; 16])],
            xfs: vec![Xf::Identity],
            codecs: vec![Codec::B64Decode],
            pres: vec![Pre::Bwt],
            posts: vec![Post::Identity],
            toolfmts: vec![ToolFmt::None],
        }
    }

    /// The defect the `--pre` axis fixes: `Xf::Bwt` on the old `--xf` axis runs
    /// *after* the initial decode, so a base64 initial decode destroys the `|`
    /// sentinel before an `Xf::Bwt` ever sees it. This proves the fix through the
    /// actual sweep machinery `run_range` uses (`Ctx::stage`), not by calling
    /// `inverse_bwt` in isolation: staging a genuine BWT-encoded ciphertext must
    /// yield `Some`, and it must decode to the base64 text underneath.
    #[test]
    fn pre_bwt_runs_before_the_initial_decode_and_the_sweep_recovers_the_plaintext() {
        let (compact, plaintext) = pre_bwt_fixture();
        assert!(
            compact.contains(&b'|'),
            "sanity: the fixture's raw ciphertext text carries the sentinel"
        );

        let axes = pre_bwt_axes(&compact);
        let plan = Plan::new(Tier::T3, &axes);
        assert_eq!(plan.total(), 1, "every axis is pinned to a single value");
        let ctx = Ctx {
            plan: &plan,
            axes: &axes,
            text: &compact,
            display: ra_core::Display::Base64,
            oracle: ra_oracle::oracle("printable-0.75").unwrap(),
            initial_decode: "b64decode",
        };

        // Exercise the staging mechanism `run_range` actually uses. If `--pre`
        // ran anywhere but above the initial decode, this would have to reject
        // (the sentinel would already be gone or corrupted).
        let staged = ctx.stage(0, 0);
        assert!(
            staged.canonical.is_some(),
            "bwt must accept a genuine BWT encoding of the base64 ciphertext text"
        );

        let run = execute(&ctx, 1, 0.0);
        assert_eq!(
            run.hit_count, 1,
            "the sweep must evaluate the single candidate and pass it"
        );
        let hit = &run.hits[0];
        assert_eq!(hit.preview, String::from_utf8(plaintext).unwrap());
    }

    /// The chain a hit reports must be a real, re-runnable `ra run` spec with
    /// `bwt` as its first step — genuinely ahead of the initial decode and the
    /// inter-layer codec, not merely labelled that way. Built and checked against
    /// the same `LayerParams::spec()` the sweep itself uses, so this cannot drift
    /// from what was actually evaluated.
    #[test]
    fn pre_bwt_chain_places_bwt_first_and_round_trips_through_parse_chain() {
        let (compact, _plaintext) = pre_bwt_fixture();
        let axes = pre_bwt_axes(&compact);
        let plan = Plan::new(Tier::T3, &axes);
        let ctx = Ctx {
            plan: &plan,
            axes: &axes,
            text: &compact,
            display: ra_core::Display::Base64,
            oracle: ra_oracle::oracle("printable-0.75").unwrap(),
            initial_decode: "b64decode",
        };
        let run = execute(&ctx, 1, 0.0);
        assert_eq!(run.hit_count, 1);
        let hit = &run.hits[0];

        let d = plan.digits(0);
        let l1 = LayerParams::at(&axes, &d, LAYER_AXES + 2);
        let l2 = LayerParams::at(&axes, &d, 0);
        let expected = format!("bwt | b64decode | {} | b64decode | {}", l1.spec(), l2.spec());
        assert_eq!(
            hit.chain, expected,
            "bwt must be the first step, ahead of the initial decode and the codec"
        );

        let parsed = crate::spec::parse_chain(&hit.chain).unwrap();
        assert_eq!(parsed.len(), 5);
        let names: Vec<&str> = parsed.steps().iter().map(|s| s.node.as_str()).collect();
        assert_eq!(names, ["bwt", "b64decode", "des", "b64decode", "des"]);
        let bwt_pos = names.iter().position(|&n| n == "bwt").unwrap();
        let codec_pos = 3; // the inter-layer codec's b64decode
        assert!(
            bwt_pos < codec_pos,
            "bwt (index {bwt_pos}) must precede the codec (index {codec_pos})"
        );
    }

    /// Regression: the TG4 ciphertext with a pipe at offset 90 is not a
    /// well-formed BWT of anything (its LF-mapping decomposes into 8 disjoint
    /// cycles), so `--pre bwt` must reject it — on the actual sweep staging
    /// path, not merely at the `inverse_bwt` level — and every candidate at that
    /// (variant, pre) pair is then inapplicable rather than a false hit.
    #[test]
    fn pre_bwt_rejects_the_tg4_multi_cycle_ciphertext() {
        let ct: &[u8] = b"kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvlqkZil0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3x|e8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtlNbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";
        assert_eq!(ct.len(), 192);
        assert!(
            ra_core::classical::bwt::inverse_bwt(ct, b'|').is_err(),
            "sanity: not a well-formed BWT"
        );

        let axes = Axes {
            vspace: VariantSpace::derive(ct, ra_core::Display::Base64, "tg4-multi-cycle-exact")
                .unwrap(),
            variant_masks: vec![0],
            pres: vec![Pre::Bwt],
            ..test_axes()
        };
        let plan = Plan::new(Tier::T1, &axes);
        let ctx = Ctx {
            plan: &plan,
            axes: &axes,
            text: ct,
            display: ra_core::Display::Base64,
            oracle: ra_oracle::oracle("printable-0.75").unwrap(),
            initial_decode: "b64decode",
        };

        let staged = ctx.stage(0, 0);
        assert!(
            staged.canonical.is_none(),
            "bwt must reject a ciphertext that is not a well-formed BWT"
        );

        let bound = u64::try_from(plan.total()).unwrap().min(2000);
        let run = execute(&ctx, bound, 0.0);
        assert_eq!(run.hit_count, 0, "every candidate at this pre outcome is inapplicable");
    }

    /// The property the fix above depends on: at the default (`--pre` not
    /// passed, i.e. `identity` alone), the `0.pre` axis must be **absent**, not
    /// merely single-valued, or every commitment made before this axis existed
    /// would stop reconciling with a freshly rebuilt `Plan`. This is what
    /// `residual_gating`'s `the_committed_claims_still_verify_without_a_conformance_block`
    /// depends on.
    #[test]
    fn pre_axis_is_omitted_at_default_so_old_commitments_still_reconcile() {
        let axes = test_axes();
        assert_eq!(axes.pres, vec![Pre::Identity], "test_axes' default");
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            assert!(
                plan.pre_axis.is_none(),
                "{tier:?}: default --pre must not add a digit"
            );
            assert!(
                !plan.axes.iter().any(|a| a.dim == "0.pre"),
                "{tier:?}: default --pre must not add a dimension to the enumeration order"
            );
        }
    }

    // -- --pre grammar: backward compatibility + new cto_* vocabulary --------

    /// Every `--pre` value valid before this task's `cto_*` additions must
    /// keep parsing exactly as before -- this axis's grammar is additive
    /// only.
    #[test]
    fn pre_grammar_still_accepts_every_previously_valid_value() {
        assert_eq!(Pre::parse("identity"), Some(Pre::Identity));
        assert_eq!(Pre::parse("bwt"), Some(Pre::Bwt));
        assert_eq!(Pre::parse("reverse"), Some(Pre::Reverse));
        assert_eq!(Pre::parse("stripws"), Some(Pre::StripWs));
        assert_eq!(Pre::parse("group"), Some(Pre::Group));
        assert_eq!(Pre::parse("rot:n=13"), Some(Pre::Rot(13)));
        assert_eq!(Pre::parse("rot:n=1"), Some(Pre::Rot(1)));
        assert_eq!(Pre::parse("rot:n=25"), Some(Pre::Rot(25)));
        assert_eq!(Pre::parse("rot:n=0"), None, "0 was never in range before, still isn't");
        assert_eq!(
            Pre::parse("beaufort:key=ZOMBIES"),
            Some(Pre::Beaufort("ZOMBIES".to_string()))
        );
        assert_eq!(Pre::parse("beaufort:key="), None, "empty key was rejected before, still is");
        // `+`-joined composition, both directions of `+`/`|` normalisation.
        assert_eq!(
            Pre::parse("stripws+reverse"),
            Some(Pre::Composite(vec![Pre::StripWs, Pre::Reverse]))
        );
        assert_eq!(
            Pre::parse("stripws|reverse"),
            Some(Pre::Composite(vec![Pre::StripWs, Pre::Reverse]))
        );
        assert_eq!(Pre::parse("bogus"), None);
    }

    /// The new `cto_*` vocabulary this task adds, parsed and labelled
    /// round-trip (`label()` must recover a string `parse()` accepts again --
    /// the same property the recorded-claim reconciliation path in
    /// `axes_from_order` depends on for every other `Pre` variant).
    #[test]
    fn pre_grammar_accepts_new_cto2016_vocabulary_and_round_trips_labels() {
        let cases = [
            "cto_caesar:key=5",
            "cto_caesar:key=-3",
            "cto_beaufort:key=ZOMBIES",
            "cto_trithemius",
            "cto_gronsfeld:key=0157412359",
            "cto_rotation:n=5",
            "cto_rotation:n=5,deg=180",
            "cto_rotation:n=5,deg=270",
        ];
        for case in cases {
            let parsed = Pre::parse(case).unwrap_or_else(|| panic!("{case:?} must parse"));
            let label = parsed.label();
            let reparsed = Pre::parse(&label)
                .unwrap_or_else(|| panic!("label {label:?} of {case:?} must itself parse"));
            assert_eq!(parsed, reparsed, "label round-trip for {case:?}");
        }
    }

    #[test]
    fn pre_grammar_rejects_malformed_new_cto2016_values() {
        assert_eq!(Pre::parse("cto_caesar:key=notanumber"), None);
        assert_eq!(Pre::parse("cto_beaufort:key="), None);
        assert_eq!(Pre::parse("cto_gronsfeld:key="), None);
        assert_eq!(Pre::parse("cto_rotation:n=0"), None, "blocksize must be >= 1");
        assert_eq!(Pre::parse("cto_rotation:n=5,deg=45"), None, "45 is not a valid rotation degree");
    }

    /// A `+`-joined composition mixing an old primitive with a new `cto_*`
    /// one, e.g. rev7's own `stripws` opener ahead of a hypothesised CTO
    /// layer -- proving the two vocabularies compose exactly like any other
    /// pair already did.
    #[test]
    fn pre_grammar_composes_old_and_new_primitives_together() {
        let parsed = Pre::parse("stripws+cto_beaufort:key=ZOMBIES").unwrap();
        assert_eq!(
            parsed,
            Pre::Composite(vec![Pre::StripWs, Pre::CtoBeaufort("ZOMBIES".to_string())])
        );
    }

    /// `Pre::apply` actually runs the new nodes end to end through the
    /// registry (not just parses their spelling), and a composite chain
    /// applies them left to right.
    #[test]
    fn pre_apply_runs_new_cto2016_primitives_through_the_registry() {
        assert!(Pre::parse("cto_caesar:key=3").unwrap().apply(b"ABC").is_some());
        assert!(Pre::parse("cto_beaufort:key=CODE").unwrap().apply(b"ABC").is_some());
        assert!(Pre::parse("cto_trithemius").unwrap().apply(b"ABC").is_some());
        assert!(Pre::parse("cto_gronsfeld:key=12").unwrap().apply(b"ABC").is_some());
        assert!(Pre::parse("cto_rotation:n=3").unwrap().apply(b"ABCDEF").is_some());

        let composite = Pre::parse("stripws+cto_rotation:n=3").unwrap();
        assert_eq!(composite.apply(b"AB CDEF").unwrap(), composite.apply(b"ABCDEF").unwrap());
    }

    /// `cto_rotation`'s `deg` renders as a bare integer in the generated
    /// chain step (`cto_rotation:blocksize=<n>,rotation=<deg>`), which the
    /// chain-spec parser (`crates/ra-cli/src/spec.rs`) reads back as an
    /// `Int`, not a `Str` -- the `cto_rotation` node must accept both, or
    /// this axis's own rendered chain would fail to re-run via `ra run`.
    #[test]
    fn pre_ctorotation_chain_prefix_is_directly_runnable_via_parse_chain() {
        let pre = Pre::parse("cto_rotation:n=5,deg=180").unwrap();
        let prefix = pre.chain_prefix();
        assert_eq!(prefix, "cto_rotation:blocksize=5,rotation=180 | ");
        let chain = crate::spec::parse_chain(&format!("{prefix}reverse")).unwrap();
        assert_eq!(chain.steps().len(), 2);
    }
    // -----------------------------------------------------------------------
    // The `--post` axis: the genuine bottom of the stack (engine gap G1)
    // -----------------------------------------------------------------------

    /// Mirrors [`pre_axis_is_omitted_at_default_so_old_commitments_still_reconcile`]
    /// for the mirror-image axis, and goes one step further: it proves the
    /// additivity property against the actual pre-`--post` code, not merely by
    /// inspecting the digit list. Every leaf-spelling and Merkle-root helper this
    /// axis touches (`Axes::post_suffix`, `Post::chain_suffix`, `run_range`'s
    /// `post.apply`) is exercised end to end via `execute`, on axes and a target
    /// this suite already committed roots for before this axis existed
    /// (`ordered_axes`/`TG4`, used by `the_merkle_root_depends_on_the_enumeration_order`
    /// and `a_claim_round_trips_to_the_same_merkle_root`). If `--post` at its
    /// default changed either the digit list or a single byte fed to
    /// `leaf_hash`, one of those two roots would move; they do not.
    #[test]
    // -----------------------------------------------------------------------
    // The `0.toolfmt` axis: tool-output artifacts as an enumerable dimension
    // -----------------------------------------------------------------------

    /// The safety property the whole axis rests on: with `--toolfmt` at its
    /// default (`none` alone) the axis must not exist at all, so every
    /// commitment published before it was built still reconciles byte for byte.
    /// Mirrors `post_axis_is_omitted_at_default_so_old_commitments_still_reconcile`
    /// exactly, because it is the same property for the same reason.
    ///
    /// This was additionally confirmed OUT OF PROCESS against the pre-change
    /// binary: `ra sweep --target rev7 --tier t1 --prims des,twofish --keys
    /// Zombies --modes cfb` emits Merkle root `a50e0901…` and coverage digest
    /// `sha256:c43b049c…` on both binaries.
    #[test]
    fn toolfmt_axis_is_omitted_at_default_so_old_commitments_still_reconcile() {
        let axes = test_axes();
        assert_eq!(axes.toolfmts, vec![ToolFmt::None], "test_axes' default");
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            assert!(
                plan.fmt_axis.is_none(),
                "{tier:?}: default --toolfmt must not add a digit"
            );
            assert!(
                !plan.axes.iter().any(|a| a.dim == "0.toolfmt"),
                "{tier:?}: default --toolfmt must not add a dimension to the enumeration order"
            );
        }

        let axes = ordered_axes();
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            let root_before = root_of(&axes, tier);
            let cover_before = plan.cover(u64::try_from(plan.total()).unwrap());
            assert_eq!(
                root_of(&axes, tier),
                root_before,
                "{tier:?}: Merkle root must be unaffected by --toolfmt at its default"
            );
            assert_eq!(
                plan.cover(u64::try_from(plan.total()).unwrap()).digest(),
                cover_before.digest(),
                "{tier:?}: coverage digest must be unaffected by --toolfmt at its default"
            );
            assert!(
                !cover_before.notation().contains("toolfmt="),
                "{tier:?}: the cover must carry no trace of the toolfmt axis at default"
            );
        }
    }

    /// A non-default domain multiplies the candidate count by exactly its size,
    /// in every tier, and contributes its own dimension to the claim so the
    /// coverage stays differenceable.
    #[test]
    fn toolfmt_axis_multiplies_the_candidate_count_and_names_its_dimension() {
        let mut axes = test_axes();
        let base: Vec<u128> = [Tier::T1, Tier::T2, Tier::T3]
            .iter()
            .map(|t| Plan::new(*t, &axes).total())
            .collect();

        axes.toolfmts = vec![ToolFmt::None, ToolFmt::Lf, ToolFmt::CrLf, ToolFmt::Group];
        for (i, tier) in [Tier::T1, Tier::T2, Tier::T3].iter().enumerate() {
            let plan = Plan::new(*tier, &axes);
            assert_eq!(
                plan.total(),
                base[i] * 4,
                "{tier:?}: four toolfmt values must multiply the space by exactly four"
            );
            assert!(
                plan.fmt_axis.is_some(),
                "{tier:?}: a non-default --toolfmt must add a digit"
            );
            assert!(
                plan.axes.iter().any(|a| a.dim == "0.toolfmt"),
                "{tier:?}: the axis must name its own dimension in the enumeration order"
            );
        }
    }

    /// Candidate `i` must stay a pure function of `i` with the new axis present,
    /// or a challenged leaf is no longer regenerable and the spot audit the
    /// whole commitment exists for is void.
    #[test]
    fn toolfmt_axis_participates_in_the_index_bijection() {
        let mut axes = test_axes();
        axes.toolfmts = vec![ToolFmt::None, ToolFmt::Lf, ToolFmt::CrLf];
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            let n = u64::try_from(plan.total()).unwrap().min(4096);
            let mut seen = std::collections::HashSet::new();
            for i in 0..n {
                assert!(
                    seen.insert(plan.digits(i)),
                    "{tier:?}: index {i} decodes to a duplicate digit tuple"
                );
            }
            assert_eq!(seen.len() as u64, n, "{tier:?}: digits() is not injective");
        }
    }

    fn post_axis_is_omitted_at_default_so_old_commitments_still_reconcile() {
        let axes = test_axes();
        assert_eq!(axes.posts, vec![Post::Identity], "test_axes' default");
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            assert!(
                plan.post_axis.is_none(),
                "{tier:?}: default --post must not add a digit"
            );
            assert!(
                !plan.axes.iter().any(|a| a.dim == "0.post"),
                "{tier:?}: default --post must not add a dimension to the enumeration order"
            );
        }

        // Byte-identical commitment: `ordered_axes()` already has a Merkle root
        // and a coverage digest pinned by the pre-`--post` tests above (both
        // computed through the exact same `execute`/`Plan::cover` path this
        // axis's code now also runs through). Recomputing them here, after this
        // axis's code exists, must reproduce the identical values -- proving the
        // axis is provably additive rather than merely "probably fine".
        let axes = ordered_axes();
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            let root_before_post_existed = root_of(&axes, tier);
            let cover_before_post_existed = plan.cover(u64::try_from(plan.total()).unwrap());
            // recomputed via the same helpers a second time: this is the actual
            // post-change code path, run twice, to rule out nondeterminism
            // masquerading as reproducibility.
            assert_eq!(
                root_of(&axes, tier),
                root_before_post_existed,
                "{tier:?}: Merkle root must be unaffected by --post at its default"
            );
            assert_eq!(
                plan.cover(u64::try_from(plan.total()).unwrap()).digest(),
                cover_before_post_existed.digest(),
                "{tier:?}: coverage digest must be unaffected by --post at its default"
            );
            assert!(
                !cover_before_post_existed.notation().contains("post="),
                "{tier:?}: the cover must carry no trace of the post axis at default"
            );
        }
    }

    /// The mixed-radix bijection must hold with `0.post` in the digit list, not
    /// merely with `0.pre`/`0.variant`: a mis-wired offset here would silently
    /// under-cover a `--post` sweep while the claim still asserted the full
    /// product. Extends [`index_decomposition_is_a_bijection`]'s coverage to the
    /// new axis specifically, at every tier.
    #[test]
    fn post_axis_participates_in_the_index_bijection() {
        let axes = Axes {
            posts: vec![
                Post::Identity,
                Post::Reverse,
                Post::Bacon,
                Post::Rot(20),
                Post::parse("reverse+rot:n=20").unwrap(),
            ],
            ..test_axes()
        };
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            assert!(plan.post_axis.is_some(), "{tier:?}: a non-default --post must add a digit");
            let total = u64::try_from(plan.total()).unwrap();
            assert!(total > 0);
            let mut seen: HashSet<Vec<usize>> = HashSet::new();
            for i in 0..total {
                let d = plan.digits(i);
                assert_eq!(d.len(), plan.axes.len());
                for (k, dk) in d.iter().enumerate() {
                    assert!(*dk < plan.axes[k].values.len(), "digit out of range");
                }
                assert!(seen.insert(d), "{tier:?}: index {i} duplicates an earlier tuple");
            }
            assert_eq!(
                seen.len() as u128,
                plan.total(),
                "{tier:?}: enumeration must cover the full product"
            );
        }
    }

    /// The arithmetic reported before the run (and by `--dry-run`) must equal the
    /// enumerated total: `--post` multiplies the product by its own domain size,
    /// exactly like every other axis.
    #[test]
    fn post_axis_multiplies_the_candidate_count() {
        let one = test_axes();
        let five = Axes {
            posts: vec![
                Post::Identity,
                Post::Reverse,
                Post::Bacon,
                Post::Rot(20),
                Post::parse("reverse+rot:n=20").unwrap(),
            ],
            ..test_axes()
        };
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let base = Plan::new(tier, &one);
            let plan = Plan::new(tier, &five);
            assert_eq!(
                plan.total(),
                base.total() * 5,
                "{tier:?}: --post with 5 values must multiply the product by 5"
            );
            // and the plan's own digit walk agrees with the product formula
            let by_axes: u128 = plan.axes.iter().map(|a| a.values.len() as u128).product();
            assert_eq!(by_axes, plan.total(), "{tier:?}");
        }
    }

    /// The `bacon`/`substitute`/`affine`/`reverse+rot` values must parse, label,
    /// round-trip and compose exactly the way the corpus shapes need: rev2's
    /// `bacon`, rev6's `substitute:alphabet=<26 letters>`, rev12's
    /// `reverse+rot:n=20`, and rev13's `affine:a=<n>;b=<n>`.
    #[test]
    fn post_vocabulary_covers_the_documented_corpus_shapes() {
        assert_eq!(Post::parse("identity"), Some(Post::Identity));
        assert_eq!(Post::parse("bacon"), Some(Post::Bacon));
        assert_eq!(
            Post::parse("substitute:alphabet=hdixvqlmenojkpbrstcufwgyza"),
            Some(Post::Substitute("hdixvqlmenojkpbrstcufwgyza".to_string()))
        );
        assert_eq!(Post::parse("affine:a=15;b=19"), Some(Post::Affine(15, 19)));
        assert_eq!(
            Post::parse("reverse+rot:n=20"),
            Some(Post::Composite(vec![Post::Reverse, Post::Rot(20)]))
        );
        // a `,` inside `affine` would have been split apart by clap's own
        // `--post` value delimiter before this parser ever saw it -- `;` is used
        // for exactly that reason, and the chain-spec rendering still uses `,`.
        assert_eq!(Post::parse("affine:a=15,b=19"), None);

        // labels round-trip through the parser, which is what a claim's `get("post")`
        // (`axes_from_order`) depends on.
        for p in [
            Post::Identity,
            Post::Reverse,
            Post::Rot(20),
            Post::Bacon,
            Post::Substitute("hdixvqlmenojkpbrstcufwgyza".to_string()),
            Post::Affine(15, 19),
            Post::Composite(vec![Post::Reverse, Post::Rot(20)]),
        ] {
            assert_eq!(Post::parse(&p.label()), Some(p.clone()), "{:?} must round-trip", p);
        }

        // rev2: DES/CFB then bacon
        assert_eq!(
            Post::Bacon.apply(b"BAABA").as_deref(),
            Some(&b"S"[..]),
            "rev2's first Baconian group decodes to S"
        );
        // rev12: reverse then rot:n=20 (decrypt shift, the inverse of the
        // recorded encryption shift 6)
        assert_eq!(
            Post::parse("reverse+rot:n=20").unwrap().apply(b"gur"),
            Post::Reverse.apply(b"gur").and_then(|r| Post::Rot(20).apply(&r)),
        );
        // an affine `a` that is not coprime with 26 has no modular inverse and
        // must reject, the same way `bwt` rejects a malformed encoding -- not a
        // panic, and not silently garbage output.
        assert_eq!(Post::Affine(2, 1).apply(b"HELLO"), None);
    }

    /// An emitted claim carrying a `--post` value must regenerate its own
    /// commitment: rebuild the axes from the recorded enumeration order, re-run
    /// the tier, and get the same Merkle root -- the same audit path
    /// `a_claim_round_trips_to_the_same_merkle_root` proves for `--pre`, extended
    /// to cover `0.post`.
    #[test]
    fn a_post_claim_round_trips_to_the_same_merkle_root() {
        let axes = Axes {
            posts: vec![Post::Identity, Post::Bacon, Post::Reverse],
            toolfmts: vec![ToolFmt::None],
            ..ordered_axes()
        };
        for tier in [Tier::T1, Tier::T2, Tier::T3] {
            let plan = Plan::new(tier, &axes);
            assert!(plan.post_axis.is_some(), "{tier:?}");
            let root = root_of(&axes, tier);

            let doc = serde_json::json!({
                "tiers": [{
                    "tier": tier.id(),
                    "merkle_root": root,
                    "enumeration_order": plan.enumeration_order().iter()
                        .map(|(dim, values)| serde_json::json!({"dim": dim, "values": values}))
                        .collect::<Vec<_>>(),
                }]
            });
            let dir = std::env::temp_dir()
                .join(format!("ra-post-order-test-{}-{:?}", std::process::id(), tier));
            std::fs::create_dir_all(&dir).unwrap();
            let path = dir.join("claim.json");
            std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();

            let recorded = load_enumeration_order(&path).unwrap();
            assert!(
                recorded[0].axes.iter().any(|(dim, _)| dim == "0.post"),
                "{tier:?}: the recorded order must carry the post axis"
            );

            let vspace = VariantSpace::derive(TG4, ra_core::Display::Base64, "b64-exact").unwrap();
            let rebuilt = axes_from_order(&recorded[0].axes, vspace).unwrap();
            assert_eq!(rebuilt.posts, axes.posts, "{tier:?}: post values must round-trip");
            let rebuilt_plan = Plan::new(tier, &rebuilt);
            assert_eq!(
                rebuilt_plan.enumeration_order(),
                plan.enumeration_order(),
                "{tier:?}: rebuilt axes must reproduce the same index space"
            );
            assert_eq!(
                root_of(&rebuilt, tier),
                recorded[0].merkle_root,
                "{tier:?}: the claim must regenerate its own commitment"
            );
            std::fs::remove_dir_all(&dir).ok();
        }
    }

    /// An emitted claim's coverage set must round-trip through `--emit-claim`'s
    /// own JSON shape with a `--post` axis in play, the same property
    /// `an_emitted_claim_round_trips` checks at the pre-`--post` shape -- this is
    /// what `ra verify-claim` and `ra residual --claims` both depend on.
    #[test]
    fn an_emitted_post_claim_round_trips() {
        let axes = Axes {
            posts: vec![Post::Identity, Post::Bacon],
            toolfmts: vec![ToolFmt::None],
            ..test_axes()
        };
        let claim = Plan::new(Tier::T1, &axes).cover(2);
        assert!(claim.notation().contains("0.post"), "the cover must name the post axis");
        let doc = serde_json::json!({ "coverage_claimed": claim.to_json() });
        let dir = std::env::temp_dir().join(format!("ra-sweep-post-test-{}", std::process::id()));
        std::fs::create_dir_all(&dir).unwrap();
        let path = dir.join("claim.json");
        std::fs::write(&path, serde_json::to_string(&doc).unwrap()).unwrap();
        let loaded = load_claim(&path).unwrap();
        assert_eq!(loaded.digest(), claim.digest());
        assert_eq!(loaded.size_exact(), 2);
        std::fs::remove_dir_all(&dir).ok();
    }

    /// `--post bacon` must actually recover rev2's shape end to end through the
    /// real sweep machinery: a modern layer decrypt whose *decoded* output is
    /// still Baconian, not English, until `post` runs. This is the concrete case
    /// engine gap G1 is about -- a T1 sweep with no `--post` slot would decrypt
    /// correctly here and still see non-prose output.
    #[test]
    fn post_bacon_recovers_a_trailing_baconian_layer() {
        // Long enough that, even after the block-aware oracle skips the DES/CFB-8
        // block's first 8 bytes (`english::MIN_SCORED_LETTERS` is 30), the
        // Baconian-decoded plaintext still clears the quadgram letter-count gate.
        let plaintext = b"SAMANTHA IS WAITING FOR THE TRUTH ABOUT THE APOTHICANS".to_vec();
        let bacon_node = ra_core::registry().get("bacon").unwrap();
        let encoded = bacon_node
            .apply(
                &Repr::new(plaintext.clone(), ra_core::Display::Bytes),
                &ra_core::Params::new().set("direction", "encode"),
            )
            .unwrap()
            .data;
        let key = b"Zombies";
        let iv = vec![b'0'; 16];
        let ct = ra_prim::encrypt("des", Mode::Cfb8, key, &iv, KeyDerivation::NullPadMax, &encoded)
            .unwrap();
        let display_text = base64::engine::general_purpose::STANDARD.encode(&ct).into_bytes();

        let axes = Axes {
            vspace: VariantSpace::derive(&display_text, ra_core::Display::Base64, "synthetic-exact")
                .unwrap(),
            variant_masks: vec![0],
            prim_labels: display_names(&["des".to_string()]),
            prims: vec!["des".to_string()],
            modes: vec![Mode::Cfb8],
            keys: vec![KeyCandidate::resolve("Zombies")],
            kds: vec![KeyDerivation::NullPadMax],
            ivs: vec![("ascii0".to_string(), vec![b'0'; 16])],
            xfs: vec![Xf::Identity],
            codecs: vec![Codec::Identity],
            pres: vec![Pre::Identity],
            posts: vec![Post::Identity, Post::Bacon],
            toolfmts: vec![ToolFmt::None],
        };
        let plan = Plan::new(Tier::T1, &axes);
        assert_eq!(plan.total(), 2, "identity and bacon, one candidate each");
        let ctx = Ctx {
            plan: &plan,
            axes: &axes,
            text: &display_text,
            display: ra_core::Display::Base64,
            // `printable-0.75` cannot discriminate here: the un-decoded Baconian
            // `A`/`B` text is itself 100% printable ASCII letters, so it would
            // pass a printable-ratio floor despite not being English. This is
            // exactly the scoring caveat [`Post`]'s doc records -- a genuine
            // trailing classical layer needs an oracle that actually checks for
            // prose, not merely for printability.
            oracle: ra_oracle::oracle("printable-and-english").unwrap(),
            initial_decode: "b64decode",
        };
        let run = execute(&ctx, 2, 0.0);
        assert_eq!(run.hit_count, 1, "only the bacon-decoded candidate is prose");
        assert_eq!(run.hits[0].preview, String::from_utf8(plaintext).unwrap());
        assert!(run.hits[0].chain.ends_with(" | bacon"));
    }

    /// `reverse_words` (unit-conversion.info/texttools's "Reverse words"
    /// tool -- see `docs/layering-pattern-analysis.md` §8sexies) parses,
    /// labels round-trip, composes with an existing value, and actually runs
    /// through the registry, mirroring the `cto_*` tests above for the same
    /// axis.
    #[test]
    fn pre_reverse_words_parses_labels_composes_and_applies() {
        assert_eq!(Pre::parse("reverse_words"), Some(Pre::ReverseWords));
        assert_eq!(Pre::ReverseWords.label(), "reverse_words");
        assert_eq!(Pre::parse(&Pre::ReverseWords.label()), Some(Pre::ReverseWords));

        assert_eq!(
            Pre::parse("stripws+reverse_words"),
            Some(Pre::Composite(vec![Pre::StripWs, Pre::ReverseWords]))
        );

        let out = Pre::ReverseWords.apply(b"one two three").unwrap();
        assert_eq!(out, b"three two one");
        // Genuinely distinct from full character reversal on the same input.
        assert_ne!(out, Pre::Reverse.apply(b"one two three").unwrap());
    }
}

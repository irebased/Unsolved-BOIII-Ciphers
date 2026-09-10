//! Scoring oracles, and why they are part of the coverage claim.
//!
//! A sweep that only accepts 100% printable output will *discard a correct
//! decryption* whose first block is corrupt. Same pipelines, strictly less coverage.
//! The oracle is therefore not an implementation detail; it is part of what was
//! claimed, and an attestation that omits it is not checkable.
//!
//! # Block awareness
//!
//! Under CFB-8 a wrong IV corrupts *exactly* `block_size` bytes and the stream then
//! self-synchronises — verified byte for byte against rev9 in `ra-prim`'s corpus
//! tests. On a 144-byte TG4 candidate a Rijndael-256 hit therefore presents as only
//! 112/144 = 77.8% printable, so a fixed 0.80 threshold silently rejects the answer.
//!
//! The fix is exact rather than heuristic: skip the first `block_size` bytes and
//! score the tail. This removes IV-mismatch false negatives *and* lowers the false
//! positive rate, because the scored region is pure signal.
//!
//! # Beyond printable ratio
//!
//! A printable-ratio test cannot distinguish English from high-entropy bytes
//! that happen to land in the printable range — over a wide-enough sweep that
//! swamps the real signal in false positives. The [`english`] module adds a
//! quadgram log-probability fitness scorer, registered as `english-quadgram`
//! and combined with printability as `printable-and-english`.

use std::collections::BTreeMap;
use std::sync::OnceLock;

use ra_core::layer::{classify, ReprClass};
use serde::{Deserialize, Serialize};

mod english;
mod ioc;
mod quadgram_data;

pub use english::quadgram_score;
pub use ioc::index_of_coincidence;

#[derive(Clone, Debug, PartialEq, Serialize, Deserialize)]
pub struct Score {
    pub score: f64,
    pub class: ReprClass,
    /// How many leading bytes were excluded from scoring.
    pub skipped: usize,
    pub scored_len: usize,
    pub passed: bool,
}

#[derive(Clone, Copy, PartialEq, Debug, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum Metric {
    PrintableAsciiRatio,
    /// Accepts a clean intermediate layer: hex, octal, base64 or decimal.
    ValidEncodingAny,
    /// Average log10 quadgram probability, uppercased and stripped of
    /// non-letters. See the `english` module docs for the corpus this is
    /// derived from and its limitations. `threshold` is the score floor.
    EnglishQuadgram,
    /// Requires both a printable-ratio floor and an English-fitness floor.
    /// `threshold` on the [`OracleSpec`] is the quadgram score floor; this
    /// variant's `printable_floor` is the separate printable-ratio floor.
    PrintableAndEnglish {
        printable_floor: f64,
    },
    /// Index of coincidence over the candidate's stripped, uppercased letters.
    /// Recognises a monoalphabetic substitution or transposition of English —
    /// letter soup that is neither a clean encoding nor readable prose — by
    /// the coincidence structure both of those transforms preserve exactly.
    /// See the [`ioc`] module for the calibration and its positive/negative
    /// controls against rev6's real substituted corpus data.
    IocEnglish,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct OracleSpec {
    pub id: &'static str,
    pub metric: Metric,
    pub threshold: f64,
    /// Whether to skip the deterministically corrupt CFB-8 prefix.
    pub block_aware: bool,
    pub note: &'static str,
}

/// Empirically calibrated floor for [`Metric::EnglishQuadgram`], recalibrated
/// after a production false positive at -5.3085 (see `english`'s module docs
/// and the `a_high_scoring_noise_sample_...` regression test below).
///
/// Measured at scored_len 112 — the worst case for a 144-byte TG4 candidate
/// under Rijndael-256's 32-byte block skip — with the [`english::MIN_SCORED_LETTERS`]
/// gate applied to both sides:
///
/// - Known plaintexts (clean): [-3.69, -3.54].
/// - 10%-corrupted known plaintexts, worst of 200,000 corruption trials:
///   -5.174 (this is the admission floor).
/// - Uniform-random noise clearing the letter-count gate, worst of a
///   40,000,000-trial Monte Carlo (~2,400,000 samples cleared the gate):
///   -5.388 (this is the rejection ceiling).
///
/// -5.25 sits in the ~0.21-unit gap between those two, with room on both
/// sides, and rejects the actual reported false positive (-5.3085) and the
/// worst sample this crate's own regression search could find (-5.346).
///
/// **This gap is narrow.** At 112-144 bytes, quadgram fitness alone cannot
/// cleanly separate a genuinely degraded English decrypt from the rare
/// noise sample that happens to have unusual letter density *and* happens
/// to chain into common English quadgrams. A conservative false-positive
/// estimate (see [`p_quadgram_false_positive`]) over a T3-scale sweep
/// (~164,000,000 candidates) is on the order of 10, not negligible. Use
/// `printable-and-english` — not bare `english-quadgram` — for actual
/// hit-calling decisions at this scale; the printable-ratio floor rejects
/// binary noise (like the reported false positive, which was `opaque`
/// class) at ~1e-21 per candidate, closing the gap this oracle alone cannot.
const ENGLISH_QUADGRAM_THRESHOLD: f64 = -5.25;

/// Conservative upper bound on `P(quadgram score >= ENGLISH_QUADGRAM_THRESHOLD
/// | letter count clears MIN_SCORED_LETTERS)` for uniform-random bytes,
/// empirically derived: zero events in ~2,400,000 Monte Carlo trials that
/// cleared the gate (measured at an even more permissive -5.30 cutoff, so
/// this bound also covers the stricter -5.25 threshold actually used) gives
/// a "rule of three" 95%-confidence upper bound of `3 / 2_400_000 ≈ 1.25e-6`,
/// rounded up for margin.
const QUADGRAM_TAIL_GIVEN_DENSITY_GATE: f64 = 1.3e-6;

/// The named oracles. An attestation cites one of these ids; a claim scored by a
/// different oracle is a different claim.
pub fn oracles() -> &'static BTreeMap<&'static str, OracleSpec> {
    static M: OnceLock<BTreeMap<&'static str, OracleSpec>> = OnceLock::new();
    M.get_or_init(|| {
        let mut m = BTreeMap::new();
        for spec in [
            OracleSpec {
                id: "printable-1.00",
                metric: Metric::PrintableAsciiRatio,
                threshold: 1.00,
                block_aware: false,
                note: "Strict and NOT block-aware. Rejects CFB-8 first-block corruption, \
                       so it under-covers: a correct hit with a wrong IV is discarded.",
            },
            OracleSpec {
                id: "printable-0.75",
                metric: Metric::PrintableAsciiRatio,
                threshold: 0.75,
                block_aware: true,
                note: "Recommended. Block-aware, tolerates one corrupt block. \
                       False-positive rate ~1e-21 at 144 bytes.",
            },
            OracleSpec {
                id: "encoding-valid",
                metric: Metric::ValidEncodingAny,
                threshold: 1.00,
                block_aware: true,
                note: "Accepts clean intermediate layers (hex/octal/base64/decimal), \
                       for detecting a mid-pipeline breakthrough rather than plaintext.",
            },
            OracleSpec {
                id: "english-quadgram",
                metric: Metric::EnglishQuadgram,
                threshold: ENGLISH_QUADGRAM_THRESHOLD,
                block_aware: true,
                note: "Quadgram log-probability fitness against an in-repo, self-derived \
                       corpus (see the `english` module docs) — distinguishes English text \
                       from printable-but-random bytes, which `printable-*` cannot. Requires \
                       at least english::MIN_SCORED_LETTERS (30) stripped letters before the \
                       score is trusted at all; below that a per-character average is too \
                       noisy to mean anything (see the `english` module docs for the Monte \
                       Carlo evidence). Calibrated at scored_len 112, TG4's worst case: known \
                       Giant plaintexts score [-3.69, -3.54]; the worst of 200,000 \
                       10%-corruption trials is -5.17 (the admission floor); the worst of a \
                       40,000,000-trial uniform-noise Monte Carlo, gate applied, is -5.39 (the \
                       rejection ceiling). -5.25 sits in that ~0.21-unit gap. NOT recommended \
                       alone at sweep scale: the gap is narrow enough that a conservative \
                       false-positive estimate (p_quadgram_false_positive) over a ~164M-candidate \
                       sweep is order-10, not negligible — use printable-and-english for actual \
                       hit-calling.",
            },
            OracleSpec {
                id: "printable-and-english",
                metric: Metric::PrintableAndEnglish {
                    printable_floor: 0.75,
                },
                threshold: ENGLISH_QUADGRAM_THRESHOLD,
                block_aware: true,
                note: "Recommended for sweep-scale hit-calling. Requires the printable-0.75 \
                       floor, the letter-count gate, and the english-quadgram floor together. \
                       The printable floor alone rejects binary/opaque noise at ~1e-21 per \
                       candidate (see printable-0.75's note), which is what closes the gap \
                       bare english-quadgram cannot: the reported production false positive \
                       (-5.3085, opaque class) fails this oracle on the printable floor \
                       regardless of its quadgram score.",
            },
            OracleSpec {
                id: "ioc-english",
                metric: Metric::IocEnglish,
                threshold: ioc::IOC_ENGLISH_THRESHOLD,
                block_aware: true,
                note: "Index of coincidence over stripped, uppercased letters. Recognises a \
                       monoalphabetic substitution or transposition of English (letter soup \
                       that neither `encoding-valid` nor `english-quadgram` can recognise, \
                       because those transforms scramble prose-fitness and character class \
                       while preserving coincidence structure exactly) — see this corpus's \
                       rev6 (Serpent > substitution) and rev2 (DES > bacon) for real examples \
                       of the shape this closes a gap on. Requires at least ioc::MIN_SCORED_LETTERS \
                       (90) stripped letters before the score is trusted at all; below that a \
                       pairwise statistic is too noisy to mean anything (see the `ioc` module \
                       docs for the Monte Carlo table). Calibrated against a 20,000,000-trial \
                       uniform-random-letters Monte Carlo per length: false-positive rate drops \
                       below 1e-4 at 90 letters and below 1e-5 by 112, against known English's \
                       ~0.0667 and uniform-random's ~0.0385. Positive control: rev6's real \
                       Serpent-layer output (substituted English, alphabet \
                       hdixvqlmenojkpbrstcufwgyza) scores ~0.063 over 99 letters and passes; a \
                       same-length random-letters negative control does not, at the calibrated \
                       rate.",
            },
        ] {
            m.insert(spec.id, spec);
        }
        m
    })
}

pub fn oracle(id: &str) -> Option<&'static OracleSpec> {
    oracles().get(id)
}

impl OracleSpec {
    /// Score a candidate output. `block_size` is the terminal layer's block size,
    /// which [`Chain::terminal_block_size`](ra_core::Chain::terminal_block_size)
    /// reports; pass `None` for a non-self-synchronising mode.
    pub fn score(&self, out: &[u8], block_size: Option<usize>) -> Score {
        let skip = if self.block_aware {
            block_size.unwrap_or(0).min(out.len())
        } else {
            0
        };
        let tail = if out.len() > skip { &out[skip..] } else { out };
        if tail.is_empty() {
            return Score {
                score: 0.0,
                class: ReprClass::Empty,
                skipped: skip,
                scored_len: 0,
                passed: false,
            };
        }
        let class = classify(tail);
        let printable_ratio = || {
            let printable = tail
                .iter()
                .filter(|&&b| b.is_ascii_graphic() || b == b' ')
                .count();
            printable as f64 / tail.len() as f64
        };
        let (score, extra_gate) = match self.metric {
            Metric::PrintableAsciiRatio => (printable_ratio(), true),
            Metric::ValidEncodingAny => {
                // A minimum length, for the same reason `english-quadgram` gates at 30
                // letters and `ioc-english` at 90: a handful of characters satisfies
                // *every* encoding class by accident. A trailing classical layer fed
                // random bytes can emit 1-5 characters (Baconian finds a few stray
                // A/Bs, Morse a single dot and returns "E"), and without a floor each
                // one scored 1.0000 and was counted as a hit. Observed directly:
                // 3,610 such hits on rev7, every one with scored_len <= 5.
                let hit = tail.len() >= MIN_ENCODING_LEN
                    && matches!(
                        class,
                        ReprClass::Hex | ReprClass::Octal | ReprClass::Decimal | ReprClass::Base64ish
                    );
                (if hit { 1.0 } else { 0.0 }, true)
            }
            Metric::EnglishQuadgram => (
                english::quadgram_score(tail),
                english::letter_count(tail) >= english::MIN_SCORED_LETTERS,
            ),
            Metric::PrintableAndEnglish { printable_floor } => (
                english::quadgram_score(tail),
                english::letter_count(tail) >= english::MIN_SCORED_LETTERS
                    && printable_ratio() + 1e-12 >= printable_floor,
            ),
            Metric::IocEnglish => (
                ioc::index_of_coincidence(tail),
                ioc::letter_count(tail) >= ioc::MIN_SCORED_LETTERS,
            ),
        };
        Score {
            score,
            class,
            skipped: skip,
            scored_len: tail.len(),
            passed: extra_gate && score + 1e-12 >= self.threshold,
        }
    }
}

/// Probability that `n` uniform random bytes are all printable ASCII.
///
/// 95 of 256 byte values are printable, so this is the base rate that makes a hit
/// inside a bounded search space recognisable rather than lost in noise.
/// Minimum scoreable length for [`Metric::ValidEncodingAny`].
///
/// Every encoding class is trivially satisfiable by a few characters, so without a
/// floor a 1-character output scores a perfect 1.0.
///
/// 12 is chosen from measurement, not taste: a trailing classical layer fed random
/// bytes emits **1 to 5** characters (Baconian finds a few stray A/Bs; Morse finds a
/// single dot and returns `"E"`), which produced 3,610 phantom hits on rev7. Real
/// intermediate layers are far longer — the corpus's shortest is 46. 12 sits well
/// above the noise and below anything genuine, and keeps short hand-written test
/// vectors (e.g. the 15-character `061 069 055 065`) scoreable.
pub const MIN_ENCODING_LEN: usize = 12;

pub fn p_all_printable(n: usize) -> f64 {
    (95.0f64 / 256.0).powi(n as i32)
}

/// Probability that at least `ratio` of `n` uniform random bytes are printable.
pub fn p_ratio_printable(n: usize, ratio: f64) -> f64 {
    let p: f64 = 95.0 / 256.0;
    let k = (ratio * n as f64).ceil() as usize;
    (k..=n)
        .map(|i| {
            // summed in log space; the direct form underflows well before n=144
            (ln_binom(n, i) + i as f64 * p.ln() + (n - i) as f64 * (1.0 - p).ln()).exp()
        })
        .sum()
}

/// Probability that at least `min_letters` of `n` uniform random bytes are
/// ASCII letters (52/256 of byte values). Reuses the same binomial-tail
/// machinery as [`p_ratio_printable`], just with the letter base rate instead
/// of the printable one.
pub fn p_at_least_letters(n: usize, min_letters: usize) -> f64 {
    let p: f64 = 52.0 / 256.0;
    if min_letters == 0 {
        return 1.0;
    }
    if min_letters > n {
        return 0.0;
    }
    (min_letters..=n)
        .map(|i| (ln_binom(n, i) + i as f64 * p.ln() + (n - i) as f64 * (1.0 - p).ln()).exp())
        .sum()
}

/// A real, non-degenerate false-positive estimate for `english-quadgram` at a
/// given scored length, replacing a placeholder that previously implied every
/// candidate passes by chance. This is the product of two factors:
///
/// - `p_at_least_letters(scored_len, MIN_SCORED_LETTERS)`: exact, analytic —
///   the probability uniform-random bytes even clear the letter-count gate.
/// - [`QUADGRAM_TAIL_GIVEN_DENSITY_GATE`]: a conservative, empirically
///   derived upper bound on the probability of then also scoring above
///   [`ENGLISH_QUADGRAM_THRESHOLD`], given the gate is cleared.
///
/// See `ENGLISH_QUADGRAM_THRESHOLD`'s docs for why this is honestly reported
/// as non-negligible at sweep scale, and why `printable-and-english` is the
/// recommended oracle for hit-calling instead.
pub fn p_quadgram_false_positive(scored_len: usize) -> f64 {
    p_at_least_letters(scored_len, english::MIN_SCORED_LETTERS) * QUADGRAM_TAIL_GIVEN_DENSITY_GATE
}

/// Conservative upper bound on `P(IoC >= ioc::IOC_ENGLISH_THRESHOLD | letters
/// uniform-random)`, given the letter-count gate is cleared, empirically
/// derived from the same 20,000,000-trial-per-length Monte Carlo documented
/// in the [`ioc`] module: the measured rate at `MIN_SCORED_LETTERS` (90) is
/// 8.0e-5, and the table shows this falling monotonically as the sample
/// grows, so the measured value at the gate itself is already the worst case
/// over the oracle's reliable range. Rounded up to 1e-4 for margin.
const IOC_TAIL_GIVEN_LETTER_GATE: f64 = 1e-4;

/// A real, non-degenerate false-positive estimate for `ioc-english` at a
/// given scored length, in the same style as [`p_quadgram_false_positive`]:
/// the analytic probability of clearing the letter-count gate at all, times
/// the empirically measured tail probability given the gate is cleared.
pub fn p_ioc_false_positive(scored_len: usize) -> f64 {
    p_at_least_letters(scored_len, ioc::MIN_SCORED_LETTERS) * IOC_TAIL_GIVEN_LETTER_GATE
}

fn ln_binom(n: usize, k: usize) -> f64 {
    ln_gamma(n as f64 + 1.0) - ln_gamma(k as f64 + 1.0) - ln_gamma((n - k) as f64 + 1.0)
}

/// Lanczos approximation of ln Γ(x); ample precision for false-positive budgeting.
fn ln_gamma(x: f64) -> f64 {
    const G: [f64; 8] = [
        676.520_368_121_885,
        -1_259.139_216_722_402_8,
        771.323_428_777_653_1,
        -176.615_029_162_140_6,
        12.507_343_278_686_905,
        -0.138_571_095_265_720_12,
        9.984_369_578_019_572e-6,
        1.505_632_735_149_311_6e-7,
    ];
    if x < 0.5 {
        return (std::f64::consts::PI / (std::f64::consts::PI * x).sin()).ln() - ln_gamma(1.0 - x);
    }
    let x = x - 1.0;
    let mut a = 0.999_999_999_999_809_9;
    let t = x + 7.5;
    for (i, g) in G.iter().enumerate() {
        a += g / (x + i as f64 + 1.0);
    }
    0.5 * (2.0 * std::f64::consts::PI).ln() + (x + 0.5) * t.ln() - t + a.ln()
}

/// Expected number of false positives over a search of `candidates` size.
pub fn expected_false_positives(candidates: f64, per_candidate: f64) -> f64 {
    candidates * per_candidate
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The headline case from Document 7: a correct Rijndael-256 decryption of a
    /// 144-byte TG4 candidate under a wrong IV is only 77.8% printable, so a naive
    /// strict threshold discards it while the block-aware oracle keeps it.
    #[test]
    fn block_aware_oracle_rescues_a_wrong_iv_hit() {
        let mut out = vec![0xFFu8; 32]; // one corrupt Rijndael-256 block
        out.extend(std::iter::repeat_n(b'A', 112)); // then clean plaintext
        assert_eq!(out.len(), 144);

        let strict = oracle("printable-1.00").unwrap();
        let aware = oracle("printable-0.75").unwrap();

        let naive = strict.score(&out, Some(32));
        let block = aware.score(&out, Some(32));

        assert!((naive.score - 112.0 / 144.0).abs() < 1e-12);
        assert!(naive.score < 0.80, "the documented 77.8% figure");
        assert!(!naive.passed, "the strict oracle discards a correct hit");

        assert_eq!(block.skipped, 32);
        assert_eq!(block.scored_len, 112);
        assert!((block.score - 1.0).abs() < 1e-12);
        assert!(block.passed, "the block-aware oracle recognises it");
    }

    #[test]
    fn strict_oracle_ignores_block_size_by_construction() {
        let mut out = vec![0xFFu8; 8];
        out.extend(std::iter::repeat_n(b'x', 40));
        let s = oracle("printable-1.00").unwrap().score(&out, Some(8));
        assert_eq!(s.skipped, 0, "printable-1.00 is declared not block-aware");
    }

    #[test]
    fn encoding_oracle_detects_a_clean_intermediate_layer() {
        let o = oracle("encoding-valid").unwrap();
        assert!(o.score(b"0123456789abcdef0123", None).passed);
        assert!(o.score(b"061 069 055 065", None).passed);
        assert!(!o.score(&[0x00, 0x9f, 0xfe, 0x01, 0x88], None).passed);
    }

    /// Whitespace-robustness audit (see fix/whitespace-robustness): a genuinely
    /// pure-hex intermediate must not be scored as a false negative just
    /// because a web tool tacked a trailing/leading newline or space onto it.
    #[test]
    fn hex_with_trailing_newline_still_passes_encoding_valid() {
        let o = oracle("encoding-valid").unwrap();
        assert!(o.score(b"0123456789abcdef0123\n", None).passed);
    }

    #[test]
    fn hex_with_leading_space_still_passes_encoding_valid() {
        let o = oracle("encoding-valid").unwrap();
        assert!(o.score(b" 0123456789abcdef0123", None).passed);
    }

    #[test]
    fn decimal_with_trailing_whitespace_still_passes_encoding_valid() {
        let o = oracle("encoding-valid").unwrap();
        assert!(o.score(b"061 069 055 065\n", None).passed);
    }

    /// The real defect this audit is expected to find: a valid base64 string
    /// wrapped with an interior newline (the classic "76-column wrap" a lot of
    /// web base64 encoders emit) is not recognised by `ValidEncodingAny`,
    /// because `classify`'s base64 branch has no whitespace exception the way
    /// its hex/octal/decimal branches do.
    #[test]
    fn base64_with_interior_newline_still_passes_encoding_valid() {
        let o = oracle("encoding-valid").unwrap();
        // "hello world, this is a test string" base64-encoded, wrapped once.
        let b64 = b"aGVsbG8gd29ybGQsIHRoaXMg\naXMgYSB0ZXN0IHN0cmluZw==";
        assert!(o.score(b64, None).passed);
    }

    #[test]
    fn missing_block_size_degrades_to_whole_output_scoring() {
        let out = vec![b'A'; 64];
        let s = oracle("printable-0.75").unwrap().score(&out, None);
        assert_eq!(s.skipped, 0);
        assert_eq!(s.scored_len, 64);
        assert!(s.passed);
    }

    #[test]
    fn empty_output_never_passes() {
        for id in [
            "printable-1.00",
            "printable-0.75",
            "encoding-valid",
            "english-quadgram",
            "printable-and-english",
            "ioc-english",
        ] {
            let s = oracle(id).unwrap().score(&[], Some(16));
            assert!(!s.passed, "{id} passed an empty output");
            assert_eq!(s.class, ReprClass::Empty);
        }
    }

    /// Every id an existing claim could cite must still resolve, and the
    /// pre-existing oracles' behaviour must be byte-for-byte unchanged by
    /// adding the English scorers alongside them.
    #[test]
    fn pre_existing_oracle_ids_are_unaffected() {
        for id in ["printable-1.00", "printable-0.75", "encoding-valid"] {
            assert!(oracle(id).is_some(), "{id} no longer resolves");
        }
        for id in ["english-quadgram", "printable-and-english"] {
            assert!(oracle(id).is_some(), "{id} does not resolve");
        }

        let mut out = vec![0xFFu8; 32];
        out.extend(std::iter::repeat_n(b'A', 112));
        let naive = oracle("printable-1.00").unwrap().score(&out, Some(32));
        let block = oracle("printable-0.75").unwrap().score(&out, Some(32));
        assert!((naive.score - 112.0 / 144.0).abs() < 1e-12);
        assert!(!naive.passed);
        assert!((block.score - 1.0).abs() < 1e-12);
        assert!(block.passed);
    }

    const KNOWN_GIANT_PLAINTEXTS: [&str; 4] = [
        "The mountain must be searched for the frozen one.",
        "In the cell below the waves is where honor suffers.",
        "When finished we will return to the house and the infinite",
        "A city of fire surrounds the warrior the last of his kind",
    ];

    #[test]
    fn known_plaintexts_pass_the_english_quadgram_oracle_with_margin() {
        let o = oracle("english-quadgram").unwrap();
        for pt in KNOWN_GIANT_PLAINTEXTS {
            let s = o.score(pt.as_bytes(), None);
            assert!(
                s.passed,
                "{pt:?} scored {} < threshold {}",
                s.score, o.threshold
            );
            // margin: at least 1.0 log10-unit of headroom above threshold
            assert!(
                s.score >= o.threshold + 1.0,
                "{pt:?} scored {} with less than 1.0 margin over {}",
                s.score,
                o.threshold
            );
        }
    }

    #[test]
    fn known_plaintexts_pass_the_combined_oracle() {
        let o = oracle("printable-and-english").unwrap();
        for pt in KNOWN_GIANT_PLAINTEXTS {
            assert!(o.score(pt.as_bytes(), None).passed, "{pt:?}");
        }
    }

    /// Deterministic xorshift64* PRNG, kept local so the crate does not take a
    /// `rand` dependency just for test corpora.
    struct Xorshift64(u64);
    impl Xorshift64 {
        fn next_u64(&mut self) -> u64 {
            let mut x = self.0;
            x ^= x << 13;
            x ^= x >> 7;
            x ^= x << 17;
            self.0 = x;
            x.wrapping_mul(0x2545_F491_4F6C_DD1D)
        }
        fn next_byte(&mut self) -> u8 {
            (self.next_u64() & 0xFF) as u8
        }
    }

    /// The core calibration claim: 10,000 uniform-random 144-byte strings —
    /// TG4's candidate length — essentially never pass `english-quadgram`.
    /// This is the empirical false-positive rate reported alongside the
    /// oracle's threshold.
    #[test]
    fn ten_thousand_random_byte_strings_mostly_fail_english_quadgram() {
        let o = oracle("english-quadgram").unwrap();
        let mut rng = Xorshift64(0x9E37_79B9_7F4A_7C15);
        let mut false_positives = 0usize;
        let mut max_score = f64::NEG_INFINITY;
        for _ in 0..10_000 {
            let bytes: Vec<u8> = (0..144).map(|_| rng.next_byte()).collect();
            let s = o.score(&bytes, None);
            if s.passed {
                false_positives += 1;
            }
            max_score = max_score.max(s.score);
        }
        let fp_rate = false_positives as f64 / 10_000.0;
        assert!(
            fp_rate < 0.001,
            "false positive rate {fp_rate} too high (max random score seen: {max_score}, \
             threshold {})",
            o.threshold
        );
    }

    /// Minimal base64 decoder, local to this test so calibrating against
    /// "base64-decoded noise" (rather than raw uniform bytes) doesn't require
    /// a dependency: a random 4-byte base64 group decodes to 3 uniform bytes,
    /// so this checks the oracle isn't fooled by that particular byte
    /// distribution (e.g. no run ever containing 0x00-0x1F control bytes at
    /// the same rate as raw random, since base64's alphabet excludes them
    /// upstream at the encoding step in real pipelines).
    fn base64_decode_group(g: [u8; 4]) -> [u8; 3] {
        fn val(c: u8) -> u32 {
            match c {
                b'A'..=b'Z' => (c - b'A') as u32,
                b'a'..=b'z' => (c - b'a') as u32 + 26,
                b'0'..=b'9' => (c - b'0') as u32 + 52,
                b'+' => 62,
                _ => 63, // '/'
            }
        }
        let n = (val(g[0]) << 18) | (val(g[1]) << 12) | (val(g[2]) << 6) | val(g[3]);
        [(n >> 16) as u8, (n >> 8) as u8, n as u8]
    }

    /// Same calibration, but against noise shaped like a base64-decoded
    /// intermediate layer rather than raw uniform bytes — the other noise
    /// source the spec asks this oracle to be robust against.
    #[test]
    fn ten_thousand_base64_decoded_noise_strings_mostly_fail_english_quadgram() {
        const B64: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
        let o = oracle("english-quadgram").unwrap();
        let mut rng = Xorshift64(0x1234_5678_9ABC_DEF0);
        let mut false_positives = 0usize;
        let mut max_score = f64::NEG_INFINITY;
        for _ in 0..10_000 {
            let mut decoded = Vec::with_capacity(144);
            while decoded.len() < 144 {
                let group = [
                    B64[(rng.next_u64() as usize) % 64],
                    B64[(rng.next_u64() as usize) % 64],
                    B64[(rng.next_u64() as usize) % 64],
                    B64[(rng.next_u64() as usize) % 64],
                ];
                decoded.extend_from_slice(&base64_decode_group(group));
            }
            decoded.truncate(144);
            let s = o.score(&decoded, None);
            if s.passed {
                false_positives += 1;
            }
            max_score = max_score.max(s.score);
        }
        let fp_rate = false_positives as f64 / 10_000.0;
        assert!(
            fp_rate < 0.001,
            "base64-noise false positive rate {fp_rate} too high (max score seen: {max_score}, \
             threshold {})",
            o.threshold
        );
    }

    /// A near-miss: a partly-wrong decrypt (one CFB-8 layer slightly off) must
    /// still be recognised, or the block-aware skip alone is not enough — see
    /// the module docs' warning about a fixed threshold silently rejecting a
    /// correct answer.
    #[test]
    fn ten_percent_corrupted_plaintext_still_passes() {
        let o = oracle("english-quadgram").unwrap();
        let mut rng = Xorshift64(0x0C0F_FEE1_5BAD_5EED);
        for pt in KNOWN_GIANT_PLAINTEXTS {
            let mut chars: Vec<u8> = pt.bytes().collect();
            let n_corrupt = (chars.len() / 10).max(1);
            for _ in 0..n_corrupt {
                let idx = (rng.next_u64() as usize) % chars.len();
                let letter = b'a' + (rng.next_u64() as u8 % 26);
                chars[idx] = letter;
            }
            let s = o.score(&chars, None);
            assert!(
                s.passed,
                "corrupted {:?} scored {} < threshold {}",
                String::from_utf8_lossy(&chars),
                s.score,
                o.threshold
            );
        }
    }

    /// The regression case: a real T1 sweep candidate — `opaque` class, mostly
    /// non-printable bytes with a scattering of embedded letters — scored
    /// -5.3085 under the pre-recalibration threshold (-5.4) and passed
    /// `english-quadgram`. These exact bytes are a synthetic near-miss found by
    /// this crate's own 57,500,000-sample offline search (see the `english`
    /// module docs) in the same neighbourhood: -5.346 at scored_len 112,
    /// clearing the letter-count gate. It must be rejected after recalibration.
    #[test]
    fn a_high_scoring_noise_sample_like_the_reported_false_positive_is_rejected() {
        #[rustfmt::skip]
        const NEAR_MISS_NOISE: [u8; 112] = [
            211, 118, 69, 145, 26, 239, 21, 254, 22, 1, 163, 22, 47, 2, 66, 86,
            21, 100, 153, 75, 246, 215, 67, 101, 32, 84, 175, 28, 111, 99, 246,
            171, 195, 61, 231, 49, 174, 189, 91, 55, 133, 97, 101, 84, 151, 197,
            72, 224, 101, 126, 1, 36, 241, 96, 83, 112, 65, 83, 193, 66, 68, 66,
            218, 112, 252, 199, 244, 154, 30, 43, 87, 81, 239, 144, 216, 247,
            60, 215, 146, 76, 101, 44, 166, 166, 88, 69, 11, 202, 6, 151, 183,
            163, 48, 6, 59, 209, 32, 57, 94, 42, 179, 6, 141, 202, 252, 196,
            204, 227, 126, 235, 167, 175,
        ];

        let o = oracle("english-quadgram").unwrap();
        let s = o.score(&NEAR_MISS_NOISE, None);
        assert!(
            s.score > -5.4 && s.score < -5.2,
            "expected this fixture in the -5.3-ish neighbourhood, got {}",
            s.score
        );
        assert!(
            !s.passed,
            "a noise sample scoring {} in the neighbourhood of the reported \
             false positive (-5.3085) must NOT pass after recalibration",
            s.score
        );

        // The combined oracle rejects it even more decisively: this fixture is
        // mostly non-ASCII-graphic bytes, so it fails the printable floor too.
        let combined = oracle("printable-and-english")
            .unwrap()
            .score(&NEAR_MISS_NOISE, None);
        assert!(!combined.passed);
    }

    /// The false-positive model must be a real estimate, not the degenerate
    /// "every candidate passes" placeholder (`candidates * 1.0`) reported in
    /// production before this recalibration.
    #[test]
    fn quadgram_false_positive_model_is_not_degenerate() {
        let p = p_quadgram_false_positive(112);
        assert!(
            p > 0.0 && p < 1e-6,
            "expected a small non-degenerate per-candidate rate, got {p}"
        );

        // The production case that motivated this fix: 5,768 scorable outputs.
        // The old model reported 5.768e3 (i.e. probability 1.0 per candidate).
        // The new model must report a small, honest number in the same
        // ballpark as what was actually observed (2 hits).
        let expected = expected_false_positives(5768.0, p);
        assert!(
            expected < 1.0,
            "expected false positives over 5,768 outputs should be well under 1, got {expected}"
        );

        // And at T3 sweep scale (163.92e6 candidates), the honest answer is
        // "not negligible" — this is the number that licenses recommending
        // printable-and-english over bare english-quadgram at that scale.
        let at_scale = expected_false_positives(163.92e6, p);
        assert!(
            (1.0..100.0).contains(&at_scale),
            "expected a double-digit-ish, non-negligible figure at sweep scale, got {at_scale}"
        );
    }

    /// The recommended combined oracle keeps `printable-0.75`'s already-tiny
    /// false-positive rate (~1e-21 at 144 bytes), because the printable floor
    /// dominates — it is what actually closes the gap `english-quadgram`
    /// alone cannot.
    #[test]
    fn combined_oracle_inherits_the_printable_floors_negligible_false_positive_rate() {
        let printable_rate = p_ratio_printable(144, 0.75);
        let quadgram_rate = p_quadgram_false_positive(144);
        // The combined oracle requires both, so its true rate is at most the
        // smaller of the two (in fact tighter, since it's a joint condition).
        assert!(printable_rate.min(quadgram_rate) < 1e-15);
    }

    /// POSITIVE CONTROL for `ioc-english`: real corpus data, not a synthetic
    /// fixture. This is rev6's actual chain, `decimal | reverse | hex_to_base64
    /// | serpent:key=Zombies,mode=cfb` — reproduced end to end by this crate's own
    /// conformance suite (`ra conformance`; see `crates/ra-cli/src/corpus.rs`'s
    /// `rev6`/`Serpent` vector) — up to but not including the final classical
    /// substitution step. That final step is exactly what `ioc-english` exists
    /// to recognise in place of: a monoalphabetic substitution of English
    /// (alphabet `hdixvqlmenojkpbrstcufwgyza`) that `english-quadgram` cannot
    /// see as English, because substitution scrambles quadgram statistics while
    /// preserving coincidence structure.
    #[test]
    fn ioc_english_fires_on_rev6s_real_substituted_intermediate() {
        const REV6_SERPENT_OUTPUT: &[u8] =
            b"ka ykhociq vazr vcgg vi bk vaij xktp skji gcei vcraktr xkt vcgg \
              oi btgg otr cr cq rchi rk sk qkhivaipi jiv zjb qcjs z jiv qkjs";
        let o = oracle("ioc-english").unwrap();
        let s = o.score(REV6_SERPENT_OUTPUT, None);
        assert!(
            s.scored_len >= 99,
            "expected the fixture to clear the letter gate comfortably, got {} letters scored",
            s.scored_len
        );
        assert!(
            s.score > 0.06,
            "rev6's substituted output should score close to English's ~0.0667, got {}",
            s.score
        );
        assert!(
            s.passed,
            "rev6's real substituted intermediate must pass ioc-english, scored {} < threshold {}",
            s.score, o.threshold
        );
    }

    /// NEGATIVE CONTROL for `ioc-english`, equally mandatory: uniform-random
    /// letters at rev6's exact letter count (99) must not pass at anything
    /// close to the rate a real hit would — a detector with no negative
    /// control is worse than none, because it cannot be distinguished from
    /// "fires on everything".
    #[test]
    fn ioc_english_does_not_fire_on_random_letters_of_rev6s_length() {
        let o = oracle("ioc-english").unwrap();
        let mut rng = Xorshift64(0x1DEA_C0DE_FEED_FACE);
        let mut false_positives = 0usize;
        let trials = 10_000;
        for _ in 0..trials {
            let letters: Vec<u8> = (0..99)
                .map(|_| b'A' + (rng.next_u64() % 26) as u8)
                .collect();
            if o.score(&letters, None).passed {
                false_positives += 1;
            }
        }
        let fp_rate = false_positives as f64 / trials as f64;
        // The calibration table (see the `ioc` module docs) predicts ~3e-5 at
        // n=99; over only 10,000 trials, "well under 1%" is the honest bound
        // this sample size can assert without flaking.
        assert!(
            fp_rate < 0.01,
            "random-letter false positive rate {fp_rate} too high at n=99"
        );
    }

    /// NEGATIVE CONTROL, second form: uniform-random *bytes* (not letters) of
    /// rev6's exact output length must not pass either. This is the more
    /// realistic noise source (a genuine wrong decrypt), and it fails even
    /// more easily here because far fewer than 99 of 127 random bytes are
    /// letters at all, so most trials never clear the letter-count gate.
    #[test]
    fn ioc_english_does_not_fire_on_random_bytes_of_rev6s_length() {
        let o = oracle("ioc-english").unwrap();
        let mut rng = Xorshift64(0xBAD5_EED1_2345_6789);
        let mut false_positives = 0usize;
        let trials = 10_000;
        for _ in 0..trials {
            let bytes: Vec<u8> = (0..127).map(|_| (rng.next_u64() & 0xFF) as u8).collect();
            if o.score(&bytes, None).passed {
                false_positives += 1;
            }
        }
        assert_eq!(
            false_positives, 0,
            "uniform-random bytes at rev6's length must not pass ioc-english"
        );
    }

    /// The false-positive model must be a real estimate, not the degenerate
    /// "every candidate passes" placeholder, mirroring the same regression
    /// this crate already pins for `english-quadgram`.
    #[test]
    fn ioc_false_positive_model_is_not_degenerate() {
        let p = p_ioc_false_positive(99);
        assert!(
            p > 0.0 && p < 1e-3,
            "expected a small non-degenerate per-candidate rate at n=99, got {p}"
        );
        // Grows with scored length, same shape as `p_quadgram_false_positive`:
        // more raw bytes means the letter-count gate itself is easier to
        // clear by chance, even though the *conditional* tail probability
        // (given the gate is cleared) falls with length.
        assert!(p_ioc_false_positive(144) > p_ioc_false_positive(99));
    }

    /// False positives must be negligible over the bounded programme, which is what
    /// licenses the inference "no hit found" => "the answer is outside this space".
    #[test]
    fn false_positive_rates_are_negligible_over_the_bounded_space() {
        let tg4_all = p_all_printable(144);
        assert!(tg4_all < 1e-60, "got {tg4_all:e}");

        let tg4_75 = p_ratio_printable(144, 0.75);
        assert!(
            tg4_75 > 0.0 && tg4_75 < 1e-15,
            "0.75-threshold rate out of expected band: {tg4_75:e}"
        );

        // Document 4's headline: essentially zero expected false positives over T1-T4
        let expected = expected_false_positives(1.5e9, tg4_75);
        assert!(expected < 1e-6, "expected {expected:e} false positives");
    }

    #[test]
    fn binomial_tail_is_sane_at_the_extremes() {
        assert!((p_ratio_printable(10, 0.0) - 1.0).abs() < 1e-9);
        assert!((p_ratio_printable(10, 1.0) - p_all_printable(10)).abs() < 1e-12);
        // monotone decreasing in the threshold
        assert!(p_ratio_printable(64, 0.5) > p_ratio_printable(64, 0.75));
    }
}

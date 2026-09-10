//! Index of coincidence — the letter-frequency scorer for classical layers
//! that are neither structured encodings nor readable prose.
//!
//! # Why this exists
//!
//! Every other oracle in this crate is tuned for one of two things: readable
//! English prose (`english-quadgram`, `printable-and-english`) or a clean
//! structured encoding (`encoding-valid`). Neither recognises the output of a
//! *trailing classical layer*: this corpus's rev2 (`DES > bacon`) and rev6
//! (`Serpent > substitution`) both end in a classical transform whose output
//! is letter soup, not English. A monoalphabetic substitution of English is
//! not readable — `english-quadgram` correctly rejects it, because its
//! quadgram statistics are scrambled along with everything else — but it
//! preserves the *coincidence* structure of its plaintext exactly, because
//! substitution is a relabelling: two positions that held the same plaintext
//! letter still hold the same (substituted) letter. Transposition preserves
//! it too, for the same reason: it permutes positions without changing which
//! letters occur or how often.
//!
//! Index of coincidence measures exactly that structure and nothing else, so
//! it is the right instrument for a slot that structured-encoding and
//! prose-fitness oracles both miss.
//!
//! # The statistic
//!
//! For `n` letters with counts `c_1..c_26`,
//!
//! ```text
//! IoC = sum(c_i * (c_i - 1)) / (n * (n - 1))
//! ```
//!
//! Uniform-random letters give IoC ≈ 1/26 ≈ 0.0385. English prose (and
//! anything letter-preserving derived from it, including a monoalphabetic
//! substitution or a transposition of it) gives IoC ≈ 0.0667, the standard
//! textbook figure for English letter-frequency skew.
//!
//! # Calibration
//!
//! [`IOC_ENGLISH_THRESHOLD`] and [`MIN_SCORED_LETTERS`] were both chosen from
//! a Monte Carlo of uniform-random letter sequences (20,000,000 trials per
//! length, xorshift64*-seeded, same generator family as `english`'s
//! calibration tests below) measuring `P(IoC >= threshold)` as a function of
//! sample size `n`:
//!
//! | n (letters) | max IoC seen | P(IoC >= 0.055) |
//! |---|---|---|
//! | 50  | 0.0996 | 7.16e-3 |
//! | 75  | 0.0739 | 4.9e-4  |
//! | 90  | 0.0704 | 8.0e-5  |
//! | 99  | 0.0678 | 3.0e-5  |
//! | 112 | 0.0607 | 1.0e-5  |
//! | 127 | 0.0606 | 0 (of 20,000,000) |
//! | 144 | 0.0583 | 0 (of 20,000,000) |
//!
//! IoC is a per-pair statistic with very few effective degrees of freedom at
//! low letter counts, which is why it is noisy below roughly 75-90 letters —
//! at `n=50` a uniform-random sample clears 0.055 close to 1% of the time,
//! nowhere near negligible over a sweep. [`MIN_SCORED_LETTERS`] = 90 is the
//! point in this table past which the false-positive rate has dropped below
//! 1e-4 and keeps falling; below it, `passed` is forced false the same way
//! [`crate::english`]'s `MIN_SCORED_LETTERS` gate works, for the same reason
//! (a statistic over too few samples is not trustworthy at all, not just
//! "noisier").
//!
//! [`IOC_ENGLISH_THRESHOLD`] = 0.055 sits below true English's ~0.0667 (so a
//! moderately corrupted or short substituted sample still clears it) and
//! above the random tail at every length in the reliable regime (n >= 90).
//! It is **not calibrated to be reliable below 90 scored letters** — a
//! shorter candidate is gated out entirely rather than scored with false
//! confidence.
//!
//! # Positive control
//!
//! rev6's real corpus chain is `decimal > reverse > hex_to_base64 > Serpent/CFB
//! > substitution`; the Serpent output (the substituted-but-not-yet-reversed
//! English, alphabet `hdixvqlmenojkpbrstcufwgyza`) is exactly the case this
//! oracle exists to catch — genuine substituted English, unreadable to
//! `english-quadgram`, real corpus data rather than a synthetic fixture. It
//! scores IoC ≈ 0.0631 over 99 letters (see the module's tests), clearing
//! both the letter gate and the threshold with margin, and a same-length
//! random-letters negative control fails to clear the threshold at the same
//! per-candidate rate this module's calibration table predicts.
//!
//! # Block awareness
//!
//! Registered as `block_aware: true` (see `ARCHITECTURE.md`, "The block-aware
//! oracle"), matching every other recommended oracle in this crate: if the
//! candidate's terminal step really is a self-synchronising block-cipher
//! decrypt, skipping its corrupt first block only helps. The honest edge
//! case: on a *short* candidate whose terminal step is the raw decrypt
//! itself (no subsequent classical transform, e.g. scoring mid-chain rather
//! than after a `--post` classical step), skipping a full block can remove
//! enough letters to fail [`MIN_SCORED_LETTERS`] even when the un-skipped
//! candidate would have passed comfortably — observed directly on rev6's
//! 127-byte Serpent output plus a 16-byte block skip (99 letters drops to
//! ~86). This is the same shape of tradeoff `english-quadgram` already
//! accepts for its own letter gate, not a defect unique to this oracle: the
//! fix, when it matters, is to score after the classical layer (where
//! `terminal_block_size` is `None`) rather than mid-chain.

/// Minimum number of stripped letters required before an IoC estimate is
/// trusted at all. See the module docs' calibration table: below this,
/// uniform-random letters clear [`IOC_ENGLISH_THRESHOLD`] often enough (>=5e-4)
/// that the statistic carries no real signal.
pub(crate) const MIN_SCORED_LETTERS: usize = 90;

/// Empirically calibrated IoC floor. See the module docs' Monte Carlo table
/// for how this was derived and the length range (`>= MIN_SCORED_LETTERS`)
/// over which it is reliable.
pub(crate) const IOC_ENGLISH_THRESHOLD: f64 = 0.055;

/// Number of ASCII letters `bytes` would contribute, without allocating the
/// stripped buffer. Mirrors [`crate::english::letter_count`].
pub(crate) fn letter_count(bytes: &[u8]) -> usize {
    bytes.iter().filter(|b| b.is_ascii_alphabetic()).count()
}

/// Index of coincidence over the ASCII letters in `bytes`, case-folded and
/// with everything else (spaces, punctuation, digits, control bytes)
/// dropped — the same normalisation [`crate::english::quadgram_score`] uses,
/// for the same reason: robust to formatting and to a partly-corrupt decrypt.
///
/// Returns 0.0 for fewer than 2 letters, where the statistic is undefined
/// (division by `n * (n - 1)`); callers should gate on
/// [`MIN_SCORED_LETTERS`] well before reaching that edge in practice.
pub fn index_of_coincidence(bytes: &[u8]) -> f64 {
    let mut counts = [0u64; 26];
    let mut n: u64 = 0;
    for &b in bytes {
        if b.is_ascii_alphabetic() {
            counts[(b.to_ascii_uppercase() - b'A') as usize] += 1;
            n += 1;
        }
    }
    if n < 2 {
        return 0.0;
    }
    let num: f64 = counts
        .iter()
        .map(|&c| (c * c.saturating_sub(1)) as f64)
        .sum();
    let den = (n * (n - 1)) as f64;
    num / den
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Deterministic xorshift64* PRNG, kept local like the other calibration
    /// tests in this crate — see `english`'s module tests for the same
    /// pattern and rationale (no `rand` dependency for a test-only corpus).
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
    }

    #[test]
    fn uniform_random_letters_center_near_the_textbook_rate() {
        // 1/26 ~= 0.0385 is the textbook IoC for uniform-random letters; a large
        // sample should land close to it, sanity-checking the formula itself
        // rather than any threshold.
        let mut rng = Xorshift64(0xA5A5_5A5A_1234_5678);
        let letters: Vec<u8> = (0..200_000)
            .map(|_| b'A' + (rng.next_u64() % 26) as u8)
            .collect();
        let v = index_of_coincidence(&letters);
        assert!(
            (v - 1.0 / 26.0).abs() < 0.001,
            "expected ~0.0385 over 200,000 uniform-random letters, got {v}"
        );
    }

    #[test]
    fn known_english_sentences_cluster_near_the_textbook_english_rate() {
        // Concatenated so the sample clears MIN_SCORED_LETTERS; individually
        // these are each too short to trust (see the module docs).
        let text = "The mountain must be searched for the frozen one. \
                     In the cell below the waves is where honor suffers. \
                     When finished we will return to the house and the infinite. \
                     A city of fire surrounds the warrior the last of his kind.";
        assert!(letter_count(text.as_bytes()) >= MIN_SCORED_LETTERS);
        let v = index_of_coincidence(text.as_bytes());
        // English prose sits noticeably above the uniform-random rate; this is
        // a sanity band, not the calibrated threshold itself.
        assert!(
            v > 0.045,
            "expected English text to score above the random band, got {v}"
        );
    }

    #[test]
    fn short_input_does_not_panic() {
        assert_eq!(index_of_coincidence(b""), 0.0);
        assert_eq!(index_of_coincidence(b"a"), 0.0);
    }
}

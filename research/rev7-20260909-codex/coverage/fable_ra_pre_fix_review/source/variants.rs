//! Transcription glyph variants: the `0.variant` coverage dimension, **derived from
//! the ciphertext at runtime**.
//!
//! # What the dimension is
//!
//! A recorded ciphertext is a *transcription of an image*, not a byte string. TG4's is
//! rendered in an Oswald-derived face, and two glyph pairs in it are candidates for
//! misreading — `I`/`l` and `0`/`O`. Both members of each pair are valid base64, so on
//! the face of it both readings are admissible at every occurrence.
//!
//! Only one of the two pairs is actually open:
//!
//! | pair | occurrences in TG4 | status |
//! |---|---|---|
//! | `0` / `O` | 7 | **resolved.** The project team reviewed the transcript against the font that was actually used and confirmed the recorded readings. Not enumerated. |
//! | `I` / `l` | 7 | **open.** Capital i and lower-case L are near-identical in that face. Enumerated. |
//!
//! The `0`/`O` resolution is *external ground truth about the artefact* — a human
//! reading of the source, not something derivable from the corpus — and it is what
//! makes the space `2^7 = 128` rather than `2^14 = 16,384`. It is recorded in
//! `ARCHITECTURE.md` with that provenance attached, because its evidential status is
//! not the same as a measurement.
//!
//! [`AMBIGUOUS_PAIRS`] is therefore `{(I, l)}` alone, and
//! [`RESOLVED_PAIRS`] records `{(0, O)}` so the resolution is a stated fact in the code
//! rather than an absence. `no_resolved_glyph_is_ever_enumerated` asserts that no
//! `0`/`O` position enters the variant space, so re-opening that pair has to be a
//! deliberate edit rather than a regression.
//!
//! # Why the positions are derived and not written down
//!
//! Hardcoding the 7 offsets would silently rot the moment the corpus record were
//! corrected — a re-transcription that added or moved an ambiguous glyph would leave
//! the sweep enumerating a space the ciphertext no longer has, while the claim went on
//! asserting the old one. So [`VariantSpace::derive`] scans the compacted display text
//! for members of `{I, l}`, and
//! [`tests::tg4_derives_the_seven_open_ambiguous_positions`] pins the result against
//! the recorded offsets so that a change to the corpus is **loud**.
//!
//! # Why REV7 has no variants, computed rather than assumed
//!
//! A glyph is only ambiguous if its partner is also admissible *in that display's
//! alphabet*. REV7's transcription is hex, and hex excludes `O`, `I` and `l`, so no
//! position there is ambiguous under either pair. Making admissibility display-aware
//! turns the dossier's "REV7 is unambiguous" from an assumption into an output — see
//! [`tests::hex_transcriptions_have_no_glyph_ambiguity`].
//!
//! # Labels
//!
//! A variant is identified by a **bit mask over the open ambiguous positions in
//! ascending offset order**: bit `i` clear means the *recorded* glyph at position `i`,
//! bit `i` set means its partner. The label is `v` followed by the mask in lower-case
//! hex, zero-padded to cover every position — so TG4's domain is `v00 .. v7f` and
//! **`v00` is exactly the reading the corpus records**. The label depends only on the
//! mask and the position count, so claims from different runs and different tools are
//! directly comparable.
//!
//! Masks are enumerated in plain numeric order, and the whole `positions`-wide space
//! is small enough (128 for TG4) that every tier could sweep it exhaustively. There is
//! no prioritisation to justify and no bound to log: an unnarrowed run's claim covers
//! the complete `positions`-wide variant space.
//!
//! The corpus measurement that independently corroborates the team's `0`/`O` finding —
//! 177 glyph calls verified by single-flip perturbation with zero errors, 89 of them
//! `0`/`O` and 88 `I`/`l` — is recorded in `ARCHITECTURE.md`. Its consequence here is
//! only an expectation, not a constraint: if TG4 has a solve, `v00` is the reading most
//! likely to carry it, among whichever readings are admissible.
//!
//! # Canonical transcriptions narrow admissibility, not the label space
//!
//! A corpus record may additionally carry a `ciphertext_canonical` field: a
//! project-supplied re-reading that resolves some or all of the still-open positions
//! against the source. In it, a resolved position is a plain glyph and a
//! still-open one is spelled `(A/B)`. [`VariantSpace::derive_canonical`] narrows
//! [`VariantSpace::count`] and [`VariantSpace::masks`] — and so the `all` selector —
//! to just the masks consistent with that text, without touching the label space
//! itself: `v4c` and `v6c` name exactly the bytes they always did, whether or not a
//! canonical transcription is in play, because a claim already committed to those
//! labels (see `claims/tg4-canonical-2026-07-30.json`) must go on meaning the same
//! thing. TG4's canonical transcription resolves six of its seven open `I`/`l`
//! positions and leaves the seventh (offset 90) genuinely open, so the space it
//! admits is `{v4c, v6c}` — 2 readings, not 128 — even though `v00 .. v7f` are all
//! still valid *labels*. See [`tests::canonical_narrows_tg4_to_v4c_and_v6c`].

use anyhow::{bail, Context, Result};
use ra_core::Display;

/// Glyph pairs that remain genuinely ambiguous in the source and are therefore
/// enumerated.
pub const AMBIGUOUS_PAIRS: [(u8, u8); 1] = [(b'I', b'l')];

/// Glyph pairs that *look* confusable but have been resolved against the source, and
/// are therefore fixed to the recorded reading.
///
/// This is a statement, not a leftover: `0`/`O` was resolved by the project team's
/// direct review of the font the transcript was made from. Keeping it here — rather
/// than simply deleting the pair — is what lets
/// `no_resolved_glyph_is_ever_enumerated` check that the resolution holds, and what
/// tells a later reader that the omission was decided rather than overlooked.
pub const RESOLVED_PAIRS: [(u8, u8); 1] = [(b'0', b'O')];

/// Refuse to build a variant space bigger than this many positions. `1 << n` has to
/// fit a `u64` index space alongside every cipher axis, and a space this large is a
/// modelling error rather than a run worth attempting.
const MAX_POSITIONS: usize = 24;

/// The characters a display can hold. Used to decide whether a glyph's partner is
/// even admissible: `O` is not a hex digit, so a hex `0` is unambiguous.
pub fn display_alphabet(d: Display) -> &'static str {
    match d {
        Display::Hex => "0123456789ABCDEFabcdef",
        Display::Decimal => "0123456789",
        Display::Octal => "01234567",
        Display::Base64 => {
            "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/="
        }
        // Raw bytes are not glyphs; there is nothing to misread.
        Display::Bytes => "",
    }
}

/// The other member of `c`'s *open* ambiguous pair, if it has one.
pub fn partner(c: u8) -> Option<u8> {
    pair_partner(&AMBIGUOUS_PAIRS, c)
}

/// The other member of `c`'s *resolved* pair, if it has one. Used only to check that
/// resolved glyphs stay out of the enumeration.
pub fn resolved_partner(c: u8) -> Option<u8> {
    pair_partner(&RESOLVED_PAIRS, c)
}

fn pair_partner(pairs: &[(u8, u8)], c: u8) -> Option<u8> {
    for &(a, b) in pairs {
        if c == a {
            return Some(b);
        }
        if c == b {
            return Some(a);
        }
    }
    None
}

/// One glyph of `canonical` at each *virtual* offset — the offset it would occupy
/// once every `(A/B)` marker is collapsed to the single glyph it stands for. `None`
/// at a virtual offset means `canonical` still marks it open there.
fn canonical_glyphs(canonical: &[u8]) -> Result<Vec<Option<u8>>> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < canonical.len() {
        if canonical[i] == b'(' {
            let close = canonical[i..]
                .iter()
                .position(|&c| c == b')')
                .map(|p| i + p)
                .with_context(|| {
                    format!("canonical transcription has an unclosed '(' at offset {i}")
                })?;
            let marker = &canonical[i + 1..close];
            anyhow::ensure!(
                marker.len() == 3 && marker[1] == b'/',
                "canonical transcription's marker at offset {i} is not the expected \
                 (A/B) shape: {:?}",
                String::from_utf8_lossy(&canonical[i..=close])
            );
            out.push(None);
            i = close + 1;
        } else {
            out.push(Some(canonical[i]));
            i += 1;
        }
    }
    Ok(out)
}

/// The masks a canonical transcription admits, given the legacy `positions` /
/// `recorded` / `alternative` triple `derive` computed. Generic over how many
/// positions the canonical text still leaves open — `(A/B)` markers of its own — so a
/// canonical transcription that resolves every position, or that resolves none,
/// enumerates correctly without a special case.
fn canonical_masks(
    canonical: &[u8],
    positions: &[usize],
    recorded: &[u8],
    alternative: &[u8],
) -> Result<Vec<u32>> {
    let glyphs = canonical_glyphs(canonical)?;
    // `fixed[i]` is `Some(bit)` when the canonical transcription pins position `i` to
    // one glyph, `None` when it leaves that position open too.
    let mut fixed: Vec<Option<u32>> = Vec::with_capacity(positions.len());
    for (i, &off) in positions.iter().enumerate() {
        let g = glyphs.get(off).copied().unwrap_or(None);
        let bit = match g {
            None => None,
            Some(c) if c == recorded[i] => Some(0),
            Some(c) if c == alternative[i] => Some(1),
            Some(c) => bail!(
                "canonical transcription's glyph at offset {off} is {:?}, neither the \
                 recorded {:?} nor its partner {:?}",
                c as char,
                recorded[i] as char,
                alternative[i] as char
            ),
        };
        fixed.push(bit);
    }
    let free: Vec<usize> = (0..fixed.len()).filter(|&i| fixed[i].is_none()).collect();
    let base: u32 = fixed
        .iter()
        .enumerate()
        .filter_map(|(i, b)| b.map(|bit| bit << i))
        .sum();
    let mut masks: Vec<u32> = (0..1u32 << free.len())
        .map(|combo| {
            let mut mask = base;
            for (j, &i) in free.iter().enumerate() {
                mask |= ((combo >> j) & 1) << i;
            }
            mask
        })
        .collect();
    masks.sort_unstable();
    Ok(masks)
}

/// The admissible transcriptions of one recorded ciphertext.
pub struct VariantSpace {
    /// Offsets into the *compacted* display text, ascending.
    positions: Vec<usize>,
    /// The glyph the corpus records at each position.
    recorded: Vec<u8>,
    /// The other admissible glyph at each position.
    alternative: Vec<u8>,
    /// Hex digits in a label, so every label of one space has the same width.
    width: usize,
    /// Domain value to use when there is no ambiguity at all, so a target with a
    /// one-point variant dimension still gets a distinguishable label rather than
    /// borrowing another cipher's.
    exact_label: String,
    /// The masks a project-supplied canonical transcription still admits, ascending.
    /// Every mask still names a full point in the `positions`-wide space (so labels,
    /// `apply`, and `describe` are unaffected), but only these are what `count` and
    /// `masks` — and therefore the `all` selector — report. Equal to every mask in
    /// the space when no canonical transcription was supplied: the un-narrowed
    /// behaviour is exactly this field defaulting to the full enumeration.
    admissible: Vec<u32>,
}

impl VariantSpace {
    /// Scan `compact` (the display text with whitespace removed) for glyphs whose
    /// *open* ambiguity partner is also admissible in `display`. Every mask in the
    /// resulting space is admissible: there is no canonical transcription narrowing
    /// it further.
    pub fn derive(compact: &[u8], display: Display, exact_label: &str) -> Result<VariantSpace> {
        Self::derive_canonical(compact, None, display, exact_label)
    }

    /// As [`Self::derive`], but additionally narrowed by `canonical` — the compacted
    /// text of a project-supplied canonical transcription, in which a still-open
    /// position is spelled `(A/B)` (both glyphs literal, in either order) and every
    /// other position is a single resolved glyph.
    ///
    /// The label space, and everything `apply`/`describe`/`label`/`parse_label` do
    /// with a mask, is unchanged — a claim naming `v4c` still means exactly the same
    /// bytes it always did, canonical or not. Only which masks count as *admissible*
    /// narrows: [`Self::count`], [`Self::masks`], and `select("all")` report only the
    /// masks consistent with `canonical`, while an explicit label list can still name
    /// any point in the wider, pre-canonical space.
    pub fn derive_canonical(
        compact: &[u8],
        canonical: Option<&[u8]>,
        display: Display,
        exact_label: &str,
    ) -> Result<VariantSpace> {
        let alphabet = display_alphabet(display).as_bytes();
        let mut positions = Vec::new();
        let mut recorded = Vec::new();
        let mut alternative = Vec::new();
        for (i, &c) in compact.iter().enumerate() {
            let Some(p) = partner(c) else { continue };
            if !alphabet.contains(&c) || !alphabet.contains(&p) {
                continue;
            }
            positions.push(i);
            recorded.push(c);
            alternative.push(p);
        }
        if positions.len() > MAX_POSITIONS {
            bail!(
                "{} ambiguous glyph positions is {} variants, past this command's \
                 {MAX_POSITIONS}-position limit; the index space would not fit a u64 \
                 alongside the cipher axes",
                positions.len(),
                1u128 << positions.len()
            );
        }
        let n = positions.len();
        let admissible = match canonical {
            Some(c) => canonical_masks(c, &positions, &recorded, &alternative)?,
            None => (0..1u32 << n).collect(),
        };
        Ok(VariantSpace {
            positions,
            recorded,
            alternative,
            width: n.div_ceil(4).max(1),
            exact_label: exact_label.to_string(),
            admissible,
        })
    }

    /// Ambiguous offsets into the compacted display text, ascending.
    pub fn positions(&self) -> &[usize] {
        &self.positions
    }

    /// The subset of [`Self::positions`] that is **still** open once a canonical
    /// transcription's narrowing is accounted for — the positions where the
    /// admissible masks actually disagree. Equal to [`Self::positions`] when no
    /// canonical transcription narrowed the space.
    pub fn open_positions(&self) -> Vec<usize> {
        self.positions
            .iter()
            .enumerate()
            .filter(|(i, _)| {
                let bit = |m: u32| (m >> i) & 1;
                self.admissible.windows(2).any(|w| bit(w[0]) != bit(w[1]))
            })
            .map(|(_, &off)| off)
            .collect()
    }

    /// Whether this transcription has any open glyph ambiguity at all.
    pub fn is_ambiguous(&self) -> bool {
        !self.positions.is_empty()
    }

    /// Number of admissible transcriptions: `2^|positions|`, or fewer when a
    /// canonical transcription narrowed the space.
    pub fn count(&self) -> u64 {
        self.admissible.len() as u64
    }

    /// The census of open ambiguous glyphs, as `(glyph, occurrences)` in pair order.
    pub fn census(&self) -> Vec<(u8, usize)> {
        let mut out = Vec::new();
        for (a, b) in AMBIGUOUS_PAIRS {
            for g in [a, b] {
                let n = self.recorded.iter().filter(|&&c| c == g).count();
                if n > 0 {
                    out.push((g, n));
                }
            }
        }
        out
    }

    /// Offsets carrying a glyph of a **resolved** pair. Not part of the variant space;
    /// reported so that "seven positions were fixed, not overlooked" is visible.
    pub fn resolved_positions(compact: &[u8], display: Display) -> Vec<usize> {
        let alphabet = display_alphabet(display).as_bytes();
        (0..compact.len())
            .filter(|&i| {
                resolved_partner(compact[i])
                    .is_some_and(|p| alphabet.contains(&compact[i]) && alphabet.contains(&p))
            })
            .collect()
    }

    /// The stable domain value for `mask`. `v00` is the recorded reading.
    pub fn label(&self, mask: u32) -> String {
        if !self.is_ambiguous() {
            return self.exact_label.clone();
        }
        format!("v{:0width$x}", mask, width = self.width)
    }

    /// Every mask the label space can name, whether or not a canonical
    /// transcription still admits it — `2^|positions|`. `parse_label` is checked
    /// against this, not [`Self::count`], so an explicit label list can still name a
    /// point a canonical transcription has narrowed away, which is how the wider
    /// pre-canonical space stays reachable.
    fn label_space_size(&self) -> u64 {
        1u64 << self.positions.len()
    }

    /// Inverse of [`Self::label`], so a claim's domain value round-trips back to the
    /// transcription it names.
    pub fn parse_label(&self, s: &str) -> Option<u32> {
        if !self.is_ambiguous() {
            return (s == self.exact_label).then_some(0);
        }
        let hex = s.strip_prefix('v')?;
        let m = u32::from_str_radix(hex, 16).ok()?;
        (u64::from(m) < self.label_space_size()).then_some(m)
    }

    /// Every admissible mask, in numeric order. Equal to `0..2^|positions|` when no
    /// canonical transcription narrowed the space, in which case `masks()[0] == 0` is
    /// the recorded reading; narrower otherwise, and not necessarily contiguous or
    /// including `0`.
    pub fn masks(&self) -> Vec<u32> {
        self.admissible.clone()
    }

    /// Resolve a `--variants` selector.
    ///
    /// - `all` — every transcription a canonical resolution still admits (every
    ///   transcription at all, when there is none). This is what narrows with a
    ///   canonical transcription; the wider, pre-canonical space stays reachable
    ///   through an explicit label list below.
    /// - `recorded` — the single reading that keeps every *still-open* position at its
    ///   legacy glyph, among the masks a canonical transcription admits: `v00` when no
    ///   canonical transcription narrowed the space (the pre-correction behaviour, and
    ///   still `v00` because `v00` is always admissible in that case), but whichever
    ///   admissible mask that is once a canonical transcription is in play — `v10` for
    ///   a canonical that fully resolves TG4, since `v00` is not even an admissible
    ///   reading there. [`Self::masks`] is sorted ascending and every admissible mask
    ///   is a fixed base OR'd with some subset of the still-open bits, so its first
    ///   entry is exactly that reading — never a hardcoded `0`, which is what silently
    ///   fed the wrong ciphertext to a sweep before a canonical transcription existed
    ///   to disagree with it.
    /// - a comma-separated list of labels — exactly those, canonically ordered. Any
    ///   label in the full `positions`-wide space is accepted here, admissible or not.
    pub fn select(&self, spec: &str) -> Result<Vec<u32>> {
        let s = spec.trim();
        if s.eq_ignore_ascii_case("recorded") {
            return Ok(vec![*self
                .admissible
                .first()
                .expect("admissible is never empty")]);
        }
        if s.eq_ignore_ascii_case("all") {
            return Ok(self.masks());
        }
        let mut picked: Vec<u32> = Vec::new();
        for tok in s.split(',').map(str::trim).filter(|t| !t.is_empty()) {
            let m = self.parse_label(tok).with_context(|| {
                format!(
                    "--variants {spec:?}: {tok:?} is not a variant label of this target \
                     (expected recorded, all, or labels {}..{})",
                    self.label(0),
                    self.label((self.label_space_size() - 1) as u32)
                )
            })?;
            if !picked.contains(&m) {
                picked.push(m);
            }
        }
        if picked.is_empty() {
            bail!("--variants {spec:?} selects nothing");
        }
        picked.sort_unstable();
        Ok(picked)
    }

    /// Write the transcription named by `mask` into `out`.
    ///
    /// `compact` must be the display text with whitespace removed, because
    /// [`Self::positions`] indexes that text. To splice a mask into text that still
    /// carries its whitespace, use [`Self::apply_preserving_whitespace`].
    pub fn apply(&self, mask: u32, compact: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(compact);
        for (i, &off) in self.positions.iter().enumerate() {
            let glyph = if mask >> i & 1 == 1 {
                self.alternative[i]
            } else {
                self.recorded[i]
            };
            out[off] = glyph;
        }
    }

    /// The glyph `mask` selects at ambiguous position `i`.
    fn glyph(&self, mask: u32, i: usize) -> u8 {
        if mask >> i & 1 == 1 {
            self.alternative[i]
        } else {
            self.recorded[i]
        }
    }

    /// As [`Self::apply`], but splices `mask` into `raw` — the display text with its
    /// **whitespace intact** — and writes whitespace-preserving output.
    ///
    /// [`Self::positions`] are offsets into the *compacted* text, so they cannot index
    /// `raw` directly: position `k` means "the `k`-th non-whitespace character", and in
    /// a whitespace-bearing transcription that sits at a larger raw offset. This walks
    /// `raw`, counting only non-whitespace characters, and substitutes at the counted
    /// position — so a mask names exactly the same *reading* whether it is applied to
    /// the compacted or the raw text.
    ///
    /// The invariant that ties the two together, and the reason this is not simply a
    /// second implementation that could drift: stripping whitespace from this
    /// function's output must give exactly [`Self::apply`]'s output for the same mask.
    /// [`tests::whitespace_preserving_apply_agrees_with_compact_apply`] asserts it over
    /// every mask of a whitespace-bearing fixture.
    pub fn apply_preserving_whitespace(&self, mask: u32, raw: &[u8], out: &mut Vec<u8>) {
        out.clear();
        out.extend_from_slice(raw);
        if self.positions.is_empty() {
            return;
        }
        // `positions` is ascending, so one forward walk with a cursor into it is
        // enough; no per-position search, and no allocation.
        let mut next = 0usize;
        let mut seen = 0usize;
        for byte in out.iter_mut() {
            if byte.is_ascii_whitespace() {
                continue;
            }
            if next < self.positions.len() && self.positions[next] == seen {
                *byte = self.glyph(mask, next);
                next += 1;
            }
            seen += 1;
        }
        debug_assert_eq!(
            next,
            self.positions.len(),
            "every ambiguous position must have been reached: the raw text has fewer              non-whitespace characters than the compacted text it was derived from"
        );
    }

    /// Human-readable statement of what `mask` changes, for a hit report: an auditor
    /// has to be able to reconstruct the exact bytes from the claim alone.
    pub fn describe(&self, mask: u32) -> String {
        if mask == 0 {
            return "the recorded reading".to_string();
        }
        let mut parts = Vec::new();
        for (i, &off) in self.positions.iter().enumerate() {
            if mask >> i & 1 == 1 {
                parts.push(format!(
                    "@{off}:{}->{}",
                    self.recorded[i] as char, self.alternative[i] as char
                ));
            }
        }
        format!(
            "{} correction{}: {}",
            parts.len(),
            if parts.len() == 1 { "" } else { "s" },
            parts.join(" ")
        )
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// TG4's ciphertext, exactly as `data/the_giant.json` records it.
    const TG4: &[u8] = b"kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvIqkZiI0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3xle8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtINbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";

    /// The `0`/`O` offsets the project team resolved against the source font. Recorded
    /// here so the "not enumerated" property is checkable rather than implicit.
    const TG4_RESOLVED: [usize; 7] = [37, 64, 86, 94, 105, 112, 114];

    fn tg4() -> VariantSpace {
        VariantSpace::derive(TG4, Display::Base64, "b64-exact").unwrap()
    }

    /// TG4's canonical transcription, exactly as `data/the_giant.json` records it in
    /// `ciphertext_canonical`: resolves every open `I`/`l` position but offset 90.
    const TG4_CANONICAL: &[u8] = b"kCmlgFi6GUJNgkNI1Q41fbfyLoCFTCvlqkZil0KIAXAzP1U1uy1BE4UfPBfpKmmLObjYnQNRBaPtKiVWzc5A4v0w3x(I/l)e8FOhAGJZ7g4in0wndJxMOvO3dc1M82at2T6935roTqyWDgtGD/hwwRF3oHqFM5Vcw1JtlNbsgWRm4o4/quEDkZ7x1B275bX3/Fo1";

    fn tg4_canonical() -> VariantSpace {
        VariantSpace::derive_canonical(TG4, Some(TG4_CANONICAL), Display::Base64, "b64-exact")
            .unwrap()
    }

    /// The correction this whole module exists to make executable: the canonical
    /// transcription the project owner supplied collapses TG4's admissible readings
    /// from 128 to exactly `{v4c, v6c}` — the two labels a claim has already been
    /// committed against — while every other label from `v00` to `v7f` stays a valid,
    /// parseable label naming the same bytes it always did. A drift in either the
    /// canonical text or the restriction logic that silently changed this set would
    /// invalidate `claims/tg4-canonical-2026-07-30.json` without anyone noticing; this
    /// test is what makes that loud.
    #[test]
    fn canonical_narrows_tg4_to_v4c_and_v6c() {
        let v = tg4_canonical();
        // the label space is unchanged: still 7 positions, still v00..v7f addressable
        assert_eq!(v.positions(), [3, 15, 31, 36, 39, 90, 160]);
        assert_eq!(v.label_space_size(), 128);
        // but only two of those 128 labels are admissible
        assert_eq!(v.count(), 2, "1 open position (offset 90) -> 2 admissible readings");
        let masks = v.masks();
        let labels: Vec<String> = masks.iter().map(|&m| v.label(m)).collect();
        assert_eq!(labels, vec!["v4c", "v6c"]);
        assert_eq!(v.select("all").unwrap(), masks);
        // v4c is offset 90 = 'l' (the legacy-recorded glyph, bit clear); v6c is
        // offset 90 = 'I' (the partner, bit set) — both other than at offset 90 apply
        // the same six corrections the canonical text made.
        let mut out = Vec::new();
        v.apply(v.parse_label("v4c").unwrap(), TG4, &mut out);
        assert_eq!(out[90], b'l');
        v.apply(v.parse_label("v6c").unwrap(), TG4, &mut out);
        assert_eq!(out[90], b'I');
        // every other label is still a valid, parseable point in the wider space, so
        // an explicit list can still reach it even though `all` will not
        assert_eq!(v.parse_label("v00"), Some(0));
        assert_eq!(v.select("v00,v4c").unwrap(), vec![0, 0x4c]);
    }

    /// A canonical transcription that resolves *every* open position (no `(A/B)`
    /// marker left at all) narrows the space to exactly one reading, and a canonical
    /// transcription byte-identical to the recorded one (every marker as wide-open as
    /// the raw ciphertext already was) narrows nothing.
    #[test]
    fn canonical_narrowing_handles_the_fully_resolved_and_fully_open_extremes() {
        let alphabet = display_alphabet(Display::Base64).as_bytes();
        assert!(alphabet.contains(&b'I') && alphabet.contains(&b'l'));

        let raw = b"IIll".to_vec();
        // fully resolved: canonical states a literal glyph at every position
        let resolved = VariantSpace::derive_canonical(
            &raw,
            Some(b"IIll"),
            Display::Base64,
            "b64-exact",
        )
        .unwrap();
        assert_eq!(resolved.count(), 1);
        assert_eq!(resolved.masks(), vec![0]);

        // fully open: canonical marks every position with its own (recorded/partner)
        let open = VariantSpace::derive_canonical(
            &raw,
            Some(b"(I/l)(I/l)(l/I)(l/I)"),
            Display::Base64,
            "b64-exact",
        )
        .unwrap();
        assert_eq!(open.count(), 16);
        assert_eq!(open.masks(), (0..16).collect::<Vec<u32>>());
    }

    /// A canonical transcription whose fixed glyph at some position is neither the
    /// recorded glyph nor its partner is a data-integrity error, not a silent
    /// no-op — the corpus record and its canonical companion have to describe the
    /// same underlying image.
    #[test]
    fn canonical_narrowing_rejects_a_glyph_outside_the_open_pair() {
        let raw = b"II".to_vec();
        let result = VariantSpace::derive_canonical(&raw, Some(b"Ix"), Display::Base64, "b64-exact");
        let err = match result {
            Ok(_) => panic!("expected a data-integrity error"),
            Err(e) => e,
        };
        assert!(
            err.to_string().contains("neither the recorded"),
            "{err}"
        );
    }

    /// The positions are derived from the ciphertext, but they must equal the ones the
    /// corpus record actually has — so a re-transcription that moves, adds or removes
    /// an ambiguous glyph fails the build rather than silently changing what every TG4
    /// claim means.
    #[test]
    fn tg4_derives_the_seven_open_ambiguous_positions() {
        let v = tg4();
        assert_eq!(TG4.len(), 192, "TG4 is 192 base64 characters");
        assert_eq!(v.positions(), [3, 15, 31, 36, 39, 90, 160]);
        assert_eq!(v.count(), 128, "2^7 admissible transcriptions");
        // 5 I, 2 l
        let census: Vec<(char, usize)> = v.census().iter().map(|(c, n)| (*c as char, *n)).collect();
        assert_eq!(census, vec![('I', 5), ('l', 2)]);
        assert_eq!(census.iter().map(|(_, n)| n).sum::<usize>(), 7);
    }

    /// `0`/`O` was resolved by the project team's review of the source font, so those
    /// seven positions are fixed to the recorded reading. Re-opening the pair must be a
    /// deliberate edit, never a regression: this test fails the moment a `0` or `O`
    /// offset enters the enumerated space.
    #[test]
    fn no_resolved_glyph_is_ever_enumerated() {
        let v = tg4();
        // the resolved positions are present in the ciphertext, and there are seven
        assert_eq!(
            VariantSpace::resolved_positions(TG4, Display::Base64),
            TG4_RESOLVED
        );
        // ... and none of them is enumerated
        for off in TG4_RESOLVED {
            assert!(
                !v.positions().contains(&off),
                "offset {off} carries a resolved 0/O glyph and must not be enumerated"
            );
        }
        // no variant may alter a resolved position, at any mask
        let mut out = Vec::new();
        for m in v.masks() {
            v.apply(m, TG4, &mut out);
            for off in TG4_RESOLVED {
                assert_eq!(
                    out[off], TG4[off],
                    "variant {m} changed resolved offset {off}"
                );
            }
        }
        // and the two pair tables must stay disjoint, or a glyph could be both
        for (a, b) in RESOLVED_PAIRS {
            assert_eq!(partner(a), None, "{} is resolved, not open", a as char);
            assert_eq!(partner(b), None, "{} is resolved, not open", b as char);
            assert_eq!(resolved_partner(a), Some(b));
        }
    }

    /// The correction to the dossier, stated as an executable assertion:
    /// `reference/py/space.py` models 16 TG4 readings, and the true admissible count is
    /// 128 — an 8x understatement.
    #[test]
    fn the_variant_count_corrects_the_dossier_by_8x() {
        const N_TRANS_TG_REFERENCE: u64 = 16;
        let v = tg4();
        assert_eq!(v.count(), 128);
        assert_eq!(v.count() / N_TRANS_TG_REFERENCE, 8);
        // and it is 128x smaller than the pre-resolution worst case over both pairs,
        // which is the whole value of the team's font review
        let pre_resolution = 1u64 << (v.positions().len() + TG4_RESOLVED.len());
        assert_eq!(pre_resolution, 16_384);
        assert_eq!(pre_resolution / v.count(), 128);
    }

    /// Hex excludes `O`, `I` and `l`, so no position in a hex transcription is
    /// ambiguous under either pair. REV7's "unambiguous" status is therefore computed,
    /// not assumed.
    #[test]
    fn hex_transcriptions_have_no_glyph_ambiguity() {
        let hex = b"83A0F01100OO";
        let v = VariantSpace::derive(hex, Display::Hex, "hex-exact").unwrap();
        assert!(!v.is_ambiguous());
        assert_eq!(v.count(), 1);
        assert_eq!(v.label(0), "hex-exact", "a one-point dimension still needs a name");
        assert_eq!(v.parse_label("hex-exact"), Some(0));
        assert_eq!(v.parse_label("v00"), None);
        // `O` is not a hex digit, so even the resolved pair finds nothing there
        assert!(VariantSpace::resolved_positions(hex, Display::Hex).is_empty());
        // ... whereas in a base64 transcription the same text has resolved positions
        // (the zeros and Os) but still no *open* ones, since it holds no I or l
        let b64 = VariantSpace::derive(hex, Display::Base64, "b64-exact").unwrap();
        assert!(!b64.is_ambiguous());
        assert_eq!(
            VariantSpace::resolved_positions(hex, Display::Base64),
            [3, 5, 8, 9, 10, 11]
        );
    }

    /// The enumeration must be a bijection onto the mask space, and index 0 must be the
    /// recorded reading. Same standard as the sweep's own index tests: if it is not a
    /// bijection the sweep under-covers while claiming the full product.
    #[test]
    fn mask_enumeration_is_a_bijection_and_starts_at_the_recorded_reading() {
        let v = tg4();
        let masks = v.masks();
        assert_eq!(masks.len() as u64, v.count());
        assert_eq!(masks[0], 0, "index 0 is the recorded reading");
        assert_eq!(v.label(masks[0]), "v00");
        let mut seen = vec![false; masks.len()];
        for &m in &masks {
            assert!(!seen[m as usize], "mask {m} enumerated twice");
            seen[m as usize] = true;
        }
        assert!(seen.iter().all(|b| *b), "every mask must be enumerated once");
        for w in masks.windows(2) {
            assert!(w[0] < w[1], "the order must be strictly increasing");
        }
    }

    /// Labels must be stable, unique, and round-trip. They are what makes two runs'
    /// claims comparable, so a collision or a re-spelling silently merges or splits
    /// coverage.
    #[test]
    fn labels_are_stable_unique_and_round_trip() {
        let v = tg4();
        assert_eq!(v.label(0), "v00");
        assert_eq!(v.label(1), "v01");
        assert_eq!(v.label(0x7f), "v7f");
        let mut all: Vec<String> = v.masks().iter().map(|&m| v.label(m)).collect();
        assert_eq!(all.len(), 128);
        for (i, m) in v.masks().iter().enumerate() {
            assert_eq!(v.parse_label(&all[i]), Some(*m));
        }
        all.sort();
        all.dedup();
        assert_eq!(all.len(), 128, "labels must be unique");
        assert_eq!(v.parse_label("v80"), None, "past the end of the space");
        assert_eq!(v.parse_label("nonsense"), None);
    }

    /// Applying a mask must change exactly the glyphs the mask names, and `v00` must
    /// reproduce the recorded ciphertext byte for byte.
    #[test]
    fn applying_a_mask_flips_exactly_the_named_glyphs() {
        let v = tg4();
        let mut out = Vec::new();
        v.apply(0, TG4, &mut out);
        assert_eq!(out, TG4, "v00 is the recorded transcription");

        for (i, &off) in v.positions().iter().enumerate() {
            v.apply(1 << i, TG4, &mut out);
            assert_eq!(out.len(), TG4.len());
            let differ: Vec<usize> = (0..TG4.len()).filter(|&j| out[j] != TG4[j]).collect();
            assert_eq!(differ, vec![off], "one bit must flip one glyph");
            assert_eq!(partner(TG4[off]), Some(out[off]));
        }

        // every variant is a distinct, still-valid base64 string of the same length
        let mut seen = std::collections::HashSet::new();
        for m in v.masks() {
            v.apply(m, TG4, &mut out);
            assert_eq!(out.len(), 192);
            assert!(
                out.iter()
                    .all(|c| display_alphabet(Display::Base64).as_bytes().contains(c)),
                "every reading must stay admissible base64"
            );
            assert!(seen.insert(out.clone()), "variant {m} duplicates another");
        }
        assert_eq!(seen.len(), 128);
    }

    #[test]
    fn selectors_resolve_to_the_regions_they_name() {
        let v = tg4();
        assert_eq!(v.select("recorded").unwrap(), vec![0]);
        assert_eq!(v.select("all").unwrap().len(), 128);
        // an explicit list is canonically ordered, so two spellings of the same set
        // produce the same claim
        assert_eq!(
            v.select("v02,v00,v01").unwrap(),
            v.select("v01,v02,v00").unwrap()
        );
        assert_eq!(v.select("v02,v00,v01").unwrap(), vec![0, 1, 2]);
        assert!(v.select("v80").is_err());
        assert!(v.select("hamming:1").is_err(), "no longer a selector");
        assert!(v.select("").is_err());
    }

    #[test]
    fn describe_names_the_exact_corrections() {
        let v = tg4();
        assert_eq!(v.describe(0), "the recorded reading");
        assert_eq!(v.describe(1), "1 correction: @3:l->I");
        assert_eq!(v.describe(0b11), "2 corrections: @3:l->I @15:I->l");
        assert_eq!(v.describe(1 << 6), "1 correction: @160:I->l");
    }

    #[test]
    fn partners_are_reciprocal_and_limited_to_the_open_pair() {
        assert_eq!(partner(b'I'), Some(b'l'));
        assert_eq!(partner(b'l'), Some(b'I'));
        assert_eq!(partner(b'0'), None, "0/O is resolved, not enumerated");
        assert_eq!(partner(b'O'), None, "0/O is resolved, not enumerated");
        assert_eq!(partner(b'1'), None);
        assert_eq!(partner(b'o'), None, "lower-case o is not one of the pairs");
        for (a, b) in AMBIGUOUS_PAIRS {
            assert_eq!(partner(partner(a).unwrap()), Some(a));
            assert_eq!(partner(b), Some(a));
        }
    }

    // -----------------------------------------------------------------------
    // Whitespace-preserving variant application
    //
    // `--pre` is documented to run on the RAW ciphertext text, but the sweep used to
    // hand it the whitespace-stripped text, so `reverse_words` saw a single token and
    // silently became the identity. Fixing that means the variant masks -- whose
    // positions index the COMPACTED text -- must now be spliced into text that still
    // has its whitespace, and an off-by-one there would corrupt every reading while
    // still "working". These pin the exact property that makes the fix safe.
    // -----------------------------------------------------------------------

    /// A deliberately tiny, spaced fixture with exactly TWO ambiguous glyphs, so all
    /// four masks are enumerable and an index error is visible by eye.
    ///
    /// `I` sits at compact offset 1 and `l` at compact offset 5; in the raw text they
    /// are at byte offsets 1 and 6, because of the space at offset 4. Any
    /// implementation that confuses the two coordinate systems gets a different
    /// answer here.
    const SPACED: &[u8] = b"aIbc dlef";

    fn spaced_space() -> VariantSpace {
        let compact: Vec<u8> = SPACED
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        VariantSpace::derive(&compact, Display::Base64, "b64-exact").unwrap()
    }

    /// The fixture is only worth anything if it really has two open positions at the
    /// offsets the other tests reason about; assert that rather than assume it.
    #[test]
    fn spaced_fixture_has_exactly_two_ambiguous_positions() {
        let space = spaced_space();
        assert_eq!(space.positions(), &[1, 5], "compacted offsets of `I` and `l`");
        assert_eq!(space.count(), 4, "two open positions is four readings");
        assert_eq!(SPACED[1], b'I');
        assert_eq!(SPACED[6], b'l', "`l` is at RAW offset 6, not compact offset 5");
    }

    /// (a) The substitution still picks the same glyphs.
    ///
    /// Compacting the whitespace-preserving output must give exactly what the
    /// compact-indexed [`VariantSpace::apply`] produces for the same mask. This is the
    /// invariant that makes a mask mean one reading regardless of which text it was
    /// applied to, and it is what an index shift would break.
    #[test]
    fn whitespace_preserving_apply_agrees_with_compact_apply() {
        let space = spaced_space();
        let compact: Vec<u8> = SPACED
            .iter()
            .copied()
            .filter(|c| !c.is_ascii_whitespace())
            .collect();
        for mask in 0..4u32 {
            let mut want = Vec::new();
            space.apply(mask, &compact, &mut want);

            let mut raw_out = Vec::new();
            space.apply_preserving_whitespace(mask, SPACED, &mut raw_out);
            let got: Vec<u8> = raw_out
                .iter()
                .copied()
                .filter(|c| !c.is_ascii_whitespace())
                .collect();

            assert_eq!(
                got, want,
                "mask {mask:#04x}: stripping the whitespace-preserving output must \
                 reproduce the compact application exactly"
            );
        }
    }

    /// (b) The whitespace itself is untouched.
    ///
    /// Every whitespace byte of the input must still be present at its ORIGINAL
    /// offset. Dropping one would re-break `reverse_words` (fewer words), and moving
    /// one would change the word boundaries `--pre` reads -- both silently, since the
    /// glyphs would still be right.
    #[test]
    fn whitespace_preserving_apply_moves_no_whitespace() {
        let space = spaced_space();
        for mask in 0..4u32 {
            let mut out = Vec::new();
            space.apply_preserving_whitespace(mask, SPACED, &mut out);
            assert_eq!(out.len(), SPACED.len(), "mask {mask:#04x}: length is preserved");
            for (i, &c) in SPACED.iter().enumerate() {
                if c.is_ascii_whitespace() {
                    assert_eq!(
                        out[i], c,
                        "mask {mask:#04x}: the whitespace byte at offset {i} moved or \
                         was overwritten"
                    );
                }
            }
        }
    }

    /// The masks must actually reach the RAW offsets, not the compact ones. This is
    /// the off-by-one written out explicitly: mask `0b10` flips the second ambiguous
    /// glyph, which lives at raw offset 6; a naive implementation would write at raw
    /// offset 5 and corrupt the space instead.
    #[test]
    fn whitespace_preserving_apply_substitutes_at_the_raw_offset() {
        let space = spaced_space();
        let mut out = Vec::new();
        space.apply_preserving_whitespace(0b10, SPACED, &mut out);
        assert_eq!(out, b"aIbc dIef".to_vec(), "`l` at raw offset 6 becomes `I`");
        assert_eq!(out[4], b' ', "the space at raw offset 4 is untouched");

        space.apply_preserving_whitespace(0b01, SPACED, &mut out);
        assert_eq!(out, b"albc dlef".to_vec(), "`I` at raw offset 1 becomes `l`");

        space.apply_preserving_whitespace(0b11, SPACED, &mut out);
        assert_eq!(out, b"albc dIef".to_vec(), "both flip independently");

        space.apply_preserving_whitespace(0b00, SPACED, &mut out);
        assert_eq!(out, SPACED.to_vec(), "the recorded reading is the input verbatim");
    }

    /// An unspaced transcription -- TG4's shape -- must be unaffected by the
    /// whitespace-preserving path, since there is no whitespace to preserve. This is
    /// the property that lets the TG4 merkle root stay byte-identical across the fix.
    #[test]
    fn whitespace_preserving_apply_is_identical_to_compact_apply_when_unspaced() {
        let space = tg4();
        for mask in [0u32, 1, 0x2c, 0x55, 0x7f] {
            let mut want = Vec::new();
            space.apply(mask, TG4, &mut want);
            let mut got = Vec::new();
            space.apply_preserving_whitespace(mask, TG4, &mut got);
            assert_eq!(got, want, "mask {mask:#04x} on an unspaced transcription");
        }
    }
}

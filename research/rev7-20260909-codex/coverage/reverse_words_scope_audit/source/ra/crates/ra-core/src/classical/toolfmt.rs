//! Tool-artifact modelling shared by every classical-cipher node in this module.
//!
//! We reimplement specific *websites'* cipher tools, not the abstract cipher, so
//! that a chain reproduces exactly what a puzzle-maker did in a browser. Beyond
//! the algorithm itself, the tool's page imposes artifacts on the text that
//! actually reaches the next layer:
//!
//! - a forced case (many tools uppercase or lowercase the result unconditionally),
//! - grouping into blocks of `N` separated by some string ("blocks of 5" is
//!   near-universal on these sites),
//! - a trailing CRLF (and per-block newlines) left over from a select-all copy
//!   out of a `<div>`/`<pre>` that was filled via `.innerHTML` in a Chromium
//!   browser — a tool that instead writes into an `<input>` via `.value =`
//!   copies cleanly, so this is per tool, not universal,
//! - input normalisation the tool applies before transforming at all (strip
//!   whitespace, strip characters outside its alphabet, force case, trim).
//!
//! [`InputNorm`] models the last of these; [`OutputFmt`] models the first three.
//! Both are meant to be run BOTH on and off for a given chain, since a sweep is
//! how we discover empirically which the puzzle-maker actually triggered (an
//! `innerHTML`-backed tool's CRLF is invisible in the page but present in a copy
//! buffer, so nothing about the page tells us which the maker pasted).
//!
//! # Per-node defaults
//!
//! Whether a given artifact is even *plausible* is a property of the specific
//! tool being emulated, not a global fact about "classical cipher tools" — one
//! geocachingtoolbox tool writes via `.value =` (clean), another writes via
//! `.innerHTML` (CRLF risk). [`read_input_norm`] and [`read_output_fmt`]
//! therefore both take the emulating node's defaults as an explicit argument;
//! there is deliberately no global default anywhere in this module (see the
//! `defaults_are_per_call_not_global` test below).

use std::collections::HashSet;

use crate::error::{Error, Result};
use crate::node::{ParamSpec, ParamType};
use crate::params::Params;

// ---------------------------------------------------------------------------
// Case folding, shared by InputNorm and OutputFmt.
// ---------------------------------------------------------------------------

/// How a tool folds case, either while normalising input or while formatting
/// output. `Preserve` leaves the byte case exactly as it arrived.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum CaseFold {
    #[default]
    Preserve,
    Upper,
    Lower,
}

impl CaseFold {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "preserve" => Some(CaseFold::Preserve),
            "upper" => Some(CaseFold::Upper),
            "lower" => Some(CaseFold::Lower),
            _ => None,
        }
    }

    fn apply(self, data: &[u8]) -> Vec<u8> {
        match self {
            CaseFold::Preserve => data.to_vec(),
            CaseFold::Upper => data.to_ascii_uppercase(),
            CaseFold::Lower => data.to_ascii_lowercase(),
        }
    }
}

// ---------------------------------------------------------------------------
// InputNorm
// ---------------------------------------------------------------------------

/// Declarative input normalisation, applied before a node's own transform.
///
/// # Order (fixed, and observable)
///
/// 1. `trim` — strip ASCII whitespace off both ends only.
/// 2. `case` — force the whole string to upper/lower (or leave it alone).
/// 3. `strip_whitespace` — remove every ASCII whitespace byte, not just the ends.
/// 4. `strip_outside_alphabet` — remove every byte not in the given alphabet.
///
/// This order matters and is deliberate: sites overwhelmingly force case
/// *before* filtering (typically `s.toUpperCase().replace(/[^A-Z]/g, "")` or
/// similar), so an input alphabet given in one case still matches input
/// supplied in the other. Reversing steps 2 and 4 would silently drop
/// characters a real tool keeps.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct InputNorm {
    pub trim: bool,
    pub case: CaseFold,
    pub strip_whitespace: bool,
    /// `Some(alphabet)` strips every byte not in `alphabet`; `None` strips nothing.
    pub strip_outside_alphabet: Option<String>,
}

impl InputNorm {
    /// Apply every configured normalisation step, in the fixed order above.
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        let mut d = data.to_vec();

        if self.trim {
            let start = d
                .iter()
                .position(|b| !b.is_ascii_whitespace())
                .unwrap_or(d.len());
            let end = d
                .iter()
                .rposition(|b| !b.is_ascii_whitespace())
                .map(|i| i + 1)
                .unwrap_or(0);
            d = if start < end {
                d[start..end].to_vec()
            } else {
                Vec::new()
            };
        }

        d = self.case.apply(&d);

        if self.strip_whitespace {
            d.retain(|b| !b.is_ascii_whitespace());
        }

        if let Some(alphabet) = &self.strip_outside_alphabet {
            let keep: HashSet<u8> = alphabet.bytes().collect();
            d.retain(|b| keep.contains(b));
        }

        d
    }
}

// ---------------------------------------------------------------------------
// OutputFmt
// ---------------------------------------------------------------------------

/// How output is grouped into blocks — "blocks of 5" separated by spaces is
/// near-universal on these sites; some emit a trailing separator after the
/// final block, some pad a short final block out to `size`.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Grouping {
    pub size: usize,
    pub separator: String,
    pub trailing_separator: bool,
    /// Byte to pad the final, possibly-short block out to `size` with. `None`
    /// leaves a short final block as-is. Padding is restricted to a single
    /// ASCII byte, which is all these sites ever use (`X`, `0`, a dash...).
    pub pad_final: Option<char>,
}

/// The Chromium select-all-copy artifact: a tool that fills its result
/// `<div>`/`<pre>` via `.innerHTML` leaves a trailing line terminator in the
/// clipboard that a tool writing into an `<input>` via `.value =` never
/// produces. `Lf`/`CrLf` are appended exactly once, after grouping.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Default)]
pub enum Trailing {
    #[default]
    None,
    Lf,
    CrLf,
}

impl Trailing {
    fn parse(s: &str) -> Option<Self> {
        match s {
            "none" => Some(Trailing::None),
            "lf" => Some(Trailing::Lf),
            "crlf" => Some(Trailing::CrLf),
            _ => None,
        }
    }

    fn bytes(self) -> &'static [u8] {
        match self {
            Trailing::None => b"",
            Trailing::Lf => b"\n",
            Trailing::CrLf => b"\r\n",
        }
    }
}

/// Post-transform formatting a tool's page applies to its result before the
/// puzzle-maker can copy it: case, grouping, then a trailing line terminator.
#[derive(Clone, PartialEq, Eq, Debug, Default)]
pub struct OutputFmt {
    pub case: CaseFold,
    pub grouping: Option<Grouping>,
    pub trailing: Trailing,
}

impl OutputFmt {
    /// Apply case, then grouping, then the trailing terminator — in that order,
    /// matching how a page actually builds its result string before display.
    pub fn apply(&self, data: &[u8]) -> Vec<u8> {
        let mut out = self.case.apply(data);
        if let Some(g) = &self.grouping {
            out = group(&out, g);
        }
        out.extend_from_slice(self.trailing.bytes());
        out
    }

    /// Invert [`OutputFmt::apply`], for round-trip tests (`parse(format(x)) ==
    /// x`). Case folding is lossy by construction (forcing upper/lower
    /// discards the original case), so this only genuinely round-trips when
    /// `case` is `Preserve` or the original data was already in that case.
    ///
    /// `pad_final` is also lossy in the narrow case where the genuine final
    /// block legitimately ended in the pad byte already — this strips *every*
    /// trailing occurrence of that byte from the final block, which is exactly
    /// right whenever (as in practice) the pad byte doesn't occur in real
    /// plaintext/ciphertext content.
    pub fn strip(&self, data: &[u8]) -> Vec<u8> {
        let mut d = data.to_vec();

        let t = self.trailing.bytes();
        if !t.is_empty() && d.ends_with(t) {
            d.truncate(d.len() - t.len());
        }

        if let Some(g) = &self.grouping {
            d = ungroup(&d, g);
        }

        d
    }
}

fn group(data: &[u8], g: &Grouping) -> Vec<u8> {
    if g.size == 0 || data.is_empty() {
        return data.to_vec();
    }
    let mut chunks: Vec<Vec<u8>> = data.chunks(g.size).map(|c| c.to_vec()).collect();
    if let (Some(pad), Some(last)) = (g.pad_final, chunks.last_mut()) {
        while last.len() < g.size {
            last.push(pad as u8);
        }
    }
    let mut out = Vec::new();
    for (i, chunk) in chunks.iter().enumerate() {
        if i > 0 {
            out.extend_from_slice(g.separator.as_bytes());
        }
        out.extend_from_slice(chunk);
    }
    if g.trailing_separator {
        out.extend_from_slice(g.separator.as_bytes());
    }
    out
}

fn ungroup(data: &[u8], g: &Grouping) -> Vec<u8> {
    if g.size == 0 || data.is_empty() {
        return data.to_vec();
    }
    let sep = g.separator.as_bytes();
    let mut d = data.to_vec();
    if g.trailing_separator && !sep.is_empty() && d.ends_with(sep) {
        d.truncate(d.len() - sep.len());
    }
    let mut groups = split_on(&d, sep);
    if let (Some(pad), Some(last)) = (g.pad_final, groups.last_mut()) {
        let pad_byte = pad as u8;
        while last.last() == Some(&pad_byte) {
            last.pop();
        }
    }
    groups.concat()
}

/// Split `data` on every occurrence of the (possibly multi-byte) `sep`. An
/// empty `sep` is treated as "no separator was ever inserted" and returns
/// `data` whole, since site separators are always non-empty in practice.
fn split_on(data: &[u8], sep: &[u8]) -> Vec<Vec<u8>> {
    if sep.is_empty() {
        return vec![data.to_vec()];
    }
    let mut out = Vec::new();
    let mut start = 0;
    let mut i = 0;
    while i + sep.len() <= data.len() {
        if &data[i..i + sep.len()] == sep {
            out.push(data[start..i].to_vec());
            i += sep.len();
            start = i;
        } else {
            i += 1;
        }
    }
    out.push(data[start..].to_vec());
    out
}

// ---------------------------------------------------------------------------
// Parameter plumbing
// ---------------------------------------------------------------------------
//
// Every one of these is an ordinary node parameter (see `ParamSpec`/`Params` in
// `crate::node`/`crate::params`) so a sweep can flip them the same way it flips
// any other node parameter. Nodes declare the standard set with
// `artifact_param_specs!()` spliced into their own `params_schema()` array, and
// read them back in one call each via `read_input_norm`/`read_output_fmt`.

pub const TRIM_PARAM: ParamSpec = ParamSpec::opt(
    "trim",
    ParamType::Bool,
    "strip leading/trailing whitespace before transforming (input normalisation)",
);
pub const INPUT_CASE_PARAM: ParamSpec = ParamSpec::opt(
    "input_case",
    ParamType::Str,
    "force input case before transforming: preserve|upper|lower (input normalisation)",
);
pub const STRIP_WHITESPACE_PARAM: ParamSpec = ParamSpec::opt(
    "strip_whitespace",
    ParamType::Bool,
    "remove all whitespace (not just at the ends) before transforming (input normalisation)",
);
pub const STRIP_NON_ALPHABET_PARAM: ParamSpec = ParamSpec::opt(
    "strip_non_alphabet",
    ParamType::Bool,
    "remove characters outside the node's input alphabet before transforming \
     (input normalisation)",
);
pub const INPUT_ALPHABET_PARAM: ParamSpec = ParamSpec::opt(
    "input_alphabet",
    ParamType::Str,
    "override the alphabet used by strip_non_alphabet (defaults to the node's own)",
);

pub const OUTPUT_CASE_PARAM: ParamSpec = ParamSpec::opt(
    "output_case",
    ParamType::Str,
    "force output case after transforming: preserve|upper|lower (output artifact)",
);
pub const GROUP_SIZE_PARAM: ParamSpec = ParamSpec::opt(
    "group_size",
    ParamType::Int,
    "split output into blocks of this many bytes; 0 disables grouping (output artifact)",
);
pub const GROUP_SEPARATOR_PARAM: ParamSpec = ParamSpec::opt(
    "group_separator",
    ParamType::Str,
    "string inserted between blocks (output artifact)",
);
pub const GROUP_TRAILING_SEPARATOR_PARAM: ParamSpec = ParamSpec::opt(
    "group_trailing_separator",
    ParamType::Bool,
    "also emit the separator after the final block (output artifact)",
);
pub const GROUP_PAD_FINAL_PARAM: ParamSpec = ParamSpec::opt(
    "group_pad_final",
    ParamType::Str,
    "single character to pad a short final block out to group_size with; empty \
     string disables padding (output artifact)",
);
pub const TRAILING_PARAM: ParamSpec = ParamSpec::opt(
    "trailing",
    ParamType::Str,
    "line terminator left by a Chromium select-all copy out of the site's result \
     element: none|lf|crlf (output artifact)",
);

/// All ten standard artifact `ParamSpec`s, for introspection (e.g. `ra nodes`
/// listings or tests that want to name them without repeating the literals).
/// Node authors splicing these into their own `params_schema()` array should
/// use [`artifact_param_specs!`] instead, since a `&'static [ParamSpec]` cannot
/// be spread into another array literal at compile time.
pub const ARTIFACT_PARAMS: &[ParamSpec] = &[
    TRIM_PARAM,
    INPUT_CASE_PARAM,
    STRIP_WHITESPACE_PARAM,
    STRIP_NON_ALPHABET_PARAM,
    INPUT_ALPHABET_PARAM,
    OUTPUT_CASE_PARAM,
    GROUP_SIZE_PARAM,
    GROUP_SEPARATOR_PARAM,
    GROUP_TRAILING_SEPARATOR_PARAM,
    GROUP_PAD_FINAL_PARAM,
    TRAILING_PARAM,
];

/// Build a node's `params_schema()` array in one call: its own params plus the
/// standard artifact params, e.g.
///
/// ```ignore
/// const MY_SCHEMA: &[ParamSpec] = &$crate::artifact_param_specs!(
///     ParamSpec::req("key", ParamType::Str, "..."),
/// );
/// ```
///
/// (A plain array literal can't splice a `&'static [ParamSpec]` slice into
/// itself at compile time — there is no spread syntax for that in Rust — so
/// this takes the node's own `ParamSpec`s as arguments and emits one array
/// literal containing all of them, rather than trying to concatenate slices.)
#[macro_export]
macro_rules! artifact_param_specs {
    ($($own:expr),* $(,)?) => {
        [
            $($own,)*
            $crate::classical::toolfmt::TRIM_PARAM,
            $crate::classical::toolfmt::INPUT_CASE_PARAM,
            $crate::classical::toolfmt::STRIP_WHITESPACE_PARAM,
            $crate::classical::toolfmt::STRIP_NON_ALPHABET_PARAM,
            $crate::classical::toolfmt::INPUT_ALPHABET_PARAM,
            $crate::classical::toolfmt::OUTPUT_CASE_PARAM,
            $crate::classical::toolfmt::GROUP_SIZE_PARAM,
            $crate::classical::toolfmt::GROUP_SEPARATOR_PARAM,
            $crate::classical::toolfmt::GROUP_TRAILING_SEPARATOR_PARAM,
            $crate::classical::toolfmt::GROUP_PAD_FINAL_PARAM,
            $crate::classical::toolfmt::TRAILING_PARAM,
        ]
    };
}

fn single_char(node: &str, key: &str, s: &str) -> Result<char> {
    let mut chars = s.chars();
    let c = chars
        .next()
        .ok_or_else(|| Error::bad_param(node, key, "must not be empty when set"))?;
    if chars.next().is_some() {
        return Err(Error::bad_param(
            node,
            key,
            format!("must be exactly one character, got {s:?}"),
        ));
    }
    Ok(c)
}

/// Read [`InputNorm`] back from `params` in one call. `defaults` is the
/// emulated tool's own normalisation behaviour — what happens when none of the
/// artifact params are supplied at all — and is a property of *that specific
/// tool*, never a value shared across nodes.
pub fn read_input_norm(node: &str, params: &Params, defaults: InputNorm) -> Result<InputNorm> {
    let trim = params.opt_bool("trim", defaults.trim);

    let case = match params.opt_str("input_case") {
        Some(s) => CaseFold::parse(s).ok_or_else(|| {
            Error::bad_param(
                node,
                "input_case",
                format!("expected preserve|upper|lower, got {s:?}"),
            )
        })?,
        None => defaults.case,
    };

    let strip_whitespace = params.opt_bool("strip_whitespace", defaults.strip_whitespace);

    let strip_non_alphabet =
        params.opt_bool("strip_non_alphabet", defaults.strip_outside_alphabet.is_some());
    let strip_outside_alphabet = if strip_non_alphabet {
        match params.opt_str("input_alphabet") {
            Some(s) => Some(s.to_string()),
            None => Some(defaults.strip_outside_alphabet.clone().ok_or_else(|| {
                Error::bad_param(
                    node,
                    "input_alphabet",
                    "strip_non_alphabet is set but this node has no default alphabet; \
                     input_alphabet must be given explicitly",
                )
            })?),
        }
    } else {
        None
    };

    Ok(InputNorm {
        trim,
        case,
        strip_whitespace,
        strip_outside_alphabet,
    })
}

/// Read [`OutputFmt`] back from `params` in one call. `defaults` is the
/// emulated tool's own output formatting — what happens when none of the
/// artifact params are supplied at all — and is a property of *that specific
/// tool*: e.g. geocachingtoolbox's Playfair writes via `.value =` (clean, so
/// its default `trailing` is `None`), its BWT writes via `.innerHTML` (so its
/// default `trailing` is `CrLf`). Never share one default across nodes.
pub fn read_output_fmt(node: &str, params: &Params, defaults: OutputFmt) -> Result<OutputFmt> {
    let case = match params.opt_str("output_case") {
        Some(s) => CaseFold::parse(s).ok_or_else(|| {
            Error::bad_param(
                node,
                "output_case",
                format!("expected preserve|upper|lower, got {s:?}"),
            )
        })?,
        None => defaults.case,
    };

    let trailing = match params.opt_str("trailing") {
        Some(s) => Trailing::parse(s).ok_or_else(|| {
            Error::bad_param(
                node,
                "trailing",
                format!("expected none|lf|crlf, got {s:?}"),
            )
        })?,
        None => defaults.trailing,
    };

    let grouping_overridden = ["group_size", "group_separator", "group_trailing_separator", "group_pad_final"]
        .iter()
        .any(|k| params.get(k).is_some());

    let grouping = if grouping_overridden {
        let default_size = defaults.grouping.as_ref().map(|g| g.size as i64).unwrap_or(0);
        let size = params.opt_i64("group_size", default_size);
        if size <= 0 {
            None
        } else {
            let separator = match params.opt_str("group_separator") {
                Some(s) => s.to_string(),
                None => defaults
                    .grouping
                    .as_ref()
                    .map(|g| g.separator.clone())
                    .unwrap_or_else(|| " ".to_string()),
            };
            let default_trailing_sep = defaults
                .grouping
                .as_ref()
                .map(|g| g.trailing_separator)
                .unwrap_or(false);
            let trailing_separator =
                params.opt_bool("group_trailing_separator", default_trailing_sep);
            let pad_final = match params.opt_str("group_pad_final") {
                Some("") => None,
                Some(s) => Some(single_char(node, "group_pad_final", s)?),
                None => defaults.grouping.as_ref().and_then(|g| g.pad_final),
            };
            Some(Grouping {
                size: size as usize,
                separator,
                trailing_separator,
                pad_final,
            })
        }
    } else {
        defaults.grouping
    };

    Ok(OutputFmt {
        case,
        grouping,
        trailing,
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;

    // -- InputNorm -----------------------------------------------------------

    #[test]
    fn input_norm_trim_only_strips_ends() {
        let n = InputNorm {
            trim: true,
            ..Default::default()
        };
        assert_eq!(n.apply(b"  a b c  "), b"a b c");
    }

    #[test]
    fn input_norm_trim_all_whitespace_yields_empty() {
        let n = InputNorm {
            trim: true,
            ..Default::default()
        };
        assert_eq!(n.apply(b"   \t\n  "), b"");
    }

    #[test]
    fn input_norm_case_upper() {
        let n = InputNorm {
            case: CaseFold::Upper,
            ..Default::default()
        };
        assert_eq!(n.apply(b"HeLLo"), b"HELLO");
    }

    #[test]
    fn input_norm_case_lower() {
        let n = InputNorm {
            case: CaseFold::Lower,
            ..Default::default()
        };
        assert_eq!(n.apply(b"HeLLo"), b"hello");
    }

    #[test]
    fn input_norm_strip_whitespace_removes_interior_too() {
        let n = InputNorm {
            strip_whitespace: true,
            ..Default::default()
        };
        assert_eq!(n.apply(b" a b\tc\n"), b"abc");
    }

    #[test]
    fn input_norm_strip_outside_alphabet() {
        let n = InputNorm {
            strip_outside_alphabet: Some("ABC".to_string()),
            ..Default::default()
        };
        assert_eq!(n.apply(b"AzBxCy"), b"ABC");
    }

    /// Case forcing happens *before* alphabet filtering, so a default alphabet
    /// given in uppercase still keeps lowercase input that gets uppercased first.
    #[test]
    fn input_norm_case_runs_before_alphabet_filter() {
        let n = InputNorm {
            case: CaseFold::Upper,
            strip_outside_alphabet: Some("ABC".to_string()),
            ..Default::default()
        };
        assert_eq!(n.apply(b"abcxyz"), b"ABC");
    }

    #[test]
    fn input_norm_combination_trim_case_strip_ws_alphabet() {
        let n = InputNorm {
            trim: true,
            case: CaseFold::Upper,
            strip_whitespace: true,
            strip_outside_alphabet: Some("ABC".to_string()),
        };
        assert_eq!(n.apply("  a b! c 123  ".as_bytes()), b"ABC");
    }

    #[test]
    fn input_norm_default_is_identity() {
        let n = InputNorm::default();
        assert_eq!(n.apply(b"  Mixed Case 123  "), b"  Mixed Case 123  ");
    }

    // -- OutputFmt: case -------------------------------------------------------

    #[test]
    fn output_fmt_case_preserve_is_identity() {
        let f = OutputFmt::default();
        assert_eq!(f.apply(b"MiXeD"), b"MiXeD");
    }

    #[test]
    fn output_fmt_case_upper() {
        let f = OutputFmt {
            case: CaseFold::Upper,
            ..Default::default()
        };
        assert_eq!(f.apply(b"mixed"), b"MIXED");
    }

    #[test]
    fn output_fmt_case_lower() {
        let f = OutputFmt {
            case: CaseFold::Lower,
            ..Default::default()
        };
        assert_eq!(f.apply(b"MIXED"), b"mixed");
    }

    // -- OutputFmt: grouping ----------------------------------------------------

    #[test]
    fn grouping_exact_multiple() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGHIJ"), b"ABCDE FGHIJ");
    }

    #[test]
    fn grouping_shorter_than_one_group_is_unsplit() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABC"), b"ABC");
    }

    #[test]
    fn grouping_trailing_separator_on() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: true,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGHIJ"), b"ABCDE FGHIJ ");
    }

    #[test]
    fn grouping_trailing_separator_off() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGHIJ"), b"ABCDE FGHIJ");
    }

    #[test]
    fn grouping_pad_final_on() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: Some('X'),
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGH"), b"ABCDE FGHXX");
    }

    #[test]
    fn grouping_pad_final_off_leaves_short_final_block() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGH"), b"ABCDE FGH");
    }

    #[test]
    fn grouping_zero_size_disables_grouping() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 0,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGH"), b"ABCDEFGH");
    }

    #[test]
    fn grouping_empty_input_is_empty_regardless_of_trailing_separator() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: true,
                pad_final: None,
            }),
            ..Default::default()
        };
        assert_eq!(f.apply(b""), b"");
    }

    // -- OutputFmt: trailing ------------------------------------------------

    #[test]
    fn trailing_none_appends_nothing() {
        let f = OutputFmt::default();
        assert_eq!(f.apply(b"ABC"), b"ABC");
    }

    #[test]
    fn trailing_lf_appends_exactly_one_lf() {
        let f = OutputFmt {
            trailing: Trailing::Lf,
            ..Default::default()
        };
        let out = f.apply(b"ABC");
        assert_eq!(out, b"ABC\n");
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn trailing_crlf_appends_exactly_one_crlf() {
        let f = OutputFmt {
            trailing: Trailing::CrLf,
            ..Default::default()
        };
        let out = f.apply(b"ABC");
        assert_eq!(out, b"ABC\r\n");
        assert_eq!(out.iter().filter(|&&b| b == b'\r').count(), 1);
        assert_eq!(out.iter().filter(|&&b| b == b'\n').count(), 1);
    }

    #[test]
    fn trailing_applied_after_grouping() {
        let f = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            trailing: Trailing::CrLf,
            ..Default::default()
        };
        assert_eq!(f.apply(b"ABCDEFGHIJ"), b"ABCDE FGHIJ\r\n");
    }

    // -- Round-trip -----------------------------------------------------------

    fn representative_fmts() -> Vec<OutputFmt> {
        vec![
            OutputFmt::default(),
            OutputFmt {
                trailing: Trailing::Lf,
                ..Default::default()
            },
            OutputFmt {
                trailing: Trailing::CrLf,
                ..Default::default()
            },
            OutputFmt {
                grouping: Some(Grouping {
                    size: 5,
                    separator: " ".to_string(),
                    trailing_separator: false,
                    pad_final: None,
                }),
                ..Default::default()
            },
            OutputFmt {
                grouping: Some(Grouping {
                    size: 5,
                    separator: "-".to_string(),
                    trailing_separator: true,
                    pad_final: None,
                }),
                trailing: Trailing::Lf,
                ..Default::default()
            },
            OutputFmt {
                grouping: Some(Grouping {
                    size: 4,
                    separator: " ".to_string(),
                    trailing_separator: false,
                    pad_final: Some('X'),
                }),
                trailing: Trailing::CrLf,
                ..Default::default()
            },
        ]
    }

    #[test]
    fn round_trip_inverts_every_representative_config() {
        // Chosen so the pad byte ('X') never legitimately occurs at the end of
        // a final block, keeping every config here genuinely losslessly
        // invertible (case is Preserve throughout, so that isn't an issue).
        let samples: &[&[u8]] = &[b"", b"A", b"ABCDE", b"ABCDEFGHIJ", b"ABCDEFGH"];
        for fmt in representative_fmts() {
            for sample in samples {
                let formatted = fmt.apply(sample);
                let recovered = fmt.strip(&formatted);
                assert_eq!(
                    &recovered, sample,
                    "fmt={fmt:?} sample={sample:?} formatted={formatted:?}"
                );
            }
        }
    }

    // -- Parameter plumbing ---------------------------------------------------

    #[test]
    fn read_input_norm_uses_defaults_when_no_params_given() {
        let defaults = InputNorm {
            trim: true,
            case: CaseFold::Upper,
            strip_whitespace: true,
            strip_outside_alphabet: Some("ABC".to_string()),
        };
        let got = read_input_norm("test", &params! {}, defaults.clone()).unwrap();
        assert_eq!(got, defaults);
    }

    #[test]
    fn read_input_norm_params_override_defaults() {
        let defaults = InputNorm::default();
        let p = params! {
            "trim" => true,
            "input_case" => "lower",
            "strip_whitespace" => true,
        };
        let got = read_input_norm("test", &p, defaults).unwrap();
        assert!(got.trim);
        assert_eq!(got.case, CaseFold::Lower);
        assert!(got.strip_whitespace);
        assert_eq!(got.strip_outside_alphabet, None);
    }

    #[test]
    fn read_input_norm_rejects_bad_case_string() {
        let err = read_input_norm(
            "test",
            &params! {"input_case" => "sideways"},
            InputNorm::default(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadParam { .. }), "{err}");
    }

    #[test]
    fn read_input_norm_strip_non_alphabet_without_default_or_override_errors() {
        let err = read_input_norm(
            "test",
            &params! {"strip_non_alphabet" => true},
            InputNorm::default(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadParam { .. }), "{err}");
    }

    #[test]
    fn read_input_norm_input_alphabet_overrides_default_alphabet() {
        let defaults = InputNorm {
            strip_outside_alphabet: Some("ABC".to_string()),
            ..Default::default()
        };
        let p = params! {"input_alphabet" => "XYZ"};
        let got = read_input_norm("test", &p, defaults).unwrap();
        assert_eq!(got.strip_outside_alphabet, Some("XYZ".to_string()));
    }

    #[test]
    fn read_output_fmt_uses_defaults_when_no_params_given() {
        let defaults = OutputFmt {
            case: CaseFold::Upper,
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            trailing: Trailing::CrLf,
        };
        let got = read_output_fmt("test", &params! {}, defaults.clone()).unwrap();
        assert_eq!(got, defaults);
    }

    #[test]
    fn read_output_fmt_params_override_defaults() {
        let defaults = OutputFmt::default();
        let p = params! {
            "output_case" => "upper",
            "trailing" => "crlf",
            "group_size" => 4i64,
        };
        let got = read_output_fmt("test", &p, defaults).unwrap();
        assert_eq!(got.case, CaseFold::Upper);
        assert_eq!(got.trailing, Trailing::CrLf);
        let g = got.grouping.unwrap();
        assert_eq!(g.size, 4);
        assert_eq!(g.separator, " "); // fallback default separator
    }

    #[test]
    fn read_output_fmt_group_size_zero_disables_default_grouping() {
        let defaults = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: None,
            }),
            ..Default::default()
        };
        let got = read_output_fmt("test", &params! {"group_size" => 0i64}, defaults).unwrap();
        assert_eq!(got.grouping, None);
    }

    #[test]
    fn read_output_fmt_rejects_bad_trailing_string() {
        let err = read_output_fmt(
            "test",
            &params! {"trailing" => "sideways"},
            OutputFmt::default(),
        )
        .unwrap_err();
        assert!(matches!(err, Error::BadParam { .. }), "{err}");
    }

    #[test]
    fn read_output_fmt_rejects_multi_char_pad_final() {
        let p = params! {"group_size" => 5i64, "group_pad_final" => "XY"};
        let err = read_output_fmt("test", &p, OutputFmt::default()).unwrap_err();
        assert!(matches!(err, Error::BadParam { .. }), "{err}");
    }

    #[test]
    fn read_output_fmt_empty_pad_final_disables_default_padding() {
        let defaults = OutputFmt {
            grouping: Some(Grouping {
                size: 5,
                separator: " ".to_string(),
                trailing_separator: false,
                pad_final: Some('X'),
            }),
            ..Default::default()
        };
        let p = params! {"group_pad_final" => ""};
        let got = read_output_fmt("test", &p, defaults).unwrap();
        assert_eq!(got.grouping.unwrap().pad_final, None);
    }

    /// The load-bearing property from the spec: identical params, two
    /// different default sets, different output. Proves defaults are
    /// per-call (per emulated tool), never a hidden module-level global.
    #[test]
    fn defaults_are_per_call_not_global() {
        let clean_tool_defaults = OutputFmt::default(); // e.g. a `.value =` tool
        let innerhtml_tool_defaults = OutputFmt {
            trailing: Trailing::CrLf, // e.g. a `.innerHTML` tool
            ..Default::default()
        };

        let p = params! {}; // no explicit override from the caller either way
        let clean = read_output_fmt("clean_tool", &p, clean_tool_defaults)
            .unwrap()
            .apply(b"ABC");
        let dirty = read_output_fmt("innerhtml_tool", &p, innerhtml_tool_defaults)
            .unwrap()
            .apply(b"ABC");

        assert_eq!(clean, b"ABC");
        assert_eq!(dirty, b"ABC\r\n");
        assert_ne!(clean, dirty);
    }
}

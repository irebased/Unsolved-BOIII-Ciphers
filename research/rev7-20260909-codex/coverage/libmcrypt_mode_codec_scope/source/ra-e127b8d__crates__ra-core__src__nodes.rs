//! Built-in `xf` (representation-preserving) and `codec` (display-changing) nodes.
//!
//! None of these is layer-forming on its own. A `codec` step changes how bytes are
//! displayed without changing what they denote, which is exactly why
//! [`layer_delta`](crate::layer::layer_delta) scores it at zero.

use base64::Engine as _;

use crate::error::{Error, Result};
use crate::node::{Family, Node, ParamSpec, ParamType};
use crate::params::Params;
use crate::register_node;
use crate::repr::{self, Display, Repr};

/// Declares a node with a fixed name/version/family and a body closure.
macro_rules! simple_node {
    (
        $(#[$meta:meta])*
        $ty:ident, $static:ident, $name:literal, $version:literal, $family:expr,
        schema = $schema:expr,
        |$input:ident, $params:ident| $body:block
    ) => {
        $(#[$meta])*
        pub struct $ty;

        impl Node for $ty {
            fn name(&self) -> &'static str {
                $name
            }
            fn version(&self) -> &'static str {
                $version
            }
            fn family(&self) -> Family {
                $family
            }
            fn params_schema(&self) -> &'static [ParamSpec] {
                $schema
            }
            fn apply(&self, $input: &Repr, $params: &Params) -> Result<Repr> {
                $body
            }
        }

        register_node!($static => || Box::new($ty));
    };
}

// ---------------------------------------------------------------------------
// xf: representation-preserving transforms
// ---------------------------------------------------------------------------

simple_node!(Reverse, REVERSE, "reverse", "1.0.0", Family::Xf, schema = &[], |input, _p| {
    let mut d = input.data.clone();
    d.reverse();
    Ok(Repr::new(d, input.display))
});

simple_node!(
/// "Reverse words": word order reversed, each word's own characters intact --
/// the distinct sibling of `reverse` (full character reversal) offered by
/// `https://www.unit-conversion.info/texttools/` (see
/// `docs/layering-pattern-analysis.md` §8sexies). Tokens are split on ASCII
/// whitespace runs and rejoined with a single space, matching the site's
/// tool-page description; every solved corpus chain that records a `reverse`
/// step is confirmed (`ra-cli`'s `corpus::reverse_fidelity` tests) to
/// reproduce only under full character reversal, never under this node, so
/// this exists purely to extend the search space for the two unsolved
/// ciphers rather than to correct any existing chain.
ReverseWords, REVERSE_WORDS, "reverse_words", "1.0.0", Family::Xf, schema = &[], |input, _p| {
    let text = String::from_utf8_lossy(&input.data);
    let out = text
        .split_ascii_whitespace()
        .rev()
        .collect::<Vec<_>>()
        .join(" ");
    Ok(Repr::new(out.into_bytes(), input.display))
});

simple_node!(ToLower, TOLOWER, "tolower", "1.0.0", Family::Xf, schema = &[], |input, _p| {
    Ok(Repr::new(input.data.to_ascii_lowercase(), input.display))
});

simple_node!(ToUpper, TOUPPER, "toupper", "1.0.0", Family::Xf, schema = &[], |input, _p| {
    Ok(Repr::new(input.data.to_ascii_uppercase(), input.display))
});

simple_node!(StripWs, STRIPWS, "stripws", "1.0.0", Family::Xf, schema = &[], |input, _p| {
    let d: Vec<u8> = input
        .data
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    Ok(Repr::new(d, input.display))
});

const GROUP_SCHEMA: &[ParamSpec] = &[ParamSpec::opt(
    "n",
    ParamType::Int,
    "group width in bytes (default 5)",
)];

simple_node!(Group, GROUP, "group", "1.0.0", Family::Xf, schema = GROUP_SCHEMA, |input, p| {
    let n = p.opt_i64("n", 5);
    if n <= 0 {
        return Err(Error::bad_param("group", "n", "must be positive"));
    }
    let n = n as usize;
    let stripped: Vec<u8> = input
        .data
        .iter()
        .copied()
        .filter(|c| !c.is_ascii_whitespace())
        .collect();
    let mut out = Vec::with_capacity(stripped.len() + stripped.len() / n + 1);
    for (i, chunk) in stripped.chunks(n).enumerate() {
        if i > 0 {
            out.push(b' ');
        }
        out.extend_from_slice(chunk);
    }
    Ok(Repr::new(out, input.display))
});

const ROT_SCHEMA: &[ParamSpec] = &[ParamSpec::opt(
    "n",
    ParamType::Int,
    "alphabet shift, may be negative (default 13)",
)];

simple_node!(Rot, ROT, "rot", "1.0.0", Family::Xf, schema = ROT_SCHEMA, |input, p| {
    let n = p.opt_i64("n", 13).rem_euclid(26) as u8;
    let out: Vec<u8> = input
        .data
        .iter()
        .map(|&c| match c {
            b'A'..=b'Z' => (c - b'A' + n) % 26 + b'A',
            b'a'..=b'z' => (c - b'a' + n) % 26 + b'a',
            other => other,
        })
        .collect();
    Ok(Repr::new(out, input.display))
});

const SUBST_SCHEMA: &[ParamSpec] = &[ParamSpec::req(
    "alphabet",
    ParamType::Str,
    "26-letter target alphabet; plaintext letter i maps to alphabet[i]",
)];

simple_node!(Substitute, SUBSTITUTE, "substitute", "1.0.0", Family::Xf, schema = SUBST_SCHEMA, |input, p| {
    let alpha = p.req_str("substitute", "alphabet")?.as_bytes();
    if alpha.len() != 26 || !alpha.iter().all(|c| c.is_ascii_alphabetic()) {
        return Err(Error::bad_param(
            "substitute",
            "alphabet",
            format!("expected 26 ASCII letters, got {}", alpha.len()),
        ));
    }
    let lower: Vec<u8> = alpha.to_ascii_lowercase();
    let out: Vec<u8> = input
        .data
        .iter()
        .map(|&c| match c {
            b'a'..=b'z' => lower[(c - b'a') as usize],
            b'A'..=b'Z' => lower[(c - b'A') as usize].to_ascii_uppercase(),
            other => other,
        })
        .collect();
    Ok(Repr::new(out, input.display))
});

/// Default Beaufort alphabet: the corpus's own mixed-case 52-character alphabet.
const BEAUFORT_DEFAULT_ALPHABET: &str =
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz";

const BEAUFORT_SCHEMA: &[ParamSpec] = &[
    ParamSpec::req("key", ParamType::Str, "Beaufort key, repeated cyclically"),
    ParamSpec::opt(
        "alphabet",
        ParamType::Str,
        "alphabet to index into (default: the 52-character mixed-case corpus alphabet)",
    ),
];

simple_node!(
/// Classical Beaufort cipher over an arbitrary alphabet.
///
/// For the `i`th character of the input that appears in alphabet `A` (size `n`),
/// the output is `A[(indexOf(K[i mod |K|]) - indexOf(c)) mod n]`, where `K` is the
/// key. `i` here counts only characters that are members of `A` — a character
/// absent from `A` is emitted unchanged and does *not* consume a key position, the
/// conventional behaviour for classical polyalphabetic ciphers (and confirmed
/// against rev1: counting every input byte, passthrough or not, toward the key
/// phase does not reproduce it, while skipping passthrough bytes does).
///
/// Beaufort is reciprocal: applying it a second time with the same key and
/// alphabet undoes the first application, because
/// `A[(k - (k - c mod n)) mod n] == A[c mod n] == c`. That means encryption and
/// decryption are the same operation, so this one node serves both directions.
///
/// # Cross-checked against 2016 CrypTool Online -- no change needed
///
/// TG4's rev1 layers this node first, so its fidelity has real consequences:
/// several hundred thousand chain evaluations have already run against it.
/// This node was not originally derived from any specific site (it's the
/// classical algorithm confirmed directly against rev1), but the project
/// owner has since supplied 2016 Wayback sources for the CrypTool Online
/// suite (timestamp `20160909182347`), which turned out to include a
/// Beaufort tool of its own (`docs/toolsites/cryptool2016/js/beaufort.js`,
/// `CTOBeaufortAlgorithm.crypt`) -- structurally the same "flat, case-
/// sensitive alphabet; key position advances only on alphabet members;
/// non-alphabet characters pass through" design as this node already
/// implements, right down to sharing this node's own default alphabet shape
/// (52 chars, `A`-`Z` then `a`-`z` as case-sensitive positions, not a
/// case-folded 26-letter alphabet -- see `cto_vigenere`'s module docs for
/// why that distinction matters elsewhere). Running `beaufort.js` directly
/// under Node (task scratchpad `jstest/run_beaufort.js`) against this node
/// with the site's own default checkbox state (`signs` checked, i.e. keep
/// non-alphabet characters; `casesensitiv` checked, i.e. no forced case)
/// reproduces this node's output exactly for both a punctuation-heavy
/// sample and a plain-letter sample -- see
/// `beaufort_matches_2016_cryptool_online_beaufort_js`. Verdict:
/// **identical** at TG4's actual parameters; no change was made to this
/// node, and every existing rev1 sweep result stands.
///
/// Two narrower divergences exist but do not affect TG4: (1) 2016 has a
/// `handle` toggle (site's "signs" checkbox) that, when *unchecked* (not the
/// default), drops non-alphabet characters other than whitespace instead of
/// passing them through -- this node has no such toggle and always passes
/// them through, matching only the site's *default* state; (2) 2016 returns
/// an empty string outright for an empty (post-cleaning) key, while this
/// node rejects an empty key as a `BadParam` -- neither case arises for a
/// real key like rev1's.
Beaufort, BEAUFORT, "beaufort", "1.0.0", Family::Xf, schema = BEAUFORT_SCHEMA, |input, p| {
    let key = p.req_str("beaufort", "key")?.as_bytes();
    if key.is_empty() {
        return Err(Error::bad_param("beaufort", "key", "must not be empty"));
    }
    let alphabet = p.opt_str("alphabet").unwrap_or(BEAUFORT_DEFAULT_ALPHABET).as_bytes();
    if alphabet.is_empty() {
        return Err(Error::bad_param("beaufort", "alphabet", "must not be empty"));
    }
    let n = alphabet.len();

    let key_idx: Vec<usize> = key
        .iter()
        .map(|&kc| {
            alphabet.iter().position(|&a| a == kc).ok_or_else(|| {
                Error::bad_param(
                    "beaufort",
                    "key",
                    format!("key character {:?} is not in the alphabet", kc as char),
                )
            })
        })
        .collect::<Result<_>>()?;

    let mut key_pos = 0usize;
    let out: Vec<u8> = input
        .data
        .iter()
        .map(|&c| match alphabet.iter().position(|&a| a == c) {
            Some(ci) => {
                let ki = key_idx[key_pos % key_idx.len()];
                key_pos += 1;
                alphabet[(ki + n - ci % n) % n]
            }
            None => c,
        })
        .collect();
    Ok(Repr::new(out, input.display))
});

const INSERT_SCHEMA: &[ParamSpec] = &[
    ParamSpec::req("text", ParamType::Str, "literal bytes to splice in"),
    ParamSpec::req("pos", ParamType::Int, "insertion position, interpreted per `unit`"),
    ParamSpec::opt(
        "unit",
        ParamType::Str,
        "\"byte\" (default): pos is a raw 0-based byte offset into the \
         representation. \"hexpair\": pos counts complete hex-digit pairs \
         (bigrams), skipping any non-hex-digit separators; insertion lands \
         immediately after the pos'th pair (pos=0 inserts before the first).",
    ),
];

simple_node!(
/// Repairs a ciphertext that is missing bytes, by splicing literal text in at a
/// caller-specified position.
///
/// rev8's recorded solution opens with "insert missing '63' between the 131st
/// and 132nd bigram", applied to the raw hex *display* text before it is
/// decoded. A hex "bigram" there is a two-character hex-digit pair denoting one
/// byte of the eventual ciphertext — it is emphatically not a raw byte offset
/// into [`Repr::data`], because rev8's ciphertext is transcribed as
/// space-separated pairs (`"38 63 39 37 ..."`), so a plain byte count would land
/// the insertion on the wrong side of a separator once earlier repairs shift
/// things around.
///
/// `text` accepts either a string or an integer parameter value: the CLI's
/// chain-spec parser reads any bare numeral (like the corpus's own `63`) as an
/// integer rather than a string, and a two-digit decimal hex bigram such as
/// `63` is spelled identically either way, so an integer is rendered back to
/// its decimal digits rather than rejected as the wrong type.
///
/// `pos` is therefore interpreted per the `unit` parameter, which trades
/// generality for corpus fidelity:
/// - `"byte"` (default) — `pos` is a literal 0-based byte offset into
///   `input.data`; `text`'s bytes are spliced in there verbatim. This is the
///   general-purpose, representation-agnostic mode.
/// - `"hexpair"` — `pos` counts complete hex-digit pairs, ignoring any
///   non-hex-digit separator bytes (spaces, newlines, ...) wherever they fall.
///   The insertion point lands immediately after the `pos`'th pair, so
///   `pos=131` reproduces "between the 131st and 132nd bigram" directly from
///   the corpus note. `text` is still inserted as literal raw bytes at the
///   resolved offset (typically a two hex-digit string like `"63"`), not
///   decoded — decoding happens in the next chain step.
///
/// Both units report an error rather than panicking when `pos` falls outside
/// the input (a byte offset past the end, or a bigram index past the last
/// complete pair).
Insert, INSERT, "insert", "1.0.0", Family::Xf, schema = INSERT_SCHEMA, |input, p| {
    let text: std::borrow::Cow<'_, str> = match p.get("text") {
        Some(crate::params::Value::Str(s)) => std::borrow::Cow::Borrowed(s.as_str()),
        Some(crate::params::Value::Int(i)) => std::borrow::Cow::Owned(i.to_string()),
        Some(other) => {
            return Err(Error::bad_param(
                "insert",
                "text",
                format!("expected a string or integer, got {other:?}"),
            ));
        }
        None => {
            return Err(Error::MissingParam {
                node: "insert".to_string(),
                param: "text".to_string(),
            });
        }
    };
    let text = text.as_ref();
    let pos = p.req_i64("insert", "pos")?;
    if pos < 0 {
        return Err(Error::bad_param("insert", "pos", "must be non-negative"));
    }
    let pos = pos as usize;
    let unit = p.opt_str("unit").unwrap_or("byte");

    let offset = match unit {
        "byte" => {
            if pos > input.data.len() {
                return Err(Error::bad_param(
                    "insert",
                    "pos",
                    format!(
                        "byte offset {pos} out of range for a {}-byte input",
                        input.data.len()
                    ),
                ));
            }
            pos
        }
        "hexpair" => {
            let hex_positions: Vec<usize> = input
                .data
                .iter()
                .enumerate()
                .filter(|(_, b)| b.is_ascii_hexdigit())
                .map(|(i, _)| i)
                .collect();
            let total_pairs = hex_positions.len() / 2;
            if pos > total_pairs {
                return Err(Error::bad_param(
                    "insert",
                    "pos",
                    format!("bigram position {pos} out of range ({total_pairs} bigrams present)"),
                ));
            }
            if pos == 0 {
                hex_positions.first().copied().unwrap_or(0)
            } else {
                hex_positions[pos * 2 - 1] + 1
            }
        }
        other => {
            return Err(Error::bad_param(
                "insert",
                "unit",
                format!("expected \"byte\" or \"hexpair\", got {other:?}"),
            ));
        }
    };

    let mut out = Vec::with_capacity(input.data.len() + text.len());
    out.extend_from_slice(&input.data[..offset]);
    out.extend_from_slice(text.as_bytes());
    out.extend_from_slice(&input.data[offset..]);
    Ok(Repr::new(out, input.display))
});

// ---------------------------------------------------------------------------
// codec: display changes
// ---------------------------------------------------------------------------

simple_node!(B64Decode, B64DECODE, "b64decode", "1.0.0", Family::Codec, schema = &[], |input, _p| {
    let d = repr::decode_base64(&input.data)
        .ok_or_else(|| Error::node_failed("b64decode", "input is not valid base64"))?;
    Ok(Repr::new(d, Display::Bytes))
});

simple_node!(B64Encode, B64ENCODE, "b64encode", "1.0.0", Family::Codec, schema = &[], |input, _p| {
    let s = base64::engine::general_purpose::STANDARD.encode(&input.data);
    Ok(Repr::new(s.into_bytes(), Display::Base64))
});

simple_node!(HexDecode, HEXDECODE, "hexdecode", "1.0.0", Family::Codec, schema = &[], |input, _p| {
    let d = repr::decode_hex(&input.data)
        .ok_or_else(|| Error::node_failed("hexdecode", "input is not valid hex"))?;
    Ok(Repr::new(d, Display::Bytes))
});

const HEXENC_SCHEMA: &[ParamSpec] = &[ParamSpec::opt(
    "uppercase",
    ParamType::Bool,
    "emit uppercase hex (default true)",
)];

simple_node!(HexEncode, HEXENCODE, "hexencode", "1.0.0", Family::Codec, schema = HEXENC_SCHEMA, |input, p| {
    let s = if p.opt_bool("uppercase", true) {
        hex::encode_upper(&input.data)
    } else {
        hex::encode(&input.data)
    };
    Ok(Repr::new(s.into_bytes(), Display::Hex))
});

simple_node!(DecimalDecode, DECDECODE, "decimaldecode", "1.0.0", Family::Codec, schema = &[], |input, _p| {
    let d = repr::decode_radix(&input.data, 10)
        .ok_or_else(|| Error::node_failed("decimaldecode", "input is not whitespace-separated decimal"))?;
    Ok(Repr::new(d, Display::Bytes))
});

simple_node!(OctalDecode, OCTDECODE, "octaldecode", "1.0.0", Family::Codec, schema = &[], |input, _p| {
    let d = repr::decode_radix(&input.data, 8)
        .ok_or_else(|| Error::node_failed("octaldecode", "input is not whitespace-separated octal"))?;
    Ok(Repr::new(d, Display::Bytes))
});

simple_node!(
/// `hex_to_base64` as it appears throughout the solved corpus: the solver pasted a
/// hex string into a converter and fed the base64 into the next decrypt box. It is
/// a *display* change only, so it is emphatically not a layer.
HexToB64, HEXTOB64, "hex_to_base64", "1.0.0", Family::Codec, schema = &[], |input, _p| {
    let raw = repr::decode_hex(&input.data)
        .ok_or_else(|| Error::node_failed("hex_to_base64", "input is not valid hex"))?;
    let s = base64::engine::general_purpose::STANDARD.encode(raw);
    Ok(Repr::new(s.into_bytes(), Display::Base64))
});

#[cfg(test)]
mod tests {
    use super::*;
    use crate::params;
    use crate::registry::registry;

    #[test]
    fn reverse_words_reverses_token_order_not_characters() {
        let n = registry().get("reverse_words").unwrap();
        let out = n.apply(&Repr::bytes(b"one two three".to_vec()), &Params::new()).unwrap();
        assert_eq!(out.data, b"three two one");

        // Genuinely distinct from full character reversal on the same input.
        let rev = registry().get("reverse").unwrap();
        let reversed = rev.apply(&Repr::bytes(b"one two three".to_vec()), &Params::new()).unwrap();
        assert_ne!(out.data, reversed.data);
    }

    #[test]
    fn reverse_words_collapses_whitespace_runs() {
        let n = registry().get("reverse_words").unwrap();
        let out = n.apply(&Repr::bytes(b"  one   two  three ".to_vec()), &Params::new()).unwrap();
        assert_eq!(out.data, b"three two one");
    }

    #[test]
    fn reverse_words_is_xf_family_and_not_layer_forming() {
        let n = registry().get("reverse_words").unwrap();
        assert_eq!(n.family(), Family::Xf);
        assert!(!n.layer_forming());
        assert!(!n.terminal());
    }

    #[test]
    fn rot_is_involutive_at_13_and_handles_negatives() {
        let r = registry().get("rot").unwrap();
        let input = Repr::bytes(b"Attack at Dawn, 5 units!".to_vec());
        let once = r.apply(&input, &params! {"n" => 13i64}).unwrap();
        let twice = r.apply(&once, &params! {"n" => 13i64}).unwrap();
        assert_eq!(twice.data, input.data);

        let up = r.apply(&input, &params! {"n" => 6i64}).unwrap();
        let down = r.apply(&up, &params! {"n" => -6i64}).unwrap();
        assert_eq!(down.data, input.data);
    }

    #[test]
    fn codec_round_trips_preserve_canonical_bytes() {
        let reg = registry();
        let raw = Repr::bytes(b"\x00\xff\x10sample".to_vec());
        for (enc, dec) in [("hexencode", "hexdecode"), ("b64encode", "b64decode")] {
            let e = reg.get(enc).unwrap().apply(&raw, &Params::new()).unwrap();
            let d = reg.get(dec).unwrap().apply(&e, &Params::new()).unwrap();
            assert_eq!(d.data, raw.data, "{enc}/{dec} round trip");
            assert_eq!(e.canonical_bytes(), raw.data, "{enc} canonical bytes");
        }
    }

    #[test]
    fn group_inserts_separators_without_changing_content() {
        let g = registry().get("group").unwrap();
        let out = g
            .apply(&Repr::bytes(b"ABCDEFGHIJ".to_vec()), &params! {"n" => 5i64})
            .unwrap();
        assert_eq!(out.data, b"ABCDE FGHIJ");
    }

    #[test]
    fn substitute_rejects_malformed_alphabets() {
        let s = registry().get("substitute").unwrap();
        let bad = params! {"alphabet" => "tooshort"};
        assert!(s.apply(&Repr::bytes(b"abc".to_vec()), &bad).is_err());
    }

    /// The rev6 substitution alphabet, applied to a known mapping.
    #[test]
    fn substitute_applies_corpus_alphabet() {
        let s = registry().get("substitute").unwrap();
        let p = params! {"alphabet" => "hdixvqlmenojkpbrstcufwgyza"};
        let out = s.apply(&Repr::bytes(b"abc XYZ".to_vec()), &p).unwrap();
        // a->h, b->d, c->i ; X->Y, Y->Z, Z->A (uppercase preserved)
        assert_eq!(out.data, b"hdi YZA");
    }

    #[test]
    fn insert_is_xf_family_and_not_layer_forming() {
        let n = registry().get("insert").unwrap();
        assert_eq!(n.family(), Family::Xf);
        assert!(!n.layer_forming());
        assert!(!n.terminal());
    }

    #[test]
    fn insert_byte_unit_at_start_middle_end() {
        let n = registry().get("insert").unwrap();

        let start = n
            .apply(&Repr::bytes(b"world".to_vec()), &params! {"text" => "hello ", "pos" => 0i64})
            .unwrap();
        assert_eq!(start.data, b"hello world");

        let middle = n
            .apply(&Repr::bytes(b"helloworld".to_vec()), &params! {"text" => " ", "pos" => 5i64})
            .unwrap();
        assert_eq!(middle.data, b"hello world");

        let end = n
            .apply(&Repr::bytes(b"hello".to_vec()), &params! {"text" => " world", "pos" => 5i64})
            .unwrap();
        assert_eq!(end.data, b"hello world");
    }

    #[test]
    fn insert_byte_unit_out_of_range_errors_not_panics() {
        let n = registry().get("insert").unwrap();
        let input = Repr::bytes(b"hello".to_vec());
        let result = n.apply(&input, &params! {"text" => "x", "pos" => 6i64});
        assert!(result.is_err());
    }

    /// The rev8 case: inserting a missing hex bigram into a space-separated hex
    /// dump, counting bigrams rather than raw bytes.
    #[test]
    fn insert_hexpair_unit_lands_between_bigrams() {
        let n = registry().get("insert").unwrap();
        let input = Repr::bytes(b"aa bb cc".to_vec());

        // Insert "63" between the 1st and 2nd bigram ("aa" and "bb").
        let out = n
            .apply(&input, &params! {"text" => "63", "pos" => 1i64, "unit" => "hexpair"})
            .unwrap();
        assert_eq!(out.data, b"aa63 bb cc");

        // pos=0 inserts before the very first bigram.
        let start = n
            .apply(&input, &params! {"text" => "99", "pos" => 0i64, "unit" => "hexpair"})
            .unwrap();
        assert_eq!(start.data, b"99aa bb cc");

        // pos=3 (the total bigram count) inserts after the last bigram.
        let end = n
            .apply(&input, &params! {"text" => "dd", "pos" => 3i64, "unit" => "hexpair"})
            .unwrap();
        assert_eq!(end.data, b"aa bb ccdd");
    }

    /// The CLI's chain-spec parser reads a bare numeral like `63` as an integer
    /// parameter, not a string — this is exactly the corpus's own hex bigram, so
    /// `insert` must accept it rather than requiring callers to work around the
    /// parser.
    #[test]
    fn insert_accepts_integer_text_as_decimal_digits() {
        let n = registry().get("insert").unwrap();
        let input = Repr::bytes(b"aa bb cc".to_vec());
        let out = n
            .apply(&input, &params! {"text" => 63i64, "pos" => 1i64, "unit" => "hexpair"})
            .unwrap();
        assert_eq!(out.data, b"aa63 bb cc");
    }

    /// Hand-computed over a 3-letter alphabet with a 2-character key: "ABC"
    /// encrypts to "AAB" under key "AB", worked out by hand from
    /// `A[(indexOf(K[i mod 2]) - indexOf(c)) mod 3]`.
    #[test]
    fn beaufort_hand_computed_small_alphabet() {
        let b = registry().get("beaufort").unwrap();
        let p = params! {"key" => "AB", "alphabet" => "ABC"};
        let out = b.apply(&Repr::bytes(b"ABC".to_vec()), &p).unwrap();
        assert_eq!(out.data, b"AAB");
    }

    /// Beaufort is reciprocal: applying it twice with the same key and alphabet
    /// returns the original input, for both the default corpus alphabet and a
    /// small custom one.
    #[test]
    fn beaufort_is_reciprocal() {
        let b = registry().get("beaufort").unwrap();

        let p = params! {"key" => "ZOMBIES"};
        let input = Repr::bytes(b"The many worlds are now one.".to_vec());
        let once = b.apply(&input, &p).unwrap();
        let twice = b.apply(&once, &p).unwrap();
        assert_eq!(twice.data, input.data);
        assert_ne!(once.data, input.data);

        let p2 = params! {"key" => "AB", "alphabet" => "ABC"};
        let input2 = Repr::bytes(b"ABCCBA".to_vec());
        let once2 = b.apply(&input2, &p2).unwrap();
        let twice2 = b.apply(&once2, &p2).unwrap();
        assert_eq!(twice2.data, input2.data);
    }

    /// Characters outside the alphabet pass through unchanged, but still occupy a
    /// position and advance the key phase for the characters around them.
    #[test]
    fn beaufort_passes_through_non_alphabet_characters() {
        let b = registry().get("beaufort").unwrap();
        let p = params! {"key" => "ZOMBIES"};
        let out = b
            .apply(&Repr::bytes(b"Hi, 123! bye.".to_vec()), &p)
            .unwrap();
        // Every byte that is not in the default mixed-case alphabet survives
        // untouched, at the same position.
        for (i, &c) in b"Hi, 123! bye.".iter().enumerate() {
            if !c.is_ascii_alphabetic() {
                assert_eq!(out.data[i], c, "byte {i} ({c:?}) should pass through");
            }
        }
    }

    /// A passthrough byte must not consume a key position: the alphabetic
    /// character right after it should be transformed exactly as if the
    /// passthrough byte were not there at all.
    #[test]
    fn beaufort_passthrough_does_not_advance_key_phase() {
        let b = registry().get("beaufort").unwrap();
        let p = params! {"key" => "AB", "alphabet" => "ABC"};

        let plain = b.apply(&Repr::bytes(b"AA".to_vec()), &p).unwrap();
        assert_eq!(plain.data, b"AB");

        let with_gap = b.apply(&Repr::bytes(b"A9A".to_vec()), &p).unwrap();
        assert_eq!(with_gap.data, b"A9B");
    }

    #[test]
    fn beaufort_rejects_key_characters_outside_the_alphabet() {
        let b = registry().get("beaufort").unwrap();
        let p = params! {"key" => "Z9", "alphabet" => "ABC"};
        assert!(b.apply(&Repr::bytes(b"ABC".to_vec()), &p).is_err());
    }

    /// Cross-check against the **2016** CrypTool Online Beaufort tool
    /// (`docs/toolsites/cryptool2016/js/beaufort.js`,
    /// `CTOBeaufortAlgorithm.crypt`), the era that actually made TG4 -- see
    /// this node's module docs for why this matters and what was checked.
    /// Ground truth: `beaufort.js` run directly under Node with a minimal
    /// DOM/global shim (task scratchpad `jstest/run_beaufort.js`), using the
    /// site's own default alphabet (52 chars, `A`-`Z` then `a`-`z`, case-
    /// sensitive positions -- structurally the same convention this node's
    /// `BEAUFORT_DEFAULT_ALPHABET` already uses) and default checkbox state
    /// (`signs` checked, i.e. keep non-alphabet characters; `casesensitiv`
    /// checked, i.e. no forced case).
    #[test]
    fn beaufort_matches_2016_cryptool_online_beaufort_js() {
        let b = registry().get("beaufort").unwrap();
        let p = params! {"key" => "ZOMBIES"};

        // beaufort.js encrypt("ZOMBIES", "The Quick, Brown Fox! 123", "ignore")
        let ct = "Ghi lOWqp, NVNMR NlR! 123";
        let out = b.apply(&Repr::bytes(ct.as_bytes().to_vec()), &p).unwrap();
        assert_eq!(
            String::from_utf8(out.data).unwrap(),
            "The Quick, Brown Fox! 123"
        );

        // beaufort.js encrypt("ZOMBIES", "HELLOWORLD", "ignore")
        let ct2 = "SKBquiEIDJ";
        let out2 = b.apply(&Repr::bytes(ct2.as_bytes().to_vec()), &p).unwrap();
        assert_eq!(String::from_utf8(out2.data).unwrap(), "HELLOWORLD");
    }

    #[test]
    fn beaufort_is_xf_family_and_not_layer_forming() {
        let n = registry().get("beaufort").unwrap();
        assert_eq!(n.family(), Family::Xf);
        assert!(!n.layer_forming());
        assert!(!n.terminal());
    }

    #[test]
    fn insert_hexpair_unit_out_of_range_errors_not_panics() {
        let n = registry().get("insert").unwrap();
        let input = Repr::bytes(b"aa bb cc".to_vec());
        let result = n.apply(&input, &params! {"text" => "63", "pos" => 4i64, "unit" => "hexpair"});
        assert!(result.is_err());
    }
}

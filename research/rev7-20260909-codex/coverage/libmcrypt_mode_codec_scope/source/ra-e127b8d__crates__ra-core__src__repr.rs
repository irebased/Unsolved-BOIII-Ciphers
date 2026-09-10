use base64::Engine as _;
use serde::{Deserialize, Serialize};

/// How a value is currently being *displayed*, as distinct from what it denotes.
#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Display {
    Bytes,
    Hex,
    Base64,
    Decimal,
    Octal,
}

impl Display {
    pub fn as_str(self) -> &'static str {
        match self {
            Display::Bytes => "bytes",
            Display::Hex => "hex",
            Display::Base64 => "base64",
            Display::Decimal => "decimal",
            Display::Octal => "octal",
        }
    }
}

/// A value plus how it is currently displayed.
///
/// [`Repr::canonical_bytes`] recovers the byte sequence the representation
/// *denotes*, by normalising the display away. Pure re-encoding
/// (`bytes -> hex -> base64`) changes [`Repr::data`] but leaves the canonical
/// bytes identical — which is precisely why such a move is **not** a layer.
/// This is the mechanism that makes the semantic definition of a layer computable.
#[derive(Clone, PartialEq, Eq, Debug)]
pub struct Repr {
    pub data: Vec<u8>,
    pub display: Display,
}

impl Repr {
    pub fn new(data: impl Into<Vec<u8>>, display: Display) -> Self {
        Self {
            data: data.into(),
            display,
        }
    }

    pub fn bytes(data: impl Into<Vec<u8>>) -> Self {
        Self::new(data, Display::Bytes)
    }

    pub fn text(s: &str, display: Display) -> Self {
        Self::new(s.as_bytes().to_vec(), display)
    }

    pub fn len(&self) -> usize {
        self.data.len()
    }

    pub fn is_empty(&self) -> bool {
        self.data.is_empty()
    }

    /// Undo the display encoding to recover the denoted bytes.
    ///
    /// Deliberately lossy-tolerant: a malformed display falls back to the raw
    /// bytes rather than erroring, because layer detection must still produce a
    /// comparison for inputs mid-pipeline that are not yet well formed.
    pub fn canonical_bytes(&self) -> Vec<u8> {
        match self.display {
            Display::Bytes => self.data.clone(),
            Display::Hex => decode_hex(&self.data).unwrap_or_else(|| self.data.clone()),
            Display::Base64 => decode_base64(&self.data).unwrap_or_else(|| self.data.clone()),
            Display::Decimal => decode_radix(&self.data, 10).unwrap_or_else(|| self.data.clone()),
            Display::Octal => decode_radix(&self.data, 8).unwrap_or_else(|| self.data.clone()),
        }
    }
}

/// Like [`Repr::canonical_bytes`] but **reports** a failed decode instead of
/// falling back to the undecoded text.
///
/// `canonical_bytes` is deliberately lenient: for a corpus record whose display is
/// only a hint, returning the raw text is better than nothing. That leniency is
/// wrong the moment a pipeline step has *changed* the text — a `--pre` transform
/// that alters the length can make a base64 display undecodable, and the lenient
/// path then hands the still-encoded text to the next layer, which scores it as if
/// it were a decryption. That produced 16 phantom sweep hits at a perfect oracle
/// score. Callers that treat the decode as a real step must use this.
impl Repr {
    pub fn canonical_bytes_strict(&self) -> Option<Vec<u8>> {
        match self.display {
            Display::Bytes => Some(self.data.clone()),
            Display::Hex => decode_hex(&self.data),
            Display::Base64 => decode_base64(&self.data),
            Display::Decimal => decode_radix(&self.data, 10),
            Display::Octal => decode_radix(&self.data, 8),
        }
    }
}

pub fn decode_hex(data: &[u8]) -> Option<Vec<u8>> {
    let mut s: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| c.is_ascii_hexdigit())
        .collect();
    if s.len() % 2 == 1 {
        s.pop();
    }
    hex::decode(&s).ok()
}

pub fn decode_base64(data: &[u8]) -> Option<Vec<u8>> {
    let mut s: Vec<u8> = data
        .iter()
        .copied()
        .filter(|c| c.is_ascii_alphanumeric() || *c == b'+' || *c == b'/' || *c == b'=')
        .collect();
    // re-pad; mid-pipeline values are frequently unpadded
    while s.len() % 4 != 0 {
        s.push(b'=');
    }
    base64::engine::general_purpose::STANDARD.decode(&s).ok()
}

/// Whitespace-separated numeric groups in the given radix, one byte per group.
pub fn decode_radix(data: &[u8], radix: u32) -> Option<Vec<u8>> {
    let s = std::str::from_utf8(data).ok()?;
    let mut out = Vec::new();
    for tok in s.split_ascii_whitespace() {
        out.push(u8::from_str_radix(tok, radix).ok()?);
    }
    if out.is_empty() {
        None
    } else {
        Some(out)
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// The governing invariant: pure re-encoding preserves canonical bytes.
    #[test]
    fn re_encoding_preserves_canonical_bytes() {
        let raw = b"\x00\x01\xfe\xffhello world".to_vec();
        let as_hex = Repr::new(hex::encode_upper(&raw).into_bytes(), Display::Hex);
        let as_b64 = Repr::new(
            base64::engine::general_purpose::STANDARD
                .encode(&raw)
                .into_bytes(),
            Display::Base64,
        );
        assert_eq!(as_hex.canonical_bytes(), raw);
        assert_eq!(as_b64.canonical_bytes(), raw);
        assert_eq!(as_hex.canonical_bytes(), as_b64.canonical_bytes());
    }

    #[test]
    fn decimal_and_octal_groups() {
        let d = Repr::new(b"065 066 067".to_vec(), Display::Decimal);
        assert_eq!(d.canonical_bytes(), b"ABC");
        let o = Repr::new(b"101 102 103".to_vec(), Display::Octal);
        assert_eq!(o.canonical_bytes(), b"ABC");
    }

    #[test]
    fn malformed_display_falls_back_to_raw() {
        let r = Repr::new(b"not hex at all zz".to_vec(), Display::Decimal);
        assert_eq!(r.canonical_bytes(), b"not hex at all zz");
    }

    /// Whitespace-robustness audit (see fix/whitespace-robustness): a web hex
    /// tool's trailing newline, or a leading space from a paste, must not
    /// break the decode. `decode_hex` already filters to hexdigits only, so
    /// any non-hex byte -- whitespace or otherwise -- is dropped rather than
    /// misaligning the pairing.
    #[test]
    fn decode_hex_tolerates_leading_trailing_and_interior_whitespace() {
        let clean = decode_hex(b"48656c6c6f").unwrap();
        assert_eq!(decode_hex(b"48656c6c6f\n").unwrap(), clean);
        assert_eq!(decode_hex(b" 48656c6c6f").unwrap(), clean);
        assert_eq!(decode_hex(b"4865 6c6c 6f").unwrap(), clean);
        assert_eq!(decode_hex(b"4865\n6c6c\n6f\n").unwrap(), clean);
    }

    /// Same property for base64: an interior newline (the classic wrapped
    /// web-tool output) or a leading/trailing space must not prevent the decode.
    #[test]
    fn decode_base64_tolerates_leading_trailing_and_interior_whitespace() {
        let clean = decode_base64(b"aGVsbG8gd29ybGQ=").unwrap();
        assert_eq!(decode_base64(b"aGVsbG8gd29ybGQ=\n").unwrap(), clean);
        assert_eq!(decode_base64(b" aGVsbG8gd29ybGQ=").unwrap(), clean);
        assert_eq!(decode_base64(b"aGVsbG8g\nd29ybGQ=").unwrap(), clean);
    }

    /// `decode_radix` already splits on any run of ASCII whitespace, so
    /// leading/trailing whitespace around a whitespace-separated decimal or
    /// octal intermediate is a no-op, not a decode failure.
    #[test]
    fn decode_radix_tolerates_leading_and_trailing_whitespace() {
        let clean = decode_radix(b"065 066 067", 10).unwrap();
        assert_eq!(decode_radix(b"065 066 067\n", 10).unwrap(), clean);
        assert_eq!(decode_radix(b" \t065 066 067", 10).unwrap(), clean);
        assert_eq!(decode_radix(b"065  066\n067", 10).unwrap(), clean);
    }
}

#[cfg(test)]
mod strict_tests {
    use super::*;

    /// The lenient form returns the UNDECODED text when the decode fails; the strict
    /// form reports it. This is the difference that produced 16 phantom sweep hits:
    /// a `--pre` transform left 191 base64 characters (not a multiple of 4), the
    /// lenient decode handed the still-encoded text downstream, and the oracle scored
    /// it 1.0000 as "valid base64".
    #[test]
    fn strict_reports_a_failed_decode_where_lenient_hides_it() {
        // length == 1 (mod 4) can never be valid base64, whatever the padding rules
        let bad = Repr::new(b"abcde".to_vec(), Display::Base64);
        assert_eq!(bad.canonical_bytes(), b"abcde".to_vec(), "lenient hides the failure");
        assert!(bad.canonical_bytes_strict().is_none(), "strict must report it");

        let good = Repr::new(b"aGVsbG8=".to_vec(), Display::Base64);
        assert_eq!(good.canonical_bytes_strict().unwrap(), b"hello".to_vec());
        assert_eq!(good.canonical_bytes(), b"hello".to_vec());
    }

    #[test]
    fn strict_agrees_with_lenient_whenever_the_decode_succeeds() {
        for (data, d) in [
            (b"48656c6c6f".to_vec(), Display::Hex),
            (b"aGk=".to_vec(), Display::Base64),
            (b"raw bytes".to_vec(), Display::Bytes),
        ] {
            let r = Repr::new(data, d);
            assert_eq!(r.canonical_bytes_strict().unwrap(), r.canonical_bytes());
        }
    }
}

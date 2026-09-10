//! mcrypt-faithful mode engine.
//!
//! The single most consequential fact in the dossier is that mcrypt's mode named
//! `cfb` is **8-bit feedback** (CFB-8), whereas modern libraries reserve that name
//! for full-block feedback. mcrypt spells the full-block variant `ncfb`. The same
//! `n`-prefix convention applies to OFB. This is why CyberChef and most tooling
//! structurally cannot reproduce these ciphers.
//!
//! Verified against the corpus: rev9's first layer is DES/`cfb` over its base64
//! ciphertext, and it must yield whitespace-separated decimal groups because the
//! next documented step is a decimal decode. CFB-8 produces exactly that; nCFB,
//! OFB, CBC and ECB all produce noise.

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::prim::BlockPrim;

#[derive(Clone, Copy, PartialEq, Eq, Debug, Hash, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Mode {
    Ecb,
    Cbc,
    /// mcrypt `cfb`: 8-bit feedback. One block operation **per byte**.
    Cfb8,
    /// mcrypt `ncfb`: full-block feedback. What modern libraries call CFB.
    NCfb,
    /// mcrypt `ofb`: 8-bit output feedback.
    Ofb8,
    /// mcrypt `nofb`: full-block output feedback.
    NOfb,
    /// Native stream cipher (arcfour); no mode wrapper.
    Stream,
}

impl Mode {
    pub const ALL: [Mode; 7] = [
        Mode::Ecb,
        Mode::Cbc,
        Mode::Cfb8,
        Mode::NCfb,
        Mode::Ofb8,
        Mode::NOfb,
        Mode::Stream,
    ];

    /// The mcrypt spelling, which is the name that appears in coverage claims.
    pub fn as_str(self) -> &'static str {
        match self {
            Mode::Ecb => "ecb",
            Mode::Cbc => "cbc",
            Mode::Cfb8 => "cfb",
            Mode::NCfb => "ncfb",
            Mode::Ofb8 => "ofb",
            Mode::NOfb => "nofb",
            Mode::Stream => "stream",
        }
    }

    pub fn parse(s: &str) -> Option<Self> {
        match s.to_ascii_lowercase().as_str() {
            "ecb" => Some(Mode::Ecb),
            "cbc" => Some(Mode::Cbc),
            // "cfb8" is accepted because the dossier's coverage vocabulary uses it
            "cfb" | "cfb8" => Some(Mode::Cfb8),
            "ncfb" => Some(Mode::NCfb),
            "ofb" | "ofb8" => Some(Mode::Ofb8),
            "nofb" => Some(Mode::NOfb),
            "stream" => Some(Mode::Stream),
            _ => None,
        }
    }

    pub fn uses_iv(self) -> bool {
        !matches!(self, Mode::Ecb | Mode::Stream)
    }

    /// Whether a wrong IV corrupts only a bounded prefix. True for the
    /// self-synchronising feedback modes, which is what the block-aware oracle
    /// exploits.
    pub fn self_synchronising(self) -> bool {
        matches!(self, Mode::Cfb8 | Mode::NCfb | Mode::Cbc)
    }
}

impl fmt::Display for Mode {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(self.as_str())
    }
}

/// Fit an IV to the block size: truncate if long, null-pad if short.
fn fit_iv(iv: &[u8], bs: usize) -> Vec<u8> {
    let mut v = iv.to_vec();
    v.resize(bs, 0);
    v.truncate(bs);
    v
}

/// How a block mode is expected to treat an input whose length is not a
/// multiple of the block size. There are (at least) three mutually incompatible
/// conventions in circulation for the *same* libmcrypt algorithm, and which one
/// a tool implements changes whether a candidate is a result at all — so they
/// are named here rather than left implicit.
///
/// `ra` implements [`BlockLengthConvention::PhpPadAndRound`]; see
/// [`IMPLEMENTED_CONVENTION`] for why.
#[derive(Clone, Copy, PartialEq, Eq, Debug)]
pub enum BlockLengthConvention {
    /// What `ra` did before 2026-09-10: decrypt the whole blocks, copy any
    /// trailing partial block through **unchanged**, return the input length.
    /// This is not any real tool's behaviour — it presents raw ciphertext bytes
    /// as plaintext — and is recorded only so the old outputs in `notes/` can be
    /// recognised for what they were.
    LegacyRaPassThrough,
    /// The convention of the C port in `old-ciphers/wasm/mcrypt_wrapper.c`
    /// (`BLOCK_DISPATCH`): **reject** a non-aligned input on decrypt
    /// (`if (dlen % bs != 0) return -1;`), zero-pad on encrypt, and `zero_unpad`
    /// the decrypt output —
    ///
    /// ```c
    /// static int zero_unpad(byte *data, int datalen) {
    ///     while (datalen > 0 && data[datalen - 1] == 0) datalen--;
    ///     return datalen > 0 ? datalen : 0;
    /// }
    /// ```
    ///
    /// — which strips *every* trailing NUL, so an all-NUL block unpads to empty
    /// and a plaintext genuinely ending in NUL cannot survive a round trip. This
    /// is a defensible library API, but it is *not* what the historically
    /// relevant front end did, so `ra` does not implement it.
    CPortRejectAndUnpad,
    /// What PHP's `mcrypt_decrypt`/`mcrypt_encrypt` do, and therefore what any
    /// PHP mcrypt front end such as tools4noobs did. From PHP 5.6.25
    /// `ext/mcrypt/mcrypt.c`, `php_mcrypt_do_crypt` (file sha256
    /// `340fa4d3282823c7072c820704e0e544f0d863b12641a3b748d99cd9d3d7956d`):
    ///
    /// ```c
    /// if (mcrypt_enc_is_block_mode(td) == 1) { /* It's a block algorithm */
    ///     int block_size = mcrypt_enc_get_block_size(td);
    ///     data_size = (((data_len - 1) / block_size) + 1) * block_size;
    ///     data_s = emalloc(data_size + 1);
    ///     memset(data_s, 0, data_size);
    ///     memcpy(data_s, data, data_len);
    /// } else { /* It's not a block algorithm */
    ///     data_size = data_len;
    ///     data_s = emalloc(data_size + 1);
    ///     memcpy(data_s, data, data_len);
    /// }
    /// ...
    /// mdecrypt_generic(td, data_s, data_size);
    /// data_s[data_size] = 0;
    /// RETVAL_STRINGL(data_s, data_size, 0);
    /// ```
    ///
    /// So: round the length **up** to a block multiple, NUL-fill the tail,
    /// crypt the whole buffer, and return the **rounded-up** length. Nothing is
    /// rejected and nothing is unpadded — a 546-byte input to an 8-byte block
    /// comes back as 552 bytes, and to a 16-byte block as 560. The identical
    /// code path serves both directions, so encrypt rounds up too.
    ///
    /// `mcrypt_enc_is_block_mode` is true only for `ecb` and `cbc`; `cfb`
    /// (CFB-8), `ncfb`, `ofb` (OFB-8), `nofb` and `stream` take the
    /// exact-length branch and are length-preserving.
    PhpPadAndRound,
}

/// The convention [`decrypt`] and [`encrypt`] implement.
///
/// PHP wins over the C port because tools4noobs — the tool the corpus's ciphers
/// were actually produced with — was a PHP mcrypt front end, so PHP's wrapper
/// semantics are the ones that shaped the artefacts. The C port
/// (`old-ciphers/wasm/mcrypt_wrapper.c`) is a later, independent wrapper around
/// the same library and its choices are its own.
///
/// **OPEN QUESTION, not a decision:** whether the tools4noobs *site* trimmed
/// trailing NULs (or other whitespace) before displaying the result is unknown
/// — no primary source for the site's PHP has been found. If it did, a fourth,
/// application-layer convention exists on top of this one, and outputs whose
/// only difference is a NUL tail would be indistinguishable. Nothing in `ra`
/// currently assumes either answer.
pub const IMPLEMENTED_CONVENTION: BlockLengthConvention = BlockLengthConvention::PhpPadAndRound;

/// PHP's `data_size = (((data_len - 1) / block_size) + 1) * block_size` with the
/// NUL fill, i.e. [`BlockLengthConvention::PhpPadAndRound`]'s buffer.
///
/// Note the C integer arithmetic on an **empty** input: `(0 - 1) / bs` truncates
/// toward zero to `0`, so `data_size` is one full block of NULs rather than
/// nothing. That edge is reproduced rather than "fixed"; it is what PHP returns.
fn php_block_buffer(data: &[u8], bs: usize) -> Vec<u8> {
    let rounded = if data.is_empty() || data.len() % bs != 0 {
        (data.len() / bs + 1) * bs
    } else {
        data.len()
    };
    let mut out = vec![0u8; rounded];
    out[..data.len()].copy_from_slice(data);
    out
}

/// A `Mode` that cannot be run against the primitive it was asked to wrap.
///
/// [`Mode::Stream`] is libmcrypt's spelling for a *native* stream cipher
/// (arcfour) running with no block-mode wrapper at all — it is not a block
/// mode in its own right. [`decrypt`]/[`encrypt`] only ever receive a
/// [`BlockPrim`], so reaching this arm always means the candidate asked for a
/// mode that structurally does not exist for the primitive it named. Callers
/// must surface this as a failure, never as a pass-through of the input: an
/// identity result here is indistinguishable from a genuine decrypt that
/// happens to be an involution, which is the exact failure mode this type
/// exists to rule out.
#[derive(Debug, thiserror::Error)]
pub enum ModeError {
    #[error("mode 'stream' has no block-cipher wrapping; it names a native stream cipher and does not apply here")]
    StreamIsNotABlockMode,
}

/// Decrypt `data` under `prim` in `mode`.
///
/// The two true block modes (`ecb`, `cbc`) round the input length **up** to a
/// multiple of the block size, NUL-filling the tail, and return the whole
/// rounded-length output with no unpadding — PHP's `mcrypt_decrypt`, see
/// [`BlockLengthConvention::PhpPadAndRound`]. A non-aligned input is therefore
/// a perfectly good candidate, not an error. The feedback modes (`cfb`/CFB-8,
/// `ncfb`, `ofb`/OFB-8, `nofb`) take the exact-length branch and are
/// length-preserving.
pub fn decrypt(
    prim: &dyn BlockPrim,
    mode: Mode,
    data: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, ModeError> {
    let bs = prim.block_size();
    let out = match mode {
        Mode::Cfb8 => cfb8(prim, data, iv, Feedback::Ciphertext, Xor::Decrypt),
        Mode::Ofb8 => cfb8(prim, data, iv, Feedback::Keystream, Xor::Decrypt),
        Mode::NCfb => ncfb_decrypt(prim, data, iv),
        Mode::NOfb => nofb(prim, data, iv),
        Mode::Stream => return Err(ModeError::StreamIsNotABlockMode),
        Mode::Ecb => {
            let mut out = php_block_buffer(data, bs);
            for chunk in out.chunks_exact_mut(bs) {
                prim.decrypt_block(chunk);
            }
            out
        }
        Mode::Cbc => {
            let padded = php_block_buffer(data, bs);
            let mut out = Vec::with_capacity(padded.len());
            let mut prev = fit_iv(iv, bs);
            for chunk in padded.chunks(bs) {
                let mut b = chunk.to_vec();
                prim.decrypt_block(&mut b);
                for (x, p) in b.iter_mut().zip(prev.iter()) {
                    *x ^= *p;
                }
                out.extend_from_slice(&b);
                prev = chunk.to_vec();
            }
            out
        }
    };
    Ok(out)
}

/// Encrypt `data` under `prim` in `mode`. Needed to build conformance fixtures
/// and to demonstrate the IV/mode properties.
///
/// `ecb`/`cbc` round the length up and NUL-fill exactly as [`decrypt`] does —
/// PHP runs both directions through one code path — so their ciphertext is
/// block-aligned; the feedback modes preserve length.
pub fn encrypt(
    prim: &dyn BlockPrim,
    mode: Mode,
    data: &[u8],
    iv: &[u8],
) -> Result<Vec<u8>, ModeError> {
    let bs = prim.block_size();
    let out = match mode {
        Mode::Cfb8 => cfb8(prim, data, iv, Feedback::Ciphertext, Xor::Encrypt),
        Mode::Ofb8 => cfb8(prim, data, iv, Feedback::Keystream, Xor::Encrypt),
        Mode::NCfb => ncfb_encrypt(prim, data, iv),
        // OFB is its own inverse
        Mode::NOfb => nofb(prim, data, iv),
        Mode::Stream => return Err(ModeError::StreamIsNotABlockMode),
        Mode::Ecb => {
            let mut out = php_block_buffer(data, bs);
            for chunk in out.chunks_exact_mut(bs) {
                prim.encrypt_block(chunk);
            }
            out
        }
        Mode::Cbc => {
            let padded = php_block_buffer(data, bs);
            let mut out = Vec::with_capacity(padded.len());
            let mut prev = fit_iv(iv, bs);
            for chunk in padded.chunks(bs) {
                let mut b = chunk.to_vec();
                for (x, p) in b.iter_mut().zip(prev.iter()) {
                    *x ^= *p;
                }
                prim.encrypt_block(&mut b);
                out.extend_from_slice(&b);
                prev = b;
            }
            out
        }
    };
    Ok(out)
}

#[derive(Clone, Copy)]
enum Feedback {
    /// CFB: shift the ciphertext byte into the register.
    Ciphertext,
    /// OFB: shift the keystream byte into the register.
    Keystream,
}

#[derive(Clone, Copy)]
enum Xor {
    Encrypt,
    Decrypt,
}

/// The shared 8-bit feedback loop.
///
/// One block operation per byte, which is why CFB-8 is roughly `block_size` times
/// slower than a full-block mode and is the dominant cost of any sweep.
fn cfb8(prim: &dyn BlockPrim, data: &[u8], iv: &[u8], fb: Feedback, dir: Xor) -> Vec<u8> {
    let bs = prim.block_size();
    let mut reg = fit_iv(iv, bs);
    let mut out = Vec::with_capacity(data.len());
    let mut buf = vec![0u8; bs];
    for &byte in data {
        buf.copy_from_slice(&reg);
        prim.encrypt_block(&mut buf);
        let ks = buf[0];
        let result = byte ^ ks;
        out.push(result);
        let shift_in = match fb {
            Feedback::Ciphertext => match dir {
                // the register always takes the *ciphertext* byte
                Xor::Encrypt => result,
                Xor::Decrypt => byte,
            },
            Feedback::Keystream => ks,
        };
        reg.copy_within(1.., 0);
        reg[bs - 1] = shift_in;
    }
    out
}

fn ncfb_decrypt(prim: &dyn BlockPrim, data: &[u8], iv: &[u8]) -> Vec<u8> {
    let bs = prim.block_size();
    let mut reg = fit_iv(iv, bs);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        let mut ks = reg.clone();
        prim.encrypt_block(&mut ks);
        out.extend(chunk.iter().zip(ks.iter()).map(|(c, k)| c ^ k));
        if chunk.len() == bs {
            reg.copy_from_slice(chunk);
        }
    }
    out
}

fn ncfb_encrypt(prim: &dyn BlockPrim, data: &[u8], iv: &[u8]) -> Vec<u8> {
    let bs = prim.block_size();
    let mut reg = fit_iv(iv, bs);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        let mut ks = reg.clone();
        prim.encrypt_block(&mut ks);
        let ct: Vec<u8> = chunk.iter().zip(ks.iter()).map(|(p, k)| p ^ k).collect();
        if ct.len() == bs {
            reg.copy_from_slice(&ct);
        }
        out.extend_from_slice(&ct);
    }
    out
}

fn nofb(prim: &dyn BlockPrim, data: &[u8], iv: &[u8]) -> Vec<u8> {
    let bs = prim.block_size();
    let mut reg = fit_iv(iv, bs);
    let mut out = Vec::with_capacity(data.len());
    for chunk in data.chunks(bs) {
        prim.encrypt_block(&mut reg);
        out.extend(chunk.iter().zip(reg.iter()).map(|(c, k)| c ^ k));
    }
    out
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::prim::instantiate_block;

    fn des() -> Box<dyn BlockPrim> {
        instantiate_block("des", b"Zombies\x00").unwrap()
    }

    #[test]
    fn every_mode_round_trips() {
        let p = des();
        let pt = b"THE GIANT AWAITS BENEATH THE CLOCKTOWER AT MIDNIGHT.....";
        let iv = b"0".repeat(8);
        for m in Mode::ALL {
            if m == Mode::Stream {
                continue;
            }
            let ct = encrypt(&*p, m, pt, &iv).unwrap();
            let rt = decrypt(&*p, m, &ct, &iv).unwrap();
            assert_eq!(rt, pt.to_vec(), "mode {m} did not round trip");
        }
    }

    /// `stream` names a native stream cipher with no block-mode wrapper; it is
    /// structurally inapplicable to a [`BlockPrim`] and must error rather than
    /// pass the input through unchanged.
    #[test]
    fn stream_mode_is_inapplicable_to_a_block_primitive() {
        let p = des();
        let pt = b"twelve bytes";
        let iv = b"0".repeat(8);
        assert!(matches!(
            encrypt(&*p, Mode::Stream, pt, &iv),
            Err(ModeError::StreamIsNotABlockMode)
        ));
        assert!(matches!(
            decrypt(&*p, Mode::Stream, pt, &iv),
            Err(ModeError::StreamIsNotABlockMode)
        ));
    }

    /// The property the block-aware oracle rests on: under CFB-8 a wrong IV
    /// corrupts *exactly* `block_size` bytes, then the stream self-synchronises.
    #[test]
    fn cfb8_wrong_iv_corrupts_exactly_one_block_then_recovers() {
        let p = des();
        let pt = b"THE BODY OF THE GIANT LIES BENEATH AND THE KEEPER GUARDS THE WAY HOME";
        let ct = encrypt(&*p, Mode::Cfb8, pt, &b"0".repeat(8)).unwrap();

        let good = decrypt(&*p, Mode::Cfb8, &ct, &b"0".repeat(8)).unwrap();
        let bad = decrypt(&*p, Mode::Cfb8, &ct, &[0u8; 8]).unwrap();

        assert_eq!(good, pt.to_vec());
        assert_ne!(bad[..8], pt[..8]);
        assert_eq!(&bad[8..], &pt[8..], "stream must recover after one block");
    }

    /// cfb (8-bit) and ncfb (full-block) must differ. This is the whole reason
    /// modern tooling cannot reproduce the corpus.
    #[test]
    fn cfb8_and_ncfb_are_different_modes() {
        let p = des();
        let pt = b"identical plaintext for both modes";
        let iv = b"0".repeat(8);
        assert_ne!(
            encrypt(&*p, Mode::Cfb8, pt, &iv).unwrap(),
            encrypt(&*p, Mode::NCfb, pt, &iv).unwrap()
        );
    }

    /// ASCII-zero IV is not a null IV. Both are 16 bytes of "zero" in casual
    /// speech; they are entirely different keystreams.
    #[test]
    fn ascii_zero_iv_differs_from_null_iv() {
        let p = des();
        let pt = b"the first block is where this shows up";
        let a = encrypt(&*p, Mode::Cfb8, pt, &b"0".repeat(8)).unwrap();
        let b = encrypt(&*p, Mode::Cfb8, pt, &[0u8; 8]).unwrap();
        assert_ne!(a, b);
    }

    #[test]
    fn ofb8_is_its_own_inverse_and_differs_from_cfb8() {
        let p = des();
        let pt = b"output feedback keeps the register independent of the data";
        let iv = b"0".repeat(8);
        let ct = encrypt(&*p, Mode::Ofb8, pt, &iv).unwrap();
        assert_eq!(decrypt(&*p, Mode::Ofb8, &ct, &iv).unwrap(), pt.to_vec());
        assert_ne!(ct, encrypt(&*p, Mode::Cfb8, pt, &iv).unwrap());
    }

    /// OFB-8's register feeds back only the single keystream byte it just
    /// produced, so a null IV can reach a genuine fixed point (not a mode
    /// dispatch bug): if `E(0-block)`'s first byte happens to be zero for a
    /// given key, the register never moves off all-zero and the keystream
    /// stays zero forever. This is a real, key-dependent property of 8-bit
    /// OFB with a null IV, not evidence the mode failed to run — a different
    /// key reliably produces a non-zero keystream from the same all-zero
    /// register. See `ofb8_null_iv_transforms_for_a_generic_key` and the
    /// `fix/noop-modes` report for the full derivation.
    #[test]
    fn ofb8_null_iv_fixed_point_is_key_dependent_not_a_mode_bug() {
        // "Zombies" is the corpus-standard demo key; under Blowfish its
        // E(0-block) happens to start with a zero byte, which is the
        // degenerate case. A different key does not share that coincidence.
        let degenerate = instantiate_block("blowfish", b"Zombies").unwrap();
        let generic = instantiate_block("blowfish", b"a-different-key-entirely").unwrap();
        let iv = [0u8; 8];
        for len in [16usize, 24] {
            let pt = vec![b'A'; len];
            let degenerate_ct = decrypt(&*degenerate, Mode::Ofb8, &pt, &iv).unwrap();
            assert_eq!(
                degenerate_ct, pt,
                "the degenerate key's keystream is a real, reproducible fixed point"
            );
            let generic_ct = decrypt(&*generic, Mode::Ofb8, &pt, &iv).unwrap();
            assert_ne!(
                generic_ct, pt,
                "a generic key's OFB-8 keystream over a null IV is not a no-op"
            );
        }
    }

    /// PHP's `php_mcrypt_do_crypt` rounds a block-mode length **up**:
    /// `data_size = (((data_len - 1) / block_size) + 1) * block_size`, NUL-fills
    /// the tail, decrypts the whole buffer and returns `data_size` bytes. So the
    /// corpus's 546-byte rev7 ciphertext is 552 bytes out of an 8-byte-block
    /// cipher and 560 out of a 16-byte one — not an error, and not 546.
    #[test]
    fn ecb_and_cbc_decrypt_round_the_length_up_like_php() {
        let data = vec![b'x'; 546];
        for (name, bs, expected) in [("des", 8usize, 552usize), ("rijndael-128", 16, 560)] {
            let mut key = b"Zombies".to_vec();
            key.resize(bs, 0);
            let p = instantiate_block(name, &key).unwrap();
            for m in [Mode::Ecb, Mode::Cbc] {
                let out = decrypt(&*p, m, &data, &b"0".repeat(bs)).unwrap();
                assert_eq!(
                    out.len(),
                    expected,
                    "{name}/{m} on {} bytes must return {expected}",
                    data.len()
                );
            }
        }
    }

    /// The same code path serves both directions in PHP, so encrypt rounds up
    /// too — and an already-aligned input gains no extra block (this is not
    /// PKCS#7).
    #[test]
    fn ecb_and_cbc_encrypt_round_the_length_up_like_php() {
        let p = des();
        let iv = b"0".repeat(8);
        for m in [Mode::Ecb, Mode::Cbc] {
            assert_eq!(encrypt(&*p, m, &vec![b'x'; 546], &iv).unwrap().len(), 552);
            assert_eq!(encrypt(&*p, m, b"0123456789", &iv).unwrap().len(), 16);
            assert_eq!(encrypt(&*p, m, b"01234567", &iv).unwrap().len(), 8);
        }
    }

    /// `mcrypt_enc_is_block_mode` is true only for ecb and cbc. cfb (CFB-8),
    /// ncfb, ofb (OFB-8) and nofb take PHP's exact-length branch
    /// (`data_size = data_len`) and must stay length-preserving for any input —
    /// TG4's own chain is DES/cfb over a non-aligned ciphertext.
    #[test]
    fn feedback_modes_preserve_the_exact_length_of_a_non_aligned_input() {
        let p = des();
        for data in [b"0123456789".to_vec(), vec![b'x'; 546]] {
            for m in [Mode::Cfb8, Mode::NCfb, Mode::Ofb8, Mode::NOfb] {
                let out = decrypt(&*p, m, &data, &b"0".repeat(8)).unwrap();
                assert_eq!(out.len(), data.len(), "mode {m} changed the length");
                let out = encrypt(&*p, m, &data, &b"0".repeat(8)).unwrap();
                assert_eq!(out.len(), data.len(), "mode {m} changed the length");
            }
        }
    }

    /// The filler PHP `memset`s in is genuinely NUL, which is checkable without
    /// trusting the implementation: decrypting the non-aligned input must equal
    /// decrypting the same bytes explicitly extended with zeros, and the final
    /// ECB block must be exactly `D(00..00)`.
    #[test]
    fn the_rounding_fill_is_nul_and_matches_an_independent_computation() {
        let p = des();
        let iv = b"0".repeat(8);
        let data = b"0123456789\xa1\xb2".to_vec(); // 12 bytes, 4 short of 16
        let mut explicit = data.clone();
        explicit.resize(16, 0);

        for m in [Mode::Ecb, Mode::Cbc] {
            let rounded = decrypt(&*p, m, &data, &iv).unwrap();
            let aligned = decrypt(&*p, m, &explicit, &iv).unwrap();
            assert_eq!(rounded, aligned, "mode {m} filled with something else");
            assert_eq!(rounded.len(), 16);
        }

        // Spelled out: the buffer's second block is the four leftover input
        // bytes followed by four NULs, and nothing else.
        let block2 = [data[8], data[9], data[10], data[11], 0, 0, 0, 0];

        // ECB's second output block is D(block2).
        let mut tail = block2;
        p.decrypt_block(&mut tail);
        let out = decrypt(&*p, Mode::Ecb, &data, &iv).unwrap();
        assert_eq!(hex_upper(&out[8..]), hex_upper(&tail));

        // CBC's is D(block2) XOR the preceding *ciphertext* block, which here is
        // the first 8 bytes of the input.
        let mut tail = block2;
        p.decrypt_block(&mut tail);
        for (x, c) in tail.iter_mut().zip(data[..8].iter()) {
            *x ^= *c;
        }
        let out = decrypt(&*p, Mode::Cbc, &data, &iv).unwrap();
        assert_eq!(hex_upper(&out[8..]), hex_upper(&tail));
    }

    /// A round trip through ecb/cbc recovers the input **plus** the NUL fill,
    /// because PHP never unpads. Fixture: the ciphertext of "HELLOAAAABCDEF"
    /// (14 bytes) decrypts to 16 bytes ending in two NULs — the byte string the
    /// C port's `zero_unpad` would have removed and PHP does not.
    #[test]
    fn ecb_decrypt_does_not_unpad() {
        let p = des();
        let ct = hex_bytes("B7C91DA438A928B88C854448A2CD0F1E");
        let out = decrypt(&*p, Mode::Ecb, &ct, &[]).unwrap();
        assert_eq!(hex_upper(&out), "48454C4C4F4141414142434445460000");
        assert_eq!(out.len(), 16);
    }

    fn hex_bytes(s: &str) -> Vec<u8> {
        (0..s.len() / 2)
            .map(|i| u8::from_str_radix(&s[2 * i..2 * i + 2], 16).unwrap())
            .collect()
    }

    fn hex_upper(b: &[u8]) -> String {
        b.iter().map(|x| format!("{x:02X}")).collect()
    }

    #[test]
    fn mode_names_follow_mcrypt_spelling() {
        assert_eq!(Mode::Cfb8.as_str(), "cfb");
        assert_eq!(Mode::NCfb.as_str(), "ncfb");
        assert_eq!(Mode::parse("cfb"), Some(Mode::Cfb8));
        assert_eq!(Mode::parse("cfb8"), Some(Mode::Cfb8));
        assert_eq!(Mode::parse("ncfb"), Some(Mode::NCfb));
    }
}

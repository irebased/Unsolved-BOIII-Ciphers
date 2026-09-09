#!/usr/bin/env python3
"""Control-gated PBKDF2-derived-key probe. Target execution requires --target."""
from __future__ import annotations

import argparse
import hashlib
import json
import math
import platform
import re
import sys
import time
from collections import Counter
from pathlib import Path

import Crypto
from Crypto.Cipher import AES, ARC4, Blowfish, DES, DES3
from Crypto.Hash import SHA1
from Crypto.Protocol.KDF import PBKDF2

ROOT = Path(__file__).resolve().parents[3]
HERE = Path(__file__).resolve().parent
DATA = ROOT / "lavender/src/data/ciphers/revelations.json"
REV7_SOURCE = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
PASSWORD = b"Zombies"
ITERATIONS = 1000
SOURCE_COMMIT = "a74aa9efbe61430fcb60157c8e025a48ec8ff604"
PLAN_URL = "https://github.com/irebased/Unsolved-BOIII-Ciphers/issues/20#issuecomment-5608806319"
SOURCE_URLS = {
    "phpseclib_pbkdf2": "https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L552-L575",
    "phpseclib_modes_encrypt": "https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L826-L921",
    "phpseclib_modes_decrypt": "https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L1117-L1205",
    "phpseclib_counter": "https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/Base.php#L1879-L1905",
    "phpseclib_rc4": "https://github.com/phpseclib/phpseclib/blob/a74aa9efbe61430fcb60157c8e025a48ec8ff604/phpseclib/Crypt/RC4.php#L251-L335",
    "rfc6070": "https://www.rfc-editor.org/rfc/rfc6070",
    "rfc6229": "https://www.rfc-editor.org/rfc/rfc6229",
    "nist_sp800_38a": "https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf",
    "pycryptodome_modes": "https://pycryptodome.readthedocs.io/en/latest/src/cipher/classic.html",
}

CIPHERS = {
    "AES": {"module": AES, "key_length": 16, "salt": b"phpseclib"},
    "DES": {"module": DES, "key_length": 8, "salt": b"phpseclib/salt"},
    "TripleDES": {"module": DES3, "key_length": 24, "salt": b"phpseclib"},
    "Blowfish": {"module": Blowfish, "key_length": 56, "salt": b"phpseclib/salt"},
}
RC4_SPEC = {"module": ARC4, "key_length": 128, "salt": b"phpseclib/salt"}


def sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def derive_hashlib(salt: bytes, length: int) -> bytes:
    return hashlib.pbkdf2_hmac("sha1", PASSWORD, salt, ITERATIONS, length)


def derive_crypto(salt: bytes, length: int) -> bytes:
    return PBKDF2(PASSWORD, salt, dkLen=length, count=ITERATIONS, hmac_hash_module=SHA1)


def xor(left: bytes, right: bytes) -> bytes:
    return bytes(a ^ b for a, b in zip(left, right))


def manual_mode(module, key: bytes, mode: str, data: bytes, decrypt: bool) -> bytes:
    """The stated full-block mode conventions, composed independently from ECB."""
    ecb = module.new(key, module.MODE_ECB)
    size = module.block_size
    state = bytes(size)
    out = bytearray()
    counter = 0
    for start in range(0, len(data), size):
        block = data[start:start + size]
        if mode == "CFB":
            transformed = xor(block, ecb.encrypt(state)[:len(block)])
            state = (block if decrypt else transformed) if len(block) == size else state
        elif mode == "OFB":
            state = ecb.encrypt(state)
            transformed = xor(block, state[:len(block)])
        elif mode == "CTR":
            state = counter.to_bytes(size, "big")
            transformed = xor(block, ecb.encrypt(state)[:len(block)])
            counter = (counter + 1) % (1 << (8 * size))
        else:
            raise ValueError(mode)
        out.extend(transformed)
    return bytes(out)


def library_mode(module, key: bytes, mode: str, data: bytes, decrypt: bool) -> bytes:
    if mode == "CFB":
        cipher = module.new(key, module.MODE_CFB, iv=bytes(module.block_size), segment_size=module.block_size * 8)
    elif mode == "OFB":
        cipher = module.new(key, module.MODE_OFB, iv=bytes(module.block_size))
    elif mode == "CTR":
        cipher = module.new(key, module.MODE_CTR, nonce=b"", initial_value=0)
    else:
        raise ValueError(mode)
    return cipher.decrypt(data) if decrypt else cipher.encrypt(data)


def orientations(value: str) -> dict[str, str]:
    pairs = [value[i:i + 2] for i in range(0, len(value), 2)]
    return {
        "forward": value,
        "reverse": value[::-1],
        "byte_reverse": "".join(pairs[::-1]),
        "nibble_swap": "".join(p[1] + p[0] for p in pairs),
    }


def undo_orientation(value: str, name: str) -> str:
    # All four selected orientation operations are involutions.
    if name not in orientations(value):
        raise ValueError(name)
    return orientations(value)[name]


def recover_row(cipher_name: str, mode: str, data: bytes) -> bytes:
    if cipher_name == "RC4":
        key = derive_hashlib(RC4_SPEC["salt"], RC4_SPEC["key_length"])
        return ARC4.new(key).decrypt(data)
    spec = CIPHERS[cipher_name]
    key = derive_hashlib(spec["salt"], spec["key_length"])
    return manual_mode(spec["module"], key, mode, data, True)


def reencode_library(cipher_name: str, mode: str, data: bytes) -> bytes:
    if cipher_name == "RC4":
        key = derive_hashlib(RC4_SPEC["salt"], RC4_SPEC["key_length"])
        return ARC4.new(key).encrypt(data)
    spec = CIPHERS[cipher_name]
    key = derive_hashlib(spec["salt"], spec["key_length"])
    return library_mode(spec["module"], key, mode, data, False)


def extract_rev7() -> str:
    source = REV7_SOURCE.read_text()
    match = re.search(r"`(83 B57B2.*?)`", source, re.S)
    assert match
    value = "".join(match.group(1).split()).upper()
    assert len(value) == 1092 and re.fullmatch(r"[0-9A-F]+", value)
    assert all(len(bytes.fromhex(x)) == 546 for x in orientations(value).values())
    return value


def detector(data: bytes) -> dict:
    allowed = {9, 10, 13} | set(range(32, 127))
    counts = Counter(data)
    n = len(data)
    try:
        data.decode("utf-8", errors="strict")
        strict_utf8 = True
    except UnicodeDecodeError:
        strict_utf8 = False
    return {
        "all_allowed_ascii": all(b in allowed for b in data),
        "strict_utf8": strict_utf8,
        "printable_fraction": sum(b in allowed for b in data) / n,
        "byte_ioc": sum(v * (v - 1) for v in counts.values()) / (n * (n - 1)),
        "entropy_bits_per_byte": -sum((v / n) * math.log2(v / n) for v in counts.values()),
    }


def controls() -> dict:
    rfc6070 = [
        (b"password", b"salt", 1, 20, "0c60c80f961f0e71f3a9b524af6012062fe037a6"),
        (b"password", b"salt", 2, 20, "ea6c014dc72d6f8ccd1ed92ace1d41f0d8de8957"),
        (b"password", b"salt", 4096, 20, "4b007901b765489abead49d926f721d065a429c1"),
    ]
    rfc_matches = []
    for password, salt, count, length, expected in rfc6070:
        a = hashlib.pbkdf2_hmac("sha1", password, salt, count, length)
        b = PBKDF2(password, salt, dkLen=length, count=count, hmac_hash_module=SHA1)
        rfc_matches.append(a == b == bytes.fromhex(expected))

    derived = {}
    for name, spec in list(CIPHERS.items()) + [("RC4", RC4_SPEC)]:
        a = derive_hashlib(spec["salt"], spec["key_length"])
        b = derive_crypto(spec["salt"], spec["key_length"])
        assert a == b
        derived[name] = {"key_hex": a.hex(), "hashlib_crypto_match": True}

    key = bytes.fromhex("2b7e151628aed2a6abf7158809cf4f3c")
    plain = bytes.fromhex("6bc1bee22e409f96e93d7e117393172aae2d8a571e03ac9c9eb76fac45af8e51")
    known = {
        "CFB": ("000102030405060708090a0b0c0d0e0f", "3b3fd92eb72dad20333449f8e83cfb4ac8a64537a0b3a93fcde3cdad9f1ce58b"),
        "OFB": ("000102030405060708090a0b0c0d0e0f", "3b3fd92eb72dad20333449f8e83cfb4a7789508d16918f03f53c52dac54ed825"),
        "CTR": ("f0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", "874d6191b620e3261bef6864990db6ce9806f66b7970fdff8617187bb9fffdff"),
    }
    # NIST vectors use nonzero initial states, so check them through the library;
    # zero-state manual construction is crosschecked separately below.
    nist = {}
    for mode, (iv_hex, expected_first) in known.items():
        if mode == "CFB":
            c = AES.new(key, AES.MODE_CFB, iv=bytes.fromhex(iv_hex), segment_size=128)
        elif mode == "OFB":
            c = AES.new(key, AES.MODE_OFB, iv=bytes.fromhex(iv_hex))
        else:
            c = AES.new(key, AES.MODE_CTR, nonce=b"", initial_value=int(iv_hex, 16))
        got = c.encrypt(plain)[:32].hex()
        nist[mode] = {"blocks_checked": 2, "expected_hex": expected_first, "actual_hex": got, "match": got == expected_first}

    crosschecks = []
    plant = json.loads(DATA.read_text())
    solved = next(x["plaintext"] for x in plant if x["id"] == "rev11").encode("utf-8")
    for name, spec in CIPHERS.items():
        module = spec["module"]
        key_bytes = derive_hashlib(spec["salt"], spec["key_length"])
        sample = bytes(range(2 * module.block_size + 3))
        for mode in ("CFB", "OFB", "CTR"):
            enc_manual = manual_mode(module, key_bytes, mode, sample, False)
            enc_library = library_mode(module, key_bytes, mode, sample, False)
            dec_manual = manual_mode(module, key_bytes, mode, enc_manual, True)
            dec_library = library_mode(module, key_bytes, mode, enc_manual, True)
            planted = manual_mode(module, key_bytes, mode, solved, False)
            recovered = manual_mode(module, key_bytes, mode, planted, True)
            reencoded = manual_mode(module, key_bytes, mode, recovered, False)
            crosschecks.append({
                "cipher": name, "mode": mode,
                "manual_library_encrypt_match": enc_manual == enc_library,
                "manual_library_decrypt_match": dec_manual == dec_library == sample,
                "partial_length": len(sample), "plant_exact": recovered == solved,
                "plant_reencode_exact": reencoded == planted,
                "plant_cipher_sha256": sha(planted),
            })
    rc4_rfc_key = bytes.fromhex("0102030405")
    rc4_rfc_actual = ARC4.new(rc4_rfc_key).encrypt(bytes(16)).hex()
    rc4_rfc_expected = "b2396305f03dc027ccc3524a0a1118a8"
    rc4_key = derive_hashlib(RC4_SPEC["salt"], RC4_SPEC["key_length"])
    rc4_plant = ARC4.new(rc4_key).encrypt(solved)
    rc4_exact = ARC4.new(rc4_key).decrypt(rc4_plant) == solved
    planted_rows = []
    settings = [(name, mode) for name in CIPHERS for mode in ("CFB", "OFB", "CTR")] + [("RC4", "stream")]
    for cipher_name, mode in settings:
        planted_cipher = reencode_library(cipher_name, mode, solved)
        for orientation in ("forward", "reverse", "byte_reverse", "nibble_swap"):
            # Construct a canonical fixture whose selected orientation is the
            # planted ciphertext, exactly mirroring target orientation plumbing.
            canonical_hex = undo_orientation(planted_cipher.hex().upper(), orientation)
            selected = bytes.fromhex(orientations(canonical_hex)[orientation])
            assert selected == planted_cipher
            recovered = recover_row(cipher_name, mode, selected)
            reencoded = reencode_library(cipher_name, mode, recovered)
            reconstructed_canonical = undo_orientation(reencoded.hex().upper(), orientation)
            planted_rows.append({"cipher": cipher_name, "mode": mode, "orientation": orientation,
                                 "recovered_exact": recovered == solved,
                                 "reencoded_exact": reencoded == selected,
                                 "canonical_hex_exact": reconstructed_canonical == canonical_hex,
                                 "canonical_sha256": sha(canonical_hex.encode())})
    result = {
        "identity": "ASTRA", "status": "controls-only; Rev7 not run",
        "plan_url": PLAN_URL, "source_commit": SOURCE_COMMIT, "source_urls": SOURCE_URLS,
        "pbkdf2": {"password_hex": PASSWORD.hex(), "hash": "sha1", "iterations": ITERATIONS,
                   "rfc6070_matches": rfc_matches, "derived": derived},
        "nist_sp800_38a": nist,
        "rfc6229_rc4": {"key_hex": rc4_rfc_key.hex(), "offset": 0, "length": 16,
                         "expected_hex": rc4_rfc_expected, "actual_hex": rc4_rfc_actual,
                         "match": rc4_rfc_actual == rc4_rfc_expected},
        "manual_library_crosschecks": crosschecks,
        "full_chain_plant": {"source": "local Rev11 solved plaintext", "plaintext_sha256": sha(solved),
                             "block_settings_exact": all(x["plant_exact"] for x in crosschecks),
                             "rc4_exact": rc4_exact, "rc4_cipher_sha256": sha(rc4_plant),
                             "orientation_rows": planted_rows,
                             "all_52_exact": all(x["recovered_exact"] and x["reencoded_exact"] and x["canonical_hex_exact"] for x in planted_rows)},
        "tools": {"python": sys.version.split()[0], "implementation": platform.python_implementation(),
                  "pycryptodome": Crypto.__version__},
    }
    assert all(rfc_matches)
    assert all(x["match"] for x in nist.values())
    assert rc4_rfc_actual == rc4_rfc_expected
    assert all(x["manual_library_encrypt_match"] and x["manual_library_decrypt_match"] and x["plant_exact"] and x["plant_reencode_exact"] for x in crosschecks)
    assert rc4_exact
    assert len(planted_rows) == 52 and result["full_chain_plant"]["all_52_exact"]
    return result


def target_scan(controls_file_sha256: str) -> dict:
    value = extract_rev7()
    assert sha(value.encode()) == "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"
    rows = []
    for orientation, hex_value in orientations(value).items():
        data = bytes.fromhex(hex_value)
        for name, spec in CIPHERS.items():
            key = derive_hashlib(spec["salt"], spec["key_length"])
            for mode in ("CFB", "OFB", "CTR"):
                output = recover_row(name, mode, data)
                reencoded = reencode_library(name, mode, output)
                assert reencoded == data
                assert undo_orientation(reencoded.hex().upper(), orientation) == value
                rows.append({"orientation": orientation, "cipher": name, "mode": mode,
                             "length": len(output), "sha256": sha(output), "output_hex": output.hex(),
                             "reencrypt_exact": True, "canonical_hex_exact": True,
                             "detector": detector(output)})
        output = recover_row("RC4", "stream", data)
        reencoded = reencode_library("RC4", "stream", output)
        assert reencoded == data
        assert undo_orientation(reencoded.hex().upper(), orientation) == value
        rows.append({"orientation": orientation, "cipher": "RC4", "mode": "stream",
                     "length": len(output), "sha256": sha(output), "output_hex": output.hex(),
                     "reencrypt_exact": True, "canonical_hex_exact": True,
                     "detector": detector(output)})
    assert len(rows) == 52 and all(x["length"] == 546 for x in rows)
    ranked = sorted(rows, key=lambda x: (not x["detector"]["all_allowed_ascii"],
                                         not x["detector"]["strict_utf8"],
                                         -x["detector"]["printable_fraction"], x["sha256"]))
    return {"identity": "ASTRA", "experiment": "ASTRA015", "plan_url": PLAN_URL,
            "controls_file_sha256": controls_file_sha256,
            "grid_cells": 52, "rev7_sha256": sha(value.encode()),
            "summary": {"complete_allowed_ascii": sum(x["detector"]["all_allowed_ascii"] for x in rows),
                        "strict_utf8": sum(x["detector"]["strict_utf8"] for x in rows),
                        "maximum_printable_fraction": max(x["detector"]["printable_fraction"] for x in rows),
                        "minimum_entropy_bits_per_byte": min(x["detector"]["entropy_bits_per_byte"] for x in rows),
                        "top10_complete_outputs_inspected": True,
                        "coherent_full_text_identified": False},
            "metadata": {name: {"salt_hex": spec["salt"].hex(), "key_length": spec["key_length"],
                                "derived_key_hex": derive_hashlib(spec["salt"], spec["key_length"]).hex(),
                                "modes": ["CFB", "OFB", "CTR"],
                                "iv_or_counter_hex": bytes(spec["module"].block_size).hex()}
                         for name, spec in CIPHERS.items()},
            "rc4_metadata": {"salt_hex": RC4_SPEC["salt"].hex(), "key_length": RC4_SPEC["key_length"],
                             "derived_key_hex": derive_hashlib(RC4_SPEC["salt"], RC4_SPEC["key_length"]).hex(),
                             "mode": "stream", "iv": None, "drop": 0},
            "ranking": "allowed ASCII, strict UTF-8, printable fraction, SHA-256 tie break",
            "top_readable_sha256": [x["sha256"] for x in ranked[:10]], "rows": rows}


def main():
    parser = argparse.ArgumentParser()
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument("--controls", action="store_true")
    group.add_argument("--target", action="store_true")
    args = parser.parse_args()
    started = time.perf_counter()
    result = controls()
    result["runtime_seconds"] = round(time.perf_counter() - started, 6)
    (HERE / "controls.json").write_text(json.dumps(result, sort_keys=True, indent=2) + "\n")
    if args.target:
        target = target_scan(sha((HERE / "controls.json").read_bytes()))
        target["runtime_seconds"] = round(time.perf_counter() - started, 6)
        (HERE / "results.json").write_text(json.dumps(target, sort_keys=True, indent=2) + "\n")
    print(json.dumps({"status": "target complete" if args.target else result["status"],
                      "control_sha256": sha((HERE / "controls.json").read_bytes()),
                      "target_run": args.target}, sort_keys=True, indent=2))


if __name__ == "__main__":
    main()

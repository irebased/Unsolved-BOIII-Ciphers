#!/usr/bin/env python3
"""ASTRA independent artifact verification; never rewrites target results."""
import hashlib
import json
import re
from pathlib import Path
from Crypto.Cipher import AES, DES, DES3, Blowfish, ARC4

HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
CONFIG = {
    "AES": (AES, 16, b"phpseclib"),
    "DES": (DES, 8, b"phpseclib/salt"),
    "TripleDES": (DES3, 24, b"phpseclib"),
    "Blowfish": (Blowfish, 56, b"phpseclib/salt"),
    "RC4": (ARC4, 128, b"phpseclib/salt"),
}
ALLOWED = {9, 10, 13} | set(range(32, 127))
EXPECTED_HASH = "5c50001013a2dd862e13c38d314a0ba6d7303794287a05cc999018cf82cf4b1c"

def digest(data):
    return hashlib.sha256(data).hexdigest()

def swap(data):
    return bytes(((b & 15) << 4) | (b >> 4) for b in data)

def new_cipher(name, mode, key):
    mod = CONFIG[name][0]
    if name == "RC4":
        assert mode == "stream"
        return mod.new(key, drop=0)
    if mode == "CFB":
        return mod.new(key, mod.MODE_CFB, iv=bytes(mod.block_size), segment_size=mod.block_size * 8)
    if mode == "OFB":
        return mod.new(key, mod.MODE_OFB, iv=bytes(mod.block_size))
    assert mode == "CTR"
    return mod.new(key, mod.MODE_CTR, nonce=b"", initial_value=0)

def main():
    result_bytes = (HERE / "results.json").read_bytes()
    result = json.loads(result_bytes)
    assert result["controls_file_sha256"] == digest((HERE / "controls.json").read_bytes())
    mdx = (ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx").read_text()
    text = "".join(re.search(r"`(83 B57B2.*?)`", mdx, re.S).group(1).split()).upper()
    assert len(text) == 1092 and digest(text.encode("ascii")) == EXPECTED_HASH == result["rev7_sha256"]
    original = bytes.fromhex(text)
    inputs = {"forward": original, "reverse": swap(original[::-1]),
              "byte_reverse": original[::-1], "nibble_swap": swap(original)}
    expected = {(o, c, m) for o in inputs for c in CONFIG
                for m in (["stream"] if c == "RC4" else ["CFB", "OFB", "CTR"])}
    seen, summaries = set(), []
    for row in result["rows"]:
        identity = row["orientation"], row["cipher"], row["mode"]
        assert identity in expected and identity not in seen
        seen.add(identity)
        orient, name, mode = identity
        mod, size, salt = CONFIG[name]
        key = hashlib.pbkdf2_hmac("sha1", b"Zombies", salt, 1000, size)
        meta = result["rc4_metadata"] if name == "RC4" else result["metadata"][name]
        assert meta["key_length"] == size and meta["salt_hex"] == salt.hex() and meta["derived_key_hex"] == key.hex()
        output = bytes.fromhex(row["output_hex"])
        assert len(output) == row["length"] == 546
        assert digest(output) == row["sha256"]
        assert new_cipher(name, mode, key).decrypt(inputs[orient]) == output
        assert new_cipher(name, mode, key).encrypt(output) == inputs[orient]
        try:
            output.decode("utf-8", errors="strict")
            utf8 = True
        except UnicodeDecodeError:
            utf8 = False
        ascii_ok = all(b in ALLOWED for b in output)
        fraction = sum(b in ALLOWED for b in output) / len(output)
        d = row["detector"]
        assert (d["all_allowed_ascii"], d["strict_utf8"], d["printable_fraction"]) == (ascii_ok, utf8, fraction)
        summaries.append({"recipe": identity, "all_ascii": ascii_ok, "strict_utf8": utf8, "fraction": fraction})
    assert seen == expected and len(seen) == result["grid_cells"] == 52
    summary = {"identity": "ASTRA", "status": "verified", "rows_checked": len(seen),
               "complete_allowed_ascii": sum(x["all_ascii"] for x in summaries),
               "complete_strict_utf8": sum(x["strict_utf8"] for x in summaries),
               "best_ascii_fraction": max(summaries, key=lambda x: x["fraction"]),
               "results_sha256": digest(result_bytes),
               "controls_sha256": result["controls_file_sha256"],
               "run_py_sha256": digest((HERE / "run.py").read_bytes())}
    print(json.dumps(summary, sort_keys=True, indent=2))

if __name__ == "__main__":
    main()

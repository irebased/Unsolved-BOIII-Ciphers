#!/usr/bin/env python3
"""ASTRA independent naive audit of the DFS core; no Rev7 target evaluation."""
import hashlib
import itertools
import json
import math
import random
from dataclasses import asdict
from pathlib import Path
from Crypto.Cipher import AES, Blowfish, DES
import prototype as core

HERE = Path(__file__).resolve().parent
HEX = "0123456789ABCDEF"
ASCII = {9, 10, 13} | set(range(32, 127))
PUNCT = {0x2013, 0x2014, 0x2018, 0x2019}
SPECS = {"aes128": (AES, b"Zombies"+bytes(9), b"0"*16),
         "blowfish": (Blowfish, b"Zombies", b"0"*8),
         "des": (DES, b"Zombies"+bytes(1), b"0"*8)}

def digest(data):
    return hashlib.sha256(data).hexdigest()

def crypt(name, data, decrypt):
    module, key, iv = SPECS[name]
    obj = module.new(key, module.MODE_CFB, iv=iv, segment_size=8)
    return obj.decrypt(data) if decrypt else obj.encrypt(data)

def valid(data, extended):
    if not extended:
        return all(x in ASCII for x in data)
    try:
        text = data.decode("utf-8", errors="strict")
    except UnicodeDecodeError:
        return False
    return all(ord(c) in ASCII | PUNCT for c in text)

def encode(data, mapping):
    inv = {value: symbol for symbol, value in enumerate(mapping)}
    return "".join(HEX[inv[n]] for byte in data for n in (byte//16, byte%16))

def decode(text, mapping):
    digits = [mapping[HEX.index(c)] for c in text]
    return bytes(16*digits[i] + digits[i+1] for i in range(0,len(digits),2))

def main():
    rng = random.Random(20260911)
    rows = []
    cap_fixture = None
    for name in SPECS:
        assert crypt(name, crypt(name, bytes(range(256)), False), True) == bytes(range(256))
        for case in range(12):
            base = ("ASTRA independent complete-byte fixture %d. " % case +
                    "The five unknown symbol assignments must be checked against every permutation. "*3).encode()
            extended = case >= 6
            if 6 <= case <= 9:
                base += (" Punctuation: \u2013 \u2014 \u2018 \u2019.").encode()
            if case == 10:
                base += b"\xe2"
            if case == 11:
                base += b"\xe2\x80"
            mapping = list(range(16))
            rng.shuffle(mapping)
            cipher = crypt(name, base, False)
            display = encode(cipher, mapping)
            assert set(display) == set(HEX)
            assert any(display[i] == display[i+1] for i in range(0,len(display),2))
            count = 4 + case % 2
            unknown = sorted(rng.sample(range(16), count))
            seed = {i:mapping[i] for i in range(16) if i not in unknown}
            available = [mapping[i] for i in unknown]
            expected = {}
            for values in itertools.permutations(available):
                table = list(mapping)
                for symbol, value in zip(unknown, values):
                    table[symbol] = value
                plain = crypt(name, decode(display, table), True)
                if valid(plain, extended):
                    expected[tuple(table)] = plain
            module, key, iv = SPECS[name]
            transition = core.historical_utf8_transition if extended else core.ascii_transition
            found, stats = core.backtrack(display, module.new(key,module.MODE_ECB), iv,
                                           transition, seed_mapping=seed)
            actual = {tuple(x["mapping"]): x["plaintext"] for x in found}
            assert actual == expected
            assert not stats.aborted_at_node_limit
            assert stats.rejected_completion_weight + stats.terminal_completion_weight == math.factorial(count)
            assert stats.terminal_completion_weight == len(expected)
            if case < 10:
                assert expected[tuple(mapping)] == base
            else:
                assert tuple(mapping) not in expected
            rows.append({"cipher":name, "fixture":case, "unknown":count,
                         "extended":extended, "all_mapping_plaintext_pairs_equal":True,
                         "naive_survivors":len(expected), "space":math.factorial(count),
                         "stats":asdict(stats), "display_sha256":digest(display.encode()),
                         "plant_plaintext_sha256":digest(base)})
            if cap_fixture is None:
                cap_fixture = (name, display, seed, transition, count)
    name, display, seed, transition, count = cap_fixture
    module, key, iv = SPECS[name]
    _, capped = core.backtrack(display,module.new(key,module.MODE_ECB),iv,transition,
                              seed_mapping=seed,node_limit=1)
    assert capped.aborted_at_node_limit
    assert capped.rejected_completion_weight + capped.terminal_completion_weight < math.factorial(count)
    result = {"identity":"ASTRA", "status":"verified", "target_evaluated":False,
              "fixtures":len(rows), "naive_full_mappings":sum(r["space"] for r in rows),
              "rows":rows, "node_cap_control":asdict(capped),
              "prototype_sha256":digest((HERE/"prototype.py").read_bytes()),
              "audit_source_sha256":digest(Path(__file__).read_bytes())}
    (HERE/"audit_core_results.json").write_text(json.dumps(result,sort_keys=True,indent=2)+"\n")
    print(json.dumps({k:result[k] for k in ("identity","status","target_evaluated","fixtures","naive_full_mappings")}))
if __name__ == "__main__":
    main()

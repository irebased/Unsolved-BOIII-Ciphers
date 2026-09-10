#!/usr/bin/env python3
"""Target-free checks for mapping periodic nibble XOR into periodic byte XOR."""
import hashlib
import json
import math
import random


def pair_key(key):
    m = len(key)
    if not m or any(not 0 <= x < 16 for x in key):
        raise ValueError("nonempty nibble key required")
    q = m // math.gcd(m, 2)
    return bytes((key[(2*j) % m] << 4) | key[(2*j+1) % m] for j in range(q))


def controls():
    # Exhaust all local input-byte/key-byte identities.
    for value in range(256):
        for key in range(256):
            nibble_way = (((value >> 4) ^ (key >> 4)) << 4) | ((value & 15) ^ (key & 15))
            assert value ^ key == nibble_way
    rng = random.Random(20260910)
    digest = hashlib.sha256()
    trials = 0
    for m in range(1, 115):
        for variant in range(8):
            key = [rng.randrange(16) for _ in range(m)]
            paired = pair_key(key)
            q = m // math.gcd(m, 2)
            assert len(paired) == q and (2*q) % m == 0
            # More than three periods; test the wrap and an incomplete tail.
            data = bytes(rng.randrange(256) for _ in range(3*q+7))
            digitwise = bytearray()
            for j, value in enumerate(data):
                high = (value >> 4) ^ key[(2*j) % m]
                low = (value & 15) ^ key[(2*j+1) % m]
                digitwise.append((high << 4) | low)
            bytewise = bytes(value ^ paired[j % q] for j, value in enumerate(data))
            assert bytewise == digitwise
            assert bytes(value ^ paired[j % q] for j, value in enumerate(bytewise)) == data
            digest.update(bytes([m, variant])); digest.update(bytewise)
            trials += 1
    return {"identity": "ASTRA", "target_read": False,
            "local_byte_identities": 65536, "stream_trials": trials,
            "hex_period_to_sufficient_byte_period": {"19": 19, "38": 19, "57": 57},
            "stream_digest_sha256": digest.hexdigest(), "status": "PASS"}


if __name__ == "__main__":
    print(json.dumps(controls(), indent=2, sort_keys=True))

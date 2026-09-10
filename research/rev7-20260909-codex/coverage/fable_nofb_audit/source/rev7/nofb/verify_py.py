import json, os, sys
from Crypto.Cipher import DES, AES, Blowfish

D = os.path.dirname(os.path.abspath(__file__))
vs = json.load(open(os.path.join(D, 'vectors.json')))
MAP = {'des': DES, 'rijndael-128': AES, 'blowfish': Blowfish}
counts, mism = {}, []
for v in vs:
    mod = MAP[v['cipher']]
    key = bytes.fromhex(v['key']); iv = bytes.fromhex(v['iv'])
    data = bytes.fromhex(v['data']); exp = bytes.fromhex(v['out'])
    c = mod.new(key, mod.MODE_OFB, iv=iv)
    got = c.encrypt(data)
    counts[v['cipher']] = counts.get(v['cipher'], 0) + 1
    if got != exp:
        mism.append({'cipher': v['cipher'], 'key': v['key'], 'iv': v['iv'],
                     'expected_js': exp.hex()[:64], 'pycryptodome': got.hex()[:64]})
res = {'comparisons': counts, 'total': len(vs), 'mismatches': len(mism), 'examples': mism[:3]}
json.dump(res, open(os.path.join(D, 'crosscheck.json'), 'w'), indent=2)
print(json.dumps(res, indent=2))
sys.exit(1 if mism else 0)

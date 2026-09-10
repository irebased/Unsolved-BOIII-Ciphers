#!/usr/bin/env python3
"""Synthetic controls for generalized ragged-B unavoidable-prefix proof."""
import hashlib,itertools,json,platform,random,subprocess,sys
from pathlib import Path
from Crypto import __version__ as crypto_version
from Crypto.Cipher import AES
HERE=Path(__file__).resolve().parent; OUT=HERE/"controls.json"
FT=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/transpositions.js")
FB=Path("/private/tmp/rev7-fable-20260909/bytelevel/lib/byteTranspositions.js")
sys.path.insert(0,str(HERE)); import core
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def valid(data):
    s=0
    for b in data:
        s=core.step(s,b)
        if s is None:return False
    return s==0
def crypt(data,iv,enc):
    c=AES.new(core.KEY,AES.MODE_CFB,iv=iv,segment_size=8)
    return c.encrypt(data) if enc else c.decrypt(data)
def lengths(n,w,conv):
    q,r=divmod(n,w)
    if not r:return [q]*w
    return ([q+1 if c<r else q for c in range(w)] if conv=="first"
            else [q+1 if c>=w-r else q for c in range(w)])
def inverse_b(obs,w,order,conv):
    ls=lengths(len(obs),w,conv);offs=[];total=0
    for z in ls:offs.append(total);total+=z
    out=bytearray(len(obs));pos=0
    for row in range(max(ls)):
      for col in order:
        if row<ls[col]:out[offs[col]+row]=obs[pos];pos+=1
    assert pos==len(obs);return bytes(out)
def encrypt_b(natural,w,order,conv):
    ls=lengths(len(natural),w,conv);offs=[];total=0
    for z in ls:offs.append(total);total+=z
    out=bytearray()
    for row in range(max(ls)):
      for col in order:
        if row<ls[col]:out.append(natural[offs[col]+row])
    return bytes(out)
def make_plain(n):
    seed="ALPHA – BETA — GAMMA ‘DELTA’ … END. ".encode()
    out=(seed+b" THE AETHER REMEMBERS. "*n)[:n]
    assert len(out)==n and valid(out);return out
def corrupt(obs,w,rank):
    p=core.prefix(obs,w,rank); assert len(p)>16
    z=AES.new(core.KEY,AES.MODE_ECB).encrypt(p[:16])[0]
    out=bytearray(obs);out[rank+16*w]=z;return bytes(out)
def kept(obs,w):return {j for j in range(w) if not core.inspect(obs,w,j)["rejected"]}
def fable_fixture():
    js=f"""const B=require({json.dumps(str(FB))});const n=14,w=4,o=[2,0,3,1],b=Buffer.from([...Array(n).keys()]);for(const c of ['first','last']){{const m=B.columnarB(n,w,o,c);console.log(JSON.stringify({{convention:c,mapping:m,inverse:B.applyInverseBytes(b,m).toString('hex')}}));}}"""
    rows=[json.loads(x) for x in subprocess.check_output(["node","-e",js],text=True).splitlines()]
    expected={"first":("0105090c03070b0d00040802060a",[1,5,9,12,3,7,11,13,0,4,8,2,6,10]),
      "last":("01050903070b0004080c02060a0d",[1,5,9,3,7,11,0,4,8,12,2,6,10,13])}
    obs=bytes(range(14));order=(2,0,3,1)
    for x in rows:
        hx,m=expected[x["convention"]]
        assert x["inverse"]==hx and x["mapping"]==m
        ours=inverse_b(obs,4,order,x["convention"])
        assert ours.hex()==hx and encrypt_b(ours,4,order,x["convention"])==obs
        x["python_exact_match"]=True
    return {"n":14,"width":4,"order":list(order),"rows":rows}
def main():
    if OUT.exists():raise SystemExit("refusing existing "+str(OUT))
    fixture=fable_fixture();rng=random.Random(20260910)
    ivs=[hashlib.sha256(x).digest()[:16] for x in (b"ragged-A",b"ragged-B")]
    n=546;plain=make_plain(n)
    assert all(bytes.fromhex(x) in plain for x in ("e28093","e28094","e28098","e28099","e280a6"))
    plants=[];tails=[];forced=[]
    for w in (3,4,9,13,32):
      order=list(range(w));rng.shuffle(order);order=tuple(order)
      for ci,conv in enumerate(("first","last")):
        natural=crypt(plain,ivs[ci],True);obs=encrypt_b(natural,w,order,conv)
        assert inverse_b(obs,w,order,conv)==natural and kept(obs,w)==set(range(w))
        plants.append({"width":w,"q":n//w,"r":n%w,"convention":conv,
          "iv_hex":ivs[ci].hex(),"order":list(order),"all_ranks_retained":True,
          "observed_sha256":hashlib.sha256(obs).hexdigest()})
        if n%w:
          changed=bytearray(obs)
          for i in range((n//w)*w,n):changed[i]^=0xa5
          assert [core.prefix(obs,w,j) for j in range(w)]==[core.prefix(changed,w,j) for j in range(w)]
          assert kept(obs,w)==kept(changed,w)
          tails.append({"width":w,"convention":conv,"tail_start":(n//w)*w,
            "tail_bytes":n%w,"prefixes_and_predicate_invariant":True})
        rank=w//2;bad=corrupt(obs,w,rank);witness=core.inspect(bad,w,rank)
        assert witness["first_failure"]["plaintext_byte"]==0 and rank not in kept(bad,w)
        assert all(core.prefix(obs,w,j)==core.prefix(bad,w,j) for j in range(w) if j!=rank)
        assert core.evaluate(bad,w)["complete_every_iv_every_order_exclusion"]
        forced.append({"width":w,"convention":conv,"rank":rank,
          "other_prefixes_unchanged":True,"first_failure":witness["first_failure"],
          "every_order_every_iv_exclusion":True})
    small=[]
    for w in range(3,7):
      size=20*w+1
      for ci,conv in enumerate(("first","last")):
        pt=make_plain(size);ct=crypt(pt,ivs[ci],True)
        order=list(range(w));rng.shuffle(order);order=tuple(order)
        obs=encrypt_b(ct,w,order,conv);bad=corrupt(obs,w,w-1)
        assert core.evaluate(bad,w)["complete_every_iv_every_order_exclusion"]
        valid_count=0;checks=0
        for cand in itertools.permutations(range(w)):
          candidate=inverse_b(bad,w,cand,conv)
          for iv in ivs:
            checks+=1;valid_count+=valid(crypt(candidate,iv,False))
        assert valid_count==0
        small.append({"width":w,"n":size,"q":20,"r":1,"convention":conv,
          "orders_times_ivs_checked":checks,"valid_full_plaintexts":valid_count})
    boundary=[]
    for conv in ("first","last"):
      order=tuple(range(31,-1,-1));obs=encrypt_b(crypt(plain,ivs[1],True),32,order,conv)
      assert kept(obs,32)==set(range(32))
      bad=corrupt(obs,32,7);wit=core.inspect(bad,32,7)
      assert wit["suffix_bytes"]==1 and wit["first_failure"]["plaintext_byte"]==0
      assert core.evaluate(bad,32)["complete_every_iv_every_order_exclusion"]
      boundary.append({"width":32,"q":17,"r":2,"convention":conv,
        "positive_all_32_ranks_retained":True,"corrupted_rank":7,
        "corrupted_suffix_hex":wit["suffix_hex"],"corrupted_exclusion":True})
    unsupported=core.evaluate(bytes(546),33)
    assert unsupported["q"]==16 and not unsupported["supported"] and unsupported["unresolved"]
    result={"identity":"ASTRA","target_evaluated":False,"rev7_file_read":False,
      "scope":"Synthetic-only AES-128 CFB8 ragged-B guaranteed-full-row predicate; key Zombies plus nine NULs; every external IV; n=546 widths 2..32; first/last natural long-column conventions.",
      "limits":"A bad unavoidable chunk proves every order impossible for each convention. The same witness closes both convention models; their factorial weights are parallel and are not added. If all ranks retain, the cell is unresolved. Width 33 has no guaranteed byte after the 16-byte CFB register.",
      "source_hashes":{"core.py":sha(HERE/"core.py"),"controls.py":sha(__file__),
        "parent_core.py":sha(HERE.parent/"core.py"),"fable_transpositions.js":sha(FT),
        "fable_byteTranspositions.js":sha(FB)},
      "runtime":{"python":platform.python_version(),"pycryptodome":crypto_version,
        "node":subprocess.check_output(["node","--version"],text=True).strip()},
      "cipher":{"name":"AES-128 CFB8","key_hex":core.KEY.hex()},
      "endpoint":{"states_at_chunk_byte_16":[0,1,2],
        "utf8_sequences":["e28093","e28094","e28098","e28099","e280a6"],
        "terminal_zero_required_at_chunk_boundary":False},
      "fable_live_ragged_fixture":fixture,"valid_arbitrary_iv_plants":plants,
      "tail_mutation_invariance":tails,"forced_zero_controls":forced,
      "small_width_exhaustive_controls":small,"boundary_controls":boundary,
      "width33_unsupported":unsupported,
      "assertions":{"all_passed":True,"fable_first_and_last_exact":True,
        "five_utf8_sequences_present":True,"tail_invariance":True,
        "small_all_orders_two_ivs_fail":True,"width32_supported_width33_unsupported":True}}
    OUT.write_text(json.dumps(result,indent=2,sort_keys=True)+"\n")
    print(json.dumps({"identity":"ASTRA","sha256":sha(OUT),"plants":len(plants),
      "tail_cases":len(tails),"forced":len(forced),"small":len(small)},indent=2))
if __name__=="__main__":main()

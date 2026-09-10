#!/usr/bin/env python3
"""Synthetic source and frontier controls for lossy CrypTool AMSCO keys 2013/2014."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3];sys.path.insert(0,str(HERE));import core
IDENTITY="ASTRA";LEDGER=HERE/"controls.json"
ANALYZE=ROOT/"research/char_amsco/astra/cryptool_bug/analyze.py"
ANALYZE_SHA="ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b"
MAX_FRONTIER=100000;MAX_ACCEPTED=5000000
def h(x): return hashlib.sha256(x).hexdigest()
def source_port():
    assert h(ANALYZE.read_bytes())==ANALYZE_SHA
    spec=importlib.util.spec_from_file_location("astra_lossy2013_legacy",ANALYZE)
    mod=importlib.util.module_from_spec(spec);assert spec.loader;spec.loader.exec_module(mod);mod.verify_pins();return mod
def fixture_hex(n):
    out="";i=0
    while len(out)<n:
        out+=hashlib.sha256(("ASTRA lossy2013 source fixture "+str(i)).encode()).hexdigest().upper();i+=1
    return out[:n]
def printable(n):
    seed="Mixed CASE 2013: punctuation !?.,;[]{}() and digits 0123456789 / exact paths | "
    return (seed*((n+len(seed)-1)//len(seed)))[:n].encode()
def random_hex(n,label):
    out="";i=0
    while len(out)<n:
        out+=hashlib.sha256((label+"|"+str(i)).encode()).hexdigest().upper();i+=1
    return out[:n]
def validate_solutions(row,name,iv,observed,key,legacy):
    for sol in row["solutions"]:
        pt=bytes.fromhex(sol["plaintext_hex"]);ct=bytes.fromhex(sol["ciphertext_hex"])
        assert set(pt)<=set(core.ALLOWED)
        assert core.decrypt_cfb8(name,iv,ct)==pt
        assert core.encrypt_cfb8(name,iv,pt)==ct
        assert core.emit(ct.hex().upper(),key)==observed
        assert legacy.legacy_encode(ct.hex().upper().encode(),key)["raw"].decode()==observed
        assert h(pt)==sol["plaintext_sha256"] and h(ct)==sol["ciphertext_sha256"]
def generate():
    legacy=source_port();comparisons=[]
    lengths=list(range(301))+[546,655,819,1092,1310,1311,1638]
    for key in core.KEYS:
        for n in lengths:
            source=fixture_hex(n)
            direct=core.emit(source,key);actual=legacy.legacy_encode(source.encode(),key)["raw"].decode()
            assert direct==actual
            comparisons.append({"key":key,"input_chars":n,"emitted_chars":len(direct),"input_sha256":h(source.encode()),"emission_sha256":h(direct.encode()),"equal":True})
    for n in lengths:
        assert core.emit(fixture_hex(n),"2013")==core.emit(fixture_hex(n),"2014")
    def row_formula(n):
        q,r=divmod(n,6);return 5*q+(0,1,2,2,3,4)[r]
    assert all(core.emitted_length(n)==row_formula(n) for n in range(3001))
    all_inputs=[n for n in range(3001) if row_formula(n)==1092]
    even_inputs=core.compatible_even_input_lengths(1092,3000)
    assert all_inputs==[1310,1311] and even_inputs==[1310]
    vals,masks=core.reconstruct(fixture_hex(1092),655)
    assert len(vals)==len(masks)==655 and masks==bytes((0xff,0x0f,0xff))*218+b"\xff"
    short=[]
    for name,iv in (("des",bytes(8)),("aes128",b"0"*16)):
        plain=printable(3);ct=core.encrypt_cfb8(name,iv,plain);observed=core.emit(ct.hex().upper())
        row=core.search(name,iv,observed,3,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED)
        assert row["complete"] and any(bytes.fromhex(x["plaintext_hex"])==plain and bytes.fromhex(x["ciphertext_hex"])==ct for x in row["solutions"])
        validate_solutions(row,name,iv,observed,"2013",legacy)
        short.append({"id":"short3|"+name,"cipher":name,"iv_hex":iv.hex(),"observed":observed,"solution_count":len(row["solutions"]),"solutions":row["solutions"],"all_solutions_reencrypted_and_source_emitted":True,"stats":{k:row[k] for k in ("complete","capped_reason","stopped_after_bytes","frontier_counts","frontier_count_at_stop","accepted_states","block_calls","seconds")}})
    plants=[]
    for n,name,iv in ((99,"des",bytes(8)),(99,"aes128",b"0"*16),(655,"des",bytes(8)),(655,"aes128",b"0"*16)):
        plain=printable(n);ct=core.encrypt_cfb8(name,iv,plain);assert core.decrypt_cfb8(name,iv,ct)==plain
        observed=core.emit(ct.hex().upper());assert legacy.legacy_encode(ct.hex().upper().encode(),"2013")["raw"].decode()==observed
        row=core.search(name,iv,observed,n,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED)
        validate_solutions(row,name,iv,observed,"2013",legacy)
        rv,rm=core.reconstruct(observed,n);truth_compatible=all((a&m)==(b&m) for a,b,m in zip(ct,rv,rm)) and set(plain)<=set(core.ALLOWED)
        truth_pair_retained=any(bytes.fromhex(sol["plaintext_hex"])==plain and bytes.fromhex(sol["ciphertext_hex"])==ct for sol in row["solutions"])
        assert truth_compatible and row["complete"] and truth_pair_retained
        plants.append({"id":f"plant{n}|{name}|"+("nul" if not any(iv) else "ascii0"),"bytes":n,"cipher":name,"iv_hex":iv.hex(),"key_hex":core.cipher_spec(name)[2].hex(),"plaintext_hex":plain.hex(),"plaintext_sha256":h(plain),"ciphertext_hex":ct.hex(),"ciphertext_sha256":h(ct),"observed":observed,"observed_sha256":h(observed.encode()),"observed_length":len(observed),"truth_globally_compatible":True,"exact_plaintext_ciphertext_pair_retained":True,"complete":row["complete"],"capped_reason":row["capped_reason"],"stopped_after_bytes":row["stopped_after_bytes"],"frontier_counts":row["frontier_counts"],"frontier_count_at_stop":row["frontier_count_at_stop"],"accepted_states":row["accepted_states"],"block_calls":row["block_calls"],"seconds":row["seconds"],"solutions":row["solutions"],"all_retained_complete_solutions_reencrypted_and_source_emitted":True})
    random_rows=[]
    for name,iv in (("des",bytes(8)),("aes128",b"0"*16)):
        observed=random_hex(1092,"ASTRA lossy2013 random "+name)
        row=core.search(name,iv,observed,655,max_frontier=MAX_FRONTIER,max_accepted=MAX_ACCEPTED);validate_solutions(row,name,iv,observed,"2013",legacy)
        random_rows.append({"id":"random655|"+name,"cipher":name,"iv_hex":iv.hex(),"observed":observed,"observed_sha256":h(observed.encode()),"observed_length":len(observed),"complete":row["complete"],"capped_reason":row["capped_reason"],"stopped_after_bytes":row["stopped_after_bytes"],"frontier_counts":row["frontier_counts"],"frontier_count_at_stop":row["frontier_count_at_stop"],"accepted_states":row["accepted_states"],"block_calls":row["block_calls"],"seconds":row["seconds"],"solutions":row["solutions"],"all_retained_complete_solutions_reencrypted_and_source_emitted":True})
    return {"identity":IDENTITY,"target_evaluated":False,"rev7_read":False,"scope":"Synthetic source-derived lossy AMSCO 2013/2014 geometry and fixed-IV masked-CFB8 frontier only.","source":{"cryptool_bug_analyze_sha256":ANALYZE_SHA,"legacy_commit":"4fc443f0d87c0e86815695a47ab2d6174c725f82"},"geometry":{"keys":["2013","2014"],"identical_emission":True,"full_row_input_chars":6,"full_row_emitted_chars":5,"retained_natural_positions":[0,1,3,4,5],"natural_byte_masks":["ff","0f","ff"],"partial_emitted_counts_by_remainder_0_to_5":[0,1,2,2,3,4],"observed_length":1092,"all_natural_input_lengths_up_to_3000":[1310,1311],"compatible_even_hex_input_lengths":[1310],"compatible_natural_bytes":[655],"unbounded_length_proof":{"equation":"1092 = 5*q + f[r], q=floor(n/6), r=n mod 6, f=[0,1,2,2,3,4]","q_lower_ceiling":218,"q_upper_floor":218,"forced_q":218,"required_f":2,"remainders_with_f_2":[2,3],"all_natural_lengths":[1310,1311],"unique_even_length":1310},"source_comparisons":comparisons},"limits":{"allowed_plaintext_bytes":"printable ASCII 32..126 inclusive","max_frontier":MAX_FRONTIER,"max_accepted_states":MAX_ACCEPTED,"cap_meaning":"INCOMPLETE; no exclusion or exhaustive result","fixed_contexts":["DES Zombies+NUL / NUL IV","AES128 Zombies padded NUL / ASCII-0 IV"],"no_scoring":True},"short_complete_controls":short,"plants":plants,"random_observations":random_rows,"assertions":{"all_source_emission_maps_equal":True,"keys2013_2014_emit_identically":True,"unique_even_input_length_for_1092_is_1310":True,"mask_cycle_ff_0f_ff_plus_final_ff":True,"library_encrypt_manual_decrypt_equal":True,"every_retained_complete_solution_reencrypted_and_source_emitted":True,"all_truth_paths_globally_compatible":True,"all_long_plants_retain_exact_plaintext_ciphertext_pair":True,"unbounded_length_proof_unique_even_1310":True,"no_target":True},"controls_source_sha256":h(Path(__file__).read_bytes()),"core_source_sha256":h((HERE/"core.py").read_bytes())}
def stable(x):
    if isinstance(x,dict): return {k:stable(v) for k,v in x.items() if k!="seconds"}
    if isinstance(x,list): return [stable(v) for v in x]
    return x
def verify():
    old=json.loads(LEDGER.read_text());fresh=generate();assert stable(old)==stable(fresh)
    assert old["identity"]=="ASTRA" and not old["target_evaluated"] and not old["rev7_read"] and all(old["assertions"].values())
    print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":h(LEDGER.read_bytes()),"source_comparisons":len(old["geometry"]["source_comparisons"]),"compatible_even_hex_lengths":[1310],"plant_runs":4,"random_runs":2,"target_evaluated":False},indent=2))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args()
    if a.regenerate:
        if a.regenerate.exists(): raise SystemExit("refusing existing output")
        a.regenerate.write_text(json.dumps(generate(),indent=2,sort_keys=True)+"\n")
        print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":h(a.regenerate.read_bytes()),"target_evaluated":False},indent=2))
    else: verify()
if __name__=="__main__":main()

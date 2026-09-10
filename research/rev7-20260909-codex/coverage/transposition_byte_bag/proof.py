#!/usr/bin/env python3
"""Synthetic proof controls for endpoint byte-bag invariance and one-edit CFB8 bounds."""
from __future__ import annotations
import argparse,hashlib,json
from pathlib import Path
from Crypto.Cipher import DES
HERE=Path(__file__).resolve().parent
LEDGER=HERE/"controls.json"
IDENTITY="ASTRA"
CODEPOINTS=(9,10,13,*range(0x20,0x7f),*range(0xa0,0x100),0x2013,0x2014,0x2018,0x2019,0x201c,0x201d,0x2026)
WORDS=tuple(chr(cp).encode("utf-8") for cp in CODEPOINTS)
WORD_SET=frozenset(WORDS)
BYTE_UNION=frozenset(b for word in WORDS for b in word)
KEY=b"Zombies\0"
IV=b"0"*8
BLOCK=8
def sha_bytes(data):return hashlib.sha256(data).hexdigest()
def sha(path):return sha_bytes(Path(path).read_bytes())
def longest_allowed_run(data):
    best=0
    for start in range(len(data)):
        pos=start
        while pos<len(data):
            matches=[w for w in WORDS if data.startswith(w,pos)]
            assert len(matches)<=1
            if not matches:break
            pos+=len(matches[0])
        best=max(best,pos-start)
    return best
def manual_decrypt(ciphertext,iv=IV):
    e=DES.new(KEY,DES.MODE_ECB);reg=bytearray(iv);out=bytearray()
    for c in ciphertext:
        out.append(c^e.encrypt(bytes(reg))[0]);reg[:]=reg[1:]+bytes((c,))
    return bytes(out)
def library_decrypt(ciphertext,iv=IV):
    return DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8).decrypt(ciphertext)
def library_encrypt(plaintext,iv=IV):
    return DES.new(KEY,DES.MODE_CFB,iv=iv,segment_size=8).encrypt(plaintext)
def edit_controls():
    plain=b"".join(WORDS)
    assert len(plain)==311 and set(plain)==set(BYTE_UNION)
    ct=library_encrypt(plain)
    assert manual_decrypt(ct)==library_decrypt(ct)==plain
    rows={kind:[] for kind in ("substitution","insertion","deletion")}
    for j in range(len(ct)):
        changed=ct[:j]+bytes((ct[j]^0xa5,))+ct[j+1:]
        got=library_decrypt(changed);assert manual_decrypt(changed)==got
        assert got[:j]==plain[:j] and got[min(len(got),j+BLOCK+1):]==plain[min(len(plain),j+BLOCK+1):]
        affected=sum(a!=b for a,b in zip(got,plain))
        outside=sum(x not in BYTE_UNION for x in got[BLOCK:])
        assert affected<=BLOCK+1 and outside<=BLOCK+1
        rows["substitution"].append({"position":j,"affected_output_positions":affected,"outside_union_after_initial_block":outside,"plaintext_sha256":sha_bytes(got)})
    for j in range(len(ct)+1):
        changed=ct[:j]+b"\xa5"+ct[j:]
        got=library_decrypt(changed);assert manual_decrypt(changed)==got
        assert got[:j]==plain[:j]
        if j+BLOCK<=len(plain):assert got[j+BLOCK+1:]==plain[j+BLOCK:]
        altered_aligned=sum(got[k+1]!=plain[k] for k in range(j,min(j+BLOCK,len(plain))))
        affected_with_extra=altered_aligned+1
        outside=sum(x not in BYTE_UNION for x in got[BLOCK:])
        assert affected_with_extra<=BLOCK+1 and outside<=BLOCK+1
        rows["insertion"].append({"position":j,"altered_aligned_original_positions":altered_aligned,"extra_output_positions":1,"affected_including_extra":affected_with_extra,"outside_union_after_initial_block":outside,"plaintext_sha256":sha_bytes(got)})
    for j in range(len(ct)):
        changed=ct[:j]+ct[j+1:]
        got=library_decrypt(changed);assert manual_decrypt(changed)==got
        assert got[:j]==plain[:j]
        if j+BLOCK+1<=len(plain):assert got[j+BLOCK:]==plain[j+BLOCK+1:]
        altered_aligned=sum(got[k-1]!=plain[k] for k in range(j+1,min(j+BLOCK+1,len(plain))))
        affected_with_loss=altered_aligned+1
        outside=sum(x not in BYTE_UNION for x in got[BLOCK:])
        assert affected_with_loss<=BLOCK+1 and outside<=BLOCK
        rows["deletion"].append({"position":j,"altered_aligned_original_positions":altered_aligned,"lost_original_plaintext_positions":1,"affected_including_loss":affected_with_loss,"outside_union_after_initial_block":outside,"plaintext_sha256":sha_bytes(got)})
    return {"plaintext_bytes":len(plain),"plaintext_sha256":sha_bytes(plain),"ciphertext_sha256":sha_bytes(ct),"key_hex":KEY.hex(),"iv_hex":IV.hex(),"block_size":BLOCK,"damage_positions":{"substitution":len(rows["substitution"]),"insertion":len(rows["insertion"]),"deletion":len(rows["deletion"])},"maxima":{"substitution_affected_output":max(x["affected_output_positions"] for x in rows["substitution"]),"substitution_outside_union_after_initial_block":max(x["outside_union_after_initial_block"] for x in rows["substitution"]),"insertion_affected_including_extra":max(x["affected_including_extra"] for x in rows["insertion"]),"insertion_outside_union_after_initial_block":max(x["outside_union_after_initial_block"] for x in rows["insertion"]),"deletion_affected_including_loss":max(x["affected_including_loss"] for x in rows["deletion"]),"deletion_outside_union_after_initial_block":max(x["outside_union_after_initial_block"] for x in rows["deletion"])},"rows":rows,"manual_library_all_equal":True}
def compute():
    assert len(CODEPOINTS)==201 and len(WORDS)==201 and len(set(WORDS))==201
    counts={str(n):sum(len(w)==n for w in WORDS) for n in (1,2,3)}
    assert counts=={"1":98,"2":96,"3":7}
    assert len(BYTE_UNION)==165
    union_parts={"ascii_singletons":sorted({b for w in WORDS if len(w)==1 for b in w}),"continuations":list(range(0x80,0xc0)),"multibyte_leads":[0xc2,0xc3,0xe2]}
    assert set(union_parts["ascii_singletons"])|set(union_parts["continuations"])|set(union_parts["multibyte_leads"])==set(BYTE_UNION)
    examples=[]
    for repetitions in (1,2,16,256):
        original=chr(0x2013).encode()*repetitions
        permuted=bytes.fromhex("e29380")*repetitions
        assert sorted(original)==sorted(permuted)
        assert original.decode()=="\u2013"*repetitions and permuted.decode()=="\u24c0"*repetitions
        assert longest_allowed_run(original)==len(original) and longest_allowed_run(permuted)==0
        examples.append({"repetitions":repetitions,"bytes":len(original),"original_codepoint":"U+2013","permuted_codepoint":"U+24C0","original_hex":original.hex(),"permuted_hex":permuted.hex(),"same_byte_histogram":True,"both_valid_utf8":True,"original_longest_allowed_run":len(original),"permuted_longest_allowed_run":0,"original_sha256":sha_bytes(original),"permuted_sha256":sha_bytes(permuted)})
    edits=edit_controls()
    # Same damaged ciphertext under two IVs: after b bytes, both CFB8 registers contain
    # exactly the first b damaged ciphertext bytes, independently of either initial IV.
    strong_plain=b"".join(WORDS)
    strong_ct=library_encrypt(strong_plain)
    wrong_iv=bytes.fromhex("A55AC33C9669F00F")
    wrong_iv_rows=[]
    for position in (3,10):
        damaged=strong_ct[:position]+bytes((strong_ct[position]^0xa5,))+strong_ct[position+1:]
        correct=library_decrypt(damaged,IV)
        wrong=library_decrypt(damaged,wrong_iv)
        assert manual_decrypt(damaged,wrong_iv)==wrong
        assert correct[BLOCK:]==wrong[BLOCK:]
        mismatches=[i for i,(a,b) in enumerate(zip(correct,strong_plain)) if i>=BLOCK and a!=b]
        assert all(position<=i<=position+BLOCK for i in mismatches)
        wrong_iv_rows.append({"edit":"substitution","position":position,"correct_iv_hex":IV.hex(),"arbitrary_decoder_iv_hex":wrong_iv.hex(),"outputs_equal_from_damaged_ciphertext_byte":BLOCK,"equal_after_flush":True,"post_flush_mismatch_positions_against_undamaged_plaintext":mismatches,"all_post_flush_mismatches_inside_edit_window":True,"damaged_ciphertext_sha256":sha_bytes(damaged),"post_flush_plaintext_sha256":sha_bytes(wrong[BLOCK:])})
    return {"identity":IDENTITY,"target_evaluated":False,"rev7_read":False,"scope":"Synthetic mathematics and DES-CFB8 controls for the declared 201-codepoint endpoint only.","endpoint":{"codepoints":["TAB","LF","CR","U+0020..U+007E","U+00A0..U+00FF","U+2013","U+2014","U+2018","U+2019","U+201C","U+201D","U+2026"],"codeword_counts_by_utf8_length":counts,"byte_union_count":len(BYTE_UNION),"byte_union_hex":[f"{x:02X}" for x in sorted(BYTE_UNION)],"union_partition_hex":{"ascii_singletons":[f"{x:02X}" for x in union_parts["ascii_singletons"]],"continuations_80_BF":[f"{x:02X}" for x in union_parts["continuations"]],"multibyte_leads":[f"{x:02X}" for x in union_parts["multibyte_leads"]]}},"invariance":{"necessary_condition":"Every valid endpoint encoding uses only the 165-byte union, so an arbitrary byte permutation preserves membership in that union and its complete byte histogram.","not_invariant":["UTF-8 validity","allowed codepoint count","longest consecutive allowed-codeword run"],"counterexamples":examples,"arbitrary_length_family":True},"cfb8_one_edit_bound":{"statement":"After discarding any initial block, one ciphertext substitution creates at most b+1 changed output positions; insertion creates at most b changed aligned-original positions plus one extra output; deletion creates at most b changed aligned-original outputs plus one lost original position. Thus present decoded bytes outside the endpoint byte union are at most b+1 (and at most b for deletion).","proof":{"substitution":"C_j changes P_j directly and remains in the previous-ciphertext register only for P_(j+1)..P_(j+b); later windows match.","insertion":"The inserted ciphertext produces one extra plaintext byte and shifts the register for the next b aligned original positions; at original position j+b the aligned previous-b-byte window is restored.","deletion":"The plaintext corresponding to C_j is lost. The next b aligned original positions use shifted windows; original position j+b+1 is the first with a restored previous-b-byte window."},"conditions":["Correct fixed cipher, key, CFB8 convention, and alignment outside the one edit.","Every undamaged plaintext byte belongs to the 165-byte union. This includes an arbitrary byte permutation of a valid declared-endpoint encoding before CFB8 encryption; ordered UTF-8 is not required.","An arbitrary decoder IV is flushed after the first b bytes of the damaged ciphertext, because the register then contains only ciphertext bytes.","Counts concern bytes present after the initial block; deletion's lost plaintext position is reported separately.","An arbitrary transposition or corruption applied to ciphertext is not modeled as one edit. The theorem also does not cover multiple edits, wrong keys, adaptive completion, or all Unicode."]},"synthetic_des_cfb8":edits,"unknown_iv_flush_controls":{"block_size":BLOCK,"principle":"After b damaged ciphertext bytes, the CFB8 register is ciphertext-only and independent of the decoder IV.","rows":wrong_iv_rows},"assertions":{"endpoint_counts_98_96_7":True,"byte_union_165":True,"byte_permutation_preserves_union_not_utf8_runs":True,"valid_utf8_zero_run_counterexample_arbitrary_length":True,"manual_and_library_cfb8_agree_all_damage_positions":True,"substitution_bound_b_plus_1":True,"insertion_bound_b_plus_1_including_extra":True,"deletion_bound_b_plus_1_including_loss_and_output_outside_at_most_b":True,"plaintext_byte_permutations_covered_by_membership_condition":True,"wrong_decoder_iv_flushes_after_b_damaged_ciphertext_bytes":True,"ciphertext_permutation_not_claimed_as_one_edit":True,"no_target":True},"source_sha256":sha(Path(__file__))}
def verify():
    old=json.loads(LEDGER.read_text());fresh=compute();assert old==fresh and all(old["assertions"].values())
    print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"byte_union":165,"counterexample_max_bytes":old["invariance"]["counterexamples"][-1]["bytes"],"damage_positions":old["synthetic_des_cfb8"]["damage_positions"],"target_evaluated":False},indent=2,sort_keys=True))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args()
    if a.regenerate:
        if a.regenerate.exists():raise SystemExit("refusing existing output")
        a.regenerate.write_text(json.dumps(compute(),indent=2,sort_keys=True)+"\n")
        print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate),"target_evaluated":False},indent=2))
    else:verify()
if __name__=="__main__":main()

#!/usr/bin/env python3
"""Complete source-only inventory of positive four-digit keys emitting four chars per full row."""
from __future__ import annotations
import argparse,hashlib,importlib.util,json,sys
from pathlib import Path
HERE=Path(__file__).resolve().parent
ROOT=HERE.parents[3]
LEDGER=HERE/"inventory.json"
ANALYZE=ROOT/"research/char_amsco/astra/cryptool_bug/analyze.py"
ANALYZE_SHA="ba66b3c844cf5784749587af960a11163d5e47deddf523a04530bea4f5d9629b"
IDENTITY="ASTRA"
COL_POSITIONS=((0,1),(2,),(3,4),(5,))
CANDIDATE_EVEN_LENGTHS=(1632,1634,1636,1638,1640,1642)
def sha_bytes(data):return hashlib.sha256(data).hexdigest()
def sha(path):return sha_bytes(Path(path).read_bytes())
def source_port():
    assert sha(ANALYZE)==ANALYZE_SHA
    spec=importlib.util.spec_from_file_location("astra_lossy4_twochar_source",ANALYZE)
    module=importlib.util.module_from_spec(spec);sys.modules[spec.name]=module;assert spec.loader;spec.loader.exec_module(module);module.verify_pins();return module
def cells(length):
    rows=[];pos=0;cell=0;size=2
    while pos<length:
        row=cell//4;col=cell%4
        while len(rows)<=row:rows.append([])
        take=min(size,length-pos)
        rows[row].append((col,tuple(range(pos,pos+take))))
        pos+=take;cell+=1;size=3-size
    return rows
def emission_indices(length,key):
    if length<0 or len(key)!=4 or not key.isdigit():raise ValueError("four digit key and nonnegative length required")
    labelled=[]
    for row_cells in cells(length):
        row={}
        for col,positions in row_cells:row[int(key[col])]=positions
        labelled.append(row)
    out=[]
    for label in range(1,5):
        for row in labelled:out.extend(row.get(label,()))
    return tuple(out)
def emit(text,key):return "".join(text[i] for i in emission_indices(len(text),key))
def column_order(indices):
    out=[]
    for index in indices:
        col=next(c for c,positions in enumerate(COL_POSITIONS) if index in positions)
        if col not in out:out.append(col)
    return out
def fixture(length,label):
    out="";counter=0
    while len(out)<length:
        out+=hashlib.sha256((label+"|"+str(counter)).encode()).hexdigest().upper();counter+=1
    return out[:length]
def map_hash(indices):return sha_bytes(json.dumps(list(indices),separators=(",",":")).encode())
def prefix_masks(length,indices,byte_count=8):
    nibbles=[0]*length
    for index in indices:nibbles[index]=0xf0 if index%2==0 else 0x0f
    masks=[nibbles[2*i]|nibbles[2*i+1] for i in range(byte_count)]
    unknown_nibbles=sum((mask&0xf0)==0 for mask in masks)+sum((mask&0x0f)==0 for mask in masks)
    return masks,unknown_nibbles,16**unknown_nibbles
def compute():
    legacy=source_port()
    short=(fixture(6,"ASTRA twochar short A"),fixture(6,"ASTRA twochar short B"))
    full_distribution={i:0 for i in range(7)}
    qualifying=[]
    for number in range(1000,10000):
        key=str(number);indices=emission_indices(6,key);full_distribution[len(indices)]+=1
        for source in short:assert emit(source,key)==legacy.legacy_encode(source.encode(),key)["raw"].decode()
        if len(indices)==4:
            retained=sorted({next(c for c,pos in enumerate(COL_POSITIONS) if i in pos) for i in indices})
            order=column_order(indices);dropped=sorted(set(range(4))-set(retained))
            qualifying.append({"key":key,"retained_columns":retained,"dropped_columns":dropped,"full_row_read_order":order})
    assert full_distribution=={0:1080,1:2040,2:2460,3:2196,4:864,5:336,6:24}
    assert len(qualifying)==864
    retained_set_counts={}
    for row in qualifying:
        label=",".join(map(str,row["retained_columns"]))
        retained_set_counts[label]=retained_set_counts.get(label,0)+1
    assert retained_set_counts=={"0,2":504,"1,2,3":192,"0,1,3":168}
    # Source comparisons across the complete quotient/remainder candidate set.
    for n in CANDIDATE_EVEN_LENGTHS:
        source=fixture(n,"ASTRA twochar candidate "+str(n))
        for row in qualifying:
            key=row["key"]
            assert emit(source,key)==legacy.legacy_encode(source.encode(),key)["raw"].decode()
    groups={}
    length_members={str(n):[] for n in CANDIDATE_EVEN_LENGTHS}
    partial_distributions={"r0":{},"r2":{},"r4":{}}
    for row in qualifying:
        key=row["key"]
        for r,label in ((0,"r0"),(2,"r2"),(4,"r4")):
            count=len(emission_indices(r,key))
            partial_distributions[label][str(count)]=partial_distributions[label].get(str(count),0)+1
        compatible=[]
        for n in CANDIDATE_EVEN_LENGTHS:
            indices=emission_indices(n,key)
            if len(indices)!=1092:continue
            compatible.append(n);length_members[str(n)].append(key)
            digest=map_hash(indices);gid=f"N={n}|map={digest}"
            masks,unknown,root_count=prefix_masks(n,indices)
            g=groups.setdefault(gid,{"input_chars":n,"input_bytes":n//2,"map_sha256":digest,"emission_indices":list(indices),"representative_key":key,"members":[],"retained_columns":row["retained_columns"],"dropped_columns":row["dropped_columns"],"full_row_read_order":row["full_row_read_order"],"first8_byte_masks":[f"{x:02X}" for x in masks],"first8_unknown_nibbles":unknown,"first8_root_domain_count":root_count})
            assert g["emission_indices"]==list(indices) and g["retained_columns"]==row["retained_columns"] and g["dropped_columns"]==row["dropped_columns"] and g["full_row_read_order"]==row["full_row_read_order"]
            row_masks,row_unknown,row_roots=prefix_masks(n,indices)
            assert row_masks==masks and row_unknown==unknown and row_roots==root_count
            g["members"].append(key)
        row["compatible_even_input_lengths"]=compatible
    classes=sorted(groups.values(),key=lambda x:(x["input_chars"],x["map_sha256"]))
    class_counts={}
    for index,g in enumerate(classes):
        g["class_id"]=f"N{g['input_chars']}-C{index+1:02d}"
        g["member_count"]=len(g["members"])
        class_counts[str(g["input_chars"])]=class_counts.get(str(g["input_chars"]),0)+1
    length_member_counts={k:len(v) for k,v in length_members.items()}
    root_domain_class_counts={}
    for g in classes:
        key=str(g["first8_root_domain_count"])
        root_domain_class_counts[key]=root_domain_class_counts.get(key,0)+1
    assert partial_distributions=={"r0":{"0":864},"r2":{"2":744,"0":120},"r4":{"3":648,"2":168,"4":48}}
    assert length_member_counts=={"1632":0,"1634":0,"1636":48,"1638":864,"1640":120,"1642":0}
    assert class_counts=={"1636":12,"1638":14,"1640":6}
    assert root_domain_class_counts=={"1048576":14,"16777216":18}
    assert sum(g["member_count"] for g in classes)==1032
    return {"identity":IDENTITY,"target_evaluated":False,"rev7_content_read":False,"scope":"All positive decimal four-digit keys 1000 through 9999 whose complete six-character source21 row emits exactly four characters; source and geometry only.","source":{"analyze_py":str(ANALYZE.relative_to(ROOT)),"analyze_sha256":ANALYZE_SHA,"legacy_commit":"4fc443f0d87c0e86815695a47ab2d6174c725f82"},"all_9000_distribution_by_full_row_emitted_chars":{str(k):v for k,v in full_distribution.items()},"qualification":{"qualifying_count":len(qualifying),"nonqualifying_count":9000-len(qualifying),"qualifying_keys":qualifying,"retained_column_set_counts_zero_based":retained_set_counts,"meaning":"The exact map classes below apply only to these 864 qualifying keys; all other four-digit keys are outside this family."},"length_completeness":{"observed_length":1092,"proof":"For qualifying keys M=4q+t(r), q=floor(N/6), 0<=t<=5. M=1092 forces q in {272,273}. Even N permits only r in {0,2,4}, yielding exactly the six candidates 1632,1634,1636,1638,1640,1642; exact partial-row maps test all six.","forced_full_row_quotients":[272,273],"candidate_even_lengths":list(CANDIDATE_EVEN_LENGTHS),"partial_row_emitted_count_distributions":partial_distributions,"compatible_even_lengths":[1636,1638,1640],"qualifying_key_memberships_by_length":length_member_counts,"no_bounded_scan_assumption":True},"map_classes":classes,"map_class_counts_by_input_length":class_counts,"first8_root_geometry":{"meaning":"Number of assignments to unknown ciphertext nibbles in the first eight natural bytes; geometry only, not an enumerated search.","root_domain_class_counts":root_domain_class_counts,"possible_counts":[1048576,16777216]},"source_crosschecks":{"all_9000_keys_two_complete_row_fixtures":True,"all_864_qualifiers_all_six_candidate_lengths_one_fixture_each":True,"partial_duplicate_fallback_included":True},"assertions":{"all_9000_distribution_exact":True,"qualifying_count_864":True,"retained_column_sets_exact":True,"partial_distributions_exact":True,"compatible_lengths_exact_1636_1638_1640":True,"map_class_counts_exact_12_14_6":True,"root_domains_only_1M_16M_with_class_counts_14_18":True,"all_source_crosschecks_equal":True,"no_target_or_crypto":True},"source_sha256":sha(Path(__file__))}
def verify():
    old=json.loads(LEDGER.read_text());fresh=compute();assert old==fresh and all(old["assertions"].values())
    print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"keys":9000,"qualifying":864,"compatible_even_lengths":[1636,1638,1640],"map_class_counts":{"1636":12,"1638":14,"1640":6},"target_evaluated":False},indent=2,sort_keys=True))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);a=ap.parse_args()
    if a.regenerate:
        if a.regenerate.exists():raise SystemExit("refusing existing output")
        a.regenerate.write_text(json.dumps(compute(),indent=2,sort_keys=True)+"\n")
        print(json.dumps({"identity":"ASTRA","output":str(a.regenerate),"sha256":sha(a.regenerate),"target_evaluated":False},indent=2))
    else:verify()
if __name__=="__main__":main()

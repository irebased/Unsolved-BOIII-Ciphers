#!/usr/bin/env python3
"""Complete source-only inventory of positive four-digit keys that emit five chars per full row."""
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
def sha_bytes(data):return hashlib.sha256(data).hexdigest()
def sha(path):return sha_bytes(Path(path).read_bytes())
def source_port():
    assert sha(ANALYZE)==ANALYZE_SHA
    spec=importlib.util.spec_from_file_location("astra_lossy4_source",ANALYZE)
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
def full_row_info(key):
    indices=emission_indices(6,key)
    retained=[col for col,pos in enumerate(COL_POSITIONS) if any(i in indices for i in pos)]
    read_order=[]
    for i in indices:
        col=next(c for c,pos in enumerate(COL_POSITIONS) if i in pos)
        if col not in read_order:read_order.append(col)
    qualifying=len(indices)==5
    return indices,retained,read_order,qualifying
def compatible_even_lengths(key):
    # For a qualifying key, q is forced to 218; only even remainders 0,2,4 need testing.
    return [1308+r for r in (0,2,4) if len(emission_indices(1308+r,key))==1092]
def fixture(length,label):
    out="";counter=0
    while len(out)<length:
        out+=hashlib.sha256((label+"|"+str(counter)).encode()).hexdigest().upper();counter+=1
    return out[:length]
def map_hash(indices):
    return sha_bytes(json.dumps(list(indices),separators=(",",":")).encode())
def compute():
    legacy=source_port()
    whole_cell=legacy.legacy_encode(b"ABCDEF","1123")
    assert whole_cell["raw"]==b"CDEF" and whole_cell["lost_positions"]==[0,1]
    rows=[];groups={};qualifying_keys=[]
    short_a=fixture(6,"ASTRA inventory short A")
    short_b=fixture(6,"ASTRA inventory short B")
    for number in range(1000,10000):
        key=str(number)
        indices,retained,order,qualifying=full_row_info(key)
        for source in (short_a,short_b):
            assert emit(source,key)==legacy.legacy_encode(source.encode(),key)["raw"].decode()
        row={"key":key,"full_row_emitted_chars":len(indices),"qualifying":qualifying}
        if qualifying:
            assert len(retained)==3 and len(order)==3 and (set(range(4))-set(retained))<={1,3}
            lengths=compatible_even_lengths(key)
            assert 1310 in lengths and set(lengths)<={1310,1312}
            row.update({"retained_columns":retained,"dropped_column":next(iter(set(range(4))-set(retained))),"full_row_read_order":order,"compatible_even_input_lengths":lengths})
            qualifying_keys.append(key)
            # Crosscheck all relevant partial remainders around the forced full-row quotient,
            # under two independent deterministic hexadecimal fixtures.
            for n in range(1308,1314):
                for label in ("ASTRA inventory long A","ASTRA inventory long B"):
                    source=fixture(n,label)
                    assert emit(source,key)==legacy.legacy_encode(source.encode(),key)["raw"].decode()
            for n in lengths:
                indices_n=emission_indices(n,key);mh=map_hash(indices_n);gid=f"N={n}|map={mh}"
                g=groups.setdefault(gid,{"input_chars":n,"input_bytes":n//2,"map_sha256":mh,"emission_indices":list(indices_n),"representative_key":key,"members":[],"dropped_column":row["dropped_column"],"full_row_read_order":order})
                assert g["emission_indices"]==list(indices_n) and g["dropped_column"]==row["dropped_column"] and g["full_row_read_order"]==order
                g["members"].append(key)
        rows.append(row)
    classes=sorted(groups.values(),key=lambda x:(x["input_chars"],x["map_sha256"]))
    for i,g in enumerate(classes):
        g["class_id"]=f"N{g['input_chars']}-C{i+1:02d}"
        g["member_count"]=len(g["members"])
    by_n={}
    for g in classes:by_n.setdefault(str(g["input_chars"]),0);by_n[str(g["input_chars"])]+=1
    qualifying=sum(x["qualifying"] for x in rows)
    dropped_counts={str(col):sum(x["qualifying"] and x["dropped_column"]==col for x in rows) for col in (1,3)}
    partial_r4_counts={str(count):sum(x["qualifying"] and len(emission_indices(4,x["key"]))==count for x in rows) for count in (3,4)}
    compatible_lengths=sorted({n for x in rows if x["qualifying"] for n in x["compatible_even_input_lengths"]})
    assert len(rows)==9000 and qualifying==len(qualifying_keys)==336
    assert by_n=={"1310":12}
    assert compatible_lengths==[1310]
    assert dropped_counts=={"1":192,"3":144}
    assert partial_r4_counts=={"3":168,"4":168}
    assert sum(g["member_count"] for g in classes)==336
    assert {x["dropped_column"] for x in classes}=={1,3}
    assert all(len(x["full_row_read_order"])==3 for x in classes)
    return {"identity":IDENTITY,"target_evaluated":False,"rev7_content_read":False,"scope":"All positive decimal four-digit keys 1000 through 9999 under the pinned original source21 row-label encoder; source/geometry only, no cryptography.","source":{"analyze_py":str(ANALYZE.relative_to(ROOT)),"analyze_sha256":ANALYZE_SHA,"legacy_commit":"4fc443f0d87c0e86815695a47ab2d6174c725f82","class_assignment":{"path":"research/char_amsco/astra/cryptool_bug/source/class.amsco.php","sha256":"132d61ff8b794ab9717a0ce284d7bf21f82c8dbfe39bf9f1a3b5f7aa7eb91e4f","git_blob_sha1":"33eccb9a91008386fbcc24fecb690d7589aa66e0","line":191,"quote":"$out[$row][$str_key[$col-1]] = $value;","meaning":"The complete cell value is assigned to one row/label slot; a later duplicate assignment replaces that complete value."}},"full_row":{"input_chars":6,"qualifying_emitted_chars":5,"qualifying_condition":"exactly three retained natural columns and the dropped column is one of the one-character columns 1 or 3","distinct_maps_at_1310":12,"map_scope":"The 12 maps classify only the 336 qualifying keys, not all 9000 four-digit keys.","whole_cell_overwrite_witness":{"key":"1123","input":"ABCDEF","first_two_char_cell":"AB","later_duplicate_cell":"C","output":"CDEF","lost_positions":[0,1],"entire_two_character_cell_lost":True,"partial_final_rows_classified_separately":True}},"length_completeness":{"observed_length":1092,"proof":"For qualifying keys M=5q+t(r), q=floor(N/6), 0<=t<=5. q<=217 gives M<=1090 and q>=219 gives M>=1095, so q=218. Even N permits only r=0,2,4. Exact partial-row enumeration gives t(0)=0 for all336, t(2)=2 for all336, and t(4)=3 for168 keys or4 for168 keys; therefore only r=2 reaches1092.","forced_full_rows":218,"even_candidates_tested":[1308,1310,1312],"compatible_even_lengths":compatible_lengths,"partial_row_emitted_count_distributions":{"r0":{"0":336},"r2":{"2":336},"r4":partial_r4_counts},"no_bounded_scan_assumption":True},"classification":{"all_9000_keys":rows,"qualifying_key_count":qualifying,"qualifying_fraction":"336/9000","twelve_map_claim_applies_to":"qualifying keys only","nonqualifying_key_count":9000-qualifying,"dropped_column_counts_zero_based":dropped_counts},"map_classes":classes,"map_class_counts_by_input_length":by_n,"source_crosschecks":{"all_9000_keys_two_length6_fixtures":True,"every_qualifying_key_lengths1308_through1313_two_fixtures":True,"partial_row_duplicate_fallback_included":True},"assertions":{"all_9000_classified":True,"all_source_crosschecks_equal":True,"qualifiers_drop_exactly_col1_or_col3":True,"twelve_maps_at_N1310_for_336_qualifying_keys_only":True,"whole_cell_overwrite_source_and_witness":True,"exact_class_count_by_length_1310_only":True,"exact_qualifying_count_336":True,"exact_dropped_column_counts_zero_based_1_192_3_144":True,"exact_partial_r4_counts_3_168_4_168":True,"all_length_candidates_complete":True,"no_target_or_crypto":True},"source_sha256":sha(Path(__file__))}
def verify():
    data=json.loads(LEDGER.read_text());fresh=compute();assert data==fresh
    assert data["identity"]=="ASTRA" and all(data["assertions"].values())
    print(json.dumps({"identity":"ASTRA","verified":True,"ledger_sha256":sha(LEDGER),"keys":9000,"qualifying":data["classification"]["qualifying_key_count"],"class_counts_by_length":data["map_class_counts_by_input_length"],"target_evaluated":False},indent=2,sort_keys=True))
def main():
    ap=argparse.ArgumentParser();ap.add_argument("--regenerate",type=Path);args=ap.parse_args()
    if args.regenerate:
        if args.regenerate.exists():raise SystemExit("refusing existing output")
        args.regenerate.write_text(json.dumps(compute(),indent=2,sort_keys=True)+"\n")
        print(json.dumps({"identity":"ASTRA","output":str(args.regenerate),"sha256":sha(args.regenerate),"target_evaluated":False},indent=2))
    else:verify()
if __name__=="__main__":main()

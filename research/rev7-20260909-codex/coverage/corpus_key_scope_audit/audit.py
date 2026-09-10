#!/usr/bin/env python3
"""ASTRA target-free audit of key fields in the frozen RA corpus snapshot."""
from __future__ import annotations
import argparse, hashlib, json
from pathlib import Path

HERE = Path(__file__).resolve().parent
RA = HERE.parent / "ra_prefix_inventory" / "source" / "ra"
DATA = RA / "data"
CORPUS_RS = RA / "crates" / "ra-cli" / "src" / "corpus.rs"
NODES_RS = RA / "crates" / "ra-core" / "src" / "nodes.rs"
REV3_MDX = HERE.parents[3] / "lavender" / "src" / "content" / "docs" / "ciphers" / "bo3" / "rev" / "rev3.mdx"
REV3_MDX_SHA = "0185f674db09dfe542de8ecf2880cf83690cc8331001ebfefa65ddc4f965a243"
MAPS = ("revelations.json", "soe.json", "der_eisendrache.json", "the_giant.json", "zetsubou.json", "gorod_krovi.json")
AUDITED_NINE = MAPS + ("conformance_suite.json", "evidence_base.json", "zombies_sources.csv")
EXPECTED = {
 "revelations.json":"68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e",
 "soe.json":"352bc73f7780b529b2ee50e15d05b91a70bde85c6d0ceb9b2daf490fe00a7a73",
 "der_eisendrache.json":"d1e9030643d2f0ce4c98ea280f57c394993ca4de4d30482cc24459db01836d00",
 "the_giant.json":"e730927364ad146ce579d4b6cd700f615758ab901f46c4dadeb49d4e8c079da5",
 "zetsubou.json":"c0eee2efe0385a08e0a108e6d3bd7a1b90089e92782c4e0da17410336c098de8",
 "gorod_krovi.json":"f05703ae5173e02187e4840593cf9137048a60e5dec13898961ec606ddef0d3d",
 "conformance_suite.json":"4d6c0c62e1b580dd45fe40910d4f3f59b3b75656e9869968d8676b378e13e175",
 "evidence_base.json":"cb669c458863d9d42ed1610b20ca9847fce2d1f438208faad0263eb11bcc23c8",
 "zombies_sources.csv":"4aeac9cc75f52eef12259edf20ca6f08c5e270c3296d99fba87068f91ca6e238",
}

def sha(p: Path) -> str: return hashlib.sha256(p.read_bytes()).hexdigest()
def canonical(x) -> bytes: return (json.dumps(x, sort_keys=True, indent=2, ensure_ascii=True)+"\n").encode()

def beaufort(text: str, key: str, alphabet: str) -> str:
    pos={c:i for i,c in enumerate(alphabet)}
    assert len(pos)==len(alphabet) and key and all(c in pos for c in key)
    out=[]; j=0
    for c in text:
        if c not in pos: out.append(c); continue
        out.append(alphabet[(pos[key[j]]-pos[c]) % len(alphabet)])
        j=(j+1)%len(key)
    return ''.join(out)

def generate():
    pins={name:{"sha256":sha(DATA/name),"bytes":(DATA/name).stat().st_size} for name in AUDITED_NINE}
    assert {k:v["sha256"] for k,v in pins.items()}==EXPECTED
    records=[]
    for name in MAPS:
        vals=json.loads((DATA/name).read_text())
        for rec in vals:
            steps=(rec.get("solution") or {}).get("steps") or []
            records.append((name,rec,steps))
    modern=[]; explicit_lore=[]; layered_keyed=[]; substitutions=[]
    for name,rec,steps in records:
        for i,s in enumerate(steps):
            base={"file":name,"id":rec.get("id"),"step_index":i,"step_count":len(steps),"step":s}
            if s.get("type")=="decrypt": modern.append(base)
            if name!="revelations.json" and s.get("type")=="classical" and "key" in s:
                explicit_lore.append(base)
            if name=="revelations.json" and len(steps)>1 and s.get("type")=="classical" and "key" in s:
                layered_keyed.append(base)
            if s.get("type")=="classical" and s.get("method") in ("substitution","homophonic_substitution"):
                substitutions.append(base)
    assert sha(REV3_MDX)==REV3_MDX_SHA
    rev3_doc=REV3_MDX.read_text()
    assert "fkmcpdyehbigqrosazlutjnwvx" in rev3_doc and "spare positions 3 and 7" in rev3_doc
    assert len(modern)==13
    key_counts={k:sum(x["step"].get("key")==k for x in modern) for k in sorted({x["step"].get("key") for x in modern})}
    assert key_counts=={"ZOMBIES":1,"Zombies":12}
    assert len(explicit_lore)==7 and all(x["step_count"]==1 for x in explicit_lore)
    assert len(layered_keyed)==2 and {x["step"]["key"] for x in layered_keyed}=={"ZOMBIES"}
    solved_missing=[{"file":n,"id":r.get("id")} for n,r,st in records if r.get("solved") is True and not st]
    embedded_config=[]
    for n,r,st in records:
        for i,s in enumerate(st):
            cfg=s.get("configuration")
            if isinstance(cfg,str) and "key" in cfg.lower():
                embedded_config.append({"file":n,"id":r.get("id"),"step_index":i,"configuration":cfg})
    alphabet="ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz"
    inp="ABCDEF0123456789"; enc=beaufort(inp,"F",alphabet)
    assert enc=="FEDCBA0123456789"
    assert beaufort(enc,"F",alphabet)==inp
    return {
      "identity":"ASTRA","target_evaluated":False,"new_search":False,
      "scope":{"audited_data_files":list(AUDITED_NINE),"structured_map_files":list(MAPS),
        "note":"The nine-file inventory is six map JSON files plus conformance_suite.json, evidence_base.json, and zombies_sources.csv; structured solution-step counts come from the six maps."},
      "source_pins":pins | {
        "crates/ra-cli/src/corpus.rs":{"sha256":sha(CORPUS_RS),"bytes":CORPUS_RS.stat().st_size},
        "crates/ra-core/src/nodes.rs":{"sha256":sha(NODES_RS),"bytes":NODES_RS.stat().st_size},
        "lavender/src/content/docs/ciphers/bo3/rev/rev3.mdx":{"sha256":sha(REV3_MDX),"bytes":REV3_MDX.stat().st_size}},
      "structured_counts":{"records":len(records),"solved_records":sum(r.get("solved") is True for _,r,_ in records),
        "solution_steps":sum(len(st) for _,_,st in records),"modern_decrypt_steps":len(modern),
        "modern_key_spelling_counts":key_counts,"non_revelations_explicit_classical_key_fields":len(explicit_lore),
        "those_explicit_key_records_with_exactly_one_step":sum(x["step_count"]==1 for x in explicit_lore),
        "revelations_layered_explicit_keyed_classical_steps":len(layered_keyed)},
      "modern_decrypt_steps":modern,"non_revelations_explicit_classical_keys":explicit_lore,
      "revelations_layered_explicit_keyed_classical_steps":layered_keyed,
      "structured_gaps":{"solved_records_with_no_steps":solved_missing,
        "rev3_documented_alternate_solution":{"json_steps":["base10","straddling_checkerboard","substitution"],"json_explicit_key_fields":0,"mdx_lines":"22-38","mdx_original_solution_steps":4,"documented_checkerboard_key_or_alphabet":"fkmcpdyehbigqrosazlutjnwvx","spare_positions":[3,7],"interpretation":"The MDX labels this the original four-step solution, while the JSON stores a different simplified three-step solution. The string is a documented checkerboard key/alphabet for that decode; this audit does not identify it as the puzzle author original keyword."},
        "rev11_trifid_missing_explicit_key":{"file":"revelations.json","id":"rev11","step_index":6,"method":"Trifid","has_key_field":False,"note":"The structured final Trifid step has output text but no explicit key field."},
        "substitution_like_steps":substitutions,
        "configuration_strings_with_embedded_key_text":embedded_config,
        "interpretation":"A count of seven direct classical key fields excludes parameters embedded in free-text configuration and excludes records with missing key/mapping fields."},
      "synthetic_beaufort":{"source_anchor":"nodes.rs:173-200","alphabet":alphabet,"key":"F","input":inp,"output":enc,
        "reciprocal_output":beaufort(enc,"F",alphabet),"hex_alphabet_preserved":set(enc)<=set("0123456789ABCDEF"),
        "claim":"This existential source-defined transformation refutes the claim that every letter-52 classical pre-layer must destroy hexness."},
      "limits":[
        "These are frequencies in frozen solved records, not a generative rule for Rev7.",
        "Structured steps omit some solved-record steps and some substitution keys or mappings.",
        "The seven direct lore key fields do not include keys written only inside free-text configuration.",
        "The counterexample establishes possibility only; it does not assert that Rev7 uses Beaufort or key F."
      ]}

def main():
    ap=argparse.ArgumentParser(); ap.add_argument("--generate",type=Path); a=ap.parse_args()
    got=generate()
    if a.generate:
        if a.generate.exists(): raise SystemExit(f"refusing existing output: {a.generate}")
        a.generate.write_bytes(canonical(got)); print(a.generate); return
    p=HERE/"controls.json"; frozen=json.loads(p.read_bytes()); assert frozen==got
    print(json.dumps({"status":"PASS","ledger_sha256":sha(p),"modern":got["structured_counts"]["modern_decrypt_steps"],"explicit_lore_keys":got["structured_counts"]["non_revelations_explicit_classical_key_fields"],"beaufort_output":got["synthetic_beaufort"]["output"]},sort_keys=True))
if __name__=="__main__": main()

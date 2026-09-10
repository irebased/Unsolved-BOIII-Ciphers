#!/usr/bin/env python3
"""Read-only OCR/transcript comparison; does not change the canonical cipher."""
import argparse, difflib, hashlib, json
from pathlib import Path
HERE = Path(__file__).resolve().parent
ROOT = HERE.parents[2]
parser = argparse.ArgumentParser()
parser.add_argument("--ocr", type=Path, default=HERE / "vision.json")
args = parser.parse_args()
raw = json.loads(args.ocr.read_text())
lines = []
for row in sorted(raw["rows"], key=lambda a: -a["y"]):
    group = next((g for g in lines if abs(g[0]["y"] - row["y"]) < 0.012), None)
    if group is None:
        lines.append([row])
    else:
        group.append(row)
ocr_lines = [" ".join(x["candidates"][0]["text"] for x in sorted(g, key=lambda a: a["x"])) for g in lines]
mdx = ROOT / "lavender/src/content/docs/ciphers/bo3/rev/rev7.mdx"
image = ROOT / "lavender/src/assets/revelations_7.png"
sha = lambda p: hashlib.sha256(p.read_bytes()).hexdigest()
assert sha(mdx) == "085e686e5eaff202d2869d8de3d083418697fac5151985fcc25aeb656ee19d91"
assert sha(image) == "36a1883ede6abadcf4d4420f26484ca81134f3b62fe0ac7521352c682bf0b3b7"
text = mdx.read_text()
a = text.index("`83 B57B2") + 1
b = text.index("`", a)
can_lines = text[a:b].splitlines()
canonical = "".join(text[a:b].split()).upper()
raw_text = "".join("".join(x.split()) for x in ocr_lines).upper()
normalized = raw_text.translate(str.maketrans({"O": "0", "S": "5", "З": "3", ".": None}))
changes = []
for tag, i, j, k, l in difflib.SequenceMatcher(None, canonical, normalized, autojunk=False).get_opcodes():
    if tag != "equal":
        changes.append({"operation": tag, "canonical_range": [i,j], "canonical": canonical[i:j], "ocr_range": [k,l], "ocr": normalized[k:l], "context": canonical[max(0,i-12):min(len(canonical),j+12)]})
result = {"identity": "ASTRA", "source_image_sha256": sha(image), "mdx_sha256": sha(mdx), "ocr_sha256": sha(args.ocr), "row_clustering_y_tolerance": 0.012, "line_count": len(lines), "canonical_symbol_count": len(canonical), "raw_ocr_symbol_count": len(raw_text), "normalized_ocr_symbol_count": len(normalized), "normalization": "Whitespace removal and OCR-only O->0, S->5, Cyrillic ZE->3, remove one punctuation dot; canonical target unchanged. Valid-hex differences retained for visual review.", "canonical_lines": can_lines, "raw_ocr_lines": ocr_lines, "remaining_differences": changes}
print(json.dumps(result, indent=2, ensure_ascii=False))

#!/usr/bin/env python3
"""Internal verification of the frozen image-only transcription."""
import hashlib,json,re,struct
from pathlib import Path
HERE=Path(__file__).resolve().parent
IMAGE=HERE.parents[3]/"lavender/src/assets/revelations_7.png"
IMAGE_SHA="36a1883ede6abadcf4d4420f26484ca81134f3b62fe0ac7521352c682bf0b3b7"
def sha(p):return hashlib.sha256(p.read_bytes()).hexdigest()
def main():
 assert sha(IMAGE)==IMAGE_SHA
 data=IMAGE.read_bytes();assert data[:8]==b"\x89PNG\r\n\x1a\n";width,height=struct.unpack(">II",data[16:24]);assert (width,height)==(981,412)
 obj=json.loads((HERE/"transcription.json").read_text());lines=(HERE/"transcription.txt").read_text().splitlines();assert len(lines)==16
 assert obj["identity"]=="ASTRA" and obj["canonical_or_prior_transcription_consulted"] is False and obj["uncertainties"]==[]
 assert [x["groups"] for x in obj["lines"]]==[x.split() for x in lines]
 counts=[len(x.replace(" ","")) for x in lines];assert counts==obj["line_glyph_counts"]==[67]+[70]*10+[65]+[70]*3+[50]
 joined="".join(x.replace(" ","") for x in lines);assert len(joined)==obj["total_visible_hex_glyphs"]==1092 and re.fullmatch("[0-9A-F]+",joined)
 assert hashlib.sha256(joined.encode()).hexdigest()==obj["joined_visible_hex_sha256"]
 print(json.dumps({"ok":True,"identity":"ASTRA","basis":"image-only transcription internal integrity; no canonical comparison","lines":16,"visible_hex_glyphs":1092,"joined_sha256":obj["joined_visible_hex_sha256"],"uncertainty_count":0},indent=2,sort_keys=True))
if __name__=="__main__":main()

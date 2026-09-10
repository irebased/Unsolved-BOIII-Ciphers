#!/usr/bin/env python3
"""ASTRA synthetic-only controls for limb-local decimal -> checkerboard."""
from pathlib import Path
import argparse, hashlib, importlib.util, itertools, json, random, sys
HERE=Path(__file__).resolve().parent; ROOT=HERE.parents[3]
MODEL=HERE/'model.py'; DEFAULT=HERE/'controls.json'
PINS={
 'coverage_REPORT.md':'2a5d20ae6eee4d2ddf2a8ba9ef7bd208e43f0f372fac29e5305f3bdf6918c57e',
 'rev3_replay.py':'f756922e180899de43dfbde5eef12fc45a3d8db32ccb9eec71806626fd370414',
 'rev3_mdx':'0185f674db09dfe542de8ecf2880cf83690cc8331001ebfefa65ddc4f965a243'}
DEPS={'coverage_REPORT.md':ROOT/'research/rev7-20260909-codex/coverage/REPORT.md','rev3_replay.py':ROOT/'research/rev7-20260909-codex/coverage/rev3_classical_scope/replay_original.py','rev3_mdx':ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev3.mdx'}

def sha(p): return hashlib.sha256(p.read_bytes()).hexdigest()
def shab(b): return hashlib.sha256(b).hexdigest()
def load():
 s=importlib.util.spec_from_file_location('limb32_model',MODEL);m=importlib.util.module_from_spec(s);sys.modules[s.name]=m;s.loader.exec_module(m);return m

def oracle_serialize(data,endian,order,direction):
 chunks=[data[i:i+4] for i in range(0,len(data),4)]
 if order=='reverse': chunks=chunks[::-1]
 out=''
 for c in chunks:
  width={1:3,2:5,3:8,4:10}[len(c)]
  value=sum(x << (8*(len(c)-1-j)) for j,x in enumerate(c)) if endian=='big' else sum(x << (8*j) for j,x in enumerate(c))
  out += str(value).rjust(width,'0')
 return out if direction=='forward' else out[::-1]

def oracle_tokens(digits,headers):
 out=[];i=0;h=set(map(str,headers))
 while i<len(digits):
  if digits[i] in h:
   if i+1==len(digits): return None
   out.append(digits[i:i+2]);i+=2
  else:out.append(digits[i]);i+=1
 return out

def build():
 m=load()
 assert all(sha(DEPS[k])==v for k,v in PINS.items())
 rng=random.Random(20260910); serializer=[]
 for n in [1,2,3,4,5,6,7,8,10,14,31]:
  data=bytes(rng.randrange(256) for _ in range(n))
  for endian,order,direction in itertools.product(m.ENDIANS,m.ORDERS,m.DIRECTIONS):
   got=m.serialize(data,endian,order,direction); exp=oracle_serialize(data,endian,order,direction)
   assert got==exp and m.deserialize(got,n,endian,order,direction)==data
   serializer.append({'n':n,'endian':endian,'limb_order':order,'digit_direction':direction,'digits':got,'digits_sha256':shab(got.encode())})
 parser=[]
 fixtures=['','0','3','37','370','0123456789','30313233343536373839','777','909090','123456789012345']
 for headers in m.all_headers():
  for digits in fixtures:
   got=m.parse_tokens(digits,headers);exp=oracle_tokens(digits,headers);assert got==exp
   parser.append({'headers':list(headers),'digits':digits,'tokens':got})
 assert len(m.all_headers())==45
 # Full representation + fixed Rev3 checkerboard plant. 15 digits are one u32 and one u16 limb.
 plain='HLIMBHHH'; digits=m.encode_fixed(plain); assert digits=='307032231303030' and len(digits)==15
 plants=[]
 for endian,order,direction in itertools.product(m.ENDIANS,m.ORDERS,m.DIRECTIONS):
  raw=m.deserialize(digits,6,endian,order,direction)
  assert m.serialize(raw,endian,order,direction)==digits and m.decode_fixed(digits)==plain
  for orient in m.ORIENTATIONS:
   # Construct displayed hex by exploiting that every declared orientation is an involution.
   displayed=m.orient_hex(raw.hex(),orient); recovered=bytes.fromhex(m.orient_hex(displayed,orient))
   assert recovered==raw
   assert m.decode_fixed(m.serialize(recovered,endian,order,direction))==plain
   plants.append({'orientation':orient,'endian':endian,'limb_order':order,'digit_direction':direction,'displayed_hex':displayed,'oriented_bytes_sha256':shab(recovered),'recovered_plaintext':plain})
 # Capacity semantics include 27/28 tokens; fixed Rev3 board has only 26 populated cells.
 cap_digits=''.join(m.board_codes((3,7)))
 cap=m.parse_tokens(cap_digits,(3,7));assert len(set(cap))==28
 assert m.decode_fixed(cap_digits) is None
 # A dangling header is rejected, while a non-header final digit is complete.
 assert m.parse_tokens('123',(3,7)) is None and m.parse_tokens('124',(3,7)) is not None
 out={'identity':'ASTRA','target_evaluated':False,'rev7_read':False,'model':'fixed-width independent unsigned limbs -> ordinary two-header straddling checkerboard','target_proposal':{'input_bytes':546,'full_limbs':136,'tail_bytes':2,'full_limb_decimal_width':10,'tail_decimal_width':5,'decimal_length':1365,'orientations':list(m.ORIENTATIONS),'endianness':list(m.ENDIANS),'limb_orders':list(m.ORDERS),'digit_directions':list(m.DIRECTIONS),'serializers':32,'header_pairs':45,'cells':1440,'fixed_rev3_board':{'headers':[3,7],'alphabet':m.REV3_KEY},'capacity_alphabet':'up to 28 injective output symbols; fixed Rev3 uses 26 and leaves two cells blank'},'source_pins':PINS,'serializer_cases':serializer,'parser_cases':parser,'full_chain_plants':plants,'capacity_control':{'digits':cap_digits,'distinct_tokens':28,'fixed_rev3_rejects_blank_cells':True},'assertions':{'source_pins_match':True,'independent_serializer_cases':len(serializer),'independent_parser_cases':len(parser),'all_32_orientation_serializer_plants':len(plants)==32,'u32_u16_plant_exact':True,'capacity_28_explicit':True,'dangling_header_rejected':True},'limitations':['The 32-bit limb framing and 16-bit final tail are a bounded representation hypothesis, not a recovered historical wrapper.','A complete parse with <=28 cells is structural compatibility only.','A fixed Rev3-board output or language score cannot exclude an unknown symbol assignment.','No Rev7 bytes are read or evaluated by these controls.'],'model_sha256':sha(MODEL),'controls_source_sha256':sha(Path(__file__))}
 return out

def main():
 ap=argparse.ArgumentParser();ap.add_argument('--generate',type=Path);a=ap.parse_args();out=build()
 if a.generate:
  if a.generate.exists():raise SystemExit('refusing existing output')
  a.generate.write_text(json.dumps(out,indent=2,sort_keys=True)+'\n')
  print(json.dumps({'written':str(a.generate),'sha256':sha(a.generate)}))
 else:
  saved=json.loads(DEFAULT.read_text()); assert saved==out
  print(json.dumps({'identity':'ASTRA','status':'PASS','ledger_sha256':sha(DEFAULT),'cases':len(out['serializer_cases'])+len(out['parser_cases'])+len(out['full_chain_plants'])}))
if __name__=='__main__':main()

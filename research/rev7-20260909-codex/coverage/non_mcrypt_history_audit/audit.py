#!/usr/bin/env python3
"""ASTRA read-only inventory of recorded non-libmcrypt and XXTEA history."""
from __future__ import annotations
import argparse,hashlib,json,re
from pathlib import Path
IDENTITY='ASTRA';HERE=Path(__file__).resolve().parent;ROOT=HERE.parents[3]
FILES={
 'latest_comments':(ROOT/'research/rev7-20260909-codex/latest-comments.json','493c657cb1fd8c33ddf028734464953b1847afcee84ba93dc528dbf926d09597'),
 'notebook_snapshot':(ROOT/'research/rev7-20260909-codex/notebook-snapshot.json','ad67d420644b203a8f952d84f93d4755578c079aa9b98952cab8a73ccc3461ab'),
 'coverage_report':(ROOT/'research/rev7-20260909-codex/coverage/REPORT.md','2a5d20ae6eee4d2ddf2a8ba9ef7bd208e43f0f372fac29e5305f3bdf6918c57e'),
 'primary_routes':(ROOT/'research/rev7-20260909-codex/sources/primary_routes.md','ee9f2b9cf32a0724c9bab5c421e40c498a58ae0aa78924d9a3c7651a1ad865c5'),
 'session_state_excerpt':(HERE/'session_state_excerpt.txt','f2344db7549e5f523316896f87dca6dfb1a7211ba9bc364de091eb89b7972592'),
 'rev12_mdx':(ROOT/'lavender/src/content/docs/ciphers/bo3/rev/rev12.mdx','c8c1ea91d1b311c82f2fab26f0477b902746323dbeda5fdf7800d391ec115039'),
 'revelations_data':(ROOT/'lavender/src/data/ciphers/revelations.json','68022b89d05deb080b5097d83517fea3427bcbf3364c1ac79cdf1a5af7e3550e'),
 'tg4_mdx':(HERE/'capture/local_tg4.mdx','860b4d4b9e9d552c0cf58a48343a42a0f17a50b1666626baf596bb9a2797a056'),
 'the_giant_data':(HERE/'capture/local_the_giant.json','2a9e29a12db1784777397e59d8b88bb90b00b39ab7e82a67e7ba8c617ef26552')}
def sha(p):return hashlib.sha256(Path(p).read_bytes()).hexdigest()
def comment(d,cid):
 rows=[x for x in d['comments'] if str(x.get('id'))==str(cid)];assert len(rows)==1;return rows[0]['body']
def phrase(text,value):assert value in text,value;return value
def build():
 for name,(path,want) in FILES.items():assert sha(path)==want,(name,sha(path),want)
 d=json.loads(FILES['latest_comments'][0].read_text());inventory=comment(d,5600941685);bugs=comment(d,5600942737);sources=comment(d,5600940601)
 phrase(inventory,'Exhaustive four-consecutive-hex insertion grids for NUL-padded `Zombies` and `TheGiant`')
 phrase(inventory,'Same 286,523,392 combined repair parameters checked for specified complete compressed members')
 phrase(bugs,'148,291 generated representations: zero nonidentity survivors')
 phrase(bugs,'Twenty-two literal ASCII-hex cases were unchanged by the inverse')
 phrase(bugs,'complete scans of all 2^32 effective keys in each of two direct ciphertext orientations')
 phrase(inventory,'RC4Drop, Rabbit/RabbitLegacy, CipherSaber, CryptoJS and Veness wrappers')
 phrase(inventory,'Specified OpenPGP, RNCryptor, Defuse, Halite, JavaScrypt and compression branches')
 phrase(sources,'TheGiant/XXTEA prompted additional bounded tests')
 rev12=FILES['rev12_mdx'][0].read_text();phrase(rev12,'Step 2: XTEA (CFB) decrypt with key "Zombies"');phrase(rev12,'30303030303030303030303030303030')
 records=json.loads(FILES['revelations_data'][0].read_text());r12=next(x for x in records if x['number']==12);assert any(x.get('method')=='XTEA' for x in r12['solution']['steps'])
 tg4=FILES['tg4_mdx'][0].read_text();phrase(tg4,'This is the only remaining unsolved cipher');tg=next(x for x in json.loads(FILES['the_giant_data'][0].read_text()) if x['number']==4);assert tg['solved'] is False and tg['solution'] is None
 state=FILES['session_state_excerpt'][0].read_text();phrase(state,'solveddueI/l/O/0transcriptandXXTEATheGiantnullpad')
 # The old public plan explicitly includes XTEA among libmcrypt algorithms.
 fable=[x['body'] for x in d['comments'] if 'R7-20260909-fable-001' in x.get('body','')];assert len(fable)==1 and 'loki97, xtea, 3-way' in fable[0]
 # Lossless named-term inventory for the claimed untested families in the exact issue snapshot.
 term_inventory={}
 for term in ('TEA','RC5','RC6','IDEA','Camellia','SEED','ARIA'):
  pattern=re.compile(r'(?i)(?<![A-Za-z])'+term+r'(?![A-Za-z])');hits=[]
  for c in d['comments']:
   for line_no,line in enumerate(c.get('body','').splitlines(),1):
    if pattern.search(line):hits.append({'comment_id':c['id'],'body_line':line_no,'text':line.strip()})
  term_inventory[term]=hits
 assert all(not term_inventory[x] for x in ('TEA','RC5','RC6','IDEA','Camellia','ARIA'))
 assert {x['comment_id'] for x in term_inventory['SEED']}=={5608639180,5608864204} and all('seed' in x['text'].lower() for x in term_inventory['SEED'])
 return {'identity':IDENTITY,'target_evaluated':False,'new_crypto_run':False,'review_boundary':'pinned local issue snapshot and named repository/source records; absence means no match in this reviewed corpus, not no private/community work','source_hashes':{k:v for k,(_p,v) in FILES.items()}|{'audit.py':sha(Path(__file__))},'named_term_inventory':{'corpus':'all body lines in pinned latest-comments.json','matching_rule':'case-insensitive standalone ASCII word','matches':term_inventory,'interpretation':'SEED matches are PRNG/CLI seed metadata, not cipher-family target experiments; all other named terms have zero raw-text matches'},'findings':[
 {'family':'XXTEA fixed wrapper/repair hypotheses','prior_coverage':True,'evidence':'issue comment 5600941685','scope':'four-consecutive-hex insertion grids; NUL-padded Zombies and TheGiant; fixed endianness/round/framing assumptions','recorded_count':'286,523,392 combined repair parameters; compressed recognition revisits same decryptions','evidence_level':'retained summary only; original target source/ledger unavailable in this audited package and not re-executed','status':'no validated framing/readability result','limit':'does not exclude XXTEA generally or other framing/key conventions'},
 {'family':'Chris Veness XXTEA serialization bug','prior_coverage':True,'evidence':'issue comment 5600942737 and coverage/REPORT.md','scope':'inverse of historical UTF-8-expanded ciphertext serialization','recorded_count':'148,291 representations; 22 identity ASCII-hex cases separately decrypted','evidence_level':'retained summary only; original target source/ledger unavailable in this audited package and not re-executed','status':'zero nonidentity survivors; identity cases no plaintext','limit':'one wrapper serialization, not general XXTEA'},
 {'family':'CryptoJS Rabbit password-wrapper weakness','prior_coverage':True,'evidence':'issue comment 5600942737','scope':'complete 2^32 effective keys, two direct orientations, first eight bytes as IV, exact string API','status':'no valid 64-byte UTF-8 prefix','evidence_level':'retained summary only; original target source/ledger unavailable in this audited package and not re-executed','limit':'specific wrapper/framing; not Rabbit generally'},
 {'family':'other source-specific non-libmcrypt wrappers/envelopes','prior_coverage':True,'evidence':'issue comment 5600941685/5600942737','scope':'RC4Drop, RabbitLegacy, CipherSaber, CryptoJS/Veness wrappers; specified OpenPGP/RNCryptor/Defuse/Halite/JavaScrypt envelopes','status':'finite settings/corpora recorded without a validated layer','evidence_level':'retained inventory summary; individual original run artifacts not re-executed here','limit':'not blanket exclusions of underlying algorithms'},
 {'family':'XTEA','prior_coverage':True,'evidence':'FABLE001 issue plan and local Rev12 solved record','scope':'included in the recorded libmcrypt sweep; independently author-documented in Rev12 as XTEA-CFB with Zombies and ASCII-zero 16-byte IV','status':'not a non-libmcrypt gap','limit':'XTEA is distinct from XXTEA'},
 {'family':'TEA, RC5, RC6, IDEA, Camellia, SEED, ARIA','prior_coverage':False,'evidence':'mechanical standalone-term inventory over every body line in pinned issue snapshot, followed by manual classification of its two SEED matches as PRNG metadata; manual review of pinned coverage summary found no named target experiment','scope':None,'status':'no target experiment found in reviewed corpus; raw-text absence is exact for TEA/RC5/RC6/IDEA/Camellia/ARIA, while SEED has only generic PRNG metadata matches','limit':'not proof of global absence; current FABLE work after the snapshot is outside this history claim'}],
 'author_corpus':{'rev12_local_primary_record':{'method':'XTEA-CFB','key':'Zombies','iv_hex':'30303030303030303030303030303030','mdx':'lavender/src/content/docs/ciphers/bo3/rev/rev12.mdx'},'the_giant_4':{'current_solve_method':'XXTEA with NUL-padded TheGiant, recorded in linked solver report/session source note','solver_report_url':'https://www.reddit.com/r/CODZombies/comments/1w9e5ib/solved_thegiant_cipher_solved_after_3958_days/','local_repository_status':'stale: tg4.mdx and the_giant.json still say unsolved and contain no solution','provenance_class':'current external solver report retained by project; not established by the stale local MDX'}},
 'conclusion':'A new XXTEA sweep may cover additional framings/keys, but it must be compared against the recorded repair and Veness-serialization grids. The blanket claim that XXTEA was never tried conflicts with the pinned history. No prior named target coverage was found here for TEA, RC5, RC6, IDEA, Camellia, SEED, or ARIA.'}
def main():
 ap=argparse.ArgumentParser();ap.add_argument('--regenerate',type=Path);a=ap.parse_args();got=build();out=HERE/'audit.json'
 if a.regenerate:
  if a.regenerate.exists():raise SystemExit('refusing existing output')
  a.regenerate.write_text(json.dumps(got,sort_keys=True,indent=2)+'\n');print(json.dumps({'identity':IDENTITY,'output':str(a.regenerate),'sha256':sha(a.regenerate),'findings':len(got['findings'])},sort_keys=True));return
 assert json.loads(out.read_text())==got;print(json.dumps({'identity':IDENTITY,'verified':True,'ledger_sha256':sha(out),'target_evaluated':False},sort_keys=True))
if __name__=='__main__':main()

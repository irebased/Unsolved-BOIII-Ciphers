#!/usr/bin/env python3
"""ASTRA: bounded actual-RA synthetic codec witnesses; no Rev7 ciphertext."""
import argparse, hashlib, json, re, subprocess, tempfile
from pathlib import Path
HERE = Path(__file__).resolve().parent
WORKTREE = HERE.parents[3]
RA_HOME = HERE.parent / 'ra_prefix_inventory'
BINARY = RA_HOME / 'build/target/release/ra'
DATA = RA_HOME / 'source/ra/data'
BINARY_SHA = '7908ab34a2f396f6084c56e1c8066eb5400df7498ee0f0ebdee88c3d52f899b1'
LEDGER = HERE / 'runtime_witnesses.json'
def sha(b): return hashlib.sha256(b).hexdigest()
def cases():
    # Explicit outputs; these are witnesses, not a reimplementation of the decoders.
    return [
      ('unpadded_base64_546', 'b64decode', b'A'*546, b'\0'*409),
      ('filtered_base64_ascii', 'b64decode', b'!!QUJD??', b'ABC'),
      ('filtered_base64_utf8', 'b64decode', 'Q\u00e9UJD'.encode(), b'ABC'),
      ('base64_noncanonical_tail', 'b64decode', b'AB', None),
      ('filtered_odd_hex', 'hexdecode', b'GG41 zz4', b'A'),
      ('filtered_hex_utf8', 'hexdecode', '4\u00e91'.encode(), b'A'),
      ('variable_width_decimal', 'decimaldecode', b'065 255\n0', bytes([65,255,0])),
      ('decimal_546', 'decimaldecode', b'0 '*272+b'00', b'\0'*273),
      ('octal_546', 'octaldecode', b'0 '*272+b'00', b'\0'*273),
      ('decimal_leading_plus', 'decimaldecode', b'+1', b'\x01'),
      ('decimal_nbsp_rejected', 'decimaldecode', '65\u00a066'.encode(), None),
      ('decimal_invalid_utf8_rejected', 'decimaldecode', b'65 \xff', None),
    ]
def parse_output(stdout):
    match = re.search(r'\noutput \((\d+) bytes\):\n([0-9a-fA-F]*)\n\Z', stdout)
    assert match, repr(stdout)
    encoded = match.group(2)
    assert int(match.group(1)) == len(encoded)
    return bytes.fromhex(encoded)
def validate(records):
    assert len(records) == len(cases())
    for row, (name, node, data, expected) in zip(records, cases()):
        assert (row['name'],row['node'],row['input_hex']) == (name,node,data.hex())
        assert row['input_length'] == len(data)
        assert row['input_sha256'] == sha(data)
        assert row['command'][2] == node+' | hexencode'
        assert row['command'][1] == 'run'
        assert row['command'][-2:] == ['--display','bytes']
        if expected is None:
            assert row['returncode'] != 0
            assert row['stderr'].startswith('Error: '+node+': ')
            assert row['decoded_hex'] is None
        else:
            assert row['returncode'] == 0, row
            actual = parse_output(row['stdout'])
            assert actual == expected, name
            assert row['decoded_hex'] == actual.hex()
            assert row['decoded_length'] == len(actual)
            assert row['decoded_sha256'] == sha(actual)
def main():
    ap=argparse.ArgumentParser()
    ap.add_argument('--run-record', action='store_true')
    args=ap.parse_args()
    assert sha(BINARY.read_bytes()) == BINARY_SHA
    script_sha=sha(Path(__file__).read_bytes())
    if args.run_record:
        assert not LEDGER.exists(), 'Refuse overwriting the execution receipt'
        rows=[]
        with tempfile.TemporaryDirectory(prefix='astra-codec-witness-') as temporary:
            for name,node,data,expected in cases():
                inp=Path(temporary)/(name+'.bin'); inp.write_bytes(data)
                command=[str(BINARY),'run',node+' | hexencode','--data',str(DATA),'--file',str(inp),'--display','bytes']
                run=subprocess.run(command,cwd=WORKTREE,capture_output=True,text=True,timeout=30)
                decoded=parse_output(run.stdout) if run.returncode==0 else None
                rows.append(dict(name=name,node=node,input_hex=data.hex(),input_length=len(data),input_sha256=sha(data),
                  command=command,returncode=run.returncode,stdout=run.stdout,stderr=run.stderr,
                  decoded_hex=None if decoded is None else decoded.hex(),
                  decoded_length=None if decoded is None else len(decoded),
                  decoded_sha256=None if decoded is None else sha(decoded)))
        validate(rows)
        result=dict(identity='ASTRA',target_evaluated=False,actual_cli_executions=len(rows),
          script_sha256=script_sha,binary_sha256=BINARY_SHA,ra_snapshot='e127b8d6c17f567b930fe67624d3ea199528b775',
          output_capture='Append hexencode to avoid lossy UTF-8 output; parse exact hexadecimal stdout.',
          scope='These finite witnesses do not claim whole-parser equivalence with the Python source-audit witness models.',records=rows)
        LEDGER.write_text(json.dumps(result,indent=2,sort_keys=True)+'\n')
    result=json.loads(LEDGER.read_text())
    assert result['script_sha256']==script_sha and result['binary_sha256']==BINARY_SHA
    assert result['identity']=='ASTRA' and result['target_evaluated'] is False
    validate(result['records'])
    print(json.dumps(dict(identity='ASTRA',status='PASS',actual_cli_executions=len(result['records']),
      executions_this_invocation=len(result['records']) if args.run_record else 0,
      ledger_sha256=sha(LEDGER.read_bytes()),witnesses=[dict(name=r['name'],accepted=r['returncode']==0,
      input_length=r['input_length'],decoded_length=r['decoded_length']) for r in result['records']]),sort_keys=True))
if __name__=='__main__':main()

#!/usr/bin/env python3
import argparse, json, subprocess, sys
from pathlib import Path

p=argparse.ArgumentParser()
p.add_argument('--cli', default='build/pvc-rotsymenc1')
p.add_argument('--vectors', default='test-vectors/official.json')
a=p.parse_args()
data=json.loads(Path(a.vectors).read_text())
for v in data['vectors']:
    cmd=[a.cli,'seal',v['enc_key'],v['mac_key'],v['nonce'],str(v['tag_bits']),v['associated_data'],v['plaintext']]
    r=subprocess.run(cmd,check=True,text=True,capture_output=True)
    got=dict(line.split('=',1) for line in r.stdout.strip().splitlines())
    if got.get('ciphertext') != v['ciphertext'] or got.get('tag') != v['tag']:
        print(f"mismatch: {v['id']}", file=sys.stderr); sys.exit(1)
    ocmd=[a.cli,'open',v['enc_key'],v['mac_key'],v['nonce'],v['associated_data'],v['ciphertext'],v['tag']]
    o=subprocess.run(ocmd,check=True,text=True,capture_output=True)
    ogot=dict(line.split('=',1) for line in o.stdout.strip().splitlines())
    if ogot.get('authentication') != 'ok' or ogot.get('plaintext') != v['plaintext']:
        print(f"open mismatch: {v['id']}", file=sys.stderr); sys.exit(1)
print(f"verified {len(data['vectors'])} PVC-RotSymEnc-1 vectors")

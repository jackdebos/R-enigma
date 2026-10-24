#!/usr/bin/env python3
"""Generate local-only recovery cases using verified texts and the public CLI."""
import argparse
import copy
import hashlib
import json
import os
from pathlib import Path
import random
import re
import string
import subprocess
import sys

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).resolve().parent / 'data'
LETTERS = string.ascii_uppercase
LENGTHS = (50, 75, 100, 150, 200)
TABLES = {
    'enigma1941': (DATA / 'enigma1941-trigram.json',
                   ROOT / 'e2e/bomm/frequencies/enigma1941-trigram.txt'),
    'leipzig': (DATA / 'leipzig/leipzig-trigram.json', DATA / 'leipzig/leipzig-trigram.txt'),
}


def configuration(rng):
    wheels = rng.sample(['I', 'II', 'III', 'IV', 'V'], 3)
    slots = [{'id': 'reflector', 'wheel': 'B', 'ring': 'A', 'position': 'A'}]
    for slot, wheel in zip(('left', 'middle', 'right'), wheels):
        slots.append({'id': slot, 'wheel': wheel,
                      'ring': rng.choice(LETTERS), 'position': rng.choice(LETTERS)})
    plugs = rng.sample(list(LETTERS), 20)
    return {'slots': slots, 'plugboard': [plugs[i:i + 2] for i in range(0, 20, 2)]}


def transform(engine, config, text):
    request = {'protocol_version': 1, 'machine': {'definition': {'kind': 'bundled', 'id': 'enigma-i'}},
               'job': {'kind': 'transform', 'direction': 'encrypt', 'text': text,
                       'configuration': config}}
    run = subprocess.run([str(engine), '--no-report', '--request', '-'],
                         input=json.dumps(request), capture_output=True, text=True, cwd=ROOT)
    if run.returncode:
        raise ValueError(f'engine exited {run.returncode}: {run.stderr.strip()}')
    ciphertext = run.stdout.strip()
    if not re.fullmatch('[A-Z]+', ciphertext) or len(ciphertext) != len(text):
        raise ValueError('engine returned invalid ciphertext or length')
    return ciphertext


def requests(case, level, table, destination):
    config = copy.deepcopy(case['configuration'])
    domains = []
    bomm_slots = [{'wheels': ['UKW-B'], 'rings': 'a', 'positions': 'a'}]
    for slot in config['slots'][1:]:
        slot.pop('position')
        domain = {'id': slot['id'], 'positions': list(LETTERS)}
        ring = slot['ring'].lower()
        if level == 'N2' and slot['id'] == 'right':
            slot.pop('ring')
            domain['rings'] = list(LETTERS)
            ring = '*'
        domains.append(domain)
        bomm_slots.append({'wheels': [slot['wheel']], 'rotating': True,
                           'rings': ring, 'positions': '*'})
    config['plugboard'] = []
    resource, frequencies = TABLES[table]
    ours = {'protocol_version': 1, 'machine': {'definition': {'kind': 'bundled', 'id': 'enigma-i'}},
            'job': {'kind': 'search', 'text': case['ciphertext'], 'configuration': config,
                    'space': {'slots': domains, 'plugboard': {'kind': 'attack',
                              'symbols': list(LETTERS), 'max_pairs': 13}},
                    'passes': ['hill_climb', 'reswapping', 'measure'],
                    'measures': ['ic', 'sinkov_trigram'],
                    'attack': {'kind': 'hill_climb', 'initial_measure': 'ic',
                               'final_measure': 'sinkov_trigram', 'switch_pairs': 7,
                               'backtrack_pairs': 5, 'start': [], 'hold': 100,
                               'reswapping': {'measure': 'sinkov_trigram'},
                               'measure': {'measure': 'sinkov_trigram'}},
                    'resources': {'sinkov_trigram': {'path': os.path.relpath(resource, destination)}}}}
    bomm = {'alphabet': LETTERS.lower(), 'ciphertext': case['ciphertext'].lower(),
            'space': {'slots': bomm_slots, 'plugboard': ''},
            'passes': [{'type': 'hill_climb', 'measure': 'ic', 'finalMeasure': 'sinkov_trigram',
                        'finalMeasureMinNumPlugs': 7, 'backtrackingMinNumPlugs': 5},
                       {'type': 'reswapping', 'measure': 'sinkov_trigram'},
                       {'type': 'measure', 'measure': 'sinkov_trigram'}],
            'frequencies': {'trigram': os.path.relpath(frequencies, ROOT)}}
    return ours, bomm


def generate(args):
    out = args.out.resolve()
    if args.out.exists() or args.out.is_symlink():
        raise ValueError('output directory already exists')
    if not out.is_relative_to(DATA.resolve()):
        raise ValueError('output must be inside e2e/recovery/data (unversioned material)')
    raw = args.plaintexts.read_bytes()
    records = json.loads(raw)
    verified = [r for r in records if r.get('verification', {}).get('passed') is True]
    if any(not isinstance(r.get('plaintext'), str) or not re.fullmatch('[A-Z]+', r['plaintext'])
           for r in verified):
        raise ValueError('verified plaintext must contain only A-Z')
    stream = 'X'.join(r['plaintext'] for r in verified)
    required = sum(LENGTHS) * 8
    if len(stream) < required:
        raise ValueError(f'need {required} verified letters; got {len(stream)}')
    rng = random.Random(args.seed)
    cases = []
    offset = 0
    for length in LENGTHS:
        for number in range(1, 9):
            config = configuration(rng)
            plaintext = stream[offset:offset + length]
            cases.append({'id': f'n{length:03d}-{number:02d}', 'length': length, 'offset': offset,
                          'plaintext': plaintext, 'configuration': config,
                          'ciphertext': transform(args.engine.resolve(), config, plaintext)})
            offset += length
    # Generate and validate all texts before creating any output; never overwrite a directory.
    out.mkdir(parents=True, exist_ok=False)
    for case in cases:
        case['requests'] = {}
        for level in ('N1', 'N2'):
            case['requests'][level] = {}
            for table in TABLES:
                directory = out / level / table
                directory.mkdir(parents=True, exist_ok=True)
                paths = {}
                for kind, request in zip(('ours', 'bomm'), requests(case, level, table, directory)):
                    path = directory / f'{case["id"]}-{kind}.json'
                    path.write_text(json.dumps(request, indent=2) + '\n')
                    paths[kind] = str(path.relative_to(out))
                case['requests'][level][table] = paths
    manifest = {'version': 1, 'seed': args.seed, 'hold': 100,
                'source_sha256': hashlib.sha256(raw).hexdigest(),
                'engine_sha256': hashlib.sha256(args.engine.read_bytes()).hexdigest(),
                'source_ids': [r['id'] for r in verified], 'stream_letters': len(stream),
                'used_letters': offset, 'cases': cases}
    (out / 'manifest.json').write_text(json.dumps(manifest, indent=2) + '\n')
    print('Generated 40 cases (4600 letters), N1/N2, two tables.')


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--plaintexts', type=Path, default=DATA / 'weierud/plaintexts.json',
                        help='verified plaintext records (default: data/weierud/plaintexts.json)')
    parser.add_argument('--out', type=Path, default=DATA / 'cases',
                        help='new directory under data/; existing output is never replaced')
    parser.add_argument('--engine', type=Path, default=ROOT / 'target/release/enigma',
                        help='already-built Enigma CLI (default: target/release/enigma)')
    parser.add_argument('--seed', type=int, default=20261024, help='key seed (default: 20261024)')
    args = parser.parse_args()
    try:
        generate(args)
    except (OSError, ValueError, TypeError, KeyError, AttributeError) as error:
        print(f'cases: {error}', file=sys.stderr)
        return 2
    return 0


if __name__ == '__main__':
    sys.exit(main())

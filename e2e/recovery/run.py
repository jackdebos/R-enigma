#!/usr/bin/env python3
"""Run one recovery configuration sequentially and summarize full-text recovery."""
import argparse
from datetime import datetime, timezone
import hashlib
import json
from pathlib import Path
import re
import subprocess
import sys
import time
import uuid

from cases import DATA, ROOT, TABLES, transform

RESULTS = Path(__file__).resolve().parent / 'results'


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def bomm_key(stdout):
    # Public boxed leaderboard: first UKW line is best, never a lower entry.
    line = next((line.strip('│ \t\r') for line in stdout.splitlines()
                 if line.strip('│ \t\r').startswith('UKW-')), '')
    match = re.fullmatch(r'UKW-B,((?:I|II|III|IV|V),){2}(?:I|II|III|IV|V) '
                         r'[a-z]{4} [a-z]{4}(?: [a-z]{2})*', line)
    if not match:
        raise ValueError('missing or invalid bomm top key')
    wheels, rings, positions, *pairs = line.upper().split()
    wheels = wheels.split(',')[1:]
    if len(set(wheels)) != 3 or len(set(''.join(pairs))) != len(''.join(pairs)):
        raise ValueError('invalid bomm wheels or plugboard')
    slots = [{'id': 'reflector', 'wheel': 'B', 'ring': rings[0], 'position': positions[0]}]
    slots.extend({'id': slot, 'wheel': wheel, 'ring': ring, 'position': position}
                 for slot, wheel, ring, position in
                 zip(('left', 'middle', 'right'), wheels, rings[1:], positions[1:]))
    return {'slots': slots, 'plugboard': [list(pair) for pair in pairs]}


def ours_plaintext(stdout):
    events = [json.loads(line) for line in stdout.splitlines()]
    if not events or events[-1].get('event') != 'done' or events[-1].get('reason') != 'completed':
        raise ValueError('search did not complete')
    results = [event for event in events if event.get('event') == 'result']
    if len(results) != 1:
        raise ValueError('expected one result event')
    best = results[0]['best']
    if best is None:  # A completed search without a candidate is a recovery miss.
        return None
    plaintext = best['plaintext']
    if not isinstance(plaintext, str):
        raise ValueError('invalid best plaintext')
    return plaintext


def execute(args):
    out = args.out.resolve()
    if args.out.exists() or args.out.is_symlink():
        raise ValueError('output directory already exists')
    if not out.is_relative_to(RESULTS.resolve()):
        raise ValueError('output must be inside e2e/recovery/results')
    if not 1 <= args.threads <= 8:
        raise ValueError('threads must be between 1 and 8')
    if args.configuration == 'bomm' and args.bomm is None:
        raise ValueError('--bomm is required for bomm')
    binary = (args.engine if args.configuration == 'ours' else args.bomm).resolve()
    manifest_path = args.manifest.resolve()
    manifest = json.loads(manifest_path.read_bytes())
    if manifest['version'] != 1 or not manifest['cases']:
        raise ValueError('expected a nonempty version 1 case manifest')
    tables = args.table or list(TABLES)
    if len(set(tables)) != len(tables):
        raise ValueError('duplicate table selection')
    jobs = []
    for case in manifest['cases']:
        if any(not isinstance(case.get(field), str) or not re.fullmatch('[A-Z]+', case[field])
               or len(case[field]) != case['length'] for field in ('plaintext', 'ciphertext')):
            raise ValueError('invalid case plaintext, ciphertext or length')
        for table in tables:
            request = (manifest_path.parent / case['requests'][args.level][table][args.configuration]).resolve()
            if not request.is_relative_to(manifest_path.parent):
                raise ValueError('request must be inside manifest directory')
            content = json.loads(request.read_bytes())
            resources = (content.get('job', {}).get('resources', {}) if args.configuration == 'ours'
                         else {k: {'path': v} for k, v in content.get('frequencies', {}).items()})
            base = request.parent if args.configuration == 'ours' else ROOT
            hashes = {name: digest((base / resource['path']).resolve())
                      for name, resource in resources.items()}
            jobs.append((case, table, request, digest(request), hashes))
    report = {'configuration': f'{args.configuration}/{args.level}', 'threads': args.threads,
              'started_at': datetime.now(timezone.utc).isoformat(),
              'manifest': str(manifest_path), 'manifest_sha256': digest(manifest_path),
              'binary': str(binary), 'binary_sha256': digest(binary),
              'replay_engine_sha256': digest(args.engine.resolve()) if args.configuration == 'bomm' else None,
              'seed': manifest.get('seed'), 'hold': manifest['hold'], 'runs': [], 'groups': []}
    out.mkdir(parents=True, exist_ok=False)
    for index, (case, table, request, request_hash, resources) in enumerate(jobs):
        command = ([str(binary), '--no-report', '--events', '-', '--threads', str(args.threads), str(request)]
                   if args.configuration == 'ours' else
                   [str(binary), '-q', '-t', str(args.threads), '-n', str(manifest['hold']), str(request)])
        record = {'case': case['id'], 'length': case['length'], 'table': table,
                  'configuration': report['configuration'], 'command': command, 'cwd': str(ROOT),
                  'request_sha256': request_hash, 'resource_sha256': resources,
                  'exit_code': None, 'success': False, 'error': None}
        start = time.monotonic()
        stdout, stderr = b'', b''
        try:
            run = subprocess.run(command, cwd=ROOT, capture_output=True)
            stdout, stderr = run.stdout, run.stderr
            record['exit_code'] = run.returncode
            if run.returncode:
                raise ValueError(f'process exited {run.returncode}')
            text = stdout.decode('utf-8')
            if args.configuration == 'ours':
                plaintext = ours_plaintext(text)
            else:
                config = bomm_key(text)
                record['best_configuration'] = config
                plaintext = transform(args.engine.resolve(), config, case['ciphertext'])
            record['success'] = plaintext == case['plaintext']
        except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
            record['error'] = str(error)
        record['wall_seconds'] = time.monotonic() - start
        (out / f'{index:04d}.stdout').write_bytes(stdout)
        (out / f'{index:04d}.stderr').write_bytes(stderr)
        (out / f'{index:04d}.json').write_text(json.dumps(record, indent=2) + '\n')
        report['runs'].append(record)
    for length in sorted({r['length'] for r in report['runs']}):
        for table in tables:
            runs = [r for r in report['runs'] if r['length'] == length and r['table'] == table]
            errors = sum(r['error'] is not None for r in runs)
            successes = sum(r['success'] for r in runs)
            report['groups'].append({'length': length, 'table': table,
                                     'configuration': report['configuration'], 'runs': len(runs),
                                     'successes': successes, 'errors': errors,
                                     'misses': len(runs) - successes - errors,
                                     'success_rate': successes / len(runs),
                                     'wall_seconds': sum(r['wall_seconds'] for r in runs)})
    (out / 'summary.json').write_text(json.dumps(report, indent=2) + '\n')
    lines = ['| Length | Table | Configuration | Runs | Successes | Misses | Errors | Rate | Seconds |',
             '| --- | --- | --- | --- | --- | --- | --- | --- | --- |']
    for group in report['groups']:
        lines.append('| {length} | {table} | {configuration} | {runs} | {successes} | {misses} | '
                     '{errors} | {success_rate:.1%} | {wall_seconds:.3f} |'.format(**group))
    (out / 'summary.md').write_text('\n'.join(lines) + '\n')
    print(f'Results: {out}')
    return int(any(r['error'] is not None for r in report['runs']))


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--manifest', type=Path, default=DATA / 'cases/manifest.json',
                        help='case manifest (default: data/cases/manifest.json)')
    parser.add_argument('--out', type=Path, default=RESULTS / uuid.uuid4().hex,
                        help='new directory under results/ (default: unique run ID)')
    parser.add_argument('--configuration', choices=('ours', 'bomm'), default='ours',
                        help='one implementation per invocation (default: ours)')
    parser.add_argument('--level', choices=('N1', 'N2'), default='N1', help='default: N1')
    parser.add_argument('--table', action='append', choices=tuple(TABLES),
                        help='select table; repeat for both (default: both)')
    parser.add_argument('--threads', type=int, default=6, help='1–8 (default: 6)')
    parser.add_argument('--engine', type=Path, default=ROOT / 'target/release/enigma',
                        help='Enigma CLI for searches or full bomm-key replay')
    parser.add_argument('--bomm', type=Path, help='explicit, consented bomm executable')
    try:
        return execute(parser.parse_args())
    except (OSError, ValueError, KeyError, TypeError, AttributeError) as error:
        print(f'run: {error}', file=sys.stderr)
        return 2


if __name__ == '__main__':
    sys.exit(main())

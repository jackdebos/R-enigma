"""Recovery runner public CLI tests; all messages and executables are synthetic."""
import json
from pathlib import Path
import subprocess
import sys
import tempfile
import unittest

ROOT = Path(__file__).resolve().parents[2]
BASE = ROOT / 'e2e/recovery'
SCRIPT = BASE / 'run.py'


class RunnerCLI(unittest.TestCase):
    def setUp(self):
        (BASE / 'data').mkdir(exist_ok=True)
        (BASE / 'results').mkdir(exist_ok=True)
        self.data = tempfile.TemporaryDirectory(prefix='test-run-', dir=BASE / 'data')
        self.results = tempfile.TemporaryDirectory(prefix='test-run-', dir=BASE / 'results')
        self.addCleanup(self.data.cleanup)
        self.addCleanup(self.results.cleanup)
        self.work = Path(self.data.name)
        self.out = Path(self.results.name) / 'output'
        self.engine = self.work / 'engine'
        self.engine.write_text('#!/usr/bin/env python3\n' + '''import json, pathlib, sys
if '--request' in sys.argv:
    request = json.load(sys.stdin)
    assert request['job']['configuration']['slots'][1]['ring'] == 'F'
    assert request['job']['configuration']['slots'][3]['position'] == 'S'
    assert request['job']['configuration']['plugboard'] == [['A', 'Q']]
    print('INVENTEDMESSAGE' + ('Y' if len(request['job']['text']) == 16 else ''))
else:
    assert sys.argv[1:6] == ['--no-report', '--events', '-', '--threads', '6']
    request = json.loads(pathlib.Path(sys.argv[-1]).read_text())
    assert pathlib.Path.cwd() == pathlib.Path(request['cwd'])
    print(request['output'], end='')
    print('diagnostic', file=sys.stderr)
    sys.exit(request['exit'])
''')
        self.engine.chmod(0o755)
        self.bomm = self.work / 'bomm'
        self.bomm.write_text('#!/usr/bin/env python3\n' + '''import pathlib, sys
assert sys.argv[1:6] == ['-q', '-t', '6', '-n', '100']
assert pathlib.Path.cwd() == pathlib.Path(__file__).resolve().parents[4]
print('preview: deliberately wrong')
print('│ UKW-B,II,I,III afmt akps aq │')
print('│ UKW-B,I,II,III aaaa aaaa ab │')
''')
        self.bomm.chmod(0o755)
        resource = self.work / 'table.txt'
        resource.write_text('abc 1\n')
        cases = []
        for index, length in enumerate((15, 16)):
            paths = {}
            for level in ('N1', 'N2'):
                paths[level] = {}
                for table in ('enigma1941', 'leipzig'):
                    request = self.work / f'{index}-{level}-{table}.json'
                    output = '\n'.join(json.dumps(event) for event in [
                        {'event': 'result', 'best': {'plaintext': 'INVENTEDMESSAGE'}},
                        {'event': 'done', 'reason': 'completed'}]) + '\n'
                    request.write_text(json.dumps({'cwd': str(ROOT), 'output': output, 'exit': 0,
                        'job': {'resources': {'sinkov_trigram': {'path': resource.name}}},
                        'frequencies': {'trigram': str(resource.relative_to(ROOT))}}))
                    paths[level][table] = {'ours': request.name, 'bomm': request.name}
            cases.append({'id': f'invented-{index}', 'length': length,
                          'plaintext': 'INVENTEDMESSAGE' if index == 0 else 'INVENTEDMESSAGEX',
                          'ciphertext': 'A' * length, 'requests': paths})
        self.manifest = self.work / 'manifest.json'
        self.manifest.write_text(json.dumps({'version': 1, 'hold': 100, 'seed': 42, 'cases': cases}))

    def cli(self, *args):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), '--manifest', str(self.manifest),
                               '--out', str(self.out), '--engine', str(self.engine),
                               *map(str, args)], cwd=ROOT, capture_output=True, text=True)

    def report(self, result, errors=0):
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (1 if errors else 0, f'Results: {self.out}\n', ''))
        return json.loads((self.out / 'summary.json').read_text())

    def test_default_full_match_miss_sequential_artifacts_and_provenance(self):
        report = self.report(self.cli())
        self.assertEqual([(r['length'], r['table'], r['successes'], r['errors'], r['runs'])
                          for r in report['groups']],
                         [(n, t, int(n == 15), 0, 1) for n in (15, 16)
                          for t in ('enigma1941', 'leipzig')])
        self.assertEqual(len(report['runs']), 4)
        for index, run in enumerate(report['runs']):
            self.assertEqual(run['exit_code'], 0)
            self.assertGreaterEqual(run['wall_seconds'], 0)
            self.assertEqual(run['configuration'], 'ours/N1')
            self.assertEqual(len(run['request_sha256']), 64)
            self.assertEqual(len(run['resource_sha256']['sinkov_trigram']), 64)
            self.assertEqual((self.out / f'{index:04d}.stderr').read_text(), 'diagnostic\n')
            self.assertIn('completed', (self.out / f'{index:04d}.stdout').read_text())
        self.assertEqual(len(report['binary_sha256']), 64)
        self.assertEqual(len(report['manifest_sha256']), 64)
        self.assertIn('| Length |', (self.out / 'summary.md').read_text())

    def test_errors_not_success_even_with_matching_plaintext(self):
        for mode in ('cancelled', 'missing', 'malformed', 'exit'):
            with self.subTest(mode=mode):
                for request in self.work.glob('0-N1-*.json'):
                    record = json.loads(request.read_text())
                    events = [{'event': 'result', 'best': {'plaintext': 'INVENTEDMESSAGE'}}]
                    if mode != 'missing':
                        events.append({'event': 'done', 'reason': 'cancelled' if mode == 'cancelled' else 'completed'})
                    record['output'] = 'broken\n' if mode == 'malformed' else '\n'.join(map(json.dumps, events)) + '\n'
                    record['exit'] = 7 if mode == 'exit' else 0
                    request.write_text(json.dumps(record))
                self.out = Path(self.results.name) / mode
                report = self.report(self.cli('--table', 'enigma1941'), errors=1)
                self.assertEqual(report['groups'][0]['errors'], 1)
                self.assertEqual(report['groups'][0]['successes'], 0)
                self.assertEqual(report['runs'][0]['exit_code'], 7 if mode == 'exit' else 0)
                self.assertTrue(report['runs'][0]['error'])
                record = json.loads((self.work / '0-N1-enigma1941.json').read_text())
                self.assertEqual((self.out / '0000.stdout').read_text(), record['output'])
                self.assertEqual((self.out / '0000.stderr').read_text(), 'diagnostic\n')

    def test_bomm_top_key_replay_n2_and_selected_table(self):
        report = self.report(self.cli('--configuration', 'bomm', '--bomm', self.bomm,
                                      '--level', 'N2', '--table', 'leipzig'))
        self.assertEqual(len(report['runs']), 2)
        self.assertEqual([r['success'] for r in report['runs']], [True, False])
        self.assertTrue(all(r['configuration'] == 'bomm/N2' for r in report['runs']))
        self.assertTrue(all(r['table'] == 'leipzig' for r in report['runs']))

    def test_bomm_invalid_top_key_and_process_error_are_not_success(self):
        for mode, output, code in [('key', '│ UKW-B,I,II,III ??? │\n', 0),
                                   ('exit', 'preview only\n', 3)]:
            with self.subTest(mode=mode):
                self.bomm.write_text('#!/usr/bin/env python3\nimport sys\n' +
                                     f'print({output!r}, end="")\nsys.exit({code})\n')
                self.out = Path(self.results.name) / mode
                report = self.report(self.cli('--configuration', 'bomm', '--bomm', self.bomm,
                                              '--table', 'leipzig'), errors=2)
                self.assertTrue(all(r['error'] and not r['success'] for r in report['runs']))
                self.assertEqual((self.out / '0000.stdout').read_text(), output)
                self.assertEqual((self.out / '0000.stderr').read_bytes(), b'')
                self.assertEqual(report['runs'][0]['exit_code'], code)

    def test_invalid_case_lengths_rejected_before_output(self):
        manifest = json.loads(self.manifest.read_text())
        manifest['cases'][0]['length'] += 1
        self.manifest.write_text(json.dumps(manifest))
        before = self.manifest.read_bytes()
        result = self.cli()
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, '', 'run: invalid case plaintext, ciphertext or length\n'))
        self.assertFalse(self.out.exists())
        self.assertEqual(self.manifest.read_bytes(), before)

    def test_rejections_do_not_mutate_inputs_or_existing_results(self):
        self.out.mkdir()
        sentinel = self.out / 'sentinel'
        sentinel.write_text('keep')
        before = {p.name: p.read_bytes() for p in self.work.iterdir()}
        result = self.cli()
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, '', 'run: output directory already exists\n'))
        self.assertEqual(list(self.out.iterdir()), [sentinel])
        self.assertEqual(sentinel.read_text(), 'keep')
        self.out = Path(self.results.name) / 'invalid'
        for args, message in [(('--threads', '9'), 'threads must be between 1 and 8'),
                              (('--threads', '0'), 'threads must be between 1 and 8'),
                              (('--configuration', 'bomm'), '--bomm is required for bomm'),
                              (('--table', 'leipzig', '--table', 'leipzig'), 'duplicate table selection')]:
            result = self.cli(*args)
            self.assertEqual((result.returncode, result.stdout, result.stderr),
                             (2, '', f'run: {message}\n'))
            self.assertFalse(self.out.exists())
        self.assertEqual(before, {p.name: p.read_bytes() for p in self.work.iterdir()})


if __name__ == '__main__':
    unittest.main()

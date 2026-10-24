"""Public generator tests with invented plaintexts and the real transform CLI."""
import json
from pathlib import Path
import string
import subprocess
import sys
import tempfile
import unittest

SCRIPT = Path(__file__).with_name('cases.py')
ROOT = SCRIPT.resolve().parents[2]
DATA = SCRIPT.parent / 'data'
ENGINE = ROOT / 'target/release/enigma'


class CasesCLI(unittest.TestCase):
    def setUp(self):
        DATA.mkdir(exist_ok=True)
        self.tmp = tempfile.TemporaryDirectory(prefix='test-cases-', dir=DATA)
        self.addCleanup(self.tmp.cleanup)
        self.work = Path(self.tmp.name).resolve()
        self.source = self.work / 'source.json'
        self.good = ''.join(string.ascii_uppercase[(i * i + i // 17) % 26]
                            for i in range(4700))
        self.source.write_text(json.dumps([
            {'id': 'rejected', 'plaintext': 'Z' * 5000, 'verification': {'passed': False}},
            {'id': 'invented-a', 'plaintext': self.good[:2300], 'verification': {'passed': True}},
            {'id': 'invented-b', 'plaintext': self.good[2300:], 'verification': {'passed': True}},
        ]))

    def run_cli(self, out, *args):
        return subprocess.run([sys.executable, '-B', str(SCRIPT), '--plaintexts', str(self.source),
                               '--out', str(out), *map(str, args)],
                              capture_output=True, text=True, cwd=ROOT)

    def test_segments_seeded_keys_requests_and_full_roundtrip(self):
        out = self.work / 'cases'
        result = self.run_cli(out)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (0, 'Generated 40 cases (4600 letters), N1/N2, two tables.\n', ''))
        manifest = json.loads((out / 'manifest.json').read_text())
        self.assertEqual(manifest['source_ids'], ['invented-a', 'invented-b'])
        stream = self.good[:2300] + 'X' + self.good[2300:]
        offset = 0
        for index, case in enumerate(manifest['cases']):
            length = (50, 75, 100, 150, 200)[index // 8]
            self.assertEqual((case['length'], case['offset'], case['plaintext']),
                             (length, offset, stream[offset:offset + length]))
            offset += length
            config = case['configuration']
            slots = config['slots']
            self.assertEqual(slots[0], {'id': 'reflector', 'wheel': 'B', 'ring': 'A', 'position': 'A'})
            self.assertEqual(len({s['wheel'] for s in slots[1:]}), 3)
            self.assertTrue({s['wheel'] for s in slots[1:]} <= {'I', 'II', 'III', 'IV', 'V'})
            self.assertEqual(len(config['plugboard']), 10)
            self.assertEqual(len(set(sum(config['plugboard'], []))), 20)
            replay = {'protocol_version': 1, 'machine': {'definition': {'kind': 'bundled', 'id': 'enigma-i'}},
                      'job': {'kind': 'transform', 'direction': 'decrypt', 'text': case['ciphertext'],
                              'configuration': config}}
            decoded = subprocess.run([str(ENGINE), '--no-report', '--request', '-'],
                                     input=json.dumps(replay), capture_output=True, text=True)
            self.assertEqual((decoded.returncode, decoded.stdout, decoded.stderr),
                             (0, case['plaintext'] + '\n', ''))
            for level in ('N1', 'N2'):
                for table, paths in case['requests'][level].items():
                    request_path = out / paths['ours']
                    job = json.loads(request_path.read_text())['job']
                    self.assertEqual(job['text'], case['ciphertext'])
                    self.assertEqual(job['attack']['hold'], 100)
                    self.assertEqual(job['passes'], ['hill_climb', 'reswapping', 'measure'])
                    self.assertEqual(job['configuration']['plugboard'], [])
                    self.assertEqual(job['space']['plugboard']['max_pairs'], 13)
                    self.assertEqual(len(job['space']['slots']), 3)
                    count = 1
                    for slot in job['space']['slots']:
                        self.assertEqual(slot['positions'], list(string.ascii_uppercase))
                        count *= len(slot['positions']) * len(slot.get('rings', ['A']))
                    self.assertEqual(count, 17576 if level == 'N1' else 456976)
                    right = job['configuration']['slots'][-1]
                    self.assertEqual('ring' in right, level == 'N1')
                    self.assertTrue(all('position' not in s for s in job['configuration']['slots'][1:]))
                    resource = (request_path.parent / job['resources']['sinkov_trigram']['path']).resolve()
                    self.assertEqual(resource.name, table + '-trigram.json')
                    query = json.loads((out / paths['bomm']).read_text())
                    self.assertEqual(query['ciphertext'], case['ciphertext'].lower())
                    self.assertEqual(query['space']['plugboard'], '')
                    for s in query['space']['slots'][1:]:
                        self.assertEqual(s['positions'], '*')
                    self.assertEqual(query['space']['slots'][-1]['rings'],
                                     '*' if level == 'N2' else slots[-1]['ring'].lower())
                    self.assertTrue(query['frequencies']['trigram'].endswith(table + '-trigram.txt'))
        self.assertEqual(offset, 4600)
        again = self.work / 'again'
        self.assertEqual(self.run_cli(again).returncode, 0)
        self.assertEqual((out / 'manifest.json').read_bytes(), (again / 'manifest.json').read_bytes())
        different = self.work / 'different'
        self.assertEqual(self.run_cli(different, '--seed', 1).returncode, 0)
        other = json.loads((different / 'manifest.json').read_text())
        self.assertNotEqual(manifest['cases'][0]['configuration'], other['cases'][0]['configuration'])

    def test_rejected_inputs_leave_existing_data_unchanged(self):
        for records, message in [
            ([], 'need 4600 verified letters; got 0'),
            ([{'id': 'bad', 'plaintext': 'abc', 'verification': {'passed': True}}],
             'verified plaintext must contain only A-Z'),
        ]:
            with self.subTest(message=message):
                self.source.write_text(json.dumps(records))
                before = self.source.read_bytes()
                out = self.work / 'invalid'
                result = self.run_cli(out)
                self.assertEqual((result.returncode, result.stdout, result.stderr),
                                 (2, '', 'cases: ' + message + '\n'))
                self.assertFalse(out.exists())
                self.assertEqual(self.source.read_bytes(), before)
        result = self.run_cli(self.work)
        self.assertEqual((result.returncode, result.stdout, result.stderr),
                         (2, '', 'cases: output directory already exists\n'))


if __name__ == '__main__':
    unittest.main()

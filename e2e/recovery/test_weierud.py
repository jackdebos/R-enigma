"""Only invented examples: no source keys, ciphertexts or plaintexts."""
import contextlib
import importlib.util
import io
import json
from pathlib import Path
import subprocess
import sys
import unittest
from unittest.mock import patch

SCRIPT = Path(__file__).with_name('weierud.py')
SPEC = importlib.util.spec_from_file_location('weierud', SCRIPT)
w = importlib.util.module_from_spec(SPEC)
if SCRIPT.exists():
    SPEC.loader.exec_module(w)

KEY = 'B123 abc XYZ AB CD EF GH IJ KL MN OP QR ST'
DAILY = 'B123 abc AB CD EF GH IJ KL MN OP QR ST'
HTML = '''<p><span style="background-color:yellow">Message No. 900 of 2 May 1941<br></span>
<span style="background-color:aqua">KEY<br></span>
<span style="color:red"><span style="background-color:yellow">ZZZZZ</span> ABCDE FG<br></span>
<span style="color:green">QWERT YU<br></span>Emended text must not be read.</p>'''.replace('KEY', KEY)
PDF = '''Enigma keys for 02.05.1941
DAILY
Special key for Nr. 901 QQQQQ:
B321 def AC BD EG FH IK JL MO NP QS RT
Message keys:
No: Part: Kenngruppe:      Indicator:      Start:     Stop:
900        ZZZZZ           AAA BBB CCC     XYZ        XZG
901        QQQQQ           AAA BBB         XYZ        XZG
902        WWWWW           AAA BBB         1)

2 May 1941 Nr. 900 ZZZZZ
Enigma message of 02.05.1941,
1200 - 12 - AAA BBB -
ZZZZZ ABCDE FG

2 May 1941 Nr. 901 QQQQQ
QQQQQ ABCDE FG

2 May 1941 Nr. 902 WWWWW
WWWWW ABCDE FG
'''.replace('DAILY', DAILY)


class WeierudTests(unittest.TestCase):
    def test_key_and_request(self):
        key = w.parse_key(KEY)
        request = w.build_request(key, 'ABCDEFG')
        self.assertEqual(request, {'protocol_version': 1,
            'machine': {'definition': {'kind': 'bundled', 'id': 'enigma-i'}},
            'job': {'kind': 'transform', 'direction': 'decrypt', 'text': 'ABCDEFG',
                'configuration': {'slots': [
                    {'id': 'reflector', 'wheel': 'B', 'ring': 'A', 'position': 'A'},
                    {'id': 'left', 'wheel': 'I', 'ring': 'A', 'position': 'X'},
                    {'id': 'middle', 'wheel': 'II', 'ring': 'B', 'position': 'Y'},
                    {'id': 'right', 'wheel': 'III', 'ring': 'C', 'position': 'Z'}],
                    'plugboard': [list(p) for p in ('AB', 'CD', 'EF', 'GH', 'IJ', 'KL', 'MN', 'OP', 'QR', 'ST')]}}})
        for bad in (KEY.replace('B123', 'B113'), KEY.replace('ST', 'SA'), KEY.replace('abc', 'ab')):
            with self.subTest(bad=bad), self.assertRaises(ValueError):
                w.parse_key(bad)

    def test_html_discriminant_and_raw_plaintext(self):
        messages = w.parse_html(HTML)
        self.assertEqual(len(messages), 1)
        m = messages[0]
        self.assertEqual((m['id'], m['date'], m['ciphertext'], m['expected']),
                         ('html-900', '1941-05-02', 'ABCDEFG', 'QWERTYU'))
        self.assertNotIn('skip', m)

    def test_html_ignores_narrative_message_mentions(self):
        self.assertEqual(len(w.parse_html('<p>Message No. 900 of 2 May 1941 is discussed here.</p>' + HTML)), 1)

    def test_pdf_form_number_takes_precedence_over_caption_typo(self):
        text = PDF.replace('2 May 1941 Nr. 901 QQQQQ\n',
                           '2 May 1941 Nr. 900 QQQQQ\nEnigma message of 02.05.1941,\nNr. 901, (QQQQQ):\n')
        self.assertEqual(w.parse_pdf(text)[1]['id'], 'pdf-901')

    def test_html_incomplete_and_unknown_symbols(self):
        for html in (HTML.replace('</p>', 'The complete ciphertext has not been recorded.</p>'),
                     HTML.replace('ABCDE FG', 'AB-DE FG')):
            self.assertIn('skip', w.parse_html(html)[0])

    def test_pdf_start_not_indicator_and_special_key(self):
        messages = w.parse_pdf(PDF)
        self.assertEqual(len(messages), 3)
        self.assertEqual(messages[0]['ciphertext'], 'ABCDEFG')
        self.assertEqual(messages[0]['key']['positions'], 'XYZ')
        self.assertEqual(messages[0]['stop'], 'XZG')
        self.assertEqual(messages[1]['key']['wheels'], ['III', 'II', 'I'])
        self.assertEqual(messages[1]['key']['rings'], 'DEF')
        self.assertIn('skip', messages[2])

    def test_pdf_multipart_and_page_break(self):
        text = PDF.replace('900        ZZZZZ', '900  1tl ZZZZZ').replace('Nr. 900 ZZZZZ', 'Nr. 900/1 ZZZZZ')
        text = text.replace('ZZZZZ ABCDE FG', 'ZZZZZ ABCDE\n\f     42\n\nFG')
        m = w.parse_pdf(text)[0]
        self.assertEqual(m['id'], 'pdf-900-1')
        self.assertEqual(m['ciphertext'], 'ABCDEFG')
        self.assertEqual(m['key']['positions'], 'XYZ')

    def test_pdf_ciphertext_does_not_consume_following_prose(self):
        for suffix in ('Enigma keys for another day', 'Notes: different layout', 'B123 abc AB CD'):
            text = PDF.replace('ZZZZZ ABCDE FG\n', 'ZZZZZ ABCDE FG\n\n' + suffix + '\n')
            with self.subTest(suffix=suffix):
                m = w.parse_pdf(text)[0]
                self.assertEqual(m['ciphertext'], 'ABCDEFG')
                self.assertEqual(m['header_cipher_length'], 7)
                self.assertTrue(m['header_length_matches'])

    def test_pdf_header_length_is_crosscheck_not_truncation(self):
        text = PDF.replace('1200 - 12 -', '1200 - 10 -')
        m = w.parse_pdf(text)[0]
        self.assertEqual(m['ciphertext'], 'ABCDEFG')
        self.assertEqual(m['header_cipher_length'], 5)
        self.assertFalse(m['header_length_matches'])

    def test_verification_reports_first_difference(self):
        m = w.parse_html(HTML)[0]
        result = w.verify(m, 'QWXRTAU', set())
        self.assertFalse(result['passed'])
        self.assertEqual(result['first_difference'], {'position': 3, 'actual': 'X', 'expected': 'E'})
        self.assertIn('raw plaintext mismatch', result['reasons'][0])

    def test_pdf_verification_preserves_header_and_stop_disagreements(self):
        m = w.parse_pdf(PDF)[0]
        m['stop'] = w.end_positions(m['key'], 7)
        trigrams = {'ABC', 'BCD', 'CDE', 'DEF', 'EFG'}
        result = w.verify(m, 'ABCDEFG', trigrams)
        self.assertTrue(result['passed'])
        self.assertEqual(result['reasons'], [])
        m['header_cipher_length'] = 5
        m['header_length_matches'] = False
        m['stop'] = w.end_positions(m['key'], 5)
        result = w.verify(m, 'ABCDEFG', trigrams)
        self.assertFalse(result['passed'])
        self.assertIn('header expects 5 cipher letters but extracted complete groups contain 7',
                      ' '.join(result['reasons']))
        self.assertEqual(result['extracted_cipher_length'], 7)

    def test_pdf_header_only_disagreement_fails(self):
        m = w.parse_pdf(PDF)[0]
        m['stop'] = w.end_positions(m['key'], 7)
        m['header_cipher_length'] = 5
        m['header_length_matches'] = False
        trigrams = {'ABC', 'BCD', 'CDE', 'DEF', 'EFG'}
        result = w.verify(m, 'ABCDEFG', trigrams)
        self.assertTrue(result['stop_matches'])
        self.assertFalse(result['passed'])
        self.assertEqual(result['reasons'], [
            'header expects 5 cipher letters but extracted complete groups contain 7; '
            'no truncation or padding applied'])

    def test_pdf_missing_letters_flagged(self):
        self.assertIn('skip', w.parse_pdf(PDF.replace('ZZZZZ ABCDE FG', 'ZZZZZ AB-DE FG'))[0])

    def test_stepping_double_step_and_ring_independence(self):
        key = w.parse_key(KEY.replace('XYZ', 'ADU'))
        self.assertEqual(w.end_positions(key, 1), 'ADV')
        self.assertEqual(w.end_positions(key, 2), 'AEW')
        self.assertEqual(w.end_positions(key, 3), 'BFX')

    def test_engine_failure_is_not_plaintext(self):
        failed = subprocess.CompletedProcess([], 7, '', 'synthetic engine failure\n')
        with patch.object(w.subprocess, 'run', return_value=failed):
            with self.assertRaisesRegex(RuntimeError, 'engine exited 7: synthetic engine failure'):
                w.decrypt(w.parse_key(KEY), 'ABCDEFG', Path('/var/tmp'), Path('/nonexistent/enigma'))

    def test_cli_error(self):
        result = subprocess.run([sys.executable, '-B', str(SCRIPT), '--unexpected'],
                                text=True, capture_output=True)
        self.assertEqual(result.returncode, 2)
        self.assertEqual(result.stdout, '')
        self.assertIn('error: unrecognized arguments: --unexpected\n', result.stderr)


if __name__ == '__main__':
    unittest.main()

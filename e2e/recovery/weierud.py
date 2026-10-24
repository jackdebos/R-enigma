#!/usr/bin/env python3
"""Fetch and decrypt Weierud sources; all source material stays git-ignored.

Run: python3 -B e2e/recovery/weierud.py
Requires Python 3, pdftotext, and the release enigma CLI (built if absent).
No network is used by the unit tests. Partial/unknown ciphertexts are skipped,
not repaired or concatenated across gaps. Verification failures exit 1 and are
listed individually; successful output and the full audit are kept under data/.
"""
import argparse
from collections import Counter
from datetime import datetime
from html.parser import HTMLParser
import json
from pathlib import Path
import re
import subprocess
import sys
import tempfile
from urllib.request import urlopen

ROOT = Path(__file__).resolve().parents[2]
DATA = Path(__file__).resolve().parent / 'data' / 'weierud'
PDF_URL = 'https://cryptocellar.org/bgac/heeresgruppe-nord-july-1941.pdf'
HTML_URL = 'https://cryptocellar.org/enigma/enigma-modern-breaking.html'
ROMAN = dict(zip('12345', ['I', 'II', 'III', 'IV', 'V']))
NOTCH = dict(zip(ROMAN.values(), 'QEVJZ'))
KEY_PATTERN = r'B[1-5]{3}\s+[a-z]{3}(?:\s+[A-Z]{2}){10}'


def letters(text):
    return re.sub('[^A-Z]', '', text.upper())


def parse_key(line, positions=None):
    parts = line.split()
    if len(parts) == 13 and positions is None:
        positions = parts.pop(2)
    if (len(parts) != 12 or not re.fullmatch(r'B[1-5]{3}', parts[0])
            or len(set(parts[0][1:])) != 3
            or not re.fullmatch('[a-zA-Z]{3}', parts[1])
            or (positions is not None and not re.fullmatch('[A-Z]{3}', positions))):
        raise ValueError('invalid key line')
    pairs = parts[2:]
    if any(not re.fullmatch('[A-Z]{2}', p) for p in pairs) or len(set(''.join(pairs))) != 20:
        raise ValueError('invalid plugboard pairs')
    return {'wheels': [ROMAN[n] for n in parts[0][1:]], 'rings': parts[1].upper(),
            'positions': positions, 'plugboard': pairs}


def build_request(key, ciphertext):
    if key['positions'] is None:
        raise ValueError('missing start position')
    slots = [{'id': 'reflector', 'wheel': 'B', 'ring': 'A', 'position': 'A'}]
    for slot, wheel, ring, position in zip(('left', 'middle', 'right'), key['wheels'],
                                           key['rings'], key['positions']):
        slots.append({'id': slot, 'wheel': wheel, 'ring': ring, 'position': position})
    return {'protocol_version': 1, 'machine': {'definition': {'kind': 'bundled', 'id': 'enigma-i'}},
            'job': {'kind': 'transform', 'direction': 'decrypt', 'text': ciphertext,
                    'configuration': {'slots': slots, 'plugboard': [list(p) for p in key['plugboard']]}}}


class SourceHTML(HTMLParser):
    """Collect paragraphs and styled spans, retaining nested discriminant text."""
    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.paragraphs = []
        self.current = None
        self.stack = []

    def handle_starttag(self, tag, attrs):
        if tag == 'p':
            self.current = {'text': [], 'aqua': [], 'red': [], 'green': []}
            self.stack = []
        if self.current is None:
            return
        if tag == 'br':
            self.handle_data(' ')
        if tag == 'span':
            style = dict(attrs).get('style', '').replace(' ', '').lower()
            channel = next((c for c, css in [('aqua', 'background-color:aqua'),
                            ('red', 'color:red'), ('green', 'color:green')] if css in style), None)
            buffer = [] if channel else (self.stack[-1] if self.stack else None)
            if channel:
                self.current[channel].append(buffer)
            self.stack.append(buffer)

    def handle_endtag(self, tag):
        if tag == 'span' and self.stack:
            self.stack.pop()
        if tag == 'p' and self.current is not None:
            self.paragraphs.append(self.current)
            self.current = None
            self.stack = []

    def handle_data(self, text):
        if self.current is not None:
            self.current['text'].append(text)
            if self.stack and self.stack[-1] is not None:
                self.stack[-1].append(text)


def parse_html(text):
    parser = SourceHTML()
    parser.feed(text)
    messages = []
    for p in parser.paragraphs:
        full = ''.join(p['text'])
        header = re.search(r'Message No\. (\d+) of (\d+ \w+ \d{4})', full)
        if not header or not p['aqua']:
            continue
        m = {'id': 'html-' + header[1], 'source': HTML_URL,
             'date': datetime.strptime(header[2], '%d %B %Y').date().isoformat()}
        try:
            m['key'] = parse_key(''.join(p['aqua'][0]))
            candidates = [''.join(b).strip() for b in p['red']]
            cipher = next(c for c in candidates if re.fullmatch(r'[A-Z-]{5}(?:\s+[A-Z-]{1,5})+', c))
            m['ciphertext'] = ''.join(cipher.split()[1:])  # Kenngruppe is not encrypted.
            m['expected'] = letters(''.join(p['green'][0]))
            if '-' in cipher or re.search(r'ciphertext has not been recorded', full, re.I):
                m['skip'] = 'incomplete ciphertext (unknown or unrecorded letters)'
            elif len(m['ciphertext']) != len(m['expected']):
                m['skip'] = 'ciphertext/raw plaintext length mismatch'
        except (IndexError, StopIteration, ValueError) as exc:
            m['skip'] = 'unusable HTML key or text: ' + str(exc)
        messages.append(m)
    return messages


def parse_pdf(text):
    # Remove only pdftotext page furniture; continuation groups remain contiguous.
    text = re.sub(r'\f[ \t]*\d+[ \t]*\n', '\n', text)
    keys = {}
    sections = list(re.finditer(r'Enigma keys for (\d{2}\.\d{2}\.\d{4})\s*\n', text))
    for i, section in enumerate(sections):
        body = text[section.end():sections[i + 1].start() if i + 1 < len(sections) else len(text)]
        daily_match = re.match(KEY_PATTERN, body)
        if daily_match is None:
            raise ValueError('unrecognized PDF daily key layout')
        daily = daily_match[0]
        special = {m[1]: m[2] for m in re.finditer(
            r'Special key for Nr\. (\d+) [A-Z]{5}:\s*\n(' + KEY_PATTERN + ')', body)}
        table = re.search(r'No:.*Start:.*Stop:[^\n]*\n((?:[^\n]+\n)+)', body)
        if table is None:
            raise ValueError('missing PDF message-key table')
        stop_column = table[0].splitlines()[0].index('Stop:')
        for row in table[1].splitlines():
            identity = re.match(r'\s*(\d+)\s+(?:(\d)tl\s+)?([A-Z]{5})\s+', row)
            if identity is None:
                continue
            triples = list(re.finditer(r'\b[A-Z]{3}\b', row[identity.end():]))
            # Start/Stop columns, not the two indicator fields, set the rotors.
            if not triples:
                continue
            last = triples[-1]
            has_stop = last.start() + identity.end() >= stop_column - 3
            if has_stop and len(triples) >= 4:
                start, stop = triples[-2][0], last[0]
            elif len(triples) >= 3:
                start, stop = last[0], None
            else:
                continue
            keys[(identity[1], identity[2])] = (parse_key(special.get(identity[1], daily), start), stop)

    header_pattern = r'(?m)^\s*(\d+)\.? (July|Juli|May) (\d{4}) Nr\.\s*(\d+)(?:/(\d))? ([A-Z]{5})\s*$'
    headers = list(re.finditer(header_pattern, text))
    messages = []
    for i, h in enumerate(headers):
        number, part, discriminant = h[4], h[5], h[6]
        body = text[h.end():headers[i + 1].start() if i + 1 < len(headers) else len(text)]
        form_number = re.search(r'(?m)^Nr\. (\d+),', body)
        if form_number:
            number = form_number[1]  # The form can correct a typo in the caption.
        m = {'id': 'pdf-' + number + ('-' + part if part else ''), 'source': PDF_URL,
             'date': datetime.strptime(f'{h[1]} {"July" if h[2] == "Juli" else h[2]} {h[3]}',
                                       '%d %B %Y').date().isoformat()}
        # Match complete lines, never just the initial capital of following prose.
        group_line = r'[A-Z-]{1,5}(?:[ \t]+[A-Z-]{1,5})*[ \t]*$'
        cipher = re.search(r'(?m)^' + discriminant + r' ' + group_line
                           + r'(?:\n(?:' + group_line + r'|[ \t]*$))*', body)
        if cipher is None:
            m['skip'] = 'ciphertext block not found'
        else:
            m['ciphertext'] = ''.join(cipher[0].split()[1:])
            totals = re.findall(r'\b(\d+)\s*[-–]\s*[A-Z]{3}\s+[A-Z]{3}\b', body[:cipher.start()])
            m['header_cipher_length'] = int(totals[-1]) - 5 if totals else None
            m['header_length_matches'] = (len(m['ciphertext']) == m['header_cipher_length']
                                          if totals else None)
            # A header is only a cross-check: known erroneous totals must not
            # truncate the original groups or manufacture missing letters.
            if '-' in m['ciphertext'] or re.search(r'(?m)^-----', body) or re.search(r'missing \d+ ciphertext letters', body):
                m['skip'] = 'incomplete ciphertext (gaps are not reconstructed)'
        if (number, part) not in keys:
            m['skip'] = 'no usable published message key'
        else:
            m['key'], m['stop'] = keys[(number, part)]
        messages.append(m)
    return messages


def end_positions(key, length):
    """Pre-step display notches, including double stepping; rings do not shift them."""
    p = [ord(c) - 65 for c in key['positions']]
    for _ in range(length):
        middle = p[1] == ord(NOTCH[key['wheels'][1]]) - 65
        right = p[2] == ord(NOTCH[key['wheels'][2]]) - 65
        p = [(p[0] + middle) % 26, (p[1] + (middle or right)) % 26, (p[2] + 1) % 26]
    return ''.join(chr(n + 65) for n in p)


def decrypt(key, ciphertext, scratch, engine):
    result = subprocess.run([str(engine), '--no-report', '--request', '-'],
                            input=json.dumps(build_request(key, ciphertext)), cwd=scratch,
                            capture_output=True, text=True)
    if result.returncode:
        raise RuntimeError(f'engine exited {result.returncode}: {result.stderr.strip()}')
    plaintext = result.stdout.strip()
    if not re.fullmatch('[A-Z]+', plaintext) or len(plaintext) != len(ciphertext):
        raise RuntimeError('engine returned invalid plaintext or length')
    return plaintext


def trigram_table():
    path = ROOT / 'e2e/bomm/frequencies/enigma1941-trigram.txt'
    return {line.split()[0].upper() for line in path.read_text().splitlines() if line.strip()}


def verify(message, plaintext, trigrams):
    if 'expected' in message:
        expected = message['expected']
        difference = next((i for i in range(max(len(plaintext), len(expected)))
                           if plaintext[i:i + 1] != expected[i:i + 1]), None)
        return {'method': 'published raw plaintext, ignoring case/spacing',
                'passed': difference is None,
                'first_difference': ({'position': difference + 1,
                                      'actual': plaintext[difference:difference + 1],
                                      'expected': expected[difference:difference + 1]}
                                     if difference is not None else None),
                'reasons': ['raw plaintext mismatch (1-based position); published key and ciphertext '
                            'used unchanged; transcription garbles are not assumed to explain differences']
                           if difference is not None else []}
    coverage = sum(plaintext[i:i + 3] in trigrams for i in range(len(plaintext) - 2)) / max(1, len(plaintext) - 2)
    actual = end_positions(message['key'], len(plaintext))
    stop = message['stop']
    # Coverage is a plausibility screen, not proof of authenticity or correctness.
    reasons = []
    if message.get('header_length_matches') is False:
        reasons.append(f'header expects {message["header_cipher_length"]} cipher letters but extracted '
                       f'complete groups contain {len(plaintext)}; no truncation or padding applied')
    if stop is not None and actual != stop:
        reasons.append('published Stop does not match stepping over the extracted groups; original retained')
        if message.get('header_length_matches') is True:
            reasons.append('extracted length agrees with message header; Stop inconsistency remains in source')
    if coverage < 0.65:
        reasons.append('German trigram coverage below 0.65; possible garbled original, not corrected')
        if message.get('header_length_matches') is True and actual == stop:
            reasons.append('complete groups agree with header length and published Stop; poor plaintext remains')
    return {'method': 'display-notch stepping with double step; German trigram coverage',
            'stop_expected': stop, 'stop_actual': actual, 'stop_matches': actual == stop if stop else None,
            'trigram_coverage': round(coverage, 4), 'threshold': 0.65,
            'header_cipher_length': message.get('header_cipher_length'),
            'extracted_cipher_length': len(plaintext),
            'header_length_matches': message.get('header_length_matches'), 'reasons': reasons,
            'passed': (stop is None or actual == stop) and coverage >= 0.65}


def run():
    DATA.mkdir(parents=True, exist_ok=True)
    for url in (PDF_URL, HTML_URL):
        path = DATA / url.rsplit('/', 1)[1]
        if not path.exists():
            with urlopen(url, timeout=60) as response:
                content = response.read()
            path.write_bytes(content)
    pdf_text = DATA / 'heeresgruppe-nord-july-1941.txt'
    subprocess.run(['/usr/bin/pdftotext', '-layout', str(DATA / 'heeresgruppe-nord-july-1941.pdf'),
                    str(pdf_text)], check=True, capture_output=True)
    messages = parse_html((DATA / 'enigma-modern-breaking.html').read_text()) + parse_pdf(pdf_text.read_text())
    if sum(m['source'] == HTML_URL for m in messages) != 13 or sum(m['source'] == PDF_URL for m in messages) != 56:
        raise ValueError('source layout changed: expected 13 HTML and 56 PDF entries')
    engine = ROOT / 'target/release/enigma'
    if not engine.exists():
        subprocess.run(['cargo', 'build', '--release', '-p', 'enigma-cli'], cwd=ROOT, check=True)
    output, skipped, failed = [], [], []
    trigrams = trigram_table()
    with tempfile.TemporaryDirectory(prefix='engine-', dir=DATA) as scratch:
        for m in messages:
            if 'skip' in m:
                skipped.append({'id': m['id'], 'reason': m['skip']})
                print(f'SKIP {m["id"]}: {m["skip"]}')
                continue
            try:
                plaintext = decrypt(m['key'], m['ciphertext'], scratch, engine)
                verification = verify(m, plaintext, trigrams)
                record = {name: m[name] for name in ('id', 'source', 'date')}
                record.update(length=len(plaintext), plaintext=plaintext, verification=verification)
                output.append(record)
                if not verification['passed']:
                    failed.append({'id': m['id'], 'reason': verification})
                    print(f'FAIL {m["id"]}: {json.dumps(verification)}', file=sys.stderr)
            except (OSError, RuntimeError) as exc:
                failed.append({'id': m['id'], 'reason': str(exc)})
                print(f'FAIL {m["id"]}: {exc}', file=sys.stderr)
    (DATA / 'plaintexts.json').write_text(json.dumps(output, indent=2) + '\n')
    summary = {'decrypted': len(output), 'verified': sum(r['verification']['passed'] for r in output),
               'skipped': skipped, 'failed': failed, 'total_letters': sum(r['length'] for r in output),
               'length_histogram': dict(sorted(Counter(r['length'] for r in output).items())),
               'verified_letters': sum(r['length'] for r in output if r['verification']['passed']),
               'verified_length_histogram': dict(sorted(Counter(r['length'] for r in output
                                                                if r['verification']['passed']).items()))}
    (DATA / 'audit.json').write_text(json.dumps(summary, indent=2) + '\n')
    print(json.dumps(summary, indent=2))
    return 1 if failed else 0


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.parse_args()
    try:
        return run()
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f'error: {exc}', file=sys.stderr)
        return 1


if __name__ == '__main__':
    sys.exit(main())

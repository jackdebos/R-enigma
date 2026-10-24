import test from 'node:test';
import assert from 'node:assert/strict';
import { checkText, validatePair, buildRequest, lookup, initialLanguage, buildAttackBody, parseAttackInput, estimateDuration, progressInfo, holdEntries, groupFive } from './logic.js';

test('text accepts only A-Z, including empty text, without changing input', () => {
  for (const text of ['', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ']) {
    assert.deepEqual(checkText(text), { offending: [], hasLowercase: false });
  }
  const text = 'aZ é!?\n😀A1';
  assert.deepEqual(checkText(text), {
    offending: [
      { character: 'a', position: 1 }, { character: ' ', position: 3 },
      { character: 'é', position: 4 }, { character: '!', position: 5 },
      { character: '?', position: 6 }, { character: '\n', position: 7 },
      { character: '😀', position: 8 }, { character: '1', position: 10 },
    ], hasLowercase: true,
  });
  assert.equal(text, 'aZ é!?\n😀A1');
  assert.equal(checkText(' AÄ1').hasLowercase, false);
  assert.equal(checkText('é').hasLowercase, true);
});

test('plugboard rejects invalid, identical and reused letters without mutating pairs', () => {
  const pairs = [['A', 'B']];
  assert.equal(validatePair(pairs, 'C', 'D'), null);
  for (const pair of [['A', 'C'], ['C', 'B']]) assert.equal(validatePair(pairs, ...pair), 'pair_reused');
  assert.equal(validatePair(pairs, 'C', 'C'), 'pair_same');
  for (const pair of [['a', 'C'], ['', 'C'], ['AA', 'D'], ['C', '1']]) {
    assert.equal(validatePair(pairs, ...pair), 'pair_invalid');
  }
  assert.deepEqual(pairs, [['A', 'B']]);
});

test('request preserves catalog slot order, settings, pairs and exact text for all models', () => {
  for (const model of ['enigma-i', 'enigma-m3', 'enigma-m4']) {
    const slots = (model === 'enigma-m4' ? ['greek', 'left', 'middle', 'right'] : ['left', 'middle', 'right'])
      .map((id, i) => ({ id, wheel: id === 'greek' ? 'Beta' : ['I', 'II', 'III', 'IV'][i], ring: 'B', position: 'Z' }));
    const state = { model, reflector: model === 'enigma-m4' ? 'Thin-B' : 'B', slots, plugboard: [['A', 'Z']], text: 'aZ é!?\n' };
    const before = structuredClone(state);
    const request = buildRequest(state);
    assert.deepEqual(request, before);
    request.slots[0].position = 'C';
    request.plugboard[0][0] = 'X';
    assert.deepEqual(state, before);
    assert.deepEqual(buildRequest({ ...state, text: '', plugboard: [] }).plugboard, []);
  }
});

test('dictionary lookup interpolates safely and falls back to English then key', () => {
  const es = { greeting: 'Hola {name}', blank: '' };
  const en = { greeting: 'Hello {name}', fallback: 'Available {count}', blank: 'Nonempty' };
  assert.equal(lookup(es, en, 'greeting', { name: '$&<test>' }), 'Hola $&<test>');
  assert.equal(lookup(es, en, 'fallback', { count: 2 }), 'Available 2');
  assert.equal(lookup(es, en, 'missing'), 'missing');
  assert.equal(lookup(es, en, 'blank'), 'Nonempty');
});

test('attack body preserves text, maps unknowns to null and sends only changed settings', () => {
  const state = { model: 'enigma-m4', reflector: '', slots: [
    { id: 'greek', wheel: 'Beta', ring: 'A', position: '' },
    { id: 'left', wheel: '', ring: '', position: 'Z' },
  ], plugboard: [['A', 'B']], search: true, text: 'aZ é!\n', advanced: { hold: '', threads: '2', method: 'partial_exhaustion', seeds: ['C'], stages: [] } };
  const before = structuredClone(state);
  const body = buildAttackBody(state);
  assert.deepEqual(body, { model: 'enigma-m4', reflector: null, slots: [
    { id: 'greek', wheel: 'Beta', ring: 'A', position: null },
    { id: 'left', wheel: null, ring: null, position: 'Z' },
  ], plugboard: { known: [['A', 'B']], search: true }, text: 'aZ é!\n', settings: { threads: 2, method: 'partial_exhaustion', seeds: ['C'], stages: [] } });
  assert.deepEqual(state, before);
  assert.deepEqual(buildAttackBody(parseAttackInput(body)), body);
  const simple = { ...state, advanced: {}, search: false };
  assert.equal(Object.hasOwn(buildAttackBody(simple), 'settings'), false);
  assert.equal(buildAttackBody(simple).plugboard.search, false);
  assert.deepEqual(buildAttackBody(parseAttackInput(buildAttackBody(simple))), buildAttackBody(simple));
  const hc = buildAttackBody({ ...state, advanced: { method: 'hill_climb', seeds: ['A'], max_pairs: '0', tables: { sinkov_bigram: '/own.json', trie: '' } } });
  assert.deepEqual(hc.settings, { method: 'hill_climb', max_pairs: 0, tables: { sinkov_bigram: '/own.json' } });
});

test('saved attack input round trips all advanced settings and null dimensions for every model', () => {
  for (const model of ['enigma-i', 'enigma-m3', 'enigma-m4']) {
    const input = { model, reflector: null,
      slots: (model === 'enigma-m4' ? ['greek', 'left', 'middle', 'right'] : ['left', 'middle', 'right']).map(id => ({ id, wheel: null, ring: null, position: null })),
      plugboard: { known: [['Y', 'Z']], search: false }, text: ' A\naé😀',
      settings: { method: 'partial_exhaustion', initial_measure: 'entropy', final_measure: 'sinkov_quadgram', stages: [{ pass: 'reswapping', measure: 'sinkov_bigram' }, { pass: 'trie', base_measure: 'ic' }], max_pairs: 13, switch_pairs: 0, backtrack_pairs: 13, hold: 1000, threads: 256, tables: { sinkov_quadgram: '/tables/four.json', trie: '/tables/words.json' } },
    };
    const before = structuredClone(input);
    const state = parseAttackInput(input);
    assert.deepEqual(buildAttackBody(state), input);
    state.slots[0].ring = 'Z'; state.plugboard[0][0] = 'X'; state.advanced.tables.trie = '/other.json';
    assert.deepEqual(input, before);
    assert.deepEqual(buildAttackBody(parseAttackInput({ ...input, settings: undefined })).text, input.text);
  }
});

test('duration units change at exact minute, hour and day boundaries', () => {
  for (const [seconds, value, unit] of [[0, 0, 'seconds'], [59, 59, 'seconds'], [60, 1, 'minutes'], [3599, 60, 'minutes'], [3600, 1, 'hours'], [86399, 24, 'hours'], [86400, 1, 'days'], [172800, 2, 'days'], [null, 0, 'seconds'], [-1, 0, 'seconds'], [0.5, 0.5, 'seconds']]) {
    assert.deepEqual(estimateDuration(seconds), { value, unit });
  }
});

test('progress handles decimal-string counters, nulls, bounds and ETA', () => {
  assert.deepEqual(progressInfo(null), { percent: '0.0', elapsed: '00:00:00', eta: '--:--:--', completed: '0', selected: '0', evaluations: '0' });
  assert.deepEqual(progressInfo({ outers_selected: '4', counters: { outers_completed: '1', evaluations_completed: '12345678901234567890' }, elapsed_ms: '2000' }), { percent: '25.0', elapsed: '00:00:02', eta: '00:00:06', completed: '1', selected: '4', evaluations: '12345678901234567890' });
  assert.equal(progressInfo({ outers_selected: '3', counters: { outers_completed: '1' } }).percent, '33.3');
  assert.equal(progressInfo({ outers_selected: '18446744073709551615', counters: { outers_completed: '18446744073709551615' }, elapsed_ms: '0' }).eta, '00:00:00');
  assert.equal(progressInfo({ outers_selected: '0', counters: { outers_completed: '0' } }).percent, '0.0');
  assert.equal(progressInfo({ outers_selected: '1', counters: { outers_completed: '2' }, elapsed_ms: '3661000' }).elapsed, '01:01:01');
  assert.equal(progressInfo({ outers_selected: '1', counters: { outers_completed: '2' } }).percent, '100.0');
  assert.equal(progressInfo({ outers_selected: '1', elapsed_ms: '9000' }).eta, '--:--:--');
  assert.equal(progressInfo({ outers_selected: null, counters: null, elapsed_ms: null }).eta, '--:--:--');
});

test('result extraction keeps hold order and falls back to best without inventing candidates', () => {
  const a = { plaintext: 'A' }, b = { plaintext: 'B' };
  assert.deepEqual(holdEntries({ hold: [b, a], best: a }), [b, a]);
  assert.deepEqual(holdEntries({ best: a }), [a]);
  assert.deepEqual(holdEntries({ hold: [], best: a }), [a]);
  for (const result of [null, {}, { best: null }]) assert.deepEqual(holdEntries(result), []);
});

test('five-letter grouping preserves every symbol and handles boundaries', () => {
  for (const [text, grouped] of [['', ''], ['ABCD', 'ABCD'], ['ABCDE', 'ABCDE'], ['ABCDEF', 'ABCDE F'], ['ABCDEFGHIJK', 'ABCDE FGHIJ K'], ['😀ABCDZ', '😀ABCD Z']]) assert.equal(groupFive(text), grouped);
});

test('language uses a valid saved choice, otherwise the browser language', () => {
  assert.equal(initialLanguage('en', 'es-AR'), 'en');
  assert.equal(initialLanguage('es', 'en-US'), 'es');
  assert.equal(initialLanguage(null, 'es-AR'), 'es');
  assert.equal(initialLanguage('bad', 'ES-es'), 'es');
  assert.equal(initialLanguage(null, 'fr'), 'en');
});

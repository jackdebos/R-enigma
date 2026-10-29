import test from 'node:test';
import { readFileSync } from 'node:fs';
import assert from 'node:assert/strict';
import { backendSettings, parseUKWD, convertUKWDPairs, ukwDNotations, cribInfo, selectAttackMethod, checkText, validatePair, buildRequest, lookup, initialLanguage, buildAttackBody, parseAttackInput, estimateDuration, progressInfo, holdEntries, groupFive } from './logic.js';

const bpWiring = 'AZ CX DW EV FU GT HS IR JQ KP LN MY';
const germanWiring = 'AB ZD XE WF VG UH TI SK RL QM PN OC';

test('UKW-D external vector converts exactly between German and BP, without mutation', () => {
  const bp = bpWiring.split(' ').map(pair => [...pair]);
  const german = germanWiring.split(' ').map(pair => [...pair]);
  assert.deepEqual(parseUKWD(germanWiring), { pairs: bp, error: null });
  assert.deepEqual(parseUKWD(bpWiring, 'bp'), { pairs: bp, error: null });
  assert.deepEqual(parseUKWD(germanWiring.toLowerCase()), { pairs: bp, error: null });
  assert.deepEqual(parseUKWD('ab zD Xe WF VG UH TI SK RL QM PN OC'), { pairs: bp, error: null });
  assert.deepEqual(parseUKWD(bpWiring.toLowerCase(), 'bp'), { pairs: bp, error: null });
  assert.deepEqual(convertUKWDPairs(bp, 'bp', 'german'), german);
  assert.deepEqual(convertUKWDPairs(german, 'german', 'bp'), bp);
  assert.deepEqual(ukwDNotations(bp), { bp: bpWiring, german: germanWiring });
  assert.equal(bp.map(pair => pair.join('')).join(' '), bpWiring);
});

test('UKW-D rejects incomplete, reused, fixed, absent and malformed contacts', () => {
  for (const [text, notation, error] of [
    ['', 'german', 'ukwd_count'], [germanWiring.split(' ').slice(1).join(' '), 'german', 'ukwd_count'],
    [germanWiring + ' JY', 'german', 'ukwd_count'],
    [germanWiring.replace('AB', 'AJ'), 'german', 'ukwd_german_contacts'],
    [germanWiring.replace('AB', 'AY'), 'german', 'ukwd_german_contacts'],
    [bpWiring.replace('AZ', 'AB'), 'bp', 'ukwd_bp_contacts'],
    [bpWiring.replace('AZ', 'AO'), 'bp', 'ukwd_bp_contacts'],
    [germanWiring.replace('AB', 'AA'), 'german', 'ukwd_reused'],
    [germanWiring.replace('ZD', 'AD'), 'german', 'ukwd_reused'],
    [germanWiring.replace('AB', 'aj'), 'german', 'ukwd_german_contacts'],
    [germanWiring.replace('AB', 'A-'), 'german', 'ukwd_german_contacts'],
    [germanWiring.replace('AB', 'ABC'), 'german', 'ukwd_pair'],
  ]) {
    assert.deepEqual(parseUKWD(text, notation), { pairs: null, error }, `${text}/${notation}`);
  }
});

test('UKW-D payloads send BP only, unknown wiring round trips and preserves GPU for explicit rejection', () => {
  for (const model of ['enigma-i-ukwd', 'enigma-m3-ukwd', 'enigma-kd']) {
    const state = { model, reflector: 'D', slots: [], plugboard: [], search: false, text: 'ABC', advanced: {}, wiring: germanWiring, notation: 'german', searchReflector: false };
    assert.deepEqual(buildRequest(state).reflector_pairs, parseUKWD(germanWiring).pairs);
    let body = buildAttackBody(state);
    assert.deepEqual(body.reflector_pairs, parseUKWD(germanWiring).pairs);
    assert.deepEqual(buildAttackBody(parseAttackInput(body)), body);
    state.searchReflector = true;
    state.advanced = { reflector_starts: '8', backend: 'gpu' };
    body = buildAttackBody(state);
    assert.equal(body.search_reflector, true);
    assert.equal(Object.hasOwn(body, 'reflector_pairs'), false);
    assert.equal(body.settings.reflector_starts, 8);
    assert.equal(body.settings.backend, 'gpu');
    assert.deepEqual(buildAttackBody(parseAttackInput(body)), body);
    state.searchReflector = false;
    assert.equal(Object.hasOwn(buildAttackBody(state).settings, 'reflector_starts'), false);
  }
});

test('resume host settings do not require a valid wiring in the unrelated current form', () => {
  assert.deepEqual(backendSettings({ backend: 'gpu', gpu_usage: '37' }), { backend: 'gpu', gpu_usage: 37 });
  assert.deepEqual(backendSettings({}), { backend: 'cpu' });
  assert.deepEqual(backendSettings({ backend: 'cpu', gpu_usage: '0' }), { backend: 'cpu' });
});

test('UKW-D controls, validation and results have bilingual copy', () => {
  for (const lang of ['es', 'en']) {
    const dictionary = JSON.parse(readFileSync(new URL(`./i18n/${lang}.json`, import.meta.url), 'utf8'));
    for (const key of ['ukwd_wiring', 'ukwd_wiring_hint', 'ukwd_notation', 'ukwd_notation_hint', 'ukwd_german', 'ukwd_bp', 'search_reflector', 'search_reflector_hint', 'reflector_starts', 'reflector_starts_hint', 'ukwd_cpu', 'ukwd_hc', 'ukwd_fixed', 'ukwd_count', 'ukwd_pair', 'ukwd_reused', 'ukwd_german_contacts', 'ukwd_bp_contacts', 'result_ukwd_bp', 'result_ukwd_german', 'model_enigma-i-ukwd', 'model_enigma-m3-ukwd', 'model_enigma-kd', 'reflector_D']) assert.ok(dictionary[key]?.trim(), `${lang}/${key}`);
  }
});

test('settable reflector values survive transform and attack saved-input round trips', () => {
  for (const model of ['enigma-railway', 'enigma-g312', 'enigma-g260']) {
    const state = { model, reflector: 'UKW', reflector_ring: 'D', reflector_position: 'J', slots: [], plugboard: [], search: false, text: 'ABC', advanced: {} };
    assert.equal(buildRequest(state).reflector_ring, 'D');
    assert.equal(buildRequest(state).reflector_position, 'J');
    const body = buildAttackBody({ ...state, reflector_position: '' });
    assert.equal(body.reflector_ring, 'D');
    assert.equal(body.reflector_position, null);
    assert.deepEqual(buildAttackBody(parseAttackInput(body)), body);
  }
});

test('crib is checked as typed, short warning and method defaults preserve unrelated state', () => {
  for (const [text, short] of [['', true], ['A'.repeat(13), true], ['A'.repeat(14), false]]) {
    assert.deepEqual(cribInfo(text), { text, short, offending: [], hasLowercase: false });
  }
  assert.deepEqual(cribInfo('wet ter'), { text: 'wet ter', short: true, offending: ['w', 'e', 't', ' ', 't', 'e', 'r'].map((character, i) => ({ character, position: i + 1 })), hasLowercase: true });
  assert.deepEqual(cribInfo('WET TER').offending, [{ character: ' ', position: 4 }]);
  assert.equal(cribInfo('WET TER').hasLowercase, false);
  assert.deepEqual(cribInfo(' é!').offending.map(item => item.character), [' ', 'é', '!']);
  for (const ids of [['left', 'middle', 'right'], ['greek', 'left', 'middle', 'right']]) {
    const state = { slots: ids.map(id => ({ id, ring: 'Z', position: 'B' })), advanced: { backend: 'gpu', seeds: ['E'], hold: 7 } };
    selectAttackMethod(state, 'bombe');
    assert.deepEqual(state.slots.map(slot => slot.ring), ids.map(id => id === 'right' ? '' : 'A'));
    assert.ok(state.slots.every(slot => slot.position === 'B'));
    assert.deepEqual(state.advanced, { method: 'bombe', backend: 'cpu', hold: 7 });
    state.slots.at(-1).ring = 'V';
    selectAttackMethod(state, 'hill_climb');
    assert.equal(state.slots.at(-1).ring, 'V');
  }
});

test('bombe payload sends the crib as typed, converts position and omits stale seeds', () => {
  const state = { model: 'enigma-i', reflector: 'B', slots: [], plugboard: [], search: true, text: ' A b\n', advanced: { method: 'bombe', crib: ' z y\n', crib_position: '0', seeds: ['E'] } };
  const before = structuredClone(state);
  assert.deepEqual(buildAttackBody(state).settings, { method: 'bombe', crib: ' z y\n', crib_position: 0, backend: 'cpu', distinct_wheels: true });
  assert.equal(buildAttackBody(state).text, state.text);
  assert.deepEqual(state, before);
  state.advanced.crib_position = '';
  assert.equal(Object.hasOwn(buildAttackBody(state).settings, 'crib_position'), false);
  state.advanced.method = 'hill_climb';
  assert.deepEqual(buildAttackBody(state).settings, { method: 'hill_climb', backend: 'cpu', distinct_wheels: true });
});

test('crib labels, warning and results have bilingual copy', () => {
  for (const lang of ['es', 'en']) {
    const dictionary = JSON.parse(readFileSync(new URL(`./i18n/${lang}.json`, import.meta.url), 'utf8'));
    for (const key of ['method_bombe', 'crib', 'crib_hint', 'crib_position', 'crib_position_hint', 'crib_short', 'crib_invalid_intro', 'crib_summary', 'result_crib_position', 'bombe_cpu']) assert.ok(dictionary[key]?.trim(), `${lang}/${key}`);
  }
});

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
  ], plugboard: { known: [['A', 'B']], search: true }, text: 'aZ é!\n', settings: { threads: 2, method: 'partial_exhaustion', seeds: ['C'], stages: [], backend: 'cpu', distinct_wheels: true } });
  assert.deepEqual(state, before);
  assert.deepEqual(buildAttackBody(parseAttackInput(body)), body);
  const simple = { ...state, advanced: {}, search: false };
  assert.deepEqual(buildAttackBody(simple).settings, { backend: 'cpu', distinct_wheels: true });
  assert.equal(buildAttackBody(simple).plugboard.search, false);
  assert.deepEqual(buildAttackBody(parseAttackInput(buildAttackBody(simple))), buildAttackBody(simple));
  const hc = buildAttackBody({ ...state, advanced: { method: 'hill_climb', seeds: ['A'], max_pairs: '0', tables: { sinkov_bigram: '/own.json', trie: '' } } });
  assert.deepEqual(hc.settings, { method: 'hill_climb', max_pairs: 0, tables: { sinkov_bigram: '/own.json' }, backend: 'cpu', distinct_wheels: true });
});

test('saved attack input round trips all advanced settings and null dimensions for every model', () => {
  for (const model of ['enigma-i', 'enigma-m3', 'enigma-m4']) {
    const input = { model, reflector: null,
      slots: (model === 'enigma-m4' ? ['greek', 'left', 'middle', 'right'] : ['left', 'middle', 'right']).map(id => ({ id, wheel: null, ring: null, position: null })),
      plugboard: { known: [['Y', 'Z']], search: false }, text: ' A\naé😀',
      settings: { backend: 'cpu', distinct_wheels: true, method: 'partial_exhaustion', initial_measure: 'entropy', final_measure: 'sinkov_quadgram', stages: [{ pass: 'reswapping', measure: 'sinkov_bigram' }, { pass: 'trie', base_measure: 'ic' }], max_pairs: 13, switch_pairs: 0, backtrack_pairs: 13, hold: 1000, threads: 256, tables: { sinkov_quadgram: '/tables/four.json', trie: '/tables/words.json' } },
    };
    const before = structuredClone(input);
    const state = parseAttackInput(input);
    assert.deepEqual(buildAttackBody(state), input);
    state.slots[0].ring = 'Z'; state.plugboard[0][0] = 'X'; state.advanced.tables.trie = '/other.json';
    assert.deepEqual(input, before);
    assert.deepEqual(buildAttackBody(parseAttackInput({ ...input, settings: undefined })).text, input.text);
  }
});

// Distinct wheels: default checked, explicit opt-out and saved-input loading.
test('distinct wheels defaults on and preserves an explicit opt-out without changing text', () => {
  const state = { model: 'enigma-i', reflector: 'B', slots: [], plugboard: [], search: true, text: ' aZ é!\n', advanced: {} };
  const before = structuredClone(state);
  assert.equal(buildAttackBody(state).settings.distinct_wheels, true);
  const off = buildAttackBody({ ...state, distinctWheels: false });
  assert.equal(off.settings.distinct_wheels, false);
  assert.equal(off.text, state.text);
  assert.equal(parseAttackInput(off).distinctWheels, false);
  assert.deepEqual(buildAttackBody(parseAttackInput(off)), off);
  const legacy = { ...off }; delete legacy.settings;
  assert.equal(parseAttackInput(legacy).distinctWheels, true);
  assert.deepEqual(state, before);
});

test('backend payload defaults to CPU and sends numeric GPU usage only for GPU', () => {
  const state = { model: 'enigma-i', reflector: 'B', slots: [], plugboard: [], search: true, text: 'ABC', advanced: {} };
  const before = structuredClone(state);
  assert.deepEqual(buildAttackBody(state).settings, { backend: 'cpu', distinct_wheels: true });
  assert.deepEqual(parseAttackInput(buildAttackBody(state)).advanced, { backend: 'cpu', gpu_usage: 100, distinct_wheels: true });
  for (const [usage, expected] of [[undefined, 100], ['1', 1], ['37', 37], ['100', 100]]) {
    const body = buildAttackBody({ ...state, advanced: { backend: 'gpu', gpu_usage: usage } });
    assert.deepEqual(body.settings, { backend: 'gpu', gpu_usage: expected, distinct_wheels: true });
    assert.deepEqual(buildAttackBody(parseAttackInput(body)), body);
  }
  assert.deepEqual(buildAttackBody({ ...state, advanced: { backend: 'cpu', gpu_usage: '0' } }).settings, { backend: 'cpu', distinct_wheels: true });
  assert.deepEqual(state, before);
});

test('backend labels, hints and errors exist with exact bilingual copy', () => {
  for (const [lang, cpu, gpu, usage] of [
    ['es', 'Procesador (CPU)', 'Placa de video (GPU)', 'Uso de GPU (%)'],
    ['en', 'Processor (CPU)', 'Graphics card (GPU)', 'GPU usage (%)'],
  ]) {
    const dictionary = JSON.parse(readFileSync(new URL(`./i18n/${lang}.json`, import.meta.url), 'utf8'));
    assert.equal(dictionary.backend_cpu, cpu);
    assert.equal(dictionary.backend_gpu, gpu);
    assert.equal(dictionary.gpu_usage, usage);
    for (const key of ['backend', 'backend_hint', 'gpu_usage_hint', 'error_backend_unavailable', 'engine_error_unsupported_job']) {
      assert.equal(typeof dictionary[key], 'string', `${lang}/${key}`);
      assert.notEqual(dictionary[key].trim(), '', `${lang}/${key}`);
    }
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

test('crib keeps BOM and non-breaking space as offending symbols', () => {
  assert.deepEqual(cribInfo('\uFEFFZ\u00a0Y').offending.map(o => o.position), [1, 3]);
  assert.equal(cribInfo('\uFEFFZ\u00a0Y').text, '\uFEFFZ\u00a0Y');
});

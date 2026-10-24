import test from 'node:test';
import assert from 'node:assert/strict';
import { checkText, validatePair, buildRequest, lookup, initialLanguage } from './logic.js';

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

test('language uses a valid saved choice, otherwise the browser language', () => {
  assert.equal(initialLanguage('en', 'es-AR'), 'en');
  assert.equal(initialLanguage('es', 'en-US'), 'es');
  assert.equal(initialLanguage(null, 'es-AR'), 'es');
  assert.equal(initialLanguage('bad', 'ES-es'), 'es');
  assert.equal(initialLanguage(null, 'fr'), 'en');
});

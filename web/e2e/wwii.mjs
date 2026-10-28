// Optional real-browser smoke: from the root, node web/e2e/wwii.mjs.
// Requires ENIGMA_WEB_BIN, ENIGMA_TEST_BIN and Google Chrome (defaults below).
// All browser/server state lives in a fresh system-temp directory.
import { spawn, spawnSync } from 'node:child_process';
import { mkdtemp, readFile, rm } from 'node:fs/promises';
import { once } from 'node:events';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';

const scratch = await mkdtemp(join(tmpdir(), 'enigma-web-wwii-'));
console.log(`Scratch: ${scratch}`);
const engineBin = resolve(process.env.ENIGMA_TEST_BIN || 'target/release/enigma');
const server = spawn(resolve(process.env.ENIGMA_WEB_BIN || 'target/enigma-web'), ['--no-browser'], {
  env: { ...process.env, ENIGMA_WEB_CONFIG: join(scratch, 'config.json') },
  stdio: ['ignore', 'pipe', 'pipe'],
});
const chrome = spawn('/usr/bin/google-chrome', ['--headless', '--no-sandbox', '--disable-gpu', '--disable-dev-shm-usage', '--no-first-run', '--no-default-browser-check', `--user-data-dir=${join(scratch, 'chrome')}`, '--remote-debugging-pipe', 'about:blank'], {
  stdio: ['ignore', 'ignore', 'ignore', 'pipe', 'pipe'],
});
let sequence = 0, buffer = '';
const pending = new Map();
const browserErrors = [];
chrome.stdio[4].on('data', data => {
  buffer += data.toString();
  let end;
  while ((end = buffer.indexOf('\0')) >= 0) {
    const message = JSON.parse(buffer.slice(0, end)); buffer = buffer.slice(end + 1);
    if (message.id) {
      const job = pending.get(message.id); pending.delete(message.id);
      if (message.error) job?.reject(new Error(JSON.stringify(message.error))); else job?.resolve(message.result);
    }
    if (message.method === 'Runtime.exceptionThrown') browserErrors.push(message.params);
    if (message.method === 'Log.entryAdded' && message.params.entry.level === 'error') browserErrors.push(message.params.entry);
  }
});
function cdp(method, params = {}, sessionId) {
  return new Promise((resolve, reject) => {
    const id = ++sequence;
    pending.set(id, { resolve, reject });
    chrome.stdio[3].write(JSON.stringify({ id, method, params, ...(sessionId ? { sessionId } : {}) }) + '\0');
  });
}
let session;
async function evaluate(expression) {
  const response = await cdp('Runtime.evaluate', { expression, awaitPromise: true, returnByValue: true }, session);
  if (response.exceptionDetails) throw new Error(JSON.stringify(response.exceptionDetails));
  return response.result.value;
}
async function wait(expression) {
  const deadline = Date.now() + 15000;
  while (Date.now() < deadline) {
    if (await evaluate(expression)) return;
    await new Promise(resolve => setTimeout(resolve, 100));
  }
  throw new Error(`Timeout: ${expression}`);
}
const set = (id, value, event = 'change') => `document.getElementById(${JSON.stringify(id)}).value=${JSON.stringify(value)};document.getElementById(${JSON.stringify(id)}).dispatchEvent(new Event(${JSON.stringify(event)}, {bubbles:true}));`;
const watchdog = setTimeout(() => { console.error('Browser smoke timed out'); server.kill('SIGINT'); chrome.kill('SIGTERM'); process.exitCode = 1; }, 90000);
try {
  const url = await new Promise((resolve, reject) => {
    let output = '';
    server.stdout.on('data', data => { output += data; const url = output.match(/http:\/\/127\.0\.0\.1:\d+\/\?token=[a-f0-9]+/); if (url) resolve(url[0]); });
    server.on('error', reject);
    server.on('exit', code => reject(new Error(`Server exited ${code}`)));
  });
  const { targetId } = await cdp('Target.createTarget', { url: 'about:blank' });
  session = (await cdp('Target.attachToTarget', { targetId, flatten: true })).sessionId;
  await cdp('Runtime.enable', {}, session); await cdp('Log.enable', {}, session);
  await cdp('Page.navigate', { url }, session);
  await wait(`document.getElementById('model')?.options.length === 9`);
  await evaluate(set('path', engineBin, 'input') + `document.getElementById('save').click()`);
  await wait(`!document.getElementById('machine').disabled`);
  const vector = JSON.parse(await readFile('crates/enigma-cli/tests/fixtures/wwii_reference_vectors.json', 'utf8'))[0];
  await evaluate(set('model', 'enigma-railway'));
  assert.equal(await evaluate(`document.getElementById('machine-plugboard').hidden && !document.getElementById('etw-position')`), true);
  await evaluate(set('reflector-ring', 'D') + set('reflector-position', 'J') + ['left', 'middle', 'right'].map((id, i) => set(`${id}-wheel`, ['III', 'II', 'I'][i]) + set(`${id}-ring`, ['F', 'C', 'P'][i]) + set(`${id}-position`, ['K', 'D', 'M'][i])).join('') + set('text', vector.plaintext, 'input') + `document.getElementById('start').click()`);
  await wait(`document.getElementById('output').value === ${JSON.stringify(vector.ciphertext)}`);
  console.log('PASS Railway external fixture through Machine page (114 letters)');
  await evaluate(`document.getElementById('view-attack').click()`);
  await evaluate(set('attack-model', 'enigma-railway'));
  assert.equal(await evaluate(`!document.getElementById('attack-pairs-editor') && !document.getElementById('attack-max_pairs') && !document.getElementById('attack-etw-position')`), true);
  await evaluate(set('attack-reflector-ring', 'D') + ['left', 'middle', 'right'].map((id, i) => set(`attack-${id}-wheel`, ['III', 'II', 'I'][i]) + set(`attack-${id}-ring`, ['F', 'C', 'P'][i]) + set(`attack-${id}-position`, ['K', 'D', 'M'][i])).join('') + set('attack-text', vector.ciphertext, 'input'));
  await wait(`!document.getElementById('attack-start').disabled`);
  const request = await evaluate(`JSON.parse(document.getElementById('attack-request').textContent)`);
  assert.equal(request.job.space.plugboard.max_pairs, 0);
  assert.equal(request.job.space.slots[0].positions.length, 26);
  await evaluate(`document.getElementById('attack-start').click()`);
  await wait(`document.querySelector('#attack-last progress')?.value === 100`);
  const attack = await evaluate(`fetch('/api/attack').then(r=>r.json()).then(r=>r.attack)`);
  assert.equal(attack.status, 'completed'); assert.equal(attack.outer_keys, '26'); assert.equal(attack.outers_selected, '26');
  console.log('PASS Railway attack through Attack page; preview = started = 26; max_pairs = 0');
  await evaluate(set('language', 'es'));
  assert.equal(await evaluate(`document.getElementById('attack-model').selectedOptions[0].textContent`), 'Enigma Railway (Reichsbahn)');
  // L26 independent wiring/key, entered in the default German notation.
  const ukwd = JSON.parse(await readFile('crates/enigma-cli/tests/fixtures/wwii_reference_vectors.json', 'utf8')).find(v => v.machine === 'enigma-i-ukwd');
  await evaluate(set('language', 'en') + `document.getElementById('view-machine').click()`);
  await evaluate(set('model', ukwd.machine));
  assert.equal(await evaluate(`document.getElementById('machine-notation').value`), 'german');
  assert.equal(await evaluate(`!document.getElementById('reflector-position') && !document.getElementById('reflector-ring')`), true);
  await evaluate(set('machine-wiring', ukwd.german_pairs.join(' '), 'input') + ['left', 'middle', 'right'].map((id, i) => set(`${id}-wheel`, ['V', 'III', 'II'][i]) + set(`${id}-ring`, ukwd.rings.rotors[i]) + set(`${id}-position`, ukwd.positions.rotors[i])).join(''));
  for (const pair of ukwd.plugboard) await evaluate(set('first', pair[0]) + set('second', pair[1]) + `document.getElementById('add-pair').click()`);
  await evaluate(set('text', ukwd.plaintext, 'input') + `document.getElementById('start').click()`);
  await wait(`document.getElementById('output').value === ${JSON.stringify(ukwd.ciphertext)}`);
  const slots = [{ id: 'reflector', wheel: 'D', ring: 'A', position: 'A', pairs: ukwd.reflector_pairs.map(p => [...p]) }, ...['left', 'middle', 'right'].map((id, i) => ({ id, wheel: ['V', 'III', 'II'][i], ring: ukwd.rings.rotors[i], position: ukwd.positions.rotors[i] }))];
  const cli = spawnSync(engineBin, ['--events', '-', '--request', '-'], { input: JSON.stringify({ protocol_version: 1, machine: { definition: { kind: 'bundled', id: ukwd.machine } }, job: { kind: 'transform', direction: 'encrypt', text: ukwd.plaintext, configuration: { slots, plugboard: ukwd.plugboard.map(p => [...p]) } } }), encoding: 'utf8' });
  assert.equal(cli.status, 0, cli.stderr);
  assert.equal(JSON.parse(cli.stdout.trim().split('\n')[1]).output, await evaluate(`document.getElementById('output').value`));
  console.log('PASS German-default UKW-D L26 transform = external vector = CLI');
  await evaluate(set('machine-notation', 'bp'));
  assert.equal(await evaluate(`document.getElementById('machine-wiring').value`), ukwd.reflector_pairs.join(' '));
  await evaluate(set('machine-wiring', 'AB', 'input'));
  assert.equal(await evaluate(`document.getElementById('start').disabled`), true);
  await evaluate(`document.getElementById('view-attack').click()`);
  await evaluate(set('attack-model', 'enigma-kd'));
  assert.equal(await evaluate(`!document.getElementById('attack-pairs-editor') && !document.getElementById('attack-max_pairs') && !document.getElementById('attack-etw-position') && !document.getElementById('attack-reflector-position')`), true);
  await evaluate(`document.getElementById('attack-search_reflector').click()`);
  assert.deepEqual(await evaluate(`Array.from(document.getElementById('attack-method').options).map(o=>o.value)`), ['hill_climb']);
  await evaluate(['left', 'middle', 'right'].map(id => set(`attack-${id}-position`, 'A')).join('') + set('attack-reflector_starts', '1', 'input') + set('attack-initial_measure', 'ic') + set('attack-final_measure', 'ic') + set('attack-text', 'ABCDEFGHIJKLMNOPQRSTUVWXYZ', 'input'));
  await evaluate(set('attack-backend', 'gpu'));
  await wait(`document.getElementById('attack-preview').textContent.includes('CPU') && document.getElementById('attack-start').disabled`);
  assert.equal(await evaluate(`document.getElementById('attack-backend').value`), 'gpu');
  await evaluate(set('attack-backend', 'cpu'));
  await wait(`!document.getElementById('attack-start').disabled`);
  const searched = await evaluate(`JSON.parse(document.getElementById('attack-request').textContent)`);
  assert.deepEqual(searched.job.space.slots[0].pairs, { kind: 'attack' });
  assert.equal(searched.job.attack.reflector_starts, 1);
  assert.equal(searched.job.space.plugboard.max_pairs, 0);
  await evaluate(`document.getElementById('attack-start').click()`);
  await wait(`document.querySelector('#attack-last progress')?.value === 100 && document.getElementById('attack-last').textContent.includes('UKW-D wiring (German)')`);
  const found = await evaluate(`fetch('/api/attack').then(r=>r.json()).then(r=>r.attack)`);
  assert.equal(found.status, 'completed');
  assert.equal(found.result.best.configuration.slots[0].pairs.length, 12);
  assert.equal(await evaluate(`document.getElementById('attack-last').textContent.includes('UKW-D wiring (BP)')`), true);
  await evaluate(set('language', 'es'));
  assert.equal(await evaluate(`document.getElementById('attack-last').textContent.includes('Cableado UKW-D (alemán)')`), true);
  console.log('PASS unknown-wiring CPU attack completed, BP/German results, explicit GPU block, KD fixed controls, es/en');
  // The deliberately rejected GPU preview is an expected HTTP 400, not a script/CSP failure.
  assert.deepEqual(browserErrors.filter(error => !(error.source === 'network' && error.url?.endsWith('/api/attack/preview') && error.text.includes('400 (Bad Request)'))), []);
  console.log('PASS Spanish rerender, hidden ETW/plugboard controls; no script/CSP errors');
} finally {
  clearTimeout(watchdog);
  const exited = Promise.all([server.exitCode === null ? once(server, 'exit') : null, chrome.exitCode === null ? once(chrome, 'exit') : null]);
  server.kill('SIGINT'); chrome.kill('SIGTERM');
  await exited;
  await rm(scratch, { recursive: true, force: true, maxRetries: 10, retryDelay: 100 });
  console.log(`Cleaned scratch: ${scratch}`);
}

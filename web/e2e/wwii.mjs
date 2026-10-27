// Optional real-browser smoke: from the root, node web/e2e/wwii.mjs.
// Requires target/enigma-web, target/release/enigma and Google Chrome.
// Scratch is deliberately retained and printed for manual removal.
import { spawn } from 'node:child_process';
import { mkdtemp, readFile } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { resolve, join } from 'node:path';
import assert from 'node:assert/strict';

const scratch = await mkdtemp(join(tmpdir(), 'enigma-web-wwii-'));
console.log(`Scratch: ${scratch}`);
const server = spawn(resolve('target/enigma-web'), ['--no-browser'], {
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
const watchdog = setTimeout(() => { console.error('Browser smoke timed out'); server.kill('SIGINT'); chrome.kill('SIGTERM'); process.exitCode = 1; }, 45000);
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
  await wait(`document.getElementById('model')?.options.length === 6`);
  await evaluate(set('path', resolve('target/release/enigma'), 'input') + `document.getElementById('save').click()`);
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
  assert.deepEqual(browserErrors, []);
  console.log('PASS Spanish rerender, hidden ETW/plugboard controls; no script/CSP errors');
} finally {
  clearTimeout(watchdog);
  server.kill('SIGINT'); chrome.kill('SIGTERM');
}

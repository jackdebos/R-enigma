// Run against separately built base/current web binaries; never reads Git history.
// ENIGMA_BASE_WEB_BIN, ENIGMA_WEB_BIN and ENIGMA_TEST_BIN must be absolute paths.
import { spawn } from 'node:child_process';
import { mkdtemp, rm } from 'node:fs/promises';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { once } from 'node:events';
import assert from 'node:assert/strict';

const scratch = await mkdtemp(join(tmpdir(), 'enigma-t13-differential-'));
console.log(`Scratch: ${scratch}`);
const children = [];
async function start(binary, name) {
  assert.ok(binary, `${name} binary is required`);
  const process = spawn(binary, ['--no-browser'], { env: { ...globalThis.process.env, ENIGMA_WEB_CONFIG: join(scratch, name, 'config.json') }, stdio: ['ignore', 'pipe', 'pipe'] });
  children.push(process);
  let stderr = '';
  process.stderr.on('data', data => { stderr += data; });
  const url = await new Promise((resolve, reject) => {
    let stdout = '';
    process.stdout.on('data', data => { stdout += data; const match = stdout.match(/http:\/\/127\.0\.0\.1:\d+\/\?token=[a-f0-9]+/); if (match) resolve(match[0]); });
    process.on('error', reject);
    process.on('exit', code => reject(new Error(`${name} exited ${code}: ${stderr}`)));
  });
  const bootstrap = await fetch(url, { redirect: 'manual' });
  const cookie = bootstrap.headers.get('set-cookie').split(';')[0];
  const origin = new URL(url).origin;
  return { process, stderr: () => stderr, post: async (route, body) => {
    const response = await fetch(origin + route, { method: 'POST', headers: { Origin: origin, Cookie: cookie, 'Content-Type': 'application/json' }, body: JSON.stringify(body) });
    return { status: response.status, body: await response.text() };
  } };
}
const watchdog = setTimeout(() => { for (const process of children) process.kill('SIGTERM'); }, 30000);
try {
  const base = await start(process.env.ENIGMA_BASE_WEB_BIN, 'base');
  const current = await start(process.env.ENIGMA_WEB_BIN, 'current');
  for (const server of [base, current]) assert.equal((await server.post('/api/engine', { path: process.env.ENIGMA_TEST_BIN })).status, 200);
  let comparisons = 0;
  for (const model of ['enigma-i', 'enigma-m3', 'enigma-m4', 'enigma-railway', 'enigma-g312', 'enigma-g260']) {
    const wwii = ['enigma-railway', 'enigma-g312', 'enigma-g260'].includes(model);
    const body = { model, reflector: wwii ? 'UKW' : model === 'enigma-m4' ? 'Thin-B' : 'B',
      ...(wwii ? { reflector_ring: 'D', reflector_position: 'J' } : {}),
      slots: [...(model === 'enigma-m4' ? [{ id: 'greek', wheel: 'Beta', ring: 'A', position: 'B' }] : []), ...['left', 'middle', 'right'].map((id, i) => ({ id, wheel: ['I', 'II', 'III'][i], ring: ['F', 'C', 'P'][i], position: ['K', 'U', 'D'][i] }))],
      plugboard: wwii ? [] : [['A', 'Z']], text: 'DIESXISTXEINXTESTDERMASCHINE' };
    // Real engine timestamps have whole-second resolution. Concurrent requests
    // exercise identical engine events without stripping or rewriting any bytes.
    const responses = await Promise.all([base.post('/api/transform', body), current.post('/api/transform', body)]);
    assert.equal(responses[0].status, 200);
    assert.deepEqual(responses[1], responses[0], `${model} transform response bytes`);
    comparisons++;
    const pairs = 'AZ CX DW EV FU GT HS IR JQ KP LN MY'.split(' ').map(pair => [...pair]);
    for (const [route, extra] of [
      ['/api/transform', { reflector_pairs: pairs }],
      ...['/api/attack/preview', '/api/attack'].flatMap(route => [
        [route, { reflector_pairs: pairs }], [route, { search_reflector: true }], [route, { search_reflector: false }], [route, { settings: { reflector_starts: 8 } }],
      ]),
    ]) {
      const input = { ...body, ...(route === '/api/transform' ? {} : { plugboard: { known: body.plugboard, search: !wwii } }), ...extra };
      const [before, after] = await Promise.all([base.post(route, input), current.post(route, input)]);
      assert.equal(before.status, 400);
      assert.deepEqual(after, before, `${model} ${route} ${JSON.stringify(extra)}`);
      comparisons++;
    }
    console.log(`PASS ${model}: real transform and new-field sibling rejections byte-identical`);
  }
  for (const server of [base, current]) assert.equal(server.stderr(), '');
  console.log(`PASS ${comparisons} HTTP status/body byte comparisons; stderr empty`);
} finally {
  clearTimeout(watchdog);
  const exits = children.map(process => process.exitCode === null ? once(process, 'exit') : [process.exitCode]);
  for (const process of children) process.kill('SIGINT');
  const codes = await Promise.all(exits);
  await rm(scratch, { recursive: true, force: true });
  console.log(`Cleaned scratch: ${scratch}`);
  assert.ok(codes.every(([code]) => code === 0), `web exit codes: ${JSON.stringify(codes)}`);
}

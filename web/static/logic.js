// Pure form logic: no browser state or DOM access.
const bpContacts = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ';
const germanContacts = 'A-ZXWVUTSRQPON-MLKIHGFEDCB';

export function convertUKWDPairs(pairs, from, to) {
  const source = from === 'bp' ? bpContacts : germanContacts;
  const target = to === 'bp' ? bpContacts : germanContacts;
  return pairs.map(pair => pair.map(contact => target[source.indexOf(contact)]));
}

// Input pairs are free contacts only; BO is supplied by the engine definition.
export function parseUKWD(text, notation = 'german') {
  const fail = error => ({ pairs: null, error });
  const words = text.trim() ? text.trim().split(/\s+/u) : [];
  if (words.length !== 12) return fail('ukwd_count');
  if (words.some(pair => Array.from(pair).length !== 2)) return fail('ukwd_pair');
  const contacts = notation === 'bp' ? 'ACDEFGHIJKLMNPQRSTUVWXYZ' : 'ABCDEFGHIKLMNOPQRSTUVWXZ';
  const pairs = words.map(pair => Array.from(pair));
  if (pairs.flat().some(contact => !contacts.includes(contact))) return fail(notation === 'bp' ? 'ukwd_bp_contacts' : 'ukwd_german_contacts');
  if (new Set(pairs.flat()).size !== 24) return fail('ukwd_reused');
  return { pairs: convertUKWDPairs(pairs, notation, 'bp'), error: null };
}

export function ukwDNotations(pairs) {
  return { bp: pairs.map(pair => pair.join('')).join(' '), german: convertUKWDPairs(pairs, 'bp', 'german').map(pair => pair.join('')).join(' ') };
}

function wiringSettings(state, attack = false) {
  if (!['enigma-i-ukwd', 'enigma-m3-ukwd', 'enigma-kd'].includes(state.model)) return {};
  if (attack && state.searchReflector) return { search_reflector: true };
  const { pairs, error } = parseUKWD(state.wiring || '', state.notation || 'german');
  if (error) throw new Error(error);
  return { reflector_pairs: pairs };
}
// The crib is sent exactly as typed, like the message: nothing is converted.
export function cribInfo(text) {
  return { text, short: Array.from(text).length < 14, ...checkText(text) };
}

// Apply recommendations only when choosing the method, never on render/load.
export function selectAttackMethod(state, method) {
  state.advanced.method = method;
  delete state.advanced.seeds;
  if (method === 'bombe') {
    state.advanced.backend = 'cpu';
    state.slots.forEach(slot => { slot.ring = slot.id === 'right' ? '' : 'A'; });
  }
}
export function checkText(text) {
  const offending = [];
  let hasLowercase = false;
  Array.from(text).forEach((character, index) => {
    if (!/^[A-Z]$/.test(character)) {
      offending.push({ character, position: index + 1 });
      if (character.toUpperCase() !== character) hasLowercase = true;
    }
  });
  return { offending, hasLowercase };
}

export function validatePair(pairs, first, second) {
  if (!/^[A-Z]$/.test(first) || !/^[A-Z]$/.test(second)) return 'pair_invalid';
  if (first === second) return 'pair_same';
  if (pairs.some(pair => pair.includes(first) || pair.includes(second))) return 'pair_reused';
  return null;
}

function reflectorSettings(state, unknown = false) {
  if (!Object.hasOwn(state, 'reflector_ring')) return {};
  return Object.fromEntries(['reflector_ring', 'reflector_position'].map(key => [key, unknown ? state[key] || null : state[key] ?? '']));
}

export function buildRequest(state) {
  return {
    model: state.model,
    reflector: state.reflector,
    ...reflectorSettings(state),
    ...wiringSettings(state),
    slots: state.slots.map(({ id, wheel, ring, position }) => ({ id, wheel, ring, position })),
    plugboard: state.plugboard.map(pair => [...pair]),
    text: state.text,
  };
}

export function backendSettings(advanced = {}) {
  const backend = advanced.backend ?? 'cpu';
  return { backend, ...(backend === 'gpu' ? { gpu_usage: Number(advanced.gpu_usage ?? 100) } : {}) };
}

export function buildAttackBody(state) {
  const numeric = new Set(['max_pairs', 'switch_pairs', 'backtrack_pairs', 'hold', 'threads', 'crib_position', 'reflector_starts']);
  const settings = {};
  for (const [key, value] of Object.entries(state.advanced || {})) {
    if (value === '' || value === undefined || value === null) continue;
    if (key === 'backend' || key === 'gpu_usage') continue;
    if (key === 'reflector_starts' && !state.searchReflector) continue;
    if (key === 'seeds' && state.advanced.method !== 'partial_exhaustion') continue;
    if ((key === 'crib' || key === 'crib_position') && state.advanced.method !== 'bombe') continue;
    if (key === 'tables') {
      const tables = Object.fromEntries(Object.entries(value).filter(([, path]) => path !== ''));
      if (Object.keys(tables).length) settings.tables = tables;
    } else settings[key] = numeric.has(key) ? Number(value) : structuredClone(value);
  }
  Object.assign(settings, backendSettings(state.advanced));
  settings.distinct_wheels = state.distinctWheels ?? true;
  return {
    model: state.model,
    reflector: state.reflector || null,
    ...reflectorSettings(state, true),
    ...wiringSettings(state, true),
    slots: state.slots.map(({ id, wheel, ring, position }) => ({ id, wheel: wheel || null, ring: ring || null, position: position || null })),
    plugboard: { known: state.plugboard.map(pair => [...pair]), search: state.search },
    text: state.text,
    ...(Object.keys(settings).length ? { settings } : {}),
  };
}

export function parseAttackInput(input) {
  return {
    model: input.model, reflector: input.reflector || '', ...reflectorSettings(input),
    ...(input.reflector_pairs || input.search_reflector ? { notation: 'german', wiring: input.reflector_pairs ? ukwDNotations(input.reflector_pairs).german : '', searchReflector: input.search_reflector || false } : {}),
    slots: input.slots.map(slot => Object.fromEntries(Object.entries(slot).map(([key, value]) => [key, value ?? '']))),
    plugboard: input.plugboard.known.map(pair => [...pair]), search: input.plugboard.search,
    distinctWheels: input.settings?.distinct_wheels ?? true,
    text: input.text, advanced: { backend: 'cpu', gpu_usage: 100, ...structuredClone(input.settings || {}) },
  };
}

export function estimateDuration(seconds) {
  seconds = Math.max(0, Number(seconds) || 0);
  const [scale, unit] = seconds < 60 ? [1, 'seconds'] : seconds < 3600 ? [60, 'minutes'] : seconds < 86400 ? [3600, 'hours'] : [86400, 'days'];
  return { value: Math.round(seconds / scale * 10) / 10, unit };
}

function clock(seconds) {
  if (!Number.isFinite(seconds)) return '--:--:--';
  seconds = Math.max(0, Math.floor(seconds));
  return [Math.floor(seconds / 3600), Math.floor(seconds / 60) % 60, seconds % 60].map(n => String(n).padStart(2, '0')).join(':');
}

export function progressInfo(attack) {
  const completed = String(attack?.counters?.outers_completed ?? '0');
  const selected = String(attack?.outers_selected ?? '0');
  const done = Math.max(0, Number(completed) || 0);
  const total = Math.max(0, Number(selected) || 0);
  const seconds = Math.max(0, Number(attack?.elapsed_ms) || 0) / 1000;
  return {
    percent: (total ? Math.min(100, done / total * 100) : 0).toFixed(1),
    elapsed: clock(seconds), eta: done > 0 && total > 0 ? clock(seconds * Math.max(0, total - done) / done) : '--:--:--',
    completed, selected, evaluations: String(attack?.counters?.evaluations_completed ?? '0'),
  };
}

export function holdEntries(result) {
  return result?.hold?.length ? result.hold : result?.best ? [result.best] : [];
}

export function groupFive(text) {
  const symbols = Array.from(text);
  const groups = [];
  for (let i = 0; i < symbols.length; i += 5) groups.push(symbols.slice(i, i + 5).join(''));
  return groups.join(' ');
}

export function lookup(dictionary, fallback, key, values = {}) {
  const template = dictionary[key] || fallback[key] || key;
  return template.replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match);
}

export function initialLanguage(saved, browser = '') {
  return saved === 'es' || saved === 'en' ? saved : (browser.toLowerCase().startsWith('es') ? 'es' : 'en');
}

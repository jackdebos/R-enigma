// Pure form logic: no browser state or DOM access.
export function normalizeCrib(text) {
  return text.toUpperCase().replace(/\s/gu, '');
}

export function cribInfo(text) {
  text = normalizeCrib(text);
  return { text, short: Array.from(text).length < 14, offending: checkText(text).offending };
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

export function buildRequest(state) {
  return {
    model: state.model,
    reflector: state.reflector,
    slots: state.slots.map(({ id, wheel, ring, position }) => ({ id, wheel, ring, position })),
    plugboard: state.plugboard.map(pair => [...pair]),
    text: state.text,
  };
}

export function buildAttackBody(state) {
  const numeric = new Set(['max_pairs', 'switch_pairs', 'backtrack_pairs', 'hold', 'threads', 'crib_position']);
  const settings = {};
  for (const [key, value] of Object.entries(state.advanced || {})) {
    if (value === '' || value === undefined || value === null) continue;
    if (key === 'backend' || key === 'gpu_usage') continue;
    if (key === 'seeds' && state.advanced.method !== 'partial_exhaustion') continue;
    if ((key === 'crib' || key === 'crib_position') && state.advanced.method !== 'bombe') continue;
    if (key === 'crib') { settings.crib = normalizeCrib(value); continue; }
    if (key === 'tables') {
      const tables = Object.fromEntries(Object.entries(value).filter(([, path]) => path !== ''));
      if (Object.keys(tables).length) settings.tables = tables;
    } else settings[key] = numeric.has(key) ? Number(value) : structuredClone(value);
  }
  settings.backend = state.advanced?.backend ?? 'cpu';
  if (settings.backend === 'gpu') settings.gpu_usage = Number(state.advanced?.gpu_usage ?? 100);
  settings.distinct_wheels = state.distinctWheels ?? true;
  return {
    model: state.model,
    reflector: state.reflector || null,
    slots: state.slots.map(({ id, wheel, ring, position }) => ({ id, wheel: wheel || null, ring: ring || null, position: position || null })),
    plugboard: { known: state.plugboard.map(pair => [...pair]), search: state.search },
    text: state.text,
    ...(Object.keys(settings).length ? { settings } : {}),
  };
}

export function parseAttackInput(input) {
  return {
    model: input.model, reflector: input.reflector || '',
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

// Pure form logic: no browser state, DOM access, or text normalization.
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

export function lookup(dictionary, fallback, key, values = {}) {
  const template = dictionary[key] || fallback[key] || key;
  return template.replace(/\{(\w+)\}/g, (match, name) => Object.hasOwn(values, name) ? String(values[name]) : match);
}

export function initialLanguage(saved, browser = '') {
  return saved === 'es' || saved === 'en' ? saved : (browser.toLowerCase().startsWith('es') ? 'es' : 'en');
}

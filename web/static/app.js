import { checkText, validatePair, buildRequest, lookup, initialLanguage } from './logic.js';

const $ = id => document.getElementById(id);
const alphabet = Array.from('ABCDEFGHIJKLMNOPQRSTUVWXYZ');
const dictionaries = {};
let language;
let models = [];
let savedEngine = null;
let engineBusy = false;
let working = false;
let state = { model: '', reflector: '', slots: [], plugboard: [], text: '' };
let textCheck = null;
const messages = new Map();
const t = (key, values) => lookup(dictionaries[language], dictionaries.en, key, values);

// All server/user text is inserted as text, never as HTML.
function element(tag, text, className) {
  const node = document.createElement(tag);
  if (text !== undefined) node.textContent = text;
  if (className) node.className = className;
  return node;
}
function message(id, key, values = {}) {
  messages.set(id, () => t(key, values));
  renderMessage(id);
}
function renderMessage(id) {
  $(id).textContent = messages.get(id)?.() || '';
}
function errorMessage(id, failure) {
  messages.set(id, () => {
    if (failure.network) return t('error_network');
    if (failure.status === 401) return t('error_unauthorized');
    const issue = failure.data?.error;
    const code = typeof issue === 'object' ? issue?.code : '';
    const key = `error_${code}`;
    if (failure.status === 422) {
      const engineKey = `engine_error_${code}`;
      const reason = dictionaries.en[engineKey] ? t(engineKey) : t('error_engine_generic', { code });
      return `${t('engine_rejection', { reason, code })} ${t('engine_detail', { message: issue?.message || '' })}`;
    }
    if (code === 'unsupported_version') {
      const version = pair => t('version_pair', pair);
      return t(key, { found: version(issue.found), supported: issue.supported.map(version).join('; ') });
    }
    return dictionaries.en[key] ? t(key) : t('error_generic');
  });
  renderMessage(id);
}
async function api(path, body) {
  let response;
  try {
    response = await fetch(path, {
      credentials: 'same-origin',
      ...(body === undefined ? {} : { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(body) }),
    });
  } catch {
    throw { network: true };
  }
  let data;
  try { data = await response.json(); } catch { throw { status: response.status }; }
  if (!response.ok) throw { status: response.status, data };
  return data;
}
function updateAvailability() {
  const ready = Boolean(savedEngine?.configured && savedEngine?.compatible);
  $('blocker').hidden = ready;
  $('machine').hidden = !ready || models.length === 0;
  $('machine').disabled = !ready || working || engineBusy;
  $('start').disabled = !ready || models.length === 0 || working || engineBusy;
  $('save').disabled = working || engineBusy;
  $('path').disabled = working || engineBusy;
  $('text').disabled = working;
  $('uppercase').disabled = working;
}
function showEngine(state) {
  if (state.error) errorMessage('engine-status', { data: state });
  else if (state.configured && state.compatible) message('engine-status', 'engine_ready', state);
  else message('engine-status', 'engine_missing');
}

// Native details provides keyboard-accessible, local help without inline handlers.
function help(labelKey, hintKey) {
  const details = element('details', undefined, 'help');
  const summary = element('summary', t('help_symbol'));
  summary.setAttribute('aria-label', t('help_label', { name: t(labelKey) }));
  details.append(summary, element('p', t(hintKey), 'hint'));
  return details;
}
function heading(container, key, hintKey) {
  const row = element('div', undefined, 'field-heading');
  row.append(element('span', t(key)), help(key, hintKey));
  container.append(row);
}
function selectField(container, { id, key, hint, values, value, optionKey, change, disabled = [] }) {
  const row = element('div', undefined, 'field-heading');
  const label = element('label', t(key));
  label.htmlFor = id;
  row.append(label);
  if (hint) row.append(help(key, hint));
  const select = element('select');
  select.id = id;
  for (const item of values) {
    const option = element('option', optionKey ? t(`${optionKey}_${item}`) : item);
    option.value = item;
    option.disabled = disabled.includes(item);
    select.append(option);
  }
  select.value = value;
  select.addEventListener('change', () => { change(select.value); clearResult(); });
  container.append(row, select);
  return select;
}
function chooseModel(id) {
  const model = models.find(model => model.id === id);
  state.model = id;
  state.reflector = model.reflectors[0];
  state.slots = model.slots.map((slot, i) => ({
    id: slot.id, wheel: slot.allowed_wheels[slot.id === 'greek' ? 0 : (i - (model.slots[0].id === 'greek' ? 1 : 0))], ring: 'A', position: 'A',
  }));
  state.plugboard = [];
  messages.delete('pair-error');
  $('pair-error').hidden = true;
  renderMachine();
}
function renderMachine() {
  if (!models.length) return;
  const model = models.find(model => model.id === state.model);
  for (const id of ['model-field', 'reflector-field', 'rotors', 'plugboard-heading']) $(id).replaceChildren();
  selectField($('model-field'), { id: 'model', key: 'model', hint: 'model_hint', values: models.map(model => model.id), value: state.model, optionKey: 'model', change: chooseModel });
  selectField($('reflector-field'), { id: 'reflector', key: 'reflector', hint: 'reflector_hint', values: model.reflectors, value: state.reflector, optionKey: 'reflector', change: value => { state.reflector = value; } });
  state.slots.forEach((slot, i) => {
    const block = element('div', undefined, 'rotor');
    block.append(element('h3', t(`slot_${slot.id}`)));
    const window = element('div', slot.position, 'letter-window');
    window.setAttribute('aria-hidden', 'true');
    block.append(window);
    for (const [key, values, optionKey] of [['wheel', model.slots[i].allowed_wheels, 'wheel'], ['ring', alphabet], ['position', alphabet]]) {
      const container = element('div', undefined, 'field');
      selectField(container, { id: `${slot.id}-${key}`, key, hint: `${key}_hint`, values, value: slot[key], optionKey, change: value => { slot[key] = value; if (key === 'position') window.textContent = value; } });
      block.append(container);
    }
    $('rotors').append(block);
  });
  heading($('plugboard-heading'), 'plugboard', 'plugboard_hint');
  renderPairs();
}
function renderPairs() {
  const first = $('first')?.value;
  const second = $('second')?.value;
  const used = state.plugboard.flat();
  const available = alphabet.filter(letter => !used.includes(letter));
  for (const [id, key, previous, index] of [['first', 'first_letter', first, 0], ['second', 'second_letter', second, 1]]) {
    const container = $(`${id}-field`);
    container.replaceChildren();
    selectField(container, { id, key, values: alphabet, value: available.includes(previous) ? previous : (available[index] || ''), disabled: used, change: () => {} });
    $(id).disabled = available.length === 0;
  }
  $('add-pair').disabled = available.length === 0;
  $('pairs').replaceChildren();
  state.plugboard.forEach(([first, second], index) => {
    const item = element('li');
    const button = element('button', t('remove_pair', { first, second }));
    button.type = 'button';
    button.addEventListener('click', () => {
      state.plugboard.splice(index, 1);
      $('pair-error').hidden = true;
      clearResult();
      renderPairs();
    });
    item.append(button);
    $('pairs').append(item);
  });
  $('pair-count').textContent = t('pair_count', { count: state.plugboard.length });
}
function characterLabel(character) {
  const special = { ' ': 'char_space', '\n': 'char_newline', '\t': 'char_tab', '\r': 'char_return' };
  return special[character] ? t(special[character]) : t('char_other', { character, code: character.codePointAt(0).toString(16).toUpperCase().padStart(4, '0') });
}
function renderTextCheck() {
  $('text-errors').hidden = !textCheck?.offending.length;
  $('uppercase').hidden = !textCheck?.hasLowercase;
  $('offending').replaceChildren();
  for (const { character, position } of textCheck?.offending || []) {
    $('offending').append(element('li', t('offending', { character: characterLabel(character), position })));
  }
}
function clearResult() {
  $('result').hidden = true;
  $('output').value = '';
  messages.delete('copy-status');
  renderMessage('copy-status');
}
function translatePage() {
  document.documentElement.lang = language;
  document.title = t('title');
  $('language').value = language;
  for (const node of document.querySelectorAll('[data-i18n]')) node.textContent = t(node.dataset.i18n);
  $('start').textContent = t(working ? 'working' : 'start');
  $('save').textContent = t(engineBusy ? 'loading' : 'save');
  for (const id of messages.keys()) renderMessage(id);
  renderMachine();
  renderTextCheck();
  updateAvailability();
}
async function loadCatalog() {
  try {
    models = (await api('/api/machines')).models;
    chooseModel(models[0].id);
    $('catalog-error').hidden = true;
  } catch (failure) {
    errorMessage('catalog-error', failure);
    $('catalog-error').hidden = false;
  }
}
async function loadEngine() {
  try {
    savedEngine = await api('/api/engine');
    $('path').value = savedEngine.path;
    showEngine(savedEngine);
  } catch (failure) {
    savedEngine = null;
    errorMessage('engine-status', failure);
  }
  updateAvailability();
}

async function init() {
  // Dictionaries are the only source of UI copy, including errors and hints.
  const entries = await Promise.all(['es', 'en'].map(async lang => {
    const response = await fetch(`/i18n/${lang}.json`, { credentials: 'same-origin' });
    if (!response.ok) throw new Error('dictionary unavailable');
    return [lang, await response.json()];
  }));
  Object.assign(dictionaries, Object.fromEntries(entries));
  let saved;
  try { saved = localStorage.getItem('enigma-language'); } catch { /* Storage can be blocked; the page still works. */ }
  language = initialLanguage(saved, navigator.language);
  translatePage();
  $('language').addEventListener('change', () => {
    language = $('language').value;
    try { localStorage.setItem('enigma-language', language); } catch { /* Optional preference only. */ }
    translatePage();
  });
  $('engine-form').addEventListener('submit', async event => {
    event.preventDefault();
    if (engineBusy || working) return;
    engineBusy = true;
    message('engine-status', 'loading');
    $('save').textContent = t('loading');
    updateAvailability();
    try {
      savedEngine = await api('/api/engine', { path: $('path').value });
      showEngine(savedEngine);
      if (!models.length) await loadCatalog();
    } catch (failure) {
      // A rejected candidate does not replace the saved engine or erase the form.
      errorMessage('engine-status', failure);
    } finally {
      engineBusy = false;
      $('save').textContent = t('save');
      updateAvailability();
    }
  });
  $('add-pair').addEventListener('click', () => {
    const first = $('first').value;
    const second = $('second').value;
    const issue = validatePair(state.plugboard, first, second);
    $('pair-error').hidden = !issue;
    if (issue) { message('pair-error', issue); return; }
    state.plugboard.push([first, second]);
    clearResult();
    renderPairs();
  });
  $('text').addEventListener('input', () => {
    textCheck = null;
    renderTextCheck();
    messages.delete('message-status');
    renderMessage('message-status');
    clearResult();
  });
  $('uppercase').addEventListener('click', () => {
    $('text').value = $('text').value.toUpperCase();
    textCheck = null;
    renderTextCheck();
    clearResult();
    message('message-status', 'uppercase_done');
    $('text').focus();
  });
  $('message-form').addEventListener('submit', async event => {
    event.preventDefault();
    if ($('start').disabled) return;
    clearResult();
    messages.delete('message-status');
    renderMessage('message-status');
    textCheck = checkText($('text').value);
    renderTextCheck();
    if (textCheck.offending.length) return;
    state.text = $('text').value;
    working = true;
    $('start').textContent = t('working');
    updateAvailability();
    try {
      const data = await api('/api/transform', buildRequest(state));
      $('output').value = data.output;
      $('result').hidden = false;
      $('lamps').replaceChildren();
      for (const letter of alphabet) $('lamps').append(element('span', letter, letter === data.output.at(-1) ? 'lamp lit' : 'lamp'));
    } catch (failure) {
      errorMessage('message-status', failure);
      if (failure.status === 409) {
        savedEngine = null;
        // Keep the engine error visible above, without discarding the message or settings.
        errorMessage('engine-status', failure);
      }
    } finally {
      working = false;
      $('start').textContent = t('start');
      updateAvailability();
    }
  });
  $('copy').addEventListener('click', async () => {
    try {
      await navigator.clipboard.writeText($('output').value);
      message('copy-status', 'copied');
    } catch { message('copy-status', 'copy_failed'); }
  });
  message('engine-status', 'loading');
  await Promise.all([loadEngine(), loadCatalog()]);
  updateAvailability();
}

await init();

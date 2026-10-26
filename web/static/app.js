import { cribInfo, selectAttackMethod, checkText, validatePair, buildRequest, lookup, initialLanguage, buildAttackBody, parseAttackInput, estimateDuration, progressInfo, holdEntries, groupFive } from './logic.js';

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
  updateAttackAvailability();
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
function selectField(container, { id, key, hint, values, value, optionKey, change, disabled = [], clear = true }) {
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
  select.addEventListener('change', () => { change(select.value); if (clear) clearResult(); });
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
  renderAttack();
  renderAttackLast();
}
async function loadCatalog() {
  try {
    models = (await api('/api/machines')).models;
    chooseModel(models[0].id);
    if (!attackState) { chooseAttackModel(models[0].id); renderAttack(); attackChanged(); }
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
  initAttack();
}

// Attack state stays separate from the machine form. Only explicit Start runs an engine.
const measures = ['ic', 'entropy', 'sinkov_monogram', 'sinkov_bigram', 'sinkov_trigram', 'sinkov_quadgram', 'sinkov_pentagram', 'sinkov_hexagram', 'trie'];
const defaultStages = [{ pass: 'reswapping', measure: 'sinkov_trigram' }, { pass: 'measure', measure: 'sinkov_trigram' }];
let attackState = null;
let attackView = false;
let preview = null;
let previewFailure = null;
let previewTimer;
let previewVersion = 0;
let previewPending = true;
let attackLast = null;
let attackFailure = null;
let attackBusy = false;
let pollTimer;
let pollInFlight = false;
let attackVersion = 0;
let advancedOpen = false;
let requestOpen = false;

function chooseAttackModel(id) {
  const model = models.find(item => item.id === id);
  attackState = {
    model: id, reflector: model.reflectors[0],
    slots: model.slots.map((slot, i) => ({ id: slot.id,
      wheel: slot.allowed_wheels[slot.id === 'greek' ? 0 : i - (model.slots[0].id === 'greek' ? 1 : 0)],
      ring: 'A', position: '',
    })), plugboard: [], search: true, distinctWheels: true, text: attackState?.text || '', advanced: {},
  };
}
function attackIssue(failure) {
  if (failure.network) return t('error_network');
  if (failure.status === 401) return t('error_unauthorized');
  const issue = failure.data?.error || failure;
  const key = issue.field === 'settings/distinct_wheels' ? 'error_distinct_wheels' : `error_${issue.code}`;
  const engineKey = `engine_error_${issue.code}`;
  const reason = dictionaries.en[key] ? t(key) : dictionaries.en[engineKey] ? t(engineKey) : t('error_generic');
  return `${reason} ${issue.message || ''}${issue.field ? ` (${issue.field})` : ''}`;
}
function attackSelect(parent, key, values, value, change, { unknown = false, optionKey, hint = `${key}_hint`, id = `attack-${key}` } = {}) {
  const container = element('div', undefined, 'field');
  const select = selectField(container, { id, key, hint, values: unknown ? ['', ...values] : values,
    value: value ?? '', optionKey, clear: false, change });
  if (unknown) select.options[0].textContent = t('unknown');
  parent.append(container);
  return select;
}
function attackInput(parent, key, value, change, { type = 'text', placeholder = '', id = `attack-${key}`, hint = `${key}_hint`, min, max } = {}) {
  const container = element('div', undefined, 'field');
  const row = element('div', undefined, 'field-heading');
  const label = element('label', t(key));
  label.htmlFor = id;
  row.append(label, help(key, hint));
  const input = element('input');
  input.id = id;
  input.type = type;
  input.value = value;
  input.placeholder = placeholder;
  input.spellcheck = false;
  if (min !== undefined) input.min = min;
  if (max !== undefined) input.max = max;
  input.addEventListener('input', () => change(input.value));
  container.append(row, input);
  parent.append(container);
  return input;
}
function attackCheckbox(parent, key, checked, change, id = `attack-${key}`) {
  const row = element('div', undefined, 'field-heading');
  const input = element('input');
  input.type = 'checkbox'; input.id = id; input.name = key; input.checked = checked;
  const label = element('label', t(key)); label.htmlFor = id;
  input.addEventListener('change', () => change(input.checked));
  row.append(input, label, help(key, `${key}_hint`));
  parent.append(row);
  return input;
}
function attackChanged() {
  // Resource overrides are meaningful only for measures currently in use.
  if (attackState.advanced.tables) {
    const used = attackMeasures();
    attackState.advanced.tables = Object.fromEntries(Object.entries(attackState.advanced.tables).filter(([measure]) => used.includes(measure)));
  }
  previewPending = true;
  preview = null;
  previewFailure = null;
  const version = ++previewVersion;
  clearTimeout(previewTimer);
  renderAttackTextCheck();
  renderCribWarning();
  renderAttackPreview();
  updateAttackAvailability();
  previewTimer = setTimeout(() => loadAttackPreview(version), 300);
}
async function loadAttackPreview(version) {
  const body = buildAttackBody(attackState);
  try {
    const data = await api('/api/attack/preview', body);
    if (version !== previewVersion) return;
    preview = data;
  } catch (failure) {
    if (version !== previewVersion) return;
    previewFailure = failure;
  } finally {
    if (version === previewVersion) {
      previewPending = false;
      renderAttackPreview();
      updateAttackAvailability();
    }
  }
}
function attackMeasures() {
  const settings = attackState.advanced;
  const used = [settings.initial_measure || 'ic', settings.final_measure || 'sinkov_trigram'];
  for (const stage of settings.stages ?? defaultStages) {
    if (stage.pass === 'trie') used.push('trie');
    if (stage.pass !== 'trie') used.push(stage.measure || (stage.pass === 'reswapping' ? 'sinkov_trigram' : 'ic'));
    if (stage.base_measure) used.push(stage.base_measure);
  }
  return [...new Set(used.filter(measure => measure.startsWith('sinkov_') || measure === 'trie'))];
}
function renderAttackAdvanced(parent) {
  const details = element('details');
  details.open = advancedOpen;
  details.append(element('summary', t('advanced')));
  details.addEventListener('toggle', () => { advancedOpen = details.open; });
  const fields = element('div', undefined, 'advanced-grid');
  const settings = attackState.advanced;
  if (settings.method === 'bombe') {
    const rings = element('div', undefined, 'advanced-grid');
    attackState.slots.forEach(slot => {
      const select = attackSelect(rings, 'ring', alphabet, slot.ring, value => { slot.ring = value; attackChanged(); }, { unknown: true, id: `attack-${slot.id}-ring`, hint: 'attack_ring_hint' });
      select.previousElementSibling.querySelector('label').textContent = `${t(`slot_${slot.id}`)} · ${t('ring')}`;
    });
    details.append(rings);
  }
  if (settings.method === 'partial_exhaustion') {
    attackSelect(fields, 'seeds', ['all', 'touching'], settings.seeds ? 'touching' : 'all', value => {
      if (value === 'all') delete settings.seeds;
      else settings.seeds = [];
      attackChanged(); renderAttack();
    }, { optionKey: 'seeds' });
    if (settings.seeds) attackInput(fields, 'seed_letters', settings.seeds.join(''), value => { settings.seeds = Array.from(value); attackChanged(); });
  }
  for (const [key, fallback] of [['initial_measure', 'ic'], ['final_measure', 'sinkov_trigram']]) {
    attackSelect(fields, key, measures, settings[key] || fallback, value => { settings[key] = value; attackChanged(); renderAttack(); });
  }
  const stages = element('div', undefined, 'stage-fields');
  heading(stages, 'stages', 'stages_hint');
  for (const pass of ['reswapping', 'measure', 'trie']) {
    const selected = (settings.stages ?? defaultStages).find(stage => stage.pass === pass);
    attackCheckbox(stages, `stage_${pass}`, Boolean(selected), checked => {
      const list = structuredClone(settings.stages ?? defaultStages).filter(stage => stage.pass !== pass);
      if (checked) list.push(pass === 'trie' ? { pass, base_measure: 'sinkov_trigram' } : { pass, measure: 'sinkov_trigram' });
      settings.stages = ['reswapping', 'measure', 'trie'].flatMap(name => list.filter(stage => stage.pass === name));
      attackChanged(); renderAttack();
    });
    if (selected) {
      const key = pass === 'trie' ? 'base_measure' : 'stage_score';
      const member = pass === 'trie' ? 'base_measure' : 'measure';
      const values = pass === 'trie' ? ['', ...measures] : measures;
      const select = attackSelect(stages, key, values, selected[member] ?? (pass === 'trie' ? '' : pass === 'measure' ? 'ic' : 'sinkov_trigram'), value => {
        const list = structuredClone(settings.stages ?? defaultStages);
        const stage = list.find(stage => stage.pass === pass);
        if (value) stage[member] = value; else delete stage[member];
        settings.stages = list;
        attackChanged(); renderAttack();
      }, { id: `attack-${pass}-measure` });
      if (pass === 'trie') select.options[0].textContent = t('previous_measure');
    }
  }
  details.append(fields, stages);
  const numbers = element('div', undefined, 'advanced-grid');
  for (const [key, placeholder, min, max] of [['max_pairs', '13', 0, 13], ['switch_pairs', '7', 0, 13], ['backtrack_pairs', '5', 0, 13], ['hold', '5', 1, 1000], ['threads', t('threads_default'), 1, 256]]) {
    attackInput(numbers, key, settings[key] ?? '', value => { if (value === '') delete settings[key]; else settings[key] = value; attackChanged(); }, { type: 'number', placeholder, min, max });
  }
  const backend = attackSelect(numbers, 'backend', ['cpu', 'gpu'], settings.backend ?? 'cpu', value => {
    settings.backend = value; attackChanged(); renderAttack();
  }, { optionKey: 'backend' });
  if (settings.method === 'bombe') {
    backend.querySelector('[value="gpu"]').disabled = true;
    numbers.append(element('p', t('bombe_cpu'), 'hint'));
  }
  if (settings.backend === 'gpu') {
    attackInput(numbers, 'gpu_usage', settings.gpu_usage ?? 100, value => {
      if (value === '') delete settings.gpu_usage; else settings.gpu_usage = value;
      attackChanged();
    }, { type: 'number', min: 1, max: 100, placeholder: '100' });
  }
  details.append(numbers, element('p', t('table_format'), 'hint'));
  const tables = element('div', undefined, 'advanced-grid');
  for (const measure of attackMeasures()) {
    const input = attackInput(tables, 'own_table', settings.tables?.[measure] || '', value => {
      settings.tables ||= {};
      settings.tables[measure] = value;
      attackChanged();
    }, { id: `attack-table-${measure}`, placeholder: ['sinkov_bigram', 'sinkov_trigram'].includes(measure) ? t('builtin_table') : t('table_required') });
    input.previousElementSibling.querySelector('label').textContent = `${t('own_table')} · ${measure}`;
  }
  details.append(tables);
  parent.append(details);
}
function renderAttack() {
  if (!attackState) return;
  const root = $('attack-form');
  root.replaceChildren();
  const model = models.find(model => model.id === attackState.model);
  const form = element('form'); form.id = 'attack-settings';
  const controls = element('fieldset'); controls.id = 'attack-controls';
  const modelRow = element('div', undefined, 'model-row');
  attackSelect(modelRow, 'model', models.map(model => model.id), attackState.model, value => { chooseAttackModel(value); attackChanged(); renderAttack(); }, { optionKey: 'model' });
  attackSelect(modelRow, 'reflector', model.reflectors, attackState.reflector, value => { attackState.reflector = value; attackChanged(); }, { unknown: true, optionKey: 'reflector' });
  controls.append(modelRow);
  attackSelect(controls, 'method', ['hill_climb', 'partial_exhaustion', 'bombe'], attackState.advanced.method || 'hill_climb', value => {
    selectAttackMethod(attackState, value);
    attackChanged(); renderAttack();
  }, { optionKey: 'method' });
  if (attackState.advanced.method === 'bombe') {
    attackInput(controls, 'crib', attackState.advanced.crib || '', value => { attackState.advanced.crib = value; attackChanged(); });
    attackInput(controls, 'crib_position', attackState.advanced.crib_position ?? '', value => { attackState.advanced.crib_position = value; attackChanged(); }, { type: 'number', min: 0 });
    const warning = element('p', undefined, 'notice'); warning.id = 'attack-crib-warning';
    warning.setAttribute('role', 'status'); controls.append(warning);
  }
  const rotors = element('div', undefined, 'rotors');
  attackState.slots.forEach((slot, i) => {
    const block = element('div', undefined, 'rotor'); block.append(element('h3', t(`slot_${slot.id}`)));
    for (const [key, values, optionKey] of [['wheel', model.slots[i].allowed_wheels, 'wheel'], ['ring', alphabet], ['position', alphabet]]) {
      if (key === 'ring' && attackState.advanced.method === 'bombe') continue;
      attackSelect(block, key, values, slot[key], value => { slot[key] = value; attackChanged(); }, {
        unknown: true, optionKey, id: `attack-${slot.id}-${key}`, hint: key === 'ring' ? 'attack_ring_hint' : `${key}_hint`,
      });
    }
    rotors.append(block);
  });
  controls.append(rotors);
  attackCheckbox(controls, 'distinct_wheels', attackState.distinctWheels, checked => { attackState.distinctWheels = checked; attackChanged(); });
  heading(controls, 'plugboard', 'attack_plugboard_hint');
  const pairs = element('div'); pairs.id = 'attack-pairs-editor'; controls.append(pairs);
  attackCheckbox(controls, 'search_plugboard', attackState.search, checked => { attackState.search = checked; attackChanged(); });
  const textRow = element('div', undefined, 'field-heading');
  const textLabel = element('label', t('ciphertext')); textLabel.htmlFor = 'attack-text';
  textRow.append(textLabel, help('ciphertext', 'ciphertext_hint'));
  const text = element('textarea'); text.id = 'attack-text'; text.rows = 5;
  text.value = attackState.text; text.spellcheck = false;
  text.setAttribute('autocapitalize', 'off'); text.autocomplete = 'off';
  text.addEventListener('input', () => { attackState.text = text.value; attackChanged(); });
  const errors = element('div'); errors.id = 'attack-text-errors'; errors.setAttribute('role', 'alert');
  const uppercase = element('button', t('uppercase')); uppercase.type = 'button'; uppercase.id = 'attack-uppercase';
  uppercase.addEventListener('click', () => { attackState.text = text.value.toUpperCase(); text.value = attackState.text; attackChanged(); });
  controls.append(textRow, text, errors, uppercase);
  renderAttackAdvanced(controls);
  const estimate = element('div'); estimate.id = 'attack-preview'; estimate.setAttribute('aria-live', 'polite');
  const requestDetails = element('details'); requestDetails.open = requestOpen;
  requestDetails.append(element('summary', t('show_request')));
  requestDetails.addEventListener('toggle', () => { requestOpen = requestDetails.open; });
  const request = element('pre'); request.id = 'attack-request'; request.tabIndex = 0;
  requestDetails.append(request);
  const failure = element('p'); failure.id = 'attack-action-error'; failure.setAttribute('role', 'alert');
  const start = element('button', t('attack_start')); start.id = 'attack-start'; start.type = 'submit';
  controls.append(estimate, requestDetails, failure, start);
  form.append(controls);
  form.addEventListener('submit', event => {
    event.preventDefault();
    if (!$('attack-start').disabled) attackAction('/api/attack', buildAttackBody(attackState));
  });
  root.append(form);
  renderAttackPairs(); renderAttackTextCheck(); renderCribWarning(); renderAttackPreview(); updateAttackAvailability();
}
function renderAttackPairs() {
  const root = $('attack-pairs-editor');
  const previous = [$('attack-first')?.value, $('attack-second')?.value];
  root.replaceChildren();
  const row = element('div', undefined, 'pairs-editor');
  const used = attackState.plugboard.flat();
  const available = alphabet.filter(letter => !used.includes(letter));
  ['first', 'second'].forEach((id, index) => {
    const select = attackSelect(row, `${id}_letter`, alphabet, available.includes(previous[index]) ? previous[index] : available[index] || '', () => {}, { id: `attack-${id}`, hint: 'attack_plugboard_hint' });
    for (const option of select.options) option.disabled = used.includes(option.value);
    select.disabled = available.length === 0;
  });
  const add = element('button', t('add_pair')); add.type = 'button'; add.disabled = !available.length;
  const error = element('p'); error.setAttribute('role', 'alert');
  add.addEventListener('click', () => {
    const first = $('attack-first').value, second = $('attack-second').value;
    const issue = validatePair(attackState.plugboard, first, second);
    if (issue) { error.textContent = t(issue); return; }
    attackState.plugboard.push([first, second]); attackChanged(); renderAttackPairs();
  });
  row.append(add);
  const list = element('ul', undefined, 'pairs');
  attackState.plugboard.forEach(([first, second], index) => {
    const item = element('li'); const remove = element('button', t('remove_pair', { first, second })); remove.type = 'button';
    remove.addEventListener('click', () => { attackState.plugboard.splice(index, 1); attackChanged(); renderAttackPairs(); });
    item.append(remove); list.append(item);
  });
  root.append(row, error, element('p', t('pair_count', { count: attackState.plugboard.length }), 'hint'), list);
}
function renderAttackTextCheck() {
  if (!$('attack-text-errors')) return;
  const check = checkText(attackState.text);
  const errors = $('attack-text-errors'); errors.replaceChildren(); errors.hidden = !check.offending.length;
  if (check.offending.length) {
    errors.append(element('p', t('invalid_text_intro')));
    const list = element('ul', undefined, 'offending-list');
    for (const { character, position } of check.offending) list.append(element('li', t('offending', { character: characterLabel(character), position })));
    errors.append(list);
  }
  $('attack-uppercase').hidden = !check.hasLowercase;
}
function renderCribWarning() {
  const warning = $('attack-crib-warning');
  if (!warning) return;
  const info = cribInfo(attackState.advanced.crib || '');
  warning.hidden = !info.short;
  warning.textContent = t('crib_short');
}
function groupedNumber(value) {
  try { return BigInt(value ?? 0).toLocaleString(language); } catch { return String(value ?? 0); }
}
function renderAttackPreview() {
  if (!$('attack-preview')) return;
  const root = $('attack-preview'); root.replaceChildren();
  if (previewPending) root.append(element('p', t('preview_loading'), 'hint'));
  else if (previewFailure) {
    const error = element('p', attackIssue(previewFailure)); error.setAttribute('role', 'alert'); root.append(error);
  } else if (preview) {
    const duration = estimateDuration(preview.estimate_seconds);
    root.append(element('p', t('key_count', { count: groupedNumber(preview.outer_keys) })),
      element('p', t('estimate_time', { value: duration.value.toLocaleString(language), unit: t(`duration_${duration.unit}`) })),
      element('p', t('estimate_hint'), 'hint'));
    if (preview.estimate_seconds > 3600) root.append(element('p', t(preview.estimate_seconds > 86400 ? 'estimate_very_long' : 'estimate_long'), preview.estimate_seconds > 86400 ? 'notice strong-notice' : 'notice'));
  }
  if (!attackState.distinctWheels && attackState.slots.some(slot => !slot.wheel)) root.append(element('p', t('repeated_wheels'), 'hint'));
  $('attack-request').textContent = preview ? JSON.stringify(preview.request, null, 2) : '';
}
function updateAttackAvailability() {
  if (!$('attack-start')) return;
  const ready = Boolean(savedEngine?.configured && savedEngine?.compatible);
  $('attack-controls').disabled = attackBusy;
  $('attack-start').disabled = !ready || engineBusy || attackBusy || attackLast?.status === 'running' || previewPending || !preview || Boolean(previewFailure) || checkText(attackState.text).offending.length > 0;
  $('attack-action-error').textContent = attackFailure ? attackIssue(attackFailure) : '';
}
async function attackAction(path, body = {}) {
  if (attackBusy) return;
  attackVersion++;
  attackBusy = true; attackFailure = null; updateAttackAvailability(); renderAttackLast();
  try {
    attackLast = (await api(path, body)).attack;
  } catch (failure) { attackFailure = failure; }
  finally { attackBusy = false; updateAttackAvailability(); renderAttackLast(); scheduleAttackPoll(); }
}
function renderAttackLast() {
  const root = $('attack-last');
  if (!root) return;
  root.replaceChildren();
  root.append(element('h2', t('last_attack')));
  if (attackFailure) {
    const error = element('p', attackIssue(attackFailure)); error.setAttribute('role', 'alert'); root.append(error);
  }
  if (!attackLast) { root.append(element('p', t('no_attack'), 'hint')); return; }
  const attack = attackLast;
  root.append(element('h3', t(`status_${attack.status}`)), element('p', t('attack_directory', { directory: attack.directory })));
  const progress = progressInfo(attack);
  const bar = element('progress'); bar.max = 100; bar.value = Number(progress.percent);
  bar.setAttribute('aria-label', t('attack_progress')); bar.textContent = `${progress.percent}%`;
  root.append(bar, element('p', t('progress_counts', { percent: progress.percent, completed: groupedNumber(progress.completed), selected: groupedNumber(progress.selected) })),
    element('p', t('progress_times', { elapsed: progress.elapsed, eta: progress.eta, evaluations: groupedNumber(progress.evaluations) })));
  const actions = element('div', undefined, 'attack-actions');
  function action(key, callback) {
    const button = element('button', t(key)); button.type = 'button'; button.disabled = attackBusy;
    button.addEventListener('click', callback); actions.append(button);
  }
  if (attack.status === 'running') {
    action('attack_cancel', () => attackAction('/api/attack/cancel'));
    root.append(element('p', t('cancel_hint'), 'hint'));
  }
  if (['cancelled', 'interrupted'].includes(attack.status) && attack.resumable) action('attack_resume', () => {
    const { backend, gpu_usage } = buildAttackBody(attackState).settings;
    attackAction('/api/attack/resume', { backend, ...(backend === 'gpu' ? { gpu_usage } : {}) });
  });
  if (attack.input) action('load_setup', () => {
    attackState = parseAttackInput(attack.input); attackFailure = null; attackChanged(); renderAttack();
  });
  root.append(actions);
  if (attack.error) {
    const error = element('p', attackIssue(attack.error)); error.setAttribute('role', 'alert'); root.append(error);
  }
  if (attack.status === 'failed' || attack.stderr) {
    const details = element('details'); details.append(element('summary', t('engine_stderr')), element('pre', attack.stderr || t('no_stderr'))); root.append(details);
  }
  if (attack.status === 'cancelled') root.append(element('p', t('partial_results'), 'notice'));
  const crib = attack.result?.crib;
  if (crib) root.append(element('p', t('crib_summary', { text: crib.text, positions: groupedNumber(crib.positions?.length), settings: groupedNumber(crib.settings), stops: groupedNumber(crib.stops) })));
  const list = element('ol', undefined, 'attack-results');
  for (const entry of holdEntries(attack.result)) {
    const candidate = entry;
    const item = element('li');
    item.append(element('h3', t('candidate_score', { score: candidate.score?.measured ?? '—', measure: candidate.score?.measure ?? '—' })));
    if (candidate.crib_position !== undefined) item.append(element('p', t('result_crib_position', { position: candidate.crib_position })));
    const slots = candidate.configuration?.slots || [];
    for (const [key, member] of [['wheels', 'wheel'], ['rings', 'ring'], ['positions', 'position']]) {
      item.append(element('p', t(`result_${key}`, { value: slots.map(slot => `${t(`slot_${slot.id}`)}: ${slot[member]}`).join(' · ') })));
    }
    item.append(element('p', t('result_plugboard', { value: candidate.configuration?.plugboard?.map(pair => pair.join('–')).join(' ') || t('no_pairs') })));
    const plaintext = element('textarea'); plaintext.readOnly = true; plaintext.rows = 4;
    plaintext.value = groupFive(candidate.plaintext || ''); plaintext.setAttribute('aria-label', t('plaintext'));
    const copy = element('button', t('copy')); copy.type = 'button';
    const status = element('p'); status.setAttribute('role', 'status');
    copy.addEventListener('click', async () => {
      try { await navigator.clipboard.writeText(plaintext.value); status.textContent = t('copied'); }
      catch { status.textContent = t('copy_failed'); }
    });
    item.append(plaintext, copy, status); list.append(item);
  }
  root.append(list);
}
function scheduleAttackPoll() {
  clearTimeout(pollTimer);
  if (attackView && !document.hidden && attackLast?.status === 'running') pollTimer = setTimeout(loadAttackLast, 1000);
}
async function loadAttackLast() {
  if (pollInFlight) return;
  pollInFlight = true;
  const version = attackVersion;
  try {
    const data = await api('/api/attack');
    if (version === attackVersion) { attackLast = data.attack; attackFailure = null; }
  } catch (failure) { if (version === attackVersion) attackFailure = failure; }
  finally { pollInFlight = false; renderAttackLast(); updateAttackAvailability(); scheduleAttackPoll(); }
}
function selectView(attack, load = true) {
  attackView = attack;
  $('machine-view').hidden = attack;
  $('attack-view').hidden = !attack;
  $('view-machine').setAttribute('aria-pressed', String(!attack));
  $('view-attack').setAttribute('aria-pressed', String(attack));
  try { localStorage.setItem('enigma-view', attack ? 'attack' : 'machine'); } catch { /* Optional preference only. */ }
  clearTimeout(pollTimer);
  if (attack && load) loadAttackLast();
}
function initAttack() {
  let saved;
  try { saved = localStorage.getItem('enigma-view'); } catch { /* Optional preference only. */ }
  selectView(saved === 'attack', false);
  $('view-machine').addEventListener('click', () => selectView(false));
  $('view-attack').addEventListener('click', () => selectView(true));
  document.addEventListener('visibilitychange', () => {
    clearTimeout(pollTimer);
    if (!document.hidden && attackView) loadAttackLast();
  });
  loadAttackLast();
}

await init();

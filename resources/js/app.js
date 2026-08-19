/**
 * View wiring.
 *
 * Everything with a decision in it lives in ./core; this file's job is to move
 * values between the DOM and those modules, and to make sure every failure ends
 * up somewhere a person can read it.
 */

import qrcode from './vendor/qrcode.mjs';

import { ErrorCode, toAppError } from './core/errors.js';
import { HttpClient } from './core/http.js';
import { PiaClient, isTokenExpired } from './core/pia.js';
import { Prefs, groupByFavourite } from './core/prefs.js';
import { DNS_PRESETS, DEFAULT_DNS, CUSTOM_DNS, resolveDns } from './core/dns.js';
import { findRegionById, pickServer } from './core/serverlist.js';
import { generateKeyPair, buildConfig, maskPrivateKey, configFileName } from './core/wireguard.js';
import { CaCertFile, exec, storage, saveConfigFile, copyToClipboard } from './platform/neutralino.js';

// --- Wiring ----------------------------------------------------------------

const $ = (id) => document.getElementById(id);

const views = {
  blocked: $('view-blocked'),
  login: $('view-login'),
  config: $('view-config'),
  success: $('view-success'),
};

const el = {
  steps: $('steps'),
  appVersion: $('app-version'),

  blockedMessage: $('blocked-message'),
  blockedRetry: $('blocked-retry'),

  loginForm: $('login-form'),
  username: $('username'),
  password: $('password'),
  staySignedIn: $('stay-signed-in'),
  loginBtn: $('login-btn'),
  loginError: $('login-error'),

  signedInAs: $('signed-in-as'),
  signOutBtn: $('signout-btn'),
  regionFilter: $('region-filter'),
  regionSelect: $('region-select'),
  favouriteBtn: $('favourite-btn'),
  dnsPreset: $('dns-preset'),
  dnsHint: $('dns-hint'),
  customDnsField: $('custom-dns-field'),
  customDns: $('custom-dns'),
  generateBtn: $('generate-btn'),
  configError: $('config-error'),
  configNotice: $('config-notice'),

  successSubtitle: $('success-subtitle'),
  previewFilename: $('preview-filename'),
  preview: $('config-preview'),
  revealBtn: $('reveal-btn'),
  copyBtn: $('copy-btn'),
  qrBtn: $('qr-btn'),
  qrPanel: $('qr-panel'),
  qrTarget: $('qr-target'),
  saveBtn: $('save-btn'),
  saveStatus: $('save-status'),
  anotherBtn: $('another-btn'),
};

const caCert = new CaCertFile();
const http = new HttpClient(exec);
const pia = new PiaClient(http, () => caCert.path);
const prefs = new Prefs(storage);

const state = {
  /** @type {string} in memory for the session; only written to disk on request */
  token: '',
  username: '',
  /** @type {import('./core/serverlist.js').Region[]} */
  regions: [],
  /** @type {string[]} */
  favourites: [],
  selectedRegionId: '',
  generated: null,
  privateKeyRevealed: false,
};

// --- Boot ------------------------------------------------------------------

Neutralino.init();

Neutralino.events.on('windowClose', async () => {
  await caCert.cleanUp();
  await Neutralino.app.exit();
});

Neutralino.events.on('ready', () => {
  if (typeof NL_APPVERSION === 'string') {
    el.appVersion.textContent = `v${NL_APPVERSION}`;
  }
  start();
});

async function start() {
  try {
    await http.preflight();
    await caCert.materialise();
  } catch (err) {
    showBlocked(toAppError(err, 'This app could not start.'));
    return;
  }

  try {
    const { purgedToken } = await prefs.migrate();
    state.username = await prefs.getUsername();
    el.username.value = state.username;
    el.staySignedIn.checked = await prefs.getStaySignedIn();

    await restoreDnsPreferences();

    if (purgedToken) {
      // v1 stored the token whether or not anyone asked it to.
      showAlert(el.loginError, 'info',
        'For your security this update removed the sign-in token that a previous version stored on disk. ' +
        'Please sign in again.');
    }

    const stored = await prefs.getToken(isTokenExpired);
    if (stored && stored.expired) {
      showAlert(el.loginError, 'info', 'Your saved session had expired, so it was removed. Please sign in again.');
    } else if (stored && stored.token) {
      state.token = stored.token;
      switchTo('config');
      await loadRegions();
      return;
    }
  } catch (err) {
    showError(el.loginError, toAppError(err, 'Could not read your saved preferences.'));
  }

  switchTo('login');
  (el.username.value ? el.password : el.username).focus();
}

// --- Sign in ---------------------------------------------------------------

el.loginForm.addEventListener('submit', async (event) => {
  event.preventDefault();

  const username = el.username.value.trim();
  const password = el.password.value;

  if (!username || !password) {
    showAlert(el.loginError, 'error', 'Enter both your username and password.');
    return;
  }

  setBusy(el.loginBtn, true);
  hide(el.loginError);

  try {
    state.token = await pia.login(username, password);
    state.username = username;

    // The password has done its job; do not leave it sitting in the DOM.
    el.password.value = '';

    await prefs.setUsername(username);
    await prefs.setStaySignedIn(el.staySignedIn.checked);
    if (el.staySignedIn.checked) {
      await prefs.setToken(state.token);
    }

    switchTo('config');
    await loadRegions();
  } catch (err) {
    showError(el.loginError, toAppError(err, 'Could not sign in.'));
  } finally {
    setBusy(el.loginBtn, false);
  }
});

el.signOutBtn.addEventListener('click', async () => {
  state.token = '';
  state.regions = [];
  state.selectedRegionId = '';
  state.generated = null;

  el.password.value = '';
  el.staySignedIn.checked = false;
  el.generateBtn.disabled = true;
  el.regionSelect.replaceChildren();
  el.regionFilter.value = '';
  hide(el.configError);
  hide(el.configNotice);
  hide(el.loginError);

  try {
    await prefs.signOut();
  } catch {
    // Nothing actionable: the in-memory token is already gone.
  }

  switchTo('login');
  el.password.focus();
});

// --- Regions ---------------------------------------------------------------

async function loadRegions() {
  el.regionSelect.disabled = true;
  el.regionSelect.setAttribute('aria-busy', 'true');
  el.regionSelect.replaceChildren(makeOption('', 'Loading regions…', true));
  el.generateBtn.disabled = true;
  hide(el.configError);
  hide(el.configNotice);

  el.signedInAs.textContent = state.username ? `Signed in as ${state.username}` : '';

  try {
    state.regions = await pia.fetchRegions();
    state.favourites = await prefs.getFavourites();

    const savedRegionId = await prefs.getRegionId();
    if (savedRegionId && findRegionById(state.regions, savedRegionId)) {
      state.selectedRegionId = savedRegionId;
    } else {
      state.selectedRegionId = '';
      if (savedRegionId) {
        showAlert(el.configNotice, 'info',
          `The region you used last time ("${savedRegionId}") is no longer offered with WireGuard. ` +
          'Pick another one.');
        await prefs.setRegionId('');
      }
    }

    el.regionSelect.disabled = false;
    renderRegions();
  } catch (err) {
    const appError = toAppError(err, 'Could not load the list of regions.');

    el.regionSelect.replaceChildren(makeOption('', 'No regions available', true));
    el.regionSelect.disabled = true;
    el.generateBtn.disabled = true;
    showError(el.configError, appError);

    if (appError.code === ErrorCode.AUTH) {
      await forceReauthentication(appError.message);
    }
  } finally {
    el.regionSelect.removeAttribute('aria-busy');
  }
}

function renderRegions() {
  const term = el.regionFilter.value.trim().toLowerCase();
  const matches = term
    ? state.regions.filter((region) =>
      region.name.toLowerCase().includes(term) ||
      region.id.toLowerCase().includes(term) ||
      region.country.toLowerCase().includes(term))
    : state.regions;

  el.regionSelect.replaceChildren();

  // A selection the filter has hidden must stop counting as selected: leaving
  // the button live for a region the user can no longer see is how you generate
  // a config for the wrong place. The stored preference is left alone, so the
  // choice comes back on the next launch.
  if (!matches.some((region) => region.id === state.selectedRegionId)) {
    state.selectedRegionId = '';
  }

  if (matches.length === 0) {
    el.regionSelect.appendChild(makeOption('', `No region matches "${el.regionFilter.value.trim()}"`, true));
    syncSelectionUi();
    return;
  }

  const { favourites, rest } = groupByFavourite(matches, state.favourites);

  if (favourites.length > 0) {
    el.regionSelect.appendChild(makeGroup('Pinned', favourites));
    if (rest.length > 0) el.regionSelect.appendChild(makeGroup('All regions', rest));
  } else {
    for (const region of rest) {
      el.regionSelect.appendChild(makeOption(region.id, regionLabel(region)));
    }
  }

  el.regionSelect.value = state.selectedRegionId;
  syncSelectionUi();
}

function makeGroup(label, regions) {
  const group = document.createElement('optgroup');
  group.label = label;
  for (const region of regions) {
    group.appendChild(makeOption(region.id, regionLabel(region)));
  }
  return group;
}

function makeOption(value, text, disabled = false) {
  const option = document.createElement('option');
  option.value = value;
  option.textContent = text;
  option.disabled = disabled;
  return option;
}

function regionLabel(region) {
  const flags = [];
  if (region.portForward) flags.push('port forwarding');
  if (region.geo) flags.push('geo-located');
  return flags.length > 0 ? `${region.name} — ${flags.join(', ')}` : region.name;
}

/**
 * Derive every piece of selection-dependent UI from `state.selectedRegionId`.
 *
 * The previous version enabled the Generate button straight after assigning to
 * `select.value`, without checking the assignment matched an option — so an
 * empty or stale value left an enabled button that did nothing when clicked.
 */
function syncSelectionUi() {
  const selected = state.selectedRegionId
    ? findRegionById(state.regions, state.selectedRegionId)
    : undefined;

  el.generateBtn.disabled = !selected;
  el.favouriteBtn.disabled = !selected;
  el.favouriteBtn.setAttribute(
    'aria-pressed',
    selected && state.favourites.includes(selected.id) ? 'true' : 'false',
  );
}

el.regionSelect.addEventListener('change', async () => {
  state.selectedRegionId = el.regionSelect.value;
  syncSelectionUi();
  hide(el.configNotice);

  try {
    await prefs.setRegionId(state.selectedRegionId);
  } catch {
    // A preference that fails to save is not worth interrupting anyone over.
  }
});

el.regionFilter.addEventListener('input', renderRegions);

el.favouriteBtn.addEventListener('click', async () => {
  if (!state.selectedRegionId) return;
  try {
    state.favourites = await prefs.toggleFavourite(state.selectedRegionId);
  } catch {
    return;
  }
  renderRegions();
});

// --- DNS -------------------------------------------------------------------

for (const preset of DNS_PRESETS) {
  el.dnsPreset.appendChild(makeOption(preset.value, preset.label));
}

async function restoreDnsPreferences() {
  const saved = await prefs.getDns();
  const known = DNS_PRESETS.some((preset) => preset.value === saved.preset);

  el.dnsPreset.value = known ? saved.preset : DEFAULT_DNS;
  el.customDns.value = saved.custom || '';
  syncDnsUi();
}

function syncDnsUi() {
  const isCustom = el.dnsPreset.value === CUSTOM_DNS;
  el.customDnsField.hidden = !isCustom;

  const preset = DNS_PRESETS.find((item) => item.value === el.dnsPreset.value);
  el.dnsHint.textContent = preset ? preset.hint : '';
}

el.dnsPreset.addEventListener('change', async () => {
  syncDnsUi();
  if (el.dnsPreset.value === CUSTOM_DNS) el.customDns.focus();
  await persistDns();
});

el.customDns.addEventListener('change', persistDns);

async function persistDns() {
  try {
    await prefs.setDns(el.dnsPreset.value, el.customDns.value.trim());
  } catch {
    // Preferences are best-effort.
  }
}

// --- Generate --------------------------------------------------------------

el.generateBtn.addEventListener('click', async () => {
  const region = findRegionById(state.regions, state.selectedRegionId);
  if (!region) {
    showAlert(el.configError, 'error', 'Choose a region first.');
    return;
  }
  if (!state.token) {
    await forceReauthentication('Your session has expired. Please sign in again.');
    return;
  }

  setBusy(el.generateBtn, true);
  el.regionSelect.disabled = true;
  hide(el.configError);
  hide(el.configNotice);

  try {
    const dns = resolveDns(el.dnsPreset.value, el.customDns.value);
    const keys = generateKeyPair(webCrypto);
    const server = pickServer(region);

    const peer = await pia.addKey({ token: state.token, publicKey: keys.publicKey, server });

    state.generated = {
      config: buildConfig({ keys, peer, dns, regionName: region.name }),
      filename: configFileName(region.id),
      regionName: region.name,
      serverIp: peer.serverIp,
    };

    showGenerated();
  } catch (err) {
    const appError = toAppError(err, 'Could not generate a configuration.');
    showError(el.configError, appError);
    if (appError.code === ErrorCode.AUTH) {
      await forceReauthentication(appError.message);
    }
  } finally {
    setBusy(el.generateBtn, false);
    el.regionSelect.disabled = false;
  }
});

const webCrypto = {
  randomBytes(length) {
    const bytes = new Uint8Array(length);
    globalThis.crypto.getRandomValues(bytes);
    return bytes;
  },
  scalarMultBase(secretKey) {
    // tweetnacl is loaded as a classic script and exposes `nacl` globally.
    return nacl.box.keyPair.fromSecretKey(secretKey).publicKey;
  },
};

// --- Result ----------------------------------------------------------------

function showGenerated() {
  state.privateKeyRevealed = false;

  el.successSubtitle.textContent =
    `${state.generated.regionName} · endpoint ${state.generated.serverIp}`;
  el.previewFilename.textContent = state.generated.filename;

  el.revealBtn.setAttribute('aria-pressed', 'false');
  el.revealBtn.textContent = 'Reveal private key';
  el.qrBtn.setAttribute('aria-pressed', 'false');
  el.qrBtn.textContent = 'Show QR';
  el.qrPanel.hidden = true;
  el.qrTarget.replaceChildren();
  el.copyBtn.textContent = 'Copy';

  hide(el.saveStatus);
  renderPreview();
  switchTo('success');
}

function renderPreview() {
  el.preview.textContent = state.privateKeyRevealed
    ? state.generated.config
    : maskPrivateKey(state.generated.config);
}

el.revealBtn.addEventListener('click', () => {
  state.privateKeyRevealed = !state.privateKeyRevealed;
  el.revealBtn.setAttribute('aria-pressed', String(state.privateKeyRevealed));
  el.revealBtn.textContent = state.privateKeyRevealed ? 'Hide private key' : 'Reveal private key';
  renderPreview();
});

el.copyBtn.addEventListener('click', async () => {
  if (!state.generated) return;

  const copied = await copyToClipboard(state.generated.config);
  el.copyBtn.textContent = copied ? 'Copied' : 'Copy failed';
  setTimeout(() => { el.copyBtn.textContent = 'Copy'; }, 1800);

  if (copied) {
    showAlert(el.saveStatus, 'warn',
      'The configuration — including the private key — is now on your clipboard. Paste it somewhere safe, ' +
      'then copy something else to clear it.');
  }
});

el.qrBtn.addEventListener('click', () => {
  if (!state.generated) return;

  const showing = el.qrPanel.hidden;
  el.qrPanel.hidden = !showing;
  el.qrBtn.setAttribute('aria-pressed', String(showing));
  el.qrBtn.textContent = showing ? 'Hide QR' : 'Show QR';

  if (showing && el.qrTarget.childElementCount === 0) {
    renderQr(state.generated.config);
  }
});

function renderQr(text) {
  // Fall back to the lowest error-correction level if the payload will not fit
  // at the default; a long region name plus a custom DNS list can get close.
  for (const level of ['M', 'L']) {
    try {
      const code = qrcode(0, level);
      code.addData(text);
      code.make();

      const image = document.createElement('img');
      image.src = code.createDataURL(6, 2);
      image.alt = 'QR code containing the WireGuard configuration';
      el.qrTarget.replaceChildren(image);
      return;
    } catch {
      // try the next level
    }
  }

  const message = document.createElement('p');
  message.className = 'hint';
  message.textContent = 'This configuration is too long to fit in a QR code. Save the file instead.';
  el.qrTarget.replaceChildren(message);
}

el.saveBtn.addEventListener('click', async () => {
  if (!state.generated) return;

  hide(el.saveStatus);

  try {
    const result = await saveConfigFile({
      defaultName: state.generated.filename,
      contents: state.generated.config,
    });

    if (!result) return; // cancelled

    if (result.restricted) {
      showAlert(el.saveStatus, 'success', `Saved to ${result.path}, readable only by your account.`);
    } else {
      showAlert(el.saveStatus, 'warn',
        `Saved to ${result.path}. This system would not let the app restrict the file's permissions, ` +
        'so check that other users cannot read it — it contains your private key.');
    }
  } catch (err) {
    showError(el.saveStatus, toAppError(err, 'Could not save the file.'), 'error');
  }
});

el.anotherBtn.addEventListener('click', () => {
  state.generated = null;
  switchTo('config');
});

// --- Blocked ---------------------------------------------------------------

el.blockedRetry.addEventListener('click', () => {
  switchTo('login');
  start();
});

function showBlocked(error) {
  el.blockedMessage.textContent = error.message;
  switchTo('blocked');
}

// --- View helpers ----------------------------------------------------------

const STEP_ORDER = ['login', 'config', 'success'];

function switchTo(name) {
  for (const [key, view] of Object.entries(views)) {
    view.classList.toggle('is-active', key === name);
  }
  views[name].focus();

  const currentIndex = STEP_ORDER.indexOf(name);
  el.steps.hidden = currentIndex === -1;

  for (const item of el.steps.children) {
    const index = STEP_ORDER.indexOf(item.dataset.step);
    item.classList.toggle('is-current', index === currentIndex);
    item.classList.toggle('is-done', currentIndex > -1 && index < currentIndex);
  }
}

async function forceReauthentication(message) {
  state.token = '';
  try {
    await prefs.clearToken();
  } catch {
    // best effort
  }
  switchTo('login');
  showAlert(el.loginError, 'error', message);
  el.password.focus();
}

function setBusy(button, busy) {
  button.disabled = busy;
  button.setAttribute('aria-busy', String(busy));
  button.querySelector('.btn__label').hidden = busy;
  button.querySelector('.spinner').hidden = !busy;
}

/**
 * @param {HTMLElement} box
 * @param {AppError} error
 * @param {string} [tone]
 */
function showError(box, error, tone = 'error') {
  showAlert(box, tone, error.message);

  const details = box.querySelector('.alert__details');
  if (!details) return;

  if (error.detail) {
    details.querySelector('pre').textContent = error.detail;
    details.hidden = false;
    details.open = false;
  } else {
    details.hidden = true;
  }
}

/**
 * @param {HTMLElement} box
 * @param {'error'|'warn'|'info'|'success'} tone
 * @param {string} message
 */
function showAlert(box, tone, message) {
  box.className = `alert alert--${tone}`;
  box.querySelector('.alert__message').textContent = message;

  const details = box.querySelector('.alert__details');
  if (details) details.hidden = true;

  box.hidden = false;
}

function hide(box) {
  box.hidden = true;
}

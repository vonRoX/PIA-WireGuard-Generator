/* global document -- browser module; eslint.config.js lints scripts/** with Node globals */
/**
 * Setup: console address → certificate → UniFi API key → PIA login.
 *
 * The stepper is derived from the server state every time it changes. A step the state says is
 * done collapses to a summary with "Change"; the first step that is not done is open; the rest
 * wait. "Change" reopens a done step without forgetting anything until the new value is stored.
 */

import { api } from './api.js';
import { $, h, setBusy, announce, setFieldError } from './dom.js';
import { showError, clearError, showNotice } from './alerts.js';
import {
  DEFAULT_CONSOLE_URL,
  normaliseConsoleUrl,
  fingerprintRows,
  fingerprintBytes,
  fingerprintShort,
  formatDate,
  validityProblem,
} from './format.js';

const STEPS = /** @type {const} */ (['console', 'key', 'pia']);

/** ["3B","9F","0C","D2"] → [["3B","9F"],["0C","D2"]] */
function pairs(bytes) {
  const out = [];
  for (let i = 0; i < bytes.length; i += 2) out.push(bytes.slice(i, i + 2));
  return out;
}
const STORED_COPY = 'Stored, encrypted for this Windows account.';

export function createSetup(store) {
  /** Step reopened with "Change", or null. */
  let editing = null;
  /** The certificate being looked at, before it is trusted. */
  let pending = null;
  /** applicationVersion from the last successful key check, for the summary. */
  let lastVersion = null;
  let rendered = false;

  const el = {
    consoleForm: $('console-form'),
    consoleUrl: $('console-url'),
    consoleUrlError: $('console-url-error'),
    consoleCheck: $('console-check'),
    consoleError: $('console-error'),
    certPanel: $('cert-panel'),
    certCompare: $('cert-compare'),
    certTrust: $('cert-trust'),
    trustError: $('trust-error'),
    keyForm: $('key-form'),
    key: $('unifi-key'),
    keyFieldError: $('unifi-key-error'),
    keyReveal: $('unifi-key-reveal'),
    keySave: $('key-save'),
    keyError: $('key-error'),
    piaForm: $('pia-form'),
    piaUser: $('pia-username'),
    piaUserError: $('pia-username-error'),
    piaPass: $('pia-password'),
    piaPassError: $('pia-password-error'),
    piaSave: $('pia-save'),
    piaError: $('pia-error'),
    done: $('setup-done'),
    forgetZone: $('forget-zone'),
    forgetOpen: $('forget-open'),
    forgetConfirm: $('forget-confirm'),
    forgetConfirmBtn: $('forget-confirm-btn'),
    forgetError: $('forget-error'),
  };

  const doneMap = (s) => ({
    console: Boolean(s?.console?.trusted),
    key: Boolean(s?.unifiKey?.stored),
    pia: Boolean(s?.pia?.stored),
  });

  // ------------------------------------------------------------------ rendering

  function render() {
    const s = store.state;
    if (!s) return;
    const done = doneMap(s);
    const current = editing ?? STEPS.find((step) => !done[step]) ?? null;

    for (const [index, step] of STEPS.entries()) {
      const item = $(`step-${step}`);
      let phase;
      if (step === editing) phase = 'editing';
      else if (step === current) phase = 'current';
      else if (done[step]) phase = 'done';
      else phase = 'upcoming';
      // A step cannot be worked on before the ones it depends on.
      if (phase === 'current' && STEPS.slice(0, index).some((before) => !done[before])) phase = 'upcoming';

      item.dataset.state = phase;
      if (phase === 'current' || phase === 'editing') item.setAttribute('aria-current', 'step');
      else item.removeAttribute('aria-current');

      item.querySelector('.step__sr-state').textContent =
        phase === 'done' ? 'Done.' : phase === 'upcoming' ? 'Not started.' : 'Current step.';
      const number = item.querySelector('.step__number');
      number.textContent = phase === 'done' ? '✓' : String(index + 1);

      $(`step-${step}-summary`).textContent = summary(step, phase, s);
      item.querySelector('.step__cancel').hidden = phase !== 'editing';
    }

    for (const node of document.querySelectorAll('.js-console-url')) {
      node.textContent = s.console?.url || DEFAULT_CONSOLE_URL;
    }

    const allDone = STEPS.every((step) => done[step]);
    el.done.hidden = !allDone || editing !== null;
    el.forgetZone.hidden = !(done.key || done.pia);
    if (el.forgetZone.hidden) closeForget();

    if (!rendered) {
      rendered = true;
      if (s.console?.url) el.consoleUrl.value = s.console.url;
    }
  }

  function summary(step, phase, s) {
    if (step === 'console') {
      if (phase === 'done' && s.console) {
        return `${s.console.url} · certificate ${fingerprintShort(s.console.fingerprint256)} trusted`;
      }
      return phase === 'editing' ? 'Check the certificate again, or cancel to keep the current one.' : '';
    }
    if (step === 'key') {
      if (phase === 'done') return lastVersion ? `Checked with UniFi Network ${lastVersion}. ${STORED_COPY}` : STORED_COPY;
      if (phase === 'editing') return 'Paste a new key to replace the stored one.';
      return phase === 'upcoming' ? 'After the console certificate is trusted.' : '';
    }
    if (phase === 'done') return STORED_COPY;
    if (phase === 'editing') return 'Enter a new login to replace the stored one.';
    return phase === 'upcoming' ? 'After the UniFi API key.' : '';
  }

  /** Move focus to wherever the person should look next. */
  function focusNext() {
    const s = store.state;
    const done = doneMap(s);
    const next = STEPS.find((step) => !done[step]);
    if (next) {
      $(`step-${next}-title`).focus();
    } else {
      $('setup-done-title').focus();
    }
  }

  // ------------------------------------------------------------------ step 1: console + certificate

  function hideCertificate() {
    pending = null;
    el.certPanel.hidden = true;
    clearError(el.trustError);
    clearError(el.certCompare);
  }

  async function inspect() {
    setFieldError(el.consoleUrl, el.consoleUrlError, '');
    clearError(el.consoleError);
    hideCertificate();

    const url = normaliseConsoleUrl(el.consoleUrl.value);
    if (!url) {
      setFieldError(el.consoleUrl, el.consoleUrlError, 'Enter the console address, for example https://192.168.1.1.');
      el.consoleUrl.focus();
      return;
    }
    el.consoleUrl.value = url;

    setBusy(el.consoleCheck, true);
    try {
      const result = await api.inspectConsole(url);
      showCertificate(result);
    } catch (error) {
      const err = showError(el.consoleError, error, { retry: inspect });
      if (err.code === 'INVALID_INPUT') el.consoleUrl.focus();
    } finally {
      setBusy(el.consoleCheck, false);
    }
  }

  function showCertificate(result) {
    const cert = result.certificate || {};
    pending = { url: result.url, certificate: cert };

    $('cert-url').textContent = result.url;
    $('cert-url-again').textContent = result.url;
    $('cert-subject').textContent = cert.subject || '—';
    $('cert-issuer').textContent = cert.issuer || '—';
    $('cert-selfsigned').textContent = cert.selfSigned ? 'Yes (normal for a UniFi console)' : 'No';

    const names = Array.isArray(cert.names) ? cert.names : [];
    $('cert-names').replaceChildren(...(names.length
      ? names.map((name) => h('span', { class: 'tag mono', text: name }))
      : [document.createTextNode('None listed')]));

    const problem = validityProblem(cert);
    const validity = [document.createTextNode(`${formatDate(cert.validFrom)} to ${formatDate(cert.validTo)}`)];
    if (problem) {
      validity.push(h('span', { class: 'tag tag--warn', text: problem === 'expired' ? 'Expired' : 'Not valid yet' }));
    }
    $('cert-validity').replaceChildren(...validity);

    const rows = fingerprintRows(cert.fingerprint256);
    $('cert-fingerprint').replaceChildren(...rows.map((row, index) => h('div', { class: 'fingerprint__row' },
      h('span', { class: 'fingerprint__offset', 'aria-hidden': 'true', text: String(index * 8 + 1).padStart(2, '0') }),
      ...pairs(row).map((pair) => h('span', { class: 'fingerprint__pair' },
        ...pair.flatMap((byte, i) => [i ? ' ' : null, h('span', { class: 'fingerprint__byte', text: byte })]),
      )),
    )));
    $('cert-fingerprint').setAttribute('aria-description', fingerprintBytes(cert.fingerprint256).join(' '));

    const trusted = store.state?.console;
    if (trusted?.fingerprint256) {
      const same = fingerprintBytes(trusted.fingerprint256).join('') === fingerprintBytes(cert.fingerprint256).join('');
      if (same) {
        showNotice(el.certCompare, 'success', 'This is the certificate you already trust.');
      } else {
        showNotice(el.certCompare, 'warn',
          'This is not the certificate you trusted before.',
          `Previously trusted: ${fingerprintShort(trusted.fingerprint256)}. A console gets a new certificate after ` +
          'a reset or some updates, but it can also mean another device is answering at this address. ' +
          'Compare carefully before trusting it.');
      }
    }

    el.certTrust.disabled = fingerprintBytes(cert.fingerprint256).length !== 32;
    el.certPanel.hidden = false;
    $('cert-title').focus();
  }

  async function trust() {
    if (!pending) return;
    clearError(el.trustError);
    setBusy(el.certTrust, true);
    let changed = false;
    try {
      const next = await api.trustConsole(pending.url, pending.certificate.fingerprint256);
      setBusy(el.certTrust, false);
      hideCertificate();
      editing = null;
      store.set(next);
      announce('Certificate trusted.');
      focusNext();
    } catch (error) {
      const err = showError(el.trustError, error, {
        retry: inspect,
        retryLabel: 'Check the certificate again',
      });
      changed = err.code === 'CERT_CHANGED';
    } finally {
      setBusy(el.certTrust, false);
      // The certificate on screen is no longer what the console presents; do not offer to trust it.
      if (changed) el.certTrust.disabled = true;
    }
  }

  function reject() {
    hideCertificate();
    showNotice(el.consoleError, 'warn', 'Good call — nothing was trusted.',
      'Make sure the address is your UniFi console and that you are on your own network, then check again.');
    el.consoleUrl.focus();
  }

  el.consoleForm.addEventListener('submit', (event) => {
    event.preventDefault();
    inspect();
  });
  // A certificate belongs to the address it was read from; editing the address retires it.
  el.consoleUrl.addEventListener('input', () => {
    if (pending) hideCertificate();
    setFieldError(el.consoleUrl, el.consoleUrlError, '');
  });
  el.certTrust.addEventListener('click', trust);
  $('cert-reject').addEventListener('click', reject);

  // ------------------------------------------------------------------ step 2: UniFi API key

  async function saveKey() {
    setFieldError(el.key, el.keyFieldError, '');
    clearError(el.keyError);

    const apiKey = el.key.value.trim();
    el.key.value = apiKey;
    if (!apiKey) {
      setFieldError(el.key, el.keyFieldError, 'Paste the API key from the console first.');
      el.key.focus();
      return;
    }

    setBusy(el.keySave, true);
    try {
      const result = await api.setUnifiKey(apiKey);
      lastVersion = typeof result.applicationVersion === 'string' ? result.applicationVersion : null;
      el.key.value = '';
      setReveal(false);
      editing = null;
      await store.refresh();
      announce(lastVersion ? `Key accepted by UniFi Network ${lastVersion}.` : 'Key accepted.');
      focusNext();
    } catch (error) {
      const err = showError(el.keyError, error, { retry: saveKey });
      if (err.code === 'UNIFI_KEY_REJECTED' || err.code === 'INVALID_INPUT') {
        el.key.focus();
        el.key.select();
      }
    } finally {
      setBusy(el.keySave, false);
    }
  }

  function setReveal(on) {
    el.key.type = on ? 'text' : 'password';
    el.keyReveal.setAttribute('aria-pressed', String(on));
    el.keyReveal.textContent = on ? 'Hide' : 'Show';
  }

  el.keyForm.addEventListener('submit', (event) => {
    event.preventDefault();
    saveKey();
  });
  el.keyReveal.addEventListener('click', () => setReveal(el.key.type === 'password'));
  el.key.addEventListener('input', () => setFieldError(el.key, el.keyFieldError, ''));

  // ------------------------------------------------------------------ step 3: PIA

  async function savePia() {
    setFieldError(el.piaUser, el.piaUserError, '');
    setFieldError(el.piaPass, el.piaPassError, '');
    clearError(el.piaError);

    const username = el.piaUser.value.trim();
    const password = el.piaPass.value;
    el.piaUser.value = username;
    let invalid = null;
    if (!password) {
      setFieldError(el.piaPass, el.piaPassError, 'Enter your PIA password.');
      invalid = el.piaPass;
    }
    if (!username) {
      setFieldError(el.piaUser, el.piaUserError, 'Enter your PIA username.');
      invalid = el.piaUser;
    }
    if (invalid) {
      invalid.focus();
      return;
    }

    setBusy(el.piaSave, true);
    try {
      const next = await api.setPia(username, password);
      el.piaPass.value = '';
      el.piaUser.value = '';
      editing = null;
      store.set(next);
      announce('PIA login stored.');
      focusNext();
    } catch (error) {
      showError(el.piaError, error, { retry: savePia });
    } finally {
      setBusy(el.piaSave, false);
    }
  }

  el.piaForm.addEventListener('submit', (event) => {
    event.preventDefault();
    savePia();
  });
  el.piaUser.addEventListener('input', () => setFieldError(el.piaUser, el.piaUserError, ''));
  el.piaPass.addEventListener('input', () => setFieldError(el.piaPass, el.piaPassError, ''));

  // ------------------------------------------------------------------ Change / Cancel

  const FIRST_INPUT = { console: () => el.consoleUrl, key: () => el.key, pia: () => el.piaUser };

  function resetStep(step) {
    if (step === 'console') {
      hideCertificate();
      clearError(el.consoleError);
      setFieldError(el.consoleUrl, el.consoleUrlError, '');
      el.consoleUrl.value = store.state?.console?.url || DEFAULT_CONSOLE_URL;
    } else if (step === 'key') {
      el.key.value = '';
      setReveal(false);
      clearError(el.keyError);
      setFieldError(el.key, el.keyFieldError, '');
    } else {
      el.piaUser.value = '';
      el.piaPass.value = '';
      clearError(el.piaError);
      setFieldError(el.piaUser, el.piaUserError, '');
      setFieldError(el.piaPass, el.piaPassError, '');
    }
  }

  for (const step of STEPS) {
    $(`${step}-change`).addEventListener('click', () => {
      if (editing && editing !== step) resetStep(editing);
      editing = step;
      resetStep(step);
      render();
      FIRST_INPUT[step]().focus();
    });
    $(`${step}-cancel`).addEventListener('click', () => {
      resetStep(step);
      editing = null;
      render();
      $(`${step}-change`).focus();
    });
  }

  // ------------------------------------------------------------------ Forget

  function closeForget() {
    el.forgetConfirm.hidden = true;
    el.forgetOpen.setAttribute('aria-expanded', 'false');
  }

  el.forgetOpen.addEventListener('click', () => {
    clearError(el.forgetError);
    el.forgetConfirm.hidden = false;
    el.forgetOpen.setAttribute('aria-expanded', 'true');
    $('forget-cancel').focus();
  });
  $('forget-cancel').addEventListener('click', () => {
    closeForget();
    el.forgetOpen.focus();
  });
  el.forgetConfirm.addEventListener('keydown', (event) => {
    if (event.key === 'Escape') {
      closeForget();
      el.forgetOpen.focus();
    }
  });

  async function forget() {
    clearError(el.forgetError);
    setBusy(el.forgetConfirmBtn, true);
    try {
      const next = await api.forgetCredentials();
      lastVersion = null;
      if (editing === 'key' || editing === 'pia') {
        resetStep(editing);
        editing = null;
      }
      closeForget();
      store.set(next);
      announce('Stored credentials forgotten.');
      focusNext();
    } catch (error) {
      showError(el.forgetError, error, { retry: forget });
    } finally {
      setBusy(el.forgetConfirmBtn, false);
    }
  }
  el.forgetConfirmBtn.addEventListener('click', forget);

  store.subscribe(render);

  return {
    enter() {
      render();
    },
  };
}

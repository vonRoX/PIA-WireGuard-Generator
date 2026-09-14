/**
 * API explorer: read-only GETs under /proxy/network/, answered with a redacted body.
 */

import { api } from './api.js';
import { $, h, setBusy, announce, setFieldError } from './dom.js';
import { showError, clearError } from './alerts.js';
import { EXPLORE_PRESETS, checkExplorePath, toPrettyJson } from './format.js';
import { renderJsonTree, expandAll, collapseAll } from './json-tree.js';

const REASONS = {
  200: 'OK',
  201: 'Created',
  204: 'No content',
  400: 'Bad request',
  401: 'Unauthorized',
  403: 'Forbidden',
  404: 'Not found',
  405: 'Method not allowed',
  429: 'Too many requests',
  500: 'Server error',
  502: 'Bad gateway',
  503: 'Unavailable',
};

function statusTone(status) {
  if (status >= 200 && status < 300) return 'ok';
  if (status >= 300 && status < 500) return 'pending';
  return 'bad';
}

export function createExplorer(_store) {
  const form = $('explore-form');
  const input = $('explore-path');
  const fieldError = $('explore-path-error');
  const send = $('explore-send');
  const errorSlot = $('explore-error');
  const result = $('explore-result');
  const tree = $('explore-tree');
  const raw = $('explore-raw-view');
  const rawToggle = $('explore-raw');
  const copy = $('explore-copy');

  /** @type {{ path: string, status: number, body: unknown } | null} */
  let last = null;
  let copyTimer = 0;

  async function run() {
    setFieldError(input, fieldError, '');
    clearError(errorSlot);

    const check = checkExplorePath(input.value);
    if (!check.ok) {
      setFieldError(input, fieldError, check.message);
      input.focus();
      return;
    }
    input.value = check.path;

    setBusy(send, true);
    const started = performance.now();
    try {
      const response = await api.explore(check.path);
      const elapsed = Math.round(performance.now() - started);
      show(check.path, response, elapsed);
    } catch (error) {
      const err = showError(errorSlot, error, { retry: run });
      if (err.code === 'INVALID_INPUT') input.focus();
    } finally {
      setBusy(send, false);
    }
  }

  function show(path, response, elapsed) {
    const status = Number(response?.status) || 0;
    last = { path, status, body: response?.body ?? null };

    const badge = $('explore-status');
    const tone = statusTone(status);
    badge.className = `badge badge--${tone}`;
    badge.replaceChildren(
      h('span', { class: 'badge__dot', 'aria-hidden': 'true' }),
      `${status} ${REASONS[status] ?? ''}`.trim(),
    );
    $('explore-shown-path').textContent = `${path} · ${elapsed} ms`;

    tree.replaceChildren(renderJsonTree(last.body, { openDepth: 2 }));
    raw.textContent = toPrettyJson(last.body);
    result.hidden = false;
    announce(`Response ${status} ${REASONS[status] ?? ''}.`);
  }

  function setRaw(on) {
    rawToggle.setAttribute('aria-pressed', String(on));
    raw.hidden = !on;
    tree.hidden = on;
    $('explore-expand').disabled = on;
    $('explore-collapse').disabled = on;
  }

  async function copyJson() {
    if (!last) return;
    const text = toPrettyJson(last.body);
    let ok = false;
    try {
      await navigator.clipboard.writeText(text);
      ok = true;
    } catch {
      ok = false;
    }
    clearTimeout(copyTimer);
    copy.textContent = ok ? 'Copied' : 'Copy failed';
    announce(ok ? 'JSON copied to the clipboard.' : 'Could not copy. Switch to Raw and select the text instead.');
    copyTimer = setTimeout(() => {
      copy.textContent = 'Copy JSON';
    }, 2000);
  }

  $('explore-presets').replaceChildren(...EXPLORE_PRESETS.map((path) => h('button', {
    type: 'button',
    class: 'chip mono',
    text: path.replace('/proxy/network', ''),
    title: path,
    'aria-label': `Send GET ${path}`,
    on: {
      click: () => {
        input.value = path;
        run();
      },
    },
  })));

  form.addEventListener('submit', (event) => {
    event.preventDefault();
    run();
  });
  input.addEventListener('input', () => setFieldError(input, fieldError, ''));
  $('explore-expand').addEventListener('click', () => expandAll(tree));
  $('explore-collapse').addEventListener('click', () => collapseAll(tree));
  rawToggle.addEventListener('click', () => setRaw(raw.hidden));
  copy.addEventListener('click', copyJson);

  return {};
}

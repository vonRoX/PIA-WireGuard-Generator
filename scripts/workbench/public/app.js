/* global document, window -- browser module; eslint.config.js lints scripts/** with Node globals */
/**
 * UniFi Workbench — page entry point.
 *
 * Loads the state, routes between the three views by URL hash, and hands state changes to
 * whichever view cares. Views live in their own modules; all network access is in api.js.
 */

import { api } from './api.js';
import { $ } from './dom.js';
import { showError, clearError } from './alerts.js';
import { createSetup } from './setup.js';
import { createTunnels } from './tunnels.js';
import { createExplorer } from './explorer.js';

const VIEWS = /** @type {const} */ (['setup', 'tunnels', 'explorer']);
const TITLES = { setup: 'Setup', tunnels: 'Tunnels', explorer: 'API explorer' };

/** @type {null | { console: any, unifiKey: { stored: boolean }, pia: { stored: boolean } }} */
let state = null;
const listeners = new Set();
let active = null;

const store = {
  get state() {
    return state;
  },
  /** @param {typeof state} next */
  set(next) {
    state = next;
    for (const listener of listeners) listener(state);
  },
  subscribe(listener) {
    listeners.add(listener);
  },
  /** Re-read the state from the server. */
  async refresh() {
    store.set(await api.state());
    return state;
  },
};

const views = {
  setup: createSetup(store),
  tunnels: createTunnels(store),
  explorer: createExplorer(store),
};

function isComplete(s) {
  return Boolean(s?.console?.trusted && s.unifiKey?.stored && s.pia?.stored);
}

function routeFromHash() {
  const name = window.location.hash.replace(/^#/, '');
  return VIEWS.includes(name) ? name : null;
}

/**
 * @param {'setup'|'tunnels'|'explorer'} name
 * @param {{ focus?: boolean }} [options]
 */
function show(name, { focus = false } = {}) {
  $('view-boot').hidden = true;
  if (active && active !== name) views[active].leave?.();
  active = name;

  for (const view of VIEWS) $(`view-${view}`).hidden = view !== name;
  for (const link of document.querySelectorAll('.tabs__link')) {
    if (link.getAttribute('data-view') === name) link.setAttribute('aria-current', 'page');
    else link.removeAttribute('aria-current');
  }
  document.title = `${TITLES[name]} · UniFi Workbench`;

  views[name].enter?.();
  if (focus) $(`${name}-title`).focus();
}

async function boot() {
  const bootError = $('boot-error');
  const bootStatus = $('boot-status');
  clearError(bootError);
  bootStatus.hidden = false;
  try {
    await store.refresh();
  } catch (error) {
    bootStatus.hidden = true;
    showError(bootError, error, { retry: boot, retryLabel: 'Try again' });
    return;
  }

  const route = routeFromHash();
  if (route) show(route);
  else show(isComplete(state) ? 'tunnels' : 'setup');
}

window.addEventListener('hashchange', () => {
  if (!state) return;
  show(routeFromHash() ?? 'setup', { focus: true });
});

document.addEventListener('visibilitychange', () => {
  if (active) views[active].visibility?.(document.visibilityState === 'visible');
});

boot();

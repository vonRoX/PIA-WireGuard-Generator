/* global document -- browser module; eslint.config.js lints scripts/** with Node globals */
/**
 * Tunnels: the console's VPN clients and their live status. Read-only in this milestone.
 */

import { api, ApiError } from './api.js';
import { $, h, setBusy, announce } from './dom.js';
import { showError, clearError, toApiError } from './alerts.js';
import { statusTone, statusLabel, modeLabel, humanise } from './format.js';

export const REFRESH_MS = 10_000;
const NOT_CONFIGURED = {
  code: 'NOT_CONFIGURED',
  message: 'The UniFi API key is not set up yet.',
  hint: 'Finish Setup, then come back here.',
};
const STOP_POLLING = new Set(['NOT_CONFIGURED', 'SESSION']);

export function createTunnels(store) {
  const body = $('tunnels-body');
  const refresh = $('tunnels-refresh');
  const errorSlot = $('tunnels-error');
  const updated = $('tunnels-updated');

  let timer = 0;
  let inFlight = false;
  let active = false;
  let lastLoaded = 0;
  let loadedOnce = false;

  function placeholder(text) {
    body.replaceChildren(h('tr', null, h('td', { class: 'table__placeholder', colspan: '4', text })));
  }

  function row(tunnel) {
    const tone = statusTone(tunnel.status);
    const notes = Array.isArray(tunnel.notes) ? tunnel.notes.filter((note) => typeof note === 'string' && note) : [];
    return h('tr', { 'data-id': tunnel.id },
      h('th', { scope: 'row', 'data-label': 'Name' },
        h('span', { class: 'tunnel__name', text: tunnel.name || 'Unnamed' }),
      ),
      h('td', { 'data-label': 'Mode', text: modeLabel(tunnel.mode) }),
      h('td', { 'data-label': 'Enabled' },
        h('span', { class: tunnel.enabled ? 'enabled enabled--on' : 'enabled enabled--off', text: tunnel.enabled ? 'Yes' : 'No' }),
      ),
      h('td', { 'data-label': 'Status' },
        h('div', null,
          h('span', { class: `badge badge--${tone}`, 'data-tone': tone },
            h('span', { class: 'badge__dot', 'aria-hidden': 'true' }),
            statusLabel(tunnel.status, tunnel.enabled !== false),
          ),
          notes.length ? h('ul', { class: 'notes' }, notes.map((note) => h('li', { text: humanise(note), title: note }))) : null,
        ),
      ),
    );
  }

  async function load({ manual = false } = {}) {
    if (inFlight) return;
    inFlight = true;
    if (manual) setBusy(refresh, true);
    try {
      const result = await api.tunnels();
      const tunnels = Array.isArray(result?.tunnels) ? result.tunnels : [];
      clearError(errorSlot);
      if (tunnels.length) body.replaceChildren(...tunnels.map(row));
      else placeholder('This console has no VPN clients yet.');
      loadedOnce = true;
      lastLoaded = Date.now();
      updated.textContent = `Updated ${new Date(lastLoaded).toLocaleTimeString()}`;
      if (manual) announce(`Tunnels updated. ${tunnels.length} VPN ${tunnels.length === 1 ? 'client' : 'clients'}.`);
    } catch (error) {
      const err = toApiError(error);
      showError(errorSlot, err, { retry: () => load({ manual: true }) });
      if (!loadedOnce) placeholder('No tunnel information yet.');
      if (STOP_POLLING.has(err.code)) stop();
    } finally {
      inFlight = false;
      if (manual) setBusy(refresh, false);
    }
  }

  function stop() {
    clearInterval(timer);
    timer = 0;
  }

  function start() {
    stop();
    if (!store.state?.unifiKey?.stored) {
      placeholder('Nothing to show until the UniFi API key is set up.');
      showError(errorSlot, new ApiError(NOT_CONFIGURED));
      return;
    }
    if (!loadedOnce) placeholder('Loading tunnels…');
    load();
    timer = setInterval(() => {
      if (document.visibilityState === 'visible') load();
    }, REFRESH_MS);
  }

  refresh.addEventListener('click', () => {
    if (!timer && store.state?.unifiKey?.stored) start();
    else load({ manual: true });
  });
  $('tunnels-refresh-keys').addEventListener('click', (event) => {
    event.preventDefault();
    announce('Refreshing keys is coming next.');
  });

  store.subscribe(() => {
    if (active && !timer && store.state?.unifiKey?.stored) start();
    if (!store.state?.unifiKey?.stored) {
      loadedOnce = false;
      if (active) start();
    }
  });

  return {
    enter() {
      active = true;
      start();
    },
    leave() {
      active = false;
      stop();
    },
    visibility(visible) {
      if (active && visible && timer && Date.now() - lastLoaded >= REFRESH_MS) load();
    },
  };
}

/* global window -- browser module; eslint.config.js lints scripts/** with Node globals */
/**
 * Errors rendered next to the action that caused them: `{ code, message, hint }` from the
 * server, plus a way forward (try again, or go to Setup).
 */

import { h } from './dom.js';
import { ApiError } from './api.js';

const RETRYABLE = new Set(['OFFLINE', 'TIMEOUT', 'NETWORK', 'TLS', 'HTTP', 'PARSE']);

/** @param {unknown} error */
export function toApiError(error) {
  if (error instanceof ApiError) return error;
  return new ApiError({
    code: 'UNEXPECTED',
    message: 'Something went wrong on this page.',
    hint: error instanceof Error ? error.message : String(error),
  });
}

/**
 * @param {HTMLElement} slot
 * @param {unknown} error
 * @param {{ retry?: () => unknown, retryLabel?: string }} [options]
 */
export function showError(slot, error, options = {}) {
  const err = toApiError(error);
  const prominent = err.code === 'UNIFI_KEY_REJECTED' || err.code === 'CERT_CHANGED';

  const box = h('div', { class: 'alert alert--error', role: 'alert', 'data-code': err.code },
    h('p', { class: 'alert__message', text: err.message }),
    err.hint ? h('p', { class: prominent ? 'alert__hint alert__hint--prominent' : 'alert__hint', text: err.hint }) : null,
  );

  const actions = h('div', { class: 'alert__actions' });
  if (options.retry && (RETRYABLE.has(err.code) || options.retryLabel)) {
    const button = h('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      text: options.retryLabel || 'Try again',
      on: { click: () => options.retry() },
    });
    actions.append(button);
  }
  if (err.code === 'NOT_CONFIGURED') {
    actions.append(h('a', { class: 'btn btn--ghost btn--sm', href: '#setup', text: 'Go to Setup' }));
  }
  if (err.code === 'SESSION') {
    actions.append(h('button', {
      type: 'button',
      class: 'btn btn--ghost btn--sm',
      text: 'Reload page',
      on: { click: () => window.location.reload() },
    }));
  }
  if (actions.childElementCount) box.append(actions);
  box.append(h('p', { class: 'alert__code', text: `Code: ${err.code}` }));

  slot.replaceChildren(box);
  slot.hidden = false;
  return err;
}

/** @param {HTMLElement} slot */
export function clearError(slot) {
  slot.replaceChildren();
  slot.hidden = true;
}

/**
 * A calm, non-error notice (warn / info / success).
 * @param {HTMLElement} slot
 * @param {'info'|'warn'|'success'} tone
 * @param {string} message
 * @param {string} [detail]
 */
export function showNotice(slot, tone, message, detail) {
  slot.replaceChildren(h('div', { class: `alert alert--${tone}`, role: 'status' },
    h('p', { class: 'alert__message', text: message }),
    detail ? h('p', { class: 'alert__hint', text: detail }) : null,
  ));
  slot.hidden = false;
}

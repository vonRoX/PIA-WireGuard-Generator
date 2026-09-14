/**
 * A collapsible JSON tree built from <details>/<summary>, so it is keyboard operable and
 * announced correctly without any ARIA wiring. Branches below `openDepth` render their
 * children only when first opened, which keeps a large networkconf body quick.
 *
 * Every value is placed with textContent (via `h`).
 */

import { h } from './dom.js';

const fillers = new WeakMap();
const REDACTED = '<redacted>';

/**
 * @param {unknown} value
 * @param {{ openDepth?: number }} [options]
 */
export function renderJsonTree(value, { openDepth = 2 } = {}) {
  return h('div', { class: 'json' }, node(null, value, 0, false, openDepth));
}

function node(key, value, depth, inArray, openDepth) {
  const label = key === null ? null : h('span', { class: inArray ? 'json__index' : 'json__key', text: inArray ? key : `${key}` });
  const colon = key === null ? null : h('span', { class: 'json__punct', text: ': ' });

  if (value !== null && typeof value === 'object') {
    const isArray = Array.isArray(value);
    const entries = isArray ? value.map((item, index) => [index, item]) : Object.entries(value);

    if (entries.length === 0) {
      return h('div', { class: 'json__leaf' }, label, colon, h('span', { class: 'json__punct', text: isArray ? '[]' : '{}' }));
    }

    const count = isArray ? `[${entries.length}]` : `{${entries.length}}`;
    const hint = !isArray && typeof value.name === 'string' ? value.name : null;
    const details = h('details', { class: 'json__branch' },
      h('summary', null,
        label, colon,
        h('span', { class: 'json__count', text: count }),
        hint ? h('span', { class: 'json__preview', text: hint }) : null,
      ),
    );

    let filled = false;
    const fill = () => {
      if (filled) return;
      filled = true;
      const list = h('ul', { class: 'json__children' });
      for (const [childKey, childValue] of entries) {
        list.append(h('li', null, node(childKey, childValue, depth + 1, isArray, openDepth)));
      }
      details.append(list);
    };
    fillers.set(details, fill);
    details.addEventListener('toggle', () => {
      if (details.open) fill();
    });
    if (depth < openDepth) {
      fill();
      details.open = true;
    }
    return details;
  }

  return h('div', { class: 'json__leaf' }, label, colon, primitive(value));
}

function primitive(value) {
  if (value === null) return h('span', { class: 'json__null', text: 'null' });
  if (typeof value === 'boolean') return h('span', { class: 'json__bool', text: String(value) });
  if (typeof value === 'number') return h('span', { class: 'json__number', text: String(value) });
  const text = String(value);
  if (text === REDACTED) return h('span', { class: 'json__redacted', text });
  const classes = ['json__string'];
  if (text.includes('\n')) classes.push('json__string--multiline');
  if (text.includes(REDACTED)) classes.push('json__string--has-redacted');
  return h('span', { class: classes.join(' '), text: text.includes('\n') ? text : JSON.stringify(text) });
}

/** Open every branch, rendering lazily built ones as it goes. */
export function expandAll(root) {
  for (let pass = 0; pass < 1000; pass += 1) {
    const closed = root.querySelectorAll('details:not([open])');
    if (closed.length === 0) return;
    for (const details of closed) {
      fillers.get(details)?.();
      details.open = true;
    }
  }
}

/** Close everything except the root. */
export function collapseAll(root) {
  const all = root.querySelectorAll('details');
  all.forEach((details, index) => {
    details.open = index === 0;
  });
}

/* global document -- browser module; eslint.config.js lints scripts/** with Node globals */
/**
 * The page builds every dynamic node through `h`, which only ever assigns text with
 * textContent and attributes with setAttribute. No HTML string is ever parsed, so a value
 * coming back from the console (a network name, a JSON body) cannot become markup.
 */

/** @param {string} id */
export const $ = (id) => {
  const el = document.getElementById(id);
  if (!el) throw new Error(`Missing element #${id}`);
  return el;
};

/**
 * @param {string} tag
 * @param {Record<string, any>|null} [props]  `class`, `text`, `on: {event: handler}`, or attributes
 * @param {...(Node|string|number|null|undefined|false)} children
 * @returns {HTMLElement}
 */
export function h(tag, props, ...children) {
  const el = document.createElement(tag);
  for (const [name, value] of Object.entries(props ?? {})) {
    if (value === undefined || value === null || value === false) continue;
    if (name === 'class') {
      el.className = value;
    } else if (name === 'text') {
      el.textContent = String(value);
    } else if (name === 'on') {
      for (const [event, handler] of Object.entries(value)) el.addEventListener(event, handler);
    } else if (name === 'style' || /^on/i.test(name)) {
      // The CSP forbids inline styles and handlers anyway; fail loudly in development.
      throw new Error(`h(): refusing to set ${name}`);
    } else {
      el.setAttribute(name, value === true ? '' : String(value));
    }
  }
  append(el, children);
  return el;
}

function append(el, children) {
  for (const child of children) {
    if (child === null || child === undefined || child === false) continue;
    if (Array.isArray(child)) append(el, child);
    else el.append(typeof child === 'string' || typeof child === 'number' ? document.createTextNode(String(child)) : child);
  }
}

/**
 * Put a button into (or out of) its working state: disabled, aria-busy, spinner visible.
 * @param {HTMLButtonElement} button
 * @param {boolean} busy
 */
export function setBusy(button, busy) {
  button.disabled = busy;
  if (busy) button.setAttribute('aria-busy', 'true');
  else button.removeAttribute('aria-busy');
  const spinner = button.querySelector('.spinner');
  if (spinner) spinner.hidden = !busy;
}

let announceTimer = 0;

/** Say something to screen-reader users without moving focus. */
export function announce(message) {
  const region = document.getElementById('announcer');
  if (!region) return;
  region.textContent = '';
  clearTimeout(announceTimer);
  announceTimer = setTimeout(() => {
    region.textContent = message;
  }, 60);
}

/** Show or clear a field-level validation message tied to an input via aria-describedby. */
export function setFieldError(input, messageEl, message) {
  if (message) {
    messageEl.textContent = message;
    messageEl.hidden = false;
    input.setAttribute('aria-invalid', 'true');
  } else {
    messageEl.textContent = '';
    messageEl.hidden = true;
    input.removeAttribute('aria-invalid');
  }
}

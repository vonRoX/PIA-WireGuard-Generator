/**
 * Redaction applied to anything the engine hands out of Node.
 *
 * Exactly the rules in scripts/workbench/CONTRACT.md:
 *  - any object key matching {@link SECRET_KEY} has its whole value replaced by
 *    `"<redacted>"`, whatever that value was;
 *  - inside every string, a WireGuard `PrivateKey = …` or `PresharedKey = …`
 *    assignment becomes `PrivateKey = <redacted>`. That is what catches a
 *    file-mode VPN Client row, whose `wireguard_client_configuration_file` — a
 *    key name that matches nothing — carries the whole `.conf`.
 *
 * The input is never modified. Cycles are cut rather than followed, so a hostile
 * or merely odd structure cannot hang or crash the server.
 */

export const REDACTED = '<redacted>';

export const SECRET_KEY = /key|secret|password|passphrase|token|psk|x_/i;

// Anywhere in a string, not only at the start of a line: a body that arrived as
// text rather than JSON can carry the `.conf` with its newlines still escaped,
// and eating the rest of such a "line" over-redacts, which is the safe side.
const CONF_SECRET = /(PrivateKey|PresharedKey)[ \t]*=[^\r\n]*/gi;

/**
 * @param {string} text
 * @returns {string}
 */
export function redactString(text) {
  return text.replace(CONF_SECRET, (_match, name) => `${name} = ${REDACTED}`);
}

/**
 * @param {unknown} value
 * @returns {unknown} a redacted deep copy
 */
export function redact(value) {
  const seen = new WeakSet();

  const walk = (node) => {
    if (typeof node === 'string') return redactString(node);
    if (node === null || typeof node !== 'object') {
      // Functions, symbols and bigints have no JSON form; say what was there.
      if (typeof node === 'function' || typeof node === 'symbol') return undefined;
      if (typeof node === 'bigint') return node.toString();
      return node;
    }
    if (seen.has(node)) return '<circular>';
    seen.add(node);

    let out;
    if (Array.isArray(node)) {
      out = node.map(walk);
    } else {
      out = {};
      for (const key of Object.keys(node)) {
        out[key] = SECRET_KEY.test(key) ? REDACTED : walk(node[key]);
      }
    }

    // Siblings may share an object without it being a cycle; only an ancestor
    // counts, so the mark comes off on the way back up.
    seen.delete(node);
    return out;
  };

  return walk(value);
}

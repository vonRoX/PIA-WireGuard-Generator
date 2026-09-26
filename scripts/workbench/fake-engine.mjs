/**
 * An in-memory stand-in for the Workbench engine (see CONTRACT.md → "Engine interface").
 *
 * It lets the UI be built and the server be tested without a console on the network, without
 * PowerShell, and without a single real secret. Nothing here touches the disk or the network.
 *
 * Deterministic triggers, so the error paths can be driven from the UI:
 *   - API key `sitemanager`          → UNIFI_KEY_REJECTED (the Site Manager mistake)
 *   - console host ending `.invalid`  → NETWORK
 *   - console host ending `.tls-fail` → TLS
 *
 * `_rotateCertificate()` is a test hook (not part of the contract): the console then presents a
 * different certificate, so a pending trust fails with CERT_CHANGED.
 */

import { AppError } from '../../resources/js/core/errors.js';

export const FAKE_APPLICATION_VERSION = '10.0.162';

export const SITE_MANAGER_KEY_HINT =
  'Create the key on the console itself: Settings → Control Plane → Integrations. ' +
  'A key from unifi.ui.com (Site Manager) is refused by the console with the same ' +
  '"401 Unauthorized" as no key at all.';

const FINGERPRINT_A =
  '3B:9F:0C:D2:71:4E:A8:65:1D:C0:92:BB:47:E3:5A:08:F6:21:9C:7D:E4:30:B5:6A:8F:12:DE:49:C7:03:5B:A1';
const FINGERPRINT_B =
  'A4:17:E2:5C:08:9D:F1:36:BB:60:2E:C9:74:0A:D5:83:1F:6C:E8:52:97:3D:0B:A6:C4:29:F0:5E:81:B7:4D:12';

const CZ_ID = '6650f1c2a7b3e41d9c0a1b01';
const US_ID = '6650f1c2a7b3e41d9c0a1b02';
const OVPN_ID = '6650f1c2a7b3e41d9c0a1b03';
const LAN_ID = '6650f0a9a7b3e41d9c0a1a00';

function fail(code, message, hint) {
  const error = new AppError(code, message);
  if (hint) error.hint = hint;
  return error;
}

function certificate(fingerprint256) {
  return {
    subject: 'CN=unifi.local',
    issuer: 'CN=unifi.local',
    selfSigned: true,
    ca: false,
    names: ['unifi.local', 'unifi'],
    fingerprint256,
    validFrom: '2025-03-02T10:14:07.000Z',
    validTo: '2035-02-28T10:14:07.000Z',
    connectName: 'unifi.local',
  };
}

function wireguardFile(address, endpoint) {
  return [
    '[Interface]',
    'PrivateKey = <redacted>',
    `Address = ${address}`,
    'DNS = 10.0.0.243',
    '',
    '[Peer]',
    'PublicKey = sZ0Ck1FQpjDMkFRZQ2rDBz8xWiXbxHgAqhP9uOnFvj4=',
    `Endpoint = ${endpoint}:1337`,
    'AllowedIPs = 0.0.0.0/0',
    'PersistentKeepalive = 25',
    '',
  ].join('\n');
}

const NETWORKCONF_ROWS = [
  {
    _id: LAN_ID,
    name: 'Default',
    purpose: 'corporate',
    ip_subnet: '192.168.1.1/24',
    dhcpd_enabled: true,
    dhcpd_start: '192.168.1.6',
    dhcpd_stop: '192.168.1.254',
    enabled: true,
    site_id: '6650f0a9a7b3e41d9c0a19ff',
  },
  {
    _id: CZ_ID,
    name: 'WireGuard PIA CZ',
    purpose: 'vpn-client',
    vpn_type: 'wireguard-client',
    wireguard_client_mode: 'file',
    wireguard_client_configuration_file: wireguardFile('10.13.114.87/32', '185.242.6.29'),
    wireguard_client_configuration_filename: 'pia-cz-prague.conf',
    wireguard_client_peer_public_key: '<redacted>',
    x_wireguard_private_key: '<redacted>',
    enabled: true,
    site_id: '6650f0a9a7b3e41d9c0a19ff',
  },
  {
    _id: US_ID,
    name: 'WireGuard US East',
    purpose: 'vpn-client',
    vpn_type: 'wireguard-client',
    wireguard_client_mode: 'file',
    wireguard_client_configuration_file: wireguardFile('10.7.201.14/32', '84.239.43.130'),
    wireguard_client_configuration_filename: 'pia-us-east.conf',
    wireguard_client_peer_public_key: '<redacted>',
    x_wireguard_private_key: '<redacted>',
    enabled: true,
    site_id: '6650f0a9a7b3e41d9c0a19ff',
  },
  {
    _id: OVPN_ID,
    name: 'OpenVPN Office',
    purpose: 'vpn-client',
    vpn_type: 'openvpn-client',
    openvpn_configuration_filename: 'office.ovpn',
    x_openvpn_password: '<redacted>',
    openvpn_username: 'office-gateway',
    enabled: false,
    site_id: '6650f0a9a7b3e41d9c0a19ff',
  },
];

const EXPLORE = {
  '/proxy/network/integration/v1/info': () => ({ applicationVersion: FAKE_APPLICATION_VERSION }),
  '/proxy/network/integration/v1/sites': () => ({
    offset: 0,
    limit: 25,
    count: 1,
    totalCount: 1,
    data: [{ id: '88f7af54-98f8-306a-a1c7-c9349722b1f6', internalReference: 'default', name: 'Default' }],
  }),
  '/proxy/network/api/s/default/rest/networkconf': () => ({ meta: { rc: 'ok' }, data: NETWORKCONF_ROWS }),
  '/proxy/network/v2/api/site/default/vpn/connections': () => ({
    connections: [
      { network_id: CZ_ID, status: 'CONNECTING', type: 'WIREGUARD_CLIENT', notes: ['CONNECTING_LONGER_THAN_USUAL'] },
      { network_id: US_ID, status: 'CONNECTING', type: 'WIREGUARD_CLIENT', notes: ['CONNECTING_LONGER_THAN_USUAL'] },
    ],
  }),
  '/proxy/network/api/s/default/stat/health': () => ({
    meta: { rc: 'ok' },
    data: [
      { subsystem: 'wlan', num_user: 17, num_guest: 2, num_ap: 2, status: 'ok' },
      { subsystem: 'wan', status: 'ok', wan_ip: '203.0.113.24', gw_name: 'UCG Ultra', isp_name: 'Example ISP', latency: 14 },
      { subsystem: 'www', status: 'ok', latency: 14, xput_down: 412.6, xput_up: 38.1 },
      { subsystem: 'lan', status: 'ok', num_user: 23, lan_ip: '192.168.1.1' },
      { subsystem: 'vpn', status: 'ok', remote_user_enabled: false, site_to_site_enabled: false },
    ],
  }),
};

function explorePath(path) {
  if (typeof path !== 'string' || !path.startsWith('/proxy/network/')) {
    throw fail('INVALID_INPUT', 'The path must start with /proxy/network/.');
  }
  // eslint-disable-next-line no-control-regex
  if (path.includes('..') || path.includes('//') || path.includes('\\') || /[\s\x00-\x1f]/.test(path)) {
    throw fail('INVALID_INPUT', 'The path may not contain "..", "//", backslashes or spaces.');
  }
  return path.split('?')[0].replace(/\/+$/, '');
}

function consoleOrigin(url) {
  let parsed;
  try {
    parsed = new URL(String(url ?? '').trim());
  } catch {
    throw fail('INVALID_INPUT', 'That is not a valid address. Use something like https://192.168.1.1.');
  }
  if (parsed.protocol !== 'https:') {
    throw fail('INVALID_INPUT', 'The console address must start with https://.');
  }
  if (parsed.username || parsed.password || (parsed.pathname !== '/' && parsed.pathname !== '')) {
    throw fail('INVALID_INPUT', 'Enter only the console address, without a path or login, e.g. https://192.168.1.1.');
  }
  if (parsed.hostname.endsWith('.invalid')) {
    throw fail('NETWORK', `Could not connect to ${parsed.host}.`,
      'Check that this computer is on the same network as the console and that the address is right.');
  }
  if (parsed.hostname.endsWith('.tls-fail')) {
    throw fail('TLS', `${parsed.host} did not complete a secure connection.`,
      'Make sure the address points at the UniFi console and not another device.');
  }
  return parsed.origin;
}

export function createFakeEngine() {
  let presented = FINGERPRINT_A;
  let trusted = null;
  let unifiKey = false;
  let pia = false;

  const state = () => ({
    console: trusted ? { ...trusted } : null,
    unifiKey: { stored: unifiKey },
    pia: { stored: pia },
  });

  const requireKey = () => {
    if (!trusted) throw fail('NOT_CONFIGURED', 'The console is not set up yet.', 'Finish step 1 in Setup first.');
    if (!unifiKey) throw fail('NOT_CONFIGURED', 'No UniFi API key is stored yet.', 'Add the key in Setup first.');
  };

  return {
    async getState() {
      return state();
    },

    async inspectConsole(url) {
      const origin = consoleOrigin(url);
      return { url: origin, certificate: certificate(presented) };
    },

    async trustConsole(url, fingerprint256) {
      const origin = consoleOrigin(url);
      if (typeof fingerprint256 !== 'string' || !/^([0-9A-F]{2}:){31}[0-9A-F]{2}$/i.test(fingerprint256)) {
        throw fail('INVALID_INPUT', 'The certificate fingerprint is missing or malformed.');
      }
      if (fingerprint256.toUpperCase() !== presented) {
        throw fail('CERT_CHANGED', 'The console presented a different certificate than the one you checked.',
          'Nothing was trusted. Check the certificate again and compare it with your browser before trusting it.');
      }
      trusted = { url: origin, site: 'default', fingerprint256: presented, connectName: 'unifi.local', trusted: true };
      return state();
    },

    async setUnifiKey(apiKey) {
      const key = typeof apiKey === 'string' ? apiKey.trim() : '';
      if (!key) throw fail('INVALID_INPUT', 'Paste the UniFi API key first.');
      if (!trusted) throw fail('NOT_CONFIGURED', 'Trust the console certificate before adding a key.');
      if (key === 'sitemanager') {
        throw fail('UNIFI_KEY_REJECTED', 'The console rejected this API key (401 Unauthorized).', SITE_MANAGER_KEY_HINT);
      }
      unifiKey = true;
      return { verified: true, applicationVersion: FAKE_APPLICATION_VERSION };
    },

    async setPiaCredentials(username, password) {
      const user = typeof username === 'string' ? username.trim() : '';
      if (!user || typeof password !== 'string' || password.length === 0) {
        throw fail('INVALID_INPUT', 'Enter both your PIA username and password.');
      }
      pia = true;
      return state();
    },

    async forgetCredentials() {
      unifiKey = false;
      pia = false;
      return state();
    },

    async explore(path) {
      const key = explorePath(path);
      requireKey();
      const body = EXPLORE[key];
      if (body) return { status: 200, body: structuredClone(body()) };
      if (key.startsWith('/proxy/network/integration/')) {
        return { status: 404, body: { statusCode: 404, statusName: 'NOT_FOUND', message: `No route for ${key}` } };
      }
      return { status: 404, body: { meta: { rc: 'error', msg: 'api.err.NotFound' }, data: [] } };
    },

    async listTunnels() {
      requireKey();
      return {
        tunnels: [
          { id: CZ_ID, name: 'WireGuard PIA CZ', mode: 'file', enabled: true, status: 'CONNECTING', notes: ['CONNECTING_LONGER_THAN_USUAL'] },
          { id: US_ID, name: 'WireGuard US East', mode: 'file', enabled: true, status: 'CONNECTING', notes: ['CONNECTING_LONGER_THAN_USUAL'] },
          { id: OVPN_ID, name: 'OpenVPN Office', mode: 'unknown', enabled: false, status: null, notes: [] },
        ],
      };
    },

    /** Test hook, not part of the contract: the console starts presenting another certificate. */
    _rotateCertificate() {
      presented = presented === FINGERPRINT_A ? FINGERPRINT_B : FINGERPRINT_A;
    },
  };
}

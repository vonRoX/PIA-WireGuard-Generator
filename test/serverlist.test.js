import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import {
  extractServerListJson,
  toRegions,
  pickServer,
  findRegionById,
  wireGuardPort,
  isHostname,
} from '../resources/js/core/serverlist.js';
import { AppError, ErrorCode } from '../resources/js/core/errors.js';
import { serverListPayload, region } from './helpers.js';

describe('extractServerListJson', () => {
  test('reads the JSON line and ignores the trailing signature', () => {
    const payload = serverListPayload([region()]);
    const document = extractServerListJson(payload);

    assert.equal(document.regions.length, 1);
    assert.equal(document.regions[0].id, 'de-berlin');
  });

  test('is not fooled by braces inside an HTML error page', () => {
    // The v1 parser took everything up to the last '}', which an error page
    // full of inline CSS satisfies, producing a confusing parse failure.
    const html = '<!doctype html><html><style>body{color:red}</style><body>502 Bad Gateway</body></html>';

    assert.throws(() => extractServerListJson(html), (err) => {
      assert.equal(err.code, ErrorCode.PARSE);
      assert.match(err.message, /web page/i);
      return true;
    });
  });

  test('reports an empty body plainly', () => {
    for (const empty of ['', '   ', '\n\n']) {
      assert.throws(() => extractServerListJson(empty), (err) => {
        assert.equal(err.code, ErrorCode.PARSE);
        assert.match(err.message, /empty/i);
        return true;
      });
    }
  });

  test('reports malformed JSON without leaking a wall of text', () => {
    assert.throws(() => extractServerListJson('{"regions": [ truncated'), (err) => {
      assert.equal(err.code, ErrorCode.PARSE);
      assert.ok(err.detail.length <= 200);
      return true;
    });
  });
});

describe('toRegions', () => {
  test('keeps only regions with a verifiable WireGuard server', () => {
    const regions = toRegions({
      regions: [
        region({ id: 'ok', name: 'Has WG' }),
        region({ id: 'no-wg', name: 'No WireGuard', servers: { meta: [{ ip: '1.2.3.4', cn: 'x' }] } }),
        region({ id: 'empty-wg', name: 'Empty WG', servers: { wg: [] } }),
        region({ id: 'no-cn', name: 'No common name', servers: { wg: [{ ip: '1.2.3.4' }] } }),
        region({ id: 'blank-cn', name: 'Blank common name', servers: { wg: [{ ip: '1.2.3.4', cn: '' }] } }),
      ],
    });

    assert.deepEqual(regions.map((r) => r.id), ['ok']);
  });

  test('sorts by display name', () => {
    const regions = toRegions({
      regions: [
        region({ id: 'c', name: 'Zurich' }),
        region({ id: 'a', name: 'Amsterdam' }),
        region({ id: 'b', name: 'Madrid' }),
      ],
    });

    assert.deepEqual(regions.map((r) => r.name), ['Amsterdam', 'Madrid', 'Zurich']);
  });

  test('carries through the flags worth showing a user', () => {
    const [only] = toRegions({ regions: [region({ port_forward: true, geo: true, country: 'DE' })] });

    assert.equal(only.portForward, true);
    assert.equal(only.geo, true);
    assert.equal(only.country, 'DE');
    assert.deepEqual(only.servers, [{ ip: '193.176.86.1', cn: 'berlin401' }]);
  });

  test('a payload without a regions array is an explicit failure, not a silent hang', () => {
    // v1's `if (data && data.regions)` had no else, so the UI sat on a fake
    // "Loading regions…" placeholder forever with no message and no retry.
    for (const bad of [{}, { regions: 'nope' }, { error: 'nope' }, null, 'string']) {
      assert.throws(() => toRegions(bad), (err) => {
        assert.ok(err instanceof AppError);
        assert.equal(err.code, ErrorCode.PROTOCOL);
        return true;
      }, `${JSON.stringify(bad)} was accepted`);
    }
  });

  test('a payload where nothing is usable says so', () => {
    assert.throws(
      () => toRegions({ regions: [region({ servers: { wg: [] } })] }),
      (err) => {
        assert.equal(err.code, ErrorCode.NO_SERVERS);
        return true;
      },
    );
  });
});

describe('server entries are validated before they can reach a URL', () => {
  test('isHostname accepts real names and rejects anything with structure in it', () => {
    for (const good of ['berlin401', 'de-berlin-401.privacy.network', 'a', 'x1.y2.z3']) {
      assert.ok(isHostname(good), good);
    }
    // Each of these would change the meaning of `https://<cn>:1337/addKey`
    // or of curl's colon-separated --connect-to field.
    for (const bad of [
      'evil.com/path', 'user@evil.com', 'host:1337', 'a b', '-leading', 'trailing-',
      '', '.', 'a..b', '.leading', 'trailing.', 'a'.repeat(64), 'x'.repeat(254),
      'host\nnewline', 'host"quote', null, undefined, 42, {},
    ]) {
      assert.equal(isHostname(bad), false, JSON.stringify(bad));
    }
  });

  test('a region whose server has a malformed common name is dropped', () => {
    assert.throws(() => toRegions({
      regions: [region({ servers: { wg: [{ ip: '1.2.3.4', cn: 'evil.com/x' }] } })],
    }), (err) => {
      assert.equal(err.code, ErrorCode.NO_SERVERS);
      return true;
    });
  });

  test('a region whose server address is not an IPv4 address is dropped', () => {
    assert.throws(() => toRegions({
      regions: [region({ servers: { wg: [{ ip: 'not-an-ip', cn: 'berlin401' }] } })],
    }), (err) => {
      assert.equal(err.code, ErrorCode.NO_SERVERS);
      return true;
    });
  });

  test('a well-formed entry alongside malformed ones survives', () => {
    const [only] = toRegions({
      regions: [region({
        servers: {
          wg: [
            { ip: '1.2.3.4', cn: 'a@b' },
            { ip: '999.1.1.1', cn: 'ok401' },
            { ip: '5.6.7.8', cn: 'good401.privacy.network' },
          ],
        },
      })],
    });

    assert.deepEqual(only.servers, [{ ip: '5.6.7.8', cn: 'good401.privacy.network' }]);
  });
});

describe('wireGuardPort', () => {
  test('prefers the published port', () => {
    assert.equal(wireGuardPort({ groups: { wg: [{ ports: [1337] }] } }), 1337);
    assert.equal(wireGuardPort({ groups: { wg: [{ ports: [8443] }] } }), 8443);
  });

  test('falls back when the payload does not say', () => {
    assert.equal(wireGuardPort({}), 1337);
    assert.equal(wireGuardPort({ groups: {} }), 1337);
    assert.equal(wireGuardPort({ groups: { wg: [] } }), 1337);
    assert.equal(wireGuardPort({ groups: { wg: [{ ports: [] }] } }), 1337);
    assert.equal(wireGuardPort({ groups: { wg: [{ ports: ['nope'] }] } }), 1337);
    assert.equal(wireGuardPort({ groups: { wg: [{ ports: [99999] }] } }), 1337);
    assert.equal(wireGuardPort(null), 1337);
  });
});

describe('pickServer', () => {
  test('picks from the region\'s own list', () => {
    const [only] = toRegions({
      regions: [region({ servers: { wg: [{ ip: '1.1.1.1', cn: 'a' }, { ip: '2.2.2.2', cn: 'b' }] } })],
    });

    assert.deepEqual(pickServer(only, () => 0), { ip: '1.1.1.1', cn: 'a' });
    assert.deepEqual(pickServer(only, () => 0.99), { ip: '2.2.2.2', cn: 'b' });
  });

  test('stays in bounds even if the random source returns exactly 1', () => {
    const [only] = toRegions({ regions: [region()] });
    assert.ok(pickServer(only, () => 1));
  });

  test('refuses an empty region', () => {
    assert.throws(() => pickServer({ servers: [] }), AppError);
    assert.throws(() => pickServer(null), AppError);
  });
});

describe('findRegionById', () => {
  test('finds by the stable id rather than by position', () => {
    const regions = toRegions({
      regions: [region({ id: 'ch-zurich', name: 'Switzerland' }), region({ id: 'de-berlin', name: 'Germany' })],
    });

    assert.equal(findRegionById(regions, 'ch-zurich').name, 'Switzerland');
    assert.equal(findRegionById(regions, 'nope'), undefined);
  });
});

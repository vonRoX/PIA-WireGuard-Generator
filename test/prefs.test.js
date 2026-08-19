import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { Prefs, Keys, SCHEMA_VERSION, MAX_FAVOURITES, groupByFavourite } from '../resources/js/core/prefs.js';
import { isTokenExpired, TOKEN_LIFETIME_MS } from '../resources/js/core/pia.js';
import { toRegions } from '../resources/js/core/serverlist.js';
import { memoryStorage, region } from './helpers.js';

describe('migration from v1', () => {
  test('deletes the token v1 wrote to disk without asking', async () => {
    const storage = memoryStorage({
      authToken: 'a-real-bearer-token',
      username: 'p1234567',
      selectedRegionIndex: '87',
      dnsPreset: '10.0.0.242',
    });

    const result = await new Prefs(storage).migrate();

    assert.deepEqual(result, { migrated: true, purgedToken: true });
    assert.equal(storage.map.has('authToken'), false);
    assert.equal(storage.map.has('selectedRegionIndex'), false, 'an index into a remote list means nothing now');

    // Preferences that are not credentials survive the upgrade.
    assert.equal(storage.map.get('username'), 'p1234567');
    assert.equal(storage.map.get('dnsPreset'), '10.0.0.242');
    assert.equal(storage.map.get(Keys.SCHEMA_VERSION), SCHEMA_VERSION);
  });

  test('reports honestly when there was no token to purge', async () => {
    const storage = memoryStorage({ username: 'p1' });
    assert.deepEqual(await new Prefs(storage).migrate(), { migrated: true, purgedToken: false });
  });

  test('is a no-op once the schema is current', async () => {
    const storage = memoryStorage({ [Keys.SCHEMA_VERSION]: SCHEMA_VERSION, authToken: 'keep-me' });

    assert.deepEqual(await new Prefs(storage).migrate(), { migrated: false, purgedToken: false });
    assert.equal(storage.map.get('authToken'), 'keep-me');
  });
});

describe('token storage', () => {
  test('is not written unless the user opted in', async () => {
    const storage = memoryStorage();
    const prefs = new Prefs(storage);

    assert.equal(await prefs.getStaySignedIn(), false, 'opt-in must default to off');

    await prefs.setStaySignedIn(true);
    await prefs.setToken('tok');
    assert.equal(storage.map.get(Keys.AUTH_TOKEN), 'tok');

    await prefs.setStaySignedIn(false);
    assert.equal(storage.map.has(Keys.AUTH_TOKEN), false, 'opting out must remove what was stored');
  });

  test('an expired token is dropped rather than trusted', async () => {
    const storage = memoryStorage();
    const prefs = new Prefs(storage);

    await prefs.setToken('stale', Date.now() - TOKEN_LIFETIME_MS - 1);

    assert.deepEqual(await prefs.getToken(isTokenExpired), { token: '', expired: true });
    assert.equal(storage.map.has(Keys.AUTH_TOKEN), false);
    assert.equal(storage.map.has(Keys.AUTH_TOKEN_ISSUED_AT), false);
  });

  test('a fresh token is returned', async () => {
    const prefs = new Prefs(memoryStorage());
    await prefs.setToken('fresh', Date.now() - 60_000);

    assert.deepEqual(await prefs.getToken(isTokenExpired), { token: 'fresh', expired: false });
  });

  test('a token with no recorded issue time is treated as expired', async () => {
    const storage = memoryStorage({ [Keys.AUTH_TOKEN]: 'orphan' });
    assert.deepEqual(await new Prefs(storage).getToken(isTokenExpired), { token: '', expired: true });
  });

  test('nothing stored means nothing to restore', async () => {
    assert.equal(await new Prefs(memoryStorage()).getToken(isTokenExpired), null);
  });

  test('signing out clears the token and the opt-in', async () => {
    const storage = memoryStorage();
    const prefs = new Prefs(storage);

    await prefs.setStaySignedIn(true);
    await prefs.setToken('tok');
    await prefs.setUsername('p1234567');
    await prefs.signOut();

    assert.equal(storage.map.has(Keys.AUTH_TOKEN), false);
    assert.equal(storage.map.get(Keys.STAY_SIGNED_IN), '0');
    assert.equal(storage.map.get(Keys.USERNAME), 'p1234567', 'the username is a convenience, not a credential');
  });
});

describe('isTokenExpired', () => {
  test('draws the line where the lifetime says', () => {
    const now = 1_000_000_000_000;
    assert.equal(isTokenExpired(now - TOKEN_LIFETIME_MS + 1, now), false);
    assert.equal(isTokenExpired(now - TOKEN_LIFETIME_MS, now), true);
    assert.equal(isTokenExpired(now, now), false);
  });

  test('treats nonsense as expired', () => {
    for (const bad of [NaN, 0, -1, undefined, null, Infinity]) {
      assert.equal(isTokenExpired(bad, Date.now()), true, String(bad));
    }
  });
});

describe('region preference', () => {
  test('is stored by id, so a shifting server list cannot repoint it', async () => {
    const storage = memoryStorage();
    const prefs = new Prefs(storage);

    await prefs.setRegionId('ch-zurich');
    assert.equal(storage.map.get(Keys.REGION_ID), 'ch-zurich');
    assert.equal(await prefs.getRegionId(), 'ch-zurich');

    await prefs.setRegionId('');
    assert.equal(storage.map.has(Keys.REGION_ID), false);
  });
});

describe('favourites', () => {
  test('toggle on and off, newest first', async () => {
    const prefs = new Prefs(memoryStorage());

    assert.deepEqual(await prefs.toggleFavourite('a'), ['a']);
    assert.deepEqual(await prefs.toggleFavourite('b'), ['b', 'a']);
    assert.deepEqual(await prefs.toggleFavourite('a'), ['b']);
    assert.deepEqual(await prefs.getFavourites(), ['b']);
  });

  test('are capped and de-duplicated', async () => {
    const prefs = new Prefs(memoryStorage());
    const many = Array.from({ length: MAX_FAVOURITES + 5 }, (_, i) => `r${i}`);

    const stored = await prefs.setFavourites([...many, ...many]);
    assert.equal(stored.length, MAX_FAVOURITES);
    assert.equal(new Set(stored).size, MAX_FAVOURITES);
  });

  test('survive corrupt storage without throwing', async () => {
    for (const junk of ['not json', '{"not":"an array"}', '[1,2,3]', '']) {
      const prefs = new Prefs(memoryStorage({ [Keys.FAVOURITES]: junk }));
      assert.deepEqual(await prefs.getFavourites(), []);
    }
  });
});

describe('groupByFavourite', () => {
  const regions = toRegions({
    regions: [
      region({ id: 'a', name: 'Amsterdam' }),
      region({ id: 'b', name: 'Berlin' }),
      region({ id: 'c', name: 'Chicago' }),
    ],
  });

  test('pins favourites in the order they were starred', () => {
    const { favourites, rest } = groupByFavourite(regions, ['c', 'a']);

    assert.deepEqual(favourites.map((r) => r.id), ['c', 'a']);
    assert.deepEqual(rest.map((r) => r.id), ['b']);
  });

  test('ignores favourites that are no longer offered', () => {
    const { favourites, rest } = groupByFavourite(regions, ['gone', 'b']);

    assert.deepEqual(favourites.map((r) => r.id), ['b']);
    assert.deepEqual(rest.map((r) => r.id), ['a', 'c']);
  });

  test('with no favourites, everything stays in the main list', () => {
    const { favourites, rest } = groupByFavourite(regions, []);

    assert.deepEqual(favourites, []);
    assert.equal(rest.length, 3);
  });
});

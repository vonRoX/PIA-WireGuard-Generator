/**
 * Persisted preferences, with a deliberate line between "convenience" and
 * "credential".
 *
 * Version 1 wrote the API token to disk unconditionally and remembered the
 * chosen region as an *array index* into a list fetched from the network — so
 * when PIA added or dropped a region, the saved index silently pointed at a
 * different country and the app generated a config for the wrong place without
 * saying anything. Regions are keyed by their stable `id` now, and the token is
 * only stored when the user asks for it.
 */

export const SCHEMA_VERSION = '2';

export const Keys = Object.freeze({
  SCHEMA_VERSION: 'schemaVersion',
  USERNAME: 'username',
  REGION_ID: 'regionId',
  FAVOURITES: 'favouriteRegionIds',
  DNS_PRESET: 'dnsPreset',
  CUSTOM_DNS: 'customDns',
  STAY_SIGNED_IN: 'staySignedIn',
  AUTH_TOKEN: 'authToken',
  AUTH_TOKEN_ISSUED_AT: 'authTokenIssuedAt',
});

/** Keys written by v1 that carry no meaning under the v2 schema. */
const V1_KEYS_TO_PURGE = ['selectedRegionIndex'];

/** Everything that is, or could contain, a credential. */
const CREDENTIAL_KEYS = [Keys.AUTH_TOKEN, Keys.AUTH_TOKEN_ISSUED_AT];

export const MAX_FAVOURITES = 12;

/**
 * @typedef {object} StorageAdapter
 * @property {(key: string) => Promise<string|null>} getItem
 * @property {(key: string, value: string) => Promise<void>} setItem
 * @property {(key: string) => Promise<void>} removeItem
 */

export class Prefs {
  /** @param {StorageAdapter} storage */
  constructor(storage) {
    this.storage = storage;
  }

  /**
   * Bring storage up to the current schema.
   *
   * Upgrading from v1 deletes any token that was written to disk before the
   * user had a say in it. That is a one-time sign-out, and the right trade for
   * a tool whose whole promise is that it minds your credentials.
   *
   * @returns {Promise<{migrated: boolean, purgedToken: boolean}>}
   */
  async migrate() {
    const version = await this.storage.getItem(Keys.SCHEMA_VERSION);
    if (version === SCHEMA_VERSION) {
      return { migrated: false, purgedToken: false };
    }

    const hadToken = Boolean(await this.storage.getItem(Keys.AUTH_TOKEN));

    for (const key of [...CREDENTIAL_KEYS, ...V1_KEYS_TO_PURGE]) {
      await this.storage.removeItem(key);
    }
    await this.storage.setItem(Keys.SCHEMA_VERSION, SCHEMA_VERSION);

    return { migrated: true, purgedToken: hadToken };
  }

  /** @returns {Promise<string>} */
  async getUsername() {
    return (await this.storage.getItem(Keys.USERNAME)) || '';
  }

  /** @param {string} username */
  async setUsername(username) {
    await this.storage.setItem(Keys.USERNAME, username || '');
  }

  /** @returns {Promise<boolean>} */
  async getStaySignedIn() {
    return (await this.storage.getItem(Keys.STAY_SIGNED_IN)) === '1';
  }

  /** @param {boolean} value */
  async setStaySignedIn(value) {
    await this.storage.setItem(Keys.STAY_SIGNED_IN, value ? '1' : '0');
    if (!value) await this.clearToken();
  }

  /**
   * Read a stored token, if there is one and it is still plausibly valid.
   *
   * @param {(issuedAt: number) => boolean} isExpired
   * @returns {Promise<{token: string, expired: boolean} | null>}
   */
  async getToken(isExpired) {
    const token = await this.storage.getItem(Keys.AUTH_TOKEN);
    if (!token) return null;

    const issuedAt = Number(await this.storage.getItem(Keys.AUTH_TOKEN_ISSUED_AT));
    if (isExpired(issuedAt)) {
      await this.clearToken();
      return { token: '', expired: true };
    }

    return { token, expired: false };
  }

  /**
   * @param {string} token
   * @param {number} [issuedAt]
   */
  async setToken(token, issuedAt = Date.now()) {
    await this.storage.setItem(Keys.AUTH_TOKEN, token);
    await this.storage.setItem(Keys.AUTH_TOKEN_ISSUED_AT, String(issuedAt));
  }

  async clearToken() {
    for (const key of CREDENTIAL_KEYS) {
      await this.storage.removeItem(key);
    }
  }

  /** @returns {Promise<string>} */
  async getRegionId() {
    return (await this.storage.getItem(Keys.REGION_ID)) || '';
  }

  /** @param {string} regionId */
  async setRegionId(regionId) {
    if (regionId) {
      await this.storage.setItem(Keys.REGION_ID, regionId);
    } else {
      await this.storage.removeItem(Keys.REGION_ID);
    }
  }

  /** @returns {Promise<string[]>} */
  async getFavourites() {
    const raw = await this.storage.getItem(Keys.FAVOURITES);
    if (!raw) return [];
    try {
      const parsed = JSON.parse(raw);
      return Array.isArray(parsed) ? parsed.filter((id) => typeof id === 'string').slice(0, MAX_FAVOURITES) : [];
    } catch {
      return [];
    }
  }

  /** @param {string[]} ids */
  async setFavourites(ids) {
    const unique = [...new Set(ids.filter((id) => typeof id === 'string' && id !== ''))].slice(0, MAX_FAVOURITES);
    await this.storage.setItem(Keys.FAVOURITES, JSON.stringify(unique));
    return unique;
  }

  /**
   * @param {string} regionId
   * @returns {Promise<string[]>} the new favourites list
   */
  async toggleFavourite(regionId) {
    const current = await this.getFavourites();
    const next = current.includes(regionId)
      ? current.filter((id) => id !== regionId)
      : [regionId, ...current];
    return this.setFavourites(next);
  }

  /** @returns {Promise<{preset: string, custom: string}>} */
  async getDns() {
    return {
      preset: (await this.storage.getItem(Keys.DNS_PRESET)) || '',
      custom: (await this.storage.getItem(Keys.CUSTOM_DNS)) || '',
    };
  }

  /**
   * @param {string} preset
   * @param {string} custom
   */
  async setDns(preset, custom) {
    await this.storage.setItem(Keys.DNS_PRESET, preset || '');
    await this.storage.setItem(Keys.CUSTOM_DNS, custom || '');
  }

  /** Forget everything tied to the signed-in account, keeping UI preferences. */
  async signOut() {
    await this.clearToken();
    await this.storage.setItem(Keys.STAY_SIGNED_IN, '0');
  }
}

/**
 * Order regions for display: favourites first (in the order they were starred),
 * then everything else alphabetically.
 *
 * @param {import('./serverlist.js').Region[]} regions already sorted by name
 * @param {string[]} favouriteIds
 * @returns {{favourites: import('./serverlist.js').Region[], rest: import('./serverlist.js').Region[]}}
 */
export function groupByFavourite(regions, favouriteIds) {
  const favouriteSet = new Set(favouriteIds);
  const byId = new Map(regions.map((region) => [region.id, region]));

  const favourites = favouriteIds.map((id) => byId.get(id)).filter(Boolean);
  const rest = regions.filter((region) => !favouriteSet.has(region.id));

  return { favourites, rest };
}

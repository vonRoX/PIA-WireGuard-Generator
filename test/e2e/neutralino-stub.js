/**
 * Stands in for the Neutralino client library during browser tests.
 *
 * Served at `js/neutralino.js`, the same route the real runtime serves — which
 * is also where Neutralino injects its globals, so this file mirrors both jobs.
 * Scripted responses come from `window.__FIXTURES__`, installed by the test
 * before any page script runs.
 *
 * Every call is recorded on `window.__CALLS__` so a test can assert not only
 * what the user sees but what the app asked the machine to do — that the
 * command line never carries a password, that the saved file gets its
 * permissions tightened, that a token is only written when it was opted into.
 */

var NL_APPVERSION = '2.0.0';
var NL_OS = 'Linux';
var NL_MODE = 'window';

(function initialiseStub() {
  const fixtures = window.__FIXTURES__ || {};
  const calls = { exec: [], storage: [], files: [], permissions: [], dialogs: [], clipboard: [] };
  window.__CALLS__ = calls;

  const storage = new Map(Object.entries(fixtures.storage || {}));
  const listeners = new Map();

  const defer = (value) => Promise.resolve(value);
  const reject = (message) => Promise.reject(new Error(message));

  /** Which PIA call is this config file for? */
  function classify(stdIn) {
    if (!stdIn) return 'unknown';
    if (stdIn.includes('/api/client/v2/token')) return 'token';
    if (stdIn.includes('serverlist.piaservers.net')) return 'serverList';
    if (stdIn.includes('/addKey')) return 'addKey';
    return 'unknown';
  }

  const attempts = {};

  function respond(kind) {
    const scripted = (fixtures.responses || {})[kind];

    // An array scripts one answer per attempt; the last entry then repeats, so a
    // retry test does not have to predict how many calls the app will make.
    if (Array.isArray(scripted)) {
      const index = Math.min(attempts[kind] || 0, scripted.length - 1);
      attempts[kind] = (attempts[kind] || 0) + 1;
      return scripted[index];
    }

    if (scripted) return scripted;

    return { exitCode: 0, stdOut: '{}\n200', stdErr: '' };
  }

  window.Neutralino = {
    init() {
      setTimeout(() => emit('ready'), 0);
    },

    events: {
      on(name, handler) {
        if (!listeners.has(name)) listeners.set(name, []);
        listeners.get(name).push(handler);
        return defer();
      },
      dispatch(name, detail) {
        emit(name, detail);
        return defer();
      },
    },

    app: {
      exit() {
        calls.exec.push({ command: '<exit>' });
        return defer();
      },
    },

    os: {
      execCommand(command, options) {
        const stdIn = (options || {}).stdIn;
        calls.exec.push({ command, stdIn });

        if (command === 'curl --version') {
          return defer(fixtures.curlVersion || {
            exitCode: 0,
            stdOut: 'curl 8.5.0 (x86_64-pc-linux-gnu) libcurl/8.5.0 OpenSSL/3.0.13',
            stdErr: '',
          });
        }

        return defer(respond(classify(stdIn)));
      },

      getPath(name) {
        return defer(`/tmp/stub-${name}`);
      },

      showSaveDialog(title, options) {
        calls.dialogs.push({ title, options });
        return defer(fixtures.savePath === undefined ? '/tmp/saved/PIA.conf' : fixtures.savePath);
      },
    },

    filesystem: {
      getJoinedPath(...parts) {
        return defer(parts.join('/'));
      },
      writeFile(path, data) {
        calls.files.push({ path, data });
        return fixtures.writeFails ? reject('disk full') : defer();
      },
      setPermissions(path, permissions, mode) {
        calls.permissions.push({ path, permissions, mode });
        return fixtures.permissionsFail ? reject('unsupported') : defer();
      },
      remove(path) {
        calls.files.push({ path, removed: true });
        return defer();
      },
    },

    storage: {
      getData(key) {
        calls.storage.push({ op: 'get', key });
        if (!storage.has(key)) return reject(`key ${key} not found`);
        return defer(storage.get(key));
      },
      setData(key, value) {
        calls.storage.push({ op: 'set', key, value });
        storage.set(key, value);
        return defer();
      },
      removeData(key) {
        calls.storage.push({ op: 'remove', key });
        storage.delete(key);
        return defer();
      },
    },

    clipboard: {
      writeText(text) {
        calls.clipboard.push(text);
        return defer();
      },
    },
  };

  window.__STORAGE__ = storage;

  function emit(name, detail) {
    for (const handler of listeners.get(name) || []) handler({ detail });
  }
})();

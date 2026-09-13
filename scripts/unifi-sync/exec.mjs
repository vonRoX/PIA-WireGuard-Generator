/**
 * Running curl from Node without a shell.
 *
 * The desktop app has to go through Neutralino's `os.execCommand`, which hands
 * its argument to `/bin/sh -c` or `cmd.exe /c`, and defends itself by never
 * putting user data into that string. Node has `execFile`, which needs no such
 * defence: the program and its arguments are passed as an array, and there is
 * no shell in the picture at all. The request still travels on stdin as a curl
 * config file, exactly as it does in the app, so the same `HttpClient` and
 * `PiaClient` run unchanged.
 */

import { execFile } from 'node:child_process';

import { CURL_COMMAND } from '../../resources/js/core/curl.js';

/** The only two commands `HttpClient` ever issues. Anything else is a bug. */
const ALLOWED = new Map([
  [CURL_COMMAND, ['curl', '-q', '--config', '-']],
  ['curl --version', ['curl', '--version']],
]);

/**
 * An `ExecFn` for {@link import('../../resources/js/core/http.js').HttpClient}.
 *
 * @param {string} command
 * @param {{stdIn?: string}} [options]
 * @returns {Promise<{exitCode: number, stdOut: string, stdErr: string}>}
 */
export function curlExec(command, options = {}) {
  const argv = ALLOWED.get(command);
  if (!argv) {
    return Promise.reject(new Error(`refusing to run an unexpected command: ${command.slice(0, 40)}`));
  }

  const [file, ...args] = argv;

  return new Promise((resolve) => {
    const child = execFile(file, args, {
      encoding: 'utf8',
      maxBuffer: 16 * 1024 * 1024,
      windowsHide: true,
    }, (error, stdOut, stdErr) => {
      if (!error) {
        resolve({ exitCode: 0, stdOut, stdErr });
      } else if (error.code === 'ENOENT') {
        resolve({ exitCode: 127, stdOut: '', stdErr: 'curl was not found on PATH' });
      } else {
        resolve({ exitCode: typeof error.code === 'number' ? error.code : -1, stdOut: stdOut || '', stdErr: stdErr || error.message });
      }
    });

    child.stdin.on('error', () => { /* curl exited before reading; the exit code tells the story */ });
    if (typeof options.stdIn === 'string') child.stdin.write(options.stdIn);
    child.stdin.end();
  });
}

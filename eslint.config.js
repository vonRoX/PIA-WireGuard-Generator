import js from '@eslint/js';
import globals from 'globals';

export default [
  {
    ignores: [
      'bin/**',
      'dist/**',
      'node_modules/**',
      'resources/js/vendor/**',
      'resources/js/neutralino.js',
      'test-results/**',
      'playwright-report/**',
    ],
  },

  js.configs.recommended,

  {
    // The app itself: browser code running inside the Neutralino webview.
    files: ['resources/js/**/*.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: {
        ...globals.browser,
        // Injected by the Neutralino runtime, which prepends them to neutralino.js.
        Neutralino: 'readonly',
        NL_APPID: 'readonly',
        NL_APPVERSION: 'readonly',
        NL_CVERSION: 'readonly',
        NL_MODE: 'readonly',
        NL_OS: 'readonly',
        NL_PATH: 'readonly',
        NL_PORT: 'readonly',
        NL_TOKEN: 'readonly',
        NL_VERSION: 'readonly',
        // tweetnacl, loaded as a classic script.
        nacl: 'readonly',
        // Available in the webview; the Node test run uses Buffer instead.
        Buffer: 'readonly',
      },
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'no-console': 'error',
      'no-var': 'error',
      'prefer-const': 'error',
      'no-implicit-globals': 'error',
      'no-eval': 'error',
      'no-implied-eval': 'error',
      'no-new-func': 'error',
      // innerHTML and friends have no business in an app that renders values
      // straight out of a network response.
      'no-restricted-properties': ['error',
        { property: 'innerHTML', message: 'Use textContent or createElement — innerHTML is not needed here.' },
        { property: 'outerHTML', message: 'Use textContent or createElement — outerHTML is not needed here.' },
      ],
      'no-restricted-globals': ['error',
        { name: 'fetch', message: 'PIA blocks cross-origin fetch from the webview; use the curl-backed HttpClient.' },
      ],
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },

  {
    // Browser-side test doubles: these run inside the page, not in Node.
    files: ['test/e2e/neutralino-stub.js'],
    languageOptions: {
      ecmaVersion: 2023,
      // A classic script, like the client library it replaces: top-level `var`
      // is how the NL_* globals the app reads come into existence.
      sourceType: 'script',
      globals: { ...globals.browser },
    },
    rules: {
      'no-var': 'off',
      'no-unused-vars': ['error', { varsIgnorePattern: '^NL_' }],
    },
  },

  {
    // Playwright specs and the screenshot script: Node, but they hand snippets
    // to the browser, so both sets of globals are legitimate here.
    files: ['test/e2e/**/*.js', 'scripts/screenshots.mjs'],
    ignores: ['test/e2e/neutralino-stub.js'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node, ...globals.browser },
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_', varsIgnorePattern: '^_' }],
    },
  },

  {
    // Tooling and tests: Node.
    files: ['scripts/**/*.{js,mjs}', 'test/**/*.{js,mjs}', 'eslint.config.js', 'playwright.config.js'],
    ignores: ['test/e2e/**', 'scripts/screenshots.mjs'],
    languageOptions: {
      ecmaVersion: 2023,
      sourceType: 'module',
      globals: { ...globals.node },
    },
    rules: {
      eqeqeq: ['error', 'always'],
      'no-var': 'error',
      'prefer-const': 'error',
      'no-unused-vars': ['error', { argsIgnorePattern: '^_' }],
    },
  },
];

import { test, describe } from 'node:test';
import assert from 'node:assert/strict';

import { resolveDns, isPiaResolver, DNS_PRESETS, DEFAULT_DNS, CUSTOM_DNS } from '../resources/js/core/dns.js';
import { AppError, ErrorCode } from '../resources/js/core/errors.js';

describe('resolveDns', () => {
  test('passes a preset straight through', () => {
    for (const preset of DNS_PRESETS.filter((p) => p.value !== CUSTOM_DNS)) {
      assert.equal(resolveDns(preset.value, ''), preset.value);
    }
  });

  test('normalises a custom list', () => {
    assert.equal(resolveDns(CUSTOM_DNS, '1.1.1.1'), '1.1.1.1');
    assert.equal(resolveDns(CUSTOM_DNS, ' 1.1.1.1 , 9.9.9.9 '), '1.1.1.1, 9.9.9.9');
    assert.equal(resolveDns(CUSTOM_DNS, '1.1.1.1,,9.9.9.9,'), '1.1.1.1, 9.9.9.9');
  });

  test('refuses an empty custom value instead of silently substituting one', () => {
    // v1 quietly swapped in 1.1.1.1, sending queries to Cloudflare from a tool
    // whose entire point is not leaking them.
    for (const empty of ['', '   ', ',,,']) {
      assert.throws(() => resolveDns(CUSTOM_DNS, empty), (err) => {
        assert.ok(err instanceof AppError);
        assert.equal(err.code, ErrorCode.INVALID_INPUT);
        return true;
      });
    }
  });

  test('refuses anything that is not an IPv4 address', () => {
    for (const bad of ['dns.google', '1.1.1.256', '::1', '1.1.1', 'localhost', '1.1.1.1;rm -rf /']) {
      assert.throws(() => resolveDns(CUSTOM_DNS, bad), AppError, bad);
    }
  });

  test('names the offending entry so the user can fix it', () => {
    assert.throws(() => resolveDns(CUSTOM_DNS, '1.1.1.1, nope.example'), (err) => {
      assert.match(err.message, /"nope\.example" is not a valid IPv4 address/);
      return true;
    });
  });

  test('caps the list at something sane', () => {
    assert.throws(() => resolveDns(CUSTOM_DNS, '1.1.1.1,2.2.2.2,3.3.3.3,4.4.4.4,5.5.5.5'), AppError);
  });

  test('refuses a preset value that is not a real address', () => {
    assert.throws(() => resolveDns('', ''), AppError);
    assert.throws(() => resolveDns('not-a-preset', ''), AppError);
  });
});

describe('presets', () => {
  test('the default is one of them', () => {
    assert.ok(DNS_PRESETS.some((preset) => preset.value === DEFAULT_DNS));
  });

  test('every preset has a label and a hint', () => {
    for (const preset of DNS_PRESETS) {
      assert.ok(preset.label && preset.hint, `${preset.value} is missing copy`);
    }
  });

  test('isPiaResolver knows which choices keep queries in the tunnel', () => {
    assert.equal(isPiaResolver('10.0.0.243'), true);
    assert.equal(isPiaResolver('1.1.1.1'), false);
    assert.equal(isPiaResolver(CUSTOM_DNS), false);
  });
});

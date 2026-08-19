/**
 * DNS choices offered on the configuration screen.
 *
 * PIA's resolvers only answer from inside the tunnel, which is what makes them
 * leak-free; the custom option exists for people pointing at a Pi-hole or a
 * resolver of their own.
 */

import { AppError, ErrorCode } from './errors.js';
import { isIpv4 } from './wireguard.js';

export const DNS_PRESETS = Object.freeze([
  { value: '10.0.0.243', label: 'PIA — Streaming optimised', hint: 'Best for bypassing geo-blocks' },
  { value: '10.0.0.242', label: 'PIA — Standard', hint: "PIA's plain in-tunnel resolver" },
  { value: '10.0.0.244', label: 'PIA — MACE (ad & tracker blocking)', hint: 'Blocks ads and trackers at the resolver' },
  { value: '10.0.0.241', label: 'PIA — Streaming + MACE', hint: 'Both of the above' },
  { value: 'custom', label: 'Custom…', hint: 'Point at your own resolver' },
]);

export const DEFAULT_DNS = '10.0.0.243';
export const CUSTOM_DNS = 'custom';

const MAX_DNS_SERVERS = 4;

/**
 * Normalise and validate a DNS selection into the string the config file uses.
 *
 * @param {string} preset the selected preset value, or 'custom'
 * @param {string} customValue raw text from the custom field
 * @returns {string} comma-separated addresses
 * @throws {AppError} when a custom value is empty or not a list of IPv4 addresses
 */
export function resolveDns(preset, customValue) {
  if (preset !== CUSTOM_DNS) {
    if (!isIpv4(preset)) {
      throw new AppError(ErrorCode.INVALID_INPUT, 'Pick a DNS option before generating a configuration.');
    }
    return preset;
  }

  const parts = String(customValue || '')
    .split(',')
    .map((part) => part.trim())
    .filter((part) => part !== '');

  if (parts.length === 0) {
    throw new AppError(ErrorCode.INVALID_INPUT, 'Enter a custom DNS address, or choose one of the presets.');
  }

  if (parts.length > MAX_DNS_SERVERS) {
    throw new AppError(ErrorCode.INVALID_INPUT, `Enter at most ${MAX_DNS_SERVERS} DNS addresses.`);
  }

  const invalid = parts.filter((part) => !isIpv4(part));
  if (invalid.length > 0) {
    throw new AppError(
      ErrorCode.INVALID_INPUT,
      `"${invalid[0]}" is not a valid IPv4 address. Use addresses like 1.1.1.1, separated by commas.`,
    );
  }

  return parts.join(', ');
}

/**
 * Is this DNS choice one that keeps queries inside the tunnel?
 *
 * @param {string} dns
 * @returns {boolean}
 */
export function isPiaResolver(dns) {
  return DNS_PRESETS.some((preset) => preset.value !== CUSTOM_DNS && dns === preset.value);
}

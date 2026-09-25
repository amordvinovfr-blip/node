import { randomInt } from 'node:crypto';
import { isIP } from 'node:net';
import { domainToASCII } from 'node:url';
import { getDomain } from 'tldts';

const LABEL = /^[a-z0-9_](?:[a-z0-9_-]{0,61}[a-z0-9_])?$/;
const PLAIN_ASCII = /^[a-z0-9._-]+$/;

/**
 * Lowercase ASCII (punycode) hostname, or null for IP literals and garbage.
 */
export const normalizeHostname = (input: string): string | null => {
    const trimmed = input.trim().replace(/\.$/, '');
    if (!trimmed || trimmed.length > 253 || isIP(trimmed.replace(/^\[|\]$/g, ''))) return null;

    // Lowercase LDH names without punycode are already in ASCII form.
    const ascii =
        PLAIN_ASCII.test(trimmed) && !trimmed.includes('xn--') ? trimmed : domainToASCII(trimmed);
    if (!ascii || ascii.length > 253) return null;

    const labels = ascii.split('.');
    if (labels.length < 2 || !labels.every((label) => LABEL.test(label))) return null;

    return ascii;
};

/**
 * Registrable domain (eTLD+1) from the Public Suffix List, private section
 * included. Unknown and reserved TLDs fall back to the implicit "*" rule.
 */
export const getRegistrableDomain = (hostname: string): string | null =>
    getDomain(hostname, {
        allowPrivateDomains: true,
        extractHostname: false,
        validateHostname: false,
    });

export interface IParsedDomainEndpoint {
    host: string;
    port: number;
}

/** `tcp:host.example:22` or `host.example:22` -> normalized host and port. */
export const parseDomainEndpoint = (input: string | null): IParsedDomainEndpoint | null => {
    if (!input) return null;
    const value = input.replace(/^(?:tcp|udp):/i, '');
    const separator = value.lastIndexOf(':');
    if (separator <= 0) return null;

    const port = Number(value.slice(separator + 1));
    if (!Number.isInteger(port) || port < 1 || port > 65535) return null;

    const host = normalizeHostname(value.slice(0, separator));
    return host ? { host, port } : null;
};

const HASH_SEED = randomInt(0, 2 ** 31);

/**
 * 53-bit string hash (cyrb53) with a per-process seed, so that state keeps
 * fixed-size numbers instead of hostnames.
 */
export const hashHostname = (value: string): number => {
    let h1 = 0xdeadbeef ^ HASH_SEED;
    let h2 = 0x41c6ce57 ^ HASH_SEED;
    for (let index = 0; index < value.length; index += 1) {
        const code = value.charCodeAt(index);
        h1 = Math.imul(h1 ^ code, 2654435761);
        h2 = Math.imul(h2 ^ code, 1597334677);
    }
    h1 = Math.imul(h1 ^ (h1 >>> 16), 2246822507) ^ Math.imul(h2 ^ (h2 >>> 13), 3266489909);
    h2 = Math.imul(h2 ^ (h2 >>> 16), 2246822507) ^ Math.imul(h1 ^ (h1 >>> 13), 3266489909);
    return 4294967296 * (2097151 & h2) + (h1 >>> 0);
};

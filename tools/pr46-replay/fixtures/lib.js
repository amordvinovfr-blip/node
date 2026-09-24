'use strict';

// Shared helpers for the synthetic scenarios. Every address comes from a
// documentation or reserved range:
//   192.0.2.0/24, 198.51.100.0/24, 203.0.113.0/24  RFC 5737 (clients, resolvers, CGNAT pool)
//   198.18.0.0/15                                    RFC 2544 benchmarking (destinations)
//   10.255.0.0/16                                    RFC 1918 (entry node's internal address)
//   2001:db8::/32                                    RFC 3849 (IPv6)
// User IDs are small made-up integers. Nothing here is taken from real logs.

const BASE_MS = Date.UTC(2026, 8, 20, 12, 0, 0);
const MINUTE = 60_000;

/** Deterministic PRNG (mulberry32). */
class Rng {
    constructor(seed) {
        this.state = seed >>> 0;
    }

    next() {
        this.state = (this.state + 0x6d2b79f5) >>> 0;
        let t = this.state;
        t = Math.imul(t ^ (t >>> 15), t | 1);
        t ^= t + Math.imul(t ^ (t >>> 7), t | 61);
        return ((t ^ (t >>> 14)) >>> 0) / 4294967296;
    }

    int(min, max) {
        return min + Math.floor(this.next() * (max - min + 1));
    }

    pick(items) {
        return items[Math.floor(this.next() * items.length)];
    }

    chance(probability) {
        return this.next() < probability;
    }

    shuffle(items) {
        const copy = [...items];
        for (let index = copy.length - 1; index > 0; index -= 1) {
            const swap = Math.floor(this.next() * (index + 1));
            [copy[index], copy[swap]] = [copy[swap], copy[index]];
        }
        return copy;
    }
}

const addr = {
    /** Client source addresses (RFC 5737 TEST-NET-1). */
    client: (index) => `192.0.2.${1 + (index % 254)}`,
    /** One public CGNAT pool address (RFC 5737 TEST-NET-3). */
    cgnatPublic: '203.0.113.77',
    /** Entry node address as seen by the exit node (RFC 1918). */
    entryNode: '10.255.0.2',
    /** Destination in the "scan target / peer" space: 256 /24s (198.18.0.0/16). */
    target: (net24, host) => `198.18.${net24 & 255}.${host}`,
    /** Destination in the "service pool" space: 256 /24s (198.19.0.0/16). */
    service: (net24, host) => `198.19.${net24 & 255}.${host}`,
    /** Public resolvers for the DNS scenario (RFC 5737 TEST-NET-2 + 198.19.x). */
    resolver: (index) => `198.51.100.${1 + index}`,
    /** IPv6 destination (RFC 3849). */
    v6: (group, host) => `2001:db8:${group.toString(16)}::${host.toString(16)}`,
};

const pad = (value, width = 2) => String(value).padStart(width, '0');

const formatTimestamp = (ms) => {
    const date = new Date(ms);
    return (
        `${date.getUTCFullYear()}/${pad(date.getUTCMonth() + 1)}/${pad(date.getUTCDate())} ` +
        `${pad(date.getUTCHours())}:${pad(date.getUTCMinutes())}:${pad(date.getUTCSeconds())}.` +
        `${pad(date.getUTCMilliseconds() * 1000, 6)}`
    );
};

const endpoint = (ip, port) => (ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`);

/**
 * One Xray access.log line in the standard format.
 * @param {{ ms: number, src: string, srcPort?: number, net?: 'tcp' | 'udp', dst: string,
 *           port: number, email?: string | number | null, inbound?: string, outbound?: string }} session
 */
const formatLine = ({
    ms,
    src,
    srcPort = 40000,
    net = 'tcp',
    dst,
    port,
    email = null,
    inbound = 'VLESS_REALITY',
    outbound = 'DIRECT',
}) =>
    `${formatTimestamp(ms)} from ${endpoint(src, srcPort)} accepted ${net}:${endpoint(dst, port)} ` +
    `[${inbound} -> ${outbound}]${email === null ? '' : ` email: ${email}`}`;

/** Sorts sessions by time (stable) and renders them as log lines. */
const toLines = (sessions, rng = new Rng(1)) =>
    sessions
        .map((session, index) => ({ session, index }))
        .sort((a, b) => a.session.ms - b.session.ms || a.index - b.index)
        .map(({ session }) => formatLine({ srcPort: rng.int(32768, 60999), ...session }));

module.exports = { BASE_MS, MINUTE, Rng, addr, formatLine, formatTimestamp, toLines };

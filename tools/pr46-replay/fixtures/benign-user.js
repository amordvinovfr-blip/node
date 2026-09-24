'use strict';

// Traffic of one ordinary user, used as background for the CGNAT and chained
// node scenarios. Pool sizes and rates are synthetic and deliberately modest;
// each is listed here so it can be challenged. Shares are fractions of users.
//
// service           share  port(s)                         destinations                      cadence
// web               100%   443 (+80)                       10-60 hosts, random CDN space       15-60 sessions
// quic/dns          100%   udp 443, udp 53                 2 resolvers                          ~1/min
// push              50%    5228                            12 IPs in one /24                    every 10-20 min
// chat              25%    5222                            48 IPs in three /24s                 every 8-15 min
// imap              20%    993                             6 providers x 8 IPs (one /24 each)   every 3-10 min
// alt https         30%    8443/2053/2083/2087/2096/8080   random CDN space                     1-4 per hour
// dns-over-tls      8%     853                             3 resolvers                          every 5-15 min
// ssh               3%     22                              1-2 own servers                      every 10-30 min
// steam             5%     27015-27030                     40 IPs in four /24s                  every 5-10 min
// turn over tcp     4%     3478                            10 IPs in one /24                    2-6 per hour
// bittorrent        1%     tcp 6881 / 51413 / random, udp  random peers                         150-300 peers in the
//                                                                                              first 2 min, then ~5/min

const { MINUTE, addr } = require('./lib');

const ALT_HTTPS_PORTS = [8443, 2053, 2083, 2087, 2096, 8080];

const cdnHost = (rng) => addr.service(rng.int(128, 255), rng.int(1, 254));
const peerHost = (rng) =>
    rng.chance(0.15)
        ? addr.v6(rng.int(0x100, 0xfff), rng.int(1, 0xffff))
        : addr.target(rng.int(0, 255), rng.int(1, 254));

/** Evenly spaced sessions with jitter between `from` and `to`. */
const every = (rng, from, to, minGapMs, maxGapMs, create) => {
    const sessions = [];
    for (let ms = from + rng.int(0, maxGapMs); ms < to; ms += rng.int(minGapMs, maxGapMs)) {
        sessions.push(create(ms));
    }
    return sessions;
};

const torrentSessions = (rng, { startMs, endMs, base }) => {
    const sessions = [];
    const burstPeers = rng.int(150, 300);
    const burstStart = startMs + rng.int(0, Math.max(0, endMs - startMs - 5 * MINUTE));
    const peerPort = () => {
        const roll = rng.next();
        if (roll < 0.3) return 6881;
        if (roll < 0.6) return 51413;
        return rng.int(10000, 65000);
    };
    for (let index = 0; index < burstPeers; index += 1) {
        const ms = burstStart + rng.int(0, 2 * MINUTE);
        sessions.push({ ...base, ms, net: rng.chance(0.5) ? 'udp' : 'tcp', dst: peerHost(rng), port: peerPort() });
    }
    sessions.push(
        ...every(rng, burstStart + 2 * MINUTE, endMs, 6_000, 18_000, (ms) => ({
            ...base,
            ms,
            net: rng.chance(0.5) ? 'udp' : 'tcp',
            dst: peerHost(rng),
            port: peerPort(),
        })),
    );
    return sessions;
};

/**
 * @param {import('./lib').Rng} rng
 * @param {{ email: string | number, src: string, startMs: number, durationMs: number,
 *           torrentShare?: number }} options
 */
const benignUserSessions = (rng, { email, src, startMs, durationMs, torrentShare = 0.01 }) => {
    const endMs = startMs + durationMs;
    const base = { email, src };
    const within = () => startMs + rng.int(0, durationMs - 1);
    const sessions = [];

    const webHosts = Array.from({ length: rng.int(10, 60) }, () => cdnHost(rng));
    const webSessions = rng.int(15, 60);
    for (let index = 0; index < webSessions; index += 1) {
        sessions.push({ ...base, ms: within(), dst: rng.pick(webHosts), port: rng.chance(0.9) ? 443 : 80 });
    }

    const resolvers = [addr.resolver(rng.int(0, 3)), addr.resolver(rng.int(0, 3))];
    sessions.push(
        ...every(rng, startMs, endMs, 30_000, 90_000, (ms) => ({
            ...base,
            ms,
            net: 'udp',
            dst: rng.pick(resolvers),
            port: 53,
        })),
        ...every(rng, startMs, endMs, 60_000, 180_000, (ms) => ({
            ...base,
            ms,
            net: 'udp',
            dst: rng.pick(webHosts),
            port: 443,
        })),
    );

    if (rng.chance(0.5)) {
        sessions.push(
            ...every(rng, startMs, endMs, 10 * MINUTE, 20 * MINUTE, (ms) => ({
                ...base,
                ms,
                dst: addr.service(10, rng.int(1, 12)),
                port: 5228,
            })),
        );
    }
    if (rng.chance(0.25)) {
        sessions.push(
            ...every(rng, startMs, endMs, 8 * MINUTE, 15 * MINUTE, (ms) => ({
                ...base,
                ms,
                dst: addr.service(20 + rng.int(0, 2), rng.int(1, 16)),
                port: 5222,
            })),
        );
    }
    if (rng.chance(0.2)) {
        const provider = rng.int(0, 5);
        sessions.push(
            ...every(rng, startMs, endMs, 3 * MINUTE, 10 * MINUTE, (ms) => ({
                ...base,
                ms,
                dst: addr.service(30 + provider, rng.int(1, 8)),
                port: 993,
            })),
        );
    }
    if (rng.chance(0.3)) {
        const count = Math.max(1, Math.round((rng.int(1, 4) * durationMs) / (60 * MINUTE)));
        for (let index = 0; index < count; index += 1) {
            sessions.push({ ...base, ms: within(), dst: cdnHost(rng), port: rng.pick(ALT_HTTPS_PORTS) });
        }
    }
    if (rng.chance(0.08)) {
        sessions.push(
            ...every(rng, startMs, endMs, 5 * MINUTE, 15 * MINUTE, (ms) => ({
                ...base,
                ms,
                dst: addr.resolver(10 + rng.int(0, 2)),
                port: 853,
            })),
        );
    }
    if (rng.chance(0.03)) {
        const servers = [addr.service(rng.int(64, 127), rng.int(1, 254))];
        if (rng.chance(0.5)) servers.push(addr.service(rng.int(64, 127), rng.int(1, 254)));
        sessions.push(
            ...every(rng, startMs, endMs, 10 * MINUTE, 30 * MINUTE, (ms) => ({
                ...base,
                ms,
                dst: rng.pick(servers),
                port: 22,
            })),
        );
    }
    if (rng.chance(0.05)) {
        sessions.push(
            ...every(rng, startMs, endMs, 5 * MINUTE, 10 * MINUTE, (ms) => ({
                ...base,
                ms,
                dst: addr.service(40 + rng.int(0, 3), rng.int(1, 10)),
                port: rng.int(27015, 27030),
            })),
        );
    }
    if (rng.chance(0.04)) {
        const count = Math.max(1, Math.round((rng.int(2, 6) * durationMs) / (60 * MINUTE)));
        for (let index = 0; index < count; index += 1) {
            sessions.push({ ...base, ms: within(), dst: addr.service(50, rng.int(1, 10)), port: 3478 });
        }
    }
    if (rng.chance(torrentShare)) {
        sessions.push(...torrentSessions(rng, { startMs, endMs, base }));
    }

    return sessions;
};

module.exports = { benignUserSessions, torrentSessions };

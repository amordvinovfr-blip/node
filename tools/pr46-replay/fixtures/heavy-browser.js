'use strict';

// Heavy browsing: 600 distinct HTTPS destinations in 15 minutes, some also on
// :80 (redirects) and some over QUIC (UDP 443).

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ destinations = 600, seed = 443 } = {}) => {
    const rng = new Rng(seed);
    const email = 1006;
    const src = addr.v6(0xc11e, 6);

    const hosts = new Set();
    while (hosts.size < destinations) {
        hosts.add(
            rng.chance(0.2)
                ? addr.v6(rng.int(0x1000, 0xffff), rng.int(1, 0xffff))
                : addr.target(rng.int(0, 255), rng.int(1, 254)),
        );
    }

    const sessions = [];
    for (const dst of hosts) {
        const ms = BASE_MS + rng.int(0, 15 * MINUTE - 5000);
        if (rng.chance(0.1)) sessions.push({ ms, src, dst, port: 80, email });
        const hits = rng.int(1, 3);
        for (let hit = 0; hit < hits; hit += 1) {
            sessions.push({ ms: ms + hit * rng.int(100, 4000), src, dst, port: 443, email });
        }
        if (rng.chance(0.2)) sessions.push({ ms: ms + 50, src, net: 'udp', dst, port: 443, email });
    }

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, destinations, durationMinutes: 15, clientFamily: 'ipv6' },
    };
};

module.exports = { generate };

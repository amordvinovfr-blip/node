'use strict';

// NTP pool client: 120 servers on UDP :123, about 3 hits each (64 s poll),
// including a well-known public time service (4 addresses in one /24).

const { BASE_MS, Rng, addr, toLines } = require('./lib');

const generate = ({ servers = 120, seed = 123 } = {}) => {
    const rng = new Rng(seed);
    const email = 1003;
    const src = addr.client(30);

    const destinations = new Set([1, 2, 3, 4].map((host) => addr.service(123, host)));
    while (destinations.size < servers) {
        destinations.add(addr.target(rng.int(0, 255), rng.int(1, 254)));
    }

    const sessions = [];
    for (const dst of destinations) {
        const firstMs = BASE_MS + rng.int(0, 6 * 60_000);
        const hits = rng.chance(0.8) ? 3 : rng.int(2, 4);
        for (let hit = 0; hit < hits; hit += 1) {
            sessions.push({ ms: firstMs + hit * 64_000, src, net: 'udp', dst, port: 123, email });
        }
    }

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, servers, network: 'udp' },
    };
};

module.exports = { generate };

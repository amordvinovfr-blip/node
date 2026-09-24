'use strict';

// BitTorrent / DHT user: 300 distinct peers on 6881 and 51413 within 60 s.
// Default network is UDP (DHT + uTP), as described in CONTEXT.md; the `tcp`
// option replays the same peers as TCP peer-wire connections.

const { BASE_MS, Rng, addr, toLines } = require('./lib');

const generate = ({ network = 'udp', peers = 300, seed = 6881 } = {}) => {
    const rng = new Rng(seed);
    const email = 1001;
    const src = addr.client(10);

    const destinations = new Set();
    while (destinations.size < peers) {
        destinations.add(
            rng.chance(0.15)
                ? addr.v6(rng.int(0x100, 0xfff), rng.int(1, 0xffff))
                : addr.target(rng.int(0, 255), rng.int(1, 254)),
        );
    }

    const sessions = [];
    for (const dst of destinations) {
        const port = rng.chance(0.5) ? 6881 : 51413;
        const hits = rng.int(1, 3);
        for (let hit = 0; hit < hits; hit += 1) {
            sessions.push({ ms: BASE_MS + rng.int(0, 59_999), src, net: network, dst, port, email });
        }
    }

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, peers, network, windowSeconds: 60 },
    };
};

module.exports = { generate };

'use strict';

// True positive: an infected camera sweeping RTSP on 554 and 553.
// 200 distinct /24s per port, one random host each, random order, ports
// interleaved, all 400 targets within 2 minutes (100 per minute per port).

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ networksPerPort = 200, durationMs = 2 * MINUTE, seed = 554 } = {}) => {
    const rng = new Rng(seed);
    const email = 3002;
    const src = addr.client(61);

    const targets = [];
    for (const port of [554, 553]) {
        for (const net of rng.shuffle(Array.from({ length: networksPerPort }, (_, index) => index))) {
            targets.push({ dst: addr.target(net, rng.int(1, 254)), port });
        }
    }
    const ordered = rng.shuffle(targets);
    const stepMs = durationMs / ordered.length;
    const sessions = ordered.map((target, index) => ({
        ms: BASE_MS + Math.floor(index * stepMs),
        src,
        email,
        ...target,
    }));

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, ports: [554, 553], networksPerPort, targets: sessions.length },
    };
};

module.exports = { generate };

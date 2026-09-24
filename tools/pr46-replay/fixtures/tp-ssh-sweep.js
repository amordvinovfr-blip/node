'use strict';

// True positive: SSH sweep over 200 distinct /24s on :22.
//   order 'random'     one random host per /24, random order (zmap/Mirai style),
//                      200 targets spread evenly over `durationMs` (default 2 min)
//   order 'sequential' 25 consecutive hosts in each /24, /24 after /24
//                      (masscan-style range walk), 500 targets per minute

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const sweepSessions = (
    rng,
    { email, src, startMs, order = 'random', networks = 200, hostsPerNetwork, durationMs, port = 22 },
) => {
    const targets = [];
    if (order === 'sequential') {
        const hosts = hostsPerNetwork ?? 25;
        for (let net = 0; net < networks; net += 1) {
            for (let host = 1; host <= hosts; host += 1) targets.push(addr.target(net, host));
        }
    } else {
        const hosts = hostsPerNetwork ?? 1;
        for (const net of rng.shuffle(Array.from({ length: networks }, (_, index) => index))) {
            for (let host = 0; host < hosts; host += 1) targets.push(addr.target(net, rng.int(1, 254)));
        }
    }

    const totalMs = durationMs ?? (order === 'sequential' ? (targets.length / 500) * MINUTE : 2 * MINUTE);
    const stepMs = totalMs / targets.length;
    return targets.map((dst, index) => ({ ms: startMs + Math.floor(index * stepMs), src, dst, port, email }));
};

const generate = ({ order = 'random', durationMs, seed = 22 } = {}) => {
    const rng = new Rng(seed);
    const sessions = sweepSessions(rng, {
        email: 3001,
        src: addr.client(60),
        startMs: BASE_MS,
        order,
        durationMs,
    });
    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, order, networks: 200, targets: sessions.length },
    };
};

module.exports = { generate, sweepSessions };

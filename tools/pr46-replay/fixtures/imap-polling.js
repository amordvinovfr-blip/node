'use strict';

// Mail client polling IMAPS (:993) every 2-4 s for one hour against a large
// provider whose name resolves round-robin to 16 addresses in one /24.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ poolSize = 16, seed = 993 } = {}) => {
    const rng = new Rng(seed);
    const email = 1005;
    const src = addr.client(50);
    const pool = Array.from({ length: poolSize }, (_, index) => addr.service(31, index + 1));

    const sessions = [];
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += rng.int(2000, 4000)) {
        sessions.push({ ms, src, dst: rng.pick(pool), port: 993, email });
    }

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, sessions: sessions.length, poolSize, durationMinutes: 60 },
    };
};

module.exports = { generate };

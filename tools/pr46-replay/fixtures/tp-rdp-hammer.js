'use strict';

// True positive: 300 sessions to one host on :3389 within 10 minutes
// (one every 2 s), the `hammer_target` shape from CONTEXT.md.

const { BASE_MS, Rng, addr, toLines } = require('./lib');

const generate = ({ sessionsCount = 300, intervalMs = 2000, seed = 3389 } = {}) => {
    const rng = new Rng(seed);
    const email = 3003;
    const src = addr.client(62);
    const dst = addr.target(33, 89);

    const sessions = Array.from({ length: sessionsCount }, (_, index) => ({
        ms: BASE_MS + index * intervalMs,
        src,
        dst,
        port: 3389,
        email,
    }));

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, destinations: 1, sessions: sessionsCount },
    };
};

module.exports = { generate };

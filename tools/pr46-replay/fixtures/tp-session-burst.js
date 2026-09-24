'use strict';

// True positive: 700 non-web sessions in 60 s (the `session_rate_burst`
// shape), here a database brute force against 5 hosts on 3306/5432/6379.

const { BASE_MS, Rng, addr, toLines } = require('./lib');

const generate = ({ sessionsCount = 700, seed = 700 } = {}) => {
    const rng = new Rng(seed);
    const email = 3004;
    const src = addr.client(63);
    const hosts = [1, 2, 3, 4, 5].map((host) => addr.target(44, host));

    const sessions = Array.from({ length: sessionsCount }, () => ({
        ms: BASE_MS + rng.int(0, 59_999),
        src,
        dst: rng.pick(hosts),
        port: rng.pick([3306, 5432, 6379]),
        email,
    }));

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, destinations: hosts.length, sessions: sessionsCount },
    };
};

module.exports = { generate };

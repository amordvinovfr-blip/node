'use strict';

// An administrator using 5 SSH jump hosts under one domain for an hour: a
// session every 10-40 s, spread over jump1..jump5.corp.example.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ seed = 2201 } = {}) => {
    const rng = new Rng(seed);
    const sessions = [];
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += rng.int(10_000, 40_000)) {
        sessions.push({
            ms,
            src: addr.client(86),
            dst: `jump${rng.int(1, 5)}.corp.example`,
            port: 22,
            email: 5501,
        });
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, hosts: 5, sessions: sessions.length } };
};

module.exports = { generate };

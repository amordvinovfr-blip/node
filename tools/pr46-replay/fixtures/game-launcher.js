'use strict';

// A game launcher at start-up: 30 service domains on 443 and on game ports
// (27015-27030, 7777), then a TCP game session to one server by IP.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ domains = 30, seed = 27016 } = {}) => {
    const rng = new Rng(seed);
    const email = 5801;
    const src = addr.client(89);
    const sessions = [];
    for (let index = 0; index < domains; index += 1) {
        const host = `svc${index}.launcher${index % 10}.example`;
        const port = index % 3 === 0 ? rng.pick([7777, rng.int(27015, 27030)]) : 443;
        for (let hit = 0; hit < 3; hit += 1) {
            sessions.push({ ms: BASE_MS + rng.int(0, 2 * MINUTE), src, dst: host, port, email });
        }
    }
    for (let ms = BASE_MS + 3 * MINUTE; ms < BASE_MS + 40 * MINUTE; ms += 30_000) {
        sessions.push({ ms, src, dst: addr.service(77, 15), port: 27015, email });
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, domains } };
};

module.exports = { generate };

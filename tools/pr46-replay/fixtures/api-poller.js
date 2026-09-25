'use strict';

// An API poller: two requests per second to three API hosts on 8443 (one by
// name), plus push reconnects on 5228, for one hour.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ seed = 8443 } = {}) => {
    const rng = new Rng(seed);
    const email = 5301;
    const src = addr.client(84);
    const targets = [addr.service(60, 1), addr.service(60, 2), 'api.poller.example'];
    const sessions = [];
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += 500) {
        sessions.push({ ms, src, dst: rng.pick(targets), port: 8443, email });
    }
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += rng.int(5, 15) * MINUTE) {
        sessions.push({ ms, src, dst: 'push.poller.example', port: 5228, email });
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, sessions: sessions.length } };
};

module.exports = { generate };

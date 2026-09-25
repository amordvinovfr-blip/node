'use strict';

// Mail client polling imap.mail.example:993 by name every 2-4 s for an hour.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ seed = 9930 } = {}) => {
    const rng = new Rng(seed);
    const sessions = [];
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += rng.int(2000, 4000)) {
        sessions.push({ ms, src: addr.client(85), dst: 'imap.mail.example', port: 993, email: 5401 });
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, sessions: sessions.length } };
};

module.exports = { generate };

'use strict';

// A BitTorrent client announcing to 40 trackers by name on :6969 every
// 5 minutes for an hour.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ trackers = 40, seed = 6969 } = {}) => {
    const rng = new Rng(seed);
    const sessions = [];
    for (let minute = 0; minute < 60; minute += 5) {
        for (let tracker = 1; tracker <= trackers; tracker += 1) {
            sessions.push({
                ms: BASE_MS + minute * MINUTE + rng.int(0, 20_000),
                src: addr.client(88),
                dst: `tracker.t${tracker}.example`,
                port: 6969,
                email: 5701,
            });
        }
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, trackers } };
};

module.exports = { generate };

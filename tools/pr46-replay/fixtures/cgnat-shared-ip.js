'use strict';

// Carrier-grade NAT: 50 unrelated users share one public IPv4 for 30 minutes.
// 49 are ordinary users (benign-user.js); one runs an infected device that
// sweeps SSH sequentially from minute 10 (same pattern as tp-ssh-sweep
// `sequential`, which PR #46 does detect).

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');
const { benignUserSessions } = require('./benign-user');
const { sweepSessions } = require('./tp-ssh-sweep');

const generate = ({ users = 50, seed = 6598 } = {}) => {
    const rng = new Rng(seed);
    const src = addr.cgnatPublic;
    const durationMs = 30 * MINUTE;
    const sessions = [];

    for (let user = 0; user < users - 1; user += 1) {
        sessions.push(...benignUserSessions(rng, { email: 2001 + user, src, startMs: BASE_MS, durationMs }));
    }
    const scannerEmail = 2000 + users;
    sessions.push(
        ...sweepSessions(rng, {
            email: scannerEmail,
            src,
            startMs: BASE_MS + 10 * MINUTE,
            order: 'sequential',
        }),
    );

    return {
        lines: toLines(sessions, rng),
        meta: { users, sourceIps: 1, scanners: 1, durationMinutes: 30 },
    };
};

module.exports = { generate };

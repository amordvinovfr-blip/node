'use strict';

// True positive: a random SSH sweep at 20 targets per minute from 23:52 to
// 00:07 UTC. Neither calendar day alone holds 150 distinct /24s; the whole
// scan does. `day` returns only the lines of one UTC day, as a per-day
// replay would see them.

const { MINUTE, Rng, addr, toLines } = require('./lib');
const { randomSweepSessions } = require('./tp-ssh-random-rate');

const START_MS = Date.UTC(2026, 8, 20, 23, 52, 0);
const MIDNIGHT_MS = Date.UTC(2026, 8, 21, 0, 0, 0);

const generate = ({ day = null, seed = 2400 } = {}) => {
    const rng = new Rng(seed);
    let sessions = randomSweepSessions(rng, {
        email: 3106,
        src: addr.client(95),
        startMs: START_MS,
        ratePerMinute: 20,
        durationMs: 15 * MINUTE,
    });
    if (day === 'first') sessions = sessions.filter((session) => session.ms < MIDNIGHT_MS);
    if (day === 'second') sessions = sessions.filter((session) => session.ms >= MIDNIGHT_MS);
    return { lines: toLines(sessions, rng), meta: { users: 1, day, targets: sessions.length } };
};

module.exports = { generate, MIDNIGHT_MS };

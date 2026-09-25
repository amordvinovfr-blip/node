'use strict';

// True positive: an RDP hammer of `sessionsCount` sessions, one every 2 s,
// against one IP or one hostname.

const { BASE_MS, Rng, addr, toLines } = require('./lib');

const generate = ({ sessionsCount = 400, target = 'ip', seed = 3390 } = {}) => {
    const rng = new Rng(seed);
    const dst = target === 'ip' ? addr.target(33, 90) : 'rdp.victim.example';
    const sessions = Array.from({ length: sessionsCount }, (_, index) => ({
        ms: BASE_MS + index * 2000,
        src: addr.client(91),
        dst,
        port: 3389,
        email: 3102,
    }));
    return { lines: toLines(sessions, rng), meta: { users: 1, target, sessions: sessionsCount } };
};

module.exports = { generate };

'use strict';

// True positive: an SSH scan by name: 500 hostnames across 400 registrable
// domains (100 domains carry two names), random order, over 10 minutes.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ durationMs = 10 * MINUTE, seed = 2202 } = {}) => {
    const rng = new Rng(seed);
    const hosts = [];
    for (let domain = 0; domain < 400; domain += 1) {
        hosts.push(`ssh.victim${domain}.example`);
        if (domain < 100) hosts.push(`git.victim${domain}.example`);
    }
    const ordered = rng.shuffle(hosts);
    const stepMs = durationMs / ordered.length;
    const sessions = ordered.map((dst, index) => ({
        ms: BASE_MS + Math.floor(index * stepMs),
        src: addr.client(92),
        dst,
        port: 22,
        email: 3103,
    }));
    return { lines: toLines(sessions, rng), meta: { users: 1, hostnames: 500, domains: 400 } };
};

module.exports = { generate };

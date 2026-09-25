'use strict';

// An app that keeps contacting many peers on one unassigned high port, like
// the real 50300 and 8887 cases: every 10 minutes a burst of 80 new peers
// within 45 s, for one hour (about 480 distinct IPs per hour on one port).

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ port = 50300, bursts = 6, peersPerBurst = 80, seed = 50300 } = {}) => {
    const rng = new Rng(seed);
    const email = 5001;
    const src = addr.client(80);
    const sessions = [];
    for (let burst = 0; burst < bursts; burst += 1) {
        const startMs = BASE_MS + burst * 10 * MINUTE;
        for (let peer = 0; peer < peersPerBurst; peer += 1) {
            const dst = addr.target(rng.int(0, 255), rng.int(1, 254));
            sessions.push({ ms: startMs + rng.int(0, 45_000), src, dst, port, email });
        }
    }
    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, port, bursts, peersPerBurst },
    };
};

module.exports = { generate };

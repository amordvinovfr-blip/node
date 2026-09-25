'use strict';

// LAN-sharing and device-sync apps whose discovery walks a whole /24 through
// the tunnel: a LocalSend-style probe of 254 hosts on 53317 every 5 minutes,
// and an Apple device-sync probe of 254 hosts on 62078 every 15 minutes.
// The "LAN" is a documentation /24.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const lanHost = (host) => `192.0.2.${host}`;

const generate = ({ seed = 53317 } = {}) => {
    const rng = new Rng(seed);
    const sessions = [];
    const probe = (email, src, startMs, port) => {
        for (let host = 1; host <= 254; host += 1) {
            sessions.push({ ms: startMs + rng.int(0, 5000), src, dst: lanHost(host), port, email });
        }
    };
    for (let minute = 0; minute < 60; minute += 5) probe(5101, addr.client(81), BASE_MS + minute * MINUTE, 53317);
    for (let minute = 0; minute < 60; minute += 15) probe(5102, addr.client(82), BASE_MS + minute * MINUTE, 62078);
    return {
        lines: toLines(sessions, rng),
        meta: { users: 2, sourceIps: 2, ports: [53317, 62078] },
    };
};

module.exports = { generate };

'use strict';

// Heavy browsing by name: 600 distinct hostnames under 400 registrable
// domains on 443 (some on 80) in 15 minutes.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ hosts = 600, seed = 4430 } = {}) => {
    const rng = new Rng(seed);
    const email = 5201;
    const src = addr.client(83);
    const sessions = [];
    for (let index = 0; index < hosts; index += 1) {
        const host = `www${index}.site${index % 400}.example`;
        const ms = BASE_MS + rng.int(0, 15 * MINUTE - 5000);
        sessions.push({ ms, src, dst: host, port: rng.chance(0.9) ? 443 : 80, email });
        if (rng.chance(0.5)) sessions.push({ ms: ms + 800, src, dst: host, port: 443, email });
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, hosts, domains: 400 } };
};

module.exports = { generate };

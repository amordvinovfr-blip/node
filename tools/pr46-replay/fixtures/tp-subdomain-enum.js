'use strict';

// True positive: enumeration of 200 hostnames under one registrable domain
// on :22 and :3389 (every name tried on both ports) over 10 minutes.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ hosts = 200, durationMs = 10 * MINUTE, seed = 2203 } = {}) => {
    const rng = new Rng(seed);
    const names = rng.shuffle(Array.from({ length: hosts }, (_, index) => `h${index}.target.example`));
    const stepMs = durationMs / names.length;
    const sessions = names.flatMap((dst, index) =>
        [22, 3389].map((port) => ({
            ms: BASE_MS + Math.floor(index * stepMs) + (port === 3389 ? 200 : 0),
            src: addr.client(93),
            dst,
            port,
            email: 3104,
        })),
    );
    return { lines: toLines(sessions, rng), meta: { users: 1, hostnames: hosts, ports: [22, 3389] } };
};

module.exports = { generate };

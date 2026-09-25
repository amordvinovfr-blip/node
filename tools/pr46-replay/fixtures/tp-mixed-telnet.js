'use strict';

// True positive: a telnet (:23) scan that mixes 300 random IPs with 200
// hostnames across 150 registrable domains, interleaved, over 10 minutes.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');
const { randomTarget } = require('./tp-ssh-random-rate');

const generate = ({ durationMs = 10 * MINUTE, seed = 2323 } = {}) => {
    const rng = new Rng(seed);
    const targets = [
        ...Array.from({ length: 300 }, () => randomTarget(rng)),
        ...Array.from({ length: 200 }, (_, index) => `cam${index}.iot${index % 150}.example`),
    ];
    const ordered = rng.shuffle(targets);
    const stepMs = durationMs / ordered.length;
    const sessions = ordered.map((dst, index) => ({
        ms: BASE_MS + Math.floor(index * stepMs),
        src: addr.client(94),
        dst,
        port: 23,
        email: 3105,
    }));
    return { lines: toLines(sessions, rng), meta: { users: 1, ips: 300, hostnames: 200, domains: 150 } };
};

module.exports = { generate };

'use strict';

// True positive: a random-order SSH sweep at a fixed rate for 15 minutes.
// Targets are uniformly random hosts across 512 /24s (198.18.0.0/15).

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const randomTarget = (rng) => {
    const net = rng.int(0, 511);
    return net < 256 ? addr.target(net, rng.int(1, 254)) : addr.service(net - 256, rng.int(1, 254));
};

/** Sessions of a random sweep; shared with the midnight scenario. */
const randomSweepSessions = (rng, { email, src, startMs, ratePerMinute, durationMs, port = 22 }) => {
    const count = Math.round((ratePerMinute * durationMs) / MINUTE);
    const stepMs = durationMs / count;
    return Array.from({ length: count }, (_, index) => ({
        ms: startMs + Math.floor(index * stepMs),
        src,
        dst: randomTarget(rng),
        port,
        email,
    }));
};

const generate = ({ ratePerMinute = 25, durationMs = 15 * MINUTE, seed = 2225 } = {}) => {
    const rng = new Rng(seed + ratePerMinute);
    const sessions = randomSweepSessions(rng, {
        email: 3101,
        src: addr.client(90),
        startMs: BASE_MS,
        ratePerMinute,
        durationMs,
    });
    return { lines: toLines(sessions, rng), meta: { users: 1, ratePerMinute, targets: sessions.length } };
};

module.exports = { generate, randomSweepSessions, randomTarget };

'use strict';

// A page pulling assets from 300 CDN shard hostnames on 443 within 5 minutes
// (s1..s300.cdn.example), repeated every 15 minutes for an hour.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ shards = 300, seed = 4431 } = {}) => {
    const rng = new Rng(seed);
    const sessions = [];
    for (let round = 0; round < 4; round += 1) {
        for (let shard = 1; shard <= shards; shard += 1) {
            sessions.push({
                ms: BASE_MS + round * 15 * MINUTE + rng.int(0, 5 * MINUTE),
                src: addr.client(87),
                dst: `s${shard}.cdn.example`,
                port: 443,
                email: 5601,
            });
        }
    }
    return { lines: toLines(sessions, rng), meta: { users: 1, shards } };
};

module.exports = { generate };

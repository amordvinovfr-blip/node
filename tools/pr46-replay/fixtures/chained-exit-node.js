'use strict';

// Chained deployment seen from the exit node: 2,000 people use the entry node,
// which forwards everything to the exit node as ONE technical user from ONE
// internal address. Each person's traffic comes from benign-user.js; only the
// email and source address are rewritten, as the exit node would log them.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');
const { benignUserSessions } = require('./benign-user');

const TECHNICAL_USER = 1;

const generate = ({ people = 2000, durationMinutes = 30, torrentShare = 0.01, seed = 1918 } = {}) => {
    const rng = new Rng(seed);
    const durationMs = durationMinutes * MINUTE;
    const sessions = [];

    for (let person = 0; person < people; person += 1) {
        for (const session of benignUserSessions(rng, {
            email: TECHNICAL_USER,
            src: addr.entryNode,
            startMs: BASE_MS,
            durationMs,
            torrentShare,
        })) {
            sessions.push({ ...session, inbound: 'MESH_FROM_ENTRY' });
        }
    }

    return {
        lines: toLines(sessions, rng),
        meta: { people, userIdsInLog: 1, sourceIps: 1, durationMinutes, torrentShare },
    };
};

module.exports = { generate, TECHNICAL_USER };

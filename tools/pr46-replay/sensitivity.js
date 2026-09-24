#!/usr/bin/env node
'use strict';

// How PR #46 reacts to one scanning user as a function of target order,
// number of ports and rate. Each run is a 15-minute scan by one user from one
// IP, replayed with the schema defaults.
//
//   node tools/pr46-replay/sensitivity.js

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./fixtures/lib');
const { replayLines } = require('./lib/replay');

const DURATION_MS = 15 * MINUTE;
const RATES = [10, 25, 50, 100, 500, 2000];
const PATTERNS = [
    { order: 'random', ports: [22] },
    { order: 'random', ports: [23, 2323] },
    { order: 'random', ports: [22, 23, 2323] },
    { order: 'sequential', ports: [22] },
];

// 512 /24s: 198.18.0.0/16 then 198.19.0.0/16 (RFC 2544).
const hostAt = (net, host) => (net < 256 ? addr.target(net, host) : addr.service(net - 256, host));

const scanLines = ({ order, ports, ratePerMinute, seed }) => {
    const rng = new Rng(seed);
    const targets = Math.round((ratePerMinute * DURATION_MS) / MINUTE);
    const stepMs = DURATION_MS / targets;
    const sessions = [];
    for (let index = 0; index < targets; index += 1) {
        const dst =
            order === 'sequential'
                ? hostAt(Math.floor(index / 254) % 512, (index % 254) + 1)
                : hostAt(rng.int(0, 511), rng.int(1, 254));
        const ms = BASE_MS + Math.floor(index * stepMs);
        for (const port of ports) sessions.push({ ms, src: addr.client(70), dst, port, email: 4001 });
    }
    return toLines(sessions, rng);
};

const main = async () => {
    console.log('| Target order | Ports | Targets/min | Highest severity | Max score | Blocked | First block (s) |');
    console.log('|---|---|---:|---|---:|---|---:|');
    for (const pattern of PATTERNS) {
        for (const ratePerMinute of RATES) {
            const lines = scanLines({ ...pattern, ratePerMinute, seed: ratePerMinute });
            const report = await replayLines(lines, { scenario: 'sensitivity' });
            const severity =
                ['blocked', 'alert', 'suspicious'].find((name) => report.decisions.bySeverity[name]) ?? '-';
            console.log(
                `| ${pattern.order} | ${pattern.ports.join(', ')} | ${ratePerMinute} | ${severity} | ` +
                    `${report.decisions.maxScore ?? 0} | ${report.blocks.total > 0 ? 'yes' : 'no'} | ` +
                    `${report.timeToFirstBlock.secondsFromLogStart ?? '-'} |`,
            );
        }
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

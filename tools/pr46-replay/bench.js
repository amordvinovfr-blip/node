#!/usr/bin/env node
'use strict';

// Generates a large synthetic access.log shaped like an entry node from the
// real-data summary (about 11 M lines per day, 70% of TCP by hostname, most
// traffic on 443/80, 2-3% on recon ports), for throughput and memory runs.
//
//   node tools/pr46-replay/bench.js --lines 10000000 --out tools/pr46-replay/out/bench.log
//   node tools/pr46-replay/run.js --log tools/pr46-replay/out/bench.log --out out/bench.json
//
// Addresses come from documentation/reserved ranges; hostnames are *.example.

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const { BASE_MS, Rng, formatTimestamp } = require('./fixtures/lib');

const RECON = [22, 23, 3389, 445, 5900, 3306, 6379, 2323, 554];
const OTHER = [8443, 5228, 5222, 993, 853, 50300, 6881, 51413, 27015, 3478, 7777];

const main = async () => {
    const { values } = parseArgs({
        options: {
            lines: { type: 'string', default: '10000000' },
            out: { type: 'string' },
            users: { type: 'string', default: '4000' },
            sources: { type: 'string', default: '20000' },
            'lines-per-day': { type: 'string', default: '11000000' },
            seed: { type: 'string', default: '1' },
        },
    });
    if (!values.out) throw new Error('--out is required');
    const total = Number(values.lines);
    const users = Number(values.users);
    const sources = Number(values.sources);
    const stepMs = 86_400_000 / Number(values['lines-per-day']);
    const rng = new Rng(Number(values.seed));

    // Stable per-user source address and a few favourite hosts.
    const userSource = Array.from({ length: users }, () => rng.int(0, sources - 1));
    const sourceIp = (index) =>
        index < 254 * 3
            ? `${['192.0.2', '198.51.100', '203.0.113'][Math.floor(index / 254)]}.${(index % 254) + 1}`
            : `2001:db8:c11e:${(index >> 16).toString(16)}::${(index & 0xffff).toString(16)}`;
    const endpoint = (ip, port) => (ip.includes(':') ? `[${ip}]:${port}` : `${ip}:${port}`);
    const ipTarget = () =>
        rng.chance(0.85)
            ? `198.${18 + rng.int(0, 1)}.${rng.int(0, 255)}.${rng.int(1, 254)}`
            : `2001:db8:${rng.int(0x100, 0xffff).toString(16)}::${rng.int(1, 0xffff).toString(16)}`;
    const hostTarget = () => `h${rng.int(0, 49)}.d${rng.int(0, 9999)}.example`;

    fs.mkdirSync(path.dirname(path.resolve(values.out)), { recursive: true });
    const out = fs.createWriteStream(values.out);
    const chunk = [];
    let ms = BASE_MS;
    for (let index = 0; index < total; index += 1) {
        ms += stepMs;
        const user = rng.int(0, users - 1);
        const src = endpoint(sourceIp(userSource[user]), rng.int(32768, 60999));
        const roll = rng.next();
        let net = 'tcp';
        let dst;
        let port;
        if (roll < 0.06) {
            net = 'udp';
            dst = ipTarget();
            port = rng.pick([443, 53, 123, 3478, 6881]);
        } else if (roll < 0.72) {
            dst = hostTarget();
            port = rng.chance(0.93) ? 443 : rng.chance(0.5) ? 80 : rng.pick(OTHER);
        } else {
            dst = ipTarget();
            const portRoll = rng.next();
            port = portRoll < 0.72 ? 443 : portRoll < 0.8 ? 80 : portRoll < 0.9 ? rng.pick(OTHER) : rng.pick(RECON);
        }
        const email = rng.chance(0.99) ? ` email: ${1000 + user}` : '';
        chunk.push(
            `${formatTimestamp(Math.floor(ms))} from ${src} accepted ${net}:${endpoint(dst, port)} [VLESS_REALITY -> DIRECT]${email}`,
        );
        if (chunk.length === 10_000) {
            if (!out.write(`${chunk.join('\n')}\n`)) await new Promise((resolve) => out.once('drain', resolve));
            chunk.length = 0;
        }
    }
    if (chunk.length > 0) out.write(`${chunk.join('\n')}\n`);
    await new Promise((resolve) => out.end(resolve));
    console.log(`wrote ${total} lines to ${values.out}`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

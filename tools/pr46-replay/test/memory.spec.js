'use strict';

// Memory bounds: the patched blocker state must stay bounded however many
// users and events it sees, and the harness's own statistics must too (a
// month of one node exhausted a 2 GB heap before the harness fix).

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');
const v8 = require('node:v8');
const vm = require('node:vm');

const { Rng } = require('../fixtures/lib');
const { loadPr } = require('../lib/load-pr');
const { InputStats } = require('../lib/stats');

v8.setFlagsFromString('--expose-gc');
const gc = vm.runInNewContext('gc');
const MB = 1024 * 1024;

const heapUsed = () => {
    gc();
    gc();
    return process.memoryUsage().heapUsed;
};

const RECON = [22, 23, 3389, 445, 5900, 3306, 6379, 2323, 554];

describe('memory bounds', () => {
    it('patched blocker state: 5 M events from 200 k users stay bounded', (t) => {
        const pr = loadPr('patched');
        const config = pr.NodePluginSchema.parse({ abuseBlocker: { enabled: true } }).abuseBlocker;
        const state = new pr.AbuseBlockerState();
        state.configure({
            config,
            configFingerprint: 'memory',
            ignoredUsers: [],
            ignoredSources: [],
            ignoredDestinations: [],
        });

        const rng = new Rng(7);
        const xrayReport = { email: '1', network: 'tcp', ts: 0 };
        const samples = [];
        let timestamp = Date.UTC(2026, 8, 20);
        for (let index = 0; index < 5_000_000; index += 1) {
            timestamp += 20;
            const user = rng.int(1, 200_000);
            const roll = rng.next();
            const port = roll < 0.3 ? RECON[rng.int(0, RECON.length - 1)] : roll < 0.8 ? 443 : 50000 + rng.int(0, 999);
            const byName = rng.chance(0.4);
            state.analyze({
                userId: String(user),
                sourceIp: `198.${18 + (user & 1)}.${(user >> 1) & 255}.${(user >> 9) & 255}`,
                destinationIp: byName ? null : `198.51.100.${rng.int(1, 254)}`,
                destinationHost: byName ? `h${rng.int(0, 999)}.d${rng.int(0, 9999)}.example` : null,
                destinationPort: port,
                inboundTag: 'VLESS',
                timestamp,
                xrayReport,
            });
            if ((index + 1) % 1_000_000 === 0) {
                state.flushReports();
                samples.push(heapUsed());
            }
        }

        const stats = state.stats;
        t.diagnostic(
            `heap after GC at 1..5 M events (MB): ${samples.map((value) => Math.round(value / MB)).join(', ')}; ` +
                `users ${stats.trackedUsers}, sources ${stats.trackedSources}, evicted users ${stats.evictedUsers}`,
        );
        assert.ok(stats.trackedUsers <= config.maxTrackedUsers);
        assert.ok(stats.trackedSources <= config.sourceGuards.maxTrackedSources);
        assert.ok(stats.evictedUsers > 0, 'the user LRU was exercised');
        const growth = samples.at(-1) - samples[1];
        assert.ok(growth < 64 * MB, `heap grew ${Math.round(growth / MB)} MB from 2 M to 5 M events`);
        assert.ok(samples.at(-1) < 1024 * MB, `heap ${Math.round(samples.at(-1) / MB)} MB`);
    });

    it('harness input statistics: 1.2 M distinct source IPs stay bounded', (t) => {
        const input = new InputStats({ maxSources: 100_000 });
        const samples = [];
        const start = Date.UTC(2026, 8, 20);
        for (let index = 0; index < 1_200_000; index += 1) {
            const ms = start + index * 50;
            input.observeRecord(
                {
                    timestampMs: ms,
                    status: 'accepted',
                    network: 'tcp',
                    email: String(index % 5000),
                },
                `2001:db8:${(index >>> 16).toString(16)}::${(index & 0xffff).toString(16)}`,
                true,
            );
            if ((index + 1) % 400_000 === 0) samples.push(heapUsed());
        }
        t.diagnostic(`heap after GC at 0.4/0.8/1.2 M sources (MB): ${samples.map((value) => Math.round(value / MB)).join(', ')}`);
        assert.equal(input.sourceUsers.sources.size, 100_000);
        const estimate = input.build().activeSourceIpsEstimate;
        assert.ok(Math.abs(estimate - 1_200_000) / 1_200_000 < 0.03, `HLL estimate ${estimate}`);
        const growth = samples.at(-1) - samples[0];
        assert.ok(growth < 32 * MB, `heap grew ${Math.round(growth / MB)} MB`);
    });
});

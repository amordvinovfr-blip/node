'use strict';

// Pins the ACTUAL behaviour of PR #46 (schema defaults) on every synthetic
// scenario. These assertions describe what the PR does today, not what
// CONTEXT.md recommends; see docs/pr46-review/REVIEW.md for the comparison.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { SCENARIOS } = require('../scenarios');
const { replayVariant } = require('./helpers');

const byId = new Map(SCENARIOS.map((scenario) => [scenario.id, scenario]));

const run = async (id) => {
    const decisions = [];
    const report = await replayVariant(byId.get(id).generate().lines, 'head', {
        scenario: id,
        onDecision: (decision) => decisions.push(decision),
    });
    assert.equal(report.harness.handlerErrors, 0);
    return { report, decisions };
};

const assertNoBlock = (report) => {
    assert.equal(report.blocks.total, 0);
    assert.equal(report.decisions.byAction.block ?? 0, 0);
};

describe('PR #46 on false-positive classes (CONTEXT.md §2)', () => {
    it('bittorrent-dht: no block, UDP is never scored', async () => {
        const { report } = await run('bittorrent-dht');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 0);
        assert.equal(report.scoringInput.filteredNotTcp, report.input.accepted);
        assert.equal(report.decisions.total, 0);
    });

    it('bittorrent-tcp: no block, but destination_sweep raises an alert (score 100)', async () => {
        const { report, decisions } = await run('bittorrent-tcp');
        assertNoBlock(report);
        assert.deepEqual(
            decisions.map(({ rule, severity, score }) => [rule, severity, score]),
            [
                ['destination_sweep', 'suspicious', 50],
                ['destination_sweep', 'alert', 100],
            ],
        );
        assert.deepEqual(decisions.map((decision) => decision.destinationPort).sort(), [51413, 6881]);
    });

    it('dns-benchmark: no block, UDP is never scored', async () => {
        const { report } = await run('dns-benchmark');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 0);
        assert.equal(report.decisions.total, 0);
    });

    it('dns-benchmark-tcp: no block and no report (40 resolvers < 50, spread over /24s)', async () => {
        const { report } = await run('dns-benchmark-tcp');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 200);
        assert.equal(report.decisions.total, 0);
    });

    it('ntp-pool: no block, UDP is never scored', async () => {
        const { report } = await run('ntp-pool');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 0);
        assert.equal(report.decisions.total, 0);
    });

    it('steam-webrtc-xmpp: no block and no report', async () => {
        const { report } = await run('steam-webrtc-xmpp');
        assertNoBlock(report);
        assert.ok(report.scoringInput.analyzed > 0);
        assert.equal(report.decisions.total, 0);
    });

    it('imap-polling: no block and no report (16 addresses < 20 per /24)', async () => {
        const { report } = await run('imap-polling');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, report.input.accepted);
        assert.equal(report.decisions.total, 0);
    });

    it('heavy-browser: no block, 80/443 are excluded and QUIC is UDP', async () => {
        const { report } = await run('heavy-browser');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 0);
        assert.ok(report.scoringInput.excludedPort > 0);
        assert.equal(report.decisions.total, 0);
    });
});

describe('PR #46 on shared source addresses (CONTEXT.md §3)', () => {
    it('cgnat-shared-ip: blocks the shared IP, cutting off the 49 other users', async () => {
        const { report, decisions } = await run('cgnat-shared-ip');
        assert.equal(report.blocks.total, 1);
        const block = decisions.find((decision) => decision.action === 'block');
        assert.equal(block.userId, '2050');
        assert.equal(block.rule, 'horizontal_scan');
        assert.equal(block.destinationPort, 22);
        assert.equal(report.usersPerBlockedSourceIp.lastHourBeforeBlock.max, 50);
        assert.equal(report.collateral.distinctBystandersDropped, 49);
        assert.ok(report.timeToFirstBlock.secondsFromBlockedUserFirstSeen.min < 10);
    });

    it('chained-exit-node: blocks the entry node address; the log shows only 1 userId', async () => {
        const { report, decisions } = await run('chained-exit-node');
        assert.equal(report.blocks.total, 2);
        assert.equal(report.activeUsers, 1);
        assert.equal(report.usersPerBlockedSourceIp.lastHourBeforeBlock.max, 1);
        assert.deepEqual(
            decisions.filter((decision) => decision.action === 'block').map((decision) => decision.trafficClass),
            ['torrent', 'torrent'],
        );
        assert.ok(report.timeToFirstBlock.secondsFromLogStart > 600);
        assert.ok(report.timeToFirstBlock.secondsFromLogStart < 900);
        assert.ok(report.collateral.sessionsDroppedWhileBlocked > 50_000);
    });

    it('chained-exit-node-no-torrent: no block and no report in this traffic mix', async () => {
        const { report } = await run('chained-exit-node-no-torrent');
        assertNoBlock(report);
        assert.equal(report.decisions.total, 0);
    });
});

describe('PR #46 on true positives (CONTEXT.md §1)', () => {
    it('tp-ssh-sweep (random order): no block, only one suspicious report (score 50)', async () => {
        const { report, decisions } = await run('tp-ssh-sweep');
        assertNoBlock(report);
        assert.deepEqual(
            decisions.map(({ rule, severity, score }) => [rule, severity, score]),
            [['destination_sweep', 'suspicious', 50]],
        );
    });

    it('tp-ssh-sweep-sequential: blocks within seconds', async () => {
        const { report } = await run('tp-ssh-sweep-sequential');
        assert.equal(report.blocks.total, 1);
        assert.deepEqual(report.blocks.byRule, { horizontal_scan: 1 });
        assert.ok(report.timeToFirstBlock.secondsFromLogStart < 10);
    });

    it('tp-rtsp-sweep: no block, alert only (one destination_sweep per port)', async () => {
        const { report, decisions } = await run('tp-rtsp-sweep');
        assertNoBlock(report);
        assert.deepEqual(
            decisions.map(({ rule, severity, score }) => [rule, severity, score]),
            [
                ['destination_sweep', 'suspicious', 50],
                ['destination_sweep', 'alert', 100],
            ],
        );
    });

    it('tp-rdp-hammer: no block and no report (one destination)', async () => {
        const { report } = await run('tp-rdp-hammer');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 300);
        assert.equal(report.decisions.total, 0);
    });

    it('tp-session-burst: no block and no report (5 destinations)', async () => {
        const { report } = await run('tp-session-burst');
        assertNoBlock(report);
        assert.equal(report.scoringInput.analyzed, 700);
        assert.equal(report.decisions.total, 0);
    });
});

describe('scenario registry', () => {
    // compare.test.js pins every registered scenario for both variants; this
    // file keeps the detailed PR head assertions for the original sixteen.
    it('the scenarios detailed above are registered', () => {
        const covered = [
            'bittorrent-dht',
            'bittorrent-tcp',
            'dns-benchmark',
            'dns-benchmark-tcp',
            'ntp-pool',
            'steam-webrtc-xmpp',
            'imap-polling',
            'heavy-browser',
            'cgnat-shared-ip',
            'chained-exit-node',
            'chained-exit-node-no-torrent',
            'tp-ssh-sweep',
            'tp-ssh-sweep-sequential',
            'tp-rtsp-sweep',
            'tp-rdp-hammer',
            'tp-session-burst',
        ];
        const registered = new Set(SCENARIOS.map((scenario) => scenario.id));
        assert.deepEqual(covered.filter((id) => !registered.has(id)), []);
    });
});

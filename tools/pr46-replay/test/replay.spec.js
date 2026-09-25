'use strict';

const assert = require('node:assert/strict');
const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const net = require('node:net');
const os = require('node:os');
const path = require('node:path');
const { describe, it } = require('node:test');

const { BASE_MS, addr, formatLine } = require('../fixtures/lib');
const { loadPr } = require('../lib/load-pr');
const { replayLines } = require('../lib/replay');
const { replayVariant } = require('./helpers');

const RUN_JS = path.join(__dirname, '..', 'run.js');

/** 20 hosts in one /24 on :22 (alert), then 30 more /24s (sweep -> 150 -> block). */
const scanLines = ({ email = 42, src = addr.client(1), startMs = BASE_MS } = {}) =>
    Array.from({ length: 50 }, (_, index) =>
        formatLine({
            ms: startMs + index * 100,
            src,
            dst: index < 20 ? addr.target(0, index + 1) : addr.target(index, 1),
            port: 22,
            email,
        }),
    );

describe('replay harness', () => {
    it('drives the PR handler and records the block instead of calling nftables', async () => {
        const decisions = [];
        const report = await replayVariant(scanLines(), 'head', {
            onDecision: (decision) => decisions.push(decision),
        });

        assert.deepEqual(
            decisions.map(({ rule, score, action, severity }) => ({ rule, score, action, severity })),
            [
                { rule: 'horizontal_scan', score: 100, action: 'report', severity: 'alert' },
                { rule: 'destination_sweep', score: 150, action: 'block', severity: 'blocked' },
            ],
        );
        const block = decisions[1];
        assert.equal(block.userId, '42');
        assert.equal(block.sourceIp, addr.client(1));
        assert.equal(block.time, new Date(BASE_MS + 4000).toISOString());
        assert.equal(report.blocks.total, 1);
        assert.equal(report.harness.recorderCalls, 1);
        assert.equal(report.harness.handlerErrors, 0);
    });

    it('never reaches nftables-napi: the module is an inert stub', () => {
        loadPr();
        const { NftManager } = require('nftables-napi');
        assert.throws(() => new NftManager({}), /disabled in the PR #46 replay harness/);
        assert.equal(require('sockdestroy').hasCapNetAdmin(), false);
    });

    it('drops later events from a blocked IP (closed loop) and counts bystanders', async () => {
        const lines = [
            ...scanLines({ email: 42, src: addr.cgnatPublic }),
            formatLine({ ms: BASE_MS + 10_000, src: addr.cgnatPublic, dst: addr.service(1, 1), port: 993, email: 43 }),
            formatLine({ ms: BASE_MS + 700_000, src: addr.cgnatPublic, dst: addr.service(1, 1), port: 993, email: 44 }),
        ];
        const report = await replayVariant(lines, 'head');

        assert.equal(report.blocks.total, 1);
        assert.equal(report.scoringInput.droppedWhileSourceBlocked, 1);
        assert.equal(report.collateral.distinctBystandersDropped, 1);
        assert.equal(report.usersPerBlockedSourceIp.lastHourBeforeBlock.max, 1);
        assert.equal(report.usersPerBlockedSourceIp.duringBlock.max, 2);
    });

    it('in open-loop mode the PR asks to block the same IP again while it is blocked', async () => {
        const decisions = [];
        const lines = [
            ...scanLines(),
            ...scanLines({ startMs: BASE_MS + 400_000 }).map((line) => line.replace(':22 ', ':23 ')),
        ];
        const report = await replayVariant(lines, 'head', {
            closedLoop: false,
            onDecision: (decision) => decisions.push(decision),
        });

        assert.deepEqual(
            decisions.filter((decision) => decision.action === 'block').map((decision) => decision.repeat),
            [false, true, true],
        );
        assert.equal(report.blocks.total, 1);
        assert.equal(report.blocks.repeatWhileActive, 2);
    });

    it('restores the real clock after a replay', async () => {
        const RealDate = Date;
        await replayLines(scanLines());
        assert.equal(Date, RealDate);
        assert.ok(Math.abs(Date.now() - RealDate.prototype.getTime.call(new RealDate())) < 1000);
    });

    it('opens no network connections', async () => {
        const originalConnect = net.Socket.prototype.connect;
        const originalFetch = globalThis.fetch;
        let attempts = 0;
        net.Socket.prototype.connect = function connect(...args) {
            attempts += 1;
            return originalConnect.apply(this, args);
        };
        globalThis.fetch = async () => {
            attempts += 1;
            throw new Error('network is not allowed');
        };
        try {
            await replayLines(scanLines());
        } finally {
            net.Socket.prototype.connect = originalConnect;
            globalThis.fetch = originalFetch;
        }
        assert.equal(attempts, 0);
    });

    it('applies --config overrides through the PR schema, including ignore lists', async () => {
        const ignored = await replayVariant(scanLines(), 'head', {
            abuseBlocker: { ignoreLists: { sourceIp: ['192.0.2.0/24'] } },
        });
        assert.equal(ignored.decisions.total, 0);
        assert.equal(ignored.scoringInput.ignoredByList, 50);
        assert.equal(ignored.scoringInput.analyzed, 0);

        const stricter = await replayVariant(scanLines(), 'head', { abuseBlocker: { blockScore: 300 } });
        assert.equal(stricter.policy.blockScore, 300);
        assert.equal(stricter.blocks.total, 0);
        assert.equal(stricter.decisions.bySeverity.alert, 2);
    });

    it('report contains aggregates only, no IPs or user IDs', async () => {
        const report = await replayLines(
            [
                ...scanLines({ email: 987654 }),
                formatLine({ ms: BASE_MS + 9000, src: addr.client(3), dst: 'ssh.victim.example', port: 22, email: 987654 }),
            ],
            { variants: ['head', 'patched'] },
        );
        const text = JSON.stringify(report);
        assert.equal(report.variants.patched.domainDestinations.observed, 1);
        assert.doesNotMatch(text, /\d+\.\d+\.\d+\.\d+/);
        assert.doesNotMatch(text, /987654/);
        assert.doesNotMatch(text, /victim/);
    });
});

describe('run.js CLI', () => {
    it('runs as one command with no native addons and no child processes allowed', () => {
        const dir = fs.mkdtempSync(path.join(os.tmpdir(), 'pr46-replay-'));
        const log = path.join(dir, 'access.log');
        const out = path.join(dir, 'report.json');
        fs.writeFileSync(
            log,
            [
                ...scanLines(),
                formatLine({ ms: BASE_MS + 9000, src: addr.client(2), net: 'udp', dst: addr.resolver(0), port: 53, email: 7 }),
                '2026/09/20 12:00:10 from 192.0.2.3:1 accepted tcp:198.51.100.7:22 [api -> api]',
                'not an access log line',
            ].join('\n'),
        );

        const result = spawnSync(
            process.execPath,
            [
                '--permission',
                '--allow-fs-read=*',
                `--allow-fs-write=${dir}`,
                RUN_JS,
                '--compare',
                '--log',
                log,
                '--out',
                out,
            ],
            { encoding: 'utf8' },
        );
        assert.equal(result.status, 0, result.stderr);

        const report = JSON.parse(fs.readFileSync(out, 'utf8'));
        assert.equal(report.input.total, 53);
        assert.equal(report.input.unparsed, 1);
        const head = report.variants.head;
        assert.equal(head.scoringInput.filteredNotTcp, 1);
        assert.equal(head.scoringInput.filteredNoNumericEmail, 1);
        assert.equal(head.blocks.total, 1);
        assert.equal(report.variants.patched.blocks.total, 0);

        const decisions = fs
            .readFileSync(path.join(dir, 'report.decisions.jsonl'), 'utf8')
            .trim()
            .split('\n')
            .map((line) => JSON.parse(line));
        assert.equal(decisions.filter((decision) => decision.variant === 'head').length, 2);
        for (const decision of decisions) {
            for (const key of ['variant', 'time', 'userId', 'sourceIp', 'rule', 'score', 'action']) {
                assert.ok(key in decision, `decision has ${key}`);
            }
        }
        fs.rmSync(dir, { recursive: true, force: true });
    });
});

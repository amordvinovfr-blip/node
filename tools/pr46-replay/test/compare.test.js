'use strict';

// Pins BOTH behaviours on every scenario: the PR #46 head rules and the
// patched rules (defaults, measured in block mode). These describe what the
// code does today, not what CONTEXT.md recommends.

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const HEAD_EQUIVALENT = require('../configs/pr46-head-equivalent.json');
const midnight = require('../fixtures/tp-midnight');
const { replayLines } = require('../lib/replay');
const { SCENARIOS } = require('../scenarios');

const byId = new Map(SCENARIOS.map((scenario) => [scenario.id, scenario]));

/** blocks, decisions by severity, rule:phase pairs and skip reasons per variant. */
const PINS = {
    "bittorrent-dht": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "bittorrent-tcp": {head: {blocks: 0,severity: {suspicious: 1,alert: 1},rules: ["destination_sweep:single"]},patched: {blocks: 0,severity: {alert: 1},rules: ["session_rate_burst:candidate"]}},
    "dns-benchmark": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "dns-benchmark-tcp": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "ntp-pool": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "steam-webrtc-xmpp": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "imap-polling": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "heavy-browser": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "app-peers-50300": {head: {blocks: 2,severity: {suspicious: 1,alert: 1,blocked: 2},rules: ["destination_sweep:single"]},patched: {blocks: 0,severity: {}}},
    "app-peers-8887": {head: {blocks: 2,severity: {suspicious: 1,alert: 1,blocked: 2},rules: ["destination_sweep:single"]},patched: {blocks: 0,severity: {}}},
    "lan-sync": {head: {blocks: 10,severity: {alert: 2,blocked: 10},rules: ["destination_sweep:single","horizontal_scan:single"]},patched: {blocks: 0,severity: {}}},
    "heavy-browser-domains": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "api-poller": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "imap-domain": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "ssh-jump-hosts": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "cdn-shards": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "tracker-announce": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "game-launcher": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "cgnat-shared-ip": {head: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_scan:single"]},patched: {blocks: 0,severity: {alert: 1,blocked: 1},rules: ["horizontal_sweep:candidate","horizontal_sweep:confirmed"],skip: {"shared_source":1}}},
    "chained-exit-node": {head: {blocks: 2,severity: {suspicious: 1,alert: 1,blocked: 2},rules: ["destination_sweep:single"]},patched: {blocks: 0,severity: {}}},
    "chained-exit-node-no-torrent": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {}}},
    "tp-ssh-sweep": {head: {blocks: 0,severity: {suspicious: 1},rules: ["destination_sweep:single"]},patched: {blocks: 0,severity: {alert: 1},rules: ["horizontal_sweep:candidate"]}},
    "tp-ssh-sweep-sequential": {head: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_scan:single"]},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_sweep:candidate","horizontal_sweep:confirmed"]}},
    "tp-rtsp-sweep": {head: {blocks: 0,severity: {suspicious: 1,alert: 1},rules: ["destination_sweep:single"]},patched: {blocks: 0,severity: {alert: 2},rules: ["horizontal_sweep:candidate"]}},
    "tp-rdp-hammer": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {alert: 1},rules: ["hammer_target:candidate"]}},
    "tp-rdp-hammer-400": {head: {blocks: 0,severity: {}},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["hammer_target:candidate","hammer_target:confirmed"]}},
    "tp-rdp-hammer-host-300": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {alert: 1},rules: ["hammer_target:candidate"]}},
    "tp-rdp-hammer-host-400": {head: {blocks: 0,severity: {}},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["hammer_target:candidate","hammer_target:confirmed"]}},
    "tp-ssh-random-25": {head: {blocks: 0,severity: {}},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_sweep:candidate","horizontal_sweep:confirmed"]}},
    "tp-ssh-random-50": {head: {blocks: 0,severity: {suspicious: 1},rules: ["destination_sweep:single"]},patched: {blocks: 2,severity: {alert: 1,blocked: 2},rules: ["horizontal_sweep:candidate","horizontal_sweep:confirmed"]}},
    "tp-ssh-random-500": {head: {blocks: 0,severity: {suspicious: 1},rules: ["destination_sweep:single"]},patched: {blocks: 2,severity: {alert: 1,blocked: 2},rules: ["horizontal_sweep:candidate","horizontal_sweep:confirmed"]}},
    "tp-ssh-hostnames": {head: {blocks: 0,severity: {}},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_sweep_domains:candidate","horizontal_sweep_domains:confirmed"]}},
    "tp-subdomain-enum": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {alert: 2},rules: ["subdomain_sweep:candidate","subdomain_sweep:confirmed"]}},
    "tp-mixed-telnet": {head: {blocks: 0,severity: {}},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_sweep_domains:candidate","horizontal_sweep_domains:confirmed"]}},
    "tp-midnight": {head: {blocks: 0,severity: {}},patched: {blocks: 1,severity: {alert: 1,blocked: 1},rules: ["horizontal_sweep:candidate","horizontal_sweep:confirmed"]}},
    "tp-session-burst": {head: {blocks: 0,severity: {}},patched: {blocks: 0,severity: {alert: 1},rules: ["session_rate_burst:candidate"]}},
};

const compare = async (lines, options = {}) => {
    const decisions = { head: [], patched: [] };
    const report = await replayLines(lines, {
        variants: ['head', 'patched'],
        patchedMode: 'block',
        onDecision: (decision) => decisions[decision.variant].push(decision),
        ...options,
    });
    assert.equal(report.harness.handlerErrors, 0);
    return { report, decisions };
};

const outcome = (report, decisions, variant) => {
    const result = report.variants[variant];
    const pinned = { blocks: result.blocks.total, severity: result.decisions.bySeverity };
    const rules = [
        ...new Set(
            decisions[variant].flatMap((decision) =>
                decision.rules.map((rule, index) => `${rule}:${decision.phases[index]}`),
            ),
        ),
    ].sort();
    if (rules.length > 0) pinned.rules = rules;
    if (Object.keys(result.decisions.bySkipReason).length > 0) pinned.skip = result.decisions.bySkipReason;
    return pinned;
};

describe('PR #46 head vs patched, every scenario', () => {
    it('pins cover every registered scenario', () => {
        assert.deepEqual(Object.keys(PINS).sort(), SCENARIOS.map((scenario) => scenario.id).sort());
    });

    for (const [id, expected] of Object.entries(PINS)) {
        it(id, async () => {
            const { report, decisions } = await compare(byId.get(id).generate().lines);
            assert.deepEqual(outcome(report, decisions, 'head'), expected.head);
            assert.deepEqual(outcome(report, decisions, 'patched'), expected.patched);
        });
    }
});

describe('patched rules, details', () => {
    it('no benign scenario blocks, and every true positive reaches alert or higher', async () => {
        for (const scenario of SCENARIOS) {
            const patched = PINS[scenario.id].patched;
            if (scenario.group === 'false-positive') assert.equal(patched.blocks, 0, scenario.id);
            if (scenario.group === 'true-positive') {
                assert.ok((patched.severity.alert ?? 0) + (patched.severity.blocked ?? 0) > 0, scenario.id);
            }
        }
    });

    it('CGNAT: the scanner is confirmed, but the shared IP is not blocked', async () => {
        const { report, decisions } = await compare(byId.get('cgnat-shared-ip').generate().lines);
        const wouldBlock = decisions.patched.find((decision) => decision.severity === 'blocked');
        assert.equal(wouldBlock.userId, '2050');
        assert.equal(wouldBlock.action, 'report');
        assert.equal(wouldBlock.skipReason, 'shared_source');
        assert.equal(wouldBlock.sourceIpUserCount, 16);
        assert.equal(report.variants.patched.collateral.sessionsDroppedWhileBlocked, 0);
        assert.equal(report.variants.head.collateral.distinctBystandersDropped, 49);
    });

    it('report-only default: the same sweep is reported, never blocked', async () => {
        const { report, decisions } = await compare(byId.get('tp-ssh-random-25').generate().lines, {
            patchedMode: null,
        });
        assert.equal(report.variants.patched.policy.mode, 'report');
        assert.equal(report.variants.patched.blocks.total, 0);
        assert.equal(report.variants.patched.harness.recorderCalls, 0);
        assert.deepEqual(report.variants.patched.decisions.bySkipReason, { report_only: 2 });
        assert.ok(decisions.patched.some((decision) => decision.severity === 'blocked'));
    });

    it('a scan across midnight is caught in one replay but not in two per-day replays', async () => {
        const whole = await compare(midnight.generate().lines);
        assert.equal(whole.report.variants.patched.blocks.total, 1);
        const blockedAt = Date.parse(
            whole.decisions.patched.find((decision) => decision.action === 'block').time,
        );
        assert.ok(blockedAt > midnight.MIDNIGHT_MS);

        for (const day of ['first', 'second']) {
            const half = await compare(midnight.generate({ day }).lines);
            assert.equal(half.report.variants.patched.decisions.total, 0, day);
        }
    });

    it('domain destinations are counted as seen vs scored, without hostnames in the report', async () => {
        const { report } = await compare(byId.get('tp-ssh-hostnames').generate().lines);
        const domains = report.variants.patched.domainDestinations;
        assert.equal(domains.seen, 500);
        assert.ok(domains.observed > 0 && domains.observed === domains.reachedDomainRules);
        assert.equal(report.variants.head.domainDestinations.observed, 0);
        assert.doesNotMatch(JSON.stringify(report), /victim/);
    });
});

describe('configs/pr46-head-equivalent.json', () => {
    it('makes the patched code decide exactly like the PR head on every scenario', async () => {
        const key = (decision) =>
            [
                decision.time,
                decision.userId,
                decision.sourceIp,
                decision.destinationPort,
                decision.rule,
                decision.score,
                decision.severity,
                decision.action,
                decision.repeat,
            ].join('|');
        for (const scenario of SCENARIOS) {
            const { decisions } = await compare(scenario.generate().lines, {
                patchedMode: null,
                configs: { patched: HEAD_EQUIVALENT },
            });
            assert.deepEqual(decisions.patched.map(key), decisions.head.map(key), scenario.id);
        }
    });
});

import type { XrayWebhookModel } from '../../libs/contract/models';

import assert from 'node:assert/strict';
import { describe, it } from 'node:test';

import { NodePluginSchema } from '@remnawave/node-plugins';

import { toAbuseBlockerObservation } from '../../src/modules/_plugin/events/xray-webhook/xray-webhook.handler';
import { AbuseBlockerState } from '../../src/modules/_plugin/services/states/abuse-blocker.state';
import {
    getRegistrableDomain,
    normalizeHostname,
} from '../../src/modules/_plugin/utils/domain.utils';

const webhook: XrayWebhookModel = {
    email: '42',
    level: 0,
    protocol: null,
    network: 'tcp',
    source: '198.51.100.10:12345',
    destination: '192.0.2.1:22',
    routeTarget: null,
    originalTarget: null,
    inboundTag: 'VLESS',
    inboundName: null,
    inboundLocal: null,
    outboundTag: 'DIRECT',
    ts: 0,
};

const createState = (overrides: Record<string, unknown> = {}) => {
    const config = NodePluginSchema.parse({
        abuseBlocker: { enabled: true, ...overrides },
    }).abuseBlocker!;
    const state = new AbuseBlockerState();
    state.configure({
        config,
        configFingerprint: 'test-config',
        ignoredUsers: [],
        ignoredSources: [],
        ignoredDestinations: [],
    });
    return state;
};

interface IEvent {
    timestamp: number;
    port?: number;
    ip?: string | null;
    host?: string | null;
    userId?: string;
    sourceIp?: string;
    inboundTag?: string | null;
}

const analyze = (state: AbuseBlockerState, event: IEvent) =>
    state.analyze({
        userId: event.userId ?? '42',
        sourceIp: event.sourceIp ?? '198.51.100.10',
        destinationIp: event.host ? null : (event.ip ?? '192.0.2.1'),
        destinationHost: event.host ?? null,
        destinationPort: event.port ?? 22,
        inboundTag: event.inboundTag ?? 'VLESS',
        timestamp: event.timestamp,
        xrayReport: webhook,
    });

/** 198.18.<n>.1, one host in each of `count` distinct /24s (RFC 2544). */
const network = (index: number) => `198.${18 + (index >> 8)}.${index & 255}.1`;

const T0 = 1_000_000_000;

describe('AbuseBlockerState v2 defaults', () => {
    it('defaults to report mode and the v2 rule set; old configs still parse', () => {
        const config = NodePluginSchema.parse({
            abuseBlocker: {
                enabled: true,
                blockScore: 300,
                horizontalScan: { uniqueDestinations: 30 },
            },
        }).abuseBlocker!;
        assert.equal(config.mode, 'report');
        assert.equal(config.ruleSet, 'v2');
        assert.equal(config.confirmationSeconds, 60);
        assert.ok(config.scanPorts.includes(22));
        assert.ok(!config.scanPorts.includes(443));
        assert.equal(config.horizontalScan.uniqueDestinations, 30);
    });

    it('does not run the PR #46 geometry rules by default', () => {
        const state = createState();
        for (let index = 1; index <= 60; index += 1) {
            assert.equal(
                analyze(state, { timestamp: T0 + index * 100, ip: `192.0.2.${index}` }),
                null,
            );
        }
    });
});

describe('horizontal_sweep', () => {
    it('reports a candidate at 150 /24s and confirms at least 60 s later', () => {
        const state = createState();
        const results = [];
        for (let index = 0; index < 260; index += 1) {
            const result = analyze(state, { timestamp: T0 + index * 1000, ip: network(index) });
            if (result) results.push({ index, result });
        }

        const [candidate, confirmed] = results;
        assert.equal(candidate.index, 149);
        assert.equal(candidate.result.detections[0].rule, 'horizontal_sweep');
        assert.equal(candidate.result.detections[0].phase, 'candidate');
        assert.equal(candidate.result.detections[0].count, 150);
        assert.equal(candidate.result.detections[0].unit, 'networks');
        assert.equal(candidate.result.severity, 'alert');
        assert.equal(candidate.result.shouldBlock, false);

        assert.equal(confirmed.index, 209);
        assert.equal(confirmed.result.detections[0].phase, 'confirmed');
        assert.equal(confirmed.result.severity, 'blocked');
        assert.equal(confirmed.result.shouldBlock, true);
        assert.equal(confirmed.result.sourceIpUserCount, 1);
    });

    it('fires again every cooldown while the sweep continues (no latch)', () => {
        const state = createState();
        const phases = [];
        for (let index = 0; index < 900; index += 1) {
            const result = analyze(state, {
                timestamp: T0 + index * 1000,
                ip: network(index % 500),
            });
            const detection = result?.detections.find((item) => item.rule === 'horizontal_sweep');
            if (detection) phases.push([index, detection.phase]);
        }
        assert.deepEqual(phases, [
            [149, 'candidate'],
            [209, 'confirmed'],
            [509, 'confirmed'],
            [809, 'confirmed'],
        ]);
    });

    it('ignores ports outside scanPorts, such as an app port', () => {
        const state = createState({ sessionRateBurst: { enabled: false } });
        for (let index = 0; index < 400; index += 1) {
            assert.equal(
                analyze(state, { timestamp: T0 + index * 500, ip: network(index), port: 50300 }),
                null,
            );
        }
    });

    it('keeps at most maxNetworksPerKey networks per key', () => {
        const state = createState({
            horizontalSweep: { uniqueNetworks: 20, maxNetworksPerKey: 20 },
        });
        let last = null;
        for (let index = 0; index < 400; index += 1) {
            last = analyze(state, { timestamp: T0 + index * 1000, ip: network(index) }) ?? last;
        }
        assert.ok(last);
        assert.ok(last.detections.every((detection) => detection.count <= 20));
    });
});

describe('hammer_target', () => {
    it('counts sessions to one IP and confirms a continuing hammer', () => {
        const state = createState();
        const results = [];
        for (let index = 0; index < 400; index += 1) {
            const result = analyze(state, {
                timestamp: T0 + index * 2000,
                ip: '192.0.2.89',
                port: 3389,
            });
            if (result) results.push({ index, detection: result.detections[0], result });
        }
        assert.equal(results[0].index, 299);
        assert.equal(results[0].detection.rule, 'hammer_target');
        assert.equal(results[0].detection.phase, 'candidate');
        assert.equal(results[0].detection.key, '3389|192.0.2.89');
        assert.equal(results[1].index, 329);
        assert.equal(results[1].detection.phase, 'confirmed');
        assert.equal(results[1].result.shouldBlock, true);
    });

    it('counts sessions to one hostname without resolving it', () => {
        const state = createState();
        let last = null;
        for (let index = 0; index < 360; index += 1) {
            last =
                analyze(state, {
                    timestamp: T0 + index * 2000,
                    host: 'rdp.office.example',
                    port: 3389,
                }) ?? last;
        }
        assert.equal(last?.detections[0].rule, 'hammer_target');
        assert.equal(last?.detections[0].key, '3389|rdp.office.example');
        assert.equal(last?.shouldBlock, true);
    });

    it('caps tracked targets per user', () => {
        const state = createState({ hammerTarget: { maxTargetsPerUser: 2, sessions: 3 } });
        const hits = [];
        for (let index = 0; index < 30; index += 1) {
            const result = analyze(state, {
                timestamp: T0 + index * 1000,
                ip: `192.0.2.${(index % 3) + 1}`,
                port: 3389,
            });
            if (result) hits.push(index);
        }
        assert.deepEqual(hits, []);
    });
});

describe('session_rate_burst', () => {
    it('reports 600 non-web sessions per minute but never blocks by default', () => {
        const state = createState();
        const results = [];
        for (let index = 0; index < 2400; index += 1) {
            const result = analyze(state, {
                timestamp: T0 + index * 50,
                ip: `192.0.2.${(index % 5) + 1}`,
                port: 50300,
            });
            if (result) results.push(result);
        }
        assert.deepEqual(
            results.map((result) => [
                result.detections[0].rule,
                result.detections[0].phase,
                result.severity,
            ]),
            [
                ['session_rate_burst', 'candidate', 'alert'],
                ['session_rate_burst', 'confirmed', 'alert'],
            ],
        );
        assert.ok(results.every((result) => !result.shouldBlock));
    });

    it('does not count 80/443', () => {
        const state = createState();
        for (let index = 0; index < 2000; index += 1) {
            assert.equal(
                analyze(state, { timestamp: T0 + index * 10, ip: '192.0.2.1', port: 443 }),
                null,
            );
        }
    });
});

describe('domain rules', () => {
    it('horizontal_sweep_domains fires at 50 registrable domains on a scan port', () => {
        const state = createState();
        let first = null;
        for (let index = 0; index < 120; index += 1) {
            const result = analyze(state, {
                timestamp: T0 + index * 1000,
                host: `ssh.site${index}.example`,
            });
            first ??= result && { index, result };
        }
        assert.equal(first?.index, 49);
        assert.equal(first?.result.detections[0].rule, 'horizontal_sweep_domains');
        assert.equal(first?.result.detections[0].unit, 'domains');
    });

    it('subdomain_sweep reports 100 hostnames under one domain and never blocks', () => {
        const state = createState({ hammerTarget: { enabled: false } });
        const results = [];
        for (let index = 0; index < 300; index += 1) {
            const result = analyze(state, {
                timestamp: T0 + index * 1000,
                host: `host${index}.corp.example`,
                port: index % 2 ? 22 : 3389,
            });
            if (result) results.push(result);
        }
        assert.equal(results[0].detections[0].rule, 'subdomain_sweep');
        assert.equal(results[0].detections[0].key, 'corp.example');
        assert.equal(results[0].detections[0].count, 100);
        assert.ok(results.every((result) => !result.shouldBlock));
    });

    it('five jump hosts under one domain stay silent', () => {
        const state = createState();
        for (let index = 0; index < 600; index += 1) {
            assert.equal(
                analyze(state, {
                    timestamp: T0 + index * 3000,
                    host: `jump${index % 5}.corp.example`,
                }),
                null,
            );
        }
    });

    it('never scores hostnames on 80/443', () => {
        const state = createState({ scanPorts: [22, 443] });
        for (let index = 0; index < 400; index += 1) {
            assert.equal(
                analyze(state, {
                    timestamp: T0 + index * 1000,
                    host: `h${index}.site${index}.example`,
                    port: 443,
                }),
                null,
            );
        }
    });
});

describe('source guards', () => {
    const sweep = (state: AbuseBlockerState, event: Partial<IEvent> = {}) => {
        let last = null;
        for (let index = 0; index < 220; index += 1) {
            last =
                analyze(state, { timestamp: T0 + index * 1000, ip: network(index), ...event }) ??
                last;
        }
        return last!;
    };

    it('never blocks non-public sources', () => {
        const result = sweep(createState(), { sourceIp: '10.255.0.2' });
        assert.equal(result.severity, 'blocked');
        assert.equal(result.shouldBlock, false);
        assert.equal(result.skipReason, 'non_public_source');
    });

    it('reports shared_source when another user used the source in the last hour', () => {
        const state = createState();
        analyze(state, { timestamp: T0 - 1000, userId: '43', ip: '192.0.2.200', port: 443 });
        const result = sweep(state);
        assert.equal(result.skipReason, 'shared_source');
        assert.equal(result.sourceIpUserCount, 2);
    });

    it('honours reportOnlyUserIds and reportOnlyInboundTags', () => {
        assert.equal(
            sweep(createState({ sourceGuards: { reportOnlyUserIds: [42] } })).skipReason,
            'report_only_user',
        );
        assert.equal(
            sweep(createState({ sourceGuards: { reportOnlyInboundTags: ['MESH'] } }), {
                inboundTag: 'MESH',
            }).skipReason,
            'report_only_inbound',
        );
    });

    it('bounds the source tracker', () => {
        const state = createState({ sourceGuards: { maxTrackedSources: 100 } });
        for (let index = 0; index < 1000; index += 1) {
            analyze(state, {
                timestamp: T0 + index,
                sourceIp: `203.0.113.${index % 250}`,
                userId: String(index),
                port: 443,
            });
        }
        assert.equal(state.stats.trackedSources, 100);
    });
});

describe('observation mapping for hostnames', () => {
    const domainHook = {
        ...webhook,
        destination: 'SSH.Example.:22',
        originalTarget: 'tcp:SSH.Example.:22',
    };

    it('keeps the PR #46 behaviour without options', () => {
        assert.equal(toAbuseBlockerObservation(domainHook), null);
    });

    it('maps a hostname request to a normalized hostname observation', () => {
        const observation = toAbuseBlockerObservation(domainHook, { domains: true });
        assert.equal(observation?.destinationIp, null);
        assert.equal(observation?.destinationHost, 'ssh.example');
        assert.equal(observation?.destinationPort, 22);
        assert.equal(observation?.inboundTag, 'VLESS');
    });

    it('still prefers an IP from any target field', () => {
        const observation = toAbuseBlockerObservation(
            { ...domainHook, originalTarget: 'tcp:192.0.2.7:22' },
            { domains: true },
        );
        assert.equal(observation?.destinationIp, '192.0.2.7');
        assert.equal(observation?.destinationHost, null);
    });

    it('normalizes IDNA and rejects garbage', () => {
        assert.equal(normalizeHostname('Пример.Example.'), 'xn--e1afmkfd.example');
        for (const bad of [
            '',
            'localhost',
            '192.0.2.1',
            '[2001:db8::1]',
            'a..b.test',
            '-bad.test',
            'x'.repeat(64) + '.test',
        ]) {
            assert.equal(normalizeHostname(bad), null, bad);
        }
        assert.equal(getRegistrableDomain('a.b.corp.example'), 'corp.example');
    });
});

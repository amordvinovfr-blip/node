'use strict';

const assert = require('node:assert/strict');
const { describe, it } = require('node:test');

const { loadPr } = require('../lib/load-pr');
const { parseLine, toWebhook } = require('../lib/parse-log');

const TCP_LINE =
    '2026/09/20 12:00:00.123456 from 203.0.113.5:51234 accepted tcp:198.51.100.7:443 [INBOUND -> DIRECT] email: 12345';

describe('parseLine', () => {
    it('parses the standard TCP line', () => {
        assert.deepEqual(parseLine(TCP_LINE), {
            timestampMs: Date.UTC(2026, 8, 20, 12, 0, 0, 123),
            status: 'accepted',
            network: 'tcp',
            source: '203.0.113.5:51234',
            destination: '198.51.100.7:443',
            inboundTag: 'INBOUND',
            outboundTag: 'DIRECT',
            email: '12345',
        });
    });

    it('parses UDP, a tcp:-prefixed source, >> detours and whole-second timestamps', () => {
        const record = parseLine(
            '2026/09/20 12:00:01 from tcp:192.0.2.9:40000 accepted udp:198.51.100.53:53 [VLESS >> DIRECT] email: 7',
        );
        assert.equal(record.timestampMs, Date.UTC(2026, 8, 20, 12, 0, 1));
        assert.equal(record.network, 'udp');
        assert.equal(record.source, '192.0.2.9:40000');
        assert.equal(record.destination, '198.51.100.53:53');
        assert.equal(record.outboundTag, 'DIRECT');
    });

    it('parses IPv6 endpoints', () => {
        const record = parseLine(
            '2026/09/20 12:00:02.5 from [2001:db8::5]:51234 accepted tcp:[2001:db8:1::7]:22 [IN -> OUT] email: 9',
        );
        assert.equal(record.source, '[2001:db8::5]:51234');
        assert.equal(record.destination, '[2001:db8:1::7]:22');
        assert.equal(record.timestampMs, Date.UTC(2026, 8, 20, 12, 0, 2, 500));
    });

    it('parses lines without email, with a reason, and rejected lines', () => {
        assert.equal(
            parseLine('2026/09/20 12:00:03 from 192.0.2.9:1 accepted tcp:198.51.100.7:22 [api -> api]').email,
            null,
        );
        const withReason = parseLine(
            '2026/09/20 12:00:03 from 192.0.2.9:1 accepted tcp:198.51.100.7:22 [IN -> BLOCK] some reason email: 5',
        );
        assert.equal(withReason.email, '5');
        assert.equal(withReason.outboundTag, 'BLOCK');
        assert.equal(
            parseLine('2026/09/20 12:00:03 from 192.0.2.9:1 rejected tcp:198.51.100.7:22 invalid request').status,
            'rejected',
        );
    });

    it('returns null for lines that are not access entries', () => {
        assert.equal(parseLine(''), null);
        assert.equal(parseLine('2026/09/20 12:00:03 [Info] app/dispatcher: taking detour'), null);
    });
});

describe('toWebhook -> PR toAbuseBlockerObservation', () => {
    const { toAbuseBlockerObservation } = loadPr();
    const observe = (line, options) => toAbuseBlockerObservation(toWebhook(parseLine(line), options));

    it('produces the observation PR #46 scores, with whole-second time like Xray', () => {
        const observation = observe(TCP_LINE);
        assert.equal(observation.userId, '12345');
        assert.equal(observation.sourceIp, '203.0.113.5');
        assert.equal(observation.destinationIp, '198.51.100.7');
        assert.equal(observation.destinationPort, 443);
        assert.equal(observation.timestamp, Date.UTC(2026, 8, 20, 12, 0, 0));
        assert.equal(observe(TCP_LINE, { subSecond: true }).timestamp, Date.UTC(2026, 8, 20, 12, 0, 0, 123));
    });

    it('keeps IPv6 destinations', () => {
        const observation = observe(
            '2026/09/20 12:00:02 from [2001:db8::5]:51234 accepted tcp:[2001:db8:1::7]:22 [IN -> OUT] email: 9',
        );
        assert.equal(observation.sourceIp, '2001:db8::5');
        assert.equal(observation.destinationIp, '2001:db8:1::7');
    });

    it('is dropped by the PR for UDP, missing or non-numeric email, and domain destinations', () => {
        const base = '2026/09/20 12:00:00 from 192.0.2.9:1 accepted';
        assert.equal(observe(`${base} udp:198.51.100.7:53 [IN -> OUT] email: 1`), null);
        assert.equal(observe(`${base} tcp:198.51.100.7:22 [IN -> OUT]`), null);
        assert.equal(observe(`${base} tcp:198.51.100.7:22 [IN -> OUT] email: user.name`), null);
        assert.equal(observe(`${base} tcp:example.test:22 [IN -> OUT] email: 1`), null);
    });
});

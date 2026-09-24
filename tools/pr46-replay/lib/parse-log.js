'use strict';

// Xray access.log line -> the webhook payload that Xray's routing webhook
// (app/router/webhook.go) would POST for the same connection. That payload is
// what PR #46 consumes (XrayWebhookModel -> toAbuseBlockerObservation).
//
// Supported shapes (Xray common/log/access.go, prefixed by the log timestamp):
//   2026/09/20 12:00:00.123456 from 203.0.113.5:51234 accepted tcp:198.51.100.7:443 [IN -> OUT] email: 12345
//   2026/09/20 12:00:00 from tcp:203.0.113.5:51234 accepted udp:198.51.100.7:53 [IN >> OUT]
//   2026/09/20 12:00:00.123456 from [2001:db8::5]:51234 accepted tcp:[2001:db8::7]:443 [IN -> OUT] email: 7
// Timestamps carry no zone; they are read as UTC. Only relative time matters.

const LINE_RE =
    /^(\d{4})\/(\d{2})\/(\d{2}) (\d{2}):(\d{2}):(\d{2})(?:\.(\d{1,9}))? from (\S+) (accepted|rejected) (\S+)(?: \[([^\]]*)\])?(.*?)(?: email: (\S+))?\s*$/;
const DETOUR_RE = /^(.*?) (?:->|>>|==>) (.*)$/;
const NETWORK_RE = /^(tcp|udp|unix):/i;

/**
 * @returns {null | {
 *   timestampMs: number, status: 'accepted' | 'rejected', network: string,
 *   source: string, destination: string, inboundTag: string | null,
 *   outboundTag: string | null, email: string | null }}
 */
const parseLine = (line) => {
    const match = LINE_RE.exec(line);
    if (!match) return null;

    const [, year, month, day, hour, minute, second, fraction = '0'] = match;
    const [, , , , , , , , from, status, to, detour, , email] = match;
    const millis = Number(fraction.padEnd(3, '0').slice(0, 3));
    const timestampMs = Date.UTC(+year, +month - 1, +day, +hour, +minute, +second, millis);

    const network = (NETWORK_RE.exec(to)?.[1] ?? 'unknown').toLowerCase();
    const detourMatch = detour ? DETOUR_RE.exec(detour) : null;

    return {
        timestampMs,
        status,
        network,
        source: from.replace(NETWORK_RE, ''),
        destination: to.replace(NETWORK_RE, ''),
        inboundTag: detourMatch ? detourMatch[1] : (detour ?? null),
        outboundTag: detourMatch ? detourMatch[2] : null,
        email: email ?? null,
    };
};

/**
 * Builds the XrayWebhookModel for a parsed line. `ts` is whole seconds, like
 * Xray's `time.Now().Unix()`, unless `subSecond` is set.
 */
const toWebhook = (record, { subSecond = false } = {}) => ({
    email: record.email,
    level: record.email === null ? null : 0,
    protocol: null,
    network: record.network,
    source: record.source,
    destination: record.destination,
    routeTarget: null,
    originalTarget: null,
    inboundTag: record.inboundTag,
    inboundName: null,
    inboundLocal: null,
    outboundTag: record.outboundTag,
    ts: subSecond ? record.timestampMs / 1000 : Math.floor(record.timestampMs / 1000),
});

module.exports = { parseLine, toWebhook };

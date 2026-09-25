'use strict';

const fs = require('node:fs');
const { isIP } = require('node:net');
const readline = require('node:readline');
const zlib = require('node:zlib');

const { installFakeClock } = require('./fake-clock');
const { loadPr } = require('./load-pr');
const { parseLine, toWebhook } = require('./parse-log');
const { InputStats, VariantStats } = require('./stats');
const { classifyPort } = require('./traffic-class');

const WEB_PORTS = new Set([80, 443]);

/** IP of an Xray `ip:port` / `[ip]:port` endpoint, as parseNetworkEndpoint returns it, or null. */
const endpointIp = (value) => {
    let host;
    if (value.startsWith('[')) {
        const end = value.indexOf(']');
        if (end < 0) return null;
        host = value.slice(1, end);
    } else {
        const separator = value.lastIndexOf(':');
        host = separator < 0 ? value : value.slice(0, separator);
        if (host.includes(':')) host = value;
    }
    return isIP(host.split('%')[0]) === 0 ? null : host;
};

/**
 * Stands in for NftService. The PR's XrayWebhookHandler calls
 * `blockAbuseIp(sourceIp, initialBlockSeconds)`; we record the call instead
 * of adding the IP to the nftables `abuse-blocker` set.
 */
class BlockRecorder {
    constructor(clock) {
        this.clock = clock;
        this.calls = 0;
        this.blockedUntil = new Map();
        this.lastCallWasRepeat = false;
    }

    async blockAbuseIp(ip, timeoutSeconds) {
        const at = this.clock.now();
        // `nft add element` on an element that is already present is not
        // expected to extend its timeout, so the first expiry is kept.
        const repeat = this.isBlocked(ip, at);
        if (!repeat) this.blockedUntil.set(ip, at + timeoutSeconds * 1000);
        this.lastCallWasRepeat = repeat;
        this.calls += 1;
    }

    async blockIp() {
        throw new Error('torrent blocker is not part of this replay');
    }

    isBlocked(ip, at) {
        const until = this.blockedUntil.get(ip);
        if (until === undefined) return false;
        if (until > at) return true;
        this.blockedUntil.delete(ip);
        return false;
    }
}

const silentLogger = (counters) => ({
    log() {},
    warn() {},
    debug() {},
    verbose() {},
    fatal() {},
    error() {
        counters.handlerErrors += 1;
    },
});

/** One detector variant (PR head or patched) with its own state, recorder and stats. */
class VariantEngine {
    constructor({ variant, abuseBlocker, clock, closedLoop, onDecision }) {
        this.variant = variant;
        this.pr = loadPr(variant);
        this.clock = clock;
        this.closedLoop = closedLoop;
        this.onDecision = onDecision;

        this.config = this.pr.NodePluginSchema.parse({
            abuseBlocker: { enabled: true, ...abuseBlocker },
        }).abuseBlocker;
        const lists = this.config.ignoreLists;
        const shared = [...lists.sourceIp, ...lists.destinationIp].filter((ip) => ip.startsWith('ext:'));
        if (shared.length > 0) {
            throw new Error(`Shared lists are not resolved by the harness; inline them: ${shared}`);
        }

        this.pluginState = this.pr.createPluginState();
        this.state = this.pluginState.abuseBlocker;
        this.state.configure({
            config: this.config,
            configFingerprint: `pr46-replay-${variant}`,
            ignoredUsers: lists.userId.map(String),
            ignoredSources: lists.sourceIp,
            ignoredDestinations: lists.destinationIp,
        });
        this.state.setCoverage('full', 0);
        this.recorder = new BlockRecorder(clock);
        this.handler = new this.pr.XrayWebhookHandler(this.pluginState, this.recorder);
        this.stats = new VariantStats({
            name: variant,
            policy: this.state.policy,
            closedLoop,
        });

        // Mirrors the first checks of AbuseBlockerState.analyze(), only to label
        // the report; the PR code still makes every decision.
        const ignoredUsers = new Set(lists.userId.map(String));
        const ignoredSources = new this.pr.IpMatcher(lists.sourceIp);
        const ignoredDestinations = new this.pr.IpMatcher(lists.destinationIp);
        this.isIgnored = (observation) =>
            ignoredUsers.has(observation.userId) ||
            ignoredSources.matches(observation.sourceIp) ||
            (observation.destinationIp !== null && ignoredDestinations.matches(observation.destinationIp));
        this.excludedPorts = new Set(this.config.excludedPorts);
        this.scanPorts = new Set(variant === 'patched' ? this.config.scanPorts : []);
        this.v2 = variant === 'patched' && this.config.ruleSet !== 'legacy';
    }

    observationOf(webhook) {
        if (this.variant === 'head') return this.pr.mapForHandler(webhook);
        return this.pr.mapForHandler(webhook, { domains: this.state.acceptsDomains });
    }

    label(record, observation) {
        const stats = this.stats;
        if (!observation) {
            if (record.network !== 'tcp') stats.observeScoring('filteredNotTcp');
            else if (!record.email || !/^\d+$/.test(record.email)) stats.observeScoring('filteredNoNumericEmail');
            else stats.observeScoring('filteredNoIpTarget');
            return;
        }
        if (this.isIgnored(observation)) {
            stats.observeScoring('ignoredByList');
            return;
        }
        const port = observation.destinationPort;
        const excluded = this.excludedPorts.has(port);
        const inScope = this.scanPorts.size > 0 ? this.scanPorts.has(port) : !excluded;
        if (observation.destinationHost) {
            stats.observeDomain('observed');
            if (this.v2 && inScope && this.config.domains.enabled && !WEB_PORTS.has(port)) {
                stats.observeDomain('reachedDomainRules');
            }
            if (this.v2 && !excluded && this.config.sessionRateBurst.enabled) {
                stats.observeDomain('countedBySessionRate');
            }
        }
        if (excluded && !inScope) stats.observeScoring('excludedPort');
        else if (!inScope) stats.observeScoring('outsideScanPorts');
        else stats.observeScoring('analyzed', port);
    }

    async process(record, sourceIp, webhook, input) {
        if (this.closedLoop && sourceIp && this.recorder.isBlocked(sourceIp, record.timestampMs)) {
            this.stats.observeDroppedWhileBlocked(record, sourceIp);
            return;
        }

        const observation = this.observationOf(webhook);
        this.label(record, observation);
        // The handler returns right after the same mapping when it yields null,
        // so skipping it changes nothing but saves the schema parse.
        if (!observation) return;

        const callsBefore = this.recorder.calls;
        await this.handler.handle(new this.pr.XrayWebhookEvent(webhook, 'abuse'));

        // `reports` is the state's buffer; skip the flush (an array copy) when empty.
        if (this.state.reports.size === 0) return;
        for (const report of this.state.flushReports()) {
            const blocked = report.actionReport.action === 'ip_block';
            const rules = report.detections.map((detection) => detection.rule);
            const decision = {
                variant: this.variant,
                time: report.detectedAt.toISOString(),
                userId: report.userId,
                sourceIp: report.sourceIp,
                destinationIp: report.destinationIp,
                destinationHost: report.destinationHost ?? null,
                destinationPort: report.destinationPort,
                trafficClass: classifyPort(report.destinationPort),
                rule: rules.join('+'),
                rules,
                phases: report.detections.map((detection) => detection.phase ?? 'single'),
                keys: report.detections.map((detection) => detection.key),
                counts: report.detections.map((detection) => detection.count ?? detection.uniqueDestinations),
                score: report.score.after,
                severity: report.severity,
                action: blocked ? 'block' : 'report',
                skipReason: report.actionReport.skipReason ?? null,
                sourceIpUserCount: report.sourceIpUserCount ?? null,
                repeat:
                    blocked && this.recorder.calls > callsBefore ? this.recorder.lastCallWasRepeat : false,
            };
            this.onDecision(decision);
            this.stats.observeDecision(decision, record.timestampMs, input);
        }
    }
}

/**
 * Drives one or more variants over the same records in timestamp order, with
 * one replay clock and one set of input statistics.
 */
class Replay {
    /**
     * @param {object} options
     * @param {Array<'head' | 'patched'>} [options.variants=['patched']]
     * @param {object} [options.abuseBlocker] settings for every variant
     * @param {{ head?: object, patched?: object }} [options.configs] per-variant settings
     * @param {'block' | 'report' | null} [options.patchedMode] forces the patched `mode`
     * @param {boolean} [options.closedLoop=true] drop events from an IP while it is blocked
     * @param {boolean} [options.subSecond=false] keep sub-second log timestamps
     * @param {(decision: object) => void} [options.onDecision]
     * @param {number} [options.nodes=1] nodes merged into this input, for per-node-day rates
     */
    constructor(options = {}) {
        this.options = {
            variants: ['patched'],
            abuseBlocker: {},
            configs: {},
            patchedMode: null,
            closedLoop: true,
            subSecond: false,
            onDecision: () => {},
            nodes: 1,
            scenario: null,
            maxSources: 200_000,
            ...options,
        };
        this.counters = { handlerErrors: 0 };
        this.clock = installFakeClock(0);
        this.finished = false;
        try {
            this.input = new InputStats({ maxSources: this.options.maxSources });
            this.engines = this.options.variants.map((variant) => {
                const engine = new VariantEngine({
                    variant,
                    abuseBlocker: {
                        ...this.options.abuseBlocker,
                        ...this.options.configs[variant],
                        ...(variant === 'patched' && this.options.patchedMode
                            ? { mode: this.options.patchedMode }
                            : {}),
                    },
                    clock: this.clock,
                    closedLoop: this.options.closedLoop,
                    onDecision: this.options.onDecision,
                });
                engine.pr.Logger.overrideLogger(silentLogger(this.counters));
                return engine;
            });
            } catch (error) {
            this.close();
            throw error;
        }
        this.lastTimestampMs = Number.NEGATIVE_INFINITY;
    }

    observeLine(line) {
        this.input.lines.total += 1;
        const record = parseLine(line);
        if (!record && line.trim().length > 0) this.input.lines.unparsed += 1;
        return record;
    }

    /** Feeds one parsed record. Records should arrive in timestamp order. */
    async process(record) {
        if (record.timestampMs < this.lastTimestampMs) this.input.lines.lateReordered += 1;
        this.lastTimestampMs = Math.max(this.lastTimestampMs, record.timestampMs);

        const sourceIp = endpointIp(record.source);
        const destinationIsIp = endpointIp(record.destination) !== null;
        this.input.observeRecord(record, sourceIp, destinationIsIp);
        if (record.status !== 'accepted') return;

        const webhook = toWebhook(record, { subSecond: this.options.subSecond });
        this.clock.set(record.timestampMs);
        for (const engine of this.engines) {
            await engine.process(record, sourceIp, webhook, this.input);
        }
    }

    close() {
        if (this.finished) return;
        this.clock.restore();
        this.finished = true;
    }

    finish({ decisionsPath } = {}) {
        this.close();
        const variants = {};
        for (const engine of this.engines) {
            variants[engine.variant] = {
                ...engine.stats.build(this.input, { nodes: this.options.nodes }),
                harness: { recorderCalls: engine.recorder.calls },
            };
        }
        return {
            scenario: this.options.scenario,
            generatedBy: 'tools/pr46-replay (PR #46 XrayWebhookHandler + AbuseBlockerState)',
            mode: {
                variants: this.options.variants,
                patchedMode: this.options.patchedMode,
                closedLoop: this.options.closedLoop,
                nodes: this.options.nodes,
                timestampResolution: this.options.subSecond
                    ? 'log (sub-second)'
                    : 'whole seconds (as Xray webhook ts)',
            },
            input: this.input.build(),
            variants,
            harness: { handlerErrors: this.counters.handlerErrors },
            decisionsFile: decisionsPath ?? null,
        };
    }
}

/** Binary min-heap on (timestampMs, sequence) for bounded reordering. */
class ReorderBuffer {
    constructor() {
        this.items = [];
    }

    get size() {
        return this.items.length;
    }

    peek() {
        return this.items[0];
    }

    less(a, b) {
        return (
            a.record.timestampMs < b.record.timestampMs ||
            (a.record.timestampMs === b.record.timestampMs && a.sequence < b.sequence)
        );
    }

    push(item) {
        const items = this.items;
        items.push(item);
        let index = items.length - 1;
        while (index > 0) {
            const parent = (index - 1) >> 1;
            if (!this.less(items[index], items[parent])) break;
            [items[index], items[parent]] = [items[parent], items[index]];
            index = parent;
        }
    }

    pop() {
        const items = this.items;
        const top = items[0];
        const last = items.pop();
        if (items.length > 0) {
            items[0] = last;
            let index = 0;
            for (;;) {
                const left = index * 2 + 1;
                const right = left + 1;
                let smallest = index;
                if (left < items.length && this.less(items[left], items[smallest])) smallest = left;
                if (right < items.length && this.less(items[right], items[smallest])) smallest = right;
                if (smallest === index) break;
                [items[index], items[smallest]] = [items[smallest], items[index]];
                index = smallest;
            }
        }
        return top;
    }
}

/** Replays an in-memory array of log lines (sorted by timestamp, stable). */
const replayLines = async (lines, options = {}) => {
    const replay = new Replay(options);
    const records = [];
    for (const line of lines) {
        const record = replay.observeLine(line);
        if (record) records.push(record);
    }
    records.sort((a, b) => a.timestampMs - b.timestampMs);
    try {
        for (const record of records) await replay.process(record);
    } finally {
        replay.close();
    }
    return replay.finish(options);
};

const openLines = (file) => {
    let stream = file === '-' ? process.stdin : fs.createReadStream(file);
    if (file.endsWith('.gz')) stream = stream.pipe(zlib.createGunzip());
    return readline.createInterface({ input: stream, crlfDelay: Number.POSITIVE_INFINITY });
};

/** First parseable timestamp of a file, to order rotated logs (null if none). */
const firstTimestamp = async (file) => {
    if (file === '-') return null;
    const lines = openLines(file);
    let seen = 0;
    try {
        for await (const line of lines) {
            const record = parseLine(line);
            if (record) return record.timestampMs;
            if (++seen > 1000) return null;
        }
        return null;
    } finally {
        lines.close();
    }
};

/** Orders files by their first timestamp; files without one keep their place at the end. */
const sortFilesByTime = async (files) => {
    const stamped = await Promise.all(
        files.map(async (file, index) => ({ file, index, first: await firstTimestamp(file) })),
    );
    return stamped
        .sort((a, b) => (a.first ?? Infinity) - (b.first ?? Infinity) || a.index - b.index)
        .map((entry) => entry.file);
};

/**
 * Streams access.log files (optionally .gz, or '-' for stdin). Files are
 * ordered by their first timestamp unless `sortFiles` is false, and lines are
 * reordered within `reorderWindowMs`.
 */
const replayFiles = async (files, options = {}) => {
    const reorderWindowMs = options.reorderWindowMs ?? 2000;
    const ordered = options.sortFiles === false ? files : await sortFilesByTime(files);
    const replay = new Replay(options);
    const buffer = new ReorderBuffer();
    let sequence = 0;
    let maxSeen = Number.NEGATIVE_INFINITY;

    try {
        for (const file of ordered) {
            for await (const line of openLines(file)) {
                const record = replay.observeLine(line);
                if (!record) continue;
                buffer.push({ record, sequence: sequence++ });
                if (record.timestampMs > maxSeen) maxSeen = record.timestampMs;
                while (buffer.size > 0 && buffer.peek().record.timestampMs <= maxSeen - reorderWindowMs) {
                    await replay.process(buffer.pop().record);
                }
            }
        }
        while (buffer.size > 0) await replay.process(buffer.pop().record);
    } finally {
        replay.close();
    }
    return { report: replay.finish(options), files: ordered };
};

module.exports = { BlockRecorder, Replay, replayFiles, replayLines, sortFilesByTime };

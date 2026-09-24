'use strict';

const fs = require('node:fs');
const readline = require('node:readline');
const zlib = require('node:zlib');

const { installFakeClock } = require('./fake-clock');
const { loadPr } = require('./load-pr');
const { parseLine, toWebhook } = require('./parse-log');
const { ReportBuilder } = require('./report');
const { classifyPort } = require('./traffic-class');

/**
 * Stands in for NftService. The PR's XrayWebhookHandler calls
 * `blockAbuseIp(sourceIp, initialBlockSeconds)`; we record the call instead
 * of adding the IP to the nftables `abuse-blocker` set.
 */
class BlockRecorder {
    constructor(clock) {
        this.clock = clock;
        this.calls = [];
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
        this.calls.push({ ip, at, timeoutSeconds, repeat });
    }

    async blockIp() {
        throw new Error('torrent blocker is not part of this replay');
    }

    isBlocked(ip, at) {
        const until = this.blockedUntil.get(ip);
        return until !== undefined && until > at;
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

class ReplayEngine {
    /**
     * @param {object} options
     * @param {object} [options.abuseBlocker] overrides merged into `{ enabled: true }`
     *   and parsed with the PR's NodePluginSchema (defaults come from the schema).
     * @param {boolean} [options.closedLoop=true] drop later events from a source IP
     *   while the recorder has it blocked, as nftables would.
     * @param {boolean} [options.subSecond=false] keep log sub-second precision instead
     *   of Xray's whole-second webhook `ts`.
     * @param {(decision: object) => void} [options.onDecision]
     * @param {string} [options.scenario]
     */
    constructor(options = {}) {
        this.options = {
            abuseBlocker: {},
            closedLoop: true,
            subSecond: false,
            onDecision: () => {},
            scenario: null,
            ...options,
        };
        this.pr = loadPr();
        this.counters = { handlerErrors: 0 };
        this.pr.Logger.overrideLogger(silentLogger(this.counters));

        const parsed = this.pr.NodePluginSchema.parse({
            abuseBlocker: { enabled: true, ...this.options.abuseBlocker },
        });
        this.config = parsed.abuseBlocker;
        const lists = this.config.ignoreLists;
        const shared = [...lists.sourceIp, ...lists.destinationIp].filter((ip) => ip.startsWith('ext:'));
        if (shared.length > 0) {
            throw new Error(`Shared lists are not resolved by the harness; inline them: ${shared}`);
        }

        // Mirrors the ignore checks at the top of AbuseBlockerState.analyze(),
        // only to label the report; the PR code still makes the decision.
        const ignoredUsers = new Set(lists.userId.map(String));
        const ignoredSources = new this.pr.IpMatcher(lists.sourceIp);
        const ignoredDestinations = new this.pr.IpMatcher(lists.destinationIp);
        this.isIgnored = (observation) =>
            ignoredUsers.has(observation.userId) ||
            ignoredSources.matches(observation.sourceIp) ||
            ignoredDestinations.matches(observation.destinationIp);

        this.pluginState = new this.pr.PluginStateService();
        this.pluginState.abuseBlocker.configure({
            config: this.config,
            configFingerprint: 'pr46-replay',
            ignoredUsers: lists.userId.map(String),
            ignoredSources: lists.sourceIp,
            ignoredDestinations: lists.destinationIp,
        });
        this.pluginState.abuseBlocker.setCoverage('full', 0);

        this.clock = installFakeClock(0);
        this.recorder = new BlockRecorder(this.clock);
        this.handler = new this.pr.XrayWebhookHandler(this.pluginState, this.recorder);
        this.report = new ReportBuilder({
            scenario: this.options.scenario,
            policy: this.pluginState.abuseBlocker.policy,
            closedLoop: this.options.closedLoop,
            subSecond: this.options.subSecond,
        });
        this.lastTimestampMs = Number.NEGATIVE_INFINITY;
        this.finished = false;
    }

    sourceIpOf(record) {
        return this.pr.parseNetworkEndpoint(record.source)?.ip ?? null;
    }

    /** Feeds one parsed log record. Records must arrive in timestamp order. */
    async process(record) {
        if (record.timestampMs < this.lastTimestampMs) this.report.observeLate();
        this.lastTimestampMs = Math.max(this.lastTimestampMs, record.timestampMs);

        const sourceIp = this.sourceIpOf(record);
        this.report.observeRecord(record, sourceIp);
        if (record.status !== 'accepted') return;

        if (
            this.options.closedLoop &&
            sourceIp &&
            this.recorder.isBlocked(sourceIp, record.timestampMs)
        ) {
            this.report.observeDroppedWhileBlocked(record, sourceIp);
            return;
        }

        const webhook = toWebhook(record, { subSecond: this.options.subSecond });
        this.report.observeScoringInput(
            record,
            this.pr.toAbuseBlockerObservation(webhook),
            this.config.excludedPorts,
            this.isIgnored,
        );

        this.clock.set(record.timestampMs);
        const callsBefore = this.recorder.calls.length;
        await this.handler.handle(new this.pr.XrayWebhookEvent(webhook, 'abuse'));

        const reports = this.pluginState.abuseBlocker.flushReports();
        for (const report of reports) {
            const blocked = report.actionReport.action === 'ip_block';
            const decision = {
                time: report.detectedAt.toISOString(),
                userId: report.userId,
                sourceIp: report.sourceIp,
                rule: report.detections.map((detection) => detection.rule).join('+'),
                score: report.score.after,
                action: blocked ? 'block' : 'report',
                severity: report.severity,
                destinationPort: report.destinationPort,
                trafficClass: classifyPort(report.destinationPort),
                keys: report.detections.map((detection) => detection.key),
                repeat: blocked && this.recorder.calls.length > callsBefore
                    ? this.recorder.lastCallWasRepeat
                    : false,
            };
            this.options.onDecision(decision);
            this.report.observeDecision(decision, record.timestampMs);
        }
    }

    close() {
        if (this.finished) return;
        this.clock.restore();
        this.finished = true;
    }

    finish({ decisionsPath } = {}) {
        this.close();
        const built = this.report.build({ decisionsPath });
        built.harness = {
            handlerErrors: this.counters.handlerErrors,
            recorderCalls: this.recorder.calls.length,
        };
        return built;
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
        return a.record.timestampMs < b.record.timestampMs ||
            (a.record.timestampMs === b.record.timestampMs && a.sequence < b.sequence);
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

/**
 * Replays an in-memory array of log lines (sorted by timestamp, stable).
 */
const replayLines = async (lines, options = {}) => {
    const engine = new ReplayEngine(options);
    const parsed = [];
    for (const line of lines) {
        engine.report.observeLine();
        const record = parseLine(line);
        if (record) parsed.push(record);
        else if (line.trim().length > 0) engine.report.observeUnparsed();
    }
    parsed.sort((a, b) => a.timestampMs - b.timestampMs);
    try {
        for (const record of parsed) await engine.process(record);
    } finally {
        engine.close();
    }
    return engine.finish(options);
};

const openLines = (file) => {
    let stream = fs.createReadStream(file);
    if (file.endsWith('.gz')) stream = stream.pipe(zlib.createGunzip());
    return readline.createInterface({ input: stream, crlfDelay: Number.POSITIVE_INFINITY });
};

/**
 * Streams one or more access.log files (optionally .gz) in the given order.
 * Lines are reordered within `reorderWindowMs` so that small out-of-order
 * writes are replayed in timestamp order.
 */
const replayFiles = async (files, options = {}) => {
    const reorderWindowMs = options.reorderWindowMs ?? 2000;
    const engine = new ReplayEngine(options);
    const buffer = new ReorderBuffer();
    let sequence = 0;
    let maxSeen = Number.NEGATIVE_INFINITY;

    try {
        for (const file of files) {
            for await (const line of openLines(file)) {
                engine.report.observeLine();
                const record = parseLine(line);
                if (!record) {
                    if (line.trim().length > 0) engine.report.observeUnparsed();
                    continue;
                }
                buffer.push({ record, sequence: sequence++ });
                maxSeen = Math.max(maxSeen, record.timestampMs);
                while (
                    buffer.size > 0 &&
                    buffer.peek().record.timestampMs <= maxSeen - reorderWindowMs
                ) {
                    await engine.process(buffer.pop().record);
                }
            }
        }
        while (buffer.size > 0) await engine.process(buffer.pop().record);
    } finally {
        engine.close();
    }

    return engine.finish(options);
};

module.exports = { BlockRecorder, ReplayEngine, replayFiles, replayLines };

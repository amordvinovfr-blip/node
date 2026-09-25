'use strict';

// Aggregate statistics for a replay. Everything held in memory is bounded, so
// that a month of one busy node fits in a default V8 heap:
// - distinct source IPs: HyperLogLog (16 KB);
// - users per source IP: LRU of at most `maxSources` addresses x 64 users;
// - active users per hour: one Set for the current hour, counts afterwards;
// - per-variant state grows only with decisions (flagged sources, blocks).
// Reports carry aggregates only: no IPs, user IDs or hostnames.

const { CLASS_NAMES, RECON_PORTS, classifyPort } = require('./traffic-class');

const HOUR_MS = 3_600_000;
const DAY_SECONDS = 86_400;
const USERS_PER_SOURCE_TRACKED = 64;
const USERS_PER_IP_BUCKETS = [
    ['1', 1, 1],
    ['2-5', 2, 5],
    ['6-20', 6, 20],
    ['21-64', 21, 63],
    ['>=64', 64, Number.POSITIVE_INFINITY],
];

const increment = (object, key, by = 1) => {
    object[key] = (object[key] ?? 0) + by;
};

const summarize = (values) => {
    if (values.length === 0) return { count: 0, min: null, median: null, max: null };
    const sorted = [...values].sort((a, b) => a - b);
    return {
        count: sorted.length,
        min: sorted[0],
        median: sorted[Math.floor((sorted.length - 1) / 2)],
        max: sorted.at(-1),
    };
};

const histogram = (values) =>
    Object.fromEntries(
        USERS_PER_IP_BUCKETS.map(([label, from, to]) => [
            label,
            values.filter((value) => value >= from && value <= to).length,
        ]),
    );

const round = (value, digits = 3) =>
    value === null || value === undefined || !Number.isFinite(value)
        ? null
        : Number(value.toFixed(digits));

/** FNV-1a + murmur3 finalizer, 32 bit. */
const hash32 = (value) => {
    let hash = 0x811c9dc5;
    for (let index = 0; index < value.length; index += 1) {
        hash ^= value.charCodeAt(index);
        hash = Math.imul(hash, 0x01000193);
    }
    hash ^= hash >>> 16;
    hash = Math.imul(hash, 0x85ebca6b);
    hash ^= hash >>> 13;
    hash = Math.imul(hash, 0xc2b2ae35);
    hash ^= hash >>> 16;
    return hash >>> 0;
};

/** Distinct-count estimate in 2^precision bytes (about 0.8% error at 14). */
class HyperLogLog {
    constructor(precision = 14) {
        this.precision = precision;
        this.size = 1 << precision;
        this.registers = new Uint8Array(this.size);
    }

    add(value) {
        const hash = hash32(value);
        const index = hash >>> (32 - this.precision);
        const rest = (hash << this.precision) >>> 0;
        const rank = rest === 0 ? 32 - this.precision + 1 : Math.clz32(rest) + 1;
        if (rank > this.registers[index]) this.registers[index] = rank;
    }

    count() {
        let sum = 0;
        let zeros = 0;
        for (const register of this.registers) {
            sum += 2 ** -register;
            if (register === 0) zeros += 1;
        }
        const alpha = 0.7213 / (1 + 1.079 / this.size);
        const estimate = (alpha * this.size * this.size) / sum;
        if (estimate <= 2.5 * this.size && zeros > 0) {
            return Math.round(this.size * Math.log(this.size / zeros));
        }
        return Math.round(estimate);
    }
}

/** LRU of source IP -> (userId -> last seen), for "users on this IP" lookups. */
class SourceUsers {
    constructor(maxSources) {
        this.maxSources = maxSources;
        this.sources = new Map();
        this.evicted = 0;
    }

    observe(sourceIp, userId, timestampMs) {
        let users = this.sources.get(sourceIp);
        if (users) {
            this.sources.delete(sourceIp);
        } else {
            if (this.sources.size >= this.maxSources) {
                this.sources.delete(this.sources.keys().next().value);
                this.evicted += 1;
            }
            users = new Map();
        }
        this.sources.set(sourceIp, users);
        users.delete(userId);
        users.set(userId, timestampMs);
        if (users.size > USERS_PER_SOURCE_TRACKED) users.delete(users.keys().next().value);
    }

    /** Distinct users seen on the IP since `sinceMs` (saturates at 64). */
    count(sourceIp, sinceMs) {
        const users = this.sources.get(sourceIp);
        if (!users) return 0;
        let count = 0;
        for (const lastSeen of users.values()) if (lastSeen >= sinceMs) count += 1;
        return count;
    }
}

/** Input-side statistics, shared by every variant of a replay. */
class InputStats {
    constructor({ maxSources = 200_000 } = {}) {
        this.lines = { total: 0, unparsed: 0, rejected: 0, accepted: 0, lateReordered: 0 };
        this.network = {};
        this.tcpDestinations = { ip: 0, domain: 0 };
        this.firstMs = null;
        this.lastMs = null;
        this.activeUsers = new Set();
        this.userFirstSeen = new Map();
        this.sourceIps = new HyperLogLog();
        this.sourceUsers = new SourceUsers(maxSources);
        this.hours = new Map();
        this.currentHour = null;
        this.currentHourUsers = new Set();
    }

    hourIndex(timestampMs) {
        return Math.floor((timestampMs - this.firstMs) / HOUR_MS);
    }

    observeRecord(record, sourceIp, destinationIsIp) {
        if (this.firstMs === null) this.firstMs = record.timestampMs;
        this.lastMs = Math.max(this.lastMs ?? record.timestampMs, record.timestampMs);

        if (record.status !== 'accepted') {
            this.lines.rejected += 1;
            return;
        }
        this.lines.accepted += 1;
        increment(this.network, record.network);
        if (record.network === 'tcp') {
            if (destinationIsIp) this.tcpDestinations.ip += 1;
            else this.tcpDestinations.domain += 1;
        }
        if (sourceIp) this.sourceIps.add(sourceIp);
        if (!record.email) return;

        this.activeUsers.add(record.email);
        if (!this.userFirstSeen.has(record.email)) this.userFirstSeen.set(record.email, record.timestampMs);
        if (sourceIp) this.sourceUsers.observe(sourceIp, record.email, record.timestampMs);

        const hour = this.hourIndex(record.timestampMs);
        if (hour !== this.currentHour) {
            if (hour < this.currentHour) return;
            this.closeHour();
            this.currentHour = hour;
        }
        this.currentHourUsers.add(record.email);
    }

    closeHour() {
        if (this.currentHour === null) return;
        this.hours.set(this.currentHour, this.currentHourUsers.size);
        this.currentHourUsers = new Set();
    }

    usersOnSource(sourceIp, timestampMs) {
        return this.sourceUsers.count(sourceIp, timestampMs - HOUR_MS);
    }

    get durationSeconds() {
        return this.firstMs === null ? 0 : Math.max(0, (this.lastMs - this.firstMs) / 1000);
    }

    build() {
        this.closeHour();
        const tcp = this.tcpDestinations.ip + this.tcpDestinations.domain;
        return {
            ...this.lines,
            network: this.network,
            tcpDestinations: {
                ...this.tcpDestinations,
                domainShare: tcp === 0 ? null : round(this.tcpDestinations.domain / tcp),
            },
            firstEvent: this.firstMs === null ? null : new Date(this.firstMs).toISOString(),
            lastEvent: this.lastMs === null ? null : new Date(this.lastMs).toISOString(),
            durationSeconds: round(this.durationSeconds),
            activeUsers: this.activeUsers.size,
            activeSourceIpsEstimate: this.sourceIps.count(),
            sourceTrackerEvictions: this.sourceUsers.evicted,
        };
    }
}

const createRuleStats = () => ({
    decisions: 0,
    blocks: 0,
    bySeverity: {},
    byPhase: {},
    byTrafficClass: {},
    byPort: {},
    firstDecisionMs: null,
});

/** Decision-side statistics of one variant (PR head or patched). */
class VariantStats {
    constructor({ name, policy, closedLoop }) {
        this.name = name;
        this.policy = policy;
        this.closedLoop = closedLoop;
        this.scoring = {
            filteredNotTcp: 0,
            filteredNoNumericEmail: 0,
            filteredNoIpTarget: 0,
            ignoredByList: 0,
            excludedPort: 0,
            outsideScanPorts: 0,
            analyzed: 0,
            droppedWhileSourceBlocked: 0,
        };
        this.domainDestinations = { observed: 0, reachedDomainRules: 0, countedBySessionRate: 0 };
        this.analyzedByClass = {};
        this.decisions = { total: 0, bySeverity: {}, byAction: {}, bySkipReason: {}, maxScore: null };
        this.rules = new Map();
        this.firstDecisionMs = null;
        this.flaggedSources = new Map();
        this.blocks = [];
        this.repeatBlocks = 0;
        this.blockHours = new Map();
        this.activeBlockByIp = new Map();
        this.droppedUsers = new Set();
    }

    observeScoring(kind, port) {
        this.scoring[kind] += 1;
        if (kind === 'analyzed') increment(this.analyzedByClass, classifyPort(port));
    }

    observeDomain(kind) {
        this.domainDestinations[kind] += 1;
    }

    observeDroppedWhileBlocked(record, sourceIp) {
        this.scoring.droppedWhileSourceBlocked += 1;
        const block = this.activeBlockByIp.get(sourceIp);
        if (!block) return;
        block.droppedSessions += 1;
        if (record.email) {
            block.droppedUsers.add(record.email);
            this.droppedUsers.add(record.email);
        }
    }

    observeDecision(decision, timestampMs, input) {
        const decisions = this.decisions;
        decisions.total += 1;
        increment(decisions.bySeverity, decision.severity);
        increment(decisions.byAction, decision.action);
        if (decision.skipReason) increment(decisions.bySkipReason, decision.skipReason);
        decisions.maxScore = Math.max(decisions.maxScore ?? 0, decision.score);
        this.firstDecisionMs ??= timestampMs;

        const trafficClass = classifyPort(decision.destinationPort);
        const isBlock = decision.action === 'block' && !decision.repeat;
        for (const [index, rule] of decision.rules.entries()) {
            if (!this.rules.has(rule)) this.rules.set(rule, createRuleStats());
            const stats = this.rules.get(rule);
            stats.decisions += 1;
            if (isBlock) stats.blocks += 1;
            increment(stats.bySeverity, decision.severity);
            increment(stats.byPhase, decision.phases[index] ?? 'single');
            increment(stats.byTrafficClass, trafficClass);
            increment(stats.byPort, String(decision.destinationPort));
            stats.firstDecisionMs ??= timestampMs;
        }

        const usersLastHour = input.usersOnSource(decision.sourceIp, timestampMs);
        if (!this.flaggedSources.has(decision.sourceIp)) {
            this.flaggedSources.set(decision.sourceIp, usersLastHour);
        }
        if (decision.action !== 'block') return;
        if (decision.repeat) {
            this.repeatBlocks += 1;
            return;
        }

        const block = {
            at: timestampMs,
            sourceIp: decision.sourceIp,
            userId: decision.userId,
            rules: decision.rules,
            destinationPort: decision.destinationPort,
            trafficClass,
            usersOnSourceIpLastHour: usersLastHour,
            droppedSessions: 0,
            droppedUsers: new Set(),
        };
        this.blocks.push(block);
        this.activeBlockByIp.set(decision.sourceIp, block);
        increment(this.blockHours, input.hourIndex(timestampMs));
    }

    build(input, { nodes = 1 } = {}) {
        const durationSeconds = input.durationSeconds;
        const nodeDays = (nodes * durationSeconds) / DAY_SECONDS;
        const hoursForRate = Math.max(1, durationSeconds / 3600);
        const activeUsers = input.activeUsers.size;
        const blocks = this.blocks;

        const byTrafficClass = Object.fromEntries(CLASS_NAMES.map((name) => [name, 0]));
        const byPort = {};
        const byRule = {};
        for (const block of blocks) {
            increment(byTrafficClass, block.trafficClass);
            increment(byPort, String(block.destinationPort));
            for (const rule of block.rules) increment(byRule, rule);
        }
        const onReconPorts = blocks.filter((block) => RECON_PORTS.has(block.destinationPort)).length;

        const firstBlockPerUser = new Map();
        for (const block of blocks) {
            if (!firstBlockPerUser.has(block.userId)) firstBlockPerUser.set(block.userId, block.at);
        }
        const bystanders = new Set();
        for (const block of blocks) {
            for (const user of block.droppedUsers) if (user !== block.userId) bystanders.add(user);
        }
        const usersLastHour = blocks.map((block) => block.usersOnSourceIpLastHour);
        const usersDuringBlock = blocks.map(
            (block) => new Set([block.userId, ...block.droppedUsers]).size,
        );
        const flagged = [...this.flaggedSources.values()];
        const secondsFromStart = (ms) => (ms === null ? null : round((ms - input.firstMs) / 1000));

        return {
            policy: this.policy,
            scoringInput: { ...this.scoring, analyzedByTrafficClass: this.analyzedByClass },
            domainDestinations: { seen: input.tcpDestinations.domain, ...this.domainDestinations },
            decisions: this.decisions,
            rules: Object.fromEntries(
                [...this.rules].map(([rule, stats]) => [
                    rule,
                    {
                        decisions: stats.decisions,
                        blocks: stats.blocks,
                        bySeverity: stats.bySeverity,
                        byPhase: stats.byPhase,
                        byTrafficClass: stats.byTrafficClass,
                        byPort: stats.byPort,
                        timeToFirstDecisionSeconds: secondsFromStart(stats.firstDecisionMs),
                    },
                ]),
            ),
            blocks: {
                total: blocks.length,
                repeatWhileActive: this.repeatBlocks,
                perNodeDay: nodeDays > 0 ? round(blocks.length / nodeDays, 4) : null,
                nodeDays: round(nodeDays, 4),
                perHourPer1000ActiveUsers:
                    activeUsers === 0 ? null : round((blocks.length / hoursForRate / activeUsers) * 1000),
                onReconPortsShare: blocks.length === 0 ? null : round(onReconPorts / blocks.length),
                distinctSourceIps: new Set(blocks.map((block) => block.sourceIp)).size,
                distinctUserIds: firstBlockPerUser.size,
                byTrafficClass,
                byPort,
                byRule,
                byHour: Object.fromEntries([...this.blockHours].sort(([a], [b]) => a - b)),
            },
            usersPerFlaggedSourceIp: { ...summarize(flagged), histogram: histogram(flagged) },
            usersPerBlockedSourceIp: {
                lastHourBeforeBlock: { ...summarize(usersLastHour), histogram: histogram(usersLastHour) },
                duringBlock: { ...summarize(usersDuringBlock), histogram: histogram(usersDuringBlock) },
                note: 'distinct userIds on the source IP; a chained entry node shows 1 however many people it carries; counts saturate at 64',
            },
            collateral: this.closedLoop
                ? {
                      sessionsDroppedWhileBlocked: this.scoring.droppedWhileSourceBlocked,
                      distinctUsersDropped: this.droppedUsers.size,
                      distinctBystandersDropped: bystanders.size,
                  }
                : null,
            timeToFirstDecision: { secondsFromLogStart: secondsFromStart(this.firstDecisionMs) },
            timeToFirstBlock: {
                secondsFromLogStart: secondsFromStart(blocks[0]?.at ?? null),
                secondsFromBlockedUserFirstSeen: summarize(
                    [...firstBlockPerUser].map(
                        ([userId, at]) => (at - input.userFirstSeen.get(userId)) / 1000,
                    ),
                ),
            },
        };
    }
}

module.exports = { HyperLogLog, InputStats, SourceUsers, VariantStats };

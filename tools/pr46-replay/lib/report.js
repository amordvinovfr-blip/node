'use strict';

const { CLASS_NAMES, classifyPort } = require('./traffic-class');

const HOUR_MS = 3_600_000;
const USERS_PER_IP_BUCKETS = [
    ['1', 1, 1],
    ['2-5', 2, 5],
    ['6-20', 6, 20],
    ['21-100', 21, 100],
    ['101-1000', 101, 1000],
    ['>1000', 1001, Number.POSITIVE_INFINITY],
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
    value === null || !Number.isFinite(value) ? null : Number(value.toFixed(digits));

/**
 * Collects aggregate statistics during a replay. Holds user IDs and IPs in
 * memory to compute distinct counts, but `build()` only emits aggregates.
 */
class ReportBuilder {
    constructor({ scenario, policy, closedLoop, subSecond }) {
        this.scenario = scenario;
        this.policy = policy;
        this.closedLoop = closedLoop;
        this.subSecond = subSecond;

        this.lines = { total: 0, unparsed: 0, rejected: 0, accepted: 0, lateReordered: 0 };
        this.network = {};
        this.scoring = {
            filteredNotTcp: 0,
            filteredNoNumericEmail: 0,
            filteredNoIpDestination: 0,
            ignoredByList: 0,
            excludedPort: 0,
            analyzed: 0,
            droppedWhileSourceBlocked: 0,
        };
        this.analyzedByClass = {};
        this.firstMs = null;
        this.lastMs = null;

        this.activeUsers = new Set();
        this.activeSourceIps = new Set();
        this.userFirstSeen = new Map();
        this.ipUsers = new Map();
        this.hours = new Map();

        this.decisionsBySeverity = {};
        this.decisionsByAction = {};
        this.maxScore = null;
        this.blocks = [];
        this.activeBlockByIp = new Map();
        this.droppedUsers = new Set();
    }

    hour(timestampMs) {
        const index = Math.floor((timestampMs - this.firstMs) / HOUR_MS);
        let bucket = this.hours.get(index);
        if (!bucket) {
            bucket = { users: new Set(), blocks: 0 };
            this.hours.set(index, bucket);
        }
        return bucket;
    }

    observeLine() {
        this.lines.total += 1;
    }

    observeUnparsed() {
        this.lines.unparsed += 1;
    }

    observeLate() {
        this.lines.lateReordered += 1;
    }

    /** Every parsed line, before the blocker sees it. */
    observeRecord(record, sourceIp) {
        if (this.firstMs === null) this.firstMs = record.timestampMs;
        this.lastMs = Math.max(this.lastMs ?? record.timestampMs, record.timestampMs);

        if (record.status !== 'accepted') {
            this.lines.rejected += 1;
            return;
        }
        this.lines.accepted += 1;
        increment(this.network, record.network);

        if (sourceIp) this.activeSourceIps.add(sourceIp);
        if (!record.email) return;

        this.activeUsers.add(record.email);
        this.hour(record.timestampMs).users.add(record.email);
        if (!this.userFirstSeen.has(record.email)) {
            this.userFirstSeen.set(record.email, record.timestampMs);
        }
        if (sourceIp) {
            let users = this.ipUsers.get(sourceIp);
            if (!users) {
                users = new Map();
                this.ipUsers.set(sourceIp, users);
            }
            users.set(record.email, record.timestampMs);
        }
    }

    /** Why the PR's toAbuseBlockerObservation dropped (or kept) the event. */
    observeScoringInput(record, observation, excludedPorts, isIgnored) {
        if (!observation) {
            if (record.network !== 'tcp') this.scoring.filteredNotTcp += 1;
            else if (!record.email || !/^\d+$/.test(record.email))
                this.scoring.filteredNoNumericEmail += 1;
            else this.scoring.filteredNoIpDestination += 1;
            return;
        }
        if (isIgnored(observation)) {
            this.scoring.ignoredByList += 1;
            return;
        }
        if (excludedPorts.includes(observation.destinationPort)) {
            this.scoring.excludedPort += 1;
            return;
        }
        this.scoring.analyzed += 1;
        increment(this.analyzedByClass, classifyPort(observation.destinationPort));
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

    observeDecision(decision, timestampMs) {
        increment(this.decisionsBySeverity, decision.severity);
        increment(this.decisionsByAction, decision.action);
        this.maxScore = Math.max(this.maxScore ?? 0, decision.score);
        if (decision.action !== 'block') return;

        const lastHourCutoff = timestampMs - HOUR_MS;
        const users = this.ipUsers.get(decision.sourceIp) ?? new Map();
        let usersLastHour = 0;
        for (const lastSeen of users.values()) {
            if (lastSeen >= lastHourCutoff) usersLastHour += 1;
        }

        const block = {
            at: timestampMs,
            sourceIp: decision.sourceIp,
            userId: decision.userId,
            rule: decision.rule,
            score: decision.score,
            destinationPort: decision.destinationPort,
            trafficClass: classifyPort(decision.destinationPort),
            repeat: decision.repeat,
            usersOnSourceIpLastHour: usersLastHour,
            droppedSessions: 0,
            droppedUsers: new Set(),
        };
        this.blocks.push(block);
        if (!decision.repeat) {
            this.activeBlockByIp.set(decision.sourceIp, block);
            this.hour(timestampMs).blocks += 1;
        }
    }

    build({ decisionsPath }) {
        const durationSeconds =
            this.firstMs === null ? 0 : Math.max(0, (this.lastMs - this.firstMs) / 1000);
        const initialBlocks = this.blocks.filter((block) => !block.repeat);
        const activeUsers = this.activeUsers.size;
        const hoursForRate = Math.max(1, durationSeconds / 3600);

        const byTrafficClass = Object.fromEntries(CLASS_NAMES.map((name) => [name, 0]));
        const byDestinationPort = {};
        const byRule = {};
        for (const block of initialBlocks) {
            increment(byTrafficClass, block.trafficClass);
            increment(byDestinationPort, String(block.destinationPort));
            increment(byRule, block.rule);
        }

        const blockedIps = [...new Set(initialBlocks.map((block) => block.sourceIp))];
        const usersWholeLog = blockedIps.map((ip) => this.ipUsers.get(ip)?.size ?? 0);
        const usersLastHour = initialBlocks.map((block) => block.usersOnSourceIpLastHour);
        const firstBlock = initialBlocks[0] ?? null;

        const firstBlockPerUser = new Map();
        for (const block of initialBlocks) {
            if (!firstBlockPerUser.has(block.userId)) firstBlockPerUser.set(block.userId, block.at);
        }
        const secondsFromUserFirstSeen = [...firstBlockPerUser].map(
            ([userId, at]) => (at - this.userFirstSeen.get(userId)) / 1000,
        );

        const bystanders = new Set();
        for (const block of initialBlocks) {
            for (const user of block.droppedUsers) {
                if (user !== block.userId) bystanders.add(user);
            }
        }

        return {
            scenario: this.scenario,
            generatedBy: 'tools/pr46-replay (PR #46 XrayWebhookHandler + AbuseBlockerState)',
            mode: {
                closedLoop: this.closedLoop,
                timestampResolution: this.subSecond ? 'log (sub-second)' : 'whole seconds (as Xray webhook ts)',
            },
            policy: this.policy,
            input: {
                ...this.lines,
                network: this.network,
                firstEvent: this.firstMs === null ? null : new Date(this.firstMs).toISOString(),
                lastEvent: this.lastMs === null ? null : new Date(this.lastMs).toISOString(),
                durationSeconds: round(durationSeconds),
            },
            scoringInput: { ...this.scoring, analyzedByTrafficClass: this.analyzedByClass },
            activeUsers,
            activeSourceIps: this.activeSourceIps.size,
            decisions: {
                total: Object.values(this.decisionsBySeverity).reduce((sum, value) => sum + value, 0),
                bySeverity: this.decisionsBySeverity,
                byAction: this.decisionsByAction,
                maxScore: this.maxScore,
            },
            blocks: {
                total: initialBlocks.length,
                repeatWhileActive: this.blocks.length - initialBlocks.length,
                distinctSourceIps: blockedIps.length,
                distinctUserIds: new Set(initialBlocks.map((block) => block.userId)).size,
                perHourPer1000ActiveUsers:
                    activeUsers === 0
                        ? null
                        : round((initialBlocks.length / hoursForRate / activeUsers) * 1000),
                rateDefinition:
                    'blocks / max(1, log hours) / distinct active userIds * 1000; blocks exclude re-blocks of an IP that is still blocked',
                hourly: [...this.hours]
                    .sort(([a], [b]) => a - b)
                    .map(([hour, bucket]) => ({
                        hour,
                        activeUsers: bucket.users.size,
                        blocks: bucket.blocks,
                        blocksPer1000ActiveUsers:
                            bucket.users.size === 0
                                ? null
                                : round((bucket.blocks / bucket.users.size) * 1000),
                    })),
                byTrafficClass,
                byDestinationPort,
                byRule,
            },
            usersPerBlockedSourceIp: {
                lastHourBeforeBlock: { ...summarize(usersLastHour), histogram: histogram(usersLastHour) },
                wholeLog: { ...summarize(usersWholeLog), histogram: histogram(usersWholeLog) },
                note: 'distinct userIds seen on the blocked source IP; a chained entry node shows 1 here however many people it carries',
            },
            collateral: this.closedLoop
                ? {
                      sessionsDroppedWhileBlocked: this.scoring.droppedWhileSourceBlocked,
                      distinctUsersDropped: this.droppedUsers.size,
                      distinctBystandersDropped: bystanders.size,
                  }
                : null,
            timeToFirstBlock: {
                secondsFromLogStart: firstBlock ? round((firstBlock.at - this.firstMs) / 1000) : null,
                secondsFromBlockedUserFirstSeen: summarize(secondsFromUserFirstSeen),
            },
            decisionsFile: decisionsPath ?? null,
        };
    }
}

module.exports = { ReportBuilder };

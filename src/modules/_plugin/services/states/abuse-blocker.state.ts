import type { TNodePlugin } from '@remnawave/node-plugins';

import type {
    AbuseBlockerCoverageMode,
    AbuseBlockerDetectionPhase,
    AbuseBlockerPolicy,
    AbuseBlockerReportModel,
    AbuseBlockerRuleName,
    AbuseBlockerSeverity,
    AbuseBlockerSkipReason,
    XrayWebhookModel,
} from '@libs/contracts/models';

import { getRegistrableDomain, hashHostname } from '../../utils/domain.utils';
import { getNetworkKey, IpMatcher } from '../../utils/ip-address.utils';

type AbuseBlockerConfig = NonNullable<TNodePlugin['abuseBlocker']>;
type AbuseBlockerDetectionUnit = IAbuseBlockerDetection['unit'];

const NON_PUBLIC_SOURCES = [
    '0.0.0.0/8',
    '10.0.0.0/8',
    '100.64.0.0/10',
    '127.0.0.0/8',
    '169.254.0.0/16',
    '172.16.0.0/12',
    '192.168.0.0/16',
    '::1/128',
    'fc00::/7',
    'fe80::/10',
];
const MAX_USERS_PER_SOURCE_TRACKED = 16;
const SOURCE_LRU_REFRESH_MS = 60_000;
const HAMMER_BUCKETS = 15;
const BURST_BUCKETS = 12;
const WEB_PORTS = new Set([80, 443]);

/** Two-pass confirmation state of one v2 key (see evaluateIncident). */
interface IIncidentState {
    candidateAt: number | null;
    lastCandidateAt: number;
    lastFiredAt: number;
}

/** Distinct members (networks, domain or hostname hashes) with last-seen time, oldest first. */
interface IMemberSetState extends IIncidentState {
    members: Map<string | number, number>;
}

/** Rolling counter: `buckets` slots ending at absolute slot `head`. */
interface IRingCounterState extends IIncidentState {
    buckets: Uint16Array;
    head: number;
    total: number;
}

interface IDetectorKeyState {
    destinations: Map<string, number>;
    fired: boolean;
    lastFiredAt: number;
    lastSeenAt: number;
}

interface IUserState {
    horizontal: Map<string, IDetectorKeyState>;
    sweep: Map<string, IDetectorKeyState>;
    scoreEvents: Array<{ score: number; timestamp: number }>;
    lastSeenAt: number;
    networks: Map<number, IMemberSetState>;
    targets: Map<string, IRingCounterState>;
    domainSweep: Map<number, IMemberSetState>;
    subdomains: Map<number, IMemberSetState>;
    burst: IRingCounterState | null;
}

export interface IAbuseBlockerObservation {
    userId: string;
    sourceIp: string;
    /** Null when the client asked for a hostname (see destinationHost). */
    destinationIp: string | null;
    /** Normalized ASCII hostname, only when no IP is known. */
    destinationHost?: string | null;
    destinationPort: number;
    inboundTag?: string | null;
    timestamp: number;
    xrayReport: XrayWebhookModel;
}

export interface IAbuseBlockerDetection {
    rule: AbuseBlockerRuleName;
    key: string;
    uniqueDestinations: number;
    windowSeconds: number;
    score: number;
    subnet: string | null;
    phase: AbuseBlockerDetectionPhase;
    count: number;
    unit: 'destinations' | 'networks' | 'sessions' | 'domains' | 'hostnames';
}

export interface IAbuseBlockerAnalysis {
    detections: IAbuseBlockerDetection[];
    scoreBefore: number;
    scoreDelta: number;
    scoreAfter: number;
    severity: AbuseBlockerSeverity;
    evidence: Array<{ destinationIp: string; destinationPort: number; lastSeenAt: Date }>;
    shouldBlock: boolean;
    skipReason: AbuseBlockerSkipReason | null;
    sourceIpUserCount: number;
}

const createIncident = (): IIncidentState => ({
    candidateAt: null,
    lastCandidateAt: Number.NEGATIVE_INFINITY,
    lastFiredAt: Number.NEGATIVE_INFINITY,
});

const createMemberSet = (): IMemberSetState => ({ ...createIncident(), members: new Map() });

const createRing = (slots: number, head: number): IRingCounterState => ({
    ...createIncident(),
    buckets: new Uint16Array(slots),
    head,
    total: 0,
});

/** Adds `member` at `now`, drops members older than the window, returns the distinct count. */
const touchMember = (
    state: IMemberSetState,
    member: string | number,
    now: number,
    windowMs: number,
    cap: number,
): number => {
    const cutoff = now - windowMs;
    for (const [key, seenAt] of state.members) {
        if (seenAt >= cutoff) break;
        state.members.delete(key);
    }
    state.members.delete(member);
    state.members.set(member, now);
    if (state.members.size > cap) state.members.delete(state.members.keys().next().value!);
    return state.members.size;
};

/** Counts one session at `now` and returns the total over the ring. */
const addToRing = (ring: IRingCounterState, now: number, slotMs: number): number => {
    const slots = ring.buckets.length;
    const slot = Math.floor(now / slotMs);
    if (slot > ring.head) {
        const clear = Math.min(slot - ring.head, slots);
        for (let step = 1; step <= clear; step += 1) {
            const index = (ring.head + step) % slots;
            ring.total -= ring.buckets[index];
            ring.buckets[index] = 0;
        }
        ring.head = slot;
    } else if (ring.head - slot >= slots) {
        return ring.total;
    }
    const index = slot % slots;
    if (ring.buckets[index] < 0xffff) {
        ring.buckets[index] += 1;
        ring.total += 1;
    }
    return ring.total;
};

/** Map used as an LRU with at most `cap` entries. */
const getOrCreate = <K, V>(map: Map<K, V>, key: K, cap: number, create: () => V): V => {
    const existing = map.get(key);
    if (existing !== undefined) {
        map.delete(key);
        map.set(key, existing);
        return existing;
    }
    if (map.size >= cap) map.delete(map.keys().next().value!);
    const created = create();
    map.set(key, created);
    return created;
};

export class AbuseBlockerState {
    private enabled = false;
    private config: AbuseBlockerConfig | null = null;
    private configFingerprint = '';
    private ignoredUsers = new Set<string>();
    private ignoredSources = new IpMatcher([]);
    private ignoredDestinations = new IpMatcher([]);
    private excludedPorts = new Set<number>();
    private scanPorts = new Set<number>();
    private reportOnlyUsers = new Set<string>();
    private reportOnlyInbounds = new Set<string>();
    private readonly nonPublicSources = new IpMatcher(NON_PUBLIC_SOURCES);
    private sources = new Map<string, { users: Map<string, number>; touchedAt: number }>();
    private users = new Map<string, IUserState>();
    private reports = new Map<string, AbuseBlockerReportModel>();
    private coverageMode: AbuseBlockerCoverageMode = 'partial';
    private skippedWebhookRules = 0;
    private evictedUsers = 0;
    private evictedKeys = 0;
    private droppedReports = 0;
    private lastError: string | null = null;

    get isEnabled(): boolean {
        return this.enabled;
    }

    get policy(): AbuseBlockerPolicy | null {
        if (!this.config) return null;
        const config = this.config;
        return {
            excludedPorts: config.excludedPorts,
            scoreWindowSeconds: config.scoreWindowSeconds,
            incidentCooldownSeconds: config.incidentCooldownSeconds,
            suspiciousScore: config.suspiciousScore,
            alertScore: config.alertScore,
            blockScore: config.blockScore,
            initialBlockSeconds: config.initialBlockSeconds,
            repeatBlockSeconds: config.repeatBlockSeconds,
            repeatWindowSeconds: config.repeatWindowSeconds,
            evidenceLimit: config.evidenceLimit,
            enhancedEvidenceLimit: config.enhancedEvidenceLimit,
            maxTrackedUsers: config.maxTrackedUsers,
            maxKeysPerUser: config.maxKeysPerUser,
            reportBufferSize: config.reportBufferSize,
            horizontalScan: config.horizontalScan,
            destinationSweep: config.destinationSweep,
            mode: config.mode,
            ruleSet: config.ruleSet,
            scanPorts: config.scanPorts,
            confirmationSeconds: config.confirmationSeconds,
            rearmAfterCooldown: config.rearmAfterCooldown,
            horizontalSweep: config.horizontalSweep,
            hammerTarget: config.hammerTarget,
            sessionRateBurst: config.sessionRateBurst,
            domains: config.domains,
            sourceGuards: config.sourceGuards,
        };
    }

    /** Whether hostname destinations should be mapped to observations (v2 rules). */
    get acceptsDomains(): boolean {
        return this.enabled && !!this.config && this.config.ruleSet !== 'legacy';
    }

    get fingerprint(): string {
        return this.configFingerprint;
    }

    get scoreWindowSeconds(): number {
        return this.config?.scoreWindowSeconds ?? 0;
    }

    configure(args: {
        config: AbuseBlockerConfig;
        configFingerprint: string;
        ignoredUsers: string[];
        ignoredSources: string[];
        ignoredDestinations: string[];
    }): void {
        this.enabled = true;
        this.config = args.config;
        this.configFingerprint = args.configFingerprint;
        this.ignoredUsers = new Set(args.ignoredUsers);
        this.ignoredSources = new IpMatcher(args.ignoredSources);
        this.ignoredDestinations = new IpMatcher(args.ignoredDestinations);
        this.excludedPorts = new Set(args.config.excludedPorts);
        this.scanPorts = new Set(args.config.scanPorts);
        this.reportOnlyUsers = new Set(args.config.sourceGuards.reportOnlyUserIds.map(String));
        this.reportOnlyInbounds = new Set(args.config.sourceGuards.reportOnlyInboundTags);
    }

    analyze(observation: IAbuseBlockerObservation): IAbuseBlockerAnalysis | null {
        const config = this.config;
        if (!this.enabled || !config) return null;
        if (this.ignoredUsers.has(observation.userId)) return null;
        if (this.ignoredSources.matches(observation.sourceIp)) return null;
        const destinationIp = observation.destinationIp;
        if (destinationIp !== null && this.ignoredDestinations.matches(destinationIp)) return null;
        this.trackSourceUser(observation);

        // With a scanPorts allowlist, only those ports feed port-geometry rules (the
        // allowlist wins over excludedPorts); other non-excluded ports feed only the
        // report-only session counter.
        const excluded = this.excludedPorts.has(observation.destinationPort);
        const inScope =
            this.scanPorts.size > 0 ? this.scanPorts.has(observation.destinationPort) : !excluded;
        if (excluded && !inScope) return null;

        const user = this.getUserState(observation.userId, observation.timestamp);
        this.pruneScore(user, observation.timestamp, config.scoreWindowSeconds);
        const scoreBefore = user.scoreEvents.reduce((sum, event) => sum + event.score, 0);
        const detections: IAbuseBlockerDetection[] = [];
        const blockEligible: boolean[] = [];
        const legacy = config.ruleSet !== 'v2' && inScope && destinationIp !== null;

        if (legacy && config.horizontalScan.enabled) {
            const subnet = getNetworkKey(
                destinationIp,
                config.horizontalScan.ipv4Prefix,
                config.horizontalScan.ipv6Prefix,
            );
            if (subnet) {
                const key = `${observation.destinationPort}|${subnet}`;
                const state = this.getDetectorState(
                    user.horizontal,
                    key,
                    user,
                    observation.timestamp,
                );
                if (
                    this.recordDestination(
                        state,
                        destinationIp,
                        observation.timestamp,
                        config.horizontalScan.windowSeconds,
                        config.horizontalScan.uniqueDestinations,
                        config.incidentCooldownSeconds,
                    )
                ) {
                    detections.push({
                        rule: 'horizontal_scan',
                        key,
                        uniqueDestinations: state.destinations.size,
                        windowSeconds: config.horizontalScan.windowSeconds,
                        score: config.horizontalScan.score,
                        subnet,
                        phase: 'single',
                        count: state.destinations.size,
                        unit: 'destinations',
                    });
                    blockEligible.push(true);
                }
            }
        }

        if (legacy && config.destinationSweep.enabled) {
            const key = String(observation.destinationPort);
            const state = this.getDetectorState(user.sweep, key, user, observation.timestamp);
            if (
                this.recordDestination(
                    state,
                    destinationIp,
                    observation.timestamp,
                    config.destinationSweep.windowSeconds,
                    config.destinationSweep.uniqueDestinations,
                    config.incidentCooldownSeconds,
                )
            ) {
                detections.push({
                    rule: 'destination_sweep',
                    key,
                    uniqueDestinations: state.destinations.size,
                    windowSeconds: config.destinationSweep.windowSeconds,
                    score: config.destinationSweep.score,
                    subnet: null,
                    phase: 'single',
                    count: state.destinations.size,
                    unit: 'destinations',
                });
                blockEligible.push(true);
            }
        }

        if (config.ruleSet !== 'legacy') {
            this.detectV2(user, observation, { excluded, inScope }, detections, blockEligible);
        }

        if (detections.length === 0) {
            this.updateBufferedEvidence(observation.userId, user, observation.destinationPort);
            return null;
        }

        const scoreDelta = detections.reduce((sum, detection) => sum + detection.score, 0);
        user.scoreEvents.push({ score: scoreDelta, timestamp: observation.timestamp });
        const scoreAfter = scoreBefore + scoreDelta;
        if (scoreAfter < config.suspiciousScore) return null;

        // Only a confirmed, block-eligible detection can make a decision a block
        // (legacy detections count as confirmed when confirmation is off).
        const confirmed = detections.some(
            (detection, index) =>
                blockEligible[index] &&
                (detection.phase === 'confirmed' ||
                    (detection.phase === 'single' && config.confirmationSeconds === 0)),
        );
        const wouldBlock = confirmed && scoreAfter >= config.blockScore;
        const severity: AbuseBlockerSeverity = wouldBlock
            ? 'blocked'
            : scoreAfter >= config.alertScore
              ? 'alert'
              : 'suspicious';
        const evidenceLimit =
            scoreAfter >= config.alertScore ? config.enhancedEvidenceLimit : config.evidenceLimit;
        const sourceIpUserCount = this.countSourceUsers(
            observation.sourceIp,
            observation.timestamp,
        );
        const skipReason = wouldBlock ? this.blockSkipReason(observation, sourceIpUserCount) : null;

        return {
            detections,
            scoreBefore,
            scoreDelta,
            scoreAfter,
            severity,
            evidence: this.collectEvidence(user, observation.destinationPort, evidenceLimit),
            shouldBlock: wouldBlock && skipReason === null,
            skipReason,
            sourceIpUserCount,
        };
    }

    addReport(report: AbuseBlockerReportModel): void {
        const limit = this.config?.reportBufferSize ?? 1;
        if (!this.reports.has(report.eventId) && this.reports.size >= limit) {
            const oldest = this.reports.keys().next().value as string | undefined;
            if (oldest) this.reports.delete(oldest);
            this.droppedReports += 1;
        }
        this.reports.set(report.eventId, report);
    }

    flushReports(): AbuseBlockerReportModel[] {
        const reports = [...this.reports.values()];
        this.reports.clear();
        return reports;
    }

    setCoverage(mode: AbuseBlockerCoverageMode, skippedWebhookRules: number): void {
        this.coverageMode = mode;
        this.skippedWebhookRules = skippedWebhookRules;
    }

    setLastError(error: unknown): void {
        this.lastError = error instanceof Error ? error.message : String(error);
    }

    get stats() {
        return {
            enabled: this.enabled,
            reportsCount: this.reports.size,
            trackedUsers: this.users.size,
            activeIncidents: [...this.users.values()].reduce(
                (total, user) =>
                    total +
                    [...user.horizontal.values(), ...user.sweep.values()].filter(
                        (state) => state.fired,
                    ).length,
                0,
            ),
            trackedSources: this.sources.size,
            coverageMode: this.coverageMode,
            skippedWebhookRules: this.skippedWebhookRules,
            evictedUsers: this.evictedUsers,
            evictedKeys: this.evictedKeys,
            droppedReports: this.droppedReports,
            lastError: this.lastError,
        };
    }

    reset(): void {
        this.enabled = false;
        this.config = null;
        this.configFingerprint = '';
        this.ignoredUsers.clear();
        this.ignoredSources = new IpMatcher([]);
        this.ignoredDestinations = new IpMatcher([]);
        this.excludedPorts.clear();
        this.scanPorts.clear();
        this.reportOnlyUsers.clear();
        this.reportOnlyInbounds.clear();
        this.sources.clear();
        this.users.clear();
        this.reports.clear();
        this.coverageMode = 'partial';
        this.skippedWebhookRules = 0;
        this.evictedUsers = 0;
        this.evictedKeys = 0;
        this.droppedReports = 0;
        this.lastError = null;
    }

    private getUserState(userId: string, timestamp: number): IUserState {
        const existing = this.users.get(userId);
        if (existing) {
            existing.lastSeenAt = timestamp;
            this.users.delete(userId);
            this.users.set(userId, existing);
            return existing;
        }

        const config = this.config!;
        if (this.users.size >= config.maxTrackedUsers) {
            const oldest = this.users.keys().next().value as string | undefined;
            if (oldest) this.users.delete(oldest);
            this.evictedUsers += 1;
        }

        const state: IUserState = {
            horizontal: new Map(),
            sweep: new Map(),
            scoreEvents: [],
            lastSeenAt: timestamp,
            networks: new Map(),
            targets: new Map(),
            domainSweep: new Map(),
            subdomains: new Map(),
            burst: null,
        };
        this.users.set(userId, state);
        return state;
    }

    private getDetectorState(
        map: Map<string, IDetectorKeyState>,
        key: string,
        user: IUserState,
        timestamp: number,
    ): IDetectorKeyState {
        const existing = map.get(key);
        if (existing) {
            existing.lastSeenAt = timestamp;
            map.delete(key);
            map.set(key, existing);
            return existing;
        }

        const config = this.config!;
        if (user.horizontal.size + user.sweep.size >= config.maxKeysPerUser) {
            const candidates = [
                ...[...user.horizontal].map(([candidateKey, state]) => ({
                    map: user.horizontal,
                    key: candidateKey,
                    lastSeenAt: state.lastSeenAt,
                })),
                ...[...user.sweep].map(([candidateKey, state]) => ({
                    map: user.sweep,
                    key: candidateKey,
                    lastSeenAt: state.lastSeenAt,
                })),
            ];
            candidates.sort((a, b) => a.lastSeenAt - b.lastSeenAt);
            const oldest = candidates[0];
            oldest?.map.delete(oldest.key);
            this.evictedKeys += 1;
        }

        const state: IDetectorKeyState = {
            destinations: new Map(),
            fired: false,
            lastFiredAt: 0,
            lastSeenAt: timestamp,
        };
        map.set(key, state);
        return state;
    }

    private recordDestination(
        state: IDetectorKeyState,
        destinationIp: string,
        timestamp: number,
        windowSeconds: number,
        threshold: number,
        cooldownSeconds: number,
    ): boolean {
        const cutoff = timestamp - windowSeconds * 1000;
        for (const [destination, lastSeenAt] of state.destinations) {
            if (lastSeenAt < cutoff) state.destinations.delete(destination);
        }

        // rearmAfterCooldown: a key that stays above its threshold fires again after
        // the cooldown, instead of staying latched for as long as the scan lasts.
        if (
            state.fired &&
            (this.config!.rearmAfterCooldown || state.destinations.size < threshold) &&
            timestamp - state.lastFiredAt >= cooldownSeconds * 1000
        ) {
            state.fired = false;
        }

        state.destinations.set(destinationIp, timestamp);
        state.lastSeenAt = timestamp;
        if (state.fired || state.destinations.size < threshold) return false;
        if (timestamp - state.lastFiredAt < cooldownSeconds * 1000) return false;

        state.fired = true;
        state.lastFiredAt = timestamp;
        return true;
    }

    /**
     * v2 rules. Port-geometry rules only see scan ports; hostnames never share a key
     * with IPs and never enter /24 geometry; hostnames are kept as hashes.
     */
    private detectV2(
        user: IUserState,
        observation: IAbuseBlockerObservation,
        scope: { excluded: boolean; inScope: boolean },
        detections: IAbuseBlockerDetection[],
        blockEligible: boolean[],
    ): void {
        const config = this.config!;
        const now = observation.timestamp;
        const port = observation.destinationPort;
        const push = (
            rule: AbuseBlockerRuleName,
            key: string,
            state: IIncidentState,
            count: number,
            threshold: number,
            ruleConfig: { windowSeconds: number; score: number; blockEligible: boolean },
            unit: AbuseBlockerDetectionUnit,
            subnet: string | null = null,
        ) => {
            const phase = this.evaluateIncident(state, count, threshold, now);
            if (!phase) return;
            detections.push({
                rule,
                key,
                uniqueDestinations: count,
                windowSeconds: ruleConfig.windowSeconds,
                score: ruleConfig.score,
                subnet,
                phase,
                count,
                unit,
            });
            blockEligible.push(ruleConfig.blockEligible);
        };

        const burst = config.sessionRateBurst;
        if (burst.enabled && !scope.excluded) {
            const slotMs = (burst.windowSeconds * 1000) / BURST_BUCKETS;
            user.burst ??= createRing(BURST_BUCKETS, Math.floor(now / slotMs));
            const count = addToRing(user.burst, now, slotMs);
            push(
                'session_rate_burst',
                'user',
                user.burst,
                count,
                burst.sessions,
                burst,
                'sessions',
            );
        }
        if (!scope.inScope) return;

        const hammer = config.hammerTarget;
        const countHammer = (targetKey: string, label: string) => {
            if (!hammer.enabled) return;
            const slotMs = (hammer.windowSeconds * 1000) / HAMMER_BUCKETS;
            const ring = getOrCreate(user.targets, targetKey, hammer.maxTargetsPerUser, () =>
                createRing(HAMMER_BUCKETS, Math.floor(now / slotMs)),
            );
            const count = addToRing(ring, now, slotMs);
            push(
                'hammer_target',
                `${port}|${label}`,
                ring,
                count,
                hammer.sessions,
                hammer,
                'sessions',
            );
        };

        const destinationIp = observation.destinationIp;
        if (destinationIp !== null) {
            const sweep = config.horizontalSweep;
            if (sweep.enabled) {
                const network = getNetworkKey(destinationIp, sweep.ipv4Prefix, sweep.ipv6Prefix);
                if (network) {
                    const state = getOrCreate(user.networks, port, 1024, createMemberSet);
                    const count = touchMember(
                        state,
                        network,
                        now,
                        sweep.windowSeconds * 1000,
                        sweep.maxNetworksPerKey,
                    );
                    push(
                        'horizontal_sweep',
                        String(port),
                        state,
                        count,
                        sweep.uniqueNetworks,
                        sweep,
                        'networks',
                    );
                }
            }
            countHammer(`${port}|${destinationIp}`, destinationIp);
            return;
        }

        const host = observation.destinationHost;
        if (!host || !config.domains.enabled || WEB_PORTS.has(port)) return;
        const hostHash = hashHostname(host);
        countHammer(`${port}|#${hostHash}`, host);

        const domain = getRegistrableDomain(host);
        if (!domain) return;
        const domainHash = hashHostname(domain);

        const domainSweep = config.domains.sweep;
        if (domainSweep.enabled) {
            const state = getOrCreate(user.domainSweep, port, 1024, createMemberSet);
            const count = touchMember(
                state,
                domainHash,
                now,
                domainSweep.windowSeconds * 1000,
                domainSweep.maxDomainsPerKey,
            );
            push(
                'horizontal_sweep_domains',
                String(port),
                state,
                count,
                domainSweep.uniqueDomains,
                domainSweep,
                'domains',
            );
        }

        const subdomainSweep = config.domains.subdomainSweep;
        if (subdomainSweep.enabled) {
            const state = getOrCreate(
                user.subdomains,
                domainHash,
                subdomainSweep.maxDomainsPerUser,
                createMemberSet,
            );
            const count = touchMember(
                state,
                hostHash,
                now,
                subdomainSweep.windowSeconds * 1000,
                subdomainSweep.maxHostsPerKey,
            );
            push(
                'subdomain_sweep',
                domain,
                state,
                count,
                subdomainSweep.uniqueHosts,
                subdomainSweep,
                'hostnames',
            );
        }
    }

    /**
     * First time a key reaches its threshold: 'candidate' (reported). At least
     * confirmationSeconds later, still at or above: 'confirmed' (block-eligible), and
     * again every incidentCooldownSeconds while it stays there. Dropping below the
     * threshold expires the candidate.
     */
    private evaluateIncident(
        state: IIncidentState,
        count: number,
        threshold: number,
        now: number,
    ): AbuseBlockerDetectionPhase | null {
        if (count < threshold) {
            state.candidateAt = null;
            return null;
        }
        const config = this.config!;
        const cooldownMs = config.incidentCooldownSeconds * 1000;
        const confirmationMs = config.confirmationSeconds * 1000;
        if (now - state.lastFiredAt < cooldownMs) return null;

        if (state.candidateAt === null) {
            state.candidateAt = now;
            if (confirmationMs > 0) {
                if (now - state.lastCandidateAt < cooldownMs) return null;
                state.lastCandidateAt = now;
                return 'candidate';
            }
        }
        if (now - state.candidateAt < confirmationMs) return null;

        state.lastFiredAt = now;
        return 'confirmed';
    }

    /**
     * Remembers which users used a source address: an LRU of sources (position
     * refreshed at most once a minute) with at most 16 users each.
     */
    private trackSourceUser(observation: IAbuseBlockerObservation): void {
        const { sourceIp, userId, timestamp } = observation;
        let source = this.sources.get(sourceIp);
        if (!source) {
            if (this.sources.size >= this.config!.sourceGuards.maxTrackedSources) {
                this.sources.delete(this.sources.keys().next().value!);
            }
            source = { users: new Map(), touchedAt: timestamp };
            this.sources.set(sourceIp, source);
        } else if (timestamp - source.touchedAt >= SOURCE_LRU_REFRESH_MS) {
            this.sources.delete(sourceIp);
            this.sources.set(sourceIp, source);
            source.touchedAt = timestamp;
        }
        if (!source.users.has(userId) && source.users.size >= MAX_USERS_PER_SOURCE_TRACKED) {
            source.users.delete(source.users.keys().next().value!);
        }
        source.users.set(userId, timestamp);
    }

    /** Distinct users on the source in the guard window; saturates at 16. */
    private countSourceUsers(sourceIp: string, timestamp: number): number {
        const users = this.sources.get(sourceIp)?.users;
        if (!users) return 0;
        const cutoff = timestamp - this.config!.sourceGuards.userWindowSeconds * 1000;
        let count = 0;
        for (const lastSeenAt of users.values()) {
            if (lastSeenAt >= cutoff) count += 1;
        }
        return count;
    }

    private blockSkipReason(
        observation: IAbuseBlockerObservation,
        sourceIpUserCount: number,
    ): AbuseBlockerSkipReason | null {
        const guards = this.config!.sourceGuards;
        if (!guards.enabled) return null;
        if (!guards.blockNonPublicSources && this.nonPublicSources.matches(observation.sourceIp)) {
            return 'non_public_source';
        }
        if (this.reportOnlyUsers.has(observation.userId)) return 'report_only_user';
        if (observation.inboundTag && this.reportOnlyInbounds.has(observation.inboundTag)) {
            return 'report_only_inbound';
        }
        if (sourceIpUserCount > guards.maxUsersPerSource) return 'shared_source';
        return null;
    }

    private collectEvidence(
        user: IUserState,
        destinationPort: number,
        limit: number,
    ): Array<{ destinationIp: string; destinationPort: number; lastSeenAt: Date }> {
        const destinations = new Map<string, number>();
        const matchingStates = [
            ...[...user.horizontal].flatMap(([key, state]) =>
                key.startsWith(`${destinationPort}|`) ? [state] : [],
            ),
            ...(user.sweep.get(String(destinationPort))
                ? [user.sweep.get(String(destinationPort))!]
                : []),
        ];
        for (const state of matchingStates) {
            for (const [destinationIp, timestamp] of state.destinations) {
                const current = destinations.get(destinationIp) ?? 0;
                if (timestamp > current) destinations.set(destinationIp, timestamp);
            }
        }

        return [...destinations]
            .sort((a, b) => b[1] - a[1])
            .slice(0, limit)
            .map(([destinationIp, timestamp]) => ({
                destinationIp,
                destinationPort,
                lastSeenAt: new Date(timestamp),
            }));
    }

    private pruneScore(user: IUserState, timestamp: number, windowSeconds: number): void {
        const cutoff = timestamp - windowSeconds * 1000;
        user.scoreEvents = user.scoreEvents.filter((event) => event.timestamp >= cutoff);
    }

    private updateBufferedEvidence(
        userId: string,
        user: IUserState,
        destinationPort: number,
    ): void {
        const limit = this.config?.enhancedEvidenceLimit;
        if (!limit) return;

        for (const report of this.reports.values()) {
            if (report.userId !== userId || report.destinationPort !== destinationPort) continue;
            if (report.score.after < (this.config?.alertScore ?? Number.POSITIVE_INFINITY))
                continue;

            report.evidence = this.collectEvidence(user, destinationPort, limit);
        }
    }
}

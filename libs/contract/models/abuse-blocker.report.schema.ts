import { z } from 'zod';

import { XrayWebhookSchema } from './xray-webhook.schema';

export const AbuseBlockerRuleNameSchema = z.enum([
    'horizontal_scan',
    'destination_sweep',
    'horizontal_sweep',
    'hammer_target',
    'session_rate_burst',
    'horizontal_sweep_domains',
    'subdomain_sweep',
]);
export const AbuseBlockerSeveritySchema = z.enum(['suspicious', 'alert', 'blocked']);
export const AbuseBlockerCoverageModeSchema = z.enum(['full', 'partial']);
export const AbuseBlockerDetectionPhaseSchema = z.enum(['single', 'candidate', 'confirmed']);
export const AbuseBlockerSkipReasonSchema = z.enum([
    'report_only',
    'non_public_source',
    'report_only_user',
    'report_only_inbound',
    'shared_source',
]);

const AbuseBlockerRulePolicySchema = z.object({
    enabled: z.boolean(),
    windowSeconds: z.int().min(1),
    score: z.int().min(1),
    blockEligible: z.boolean(),
});

export const AbuseBlockerPolicySchema = z.object({
    excludedPorts: z.array(z.int().min(1).max(65535)),
    scoreWindowSeconds: z.int().min(1),
    incidentCooldownSeconds: z.int().min(0),
    suspiciousScore: z.int().min(1),
    alertScore: z.int().min(1),
    blockScore: z.int().min(1),
    initialBlockSeconds: z.int().min(1),
    repeatBlockSeconds: z.int().min(1),
    repeatWindowSeconds: z.int().min(1),
    evidenceLimit: z.int().min(1),
    enhancedEvidenceLimit: z.int().min(1),
    maxTrackedUsers: z.int().min(1),
    maxKeysPerUser: z.int().min(1),
    reportBufferSize: z.int().min(1),
    horizontalScan: z.object({
        enabled: z.boolean(),
        windowSeconds: z.int().min(1),
        uniqueDestinations: z.int().min(2),
        ipv4Prefix: z.int().min(0).max(32),
        ipv6Prefix: z.int().min(0).max(128),
        score: z.int().min(1),
    }),
    destinationSweep: z.object({
        enabled: z.boolean(),
        windowSeconds: z.int().min(1),
        uniqueDestinations: z.int().min(2),
        score: z.int().min(1),
    }),
    mode: z.enum(['report', 'block']),
    ruleSet: z.enum(['v2', 'legacy', 'both']),
    scanPorts: z.array(z.int().min(1).max(65535)),
    confirmationSeconds: z.int().min(0),
    rearmAfterCooldown: z.boolean(),
    horizontalSweep: AbuseBlockerRulePolicySchema.extend({
        uniqueNetworks: z.int().min(2),
        ipv4Prefix: z.int().min(0).max(32),
        ipv6Prefix: z.int().min(0).max(128),
        maxNetworksPerKey: z.int().min(2),
    }),
    hammerTarget: AbuseBlockerRulePolicySchema.extend({
        sessions: z.int().min(2),
        maxTargetsPerUser: z.int().min(1),
    }),
    sessionRateBurst: AbuseBlockerRulePolicySchema.extend({
        sessions: z.int().min(2),
    }),
    domains: z.object({
        enabled: z.boolean(),
        sweep: AbuseBlockerRulePolicySchema.extend({
            uniqueDomains: z.int().min(2),
            maxDomainsPerKey: z.int().min(2),
        }),
        subdomainSweep: AbuseBlockerRulePolicySchema.extend({
            uniqueHosts: z.int().min(2),
            maxHostsPerKey: z.int().min(2),
            maxDomainsPerUser: z.int().min(1),
        }),
    }),
    sourceGuards: z.object({
        enabled: z.boolean(),
        blockNonPublicSources: z.boolean(),
        maxUsersPerSource: z.int().min(1),
        userWindowSeconds: z.int().min(1),
        maxTrackedSources: z.int().min(1),
        reportOnlyUserIds: z.array(z.int().min(1)),
        reportOnlyInboundTags: z.array(z.string()),
    }),
});

export const AbuseBlockerReportSchema = z.object({
    eventId: z.uuid(),
    userId: z.string().regex(/^\d+$/),
    sourceIp: z.union([z.ipv4(), z.ipv6()]),
    sourceIpUserCount: z.int().min(0),
    inboundTag: z.string().nullable(),
    destinationIp: z.union([z.ipv4(), z.ipv6()]).nullable(),
    destinationHost: z.string().nullable(),
    destinationPort: z.int().min(1).max(65535),
    detectedAt: z.coerce.date(),
    detections: z.array(
        z.object({
            rule: AbuseBlockerRuleNameSchema,
            key: z.string(),
            uniqueDestinations: z.int().min(1),
            windowSeconds: z.int().min(1),
            score: z.int().min(1),
            subnet: z.string().nullable(),
            phase: AbuseBlockerDetectionPhaseSchema,
            count: z.int().min(1),
            unit: z.enum(['destinations', 'networks', 'sessions', 'domains', 'hostnames']),
        }),
    ),
    score: z.object({
        before: z.int().min(0),
        delta: z.int().min(1),
        after: z.int().min(1),
        windowSeconds: z.int().min(1),
    }),
    severity: AbuseBlockerSeveritySchema,
    evidence: z.array(
        z.object({
            destinationIp: z.union([z.ipv4(), z.ipv6()]),
            destinationPort: z.int().min(1).max(65535),
            lastSeenAt: z.coerce.date(),
        }),
    ),
    actionReport: z.object({
        action: z.enum(['none', 'ip_block']),
        blocked: z.boolean(),
        blockDuration: z.int().min(0),
        willUnblockAt: z.coerce.date().nullable(),
        error: z.string().nullable(),
        skipReason: AbuseBlockerSkipReasonSchema.nullable(),
        processedAt: z.coerce.date(),
    }),
    policy: AbuseBlockerPolicySchema,
    configFingerprint: z.string().min(1),
    coverageMode: AbuseBlockerCoverageModeSchema,
    xrayReport: XrayWebhookSchema,
});

export type AbuseBlockerRuleName = z.infer<typeof AbuseBlockerRuleNameSchema>;
export type AbuseBlockerSeverity = z.infer<typeof AbuseBlockerSeveritySchema>;
export type AbuseBlockerCoverageMode = z.infer<typeof AbuseBlockerCoverageModeSchema>;
export type AbuseBlockerDetectionPhase = z.infer<typeof AbuseBlockerDetectionPhaseSchema>;
export type AbuseBlockerSkipReason = z.infer<typeof AbuseBlockerSkipReasonSchema>;
export type AbuseBlockerPolicy = z.infer<typeof AbuseBlockerPolicySchema>;
export type AbuseBlockerReportModel = z.infer<typeof AbuseBlockerReportSchema>;

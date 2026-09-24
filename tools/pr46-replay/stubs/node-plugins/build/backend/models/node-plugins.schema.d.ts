import { z } from 'zod';
export declare const SharedListConfigSchema: z.ZodDiscriminatedUnion<[z.ZodObject<{
    type: z.ZodLiteral<"ipList">;
    items: z.ZodArray<z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>]>>;
}, z.core.$strip>, z.ZodObject<{
    type: z.ZodLiteral<"asList">;
    items: z.ZodArray<z.ZodInt>;
}, z.core.$strip>], "type">;
export declare const SharedListSchema: z.ZodDiscriminatedUnion<[z.ZodObject<{
    type: z.ZodLiteral<"ipList">;
    items: z.ZodArray<z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>]>>;
    name: z.ZodString;
}, z.core.$strip>, z.ZodObject<{
    type: z.ZodLiteral<"asList">;
    items: z.ZodArray<z.ZodInt>;
    name: z.ZodString;
}, z.core.$strip>], "type">;
export declare const TorrentBlockerPluginSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    blockDuration: z.ZodInt;
    ignoreLists: z.ZodObject<{
        ip: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
        userId: z.ZodOptional<z.ZodArray<z.ZodInt>>;
    }, z.core.$strip>;
    includeRuleTags: z.ZodOptional<z.ZodArray<z.ZodString>>;
    webhookUrl: z.ZodOptional<z.ZodURL>;
}, z.core.$strip>;
export declare const AbuseBlockerPluginSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    excludedPorts: z.ZodDefault<z.ZodArray<z.ZodInt>>;
    ignoreLists: z.ZodDefault<z.ZodObject<{
        userId: z.ZodDefault<z.ZodArray<z.ZodInt>>;
        sourceIp: z.ZodDefault<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
        destinationIp: z.ZodDefault<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
    }, z.core.$strip>>;
    scoreWindowSeconds: z.ZodDefault<z.ZodInt>;
    incidentCooldownSeconds: z.ZodDefault<z.ZodInt>;
    suspiciousScore: z.ZodDefault<z.ZodInt>;
    alertScore: z.ZodDefault<z.ZodInt>;
    blockScore: z.ZodDefault<z.ZodInt>;
    initialBlockSeconds: z.ZodDefault<z.ZodInt>;
    repeatBlockSeconds: z.ZodDefault<z.ZodInt>;
    repeatWindowSeconds: z.ZodDefault<z.ZodInt>;
    evidenceLimit: z.ZodDefault<z.ZodInt>;
    enhancedEvidenceLimit: z.ZodDefault<z.ZodInt>;
    maxTrackedUsers: z.ZodDefault<z.ZodInt>;
    maxKeysPerUser: z.ZodDefault<z.ZodInt>;
    reportBufferSize: z.ZodDefault<z.ZodInt>;
    horizontalScan: z.ZodDefault<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        windowSeconds: z.ZodDefault<z.ZodInt>;
        uniqueDestinations: z.ZodDefault<z.ZodInt>;
        ipv4Prefix: z.ZodDefault<z.ZodInt>;
        ipv6Prefix: z.ZodDefault<z.ZodInt>;
        score: z.ZodDefault<z.ZodInt>;
    }, z.core.$strip>>;
    destinationSweep: z.ZodDefault<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        windowSeconds: z.ZodDefault<z.ZodInt>;
        uniqueDestinations: z.ZodDefault<z.ZodInt>;
        score: z.ZodDefault<z.ZodInt>;
    }, z.core.$strip>>;
}, z.core.$strip>;
export declare const ConnectionDropPluginSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    whitelistIps: z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>;
}, z.core.$strip>;
export declare const IngressFilterPluginSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    blockedIps: z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>;
}, z.core.$strip>;
export declare const EgressFilterPluginSchema: z.ZodObject<{
    enabled: z.ZodBoolean;
    blockedIps: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
    blockedPorts: z.ZodOptional<z.ZodArray<z.ZodInt>>;
}, z.core.$strip>;
export declare const preStartPluginSchema: z.ZodObject<{
    enabled: z.ZodDefault<z.ZodBoolean>;
    cleanupSockets: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        files: z.ZodArray<z.ZodString>;
    }, z.core.$strip>>;
}, z.core.$strip>;
export declare const NodePluginSchema: z.ZodObject<{
    sharedLists: z.ZodDefault<z.ZodOptional<z.ZodArray<z.ZodDiscriminatedUnion<[z.ZodObject<{
        type: z.ZodLiteral<"ipList">;
        items: z.ZodArray<z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>]>>;
        name: z.ZodString;
    }, z.core.$strip>, z.ZodObject<{
        type: z.ZodLiteral<"asList">;
        items: z.ZodArray<z.ZodInt>;
        name: z.ZodString;
    }, z.core.$strip>], "type">>>>;
    torrentBlocker: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        blockDuration: z.ZodInt;
        ignoreLists: z.ZodObject<{
            ip: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
            userId: z.ZodOptional<z.ZodArray<z.ZodInt>>;
        }, z.core.$strip>;
        includeRuleTags: z.ZodOptional<z.ZodArray<z.ZodString>>;
        webhookUrl: z.ZodOptional<z.ZodURL>;
    }, z.core.$strip>>;
    abuseBlocker: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        excludedPorts: z.ZodDefault<z.ZodArray<z.ZodInt>>;
        ignoreLists: z.ZodDefault<z.ZodObject<{
            userId: z.ZodDefault<z.ZodArray<z.ZodInt>>;
            sourceIp: z.ZodDefault<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
            destinationIp: z.ZodDefault<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
        }, z.core.$strip>>;
        scoreWindowSeconds: z.ZodDefault<z.ZodInt>;
        incidentCooldownSeconds: z.ZodDefault<z.ZodInt>;
        suspiciousScore: z.ZodDefault<z.ZodInt>;
        alertScore: z.ZodDefault<z.ZodInt>;
        blockScore: z.ZodDefault<z.ZodInt>;
        initialBlockSeconds: z.ZodDefault<z.ZodInt>;
        repeatBlockSeconds: z.ZodDefault<z.ZodInt>;
        repeatWindowSeconds: z.ZodDefault<z.ZodInt>;
        evidenceLimit: z.ZodDefault<z.ZodInt>;
        enhancedEvidenceLimit: z.ZodDefault<z.ZodInt>;
        maxTrackedUsers: z.ZodDefault<z.ZodInt>;
        maxKeysPerUser: z.ZodDefault<z.ZodInt>;
        reportBufferSize: z.ZodDefault<z.ZodInt>;
        horizontalScan: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            windowSeconds: z.ZodDefault<z.ZodInt>;
            uniqueDestinations: z.ZodDefault<z.ZodInt>;
            ipv4Prefix: z.ZodDefault<z.ZodInt>;
            ipv6Prefix: z.ZodDefault<z.ZodInt>;
            score: z.ZodDefault<z.ZodInt>;
        }, z.core.$strip>>;
        destinationSweep: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            windowSeconds: z.ZodDefault<z.ZodInt>;
            uniqueDestinations: z.ZodDefault<z.ZodInt>;
            score: z.ZodDefault<z.ZodInt>;
        }, z.core.$strip>>;
    }, z.core.$strip>>;
    ingressFilter: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        blockedIps: z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>;
    }, z.core.$strip>>;
    egressFilter: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        blockedIps: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
        blockedPorts: z.ZodOptional<z.ZodArray<z.ZodInt>>;
    }, z.core.$strip>>;
    connectionDrop: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        whitelistIps: z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>;
    }, z.core.$strip>>;
    preStart: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        cleanupSockets: z.ZodOptional<z.ZodObject<{
            enabled: z.ZodBoolean;
            files: z.ZodArray<z.ZodString>;
        }, z.core.$strip>>;
    }, z.core.$strip>>;
}, z.core.$strip>;
export declare const NodePluginEditorSchema: z.ZodObject<{
    torrentBlocker: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        blockDuration: z.ZodInt;
        ignoreLists: z.ZodObject<{
            ip: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
            userId: z.ZodOptional<z.ZodArray<z.ZodInt>>;
        }, z.core.$strip>;
        includeRuleTags: z.ZodOptional<z.ZodArray<z.ZodString>>;
        webhookUrl: z.ZodOptional<z.ZodURL>;
    }, z.core.$strip>>;
    abuseBlocker: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        excludedPorts: z.ZodDefault<z.ZodArray<z.ZodInt>>;
        ignoreLists: z.ZodDefault<z.ZodObject<{
            userId: z.ZodDefault<z.ZodArray<z.ZodInt>>;
            sourceIp: z.ZodDefault<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
            destinationIp: z.ZodDefault<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
        }, z.core.$strip>>;
        scoreWindowSeconds: z.ZodDefault<z.ZodInt>;
        incidentCooldownSeconds: z.ZodDefault<z.ZodInt>;
        suspiciousScore: z.ZodDefault<z.ZodInt>;
        alertScore: z.ZodDefault<z.ZodInt>;
        blockScore: z.ZodDefault<z.ZodInt>;
        initialBlockSeconds: z.ZodDefault<z.ZodInt>;
        repeatBlockSeconds: z.ZodDefault<z.ZodInt>;
        repeatWindowSeconds: z.ZodDefault<z.ZodInt>;
        evidenceLimit: z.ZodDefault<z.ZodInt>;
        enhancedEvidenceLimit: z.ZodDefault<z.ZodInt>;
        maxTrackedUsers: z.ZodDefault<z.ZodInt>;
        maxKeysPerUser: z.ZodDefault<z.ZodInt>;
        reportBufferSize: z.ZodDefault<z.ZodInt>;
        horizontalScan: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            windowSeconds: z.ZodDefault<z.ZodInt>;
            uniqueDestinations: z.ZodDefault<z.ZodInt>;
            ipv4Prefix: z.ZodDefault<z.ZodInt>;
            ipv6Prefix: z.ZodDefault<z.ZodInt>;
            score: z.ZodDefault<z.ZodInt>;
        }, z.core.$strip>>;
        destinationSweep: z.ZodDefault<z.ZodObject<{
            enabled: z.ZodDefault<z.ZodBoolean>;
            windowSeconds: z.ZodDefault<z.ZodInt>;
            uniqueDestinations: z.ZodDefault<z.ZodInt>;
            score: z.ZodDefault<z.ZodInt>;
        }, z.core.$strip>>;
    }, z.core.$strip>>;
    ingressFilter: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        blockedIps: z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>;
    }, z.core.$strip>>;
    egressFilter: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        blockedIps: z.ZodOptional<z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodCIDRv4, z.ZodString]>, z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>>;
        blockedPorts: z.ZodOptional<z.ZodArray<z.ZodInt>>;
    }, z.core.$strip>>;
    connectionDrop: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodBoolean;
        whitelistIps: z.ZodArray<z.ZodUnion<readonly [z.ZodUnion<readonly [z.ZodIPv4, z.ZodString]>, z.ZodString]>>;
    }, z.core.$strip>>;
    preStart: z.ZodOptional<z.ZodObject<{
        enabled: z.ZodDefault<z.ZodBoolean>;
        cleanupSockets: z.ZodOptional<z.ZodObject<{
            enabled: z.ZodBoolean;
            files: z.ZodArray<z.ZodString>;
        }, z.core.$strip>>;
    }, z.core.$strip>>;
}, z.core.$strip>;
export type TSharedListConfig = z.infer<typeof SharedListConfigSchema>;
export type TNodePlugin = z.infer<typeof NodePluginSchema>;
export type TNodePluginEditor = z.infer<typeof NodePluginEditorSchema>;

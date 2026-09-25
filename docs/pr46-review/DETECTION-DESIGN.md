# Proposed detector changes for PR #46

Inputs: [CONTEXT.md](CONTEXT.md) (operator rules and false-positive classes),
the real-traffic sections of [REVIEW.md](REVIEW.md), and
[DETECTION-FACTS.md](DETECTION-FACTS.md) (what the webhook carries).

Two principles from CONTEXT.md drive every choice:

- **Precision first.** Anything that can block must essentially never fire
  on a normal consumer.
- **Report-only by default.** Everything new or changed defaults to
  reporting.

The patch changes the PR's own files (`abuse-blocker.state.ts`,
`xray-webhook.handler.ts`, the report contract and the `abuseBlocker` plugin
schema). Every new schema field has a default, so an old config still parses.

## A. Rule set

### A.0 Modes and rule sets (new top-level fields)

| Field | Default | Meaning |
|---|---|---|
| `mode` | `"report"` | `"block"` is an explicit per-node opt-in. In `report` mode, a decision that would block is reported with `severity: "blocked"`, `action: "none"`, `skipReason: "report_only"`. |
| `ruleSet` | `"v2"` | `"legacy"` runs only the PR head detectors (`horizontalScan`, `destinationSweep`); `"both"` runs both, for A/B. |
| `scanPorts` | recon allowlist (56 ports) | Positive scope for every port-geometry rule. `[]` restores the PR head behaviour: every port not in `excludedPorts`. |
| `confirmationSeconds` | `60` | Two-pass confirmation (A.6). `0` turns it off. |
| `rearmAfterCooldown` | `true` | The latch fix (A.2). |

`configs/pr46-head-equivalent.json` sets `mode: block`, `ruleSet: legacy`,
`scanPorts: []`, `confirmationSeconds: 0`, `rearmAfterCooldown: false`, and
turns off `sourceGuards` and `domains`. A test replays every scenario with
it and checks that the patched code makes exactly the same decisions as the
PR head.

### A.1 Positive recon-port scope

`scanPorts` defaults to the CONTEXT.md §1 list with its ranges expanded:
21, 22, 23, 88, 111, 135, 137, 139, 179, 389, 445, 502, 512-515, 523, 548,
553, 554, 623, 636, 873, 1099, 1433, 1521, 1723, 2049, 2222, 2323, 2375,
2376, 2379, 2380, 3306, 3389, 4444, 4786, 5432, 5555, 5900-5902, 5984-5986,
6379, 6443, 7547, 8291, 9200, 9300, 11211, 27017, 27018, 47808.

- The list is held as a `Set`. `excludedPorts` also becomes a `Set`;
  `includes()` used to run on every event.
- Only ports in scope feed the sweep, hammer and domain rules, and the legacy
  rules when they are enabled.
- Every other port feeds `session_rate_burst` only, which is report-only
  (A.5).
- `excludedPorts` is kept. When `scanPorts` is non-empty, the allowlist wins
  for scope: a recon port listed in `excludedPorts` is still scanned. To
  exempt a recon port, remove it from `scanPorts`.
- **Effect on the real-data noise.** 86% of entry-node blocks were on ports
  outside the allowlist (50300, 6881, 8887, 53317, 62078, ...). None of these
  can score towards a block any more.

### A.2 Latch fix

- **PR head:** a key resets `fired` only when its distinct count drops below
  the threshold *and* the cooldown has passed. A steady scan is therefore
  scored once, however long it runs.
- **Legacy rules:** with `rearmAfterCooldown` (default on), the count
  condition is dropped. A key that stays above its threshold fires again
  every `incidentCooldownSeconds` (300 s). This is a one-line change in
  `recordDestination`.
- **New rules:** they use one shared incident helper (A.6) that has this
  behaviour built in.

### A.3 `horizontal_sweep`

- **What it counts:** distinct destination networks (IPv4 /24, IPv6 /48) per
  (user, recon port) over 900 s.
- **Fires at:** 150 networks.
- **Memory:** per key, a `Map` of network to last-seen time, kept in
  insertion order with refresh on repeat. It is pruned from the old end and
  capped at `maxNetworksPerKey` (256), evicting the oldest.
- **Compared with the PR head rule** (20 hosts in one /24 in 60 s):
  - it sees random-order sweeps at 25 targets per minute and up. The PR head
    rule never scores them above 50;
  - it ignores dense CDN or provider pools, which fill a few /24s;
  - it does not see a dense walk that stays inside fewer than 150 /24s in
    15 minutes (for example 500 targets per minute, 254 hosts per /24). The
    operator's detector did not act on those either. `ruleSet: "both"` still
    reports them through the legacy rule.

### A.4 `hammer_target`

- **What it counts:** sessions per (user, destination, recon port) over
  900 s, where the destination is an IP, or a hostname hash for domain
  requests (B).
- **Fires at:** 300 sessions.
- **Memory:** per key, a 15 x 60 s ring of `Uint16` buckets; no per-session
  state. Keys are capped at `maxTargetsPerUser` (64) per user, LRU.

### A.5 `session_rate_burst`

- **What it counts:** non-web sessions per user over 60 s, fed by IP and
  domain destinations alike. "Non-web" means any port not in
  `excludedPorts`, which defaults to 80/443.
- **Fires at:** 600 sessions.
- **Memory:** a 12 x 5 s ring per user.
- **Report-only** (`blockEligible: false`), because it counts non-recon
  ports too. This keeps A.1 true: only recon ports can lead to a block.
- **Deduplication:** DETECTION-FACTS §3 shows Xray does not deduplicate PR
  #46's webhooks, so every TCP session is counted. If a rule with a foreign,
  deduplicating webhook is skipped (`coverageMode: "partial"`), or the node
  drops webhook POSTs under load, the count is a lower bound. The rule
  under-reports; it never over-reports.

### A.6 Two-pass confirmation and scoring

All new rules share one incident helper per key:

1. When the count first reaches the threshold, the rule records the
   **candidate** time and reports it (`phase: "candidate"`, rule score 100).
   That makes the user an `alert`.
2. When an event arrives at least `confirmationSeconds` (60) after the
   candidate time, and the count is still at or above the threshold, the
   rule fires **confirmed** (another +100). A confirmed, block-eligible
   detection with a user score of at least `blockScore` (150) is the only way
   to reach `severity: "blocked"`.
3. If the count drops below the threshold, the candidate expires. After a
   confirmed firing, the key fires again every `incidentCooldownSeconds`
   while it stays above its threshold.

Legacy detections have no candidate stage (`phase: "single"`). They are
block-eligible only when `confirmationSeconds` is 0, as in the PR head.
Candidates from two different keys can add up past 150, but they stay at
`alert`.

### A.7 Source guards (`sourceGuards`, enabled by default)

A decision that would block is turned into a report with a `skipReason` when:

| Reason | Condition |
|---|---|
| `non_public_source` | source in 10/8, 172.16/12, 192.168/16, 100.64/10, 127/8, 169.254/16, 0/8, ::1, fc00::/7, fe80::/10 (`blockNonPublicSources: false`) |
| `report_only_user` | `userId` in `reportOnlyUserIds` |
| `report_only_inbound` | `inboundTag` in `reportOnlyInboundTags` (for example the mesh inbound on an exit node) |
| `shared_source` | the source carried more than `maxUsersPerSource` (1) distinct userIds in the last `userWindowSeconds` (3600) |

- Users per source are tracked for every scored TCP event, before the port
  filters, so that web traffic counts too. UDP never reaches the state.
- The tracker is an LRU of `maxTrackedSources` (100,000) addresses, each
  holding at most 16 users. The count saturates at 16.

### A.8 Report fields

Added to every report:

- `sourceIpUserCount`;
- `inboundTag`;
- `destinationHost` (for domain requests). `destinationIp` becomes nullable;
- `actionReport.skipReason`.

Each detection also carries `phase`, `count` (the raw count) and `unit`
(`destinations`, `networks`, `sessions`, `domains` or `hostnames`), next to
the existing `windowSeconds`.

## B. Domain destinations

- **Identity.** An observation carries either `destinationIp` or
  `destinationHost`, never both. The IP is preferred whenever any of
  `originalTarget`, `routeTarget` or `destination` has one, as in the PR
  head. `toAbuseBlockerObservation(webhook, { domains })` keeps its old
  behaviour when called without options.
- **Normalization** (`utils/domain.utils.ts`):
  - trim, then strip the trailing dot;
  - `node:url` `domainToASCII` for IDNA/punycode and lowercasing;
  - reject IP literals, a total length over 253, fewer than two labels, and
    labels that are empty, longer than 63, contain anything but
    `[a-z0-9_-]`, or start or end with `-`.
- **Registrable domain:** `tldts` `getDomain(host, { allowPrivateDomains:
  true })`. Unknown and reserved TLDs (`.example`, `.test`, `.invalid`) fall
  back to the implicit `*` rule, so `a.b.example` becomes `b.example`.
- **Why `tldts`.** The alternatives were a vendored Public Suffix List
  snapshot and `psl`:

  | Option | License | Size | Updates | Cost |
  |---|---|---|---|---|
  | **`tldts` 7.4.15** (recommended) | MIT | 3.0 MB unpacked (all builds), about 230 KB loaded (with `tldts-core`), 1 dependency | weekly PSL releases, last 2026-09-23 | ~0.4 µs per lookup |
  | vendored PSL + matcher | MPL-2.0 data | ~230 KB list + ~80 lines | manual; goes stale silently | similar |
  | `psl` 1.15.0 | MIT | 0.7 MB | last release 2024-12 | similar |

  Pin it exactly (`"tldts": "7.4.15"`) and bump it like the other dependencies.
- **No DNS resolution** anywhere in the detector. It would cost latency,
  leak destinations to resolvers, and give different answers for CDNs.
  Resolving a confirmed candidate could be added later: bounded, cached and
  report-only. It is not part of this patch.
- **Separate keys.** Domain and IP destinations never share a key. Domains
  never enter /24 or /48 geometry: the legacy rules and `horizontal_sweep`
  see IPs only.
- **Hashes, not strings.** Hostnames and registrable domains are stored in
  state as 53-bit hashes (cyrb53 with a per-process random seed). Only the
  report carries the triggering hostname.
- **Rules**, on recon ports only; domain rules never run on 80/443:

  | Rule | Key | Counts | Window | Fires at | Can block |
  |---|---|---|---|---|---|
  | `hammer_target` (domain) | user, hostname hash, port | sessions | 900 s | 300 | yes |
  | `horizontal_sweep_domains` | user, port | distinct registrable domains | 900 s | 50 (N) | yes |
  | `subdomain_sweep` | user, registrable domain | distinct hostnames on recon ports | 900 s | 100 (M) | no, report-only |
  | `session_rate_burst` | user | IP and domain sessions together | 60 s | 600 | no, report-only |

- **Choosing N and M** (`tools/pr46-replay/sensitivity-domains.js`):
  - the benign recon-port cases (SSH to a few own servers, 5 jump hosts
    under one domain, git over SSH) stay below 10 distinct names;
  - hostname-based scans of 100 or more names reach 50 distinct registrable
    domains well inside 15 minutes.
  - `subdomain_sweep` is report-only, because an administrator running
    Ansible or SSH over their own fleet by name looks exactly like
    enumeration from the log.
- **Out of scope**, and why:

  | Traffic | Why it is left out |
  |---|---|
  | mail ports | no auth result in the log, so brute force cannot be shown (CONTEXT §2) |
  | web floods on 80/443 | not a DoS signal (CONTEXT §2) |
  | torrent trackers by domain (:6969, :80, :443) | BitTorrent is a known false-positive class, and its ports are not recon ports |
  | push and realtime ports (5222/5223, 5228-5230, STUN) | long-lived app connections to large pools |

## Performance

The harness must replay a month of one node, and the node itself receives one
webhook per TCP connection, so the hot path matters. The patch keeps the
patched rules above 50,000 lines per second in the harness:

- **IP validity.** `parseNetworkEndpoint` now checks IP validity with
  `net.isIP` (`isIpAddress`) instead of building a BigInt through
  `parseIpAddress`. The two give identical answers on 400,000 fuzzed inputs.
  `IpMatcher.matches` returns at once when it has no ranges; the ignore lists
  are usually empty.
- **Observation mapping.** It stops at the first usable target instead of
  parsing all three.
- **Hostnames.** Lowercase ASCII hostnames skip `domainToASCII`.
- **LRU eviction.** `map.keys().next()` walks over every deleted slot at the
  front of a V8 hash table, and an LRU that re-inserts on every access leaves
  one such slot per event. In a micro-benchmark with 50,000 entries and
  churn, eviction costs 31 µs this way, against 0.5 µs with a kept iterator.
  The PR head's user LRU (`getUserState`) has this pattern, and it bites once
  a node sees more users than `maxTrackedUsers`. The patch evicts through a
  kept iterator (`deleteOldest`) for users, reports, sources and per-user
  keys.
- **Source tracker.** Its LRU position is refreshed at most once a minute
  per source, not on every event.

## Memory bounds (blocker state)

| Structure | Bound |
|---|---|
| users | `maxTrackedUsers` (50,000), LRU (PR head) |
| legacy keys | `maxKeysPerUser` (256) per user (PR head) |
| `horizontal_sweep` | one key per recon port (at most 61) x `maxNetworksPerKey` (256) |
| `horizontal_sweep_domains` | one key per recon port x `maxDomainsPerKey` (256) |
| `subdomain_sweep` | `maxDomainsPerUser` (32) keys x `maxHostsPerKey` (256) |
| `hammer_target` | `maxTargetsPerUser` (64) x a 15-slot ring |
| `session_rate_burst` | one 12-slot ring per user |
| users per source | `maxTrackedSources` (100,000) x 16 users |

Normal users touch few recon ports, so the typical cost per user stays small.
The worst case is a scanner, and scanners are few.

## Targets for the operator's real-data re-run

These are targets to measure, not promises:

- blocks per entry node-day of 0.05 or less (`mode: block`, measured by the
  harness), at least 80% of them on recon ports;
- at least 80% of confirmed sweeps and hammers reaching `alert` or higher;
- throughput of 50,000 lines per second or more;
- bounded memory on a month of one node.

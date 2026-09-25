Read these first, on branch `review/pr46-replay`:
- `docs/pr46-review/CONTEXT.md`;
- `docs/pr46-review/HOW-IT-WORKS.md`;
- `docs/pr46-review/REVIEW.md`, especially the two "Real traffic" sections.

They summarize about a month of production logs (17 entry nodes, 2.8 B
lines) replayed through PR #46. The main findings on entry nodes:

- **Noise.** 0.83 blocks per node-day, 86% of them on non-recon ports:
  unassigned app ports such as 50300, 8887, 53317 and 62078, and BitTorrent
  6881/51413. A few users were blocked over and over for normal app traffic.
- **Recall (upper bound)** against the operator's confirmed incidents:
  - horizontal sweeps (>= 150 /24s on a recon port): 27% blocked, 35% not
    noticed;
  - single-target hammers (>= 300 sessions to one host:port): 0 of 43 blocked;
  - non-web session bursts (>= 600 per minute): 11% blocked, 75% not noticed.
- **Coverage.** Only about 4.5% of log lines are scored. 68% of TCP sessions
  have a domain destination and are dropped by `toAbuseBlockerObservation`.
- **Chained exit nodes.** The blocker blocks the entry node's address, as
  expected. Guard against it; do not dwell on it.

Task: produce a concrete, tested improvement to the PR #46 detector, covering
both the rule set and domain destinations. The operator will then re-run it on
the same real logs with the existing harness and compare. Work only with
synthetic data. You have no production logs, and none will be provided.

Branch: create `review/pr46-detection` from `review/pr46-replay`. Push only
that branch to this fork. Do not open PRs, issues or comments anywhere.

## Step 0. Facts from Xray source (docs/pr46-review/DETECTION-FACTS.md)

Cite file:line in Xray-core at the version PR #46 targets (v26.7.28). Answer
these:

1. **Domain requests.** For a VLESS/REALITY client that asks for
   `example.com:443`, what do `destination`, `originalTarget` and
   `routeTarget` in the routing webhook contain (`app/router/webhook.go`,
   `buildEvent`, `enrichFromSession`)? Is a resolved IP ever present?
2. **What fills `originalTarget`/`routeTarget`.** Sniffing `destOverride`,
   `routeOnly`, `domainStrategy` `IPIfNonMatch`/`IPOnDemand`? Does the router
   resolve before the webhook fires, or does only the freedom outbound resolve
   later?
3. **When the webhook fires.** On every connection, or only when a rule with
   `webhook` matches? What per-user dedup or TTL exists? How does PR #46
   generate that rule for `target=abuse`? Dedup matters a lot for rate-based
   rules: if it exists, a session-rate rule cannot see every session.

If something cannot be established from source, say so and design for both
cases.

## Step 1. Design (docs/pr46-review/DETECTION-DESIGN.md)

Principles (CONTEXT.md):
- **Precision first.** Anything that can block must essentially never fire
  on a normal consumer.
- **Report-only by default** for everything that is new or changed.

### A. Rule-set changes, driven by the real-data findings

1. **Positive recon-port scope.** Scoring for blocking uses only the recon
   allowlist from CONTEXT.md §1 (about 55 ports), as a `Set`.
   - Every other port feeds at most an observe-only counter.
   - Keep `excludedPorts` for backward compatibility; the allowlist wins.
   - This alone should remove the repeat blocks on app ports.
2. **Fix the latching key.** A key that stays above its threshold must be
   able to fire again after `incidentCooldownSeconds`. Today `fired` resets
   only when the count drops below the threshold, so a steady scan is scored
   once.
3. **`horizontal_sweep`.** Count distinct /24s (IPv6 /48) per (user, recon
   port) over 15 minutes; fire at 150.
   - Memory: a bounded map of /24 to last-seen per key, capped (for example
     at 256), with eviction of the oldest entries.
   - Compare against the current 60-second, 20-per-/24 rule on the
     sensitivity table (random vs sequential order).
4. **`hammer_target`.** Count sessions per (user, destination, recon port)
   over 15 minutes; fire at 300. Keep only a counter per destination key, and
   cap the keys per user.
5. **`session_rate_burst`.** Count non-web sessions per user over 60 s; fire
   at 600. Use a rolling counter; do not store per-session state. If step 0
   shows webhook dedup, document how this rule degrades.
6. **Two-pass confirmation before `shouldBlock`.** The condition must still
   hold at least 60 s after the first firing. The first firing is a report.
7. **Source guards**, briefly:
   - never block non-public sources (RFC 1918, 100.64/10, loopback, ULA,
     link-local);
   - report-only for configurable `reportOnlyInboundTags`/`reportOnlyUserIds`
     (technical and chained users);
   - skip the block, and report `shared_source` instead, when a source IP
     carried more than N distinct `userId`s in the last hour. Use a small
     bounded map.
8. **Report fields:** add `sourceIpUserCount`, `inboundTag`, the rule's raw
   count and its window, so a panel can judge a report without the log.

Keep the existing rules available behind config so the operator can A/B
them. Default to the new set in report-only mode.

### B. Domain destinations

- **Destination identity.** Use `DestKey = { kind: 'ip' | 'domain', host,
  port }`.
  - Domain names: lowercase, strip the trailing dot, IDNA/punycode, reject
    garbage.
  - Registrable domain (eTLD+1) via the Public Suffix List. Evaluate a small
    maintained dependency (for example `tldts`: size, license, updates)
    against a vendored snapshot, and recommend one.
- **Never resolve DNS in the webhook hot path.** Resolution costs latency,
  leaks destinations, and CDN answers vary. If resolution is useful at all,
  do it only for a candidate that has already crossed a threshold, bounded
  and cached, and report-only.
- **Never mix domain and IP destinations in one key**, and never put domains
  into /24 geometry.
- **Store hostnames as fixed-size hashes** in state, not as strings.
- **Rules**, recon ports only, 80/443 never:
  - `hammer_target` with a domain key: (user, hostname, recon port), 300 in
    15 minutes;
  - `horizontal_sweep_domains`: distinct registrable domains per (user,
    recon port), at least N in 15 minutes;
  - `subdomain_sweep`: distinct hostnames under one registrable domain on
    recon ports, at least M in 15 minutes. Watch out for corporate jump hosts
    and CDN shards;
  - `session_rate_burst` counts domain and IP sessions together.
- **Choose N and M** with a synthetic sensitivity table, like
  `sensitivity.js`.
- **Out of scope, but document why:** mail ports, web floods, torrent
  trackers by domain, and push/realtime ports.

## Step 2. Implementation

- **Implement in the PR's own code** (`abuse-blocker.state.ts`, the
  observation mapping in `xray-webhook.handler.ts`, schema/contract), so the
  result reads as a patch to PR #46.
  - Keep the diff minimal and idiomatic to the repo.
  - Add schema fields with defaults, so that an old config still parses.
  - Save the full patch against the PR head as
    `docs/pr46-review/detection.patch`.
- **Harness:**
  - `run.js --compare` runs the PR head's rules and the patched rules side
    by side on the same input. The output is one report with both result
    sets, aggregates only;
  - for every rule, report decisions by severity, traffic class and port;
    blocks per node-day; users per flagged source IP; time to first
    decision; and domain destinations seen vs scored;
  - `report.json` must stay free of IPs, user IDs and hostnames. Those may
    appear only in the local decisions JSONL.
- **Performance.** The current harness does about 70k lines/s per core.
  Keep the patched rules at 50k lines/s or more, and measure it on a
  generated 10-million-line log.
- **Memory.** A whole month of one entry node already exceeds a 2 GB V8 heap
  in the current harness. Find out whether the harness or the blocker state
  grows unbounded (for example per-IP user maps or per-hour sets in
  `report.js`) and fix the harness side. Prove the blocker state is bounded
  with a test that feeds 5 M synthetic events from 200 k users and checks
  heap growth.

## Step 3. Synthetic scenarios and tests

Use only documentation IPs and reserved names (`*.example`, `*.test`,
`*.invalid`).

**Keep all existing scenarios.** In addition:
- **Benign:**
  - an app that repeatedly contacts many peers on one unassigned high port,
    like the real 50300/8887 cases (hundreds of distinct IPs per hour on one
    port);
  - LAN-sharing or device-sync apps (53317, 62078);
  - heavy browsing on 600 domains on 443;
  - an API poller on 8443/5228;
  - IMAP on imap.* :993;
  - 5 SSH jump hosts under one domain;
  - CDN shards on 443;
  - tracker announces by domain on :6969;
  - a game launcher contacting 30 domains.
- **True positive:**
  - a random-order SSH sweep at 25/50/500 targets per minute for 15 min;
  - an RDP hammer of 300-400 sessions to one IP and to one hostname;
  - a 700-per-minute non-web burst;
  - an SSH scan of 500 hostnames across 400 domains;
  - subdomain enumeration of 200 hosts on :22/:3389;
  - a mixed IP and domain scan on :23;
  - a scan that crosses midnight.

For every scenario, pin both behaviours (PR head and patched) in tests. Add
a single `node --test` entry point that runs everything, and keep all
existing tests passing.

## Step 4. Documentation

- **`REVIEW.md`:** add a section "Proposed detector changes" with the
  facts, the design summary, the synthetic before/after table, and one line
  that the real-data comparison is pending with the operator.
- **`tools/pr46-replay/README.md`:** give the exact offline command for the
  operator, for example
  `node tools/pr46-replay/run.js --log access.log.* --out report.json --compare`.
  State which report numbers decide success.

**Targets for the operator's real-data re-run.** State them as targets to
measure, not as promises:
- blocks per entry node-day of 0.05 or less, at least 80% of them on recon
  ports;
- at least 80% of confirmed sweeps and hammers reach `alert` or higher;
- throughput of 50k lines/s or more;
- memory bounded on a month of one node.

## Rules

- No real IPs, domains or user data anywhere.
- Small logical commits.
- Finish with a summary covering:
  - what is established from source vs assumed;
  - the changes and their thresholds;
  - the before/after on synthetic data;
  - the measured throughput and memory;
  - exactly what the operator should run.

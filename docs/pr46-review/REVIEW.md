# PR #46 (abuse blocker runtime): offline replay review

Thanks for this PR. Scoring locally, with time-limited blocks, bounded state,
reports with evidence and a coverage flag, is a sound shape, and several
choices already avoid known false positives (UDP is not scored, 80/443 are
excluded). The notes below come from replaying synthetic Xray access logs
through the PR's own code and comparing the result with an operator's
experience of running a similar detector on the same input.

Most of this review uses synthetic data. One section,
[Real traffic](#real-traffic-one-day-four-entry-nodes), is an aggregate-only
replay of one day of production logs, run by the operator on their own
infrastructure. How the blocker works is summarized in
[HOW-IT-WORKS.md](HOW-IT-WORKS.md).

## Summary

- **Shared source addresses get blocked.** Behind CGNAT, one scanning user
  got the shared IP blocked 5 s after the scan started, cutting off the 49
  other users on it for 600 s. On a chain exit node, BitTorrent-over-TCP
  traffic from about 1% of 2,000 people, all scored as one technical user,
  got the entry node's address blocked twice in 30 minutes.
- **Common scanner shapes are not blocked.** A random-order sweep of one port
  never scores above 50 at any rate, because a detector key fires once and
  stays latched while the scan continues. A two-port RTSP sweep stops at
  `alert`. A 300-session RDP hammer and a 700-sessions-per-minute burst do not
  register at all.
- **Consumer false positives mostly stay below the block threshold** with the
  defaults. TCP BitTorrent still reaches `alert`. Exempting the ports the
  operator exempts (possible with the existing `excludedPorts` field) removes
  that alert and the chain-node block.
- **About a month of real traffic from 17 entry nodes** (plus 55 exit nodes,
  4.8 billion log lines in total) shows three problems:
  - The blocker fired 0.83 times per node-day. 86% of those blocks were on
    non-recon ports (BitTorrent and app ports).
  - It blocked 27% of the confirmed horizontal sweeps, and none of the 43
    single-target hammers.
  - Only about 4.5% of lines are scored at all.

  As expected, on chained exit nodes it blocks the entry node's address.
- The PR does not build yet: no published `@remnawave/node-plugins` release
  contains the `abuseBlocker` schema.
- **A tested patch is proposed** in
  [Proposed detector changes](#proposed-detector-changes):
  - report-only default and recon-port scope;
  - sweep, hammer and burst rules with two-pass confirmation;
  - hostname rules and source guards.

  On synthetic data it removes every false block, and every true positive
  still reaches `alert` or higher. The real-data comparison is pending.

## Build status (as-is)

Run with Node 24.21 (the Dockerfile uses 24.19).

| Step | Result on PR head `2e47450` | With the stub below |
|---|---|---|
| `npm ci` | fails: `package-lock.json` still pins `@remnawave/node-plugins@0.6.3` while `package.json` asks for `0.7.0` | passes |
| `npm run typecheck` | fails: 3 x TS2339, `abuseBlocker` does not exist on `TNodePlugin` (`plugin.service.ts:105`, `plugin.service.ts:229`, `abuse-blocker.state.ts:14`) | passes |
| `npm run build` | fails with the same 3 errors | passes |
| PR tests (`tsx --test tests/abuse-blocker/*.test.ts`) | 16 of 25 pass. All 9 failures are in `abuse-blocker.state.test.ts`, where `NodePluginSchema.parse()` strips the unknown `abuseBlocker` key and the state gets `undefined` config | 25 of 25 pass |

- `@remnawave/node-plugins@0.7.0` is published, but neither it nor any later
  release up to `0.8.2` has an `abuseBlocker` key. The schema only exists on
  the author's branch `l0nelynx/backend@staging/abuse-blocker-plugin-schema`
  (`dc5336f`, `libs/node-plugins` 0.7.4).
- The repo has no `test` script, and the tests cannot run under plain
  `node --test`: they need decorator support and the tsconfig path aliases.
  `tsx` was used here.
- `npm run lint` cannot start (`eslint-plugin-perfectionist` is not
  installed). That is repo-wide and unrelated to this PR. `oxfmt --check` flags
  20 files, none of them touched by the PR.
- Three state tests pass even without any config, because they only assert
  `null`: "counts unique destinations and ignores duplicates", "does not
  combine destinations across users or ports", and "respects excluded ports
  and source ignore ranges". Adding a positive control to each would make them
  meaningful (for example, the same input on a non-excluded port does fire).

### Stubs used (complete list)

No file under `src/`, `libs/` or `tests/` was changed.

1. `tools/pr46-replay/stubs/node-plugins/`: a local `@remnawave/node-plugins`
   package. Its schema is copied from the author's branch (`dc5336f`). The only
   edit is removing the unrelated `torrentBlocker.rulePlacement` field, so that
   everything except `abuseBlocker` matches the published `0.7.0`. The compiled
   output is committed.
2. `package.json`: `"@remnawave/node-plugins": "0.7.0"` becomes
   `"file:tools/pr46-replay/stubs/node-plugins"`.
3. `package-lock.json`: regenerated for that one entry.

The harness also swaps a few things in memory, at run time only:
`nftables-napi` and `sockdestroy` are inert stubs, `NftService` is replaced by
a recorder, and `Date` follows replay time while a replay runs.

## Method

- `tools/pr46-replay/run.js` reads Xray access-log lines (TCP, UDP, IPv6,
  with or without `email:`). It turns each accepted line into the webhook
  payload Xray's router would send (`app/router/webhook.go`: `ts` in whole
  seconds, `ip:port` source, destination without the network prefix). It then
  calls the PR's real `XrayWebhookHandler.handle()` with target `abuse`, which
  runs `toAbuseBlockerObservation` and then `AbuseBlockerState.analyze`.
- Events are replayed in timestamp order under a fake clock. The recorder
  writes every decision to JSONL and keeps blocked IPs for `initialBlockSeconds`.
  While an IP is blocked, later lines from it are dropped, as nftables would
  drop them.
- There is one deterministic generator per scenario. They use only RFC 5737,
  RFC 2544, RFC 1918 and RFC 3849 addresses.
- All settings are the schema defaults: `excludedPorts [80, 443]`, horizontal
  20 per /24 in 60 s for +100, sweep 50 in 60 s for +50, block at 150 for
  600 s.
- `tools/pr46-replay/test/scenarios.test.js` pins the actual PR behaviour for
  every row below.

### Operator baseline (the "Expected" column)

This comes from an operator who ran their own detector on the same input
(user, source IP, destination IP and port, time) for about two months. After
manual review, only these signals held up. Each needs confirmation on two
consecutive scoring passes, and the operator runs them report-only by default:

| Rule | Threshold | Window |
|---|---|---|
| `hammer_target`: sessions to one (destination IP, recon port) | 300 or more | 15 min |
| `horizontal_sweep_hard`: distinct /24s on one recon port | 150 or more | 15 min |
| `session_rate_burst`: non-web sessions per user | 600 or more | 60 s |
| `blacklist_hit`: destination in a criminal/C2 feed | any | n/a |

"Recon ports" is a positive list of about 55 ports that generate hoster abuse
tickets (21, 22, 23, 445, 3389, 5900, ...). Rules of the form "N distinct IPs
on one port in a short window" fired mostly on ordinary users, so the operator
demoted them to observe-only. The noisy classes were BitTorrent/DHT, DNS,
NTP, games and realtime apps, mail clients, proxies to the user's own server,
and heavy browsing. Blocking by source IP was judged unsafe behind CGNAT and
on chained nodes. The full operator notes are in [CONTEXT.md](CONTEXT.md).

## Results

| Scenario | Expected (operator baseline) | Actual (PR #46 defaults) | Verdict |
|---|---|---|---|
| BitTorrent/DHT: 300 peers, UDP 6881/51413, 60 s | no action | no block; never scored (UDP is ignored) | Agrees |
| Variant: the same 300 peers over TCP | no action | no block; `destination_sweep` on 51413 then 6881, `alert` (score 100) | Agrees on blocking; reports an alert |
| DNS benchmark: 40 resolvers on :53 in 1 s, 5 users (UDP) | no action | no block; never scored (UDP) | Agrees |
| Variant: the same benchmark over TCP | no action | no block; no report (40 < 50, resolvers spread over /24s) | Agrees |
| NTP pool client: 120 servers on :123, ~3 hits each | no action | no block; never scored (UDP) | Agrees |
| Steam game + WebRTC call + XMPP chat, 1 h | no action | no block; no report | Agrees |
| IMAP client polling :993 every 2-4 s for 1 h (16-address pool) | no action | no block; no report | Agrees |
| Heavy browser: 600 HTTPS destinations in 15 min | no action | no block; never scored (443 excluded, QUIC is UDP) | Agrees |
| CGNAT: 50 users on one IP, one scanning (sequential SSH walk) | flag the scanning user; do not block the shared IP | **block** of the shared IP 5.3 s after the scan starts (`horizontal_scan` x2); 50 userIds on the IP; 49 other users cut off for 600 s | Disagrees: shared IP blocked |
| Chained exit node: 2,000 people as one userId from one internal IP, 30 min | never block; report-only at most | **block** of the entry node's address 12 min 17 s into the log, and again at 22 min 56 s (after the first block expired); both `destination_sweep` on 51413/6881; the report shows 1 userId on the IP | Disagrees: entry node blocked |
| Variant: the same, with nobody running BitTorrent | never block | no block; no report | Agrees in this traffic mix |
| SSH sweep: 200 /24s on :22, random order, 2 min | flag (`horizontal_sweep_hard`) | no block; one `suspicious` (score 50) | Partly detected (report only) |
| Variant: 200 /24s x 25 hosts, sequential, 500 per minute | flag | **block** after 5.3 s (`horizontal_scan` x2) | Detected |
| RTSP sweep: 200 /24s each on 554 and 553, 2 min | flag (`horizontal_sweep_hard`) | no block; `alert` (score 100), one sweep per port | Partly detected (report only) |
| 300 sessions to one host on :3389 in 10 min | flag (`hammer_target`) | no block; no report | Missed |
| 700 non-web sessions in 60 s to 5 database hosts | flag (`session_rate_burst`) | no block; no report | Missed |

Aggregates from the same runs (`node tools/pr46-replay/run-scenarios.js`):

| Scenario | log lines | scored by PR | blocks | blocks / h / 1k userIds | userIds on blocked IP | first block (s into log) | sessions dropped while blocked |
|---|---:|---:|---:|---:|---:|---:|---:|
| cgnat-shared-ip | 9,032 | 116 | 1 | 20 | 50 | 605 (scan starts at 600) | 6,340 |
| chained-exit-node | 179,365 | 4,193 | 2 | 2,000 (1 userId) | 1 | 737 | 103,259 (58%) |
| tp-ssh-sweep-sequential | 5,000 | 45 | 1 | 1,000 (1 userId) | 1 | 5.3 | 4,955 |

The per-1,000-users rate breaks down on a chained node: 2,000 people show up
as one `userId`, so every rate and every "users on this IP" count is off by
three orders of magnitude.

### Scan shape sensitivity

These rows are one user scanning for 15 minutes, with the defaults
(`node tools/pr46-replay/sensitivity.js`). "Random" means uniformly random
targets across 512 /24s.

| Target order | Ports | Targets/min | Highest severity | Max score | Blocked | First block (s) |
|---|---|---:|---|---:|---|---:|
| random | 22 | 10 / 25 | none | 0 | no | - |
| random | 22 | 50 / 100 / 500 / 2000 | suspicious | 50 | no | - |
| random | 23, 2323 | 10 / 25 | none | 0 | no | - |
| random | 23, 2323 | 50 / 100 / 500 / 2000 | alert | 100 | no | - |
| random | 22, 23, 2323 | 10 / 25 | none | 0 | no | - |
| random | 22, 23, 2323 | 50 | blocked | 200 | yes | 59 |
| random | 22, 23, 2323 | 2000 | blocked | 200 | yes | 1.5 |
| sequential | 22 | 10 | none | 0 | no | - |
| sequential | 22 | 25 | blocked | 200 | yes | 655 |
| sequential | 22 | 50 | blocked | 250 | yes | 59 |
| sequential | 22 | 100 | blocked | 250 | yes | 29 |
| sequential | 22 | 500 / 2000 | blocked | 250 | yes | 5.9 / 1.5 |

The block decision depends mostly on target order and on how many ports are
scanned, not on volume. A random single-port scan of 30,000 hosts is never
blocked. A sequential walk at 25 hosts per minute is. The baseline's
`horizontal_sweep_hard` (150 distinct /24s in 15 minutes) would flag every
random row from about 25 targets per minute up. At 10 per minute, a random
scan covers only about 130 distinct /24s in 15 minutes.

### What-if: exempting the operator's noisy ports

The operator's exemptions fit the PR's existing `excludedPorts` field. The
list has 144 entries: 53, 853, 123, torrent, Steam, STUN/TURN, XMPP, push,
mail, and 1080/3128/5060/8080/8443
(`tools/pr46-replay/configs/excluded-ports-context.json`). Rerun with
`node tools/pr46-replay/run-scenarios.js --config tools/pr46-replay/configs/excluded-ports-context.json`:

- TCP BitTorrent: `alert` becomes no report.
- Chained exit node: 2 blocks become no block.
- CGNAT: still blocks the shared IP, because the scan is on :22.
- True positives: unchanged. The misses need different rules, not different
  ports.

## Real traffic: one day, four entry nodes

The operator replayed one full UTC day of September 2026 from four entry
(bridge) nodes through the same harness at commit `ed65fff`. Each node sits
with a different hosting provider, and users connect to them directly.

- **Isolation.** The code ran only in `node:24` containers. Dependencies were
  installed with no log data mounted. The replay itself ran with
  `--network none`, as a non-root user, with code and logs mounted read-only.
- **Data handling.** Only the aggregate `report.json` files left the host.
  The extracted logs and the per-decision JSONL (user IDs, client IPs) were
  deleted after the run.
- **Settings.** Two passes per node: schema defaults, and defaults plus the
  144-port exemption list (`configs/excluded-ports-context.json`).
- **Self-test.** The harness self-test passed on the host: 34 of 34.

### Input

| Node | Log lines | TCP | TCP with a domain destination | Excluded 80/443 | Scored by PR | Active users | Client IPs |
|---|---:|---:|---:|---:|---:|---:|---:|
| A | 11.0 M | 10.45 M | 7.42 M (71%) | 2.57 M | 467 k (4.2%) | 3,535 | 22,319 |
| B | 8.1 M | 7.64 M | 5.25 M (69%) | 2.01 M | 376 k (4.6%) | 3,711 | 22,990 |
| C | 4.7 M | 4.44 M | 3.16 M (71%) | 1.06 M | 213 k (4.5%) | 3,079 | 17,277 |
| D | 12.8 M | 11.73 M | 8.11 M (69%) | 3.03 M | 598 k (4.7%) | 3,507 | 22,144 |
| Total | 36.6 M | 34.26 M | 23.94 M (70%) | 8.67 M | 1.66 M (4.5%) | 13,832 user-days | |

Of the events that were scored, 39-53% were game/realtime ports and 27-36%
were DNS over TCP. Only 2.2-3.0% were recon ports.

### Decisions

| Node | Defaults | With exemptions | Operator's detector, same day |
|---|---|---|---|
| A | none | none | 4 × `session_rate_burst` (1 user) |
| B | 4 × `suspicious`, 1 × `alert`, **1 block**: `destination_sweep` on :6881 (BitTorrent), 1 user on the IP, 622 sessions dropped for 600 s | none | nothing scan-related |
| C | none | none | nothing scan-related |
| D | 2 × `suspicious` (score 50), `destination_sweep` on :22 | same | 1 × `horizontal_sweep_hard` on :22, 21 min |

`blacklist_hit` records from the operator's detector are left out of the
last column, because PR #46 has no blocklist rule.

What this shows:

- **False blocks are rare with the defaults:** 1 in 4 node-days, about 0.01
  blocks per hour per 1,000 active users. The one block was BitTorrent,
  exactly the class the synthetic run predicted. The port exemption list
  removes it.
- **The one real scan of the day was not blocked.** Node D carried an SSH
  sweep that the operator's detector confirmed. PR #46 reported it once as
  `suspicious` (score 50) 14 minutes after it started and never scored it
  again. That matches the latching behaviour described in the sensitivity
  section.
- **The `session_rate_burst` cases on node A produced no report.** This
  matches the synthetic miss.
- **CGNAT and chained nodes did not come up.** Every source IP with a
  decision had one user. Exit nodes were not replayed.
- **Coverage is the main limit.** About 70% of TCP sessions on entry nodes
  have a domain destination, and the harness does not score them (see
  "Access log vs webhook" below). Scanners mostly target IPs, so this matters
  less for recon than the number suggests. It still means the blocker sees a
  small slice of the traffic.

One day on four nodes is a small sample. The full replay below extends it to
the whole fleet and all retained logs.

## Real traffic: all retained logs, whole fleet

Same harness (`ed65fff`), schema defaults, same isolation and data handling
as above. There were two differences:
- The logs were mounted read-only in place, with no copies.
- Every node with retained raw logs was included: 55 exit nodes and 17 entry
  nodes. A few entry nodes have since been retired. Coverage runs from late
  August to late September 2026, about a month.

Only aggregates left the host. The per-decision files were deleted.

| | Exit nodes | Entry nodes |
|---|---:|---:|
| Nodes | 55 | 17 |
| Node-days | 1,340 | 353 |
| Log lines | 2.01 B | 2.76 B |
| TCP sessions with a domain destination | 81% | 68% |
| Lines scored by PR #46 | 88 M (4.4%) | 132 M (4.8%) |
| Blocks | 154 on 33 nodes | 294 (33 distinct users) |
| Blocks per node-day | 0.115 | 0.83 |
| Sessions dropped while blocked | 2.18 M | 275 k |

On chained exit nodes the result is as expected: all 154 blocks hit an entry
node's internal mesh address. Suggestion 2 below covers this; the rest of
this section is about entry nodes.

### Entry nodes: frequent, mostly non-scan blocks

- **By severity:** 436 `suspicious`, 197 `alert` and 294 `blocked`.
- **Blocks by traffic class:**
  - other (unassigned) ports 173 (59%);
  - BitTorrent 59;
  - recon ports 40 (14%);
  - game/realtime 13;
  - DNS 8;
  - alt-proxy 1.
- **The top blocked ports were app traffic, not scans:**

  | Port | Blocks | Users |
  |---|---:|---:|
  | 50300 | 85 | 2 |
  | 6881 | 51 | 5 |
  | 8887 | 19 | 1 |
  | 53317 | 16 | 7 |
  | 22 | 13 | 4 |
  | 62078 (Apple device sync) | 12 | 1 |
  | 554 | 11 | 4 |

  A few users are blocked again and again for their normal app traffic.
- **Shared addresses.** Blocked source IPs carried one user in most cases.
  In 12 per-day reports, a blocked IP carried 2-5 users, and 2 bystanders
  lost sessions. CGNAT collateral exists but was small here. This fleet's
  users mostly connect from distinct addresses.

### Recall against the operator's confirmed incidents

- **What was matched.** Actionable incidents from the operator's detector
  inside the replay's time coverage were matched to PR #46 decisions on the
  same entry node, within ±1 h, on the same port. For `session_rate_burst`,
  any port counts.
- **Match on node and time only.** Users cannot be matched, because the
  operator's history stores only keyed user hashes. The figures are
  therefore an **upper bound** on recall.

| Operator incident | In coverage | PR #46 blocked | alert | suspicious | nothing |
|---|---:|---:|---:|---:|---:|
| `horizontal_sweep_hard` (>= 150 /24s on a recon port) | 55 | 15 (27%) | 9 | 12 | 19 (35%) |
| `hammer_target` (>= 300 sessions to one host:port) | 43 | 0 | 0 | 3 | 40 (93%) |
| `session_rate_burst` (>= 600 non-web sessions/min) | 116 | 13 (11%) | 8 | 8 | 87 (75%) |

This matches the synthetic findings:
- sweeps are caught only partly, because of the latching key;
- single-target hammers and rate bursts are outside what the rules measure.

### Caveats of the full run

- **Day boundaries.** For 14 entry nodes, a whole-period replay ran out of
  V8 heap, so they were replayed one UTC day at a time. Scoring state does
  not carry across midnight, so a scan that spans midnight is scored in two
  halves.
- **Log rotation.** Exit nodes were replayed one whole period per node, and
  the host rotates logs hourly by renaming. A rotation during a run can skip
  or shift up to one hour out of about 650 for that node. Entry nodes were
  replayed from a frozen hardlink snapshot and are not affected.
- **Domain destinations** are not scored. See "Access log vs webhook" below.

## Suggestions

These are minimal and ordered by how much risk they remove.

1. **Default to report-only.** Make blocking an explicit per-node opt-in, for
   example `mode: z.enum(['report', 'block']).default('report')` in the plugin
   schema and in `AbuseBlockerPolicySchema`. In `handleAbuseBlocker`, call
   `blockAbuseIp` only when `analysis.shouldBlock && policy.mode === 'block'`,
   and keep reporting `severity: 'blocked'` with `action: 'none'` otherwise.
   Operators can then run it for a while and look at the reports before they
   enable blocking.
2. **Never block a shared source.** Before `blockAbuseIp`:
   - refuse non-public sources (10/8, 172.16/12, 192.168/16, 100.64/10,
     127/8, fc00::/7, fe80::/10). Mesh or entry-node traffic usually arrives
     from these;
   - keep a small bounded `sourceIp -> {userId: lastSeen}` map and refuse to
     block when more than one or two `userId`s used the IP in the last hour
     (CGNAT);
   - add `reportOnlyInboundTags` (the webhook already carries `inboundTag`)
     so that operators can mark the inbound that receives chained traffic, and
     `reportOnlyUserIds` for technical users. `ignoreLists.userId` drops
     events entirely, which also hides the chain's reports.
   In each case, report with a reason such as `shared_source` instead of
   blocking.
3. **Record the users-per-source-IP count and `inboundTag`** on every report
   (for example `sourceIpUserCount`). The review above had to reconstruct both
   from the log. The panel needs them to judge a block.
4. **Scope the scan rules to recon ports.** Replace or complement
   `excludedPorts` with a positive `scanPorts` list, defaulting to the recon
   ports, and check it with a `Set` (`excludedPorts.includes()` runs on every
   event). If a denylist is preferred, the 144-port list above is a drop-in
   default.
5. **Match what blocks to the geometry that holds up in practice.** For
   anything that can block:
   - count distinct /24s per (user, recon port) over 15 minutes, firing at
     150, instead of distinct IPs per 60 seconds. This catches random-order
     sweeps and ignores dense CDN pools;
   - add a sessions-per-(destination IP, recon port) counter over 15 minutes
     (300) and a non-web sessions-per-user counter over 60 seconds (600).
     Neither needs per-destination memory beyond a counter;
   - require the condition on two consecutive passes (for example, still true
     60 seconds after the first firing) before `shouldBlock`;
   - let a key re-fire after the cooldown while it stays above its threshold.
     Today `fired` resets only when the count drops below the threshold, so a
     steady scan is scored exactly once, and the longest scans score least.
6. **Smaller items:**
   - update `package-lock.json` and add a `test` script with a runner that
     supports decorators and path aliases;
   - `repeatBlockSeconds` and `repeatWindowSeconds` are sent in the policy but
     unused on the node. If the panel escalates through `refresh-block`, a
     comment would help; otherwise they could be dropped;
   - after a user crosses 150, every later firing calls `blockAbuseIp` again,
     for whatever IP that event came from. It would help to decide whether a
     re-add should extend the timeout, since `nft add element` on an existing
     element may not refresh it;
   - applying a changed plugin config calls `recreateTables()` and clears all
     active abuse blocks. That may be intended, but it is worth documenting.

## Proposed detector changes

Branch `review/pr46-detection` turns the suggestions above into a tested
patch to the PR's own files: `abuse-blocker.state.ts`,
`xray-webhook.handler.ts`, the report contract and the `abuseBlocker` plugin
schema. [DETECTION-DESIGN.md](DETECTION-DESIGN.md) has the details.
`docs/pr46-review/detection.patch` is the diff against the PR head, and
`detection-node-plugins.patch` is the schema diff for `libs/node-plugins`.

### Facts from Xray (v26.7.28)

See [DETECTION-FACTS.md](DETECTION-FACTS.md) for file:line references.

- **A request by name never carries an IP.** The routing webhook reports
  `destination: "example.com:443"` and `originalTarget:
  "tcp:example.com:443"`. It is fired with the unresolved routing context,
  even when `IPIfNonMatch` or `IPOnDemand` resolved the name for rule
  matching. The freedom outbound resolves only later. The 68-81% of TCP
  sessions that the PR drops are therefore invisible to IP rules on the node
  itself, not only in the harness.
- **When the client connected by IP,** that IP is always in
  `originalTarget`, whatever the sniffing settings.
- **Abuse webhooks are not deduplicated.** Xray deduplicates per `email`
  only when `deduplication > 0`, and PR #46 sets 0. Every matched TCP
  connection is posted, so session-rate rules are feasible. Delivery is
  best-effort (one goroutine per event, 5 s timeout, no retry), so counts are
  lower bounds.

### What changes

- **Report-only by default** (`mode: "report"`). The new rule set is the
  default (`ruleSet: "v2"`); the PR #46 rules stay available (`legacy`, or
  `both` for A/B). `configs/pr46-head-equivalent.json` reproduces the PR head
  exactly, and a test checks this on every scenario.
- **Recon-port scope** (`scanPorts`, 56 ports, a `Set`). No other port can
  lead to a block. They feed only the report-only session counter.
- **Latch fix.** A key that stays above its threshold fires again after the
  cooldown.
- **New rules**, each with a candidate report and then a confirmation at
  least 60 s later, which is the only way to reach a block:
  - `horizontal_sweep`: 150 distinct /24s (IPv6 /48) per user and recon port
    in 15 minutes;
  - `hammer_target`: 300 sessions to one IP or hostname on a recon port in
    15 minutes;
  - `session_rate_burst`: 600 non-web sessions per minute. Report-only.
- **Hostname destinations**, never resolved, stored as hashes. Registrable
  domains come from `tldts`.
  - `hammer_target` also counts by hostname;
  - `horizontal_sweep_domains`: 50 registrable domains per user and recon
    port in 15 minutes;
  - `subdomain_sweep`: 100 hostnames under one domain in 15 minutes.
    Report-only, because an administrator's own fleet looks the same.
- **Source guards.** No block for non-public sources, for sources that
  carried more than one user in the last hour (`shared_source`), or for
  listed users or inbounds. Each becomes a report with a `skipReason`.
- **New report fields:** `sourceIpUserCount`, `inboundTag`,
  `destinationHost`, and the rule's raw `count`, `unit` and `phase`.
- **Performance.**
  - IP validity checks without BigInt;
  - early exits in the observation mapping;
  - an LRU eviction that no longer rescans deleted slots. The PR head's user
    LRU degrades to O(n) per eviction once a node exceeds `maxTrackedUsers`.

### Synthetic before/after

These results come from `node tools/pr46-replay/run-scenarios.js`, with the
patched rules in block mode to show what they would block. Every row is
pinned in `test/compare.spec.js`.

| Scenario | PR #46 head | Patched |
|---|---|---|
| App peers on :50300 / :8887 (80 new peers per burst, 6 bursts/h) | 2 blocks each | nothing |
| LAN-sync /24 walks on :53317 and :62078 | 10 blocks | nothing |
| BitTorrent over TCP (300 peers in 60 s) | `alert` | `alert` from `session_rate_burst` (report-only) |
| Hostname traffic: 600-name browsing, CDN shards, IMAP by name, 5 SSH jump hosts, tracker announces, game launcher, API poller | nothing | nothing |
| DNS, NTP, BitTorrent/DHT over UDP, Steam/WebRTC/XMPP, IMAP polling, heavy browsing | nothing | nothing |
| CGNAT: 50 users on one IP, one sequential SSH scanner | 1 block, 49 other users cut off | confirmed, but `shared_source`: not blocked |
| Chained exit node, 2,000 people as one user | 2 blocks of the entry node | nothing (would be `non_public_source` anyway) |
| SSH sweep, random order, 25 / 50 / 500 targets per minute for 15 min | nothing / `suspicious` / `suspicious` | block after confirmation, all three |
| SSH sweep, 200 /24s in 2 min (random) | `suspicious` | `alert` (too short to confirm) |
| SSH sweep, sequential, 500 per minute | block after 5 s | block after 507 s |
| RTSP sweep, 200 /24s per port in 2 min | `alert` | `alert` |
| RDP hammer, 300 sessions to one IP or hostname | nothing | `alert` |
| RDP hammer, 400 sessions to one IP or hostname | nothing | block |
| 700 non-web sessions in 60 s | nothing | `alert` (report-only rule) |
| SSH scan of 500 hostnames across 400 domains | nothing | block (`horizontal_sweep_domains`) |
| Subdomain enumeration, 200 names on :22/:3389 | nothing | `alert` (report-only rule) |
| Telnet scan mixing 300 IPs and 200 hostnames | nothing | block |
| Random SSH sweep crossing midnight, 20 per minute | nothing | block in one continuous replay; nothing in two per-day halves |

In short:

- **No benign scenario blocks.** The PR head blocked 5 of them.
- **Every true positive reaches `alert` or higher.** Sustained scans and
  hammers block after confirmation.
- **Short bursts only report.** This is intended: the confirmation step
  trades a slower block for precision.

**Sweep shape.** One user scanning for 15 minutes
(`node tools/pr46-replay/sensitivity.js`); times are seconds to the first
block.

| Target order | Ports | Targets/min | PR #46 head | Patched |
|---|---|---:|---|---|
| random | 22 | 10 | nothing | nothing |
| random | 22 | 25 | nothing | block (499 s) |
| random | 22 | 50 / 100 / 500 / 2000 | `suspicious` | block (275 / 165 / 79 / 65 s) |
| random | 23, 2323 | 25 | nothing | block (499 s) |
| random | 23, 2323 | 50 to 2000 | `alert` | block (275 to 65 s) |
| random | 22, 23, 2323 | 50 / 500 / 2000 | block (59 / 5.9 / 1.5 s) | block (275 / 79 / 65 s) |
| sequential, whole /24s | 22 | 25 to 500 | block (655 to 5.9 s) | nothing |
| sequential, whole /24s | 22 | 2000 | block (1.5 s) | `alert` (`session_rate_burst`) |

- **Random sweeps.** The patched rules block every random-order sweep from
  25 targets per minute up, on one port or several. They block later than the
  PR head, because they need 150 /24s and then a confirmation.
- **Dense sequential walks.** A walk that stays inside fewer than 150 /24s in
  15 minutes is not seen. The operator's own detector does not act on that
  shape either. `ruleSet: "both"` keeps the PR #46 geometry for it, as
  reports only.

**Hostname thresholds** (`node tools/pr46-replay/sensitivity-domains.js`):

- **N = 50 registrable domains per recon port.** The busiest benign case,
  SSH to 8 own servers in 8 domains, stays at 8. Scans fire at these points:
  - 100 domains in 10 minutes: after about 5 minutes;
  - 400 domains in 10 minutes: after 74 s;
  - 200 domains spread over an hour: after about 15 minutes.
- **M = 100 hostnames under one domain.** An Ansible run over 40 hosts of
  one domain stays at 40. Enumerating 200 names in 10 or 30 minutes fires.
  M = 50 would sit close to the Ansible case. The rule is report-only either
  way.

### Harness changes for the re-run

- **`--compare`.** `run.js --compare` replays the PR head files (kept
  verbatim in `tools/pr46-replay/pr-head/`) and the patched code side by
  side, and writes one aggregate report with both result sets.
- **Memory.** The harness's own per-IP and per-hour state was unbounded; that
  is what exhausted the 2 GB heap on a month of one node. It is now bounded,
  so a month replays in one run and scans across midnight are no longer split.
- **Measured on a generated 10-million-line entry-node log**
  (`tools/pr46-replay/bench.js`), with a 512 MB heap cap:

  | Run | Lines per second | Heap after GC, at 1 M then 10 M lines |
  |---|---:|---|
  | patched only, 512 MB cap | 55,990 | 59 MB, then 59 MB (flat) |
  | PR head only | 72,302 | 87 MB, rising to 362 MB |
  | both (`--compare`), 1 GB cap | 34,276 | 102 MB, rising to 377 MB (the head's state) |

  The heap figures come from `--heap-samples 1000000`, which forces a GC
  every million lines.

- **The PR head's state is bounded, but large and still growing.**
  - It keeps one detector key per (port, /24) per user, up to
    `maxKeysPerUser` (256). Stale keys leave only through that LRU.
  - On this log, 4,000 users grew it linearly to 362 MB in 10 M lines, about
    one day of one entry node. The ceiling is `maxTrackedUsers x
    maxKeysPerUser` keys.
  - A month-long `--compare` run therefore needs a larger heap for the head
    variant (`--max-old-space-size=2048` is suggested). A patched-only run
    does not.
- **The patched rules.**
  - They keep keys for recon ports only.
  - A key with nothing in its window and no running cooldown is dropped
    before a new one is added.
  - Their state stays flat instead of filling up to the caps.

**The real-data comparison is pending with the operator**, using the exact
command and success criteria in `tools/pr46-replay/README.md`.

## Not verified

- **Real traffic, beyond one day.** Apart from the one-day replay above, all
  fixtures are synthetic. The benign traffic model
  (`tools/pr46-replay/fixtures/benign-user.js`) uses assumed pool sizes and
  rates. The chained-node blocks depend on the roughly 1% of people who run
  BitTorrent over TCP. With nobody doing so, there was no block in 30 minutes;
  60 minutes and 4,000 people were also checked ad hoc. No exit node and no
  CGNAT case was observed in real data.
- **Access log vs webhook.**
  - Now established from source (DETECTION-FACTS.md §2): the access log's
    destination is exactly the webhook's `originalTarget`, so the domain
    share the harness reports is the PR's own blind spot.
  - Still not modelled: a domain added by `routeOnly` sniffing when the
    client connected by IP (the PR uses the IP in that case anyway), rules
    that already had a webhook, and Torrent Blocker's `bittorrent` rule
    (assumed off).
- **The proposed detector changes** were tested on synthetic data only. N
  (50) and M (100) for the hostname rules were chosen on synthetic cases.
  The real-data comparison is pending with the operator.
- **nftables and kernel behaviour.** This includes timeout refresh on re-add
  and the actual connection drop. The panel side (report collection,
  `refresh-block` escalation) and the cost of one webhook per TCP connection
  were not measured either.
- **Schema defaults.** They come from the author's unreleased branch and may
  still change.

## Reproduce

```sh
git checkout review/pr46-replay && npm ci        # Node 24
node --test 'tools/pr46-replay/test/*.test.js'   # 34 tests, ~10 s
node tools/pr46-replay/run-scenarios.js          # the Results table
node tools/pr46-replay/sensitivity.js            # the sensitivity table
node tools/pr46-replay/run.js --log access.log --out report.json   # any real log, offline
```

For the proposed detector changes:

```sh
git checkout review/pr46-detection && npm ci
node --test tools/pr46-replay/test/all.test.js                     # everything, including the PR's own tests
node tools/pr46-replay/run-scenarios.js                            # the before/after table
node tools/pr46-replay/sensitivity.js                              # sweeps, head vs patched
node tools/pr46-replay/sensitivity-domains.js                      # N and M for the hostname rules
node tools/pr46-replay/run.js --log access.log* --out report.json --compare   # real logs, offline
```

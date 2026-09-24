# PR #46 (abuse blocker runtime): offline replay review

Thanks for this PR. Scoring locally, with time-limited blocks, bounded state,
reports with evidence and a coverage flag, is a sound shape, and several
choices already avoid known false positives (UDP is not scored, 80/443 are
excluded). The notes below come from replaying synthetic Xray access logs
through the PR's own code and comparing the result with an operator's
experience of running a similar detector on the same input.

Everything here is synthetic. No production logs were used. How the blocker
works is summarized in [HOW-IT-WORKS.md](HOW-IT-WORKS.md).

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
- The PR does not build yet: no published `@remnawave/node-plugins` release
  contains the `abuseBlocker` schema.

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
on chained nodes.

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

## Not verified

- **Real traffic.** All fixtures are synthetic, and the benign traffic model
  (`tools/pr46-replay/fixtures/benign-user.js`) uses assumed pool sizes and
  rates. The chained-node blocks depend on the roughly 1% of people who run
  BitTorrent over TCP. With nobody doing so, there was no block in 30 minutes;
  60 minutes and 4,000 people were also checked ad hoc.
- **Access log vs webhook.** The access log has no
  `originalTarget`/`routeTarget` and no sniffed protocol. Lines with a domain
  destination are therefore not scored, rules that already had a webhook are
  not modelled, and Torrent Blocker's `bittorrent` rule is assumed off.
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

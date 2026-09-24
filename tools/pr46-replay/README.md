# PR #46 replay harness

Replays Xray access logs through the real PR #46 abuse blocker code
(`XrayWebhookHandler` + `AbuseBlockerState`, schema defaults) without nftables,
root or network. The block action is replaced by a recorder.

## Setup (once, needs network)

```sh
git checkout review/pr46-replay
npm ci            # Node 24, as in docker/Dockerfile
```

`npm ci` works because `package.json` points `@remnawave/node-plugins` at the
stub in `stubs/node-plugins` (see its README).

## Replay a log (offline)

```sh
node tools/pr46-replay/run.js --log /var/log/remnanode/access.log --out report.json
```

- `--log` may be repeated for rotated files, oldest first; `.gz` is read directly.
- `report.json` holds aggregates only (no IPs, no user IDs) and can be shared.
- `report.decisions.jsonl` (or `--decisions <path>`) has one line per blocker
  decision: `time, userId, sourceIp, rule, score, action` (+ `severity`,
  `destinationPort`, `trafficClass`, `keys`, `repeat`). It contains user IDs
  and client IPs: keep it local.
- `--config abuse.json` merges settings into `abuseBlocker`, e.g.
  `{"blockScore": 300, "excludedPorts": [80, 443, 53, 123]}`. Shared `ext:`
  lists are not resolved; inline the addresses.
- `--open-loop` keeps scoring events from an IP after it was "blocked". By
  default they are dropped (and counted), as nftables would drop them.
- `--sub-second` keeps log precision; by default timestamps are cut to whole
  seconds, like the `ts` in Xray's webhook.

Throughput is roughly 70,000 lines per second on one core.

### What the replay does and does not model

- Input is the access log, not the webhook. Each `accepted` line is treated as
  one webhook call. The log has no `originalTarget`/`routeTarget`, so
  connections logged with a domain destination are not scored (the PR also
  drops domain-only targets). `rejected` lines are skipped.
- Every connection is assumed to reach the abuse webhook (coverage `full`).
  Rules that already had a webhook, Torrent Blocker's `bittorrent` rule, and
  anything the node's routing never sends through a rule with the webhook are
  not modelled.
- Reports are flushed after every event instead of being collected by the
  panel. This only changes the evidence lists, not scores or blocks.
- The report's `usersPerBlockedSourceIp` counts `email`s seen on the address.
  Behind a chain, one technical `email` may stand for thousands of people.

## Report fields

| Field | Meaning |
|---|---|
| `blocks.perHourPer1000ActiveUsers` | blocks / max(1, log hours) / distinct active userIds x 1000 |
| `blocks.hourly` | the same per clock hour of the log |
| `blocks.byTrafficClass`, `byDestinationPort`, `byRule` | what triggered each block, port classes from CONTEXT.md |
| `usersPerBlockedSourceIp` | distinct userIds on each blocked IP (last hour before the block, and whole log) |
| `collateral` | sessions and users dropped while an IP was blocked (closed loop) |
| `timeToFirstBlock` | from the start of the log, and from the blocked user's first line |
| `scoringInput` | why lines never reached scoring (UDP, no numeric email, domain target, excluded port) |

## Synthetic scenarios and tests

```sh
node --test 'tools/pr46-replay/test/*.test.js'     # harness + one test per scenario (~10 s)
node tools/pr46-replay/run-scenarios.js            # review table, reports in tools/pr46-replay/out/
node tools/pr46-replay/run-scenarios.js --write-logs   # also writes fixtures/out/<scenario>.log
node tools/pr46-replay/sensitivity.js              # scan order x ports x rate
```

Generators live in `fixtures/`, one per scenario, and use only documentation or
reserved addresses (RFC 5737, RFC 2544, RFC 1918, RFC 3849). They are
deterministic (seeded).

The PR's own TypeScript tests need a runner that understands decorators and the
tsconfig path aliases, for example `npx tsx --test tests/abuse-blocker/*.test.ts`.

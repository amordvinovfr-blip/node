# PR #46 replay harness

Replays Xray access logs through the real abuse-blocker code (`XrayWebhookHandler` +
`AbuseBlockerState`) without nftables, root or network. The block action is
replaced by a recorder. Two variants can run side by side on the same input:

- **`head`**: the PR #46 head detector files, kept verbatim in `pr-head/`;
- **`patched`**: the code on this branch (the proposed detector changes, see
  `docs/pr46-review/DETECTION-DESIGN.md`).

## Setup (once, needs network)

```sh
git checkout review/pr46-detection
npm ci            # Node 24, as in docker/Dockerfile
```

`npm ci` works because `package.json` points `@remnawave/node-plugins` at the
stub in `stubs/node-plugins` (see its README).

## Operator run: PR head vs patched (offline)

```sh
node tools/pr46-replay/run.js --log /path/to/access.log* --out report.json --compare
```

- **Input files.** `--log` takes any number of files, including a shell glob,
  `.gz` files and `-` for stdin. Files are replayed in order of their first
  timestamp, so rotation order does not matter.
- **One node per run.** Replay a whole month continuously; memory is bounded
  (see below), so there is no need to split by day. If you merge several
  nodes into one run, pass `--nodes <n>` so the per-node-day rates stay right.
- **Heap.** The PR head's own state grows up to `maxKeysPerUser` (256)
  keys per user (362 MB after 10 M lines with 4,000 users). For a month-long
  `--compare` run, start Node with `--max-old-space-size=2048`, that is
  `node --max-old-space-size=2048 tools/pr46-replay/run.js ...`. The patched
  variant alone stays flat, at about 60 MB on that log.
- **Block mode.** The patched variant runs with `mode: block` (`--patched-mode block`,
  the default) so the report shows what blocking *would* do. The shipped
  default is `mode: report`.
- **Output files.** `report.json` holds aggregates only (no IPs, user IDs
  or hostnames) and can be shared. `report.decisions.jsonl` has one line per
  decision, with `variant`, `time`, `userId`, `sourceIp`, `destinationIp` or
  `destinationHost`, `destinationPort`, `rules`, `phases`, `score`,
  `severity`, `action` and `skipReason`. It is needed to match your confirmed
  incidents; keep it local and delete it afterwards.
- **Other options:**
  - `--config file.json` changes settings for both variants;
    `--config-head` and `--config-patched` change one only. For example
    `{"sourceGuards": {"reportOnlyInboundTags": ["MESH"]}}`;
  - `--config-patched tools/pr46-replay/configs/pr46-head-equivalent.json`
    makes the patched code behave exactly like the PR head;
  - `--variant head|patched` runs a single variant;
  - `--open-loop` and `--sub-second` work as before;
  - `--heap-samples <n>` forces a GC every n lines and records the heap
    (`harness.heapAfterGcMb`).

### Which numbers decide success

For each entry node, compare `variants.head` with `variants.patched` in
`report.json`:

| Target | Where to read it |
|---|---|
| blocks per entry node-day of 0.05 or less | `variants.patched.blocks.perNodeDay` |
| at least 80% of those blocks on recon ports | `variants.patched.blocks.onReconPortsShare` |
| at least 80% of confirmed sweeps and hammers reach `alert` or higher | match your incidents against `report.decisions.jsonl` (`variant: "patched"`, same node, ±1 h, same port; severity `alert` or `blocked`), as in the previous recall table |
| 50,000 lines per second or more | `run.linesPerSecond` of a `--variant patched` run (`--compare` runs both variants and is slower) |
| memory bounded on a month of one node | a `--variant patched` run with `--heap-samples 10000000`: `harness.heapAfterGcMb` should stay flat, and the run should finish under `node --max-old-space-size=1024` |

Useful context in the same report:

- **Rules:** `variants.<v>.rules.<rule>`, with decisions by severity, phase,
  traffic class and port, and the time to first decision.
- **Decisions:** `variants.patched.decisions.bySkipReason`
  (`shared_source`, `non_public_source`, ...), which shows blocks the guards
  turned into reports.
- **Users per IP:** `usersPerFlaggedSourceIp` and `usersPerBlockedSourceIp`.
- **Domain coverage:** `variants.patched.domainDestinations`, which gives
  seen, observed, `reachedDomainRules` (scan ports) and
  `countedBySessionRate`.

## Report fields

| Field | Meaning |
|---|---|
| `input` | lines, networks, TCP destinations by IP vs hostname, active users, distinct source IPs (HyperLogLog estimate) |
| `variants.<v>.scoringInput` | why lines never reached the rules (UDP, no numeric email, no IP target, ignore lists, excluded port, outside `scanPorts`) |
| `variants.<v>.rules` | per rule: decisions, blocks, severity, phase, traffic class, port, time to first decision |
| `variants.<v>.blocks` | total, `perNodeDay`, per hour per 1,000 active users, recon share, by class, port, rule and hour |
| `variants.<v>.usersPerFlaggedSourceIp`, `usersPerBlockedSourceIp` | distinct userIds on the IP in the hour before the decision; a chained entry node shows 1 however many people it carries |
| `variants.<v>.collateral` | sessions and users dropped while an IP was blocked (closed loop) |
| `variants.<v>.timeToFirstDecision`, `timeToFirstBlock` | seconds from the log start, and from the blocked user's first line |
| `run` | files, seconds, lines per second, heap and RSS at the end |

### What the replay does and does not model

- **Access log as the webhook.** Each `accepted` line is treated as one
  webhook call. The log's destination is what the client asked for, which
  Xray also puts into `originalTarget` (see `DETECTION-FACTS.md`). A domain
  that sniffing added with `routeOnly` is not in the log, which matters only
  when the client connected by IP. `rejected` lines are skipped.
- **Coverage.** Every connection is assumed to reach the abuse webhook
  (coverage `full`). Rules that already had a webhook, and Torrent Blocker's
  `bittorrent` rule, are not modelled.
- **Reports** are flushed after every event instead of being collected by the
  panel. This changes only the evidence lists.
- **Shortcuts that do not change decisions:**
  - the observation computed for labelling is handed to the handler for the
    same event (same PR function, computed once);
  - debug timing strings are not formatted, because logs are silenced.

### Memory

Memory is bounded, so a month of one node replays in one run:

- distinct source IPs are estimated with a HyperLogLog;
- users per source IP live in an LRU (`--max-sources`, default 200,000);
- per-hour user sets are closed as time advances.

The old harness kept per-IP maps and per-hour sets for the whole log, and ran
out of a 2 GB heap on a month of one node. The blocker state's own bounds
are listed in `DETECTION-DESIGN.md`. `test/memory.spec.js` feeds 5 M events
from 200 k users into it and checks heap growth.

## Tests, scenarios and benchmarks

```sh
node --test tools/pr46-replay/test/all.test.js     # everything: harness specs + the PR's own TypeScript tests
node tools/pr46-replay/run-scenarios.js            # before/after table for all scenarios
node tools/pr46-replay/sensitivity.js              # sweeps: order x ports x rate, head vs patched
node tools/pr46-replay/sensitivity-domains.js      # choosing N and M for the hostname rules
node tools/pr46-replay/bench.js --lines 10000000 --out tools/pr46-replay/out/bench.log
```

- **All tests.** `all.test.js` also runs `tests/abuse-blocker/*.test.ts`
  through the harness's TypeScript loader, so `tsx` is not needed.
- **Scenarios.** The generators live in `fixtures/`, one per scenario. They
  use only documentation or reserved addresses (RFC 5737, RFC 2544, RFC 3849)
  and `.example` names, with a few older scenarios using RFC 1918. They are
  deterministic (seeded).
- **Benchmark.** `bench.js` writes an entry-node-shaped log for throughput
  and memory runs.

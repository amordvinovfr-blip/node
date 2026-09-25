Read CONTEXT.md in the repo root first. It is operator experience from a
production fleet and it is the basis for this review.

Task: build an offline replay harness for the abuse blocker from PR #46 and
test it against the false-positive classes in CONTEXT.md. Work only with
synthetic data. You have no real logs, and none will be provided.

Steps:

1. Fetch PR #46 (`git fetch origin pull/46/head:pr-46`, then check it out on a
   new branch `review/pr46-replay`). Install, build, and run the PR's own tests
   and typecheck. Report results as-is. If something fails because
   `@remnawave/node-plugins@0.7.0` is unpublished, say so and stub only what is
   needed.

2. Read the blocker's scoring, state and nftables code. Write a short summary
   (docs/pr46-review/HOW-IT-WORKS.md): input event shape, windows, points per
   rule, thresholds, what exactly gets blocked and for how long, and whether it
   can tell a chained or technical user apart.

3. Build a replay harness (tools/pr46-replay/):
   - Input: Xray access.log lines in the standard format:
     `2026/09/20 12:00:00.123456 from 203.0.113.5:51234 accepted tcp:198.51.100.7:443 [INBOUND -> DIRECT] email: 12345`
     (also `udp:`, IPv6, and lines without `email:`).
   - Converter: log line -> the blocker's event type.
   - Drive the real scoring code in timestamp order with an injected/fake
     clock. Do NOT touch nftables. Replace the block action with a recorder that
     writes JSONL decisions: time, userId, sourceIp, rule, score, action.
   - Output an aggregate report only: blocks per hour per 1,000 active users,
     blocks by traffic class (by dst port), distinct userIds per blocked
     sourceIp, and time-to-first-block per scenario.
   - It must run as a single command, e.g.
     `node tools/pr46-replay/run.js --log access.log --out report.json`,
     with no network access and no root.

4. Synthetic scenarios (tools/pr46-replay/fixtures/), one generator each, using
   only RFC 5737 / RFC 3849 documentation addresses or clearly fake ranges:
   - BitTorrent/DHT user: 300 peers over UDP 6881 and 51413 in 60 s
   - DNS benchmark: 40 public resolvers on :53 in 1 s, 5 different users
   - NTP pool client: 120 servers on :123, about 3 hits each
   - Steam game + WebRTC call + XMPP chat
   - IMAP client polling :993 every few seconds for 1 h
   - Heavy browser: 600 distinct HTTPS destinations in 15 min
   - CGNAT: 50 unrelated users behind one sourceIp, one of them scanning
   - Chained exit node: 2,000 users all arriving as one userId from one internal IP
   - True positives: SSH sweep over 200 /24s on :22; RTSP sweep on 554/553;
     300 sessions to one host on :3389; 700 non-web sessions in 60 s
   For every scenario add a test asserting the actual behaviour of PR #46
   (block or no block). Do not assert the behaviour you wish it had.

5. Write docs/pr46-review/REVIEW.md: a table of scenario, expected (per
   CONTEXT.md), actual (PR #46), verdict. Add concrete, minimal suggestions:
   thresholds, port allowlists or exemptions, a report-only default, and
   chained-node detection. Keep it factual and polite. This will be posted to
   an upstream PR by a human after review.

Rules:
- Do not open PRs, issues or comments on remnawave/node or anywhere else. Only
  push the `review/pr46-replay` branch to this fork.
- Do not modify the PR's source files except for minimal stubs to make it
  build. List every stub in REVIEW.md.
- No real IPs, domains or user data anywhere in fixtures or docs.
- Commit in small logical steps. Finish with a summary of what works, what is
  unverified, and exactly how to run the harness on a real log file.

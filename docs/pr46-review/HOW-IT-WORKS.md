# How the PR #46 abuse blocker works

Reviewed revision: PR #46 head `2e47450` (three commits on top of `3.2.2`).
Defaults come from the `abuseBlocker` schema on the author's companion branch
`l0nelynx/backend@staging/abuse-blocker-plugin-schema` (`dc5336f`). No
published `@remnawave/node-plugins` release contains that schema yet (see
REVIEW.md, "Build status").

## 1. Input event

Xray posts one routing webhook per routed connection (`app/router/webhook.go`,
`deduplication: 0`). When the blocker is enabled, `generateApiConfig`:

- adds the abuse webhook to every routing rule except `rules[0]` (the API
  rule), unless the rule already has a webhook (then coverage is `partial`);
- appends a catch-all rule `RW_ABUSE_DEFAULT` with `network: "tcp"` towards the
  first outbound, plus `ip: ["0.0.0.0/0", "::/0"]` when `domainStrategy` is
  `IPIfNonMatch`.

If Torrent Blocker is also enabled, its `protocol: ["bittorrent"]` rule is
inserted at index 1 with its own webhook, so sniffed BitTorrent flows are not
scored by the abuse blocker. Peer traffic the sniffer does not recognise is
still scored.

Payload (`XrayWebhookModel`): `email, level, protocol, network, source,
destination, routeTarget, originalTarget, inboundTag, inboundName,
inboundLocal, outboundTag, ts`. `ts` is `time.Now().Unix()`, whole seconds.

`toAbuseBlockerObservation` turns it into
`{ userId, sourceIp, destinationIp, destinationPort, timestamp }` and drops:

- anything that is not `tcp` (all UDP: DNS, NTP, QUIC, DHT, uTP, STUN);
- events whose `email` is missing or not all digits;
- events where none of `originalTarget`, `routeTarget`, `destination` is an
  `IP:port` (domain-only targets).

`analyze()` then skips `ignoreLists.userId`, `ignoreLists.sourceIp`,
`ignoreLists.destinationIp` and `excludedPorts` (default `[80, 443]`).

## 2. Scoring (per `userId`)

| Rule | Key | Counts | Window | Fires at | Points |
|---|---|---|---|---|---|
| `horizontal_scan` | destination port + /24 (IPv4) or /64 (IPv6) | distinct destination IPs | 60 s | 20 | +100 |
| `destination_sweep` | destination port | distinct destination IPs | 60 s | 50 | +50 |

- The user score is the sum of firings in the last `scoreWindowSeconds`
  (3600 s).
- Severity: `suspicious` at 50 or more, `alert` at 100 or more, `blocked` at
  150 or more. A report is only produced on an event where a key fires and
  the score reaches at least 50.
- Each key latches: after firing it fires again only once its distinct count in
  the window has dropped below the threshold **and** `incidentCooldownSeconds`
  (300 s) have passed. A scan that keeps a steady rate therefore scores once per
  key, however long it runs.
- Memory bounds: `maxTrackedUsers` 50,000 (LRU), `maxKeysPerUser` 256,
  `reportBufferSize` 10,000.

Ways one user reaches 150 within an hour:

- 20 hosts in one /24 and 50 distinct hosts on the same port within 60 s
  (100 + 50);
- 20 hosts in each of two /24s on the same port (100 + 100);
- 50 or more distinct hosts on each of three ports within 60 s (50 + 50 + 50);
- any mix of firings spread over the hour, e.g. an `alert` at 12:00 and one
  sweep on another port at 12:50.

## 3. What gets blocked, and for how long

When a firing leaves the score at 150 or above, the handler calls
`NftService.blockAbuseIp(observation.sourceIp, initialBlockSeconds)`:

- **What:** the source IP of the one connection that crossed the threshold.
  Not the user, and not the user's other IPs. Any later firing while the score
  is still 150 or more blocks the source IP of that event too.
- **How:** the IP goes into the `abuse-blocker` nftables set, which is an
  ingress set: packets from that address are dropped on the input and forward
  hooks, on every port and protocol. Then `DropConnectionsEvent` kills the
  address's open sockets.
- **How long:** `initialBlockSeconds`, 600 s by default. `repeatBlockSeconds`
  (3600) and `repeatWindowSeconds` (7 days) are sent to the panel in the
  policy, but the node never uses them. The panel can call `refresh-block` with
  any timeout up to 30 days (remove, then add).
- Applying a changed plugin config (`recreateTables()`) clears all active
  abuse blocks.

## 4. Can it tell a chained or technical user apart?

No. The runtime has no notion of technical users, chained inbounds or shared
source addresses:

- `userId` is the Xray `email`. On an exit node behind an entry node, all
  traffic of everyone behind the entry node arrives as the entry node's
  technical user from the entry node's address, and is scored as one user.
- `inboundTag` is in the payload, but it is only copied into the report.
- Nothing counts how many `userId`s share a `sourceIp`, and the report carries
  exactly one `userId` and one `sourceIp`.
- The only protection is manual: `ignoreLists.userId`,
  `ignoreLists.sourceIp` (including `ext:` shared lists) and
  `ignoreLists.destinationIp`.

So behind CGNAT, one user's score blocks the shared public address. On a chain
exit node, the combined score of everyone behind the entry node blocks the
entry node.

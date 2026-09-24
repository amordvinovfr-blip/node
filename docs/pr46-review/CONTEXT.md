# Operator context for reviewing PR #46 (abuse blocker runtime)

This file comes from an operator who runs a production Remnawave fleet. We
built our own abuse detector on the same input (Xray access logs: user,
source IP, destination IP, destination port, time) and ran it for about two
months. The notes below are what we learned the hard way. They are
generalized on purpose: no hostnames, addresses or user data.

## 1. What turned out to be real abuse

Only four signals held up to manual review. They are the only ones we act on:

| Rule | Threshold | Window |
|---|---|---|
| `hammer_target`: many sessions to one `(dst IP, recon port)` | >= 300 sessions | 15 min |
| `horizontal_sweep_hard`: many distinct /24s on one recon port | >= 150 distinct /24 | 15 min |
| `session_rate_burst`: non-web sessions per user | >= 600 sessions | 60 s |
| `blacklist_hit`: destination in a C2/criminal feed | any | n/a |

Thresholds are deliberately exaggerated: a normal consumer never gets close.
Before a durable record is created, a candidate must also be confirmed on two
consecutive scoring passes.

"Recon ports" is a positive allowlist of about 55 ports that generate hoster
abuse tickets: 21, 22, 23, 88, 111, 135, 137, 139, 179, 389, 445, 502,
512-515, 523, 548, 553, 554, 623, 636, 873, 1099, 1433, 1521, 1723, 2049,
2222, 2323, 2375, 2376, 2379, 2380, 3306, 3389, 4444, 4786, 5432, 5555,
5900-5902, 5984-5986, 6379, 6443, 7547, 8291, 9200, 9300, 11211, 27017,
27018, 47808. Scan geometry counts only these ports. Mail, web, DNS, NTP and
app ports are excluded.

## 2. What looked like scanning but was not

Every rule of the form "N distinct IPs on one port within a short window"
fired mostly on ordinary users. We demoted all such geometry rules to
observe-only. Concrete false-positive classes:

- **BitTorrent / DHT** (6881-6889, 6969, 51413; mostly UDP): hundreds of peers
  on the same port within seconds. Geometrically it is indistinguishable from
  a sweep. We isolate these ports in a separate bucket that never feeds scan
  rules.
- **DNS (:53)**: resolver benchmarks and resolver-picking apps touch dozens of
  public resolvers in under a second. Several users hit the same resolver
  catalogue. Port 53 is diagnostics-only.
- **NTP (:123)**: NTP-pool clients, latency probes and anti-fraud SDKs. In 71
  of 77 flagged users the target set included a well-known public time
  service, with about 2.8 hits per destination. Diagnostics-only.
- **Games and realtime apps**: Steam 27000-27100 (except 27017), WebRTC/STUN
  3478/3479/5349/5350/19302-19309, XMPP 5222/5223, push 5228-5230. These were
  about 9% pure false positives in our multi-port rule. We drop them before
  analysis.
- **Mail clients** (25/110/143/465/587/993/995): aggressive IMAP polling. One
  user made about 117,000 sessions to :993 in a week, and another made 6,500
  sessions to a single large mail provider. The logs carry no auth result, so a brute-force claim cannot be
  proven. Never act on these.
- **Proxies to own server** (1080/3128/5060/8080/8443): a user reconnecting to
  their own endpoint. Median distinct targets: 1.
- **Heavy browsing on 80/443**: a median of about 566 distinct targets per
  flagged user. Web floods are not a DoS signal.
- **Blocklist ranges**: in a week of `blacklist_hit` records, most hits were
  torrent peers and ordinary HTTPS inside large DROP-list ranges, not C2.

## 3. Structural risks of blocking by source IP

PR #46 blocks the client's **source IP** with nftables. Two deployment shapes
make this dangerous:

1. **Carrier-grade NAT.** Mobile and many residential ISPs put many unrelated
   subscribers behind one public IPv4. Blocking the IP punishes everyone
   behind it. The offender changes nothing, because their next connection
   arrives from another pool address.
2. **Chained nodes (entry node -> mesh -> exit node).** A common anti-censorship
   layout: the exit node sees every user arriving as **one technical user from
   one internal address**, the entry node's address. If the blocker runs on an
   exit node, one score crossing 150 blocks the entire entry node, which
   carries thousands of users. `userId` on the exit is meaningless too.

Questions the PR should answer:
- Can the blocker detect or be told that it runs behind a chain, and refuse
  to block, or fall back to report-only?
- How many distinct `userId`s share each `sourceIp` it would block?

## 4. Who the real offenders were

From reviewing our top-50 accounts by incident count:

- Real scanners were **infected devices** (cameras, TV boxes, "earn money by
  sharing bandwidth" apps), not people. Their volume scaled with the number
  of client IPs on the account.
- Heavy offenders were often **resold subscriptions**: one account seen from
  150-5,000 distinct client IPs per week.
- Of the top 50, only 7 warranted action and 20 were completely clean.

For operators, "distinct client IPs per account" was a better early signal
than any scan geometry.

## 5. What we would suggest for the blocker

- Default to **report-only**. Blocking should be an explicit per-node opt-in.
- Recon-port allowlist instead of "any port". Exempt 53/123, torrent,
  game/realtime, mail and alt-proxy ports from blocking scores.
- Much higher thresholds for anything that blocks (see section 1), plus
  confirmation across two passes.
- Detect chained or technical-user inbounds and never block there.
- Record the users-per-source-IP count with every block decision.

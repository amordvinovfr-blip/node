# Facts from Xray-core for the PR #46 detector

Source: Xray-core tag `v26.7.28` (commit `5ca6f4b`), the version pinned in
`docker/Dockerfile:20` (`ARG XRAY_CORE_VERSION=v26.7.28`). PR #46 lines refer
to the PR head `2e47450`. Everything below was read from source; nothing was
run against a live Xray.

## 1. What a domain request looks like in the webhook

A VLESS/REALITY client asks for `example.com:443`.

| Field | Value | Where it comes from |
|---|---|---|
| `destination` | `example.com:443` | `app/router/webhook.go:130-135`: `GetTargetDomain()` wins over `GetTargetIPs()` |
| `originalTarget` | `tcp:example.com:443` | `app/dispatcher/default.go:334` sets `ob.OriginalTarget = destination` before sniffing; `webhook.go:157-158` prints it with `Destination.String()` (`tcp:` prefix) |
| `routeTarget` | `null`, or `tcp:<sniffed domain>:443` when sniffing runs with `routeOnly` | `default.go:366-367`; `webhook.go:160-161` |

**A resolved IP is never present.** There are three reasons:

- `features/routing/session/context.go:48-58`: `GetTargetIPs()` returns an IP
  only when the target address itself is an IP literal.
- `app/router/router.go:95-107`: `PickRoute` keeps `originalCtx` and fires the
  webhook with it (`rule.Webhook.Fire(originalCtx, tag)`, line 106). This
  holds even when `pickRouteInternal` swapped in a DNS-resolving context
  (`router.go:251-253` for `IPOnDemand`, `router.go:265` for the
  `IPIfNonMatch` second pass, `features/routing/dns/context.go:21-50`).
  Those resolved IPs stay inside the routing decision.
- The freedom outbound resolves only later, inside `Process`
  (`proxy/freedom/freedom.go:290-325`), after the webhook has already been
  sent. That happens in `handler.Dispatch`, `default.go:504`.

`toAbuseBlockerObservation` (PR `xray-webhook.handler.ts:29-33`) looks for an
`IP:port` in `originalTarget`, `routeTarget` and `destination`. For a domain
request it finds none and drops the event. The real-data figure fits this:
68% of TCP sessions on entry nodes, and 81% on exit nodes, are never
scored.

## 2. What fills `originalTarget` and `routeTarget`

VLESS inbound hands the request to `DispatchLink`
(`proxy/vless/inbound/inbound.go:633`). Mux sub-streams use `Dispatch`
(`common/mux/server.go:232`, `:264`). Both paths do the same thing
(`default.go:267-321` and `:324-376`):

1. `OriginalTarget` and `Target` are set to the requested destination
   (`:277-278` / `:334-335`).
2. If sniffing is enabled and `shouldOverride` accepts the result
   (`destOverride`, `:232-265`), the sniffed domain goes into `RouteTarget`
   when `routeOnly` is set (and the protocol is not FakeDNS). Otherwise it
   replaces `Target` (`:311-315` / `:366-370`).
3. Routing, then the webhook (`routedDispatch`, `:434-505`; `PickRoute` at
   `:456`).

| Client asks for | Sniffing | `destination` | `originalTarget` | `routeTarget` |
|---|---|---|---|---|
| IP | off, or not overridden | IP:port | tcp:IP:port | null |
| IP | override, `routeOnly: false` | sniffed domain:port | tcp:IP:port | null |
| IP | override, `routeOnly: true` | sniffed domain:port (`context.go:94-96` prefers `RouteTarget`) | tcp:IP:port | tcp:sniffed domain:port |
| domain | any | domain:port | tcp:domain:port | null or tcp:sniffed domain:port |
| FakeDNS IP | `fakedns` override | domain:port | tcp:**fake IP**:port | null (`routeOnly` is ignored for FakeDNS, `:311`) |

Consequences:

- When the client connected by IP, the PR always finds that IP in
  `originalTarget`, whatever the sniffing settings. When it connected by
  name, no IP exists anywhere in the payload.
- `domainStrategy` (`AsIs`, `IPIfNonMatch`, `IPOnDemand`) does not change the
  payload. See section 1.
- With server-side FakeDNS, `originalTarget` holds an address from the fake
  pool (`features/dns/fakedns.go:15`, `198.18.0.0/15` by default), and the PR
  would score fake IPs. Remnawave nodes are not expected to run FakeDNS; this
  is noted, not handled.
- The access log's `to` field is `request.Destination()`
  (`proxy/vless/inbound/inbound.go:601-607`), which is the same value as
  `originalTarget`. So the replay harness sees exactly what the PR would pick
  (IP) or drop (domain). The harness's domain count is therefore the PR's
  blind spot, not an artefact of the access log.

## 3. When the webhook fires, and deduplication

- **Only on a rule match.** The webhook is attached per routing rule
  (`router.go:68-75`) and fired only when the matched rule has one
  (`router.go:105-107`). A connection that matches no rule goes to the default
  outbound (`router.go:261-262`, `default.go:472-478`), and no webhook is sent.
- **One event per dispatched connection.** Every TCP connection and every mux
  sub-stream is routed once, so at most one webhook is sent per connection.
- **PR #46 makes every TCP connection match a webhook rule** for
  `target=abuse` (`src/common/utils/generate-api-config.ts` at the PR head):
  - lines 113-120 add `{ url: abuseUrl, deduplication: 0 }` to every rule
    after `rules[0]` that has no webhook yet. Rules that already have one are
    skipped and counted, and coverage becomes `partial`;
  - lines 122-134 append `RW_ABUSE_DEFAULT` (`network: "tcp"`, first outbound,
    webhook with `deduplication: 0`). For `IPIfNonMatch` it also gets
    `ip: ["0.0.0.0/0", "::/0"]`, so it matches only on the resolved second pass
    and user IP rules still get their turn.
- **Deduplication** is per `email` only: one `seen` timestamp per user
  (`webhook.go:198-211`, swept by `cleanupLoop`, `:213-232`). It is disabled
  when `deduplication == 0` (`:199`), and PR #46 always sets 0 for its own
  rules (lines 119 and 128; 157 and 159 for the torrent/combined URLs).
  **Established: Xray does not deduplicate abuse webhooks.** Every matched TCP
  connection is posted.
- **Delivery is best-effort.** Each event is posted from its own goroutine
  (`webhook.go:99-109`), with a 5 s client timeout (`:57-59`). Failures are
  logged at Info level and dropped (`:184-187`), with no retry and no order.
  `ts` is `time.Now().Unix()`, whole seconds (`:114`). Under load, the node
  can therefore miss events or receive them out of order within a few
  seconds.

### What this means for rate rules

- **As deployed by PR #46,** a per-user session counter sees every TCP
  session that reaches the webhook. `hammer_target` and `session_rate_burst`
  are therefore feasible.
- **If deduplication were ever non-zero on a scored rule,** a rule the PR
  skips because it already had a webhook with `deduplication > 0` delivers at
  most one event per user per TTL. Rate rules would then undercount: a user
  capped at one event per T seconds can never reach 600 sessions per minute
  when T >= 1. The design treats `coverageMode: "partial"` as "rate rules may
  undercount". It reports the coverage mode with every report, and never
  relies on rate rules alone for blocking. `session_rate_burst` is
  report-only by default.
- **Lost POSTs under load** also make counts lower bounds. They never inflate
  them.

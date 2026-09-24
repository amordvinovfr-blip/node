'use strict';

// Scenario registry. `expected` is what CONTEXT.md says should happen; the
// actual PR #46 behaviour is measured by run-scenarios.js and pinned in
// test/scenarios.test.js.

const fixture = (name) => require(`./fixtures/${name}`);

const SCENARIOS = [
    {
        id: 'bittorrent-dht',
        title: 'BitTorrent/DHT: 300 peers, UDP 6881/51413, 60 s',
        group: 'false-positive',
        generate: () => fixture('bittorrent-dht').generate(),
        expected: 'no action',
        basis: 'CONTEXT §2: torrent ports isolated, never feed scan rules',
    },
    {
        id: 'bittorrent-tcp',
        title: 'Variant: same 300 peers over TCP',
        group: 'false-positive',
        generate: () => fixture('bittorrent-dht').generate({ network: 'tcp' }),
        expected: 'no action',
        basis: 'CONTEXT §2: torrent ports isolated, never feed scan rules',
    },
    {
        id: 'dns-benchmark',
        title: 'DNS benchmark: 40 resolvers on :53 in 1 s, 5 users (UDP)',
        group: 'false-positive',
        generate: () => fixture('dns-benchmark').generate(),
        expected: 'no action',
        basis: 'CONTEXT §2: port 53 is diagnostics-only',
    },
    {
        id: 'dns-benchmark-tcp',
        title: 'Variant: same benchmark over TCP',
        group: 'false-positive',
        generate: () => fixture('dns-benchmark').generate({ network: 'tcp' }),
        expected: 'no action',
        basis: 'CONTEXT §2: port 53 is diagnostics-only',
    },
    {
        id: 'ntp-pool',
        title: 'NTP pool client: 120 servers on :123, ~3 hits each',
        group: 'false-positive',
        generate: () => fixture('ntp-pool').generate(),
        expected: 'no action',
        basis: 'CONTEXT §2: NTP is diagnostics-only',
    },
    {
        id: 'steam-webrtc-xmpp',
        title: 'Steam game + WebRTC call + XMPP chat, 1 h',
        group: 'false-positive',
        generate: () => fixture('steam-webrtc-xmpp').generate(),
        expected: 'no action',
        basis: 'CONTEXT §2: game/realtime ports dropped before analysis',
    },
    {
        id: 'imap-polling',
        title: 'IMAP client polling :993 every 2-4 s for 1 h',
        group: 'false-positive',
        generate: () => fixture('imap-polling').generate(),
        expected: 'no action',
        basis: 'CONTEXT §2: mail ports, never act',
    },
    {
        id: 'heavy-browser',
        title: 'Heavy browser: 600 HTTPS destinations in 15 min',
        group: 'false-positive',
        generate: () => fixture('heavy-browser').generate(),
        expected: 'no action',
        basis: 'CONTEXT §2: web floods are not a DoS signal',
    },
    {
        id: 'cgnat-shared-ip',
        title: 'CGNAT: 50 users on one IP, one scanning',
        group: 'structural',
        generate: () => fixture('cgnat-shared-ip').generate(),
        expected: 'flag the scanning user; do not block the shared IP',
        basis: 'CONTEXT §3.1: blocking the IP punishes everyone behind it',
    },
    {
        id: 'chained-exit-node',
        title: 'Chained exit node: 2,000 people as one userId from one internal IP',
        group: 'structural',
        generate: () => fixture('chained-exit-node').generate(),
        expected: 'never block; report-only at most',
        basis: 'CONTEXT §3.2: detect chained/technical inbounds and never block there',
    },
    {
        id: 'chained-exit-node-no-torrent',
        title: 'Variant: same, with nobody running BitTorrent',
        group: 'structural',
        generate: () => fixture('chained-exit-node').generate({ torrentShare: 0 }),
        expected: 'never block; report-only at most',
        basis: 'CONTEXT §3.2',
    },
    {
        id: 'tp-ssh-sweep',
        title: 'SSH sweep: 200 /24s on :22, random order, 2 min',
        group: 'true-positive',
        generate: () => fixture('tp-ssh-sweep').generate({ order: 'random' }),
        expected: 'flag (horizontal_sweep_hard: >=150 /24s on a recon port in 15 min)',
        basis: 'CONTEXT §1',
    },
    {
        id: 'tp-ssh-sweep-sequential',
        title: 'Variant: 200 /24s x 25 hosts, sequential, 500/min',
        group: 'true-positive',
        generate: () => fixture('tp-ssh-sweep').generate({ order: 'sequential' }),
        expected: 'flag (horizontal_sweep_hard)',
        basis: 'CONTEXT §1',
    },
    {
        id: 'tp-rtsp-sweep',
        title: 'RTSP sweep: 200 /24s each on 554 and 553, 2 min',
        group: 'true-positive',
        generate: () => fixture('tp-rtsp-sweep').generate(),
        expected: 'flag (horizontal_sweep_hard on 554 and 553)',
        basis: 'CONTEXT §1',
    },
    {
        id: 'tp-rdp-hammer',
        title: '300 sessions to one host on :3389 in 10 min',
        group: 'true-positive',
        generate: () => fixture('tp-rdp-hammer').generate(),
        expected: 'flag (hammer_target: >=300 sessions to one dst/recon port in 15 min)',
        basis: 'CONTEXT §1',
    },
    {
        id: 'tp-session-burst',
        title: '700 non-web sessions in 60 s (5 DB hosts)',
        group: 'true-positive',
        generate: () => fixture('tp-session-burst').generate(),
        expected: 'flag (session_rate_burst: >=600 non-web sessions in 60 s)',
        basis: 'CONTEXT §1',
    },
];

module.exports = { SCENARIOS };

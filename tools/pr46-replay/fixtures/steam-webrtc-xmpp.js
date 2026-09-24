'use strict';

// One user for an hour: Steam client + server browser + a game, a WebRTC
// call, an XMPP chat session and push notifications, plus light browsing.

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./lib');

const generate = ({ seed = 27015 } = {}) => {
    const rng = new Rng(seed);
    const email = 1004;
    const src = addr.client(40);
    const sessions = [];
    const add = (ms, dst, port, net = 'tcp') => sessions.push({ ms, src, net, dst, port, email });

    // Steam client: connection managers on TCP 27020-27030, reconnecting.
    const managers = [1, 2, 3, 4].map((host) => addr.service(40, host));
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += rng.int(10, 20) * MINUTE) {
        add(ms, rng.pick(managers), rng.int(27020, 27030));
    }
    // Server browser refresh: A2S queries to 250 game servers over UDP.
    const browserStart = BASE_MS + 2 * MINUTE;
    for (let server = 0; server < 250; server += 1) {
        add(browserStart + rng.int(0, 30_000), addr.target(rng.int(0, 255), rng.int(1, 254)), rng.int(27015, 27020), 'udp');
    }
    // The game itself: one UDP server for 15 minutes, a few flows.
    const gameServer = addr.target(77, 15);
    for (let flow = 0; flow < 3; flow += 1) add(BASE_MS + 5 * MINUTE + flow * 5 * MINUTE, gameServer, 27015, 'udp');

    // WebRTC call at 20-50 min: STUN/TURN over UDP, TURN over TCP 443, media to the peer.
    const callStart = BASE_MS + 20 * MINUTE;
    for (const host of [1, 2]) add(callStart + rng.int(0, 2000), addr.service(50, host), 3478, 'udp');
    for (const host of [1, 2]) add(callStart + rng.int(0, 2000), addr.service(51, host), rng.int(19302, 19309), 'udp');
    add(callStart + 3000, addr.service(50, 3), 443);
    add(callStart + 4000, addr.v6(0x5a, 0x10), rng.int(40000, 60000), 'udp');
    add(callStart + 15 * MINUTE, addr.v6(0x5a, 0x10), rng.int(40000, 60000), 'udp');

    // XMPP chat (5222 with reconnects, one 5223 session) and push on 5228.
    const xmpp = addr.service(22, 7);
    for (let ms = BASE_MS + MINUTE; ms < BASE_MS + 60 * MINUTE; ms += 5 * MINUTE) add(ms, xmpp, 5222);
    add(BASE_MS + 30 * MINUTE, xmpp, 5223);
    for (let ms = BASE_MS; ms < BASE_MS + 60 * MINUTE; ms += 15 * MINUTE) add(ms, addr.service(10, 3), 5228);

    // Light browsing.
    for (let index = 0; index < 40; index += 1) {
        add(BASE_MS + rng.int(0, 60 * MINUTE - 1), addr.service(rng.int(128, 255), rng.int(1, 254)), 443);
    }

    return {
        lines: toLines(sessions, rng),
        meta: { users: 1, sourceIps: 1, durationMinutes: 60 },
    };
};

module.exports = { generate };

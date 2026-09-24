'use strict';

// DNS benchmark: 5 users, each touching the same catalogue of 40 public
// resolvers on :53 within 1 s. Resolvers sit in 30 distinct /24s (10 /24s
// hold two resolvers), like real public resolver catalogues.

const { BASE_MS, Rng, addr, toLines } = require('./lib');

const catalogue = () => {
    const resolvers = [];
    for (let net = 0; net < 30; net += 1) {
        resolvers.push(addr.service(100 + net, 53));
        if (net < 10) resolvers.push(addr.service(100 + net, 54));
    }
    return resolvers;
};

const generate = ({ network = 'udp', users = 5, seed = 53 } = {}) => {
    const rng = new Rng(seed);
    const resolvers = catalogue();
    const sessions = [];

    for (let user = 0; user < users; user += 1) {
        const email = 1100 + user;
        const src = addr.client(20 + user);
        const startMs = BASE_MS + user * 37_000;
        for (const dst of rng.shuffle(resolvers)) {
            sessions.push({ ms: startMs + rng.int(0, 999), src, net: network, dst, port: 53, email });
        }
    }

    return {
        lines: toLines(sessions, rng),
        meta: { users, sourceIps: users, resolvers: resolvers.length, network, windowSeconds: 1 },
    };
};

module.exports = { generate, catalogue };

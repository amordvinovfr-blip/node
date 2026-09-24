'use strict';

// Destination-port classes from CONTEXT.md sections 1 and 2. Used only to
// aggregate the report; the PR's scoring never sees these classes.

const range = (from, to) => Array.from({ length: to - from + 1 }, (_, index) => from + index);

const RECON_PORTS = new Set([
    21, 22, 23, 88, 111, 135, 137, 139, 179, 389, 445, 502, ...range(512, 515), 523, 548, 553,
    554, 623, 636, 873, 1099, 1433, 1521, 1723, 2049, 2222, 2323, 2375, 2376, 2379, 2380, 3306,
    3389, 4444, 4786, 5432, 5555, ...range(5900, 5902), ...range(5984, 5986), 6379, 6443, 7547,
    8291, 9200, 9300, 11211, 27017, 27018, 47808,
]);

const CLASSES = [
    ['web', new Set([80, 443])],
    ['dns', new Set([53, 853])],
    ['ntp', new Set([123])],
    ['torrent', new Set([...range(6881, 6889), 6969, 51413])],
    ['mail', new Set([25, 110, 143, 465, 587, 993, 995])],
    ['alt_proxy', new Set([1080, 3128, 5060, 8080, 8443])],
    // Checked before game_realtime so that 27017/27018 (MongoDB) stay recon.
    ['recon', RECON_PORTS],
    [
        'game_realtime',
        new Set([
            ...range(27000, 27100),
            3478,
            3479,
            5349,
            5350,
            ...range(19302, 19309),
            5222,
            5223,
            ...range(5228, 5230),
        ]),
    ],
];

const classifyPort = (port) => {
    for (const [name, ports] of CLASSES) {
        if (ports.has(port)) return name;
    }
    return 'other';
};

module.exports = { classifyPort, RECON_PORTS, CLASS_NAMES: [...CLASSES.map(([name]) => name), 'other'] };

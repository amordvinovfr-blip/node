#!/usr/bin/env node
'use strict';

// Chooses N (horizontal_sweep_domains) and M (subdomain_sweep): for each
// candidate threshold, the largest benign count seen and whether hostname
// scans of different sizes and speeds cross it within 15 minutes.
//
//   node tools/pr46-replay/sensitivity-domains.js

const { BASE_MS, MINUTE, Rng, addr, toLines } = require('./fixtures/lib');
const { replayLines } = require('./lib/replay');

const run = async (sessions, abuseBlocker) => {
    const report = await replayLines(toLines(sessions, new Rng(1)), {
        variants: ['patched'],
        patchedMode: 'block',
        configs: { patched: abuseBlocker },
    });
    const rules = report.variants.patched.rules;
    return {
        sweep: rules.horizontal_sweep_domains?.decisions ?? 0,
        subdomain: rules.subdomain_sweep?.decisions ?? 0,
        firstSweepSeconds: rules.horizontal_sweep_domains?.timeToFirstDecisionSeconds ?? null,
        firstSubdomainSeconds: rules.subdomain_sweep?.timeToFirstDecisionSeconds ?? null,
    };
};

const spread = (names, durationMs, port = 22) =>
    names.map((dst, index) => ({
        ms: BASE_MS + Math.floor((index * durationMs) / names.length),
        src: addr.client(71),
        dst,
        port,
        email: 4101,
    }));

// Benign recon-port traffic by name (one hour each).
const BENIGN = {
    'SSH to 8 own servers in 8 domains': Array.from({ length: 240 }, (_, index) => `srv.own${index % 8}.example`),
    '5 jump hosts under one domain': Array.from({ length: 240 }, (_, index) => `jump${index % 5}.corp.example`),
    'Ansible over 40 hosts of one domain': Array.from({ length: 400 }, (_, index) => `node${index % 40}.corp.example`),
    'git over SSH to 3 code hosts': Array.from({ length: 120 }, (_, index) => `git.forge${index % 3}.example`),
};

const scanByName = (domains, namesPerDomain, durationMinutes) => {
    const names = [];
    for (let domain = 0; domain < domains; domain += 1) {
        for (let name = 0; name < namesPerDomain; name += 1) names.push(`h${name}.victim${domain}.example`);
    }
    return spread(new Rng(domains).shuffle(names), durationMinutes * MINUTE);
};

const enumeration = (hosts, durationMinutes) =>
    spread(
        Array.from({ length: hosts }, (_, index) => `h${index}.target.example`),
        durationMinutes * MINUTE,
    );

const main = async () => {
    const sweepThresholds = [20, 50, 100, 150];
    const subThresholds = [50, 100, 150];

    console.log('Benign recon-port traffic by name over 1 h: distinct counts');
    console.log('| Case | distinct domains | distinct hostnames |');
    console.log('|---|---:|---:|');
    for (const [label, names] of Object.entries(BENIGN)) {
        const domains = new Set(names.map((name) => name.split('.').slice(-2).join('.'))).size;
        console.log(`| ${label} | ${domains} | ${new Set(names).size} |`);
    }

    console.log('\nhorizontal_sweep_domains (distinct registrable domains per user and port, 15 min)');
    console.log(`| Scan | ${sweepThresholds.map((n) => `N=${n}`).join(' | ')} |`);
    console.log(`|---|${sweepThresholds.map(() => '---').join('|')}|`);
    const sweepCases = [
        ['40 domains x 1 name, 10 min', scanByName(40, 1, 10)],
        ['100 domains x 1 name, 10 min', scanByName(100, 1, 10)],
        ['400 domains x 1 name, 10 min', scanByName(400, 1, 10)],
        ['200 domains x 1 name, 60 min', scanByName(200, 1, 60)],
    ];
    for (const [label, sessions] of sweepCases) {
        const cells = [];
        for (const threshold of sweepThresholds) {
            const result = await run(sessions, {
                domains: { sweep: { uniqueDomains: threshold }, subdomainSweep: { enabled: false } },
            });
            cells.push(result.sweep ? `fires (${result.firstSweepSeconds} s)` : '-');
        }
        console.log(`| ${label} | ${cells.join(' | ')} |`);
    }
    for (const [label, names] of Object.entries(BENIGN)) {
        const cells = [];
        for (const threshold of sweepThresholds) {
            const result = await run(spread(names, 60 * MINUTE), {
                domains: { sweep: { uniqueDomains: threshold }, subdomainSweep: { enabled: false } },
            });
            cells.push(result.sweep ? 'fires' : '-');
        }
        console.log(`| benign: ${label} | ${cells.join(' | ')} |`);
    }

    console.log('\nsubdomain_sweep (distinct hostnames under one registrable domain, 15 min)');
    console.log(`| Scan | ${subThresholds.map((m) => `M=${m}`).join(' | ')} |`);
    console.log(`|---|${subThresholds.map(() => '---').join('|')}|`);
    const subCases = [
        ['60 names, 10 min', enumeration(60, 10)],
        ['200 names, 10 min', enumeration(200, 10)],
        ['200 names, 30 min', enumeration(200, 30)],
        ['1000 names, 10 min', enumeration(1000, 10)],
    ];
    for (const [label, sessions] of subCases) {
        const cells = [];
        for (const threshold of subThresholds) {
            const result = await run(sessions, {
                domains: { sweep: { enabled: false }, subdomainSweep: { uniqueHosts: threshold } },
            });
            cells.push(result.subdomain ? `fires (${result.firstSubdomainSeconds} s)` : '-');
        }
        console.log(`| ${label} | ${cells.join(' | ')} |`);
    }
    for (const [label, names] of Object.entries(BENIGN)) {
        const cells = [];
        for (const threshold of subThresholds) {
            const result = await run(spread(names, 60 * MINUTE), {
                domains: { sweep: { enabled: false }, subdomainSweep: { uniqueHosts: threshold } },
            });
            cells.push(result.subdomain ? 'fires' : '-');
        }
        console.log(`| benign: ${label} | ${cells.join(' | ')} |`);
    }
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

#!/usr/bin/env node
'use strict';

// Runs every synthetic scenario through the PR #46 blocker and prints the
// review table (markdown). Per-scenario aggregate reports go to
// tools/pr46-replay/out/scenarios.json.
//
//   node tools/pr46-replay/run-scenarios.js [--write-logs] [--config <abuse.json>]
//
// --write-logs also writes each scenario's access.log to fixtures/out/, so it
// can be replayed with run.js. --config merges settings into abuseBlocker
// (what-if runs); the output file is then out/scenarios.<config name>.json.

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const { replayLines } = require('./lib/replay');
const { SCENARIOS } = require('./scenarios');

const OUT_DIR = path.join(__dirname, 'out');
const LOG_DIR = path.join(__dirname, 'fixtures', 'out');

const SEVERITY_ORDER = ['suspicious', 'alert', 'blocked'];

const maxSeverity = (bySeverity) =>
    [...SEVERITY_ORDER].reverse().find((severity) => (bySeverity[severity] ?? 0) > 0) ?? null;

const describeActual = (report) => {
    const input = report.scoringInput;
    if (report.blocks.total > 0) {
        const count = report.blocks.total;
        const parts = [
            `**block** after ${report.timeToFirstBlock.secondsFromBlockedUserFirstSeen.min} s ` +
                `(${count} block${count > 1 ? 's' : ''}, ${Object.keys(report.blocks.byRule).join(', ')})`,
        ];
        const users = report.usersPerBlockedSourceIp.lastHourBeforeBlock.max;
        parts.push(`${users} userId${users === 1 ? '' : 's'} on the blocked IP`);
        if (report.collateral?.distinctBystandersDropped) {
            parts.push(`${report.collateral.distinctBystandersDropped} other users cut off`);
        }
        return parts.join('; ');
    }
    const severity = maxSeverity(report.decisions.bySeverity);
    if (severity) {
        return `no block; highest report \`${severity}\` (score ${report.decisions.maxScore})`;
    }
    if (input.analyzed === 0) {
        if (input.filteredNotTcp > 0 && input.excludedPort === 0) return 'no block; never scored (UDP is ignored)';
        if (input.excludedPort > 0) return 'no block; never scored (excluded ports, UDP ignored)';
    }
    return 'no block; no report';
};

const verdict = (scenario, report) => {
    const blocked = report.blocks.total > 0;
    const severity = maxSeverity(report.decisions.bySeverity);
    if (scenario.group === 'false-positive') {
        if (blocked) return 'False positive: blocks';
        return severity ? `Agrees (no block), but reports \`${severity}\`` : 'Agrees';
    }
    if (scenario.group === 'structural') {
        return blocked ? 'Disagrees: blocks a shared address' : 'Agrees here (no trigger in this mix)';
    }
    if (blocked) return 'Detected (blocks)';
    return severity ? `Partly: \`${severity}\` only, no block` : 'Missed';
};

const main = async () => {
    const { values } = parseArgs({
        options: {
            'write-logs': { type: 'boolean', default: false },
            config: { type: 'string' },
        },
    });
    const writeLogs = values['write-logs'];
    const abuseBlocker = values.config ? JSON.parse(fs.readFileSync(values.config, 'utf8')) : {};
    const outFile = path.join(
        OUT_DIR,
        values.config ? `scenarios.${path.basename(values.config, '.json')}.json` : 'scenarios.json',
    );
    fs.mkdirSync(OUT_DIR, { recursive: true });
    if (writeLogs) fs.mkdirSync(LOG_DIR, { recursive: true });

    const results = [];
    for (const scenario of SCENARIOS) {
        const { lines, meta } = scenario.generate();
        if (writeLogs) fs.writeFileSync(path.join(LOG_DIR, `${scenario.id}.log`), `${lines.join('\n')}\n`);
        const report = await replayLines(lines, { scenario: scenario.id, abuseBlocker });
        results.push({ scenario, meta, report });
    }

    const summary = results.map(({ scenario, meta, report }) => ({
        id: scenario.id,
        title: scenario.title,
        group: scenario.group,
        expected: scenario.expected,
        basis: scenario.basis,
        actual: describeActual(report),
        verdict: verdict(scenario, report),
        meta,
        report,
    }));
    fs.writeFileSync(outFile, `${JSON.stringify(summary, null, 2)}\n`);

    const actualLabel = values.config ? `PR #46 + ${path.basename(values.config)}` : 'PR #46 defaults';
    console.log(`| Scenario | Expected (CONTEXT.md) | Actual (${actualLabel}) | Verdict |`);
    console.log('|---|---|---|---|');
    for (const row of summary) {
        console.log(`| ${row.title} | ${row.expected} | ${row.actual} | ${row.verdict} |`);
    }
    console.log();
    console.log('| Scenario | log lines | scored | blocks | blocks/h/1k users | users on blocked IP | first block (s from log start) |');
    console.log('|---|---:|---:|---:|---:|---:|---:|');
    for (const { id, report } of summary) {
        console.log(
            `| ${id} | ${report.input.total} | ${report.scoringInput.analyzed} | ${report.blocks.total} | ` +
                `${report.blocks.perHourPer1000ActiveUsers ?? '-'} | ` +
                `${report.usersPerBlockedSourceIp.lastHourBeforeBlock.max ?? '-'} | ` +
                `${report.timeToFirstBlock.secondsFromLogStart ?? '-'} |`,
        );
    }
    console.log(`\nwrote ${path.relative(process.cwd(), outFile)}`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

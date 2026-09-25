#!/usr/bin/env node
'use strict';

// Runs every synthetic scenario through the PR #46 head rules and the patched
// rules (block mode, to show what blocking would do) and prints the review
// table (markdown). Per-scenario reports go to tools/pr46-replay/out/.
//
//   node tools/pr46-replay/run-scenarios.js [--write-logs] [--config <abuse.json>]
//
// --write-logs also writes each scenario's access.log to fixtures/out/, so it
// can be replayed with run.js. --config merges settings into abuseBlocker for
// both variants (what-if runs); the output is then out/scenarios.<name>.json.

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const { replayLines } = require('./lib/replay');
const { SCENARIOS } = require('./scenarios');

const OUT_DIR = path.join(__dirname, 'out');
const LOG_DIR = path.join(__dirname, 'fixtures', 'out');

const highest = (bySeverity) =>
    ['blocked', 'alert', 'suspicious'].find((severity) => (bySeverity[severity] ?? 0) > 0) ?? null;

const describe = (result) => {
    const severity = highest(result.decisions.bySeverity);
    const rules = Object.keys(result.rules);
    if (result.blocks.total > 0) {
        const first = result.timeToFirstBlock.secondsFromBlockedUserFirstSeen.min;
        return `**block** after ${first} s (${rules.join(', ')})`;
    }
    if (!severity) return 'nothing';
    const skip = Object.keys(result.decisions.bySkipReason);
    const suffix = skip.length > 0 ? `, block skipped: ${skip.join(', ')}` : '';
    return `\`${severity}\` (${rules.join(', ')}${suffix})`;
};

const verdict = (scenario, head, patched) => {
    const blocked = (result) => result.blocks.total > 0;
    const flagged = (result) => ['blocked', 'alert'].includes(highest(result.decisions.bySeverity));
    if (scenario.group === 'true-positive') {
        if (blocked(patched)) return blocked(head) ? 'caught by both' : 'now blocked';
        if (flagged(patched)) return blocked(head) ? 'block becomes alert' : 'now reported (alert)';
        return 'still missed';
    }
    if (blocked(head) && !blocked(patched)) return 'false block removed';
    if (blocked(patched)) return 'still blocks';
    return 'ok';
};

const main = async () => {
    const { values } = parseArgs({
        options: {
            'write-logs': { type: 'boolean', default: false },
            config: { type: 'string' },
        },
    });
    const abuseBlocker = values.config ? JSON.parse(fs.readFileSync(values.config, 'utf8')) : {};
    const outFile = path.join(
        OUT_DIR,
        values.config ? `scenarios.${path.basename(values.config, '.json')}.json` : 'scenarios.json',
    );
    fs.mkdirSync(OUT_DIR, { recursive: true });
    if (values['write-logs']) fs.mkdirSync(LOG_DIR, { recursive: true });

    const summary = [];
    for (const scenario of SCENARIOS) {
        const { lines, meta } = scenario.generate();
        if (values['write-logs']) {
            fs.writeFileSync(path.join(LOG_DIR, `${scenario.id}.log`), `${lines.join('\n')}\n`);
        }
        const report = await replayLines(lines, {
            scenario: scenario.id,
            variants: ['head', 'patched'],
            patchedMode: 'block',
            abuseBlocker,
        });
        const { head, patched } = report.variants;
        summary.push({
            id: scenario.id,
            title: scenario.title,
            group: scenario.group,
            expected: scenario.expected,
            head: describe(head),
            patched: describe(patched),
            verdict: verdict(scenario, head, patched),
            meta,
            report,
        });
    }
    fs.writeFileSync(outFile, `${JSON.stringify(summary, null, 2)}\n`);

    console.log('| Scenario | Expected (CONTEXT.md) | PR #46 head | Patched (block mode) | Change |');
    console.log('|---|---|---|---|---|');
    for (const row of summary) {
        console.log(`| ${row.title} | ${row.expected} | ${row.head} | ${row.patched} | ${row.verdict} |`);
    }
    console.log(`\nwrote ${path.relative(process.cwd(), outFile)}`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

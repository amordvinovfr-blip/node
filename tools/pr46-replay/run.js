#!/usr/bin/env node
'use strict';

// Offline replay of Xray access logs through the PR #46 abuse blocker.
//
//   node tools/pr46-replay/run.js --log access.log [--log access.log.1.gz ...] \
//        --out report.json [--decisions decisions.jsonl] [--config abuse.json]
//
// No network, no root, no nftables: the block action is recorded to JSONL.

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const { replayFiles } = require('./lib/replay');

const USAGE = `Usage: node tools/pr46-replay/run.js --log <access.log> [--log <more>] --out <report.json> [options]

Options:
  --log <path>            Xray access log; repeat for rotated files, oldest first. .gz is read directly.
  --out <path>            Aggregate report (JSON, no IPs or user IDs).
  --decisions <path>      JSONL of every blocker decision (time, userId, sourceIp, rule, score, action).
                          Default: <out without .json>.decisions.jsonl
  --config <path>         JSON object merged into abuseBlocker (e.g. {"blockScore": 300}); schema defaults otherwise.
  --scenario <name>       Label stored in the report.
  --open-loop             Keep feeding events from a source IP after it is "blocked" (default: drop them, as nftables would).
  --sub-second            Use the log's sub-second timestamps instead of Xray's whole-second webhook ts.
  --reorder-window-ms <n> Reorder buffer for slightly out-of-order lines (default 2000).
  -h, --help`;

const main = async () => {
    const { values } = parseArgs({
        options: {
            log: { type: 'string', multiple: true },
            out: { type: 'string' },
            decisions: { type: 'string' },
            config: { type: 'string' },
            scenario: { type: 'string' },
            'open-loop': { type: 'boolean', default: false },
            'sub-second': { type: 'boolean', default: false },
            'reorder-window-ms': { type: 'string', default: '2000' },
            help: { type: 'boolean', short: 'h', default: false },
        },
    });

    if (values.help || !values.log?.length || !values.out) {
        console.log(USAGE);
        process.exitCode = values.help ? 0 : 2;
        return;
    }

    const out = path.resolve(values.out);
    const decisionsPath = path.resolve(
        values.decisions ?? `${out.replace(/\.json$/i, '')}.decisions.jsonl`,
    );
    const abuseBlocker = values.config ? JSON.parse(fs.readFileSync(values.config, 'utf8')) : {};

    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.mkdirSync(path.dirname(decisionsPath), { recursive: true });
    const decisions = fs.createWriteStream(decisionsPath);

    const started = process.hrtime.bigint();
    const report = await replayFiles(values.log.map((file) => path.resolve(file)), {
        abuseBlocker,
        scenario: values.scenario ?? path.basename(values.log[0]),
        closedLoop: !values['open-loop'],
        subSecond: values['sub-second'],
        reorderWindowMs: Number(values['reorder-window-ms']),
        decisionsPath,
        onDecision: (decision) => decisions.write(`${JSON.stringify(decision)}\n`),
    });
    await new Promise((resolve) => decisions.end(resolve));

    fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);

    const seconds = Number(process.hrtime.bigint() - started) / 1e9;
    console.log(
        [
            `lines=${report.input.total} analyzed=${report.scoringInput.analyzed}`,
            `activeUsers=${report.activeUsers} decisions=${report.decisions.total}`,
            `blocks=${report.blocks.total} (${report.blocks.perHourPer1000ActiveUsers ?? '-'} per hour per 1k users)`,
            `firstBlockAfter=${report.timeToFirstBlock.secondsFromLogStart ?? '-'}s`,
            `in ${seconds.toFixed(1)}s`,
        ].join(' | '),
    );
    console.log(`report:    ${out}`);
    console.log(`decisions: ${decisionsPath}`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

#!/usr/bin/env node
'use strict';

// Offline replay of Xray access logs through the PR #46 abuse blocker.
//
//   node tools/pr46-replay/run.js --log access.log.* --out report.json --compare
//
// No network, no root, no nftables: the block action is recorded to JSONL.

const fs = require('node:fs');
const path = require('node:path');
const { parseArgs } = require('node:util');

const { replayFiles } = require('./lib/replay');

const USAGE = `Usage: node tools/pr46-replay/run.js --log <access.log> [more logs] --out <report.json> [options]

Input
  --log <path> [paths]    Xray access logs; .gz is read directly, '-' is stdin. Several files
                          (or a shell glob) are replayed in order of their first timestamp.
  --nodes <n>             Number of nodes whose logs are merged here (default 1), for per-node-day rates.

Variants
  --compare               Run the PR #46 head rules and the patched rules side by side.
  --variant <name>        Without --compare: 'patched' (default) or 'head'.
  --config <path>         JSON merged into abuseBlocker for every variant.
  --config-head <path>    JSON merged into abuseBlocker for the head variant only.
  --config-patched <path> JSON merged into abuseBlocker for the patched variant only.
  --patched-mode <mode>   'block' (default) measures what blocking would do; 'report' keeps the
                          shipped report-only default (decisions then carry skipReason report_only).

Output
  --out <path>            Aggregate report (JSON, no IPs, user IDs or hostnames).
  --decisions <path>      JSONL of every decision, with userId, sourceIp and hostname: keep it local.
                          Default: <out without .json>.decisions.jsonl

Replay
  --open-loop             Keep feeding events from a source IP after it is "blocked".
  --sub-second            Use sub-second log timestamps instead of Xray's whole-second webhook ts.
  --reorder-window-ms <n> Reorder buffer for slightly out-of-order lines (default 2000).
  --max-sources <n>       Source IPs kept for users-per-IP counts (default 200000).
  --heap-samples <n>      Every n lines, force a GC and record the heap (report: harness.heapAfterGcMb).
  -h, --help`;

const readJson = (file) => (file ? JSON.parse(fs.readFileSync(file, 'utf8')) : {});

const main = async () => {
    const { values, positionals } = parseArgs({
        allowPositionals: true,
        options: {
            log: { type: 'string', multiple: true },
            out: { type: 'string' },
            decisions: { type: 'string' },
            compare: { type: 'boolean', default: false },
            variant: { type: 'string', default: 'patched' },
            config: { type: 'string' },
            'config-head': { type: 'string' },
            'config-patched': { type: 'string' },
            'patched-mode': { type: 'string', default: 'block' },
            nodes: { type: 'string', default: '1' },
            scenario: { type: 'string' },
            'open-loop': { type: 'boolean', default: false },
            'sub-second': { type: 'boolean', default: false },
            'reorder-window-ms': { type: 'string', default: '2000' },
            'max-sources': { type: 'string', default: '200000' },
            'heap-samples': { type: 'string', default: '0' },
            help: { type: 'boolean', short: 'h', default: false },
        },
    });

    const logs = [...(values.log ?? []), ...positionals];
    if (values.help || logs.length === 0 || !values.out) {
        console.log(USAGE);
        process.exitCode = values.help ? 0 : 2;
        return;
    }
    if (!['head', 'patched'].includes(values.variant)) throw new Error('--variant must be head or patched');
    if (!['block', 'report'].includes(values['patched-mode'])) {
        throw new Error('--patched-mode must be block or report');
    }

    const out = path.resolve(values.out);
    const decisionsPath = path.resolve(
        values.decisions ?? `${out.replace(/\.json$/i, '')}.decisions.jsonl`,
    );
    fs.mkdirSync(path.dirname(out), { recursive: true });
    fs.mkdirSync(path.dirname(decisionsPath), { recursive: true });
    const decisions = fs.createWriteStream(decisionsPath);

    const started = process.hrtime.bigint();
    const { report, files } = await replayFiles(
        logs.map((file) => (file === '-' ? file : path.resolve(file))),
        {
            variants: values.compare ? ['head', 'patched'] : [values.variant],
            abuseBlocker: readJson(values.config),
            configs: {
                head: readJson(values['config-head']),
                patched: readJson(values['config-patched']),
            },
            patchedMode: values['patched-mode'],
            nodes: Number(values.nodes),
            scenario: values.scenario ?? path.basename(logs[0]),
            closedLoop: !values['open-loop'],
            subSecond: values['sub-second'],
            reorderWindowMs: Number(values['reorder-window-ms']),
            maxSources: Number(values['max-sources']),
            heapSampleEvery: Number(values['heap-samples']),
            decisionsPath,
            onDecision: (decision) => decisions.write(`${JSON.stringify(decision)}\n`),
        },
    );
    await new Promise((resolve) => decisions.end(resolve));

    const seconds = Number(process.hrtime.bigint() - started) / 1e9;
    report.run = {
        files: files.length,
        seconds: Number(seconds.toFixed(1)),
        linesPerSecond: Math.round(report.input.total / seconds),
        heapUsedMb: Math.round(process.memoryUsage().heapUsed / 1e6),
        rssMb: Math.round(process.memoryUsage().rss / 1e6),
    };
    fs.writeFileSync(out, `${JSON.stringify(report, null, 2)}\n`);

    console.log(
        `lines=${report.input.total} users=${report.input.activeUsers} ` +
            `(${report.run.linesPerSecond} lines/s, ${report.run.seconds}s, heap ${report.run.heapUsedMb} MB)`,
    );
    for (const [variant, result] of Object.entries(report.variants)) {
        console.log(
            `${variant.padEnd(8)} decisions=${result.decisions.total} blocks=${result.blocks.total} ` +
                `perNodeDay=${result.blocks.perNodeDay ?? '-'} ` +
                `firstBlockAfter=${result.timeToFirstBlock.secondsFromLogStart ?? '-'}s`,
        );
    }
    console.log(`report:    ${out}`);
    console.log(`decisions: ${decisionsPath}`);
};

main().catch((error) => {
    console.error(error);
    process.exitCode = 1;
});

'use strict';

// Single entry point for every test on this branch:
//
//   node --test tools/pr46-replay/test/all.test.js
//
// It runs the harness specs and the PR's own TypeScript tests
// (tests/abuse-blocker/*.test.ts). The latter need decorators and the tsconfig
// path aliases, which the harness's loader provides, so no tsx is required.

const fs = require('node:fs');
const path = require('node:path');

const { installTsHook, REPO_ROOT } = require('../lib/load-pr');

installTsHook();

const specs = fs
    .readdirSync(__dirname)
    .filter((file) => file.endsWith('.spec.js'))
    .sort();
for (const spec of specs) require(path.join(__dirname, spec));

const prTests = path.join(REPO_ROOT, 'tests', 'abuse-blocker');
for (const file of fs.readdirSync(prTests).filter((name) => name.endsWith('.test.ts')).sort()) {
    require(path.join(prTests, file));
}

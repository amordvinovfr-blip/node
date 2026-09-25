'use strict';

const { replayLines } = require('../lib/replay');

/** One variant's results with the shared input fields, as a flat object. */
const view = (report, variant) => ({
    ...report.variants[variant],
    input: report.input,
    activeUsers: report.input.activeUsers,
    harness: { ...report.harness, ...report.variants[variant].harness },
});

/** Replays `lines` through one variant and returns its flat view. */
const replayVariant = async (lines, variant, options = {}) =>
    view(await replayLines(lines, { ...options, variants: [variant] }), variant);

module.exports = { replayVariant, view };

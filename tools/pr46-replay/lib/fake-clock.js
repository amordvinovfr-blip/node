'use strict';

// Replaces the global Date while the replay runs, so that every wall-clock
// read inside the PR code (`new Date()`, `Date.now()`) returns replay time.
// The scoring itself only uses event timestamps; this keeps processedAt /
// willUnblockAt and the block recorder on the same timeline as the log.

const installFakeClock = (startMs = 0) => {
    const RealDate = globalThis.Date;
    let nowMs = startMs;

    class ReplayDate extends RealDate {
        constructor(...args) {
            if (args.length === 0) super(nowMs);
            else super(...args);
        }

        static now() {
            return nowMs;
        }
    }

    globalThis.Date = ReplayDate;

    return {
        now: () => nowMs,
        set(ms) {
            nowMs = ms;
        },
        restore() {
            globalThis.Date = RealDate;
        },
    };
};

module.exports = { installFakeClock };

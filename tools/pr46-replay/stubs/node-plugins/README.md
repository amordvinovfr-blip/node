# Review stub: `@remnawave/node-plugins` with `abuseBlocker`

PR #46 bumps `@remnawave/node-plugins` to `0.7.0` and reads
`TNodePlugin['abuseBlocker']` / `NodePluginSchema.parse({ abuseBlocker })`.
The published `0.7.0` (and every published version up to `0.8.2` at the time of
review) has no `abuseBlocker` key, so typecheck and build fail and the state
tests receive `undefined` config.

This package is the smallest thing that makes the PR build:

- `src/models/node-plugins.schema.ts` is copied from the PR author's companion
  branch `l0nelynx/backend@staging/abuse-blocker-plugin-schema`
  (commit `dc5336f`, `libs/node-plugins`, version `0.7.4` there).
- The only edit is removing the unrelated `torrentBlocker.rulePlacement` field,
  so that everything except `abuseBlocker` matches the published `0.7.0`
  build output.
- `build/backend/` is the output of `tsc -p tsconfig.json` with the repo's own
  TypeScript, committed so that `npm install` needs no build step.

`package.json` points `@remnawave/node-plugins` at this folder with a `file:`
specifier. Revert that line once a real release with `abuseBlocker` exists.

'use strict';

// Loads the real PR #46 TypeScript sources into plain Node.js:
// - `.ts` files under the repo are transpiled on the fly with the repo's own
//   `typescript` package (no build step, no network);
// - tsconfig `paths` aliases (@common/*, @libs/contracts/*, ...) are resolved;
// - `nftables-napi` and `sockdestroy` are replaced by inert stubs, so nothing
//   in this process can touch nftables or kill sockets, and no root is needed.

const fs = require('node:fs');
const Module = require('node:module');
const path = require('node:path');

const REPO_ROOT = path.resolve(__dirname, '..', '..', '..');
const NODE_MODULES = path.join(REPO_ROOT, 'node_modules');
// Verbatim copies of the PR head (2e47450) versions of the files the detector
// patch changes, laid out like the repo. Their other imports resolve to the repo.
const PR_HEAD_ROOT = path.resolve(__dirname, '..', 'pr-head');

const loaded = new Map();
let installed = false;

const existsAsModule = (candidate) =>
    ['', '.ts', '.js', `${path.sep}index.ts`].some((suffix) => fs.existsSync(`${candidate}${suffix}`));

const requireFromRepo = (request) => require(require.resolve(request, { paths: [REPO_ROOT] }));

const disabled = (name) => () => {
    throw new Error(`${name} is disabled in the PR #46 replay harness`);
};

const NATIVE_STUBS = {
    'nftables-napi': {
        NftManager: class NftManagerStub {
            constructor() {
                disabled('nftables-napi')();
            }
        },
    },
    sockdestroy: {
        hasCapNetAdmin: () => false,
        killSockets: disabled('sockdestroy.killSockets'),
    },
};

const readAliases = (ts) => {
    const configPath = path.join(REPO_ROOT, 'tsconfig.json');
    const { config, error } = ts.readConfigFile(configPath, ts.sys.readFile);
    if (error) throw new Error(`Cannot read ${configPath}`);

    const baseUrl = path.resolve(REPO_ROOT, config.compilerOptions.baseUrl ?? '.');
    return Object.entries(config.compilerOptions.paths ?? {}).map(([pattern, targets]) => ({
        prefix: pattern.replace(/\*$/, ''),
        target: path.resolve(baseUrl, targets[0].replace(/\*$/, '')),
    }));
};

const install = () => {
    if (installed) return;
    installed = true;
    const ts = requireFromRepo('typescript');
    const aliases = readAliases(ts);

    const stubIds = new Map();
    for (const [name, exports] of Object.entries(NATIVE_STUBS)) {
        const id = path.join(__dirname, '__native_stub__', `${name}.js`);
        const stub = new Module(id);
        stub.filename = id;
        stub.loaded = true;
        stub.exports = exports;
        require.cache[id] = stub;
        stubIds.set(name, id);
    }

    const originalResolve = Module._resolveFilename;
    Module._resolveFilename = function resolve(request, parent, ...rest) {
        const stubId = stubIds.get(request);
        if (stubId) return stubId;

        if (request.startsWith('.') && parent?.filename?.startsWith(PR_HEAD_ROOT)) {
            const candidate = path.resolve(path.dirname(parent.filename), request);
            if (!existsAsModule(candidate)) {
                request = path.join(REPO_ROOT, path.relative(PR_HEAD_ROOT, candidate));
            }
        }

        for (const alias of aliases) {
            if (request.startsWith(alias.prefix)) {
                request = path.join(alias.target, request.slice(alias.prefix.length));
                break;
            }
        }
        return originalResolve.call(this, request, parent, ...rest);
    };

    const compilerOptions = {
        module: ts.ModuleKind.CommonJS,
        target: ts.ScriptTarget.ES2022,
        esModuleInterop: true,
        experimentalDecorators: true,
        emitDecoratorMetadata: true,
        useDefineForClassFields: true,
        inlineSourceMap: true,
    };

    const nativeTs = Module._extensions['.ts'];
    Module._extensions['.ts'] = function compileTs(module, filename) {
        if (!filename.startsWith(REPO_ROOT) || filename.startsWith(NODE_MODULES)) {
            if (nativeTs) return nativeTs(module, filename);
            throw new Error(`Refusing to load ${filename}`);
        }
        const source = fs.readFileSync(filename, 'utf8');
        const { outputText } = ts.transpileModule(source, { fileName: filename, compilerOptions });
        module._compile(outputText, filename);
    };
};

/**
 * Returns the PR's real runtime pieces used by the harness.
 * `patched`: the code on this branch. `head`: the PR #46 head detector files
 * from pr-head/, sharing every other module with the branch.
 */
const loadPr = (variant = 'patched') => {
    if (loaded.has(variant)) return loaded.get(variant);
    if (variant !== 'patched' && variant !== 'head') throw new Error(`Unknown variant ${variant}`);
    install();

    requireFromRepo('reflect-metadata');
    const { Logger } = requireFromRepo('@nestjs/common');
    const root = variant === 'head' ? PR_HEAD_ROOT : REPO_ROOT;
    const src = (relative) => require(path.join(REPO_ROOT, relative));
    const variantSrc = (relative) => require(path.join(root, relative));

    // The handler formats a debug timing string on every webhook even with debug
    // logging off; the harness silences logs, so it skips the formatting too.
    src('src/common/utils/get-elapsed-time.ts').formatExecutionTime = () => '';

    const handlerModule = variantSrc('src/modules/_plugin/events/xray-webhook/xray-webhook.handler.ts');
    const mapObservation = handlerModule.toAbuseBlockerObservation;
    // The harness maps each event once with the PR's own function (to label it)
    // and hands that result to the handler's own call for the same event.
    let handoff = null;
    const sameEvent = (a, b) =>
        a.ts === b.ts &&
        a.email === b.email &&
        a.network === b.network &&
        a.source === b.source &&
        a.destination === b.destination &&
        a.originalTarget === b.originalTarget &&
        a.routeTarget === b.routeTarget;
    handlerModule.toAbuseBlockerObservation = (webhook, options) => {
        if (handoff && sameEvent(handoff.webhook, webhook)) {
            const { observation } = handoff;
            handoff = null;
            return observation && { ...observation, xrayReport: webhook };
        }
        return mapObservation(webhook, options);
    };
    const { AbuseBlockerState } = variantSrc('src/modules/_plugin/services/states/abuse-blocker.state.ts');
    const { XrayWebhookEvent } = src('src/modules/_plugin/events/xray-webhook/xray-webhook.event.ts');
    const { PluginStateService } = src('src/modules/_plugin/services/plugin-state.service.ts');
    const { IpMatcher, parseNetworkEndpoint } = src('src/modules/_plugin/utils/ip-address.utils.ts');
    const { NodePluginSchema } = requireFromRepo('@remnawave/node-plugins');

    const result = {
        variant,
        REPO_ROOT,
        Logger,
        XrayWebhookHandler: handlerModule.XrayWebhookHandler,
        toAbuseBlockerObservation: mapObservation,
        /** Maps `webhook` and keeps the result for the handler's next call. */
        mapForHandler: (webhook, options) => {
            const observation = mapObservation(webhook, options);
            handoff = { webhook, observation };
            return observation;
        },
        XrayWebhookEvent,
        AbuseBlockerState,
        IpMatcher,
        parseNetworkEndpoint,
        NodePluginSchema,
        /** The handler only reads `abuseBlocker` (and `torrentBlocker` for other targets). */
        createPluginState: () => {
            if (variant === 'patched') return new PluginStateService();
            return { abuseBlocker: new AbuseBlockerState(), torrentBlocker: { isEnabled: false } };
        },
    };
    loaded.set(variant, result);
    return result;
};

/** Makes plain `require()` of the repo's .ts files work (used to run the PR's own tests). */
const installTsHook = () => install();

module.exports = { loadPr, installTsHook, REPO_ROOT, PR_HEAD_ROOT };

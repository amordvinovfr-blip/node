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

let loaded = null;

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
 */
const loadPr = () => {
    if (loaded) return loaded;
    install();

    requireFromRepo('reflect-metadata');
    const { Logger } = requireFromRepo('@nestjs/common');
    const src = (relative) => require(path.join(REPO_ROOT, relative));

    const handlerModule = src('src/modules/_plugin/events/xray-webhook/xray-webhook.handler.ts');
    const { XrayWebhookEvent } = src('src/modules/_plugin/events/xray-webhook/xray-webhook.event.ts');
    const { PluginStateService } = src('src/modules/_plugin/services/plugin-state.service.ts');
    const { AbuseBlockerState } = src('src/modules/_plugin/services/states/abuse-blocker.state.ts');
    const { IpMatcher, parseNetworkEndpoint } = src('src/modules/_plugin/utils/ip-address.utils.ts');
    const { NodePluginSchema } = requireFromRepo('@remnawave/node-plugins');

    loaded = {
        REPO_ROOT,
        Logger,
        XrayWebhookHandler: handlerModule.XrayWebhookHandler,
        toAbuseBlockerObservation: handlerModule.toAbuseBlockerObservation,
        XrayWebhookEvent,
        PluginStateService,
        AbuseBlockerState,
        IpMatcher,
        parseNetworkEndpoint,
        NodePluginSchema,
    };
    return loaded;
};

module.exports = { loadPr, REPO_ROOT };

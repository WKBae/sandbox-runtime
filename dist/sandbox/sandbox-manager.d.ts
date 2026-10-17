import { SentinelRegistry } from './credential-sentinel.js';
import { MaskedFileStore } from './credential-mask-files.js';
import { AwsPairRegistry } from './credential-aws-pairs.js';
import { type MitmCA } from './mitm-ca.js';
import type { SandboxRuntimeConfig } from './sandbox-config.js';
import type { SandboxAskCallback, FsReadRestrictionConfig, FsWriteRestrictionConfig, NetworkRestrictionConfig } from './sandbox-schemas.js';
import { type SandboxDependencyCheck } from './linux-sandbox-utils.js';
import { type WindowsBinShell } from './windows-sandbox-utils.js';
import { SandboxViolationStore } from './sandbox-violation-store.js';
/** Exported for testing. */
export declare function registerCommandText(command: string, options: WrapWithSandboxOptions | undefined): void;
/**
 * The command text for a decoded attribution key. Keys arrive over carriers
 * the sandboxed process can write (the observe socket's event field, the
 * macOS log tag, the proxy username), so only a key this process registered
 * carries the embedder's own text; anything else is untrusted bytes.
 * Exported for testing.
 */
export declare function resolveCommandText(decodedKey: string): string;
/**
 * Per-invocation options for {@link wrapWithSandbox} /
 * {@link wrapWithSandboxArgv} that aren't sandbox *policy* (that's
 * `customConfig`).
 */
export type WrapWithSandboxOptions = {
    /**
     * Opaque per-invocation correlation key. Violations observed while the
     * wrapped command runs (seatbelt log lines, seccomp events, proxy denies)
     * are stored under this key, so it must equal what you later pass to
     * `annotateStderrWithSandboxFailures` / `getViolationsForCommand`.
     * Defaults to `command`. Prefer a unique id (e.g. a tool-use id) over the
     * command text: keys are compared on their first 100 characters, so two
     * long commands sharing a prefix would otherwise cross-attribute, and a
     * rerun of the same text would inherit the earlier run's events.
     *
     * An id that a network allow list is registered under must also be
     * unguessable: see `registerCommandNetworkLists`.
     */
    commandId?: string;
    /**
     * The command this invocation *represents*, when that differs from the
     * string being wrapped (e.g. you wrap an assembled
     * `source <snapshot> && eval '<cmd>'` but the user-facing command is
     * `<cmd>`). Used for `ignoreViolations` command-pattern matching and
     * reported as the violation's `command`. Defaults to `command`.
     */
    commandText?: string;
};
/**
 * Interface for the sandbox manager API
 */
export interface ISandboxManager {
    initialize(runtimeConfig: SandboxRuntimeConfig, sandboxAskCallback?: SandboxAskCallback, enableLogMonitor?: boolean): Promise<void>;
    isSupportedPlatform(): boolean;
    isSandboxingEnabled(): boolean;
    checkDependencies(ripgrepConfig?: {
        command: string;
        args?: string[];
    }): SandboxDependencyCheck;
    checkDependenciesAsync(ripgrepConfig?: {
        command: string;
        args?: string[];
    }): Promise<SandboxDependencyCheck>;
    getFsReadConfig(): FsReadRestrictionConfig;
    getFsWriteConfig(): FsWriteRestrictionConfig;
    getNetworkRestrictionConfig(): NetworkRestrictionConfig;
    getAllowUnixSockets(): string[] | undefined;
    getAllowLocalBinding(): boolean | undefined;
    getAllowMachLookup(): string[] | undefined;
    getIgnoreViolations(): Record<string, string[]> | undefined;
    getEnableWeakerNestedSandbox(): boolean | undefined;
    getProxyPort(): number | undefined;
    getProxyAuthToken(): string | undefined;
    getSocksProxyPort(): number | undefined;
    getLinuxHttpSocketPath(): string | undefined;
    getLinuxSocksSocketPath(): string | undefined;
    waitForNetworkInitialization(): Promise<boolean>;
    wrapWithSandbox(command: string, binShell?: string, customConfig?: Partial<SandboxRuntimeConfig>, abortSignal?: AbortSignal, options?: WrapWithSandboxOptions): Promise<string>;
    wrapWithSandboxArgv(command: string, binShell?: string | WindowsBinShell, customConfig?: Partial<SandboxRuntimeConfig>, abortSignal?: AbortSignal, cwd?: string, options?: WrapWithSandboxOptions): Promise<{
        argv: string[];
        env: NodeJS.ProcessEnv;
    }>;
    /**
     * Register the network allow list of one invocation, under the `commandId`
     * its wrap was given ({@link WrapWithSandboxOptions}). Entries are matched
     * and validated as `network.allowedDomains` entries are; an invalid one
     * throws. Registering an id again replaces its list.
     *
     * Order of evaluation for a connection: a configured `deniedDomains` match
     * denies; a configured `allowedDomains` match allows;
     * `network.strictAllowlist` denies; a match in the list registered for the
     * id the connection presents allows; then the ask callback decides if
     * there is one, and otherwise the connection is denied. So a per-command
     * entry never overrides a configured `deniedDomains` entry and is ignored
     * entirely under `strictAllowlist`. It also never enters `network.*`, so
     * the default `injectHosts` scope of a masked credential does not grow.
     *
     * The proxy reads the id from the proxy username, which the sandboxed
     * client presents, so the id is the ONLY thing binding a connection to an
     * allow list. It MUST be unguessable: at least 128 bits of randomness (16
     * random bytes as base64url, 22 characters; a shorter id throws), never a
     * counter, a timestamp or anything derived from the command. Presenting
     * another live invocation's id gets that invocation's allows: this is
     * attribution, not a boundary between concurrent commands of one session.
     *
     * Register just before spawning the wrapped command, and unregister when
     * the child exits or never started: a registration that outlives its
     * command widens the window in which its id is worth presenting.
     *
     * As with every attribution key, only the first 100 characters of an id
     * take part, and a list under an id whose encoded form does not fit in the
     * proxy username (possible only with non-ASCII ids) never applies. An
     * unpaired surrogate does not count towards the 22 characters.
     *
     * No list applies while `network.httpProxyPort` names an external proxy:
     * the wrap gives that proxy no username, so no connection carries an id.
     * Registering still succeeds, and every connection is decided as if no list
     * existed.
     */
    registerCommandNetworkLists(commandId: string, lists: {
        allowedDomains?: string[];
    }): void;
    /**
     * Remove the list registered for `commandId`. A no-op for an id that has
     * none. `reset()` removes them all.
     */
    unregisterCommandNetworkLists(commandId: string): void;
    /**
     * True when the network filter understands an ask callback's
     * `{ allow: false, reason }` answer (see {@link SandboxAskCallback}). Read
     * it before returning that object: releases up to v0.0.77 allow on any
     * truthy answer, so there the object would be read as an allow. Where this
     * is absent, deny with a plain `false`.
     */
    readonly askCallbackDenyReason: true;
    getSandboxViolationStore(): SandboxViolationStore;
    annotateStderrWithSandboxFailures(command: string, stderr: string): string;
    getLinuxGlobPatternWarnings(): string[];
    getConfig(): SandboxRuntimeConfig | undefined;
    getMitmCA(): MitmCA | undefined;
    getSentinelRegistry(): SentinelRegistry;
    getAwsPairRegistry(): AwsPairRegistry;
    getMaskedFileStore(): MaskedFileStore;
    updateConfig(newConfig: SandboxRuntimeConfig): void;
    cleanupAfterCommand(): void;
    reset(): Promise<void>;
}
/**
 * Global sandbox manager that handles both network and filesystem restrictions
 * for this session. This runs outside of the sandbox, on the host machine.
 */
export declare const SandboxManager: ISandboxManager;
//# sourceMappingURL=sandbox-manager.d.ts.map
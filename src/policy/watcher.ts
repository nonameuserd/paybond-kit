import { watch, type FSWatcher } from "node:fs";
import { resolve } from "node:path";

import {
  type PaybondPolicyReloadBindConfig,
  type PaybondPolicyReloadOptions,
  type PaybondPolicyReloadResult,
} from "./reload.js";

const DEFAULT_WATCH_DEBOUNCE_MS = 500;
const DEFAULT_POLL_INTERVAL_MS = 60_000;

/** Minimal reload surface for background watch/poll schedulers. */
export type PolicyReloadRunner = {
  reloadPolicy(options?: PaybondPolicyReloadOptions): Promise<PaybondPolicyReloadResult>;
};

export type PaybondPolicyReloadControllerState = {
  watch: boolean;
  poll: boolean;
  policyFilePath?: string;
  lastReloadAt?: string;
  lastReloadError?: string;
};

/** Background file watcher and Gateway poll scheduler for policy hot-reload. */
export class PaybondPolicyReloadController {
  private fileWatcher: FSWatcher | undefined;
  private pollTimer: ReturnType<typeof setInterval> | undefined;
  private debounceTimer: ReturnType<typeof setTimeout> | undefined;
  private reloadInFlight = false;
  private readonly policyFilePath: string;
  private readonly reloadDefaults: PaybondPolicyReloadOptions;
  readonly state: PaybondPolicyReloadControllerState;

  private constructor(
    private readonly runner: PolicyReloadRunner,
    options: {
      policyFilePath: string;
      reloadDefaults: PaybondPolicyReloadOptions;
      state: PaybondPolicyReloadControllerState;
    },
  ) {
    this.policyFilePath = options.policyFilePath;
    this.reloadDefaults = options.reloadDefaults;
    this.state = options.state;
  }

  static start(
    runner: PolicyReloadRunner,
    config: PaybondPolicyReloadBindConfig,
    policyFilePath: string,
  ): PaybondPolicyReloadController | undefined {
    const watchEnabled = config.watch === true || typeof config.watch === "object";
    const pollEnabled = config.poll !== undefined;
    if (!watchEnabled && !pollEnabled) {
      return undefined;
    }

    const resolvedPath = resolve(policyFilePath);
    const reloadDefaults: PaybondPolicyReloadOptions = {
      file: resolvedPath,
      remote: config.poll?.remote,
      resolveInheritance: config.poll?.resolveInheritance,
      gateway: config.poll?.gateway,
    };

    const controller = new PaybondPolicyReloadController(runner, {
      policyFilePath: resolvedPath,
      reloadDefaults,
      state: {
        watch: watchEnabled,
        poll: pollEnabled,
        policyFilePath: resolvedPath,
      },
    });

    if (watchEnabled) {
      controller.startFileWatch(config.watch);
    }
    if (pollEnabled) {
      controller.startGatewayPoll(config.poll ?? {});
    }
    return controller;
  }

  private startFileWatch(watchConfig: PaybondPolicyReloadBindConfig["watch"]): void {
    const debounceMs =
      typeof watchConfig === "object" && watchConfig.debounceMs !== undefined
        ? watchConfig.debounceMs
        : DEFAULT_WATCH_DEBOUNCE_MS;

    this.fileWatcher = watch(this.policyFilePath, () => {
      if (this.debounceTimer) {
        clearTimeout(this.debounceTimer);
      }
      this.debounceTimer = setTimeout(() => {
        void this.triggerReload({ remote: false });
      }, debounceMs);
    });
  }

  private startGatewayPoll(pollConfig: NonNullable<PaybondPolicyReloadBindConfig["poll"]>): void {
    const intervalMs = pollConfig.intervalMs ?? DEFAULT_POLL_INTERVAL_MS;
    this.pollTimer = setInterval(() => {
      void this.triggerReload({
        remote: pollConfig.remote ?? true,
        resolveInheritance: pollConfig.resolveInheritance ?? true,
        gateway: pollConfig.gateway ?? this.reloadDefaults.gateway,
      });
    }, intervalMs);
  }

  private async triggerReload(overrides: PaybondPolicyReloadOptions): Promise<void> {
    if (this.reloadInFlight) {
      return;
    }
    this.reloadInFlight = true;
    try {
      const result = await this.runner.reloadPolicy({
        ...this.reloadDefaults,
        ...overrides,
        file: this.policyFilePath,
      });
      if (result.applied) {
        this.state.lastReloadAt = new Date().toISOString();
        this.state.lastReloadError = undefined;
      }
    } catch (err) {
      const message = err instanceof Error ? err.message : String(err);
      this.state.lastReloadError = message;
    } finally {
      this.reloadInFlight = false;
    }
  }

  stop(): void {
    if (this.fileWatcher) {
      this.fileWatcher.close();
      this.fileWatcher = undefined;
    }
    if (this.pollTimer) {
      clearInterval(this.pollTimer);
      this.pollTimer = undefined;
    }
    if (this.debounceTimer) {
      clearTimeout(this.debounceTimer);
      this.debounceTimer = undefined;
    }
  }
}

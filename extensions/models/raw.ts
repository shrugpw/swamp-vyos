/**
 * VyOS raw config transport (show/tree/apply/diff/run): config/result schemas, resource specs, and the raw
 * read/apply/run methods. Assembled into the model in `vyos.ts`.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  buildConfigScript,
  extractDiff,
  OP_WRAPPER,
  SCRIPT_REDACTED,
  SCRIPT_TEMPLATE,
  SENTINEL_CHANGED,
  sshExec,
  validateApplyPaths,
} from "./core.ts";
import type { ExecuteContext, ExecuteResult, SshRunner } from "./core.ts";

/** Snapshot of the running configuration as `set` commands. */
const ConfigSchema = z.object({
  host: z.string(),
  command: z.string(),
  commands: z.string().describe("Raw output of the op-mode show command"),
  retrievedAt: z.iso.datetime(),
});

/**
 * Structured running configuration from native `show configuration json`.
 *
 * The well-known top-level sections are declared so CEL expressions can
 * reference them (e.g. `...attributes.interfaces`), and `.passthrough()` keeps
 * any section a given VyOS version emits that isn't listed here (rather than
 * silently dropping it). Nested content is intentionally permissive — the VyOS
 * tree is deep and version-variable.
 */
const treeSection = () => z.record(z.string(), z.unknown()).optional();

const ConfigTreeSchema = z.object({
  host: z.string(),
  container: treeSection(),
  firewall: treeSection(),
  interfaces: treeSection(),
  "load-balancing": treeSection(),
  nat: treeSection(),
  nat64: treeSection(),
  pki: treeSection(),
  policy: treeSection(),
  protocols: treeSection(),
  qos: treeSection(),
  service: treeSection(),
  system: treeSection(),
  vrf: treeSection(),
  retrievedAt: z.iso.datetime(),
}).passthrough();

/** Outcome of an `apply` (config-mode) run. */
const ApplyResultSchema = z.object({
  host: z.string(),
  set: z.array(z.string()),
  delete: z.array(z.string()),
  dryRun: z.boolean().describe(
    "True when changes were previewed, not committed",
  ),
  changed: z.boolean().describe(
    "True when the session had staged config changes",
  ),
  committed: z.boolean(),
  saved: z.boolean(),
  confirmMinutes: z
    .number()
    .int()
    .default(0)
    .describe(
      "Minutes of the commit-confirm auto-revert timer this apply armed (0 = plain commit)",
    ),
  confirmPending: z
    .boolean()
    .default(false)
    .describe(
      "True when a commit-confirm was armed and still awaits `confirm` to be made permanent",
    ),
  script: z
    .string()
    .describe("The vbash script that was piped (redacted unless storeScript)"),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  appliedAt: z.iso.datetime(),
});

/**
 * Same shape as {@link ApplyResultSchema}, but the secret-bearing fields are
 * marked `sensitive` so they are stored in the `vyos` vault and replaced with
 * vault references at persist time. Operational fields (host, changed,
 * committed, exitCode, ...) stay in cleartext so the record is still glanceable
 * without vault access. Written only when `apply` is called with `sensitive`.
 */
const SensitiveApplyResultSchema = ApplyResultSchema.extend({
  set: z.array(z.string()).meta({ sensitive: true }),
  delete: z.array(z.string()).meta({ sensitive: true }),
  script: z
    .string()
    .meta({ sensitive: true })
    .describe("The vbash script that was piped (vaulted)"),
  stdout: z.string().meta({ sensitive: true }),
  stderr: z.string().meta({ sensitive: true }),
});

/** Preview of the config change a `set`/`delete` would make (VyOS `compare`). */
const DiffResultSchema = z.object({
  host: z.string(),
  set: z.array(z.string()),
  delete: z.array(z.string()),
  changed: z.boolean().describe(
    "True when the staged change differs from the running config",
  ),
  diff: z
    .string()
    .describe(
      "The `compare` output for the staged change (empty if unchanged)",
    ),
  stderr: z.string(),
  exitCode: z.number().int(),
  comparedAt: z.iso.datetime(),
});

/**
 * Same shape as {@link DiffResultSchema} with the secret-bearing fields marked
 * `sensitive` (the `compare` output echoes staged `set` lines, which may include
 * keys). Vaulted; operational fields stay cleartext. Written when `diff` is
 * called with `sensitive`.
 */
const SensitiveDiffResultSchema = DiffResultSchema.extend({
  set: z.array(z.string()).meta({ sensitive: true }),
  delete: z.array(z.string()).meta({ sensitive: true }),
  diff: z
    .string()
    .meta({ sensitive: true })
    .describe("The `compare` output for the staged change (vaulted)"),
  stderr: z.string().meta({ sensitive: true }),
});

/** Outcome of a generic `run` (op- or config-mode) command. */
const CommandResultSchema = z.object({
  host: z.string(),
  command: z.string(),
  opMode: z.boolean(),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  ranAt: z.iso.datetime(),
});

/** Outcome of a `confirm` (make a pending commit-confirm permanent, then save). */
const ConfirmResultSchema = z.object({
  host: z.string(),
  confirmed: z.boolean().describe(
    "True when op-mode `confirm` cancelled the pending auto-revert timer",
  ),
  saved: z.boolean().describe(
    "True when the now-permanent running config was saved to config.boot",
  ),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  confirmedAt: z.iso.datetime(),
});

/** Resource specs for the raw config transport. */
export const rawResources = {
  "config": {
    description: "Running configuration snapshot (as set commands)",
    schema: ConfigSchema,
    lifetime: "infinite",
    garbageCollection: 20,
  },
  "applyResult": {
    description: "Outcome of an apply (config-mode) run",
    schema: ApplyResultSchema,
    lifetime: "infinite",
    garbageCollection: 50,
  },
  "sensitiveApplyResult": {
    description:
      "Outcome of an apply run with secret-bearing fields vaulted (sensitive=true)",
    schema: SensitiveApplyResultSchema,
    vaultName: "vyos",
    lifetime: "infinite",
    garbageCollection: 50,
  },
  "diff": {
    description:
      "Preview of a set/delete change (VyOS compare), never committed",
    schema: DiffResultSchema,
    lifetime: "infinite",
    garbageCollection: 50,
  },
  "sensitiveDiff": {
    description:
      "Preview of a set/delete change with secret-bearing fields vaulted (sensitive=true)",
    schema: SensitiveDiffResultSchema,
    vaultName: "vyos",
    lifetime: "infinite",
    garbageCollection: 50,
  },
  "configTree": {
    description: "Structured running config (native show configuration json)",
    schema: ConfigTreeSchema,
    lifetime: "infinite",
    garbageCollection: 20,
  },
  "sensitiveConfigTree": {
    description:
      "Structured running config with the whole tree vaulted (sensitive=true)",
    schema: ConfigTreeSchema,
    sensitiveOutput: true,
    vaultName: "vyos",
    lifetime: "infinite",
    garbageCollection: 20,
  },
  "commandResult": {
    description: "Outcome of a generic run command",
    schema: CommandResultSchema,
    lifetime: "infinite",
    garbageCollection: 50,
  },
  "confirmResult": {
    description:
      "Outcome of a confirm (cancel a pending commit-confirm timer, then save)",
    schema: ConfirmResultSchema,
    lifetime: "infinite",
    garbageCollection: 50,
  },
};

/** Raw read/apply/run method definitions. */
export const rawMethods = {
  show: {
    description:
      "Read the running config (or any op-mode show command) and snapshot it.",
    arguments: z.object({
      command: z
        .string()
        .default("show configuration commands")
        .describe("Op-mode command to run (without the wrapper prefix)"),
    }),
    execute: async (
      args: { command: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading config from {host}: {command}", {
        host: cfg.host,
        command: args.command,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, ...args.command.split(/\s+/)],
      });
      if (result.code !== 0) {
        context.logger.error("show failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `show failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      const handle = await context.writeResource("config", "current", {
        host: cfg.host,
        command: args.command,
        commands: result.stdout,
        retrievedAt: new Date().toISOString(),
      });
      context.logger.info("Snapshotted config from {host}", {
        host: cfg.host,
      });
      return { dataHandles: [handle] };
    },
  },
  tree: {
    description:
      "Read the running config as a structured tree (native show configuration json), queryable via CEL.",
    arguments: z.object({
      sensitive: z
        .boolean()
        .default(false)
        .describe(
          "Vault the whole config tree (it embeds WireGuard/PKI private " +
            "keys) in the 'vyos' vault; requires that vault to be configured",
        ),
    }),
    execute: async (
      args: { sensitive: boolean; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading config tree from {host}", {
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error("tree failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `tree failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `tree: could not parse 'show configuration json' from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      const targetSpec = args.sensitive ? "sensitiveConfigTree" : "configTree";
      const handle = await context.writeResource(targetSpec, "current", {
        host: cfg.host,
        ...parsed,
        retrievedAt: new Date().toISOString(),
      });
      context.logger.info(
        "Snapshotted config tree from {host} ({sections} sections)",
        { host: cfg.host, sections: Object.keys(parsed).length },
      );
      return { dataHandles: [handle] };
    },
  },
  apply: {
    description:
      "Apply set/delete config commands via vbash, then commit and save.",
    arguments: z.object({
      set: z
        .array(z.string())
        .default([])
        .describe("Config paths to set (without the leading 'set')"),
      delete: z
        .array(z.string())
        .default([])
        .describe("Config paths to delete (without the leading 'delete')"),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      confirmMinutes: z
        .number()
        .int()
        .min(0)
        .default(0)
        .describe(
          "When > 0, commit with `commit-confirm <N>` (an N-minute auto-revert " +
            "timer) instead of a bare commit, and do not save until `confirm`; " +
            "for management-severing changes that must roll back if they cut the " +
            "mgmt path. Requires commit=true and dryRun=false.",
        ),
      dryRun: z
        .boolean()
        .default(false)
        .describe("Stage changes and print the diff without committing"),
      storeScript: z
        .boolean()
        .default(false)
        .describe("Persist the generated vbash script (may contain secrets)"),
      sensitive: z
        .boolean()
        .default(false)
        .describe(
          "Vault the secret-bearing fields (set/delete/script/stdout/stderr) " +
            "in the 'vyos' vault; requires that vault to be configured",
        ),
    }),
    execute: async (
      args: {
        set: string[];
        delete: string[];
        commit: boolean;
        save: boolean;
        confirmMinutes?: number;
        dryRun: boolean;
        storeScript: boolean;
        sensitive: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      if (args.set.length === 0 && args.delete.length === 0) {
        throw new Error("apply requires at least one set or delete command");
      }
      // Tests call execute directly, bypassing the zod default, so read it
      // defensively.
      const confirmMinutes = args.confirmMinutes ?? 0;
      if (confirmMinutes > 0 && !args.commit) {
        throw new Error(
          "apply: confirmMinutes requires commit=true (a commit-confirm is a commit)",
        );
      }
      if (confirmMinutes > 0 && args.dryRun) {
        throw new Error(
          "apply: confirmMinutes cannot be combined with dryRun (dryRun never commits)",
        );
      }
      validateApplyPaths(args.set, args.delete);
      const script = buildConfigScript({
        sets: args.set,
        deletes: args.delete,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
        confirmMinutes,
      });
      context.logger.info(
        "Applying to {host}: {sets} set, {deletes} delete (dryRun={dryRun}, confirmMinutes={confirmMinutes})",
        {
          host: cfg.host,
          sets: args.set.length,
          deletes: args.delete.length,
          dryRun: args.dryRun,
          confirmMinutes,
        },
      );
      const result = await ssh(cfg, {
        command: ["/bin/vbash", "-s"],
        stdin: script,
      });
      const changed = result.stdout.includes(SENTINEL_CHANGED);
      const committed = args.commit && changed && !args.dryRun;
      // A commit-confirm armed a timer that still awaits `confirm`.
      const confirmPending = confirmMinutes > 0 && changed && !args.dryRun &&
        result.code === 0;
      // When sensitive, the whole record is vaulted, so redacting the script
      // is pointless — persist it in full (it is protected by the vault).
      const persistFullScript = args.sensitive || args.storeScript;
      const targetSpec = args.sensitive
        ? "sensitiveApplyResult"
        : "applyResult";
      const handle = await context.writeResource(targetSpec, "last", {
        host: cfg.host,
        set: args.set,
        delete: args.delete,
        dryRun: args.dryRun,
        changed,
        committed,
        // A commit-confirm deliberately does not save until `confirm`, so the
        // record must never claim saved=true in that path even if save was set.
        saved: committed && args.save && confirmMinutes === 0,
        confirmMinutes,
        confirmPending,
        script: persistFullScript ? script : SCRIPT_REDACTED,
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.code,
        appliedAt: new Date().toISOString(),
      });
      if (result.code !== 0) {
        context.logger.error("apply failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `apply failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "apply on {host} complete (changed={changed}, committed={committed}, confirmPending={confirmPending})",
        { host: cfg.host, changed, committed, confirmPending },
      );
      return { dataHandles: [handle] };
    },
  },
  diff: {
    description:
      "Preview the config change a set/delete would make (VyOS compare) without committing — read-only.",
    arguments: z.object({
      set: z
        .array(z.string())
        .default([])
        .describe("Config paths to stage as set (without the leading 'set')"),
      delete: z
        .array(z.string())
        .default([])
        .describe(
          "Config paths to stage as delete (without the leading 'delete')",
        ),
      sensitive: z
        .boolean()
        .default(false)
        .describe(
          "Vault the secret-bearing fields (set/delete/diff/stderr) in the " +
            "'vyos' vault; requires that vault to be configured",
        ),
    }),
    execute: async (
      args: {
        set: string[];
        delete: string[];
        sensitive: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      if (args.set.length === 0 && args.delete.length === 0) {
        throw new Error("diff requires at least one set or delete command");
      }
      validateApplyPaths(args.set, args.delete);
      // dryRun stages the change, prints `compare`, and discards — never
      // commits. commit/save are irrelevant in the dryRun branch.
      const script = buildConfigScript({
        sets: args.set,
        deletes: args.delete,
        commit: false,
        save: false,
        dryRun: true,
      });
      context.logger.info(
        "Diffing on {host}: {sets} set, {deletes} delete",
        {
          host: cfg.host,
          sets: args.set.length,
          deletes: args.delete.length,
        },
      );
      const result = await ssh(cfg, {
        command: ["/bin/vbash", "-s"],
        stdin: script,
      });
      const changed = result.stdout.includes(SENTINEL_CHANGED);
      const targetSpec = args.sensitive ? "sensitiveDiff" : "diff";
      const handle = await context.writeResource(targetSpec, "last", {
        host: cfg.host,
        set: args.set,
        delete: args.delete,
        changed,
        diff: extractDiff(result.stdout),
        stderr: result.stderr,
        exitCode: result.code,
        comparedAt: new Date().toISOString(),
      });
      if (result.code !== 0) {
        context.logger.error("diff failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `diff failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info("diff on {host} complete (changed={changed})", {
        host: cfg.host,
        changed,
      });
      return { dataHandles: [handle] };
    },
  },
  run: {
    description:
      "Run an arbitrary command over SSH (op-mode wrapped when opMode=true).",
    arguments: z.object({
      command: z.string().describe("Command to run on the router"),
      opMode: z
        .boolean()
        .default(false)
        .describe("Prefix with the VyOS op-mode wrapper"),
    }),
    execute: async (
      args: { command: string; opMode: boolean; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Running on {host} (opMode={opMode}): {command}", {
        host: cfg.host,
        opMode: args.opMode,
        command: args.command,
      });
      const argv = args.opMode
        ? [OP_WRAPPER, ...args.command.split(/\s+/)]
        : ["sh", "-c", args.command];
      const result = await ssh(cfg, { command: argv });
      const handle = await context.writeResource("commandResult", "last", {
        host: cfg.host,
        command: args.command,
        opMode: args.opMode,
        stdout: result.stdout,
        stderr: result.stderr,
        exitCode: result.code,
        ranAt: new Date().toISOString(),
      });
      if (result.code !== 0) {
        context.logger.error("run failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `run failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info("run on {host} complete", { host: cfg.host });
      return { dataHandles: [handle] };
    },
  },
  confirm: {
    description:
      "Make a pending commit-confirm permanent: cancel the auto-revert timer (op-mode `confirm`), then save the now-permanent running config to config.boot.",
    arguments: z.object({
      save: z
        .boolean()
        .default(true)
        .describe(
          "Persist the now-permanent config to config.boot after confirming",
        ),
    }),
    execute: async (
      args: { save: boolean; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Confirming pending commit-confirm on {host}", {
        host: cfg.host,
      });
      const confirmRes = await ssh(cfg, { command: [OP_WRAPPER, "confirm"] });
      const confirmed = confirmRes.code === 0;
      let saveRes: { stdout: string; stderr: string; code: number } | null =
        null;
      if (args.save && confirmed) {
        // `confirm` only makes the change permanent in the running config; save
        // persists it to config.boot so it survives a reboot.
        const saveScript = `source ${SCRIPT_TEMPLATE}\nconfigure\nsave\nexit\n`;
        saveRes = await ssh(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: saveScript,
        });
      }
      const saved = saveRes !== null && saveRes.code === 0;
      const exitCode = !confirmed ? confirmRes.code : (saveRes?.code ?? 0);
      const handle = await context.writeResource("confirmResult", "last", {
        host: cfg.host,
        confirmed,
        saved,
        stdout: confirmRes.stdout + (saveRes?.stdout ?? ""),
        stderr: confirmRes.stderr + (saveRes?.stderr ?? ""),
        exitCode,
        confirmedAt: new Date().toISOString(),
      });
      if (!confirmed) {
        context.logger.error("confirm failed on {host} (exit {code})", {
          host: cfg.host,
          code: confirmRes.code,
        });
        throw new Error(
          `confirm failed on ${cfg.host} (exit ${confirmRes.code}): ${confirmRes.stderr}`,
        );
      }
      if (args.save && !saved) {
        context.logger.error("confirm: save failed on {host} (exit {code})", {
          host: cfg.host,
          code: saveRes?.code,
        });
        throw new Error(
          `confirm: save failed on ${cfg.host} (exit ${saveRes?.code}): ${saveRes?.stderr}`,
        );
      }
      context.logger.info(
        "confirm on {host} complete (confirmed={confirmed}, saved={saved})",
        { host: cfg.host, confirmed, saved },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Raw methods that require the reachable pre-flight check. */
export const rawCheckMethods = ["apply", "diff", "confirm"];

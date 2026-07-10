/**
 * VyOS router management model.
 *
 * Manages a VyOS router over SSH: read the running configuration, apply
 * `set`/`delete` configuration commands through `vbash` (with `commit`/`save`),
 * and run arbitrary operational- or config-mode commands.
 *
 * VyOS is peculiar: configuration mode requires `vbash` sourcing the Vyatta
 * `script-template`; a plain `ssh host 'configure; set ...'` does NOT work.
 * Operational reads go through the `vyatta-op-cmd-wrapper`. This model encodes
 * those requirements so callers work in terms of plain `set`/`delete` paths.
 *
 * The SSH transport is deliberately isolated in {@link sshExec}. Once
 * model-to-model calls (`context.runModel`) land in the distributed binary,
 * that one helper can be swapped to invoke `@swamp/ssh` (`exec`/`script`)
 * instead of shelling out, with no change to the VyOS method logic. Every method
 * also accepts an injectable `_ssh` runner so the logic is unit-testable without
 * a live router.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Op-mode command wrapper — required for read-only "show ..." commands. */
const OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper";

/** Sourced inside every config session so `configure`/`set`/`commit` resolve. */
const SCRIPT_TEMPLATE = "/opt/vyatta/etc/functions/script-template";

/** Emitted by the config script when the session had staged changes. */
const SENTINEL_CHANGED = "SWAMP_APPLY_CHANGED";

/** Emitted by the config script when the session was a no-op (idempotent). */
const SENTINEL_NOCHANGE = "SWAMP_APPLY_NOCHANGE";

/** Placeholder stored in place of the vbash script when `storeScript` is off. */
const SCRIPT_REDACTED =
  "<redacted: pass storeScript=true to persist the script>";

/** Connection/authentication settings for the target VyOS router. */
const GlobalArgsSchema = z.object({
  host: z.string().describe("VyOS management IP or hostname"),
  user: z.string().default("vyos").describe("SSH username"),
  port: z.number().int().positive().default(22).describe("SSH port"),
  identityFile: z
    .string()
    .optional()
    .describe("Path to a private key; omit to use the SSH agent/ssh config"),
});

/** Resolved connection/authentication settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Snapshot of the running configuration as `set` commands. */
const ConfigSchema = z.object({
  host: z.string(),
  command: z.string(),
  commands: z.string().describe("Raw output of the op-mode show command"),
  retrievedAt: z.iso.datetime(),
});

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
  script: z
    .string()
    .describe("The vbash script that was piped (redacted unless storeScript)"),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  appliedAt: z.iso.datetime(),
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

/** Result of a single SSH invocation. */
export interface SshResult {
  stdout: string;
  stderr: string;
  code: number;
}

/**
 * Transport seam: run one command on the router over SSH, optionally piping
 * `stdin`. Methods depend on this signature (not the implementation) so it can
 * be injected in tests and swapped for `@swamp/ssh` when `context.runModel`
 * ships.
 */
export type SshRunner = (
  cfg: GlobalArgs,
  opts: { command?: string[]; stdin?: string },
) => Promise<SshResult>;

/**
 * Run one command on the router over SSH, optionally piping `stdin`.
 *
 * This is the sole transport seam. TODO(runModel): when `context.runModel`
 * ships in the distributed binary, replace the `Deno.Command("ssh", ...)` body
 * with a call to `@swamp/ssh` (`exec` for `command`, `script` for `stdin`),
 * keeping this signature so callers are unaffected.
 *
 * @param cfg Connection settings.
 * @param opts `command` (remote argv joined by ssh) and/or `stdin` to pipe.
 * @returns Captured stdout, stderr, and exit code.
 */
export const sshExec: SshRunner = async (cfg, opts) => {
  const args: string[] = [
    "-o",
    "BatchMode=yes",
    "-o",
    "ConnectTimeout=15",
    "-p",
    String(cfg.port),
  ];
  if (cfg.identityFile) args.push("-i", cfg.identityFile);
  args.push(`${cfg.user}@${cfg.host}`);
  if (opts.command) args.push(...opts.command);

  const command = new Deno.Command("ssh", {
    args,
    stdin: opts.stdin !== undefined ? "piped" : "null",
    stdout: "piped",
    stderr: "piped",
  });
  const child = command.spawn();

  if (opts.stdin !== undefined) {
    const writer = child.stdin.getWriter();
    await writer.write(new TextEncoder().encode(opts.stdin));
    await writer.close();
  }

  const { code, stdout, stderr } = await child.output();
  return {
    stdout: new TextDecoder().decode(stdout),
    stderr: new TextDecoder().decode(stderr),
    code,
  };
};

/**
 * Validate caller-supplied `set`/`delete` config paths before they are
 * interpolated into a vbash script. Rejects the common footguns: empty paths,
 * embedded newlines (which would break the generated script line structure),
 * and a leading `set `/`delete ` (the caller must pass the bare path).
 *
 * @throws Error if any path is empty, multi-line, or leadingly prefixed.
 */
export function validateApplyPaths(sets: string[], deletes: string[]): void {
  for (const [kind, list] of [["set", sets], ["delete", deletes]] as const) {
    for (const p of list) {
      if (p.trim() === "") {
        throw new Error(`apply ${kind} contains an empty path`);
      }
      if (/[\r\n]/.test(p)) {
        throw new Error(
          `apply ${kind} path must be single-line: ${JSON.stringify(p)}`,
        );
      }
      if (/^\s*(set|delete)\s/.test(p)) {
        throw new Error(
          `apply ${kind} path must omit the leading '${kind}': ${
            JSON.stringify(p)
          }`,
        );
      }
    }
  }
}

/** Options controlling the generated vbash config script. */
export interface ConfigScriptOptions {
  sets: string[];
  deletes: string[];
  commit: boolean;
  save: boolean;
  dryRun: boolean;
}

/**
 * Build the vbash config script piped to `/bin/vbash -s`.
 *
 * Deletes are guarded with `cli-shell-api existsActive` so re-deleting an
 * already-absent path is a no-op (idempotent). The session only commits when
 * `cli-shell-api sessionChanged` reports staged changes, so a repeat apply that
 * changes nothing succeeds instead of erroring on an empty commit. In `dryRun`
 * mode the staged diff is printed via `compare` and then discarded.
 */
export function buildConfigScript(opts: ConfigScriptOptions): string {
  const lines = [`source ${SCRIPT_TEMPLATE}`, "configure"];
  for (const d of opts.deletes) {
    lines.push(`if cli-shell-api existsActive ${d}; then delete ${d}; fi`);
  }
  for (const s of opts.sets) lines.push(`set ${s}`);
  lines.push("if cli-shell-api sessionChanged; then");
  if (opts.dryRun) {
    lines.push("  compare");
    lines.push(`  echo ${SENTINEL_CHANGED}`);
    lines.push("  exit discard");
  } else {
    if (opts.commit) lines.push("  commit");
    if (opts.save) lines.push("  save");
    lines.push(`  echo ${SENTINEL_CHANGED}`);
    lines.push(opts.commit ? "  exit" : "  exit discard");
  }
  lines.push("else");
  lines.push(`  echo ${SENTINEL_NOCHANGE}`);
  lines.push("  exit");
  lines.push("fi");
  return lines.join("\n") + "\n";
}

/** Minimal LogTape logger surface used by this model. */
interface Logger {
  debug: (message: string, properties?: Record<string, unknown>) => void;
  info: (message: string, properties?: Record<string, unknown>) => void;
  warning: (message: string, properties?: Record<string, unknown>) => void;
  error: (message: string, properties?: Record<string, unknown>) => void;
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Minimal shape of the pre-flight check context this model relies on. */
interface CheckContext {
  globalArgs: GlobalArgs;
  logger: Logger;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** VyOS router management model definition. */
export const model = {
  type: "@shrug/vyos",
  version: "2026.07.10.2",
  description:
    "Manage a VyOS router over SSH: read config, apply set/delete via vbash, run commands.",
  globalArguments: GlobalArgsSchema,
  resources: {
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
    "commandResult": {
      description: "Outcome of a generic run command",
      schema: CommandResultSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
  },
  checks: {
    "reachable": {
      description:
        "Verify the router's config mode is reachable over SSH before applying.",
      labels: ["live"],
      appliesTo: ["apply"],
      execute: async (context: CheckContext): Promise<
        { pass: boolean; errors?: string[] }
      > => {
        const cfg = context.globalArgs;
        context.logger.info("Probing VyOS config mode on {host}", {
          host: cfg.host,
        });
        const probe = `source ${SCRIPT_TEMPLATE}\nconfigure\nexit\n`;
        const result = await sshExec(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: probe,
        });
        if (result.code !== 0) {
          return {
            pass: false,
            errors: [
              `cannot reach VyOS config mode on ${cfg.host}: ${
                result.stderr.trim() || `exit ${result.code}`
              }`,
            ],
          };
        }
        return { pass: true };
      },
    },
  },
  methods: {
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
        dryRun: z
          .boolean()
          .default(false)
          .describe("Stage changes and print the diff without committing"),
        storeScript: z
          .boolean()
          .default(false)
          .describe("Persist the generated vbash script (may contain secrets)"),
      }),
      execute: async (
        args: {
          set: string[];
          delete: string[];
          commit: boolean;
          save: boolean;
          dryRun: boolean;
          storeScript: boolean;
          _ssh?: SshRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        if (args.set.length === 0 && args.delete.length === 0) {
          throw new Error("apply requires at least one set or delete command");
        }
        validateApplyPaths(args.set, args.delete);
        const script = buildConfigScript({
          sets: args.set,
          deletes: args.delete,
          commit: args.commit,
          save: args.save,
          dryRun: args.dryRun,
        });
        context.logger.info(
          "Applying to {host}: {sets} set, {deletes} delete (dryRun={dryRun})",
          {
            host: cfg.host,
            sets: args.set.length,
            deletes: args.delete.length,
            dryRun: args.dryRun,
          },
        );
        const result = await ssh(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: script,
        });
        const changed = result.stdout.includes(SENTINEL_CHANGED);
        const committed = args.commit && changed && !args.dryRun;
        const handle = await context.writeResource("applyResult", "last", {
          host: cfg.host,
          set: args.set,
          delete: args.delete,
          dryRun: args.dryRun,
          changed,
          committed,
          saved: committed && args.save,
          script: args.storeScript ? script : SCRIPT_REDACTED,
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
          "apply on {host} complete (changed={changed}, committed={committed})",
          { host: cfg.host, changed, committed },
        );
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
  },
};

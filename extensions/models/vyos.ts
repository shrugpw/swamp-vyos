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
 * instead of shelling out, with no change to the VyOS method logic.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Op-mode command wrapper — required for read-only "show ..." commands. */
const OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper";

/** Sourced inside every config session so `configure`/`set`/`commit` resolve. */
const SCRIPT_TEMPLATE = "/opt/vyatta/etc/functions/script-template";

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

type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

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
  committed: z.boolean(),
  saved: z.boolean(),
  script: z.string().describe("The vbash script that was piped to the router"),
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
interface SshResult {
  stdout: string;
  stderr: string;
  code: number;
}

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
async function sshExec(
  cfg: GlobalArgs,
  opts: { command?: string[]; stdin?: string },
): Promise<SshResult> {
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
}

/** Build the vbash config script piped to `/bin/vbash -s`. */
function buildConfigScript(
  sets: string[],
  deletes: string[],
  commit: boolean,
  save: boolean,
): string {
  const lines = [`source ${SCRIPT_TEMPLATE}`, "configure"];
  for (const d of deletes) lines.push(`delete ${d}`);
  for (const s of sets) lines.push(`set ${s}`);
  if (commit) lines.push("commit");
  if (save) lines.push("save");
  lines.push("exit");
  return lines.join("\n") + "\n";
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** VyOS router management model definition. */
export const model = {
  type: "@shrug/vyos",
  version: "2026.07.10.1",
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
        args: { command: string },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const result = await sshExec(cfg, {
          command: [OP_WRAPPER, ...args.command.split(/\s+/)],
        });
        if (result.code !== 0) {
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
      }),
      execute: async (
        args: {
          set: string[];
          delete: string[];
          commit: boolean;
          save: boolean;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        if (args.set.length === 0 && args.delete.length === 0) {
          throw new Error("apply requires at least one set or delete command");
        }
        const script = buildConfigScript(
          args.set,
          args.delete,
          args.commit,
          args.save,
        );
        const result = await sshExec(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: script,
        });
        const handle = await context.writeResource("applyResult", "last", {
          host: cfg.host,
          set: args.set,
          delete: args.delete,
          committed: args.commit,
          saved: args.save,
          script,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          appliedAt: new Date().toISOString(),
        });
        if (result.code !== 0) {
          throw new Error(
            `apply failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
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
        args: { command: string; opMode: boolean },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const argv = args.opMode
          ? [OP_WRAPPER, ...args.command.split(/\s+/)]
          : ["sh", "-c", args.command];
        const result = await sshExec(cfg, { command: argv });
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
          throw new Error(
            `run failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        return { dataHandles: [handle] };
      },
    },
  },
};

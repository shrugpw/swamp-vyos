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
    .describe(
      "Path to a private key; presented with IdentitiesOnly so only this key " +
        "is offered (avoids MaxAuthTries when the agent holds many keys). " +
        "Omit to use the SSH agent/ssh config.",
    ),
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

/** A single advertised prefix under a router-advert interface. */
const RaPrefixSchema = z.object({
  prefix: z.string(),
  validLifetime: z.union([z.number().int(), z.literal("infinity")]).optional(),
  preferredLifetime: z.union([z.number().int(), z.literal("infinity")])
    .optional(),
  autonomousFlag: z.boolean().optional().describe(
    "false emits VyOS `no-autonomous-flag`",
  ),
  onLinkFlag: z.boolean().optional().describe(
    "false emits VyOS `no-on-link-flag`",
  ),
});

/**
 * Typed router-advert (IPv6 RA / SLAAC) config for one interface — the first
 * per-resource model on top of the raw config transport.
 */
const RouterAdvertSchema = z.object({
  host: z.string(),
  interface: z.string(),
  exists: z.boolean().describe("Whether RA is configured on the interface"),
  defaultLifetime: z.union([z.number().int(), z.string()]).optional(),
  prefixes: z.array(RaPrefixSchema).default([]),
  routes: z.array(z.string()).default([]),
  nat64prefixes: z.array(z.string()).default([]),
  retrievedAt: z.iso.datetime(),
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
  if (cfg.identityFile) {
    // Scope authentication to this one key. Without IdentitiesOnly, ssh still
    // offers every identity the agent holds first, which can trip the server's
    // MaxAuthTries (and abort with "Too many authentication failures") before
    // this key is ever tried. The agent is still used to sign if it holds the
    // key — this only restricts *which* identity is presented, it does not
    // bypass the agent.
    args.push("-o", "IdentitiesOnly=yes", "-i", cfg.identityFile);
  }
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
  // Staged operations can still be a NET no-op — e.g. a reconcile that deletes
  // an interface subtree and re-sets it to the same values. `compare` reflects
  // the true working-vs-active diff, so gate the commit on it; otherwise an
  // already-correct apply would spuriously commit (and misreport `changed`).
  lines.push('  __cmp="$(compare)"');
  lines.push(
    '  if echo "$__cmp" | grep -q "No changes between working and active"; then',
  );
  lines.push(`    echo ${SENTINEL_NOCHANGE}`);
  lines.push("    exit discard");
  lines.push("  else");
  if (opts.dryRun) {
    lines.push('    echo "$__cmp"');
    lines.push(`    echo ${SENTINEL_CHANGED}`);
    lines.push("    exit discard");
  } else {
    if (opts.commit) lines.push("    commit");
    if (opts.save) lines.push("    save");
    lines.push(`    echo ${SENTINEL_CHANGED}`);
    lines.push(opts.commit ? "    exit" : "    exit discard");
  }
  lines.push("  fi");
  lines.push("else");
  lines.push(`  echo ${SENTINEL_NOCHANGE}`);
  lines.push("  exit");
  lines.push("fi");
  return lines.join("\n") + "\n";
}

/**
 * Extract the `compare` diff from a dryRun script's stdout by dropping the
 * sentinel marker lines. Returns "" when the session was a no-op.
 */
export function extractDiff(stdout: string): string {
  return stdout
    .split("\n")
    .filter((l) => {
      const t = l.trim();
      return t !== SENTINEL_CHANGED && t !== SENTINEL_NOCHANGE;
    })
    .join("\n")
    .replace(/\s+$/, "");
}

/** Desired router-advert state for one interface (subset of RouterAdvertSchema). */
export interface RouterAdvertDesired {
  defaultLifetime?: number | string;
  prefixes?: Array<{
    prefix: string;
    validLifetime?: number | "infinity";
    preferredLifetime?: number | "infinity";
    autonomousFlag?: boolean;
    onLinkFlag?: boolean;
  }>;
  routes?: string[];
  nat64prefixes?: string[];
}

/**
 * Translate a desired router-advert state into the VyOS `set` paths for one
 * interface (bare paths, no leading `set`). Paired with a delete of the whole
 * `service router-advert interface <if>` subtree, this reconciles the interface
 * to exactly the desired state.
 */
export function routerAdvertSetPaths(
  iface: string,
  desired: RouterAdvertDesired,
): string[] {
  const base = `service router-advert interface ${iface}`;
  const paths: string[] = [];
  if (
    desired.defaultLifetime !== undefined && desired.defaultLifetime !== null
  ) {
    paths.push(`${base} default-lifetime ${desired.defaultLifetime}`);
  }
  for (const p of desired.prefixes ?? []) {
    const pp = `${base} prefix ${p.prefix}`;
    paths.push(pp);
    if (p.validLifetime !== undefined) {
      paths.push(`${pp} valid-lifetime ${p.validLifetime}`);
    }
    if (p.preferredLifetime !== undefined) {
      paths.push(`${pp} preferred-lifetime ${p.preferredLifetime}`);
    }
    if (p.autonomousFlag === false) paths.push(`${pp} no-autonomous-flag`);
    if (p.onLinkFlag === false) paths.push(`${pp} no-on-link-flag`);
  }
  for (const r of desired.routes ?? []) paths.push(`${base} route ${r}`);
  for (const n of desired.nat64prefixes ?? []) {
    paths.push(`${base} nat64prefix ${n}`);
  }
  return paths;
}

/**
 * Parse one interface's node from `show configuration json`
 * (service.router-advert.interface[<if>]) into the typed router-advert shape.
 */
export function parseRouterAdvertInterface(
  node: Record<string, unknown> | undefined,
): Omit<RouterAdvertDesired, never> & {
  prefixes: NonNullable<RouterAdvertDesired["prefixes"]>;
  routes: string[];
  nat64prefixes: string[];
} {
  const n = node ?? {};
  const asNum = (v: unknown) =>
    typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  const prefixNode = (n.prefix ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  const prefixes = Object.keys(prefixNode).map((prefix) => {
    const opts = prefixNode[prefix] ?? {};
    const out: NonNullable<RouterAdvertDesired["prefixes"]>[number] = {
      prefix,
    };
    if (opts["valid-lifetime"] !== undefined) {
      out.validLifetime = asNum(opts["valid-lifetime"]) as number | "infinity";
    }
    if (opts["preferred-lifetime"] !== undefined) {
      out.preferredLifetime = asNum(opts["preferred-lifetime"]) as
        | number
        | "infinity";
    }
    if ("no-autonomous-flag" in opts) out.autonomousFlag = false;
    if ("no-on-link-flag" in opts) out.onLinkFlag = false;
    return out;
  });
  return {
    defaultLifetime: n["default-lifetime"] as number | string | undefined,
    prefixes,
    routes: Object.keys((n.route ?? {}) as Record<string, unknown>),
    nat64prefixes: Object.keys(
      (n.nat64prefix ?? {}) as Record<string, unknown>,
    ),
  };
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
  version: "2026.07.10.6",
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
    "routerAdvert": {
      description:
        "Typed IPv6 router-advert (RA/SLAAC) config for one interface",
      schema: RouterAdvertSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
  },
  checks: {
    "reachable": {
      description:
        "Verify the router's config mode is reachable over SSH before applying.",
      labels: ["live"],
      appliesTo: ["apply", "diff", "ensureRouterAdvert", "removeRouterAdvert"],
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
        const targetSpec = args.sensitive
          ? "sensitiveConfigTree"
          : "configTree";
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
          saved: committed && args.save,
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
          "apply on {host} complete (changed={changed}, committed={committed})",
          { host: cfg.host, changed, committed },
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
    syncRouterAdvert: {
      description:
        "Read the current router-advert (RA/SLAAC) config for one interface into a typed routerAdvert resource.",
      arguments: z.object({
        interface: z.string().describe("Interface name, e.g. br10.95"),
      }),
      execute: async (
        args: { interface: string; _ssh?: SshRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        context.logger.info("Reading router-advert for {iface} on {host}", {
          iface: args.interface,
          host: cfg.host,
        });
        const result = await ssh(cfg, {
          command: [OP_WRAPPER, "show", "configuration", "json"],
        });
        if (result.code !== 0) {
          context.logger.error(
            "syncRouterAdvert failed on {host} (exit {code})",
            { host: cfg.host, code: result.code },
          );
          throw new Error(
            `syncRouterAdvert failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(result.stdout);
        } catch (e) {
          throw new Error(
            `syncRouterAdvert: could not parse config json from ${cfg.host}: ${
              e instanceof Error ? e.message : String(e)
            }`,
          );
        }
        // deno-lint-ignore no-explicit-any
        const service = (parsed.service ?? {}) as Record<string, any>;
        // deno-lint-ignore no-explicit-any
        const raRoot = (service["router-advert"] ?? {}) as Record<string, any>;
        const ifNode = ((raRoot.interface ?? {}) as Record<
          string,
          Record<string, unknown>
        >)[args.interface];
        const ra = parseRouterAdvertInterface(ifNode);
        const handle = await context.writeResource(
          "routerAdvert",
          args.interface,
          {
            host: cfg.host,
            interface: args.interface,
            exists: ifNode !== undefined,
            defaultLifetime: ra.defaultLifetime,
            prefixes: ra.prefixes,
            routes: ra.routes,
            nat64prefixes: ra.nat64prefixes,
            retrievedAt: new Date().toISOString(),
          },
        );
        context.logger.info(
          "router-advert for {iface}: exists={exists}, {n} prefix(es)",
          {
            iface: args.interface,
            exists: ifNode !== undefined,
            n: ra.prefixes.length,
          },
        );
        return { dataHandles: [handle] };
      },
    },
    ensureRouterAdvert: {
      description:
        "Declaratively set the router-advert config for one interface: reconciles to exactly the desired state (stale entries removed), idempotent.",
      arguments: z.object({
        interface: z.string(),
        defaultLifetime: z.union([z.number().int(), z.string()]).optional(),
        prefixes: z.array(RaPrefixSchema).default([]),
        routes: z.array(z.string()).default([]),
        nat64prefixes: z.array(z.string()).default([]),
        commit: z.boolean().default(true),
        save: z.boolean().default(true),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Preview the diff without committing"),
      }),
      execute: async (
        args: {
          interface: string;
          defaultLifetime?: number | string;
          prefixes: NonNullable<RouterAdvertDesired["prefixes"]>;
          routes: string[];
          nat64prefixes: string[];
          commit: boolean;
          save: boolean;
          dryRun: boolean;
          _ssh?: SshRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        const sets = routerAdvertSetPaths(args.interface, args);
        if (sets.length === 0) {
          throw new Error(
            "ensureRouterAdvert requires at least one prefix, route, or nat64prefix (use removeRouterAdvert to clear)",
          );
        }
        // Reconcile: wipe the interface's RA subtree, then set desired -> the
        // interface ends up as exactly `sets`. Net-zero change is a no-op.
        const deletes = [`service router-advert interface ${args.interface}`];
        validateApplyPaths(sets, deletes);
        const script = buildConfigScript({
          sets,
          deletes,
          commit: args.commit,
          save: args.save,
          dryRun: args.dryRun,
        });
        context.logger.info(
          "Ensuring router-advert for {iface} on {host} ({n} set path(s), dryRun={dryRun})",
          {
            iface: args.interface,
            host: cfg.host,
            n: sets.length,
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
          set: sets,
          delete: deletes,
          dryRun: args.dryRun,
          changed,
          committed,
          saved: committed && args.save,
          script: SCRIPT_REDACTED,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          appliedAt: new Date().toISOString(),
        });
        if (result.code !== 0) {
          context.logger.error(
            "ensureRouterAdvert failed on {host} (exit {code})",
            { host: cfg.host, code: result.code },
          );
          throw new Error(
            `ensureRouterAdvert failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        context.logger.info(
          "ensureRouterAdvert for {iface} complete (changed={changed}, committed={committed})",
          { iface: args.interface, changed, committed },
        );
        return { dataHandles: [handle] };
      },
    },
    removeRouterAdvert: {
      description: "Delete all router-advert config for one interface.",
      arguments: z.object({
        interface: z.string(),
        commit: z.boolean().default(true),
        save: z.boolean().default(true),
        dryRun: z.boolean().default(false),
      }),
      execute: async (
        args: {
          interface: string;
          commit: boolean;
          save: boolean;
          dryRun: boolean;
          _ssh?: SshRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        const deletes = [`service router-advert interface ${args.interface}`];
        validateApplyPaths([], deletes);
        const script = buildConfigScript({
          sets: [],
          deletes,
          commit: args.commit,
          save: args.save,
          dryRun: args.dryRun,
        });
        context.logger.info(
          "Removing router-advert for {iface} on {host} (dryRun={dryRun})",
          { iface: args.interface, host: cfg.host, dryRun: args.dryRun },
        );
        const result = await ssh(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: script,
        });
        const changed = result.stdout.includes(SENTINEL_CHANGED);
        const committed = args.commit && changed && !args.dryRun;
        const handle = await context.writeResource("applyResult", "last", {
          host: cfg.host,
          set: [],
          delete: deletes,
          dryRun: args.dryRun,
          changed,
          committed,
          saved: committed && args.save,
          script: SCRIPT_REDACTED,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          appliedAt: new Date().toISOString(),
        });
        if (result.code !== 0) {
          context.logger.error(
            "removeRouterAdvert failed on {host} (exit {code})",
            { host: cfg.host, code: result.code },
          );
          throw new Error(
            `removeRouterAdvert failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        context.logger.info(
          "removeRouterAdvert for {iface} complete (changed={changed}, committed={committed})",
          { iface: args.interface, changed, committed },
        );
        return { dataHandles: [handle] };
      },
    },
  },
};

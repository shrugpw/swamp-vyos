/**
 * Shared transport, config-script, and context primitives for the VyOS model.
 *
 * This module holds everything the per-resource families build on: the SSH
 * transport seam ({@link sshExec}), the vbash config-script builder
 * ({@link buildConfigScript}), path validation, small string helpers, the
 * connection-args schema, and the minimal execute/check context types. It has
 * no dependencies on any resource family, so the families and the thin `vyos.ts`
 * entry can all import from here without cycles.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Op-mode command wrapper — required for read-only "show ..." commands. */
export const OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper";

/** Sourced inside every config session so `configure`/`set`/`commit` resolve. */
export const SCRIPT_TEMPLATE = "/opt/vyatta/etc/functions/script-template";

/** Emitted by the config script when the session had staged changes. */
export const SENTINEL_CHANGED = "SWAMP_APPLY_CHANGED";

/** Emitted by the config script when the session was a no-op (idempotent). */
export const SENTINEL_NOCHANGE = "SWAMP_APPLY_NOCHANGE";

/** Placeholder stored in place of the vbash script when `storeScript` is off. */
export const SCRIPT_REDACTED =
  "<redacted: pass storeScript=true to persist the script>";

/** Connection/authentication settings for the target VyOS router. */
export const GlobalArgsSchema = z.object({
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
  wireguardKeys: z
    .record(z.string(), z.string())
    .optional()
    .meta({ sensitive: true })
    .describe(
      "Per-interface WireGuard private keys, keyed by interface name (e.g. " +
        '{"wg0": "<key>"}). ensureWireguard uses ' +
        "wireguardKeys[<interface>] as the interface private-key when no " +
        "explicit privateKey argument is given. This is the ONLY seam for a " +
        "vault-backed key: the engine resolves a vault.get(...) macro inside " +
        "the model definition's globalArguments, never in method inputs, so " +
        "wire each key from the vault in the definition, e.g. wireguardKeys: " +
        "{ wg0: '<vault.get macro for your wg0 private-key secret>' }. " +
        "SENSITIVE: never logged, snapshotted, or echoed (only the source " +
        "label is logged, never the value).",
    ),
});

/** Resolved connection/authentication settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

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

  // The SSH binary is the sole transport seam (see the module TODO on swapping
  // this for @swamp/ssh once context.runModel ships). The argv is fixed and
  // vetted: literal ssh flags, the integer port, and caller config/command
  // paths that pass validateApplyPaths (no shell is involved — args go straight
  // to execve, never a shell string). Config bodies are piped over stdin, not
  // argv.
  // swamp-quality-ignore deno-command
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
  /**
   * When > 0 and committing, emit `commit-confirm <N>` instead of a bare
   * `commit`: the change is committed with an N-minute auto-revert timer, so a
   * management-severing change rolls itself back unless a later `confirm`
   * cancels the timer. In this path the script deliberately does NOT `save`
   * (saving an un-confirmed change to config.boot would survive the auto-revert
   * reboot, defeating the safety); the `confirm` method saves once the change
   * is made permanent. Ignored when 0/undefined (plain `commit`) or in dryRun.
   */
  confirmMinutes?: number;
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
    const confirmMinutes = opts.confirmMinutes ?? 0;
    if (opts.commit && confirmMinutes > 0) {
      // commit-confirm arms an N-minute auto-revert timer: the change is active
      // now but config.boot is left untouched, so a management-severing change
      // rolls back on its own unless `confirm` cancels the timer. Do NOT save
      // here — an un-confirmed bad config must not survive the auto-revert
      // reboot; the `confirm` method saves once the change is made permanent.
      lines.push(`    commit-confirm ${confirmMinutes}`);
    } else {
      if (opts.commit) lines.push("    commit");
      if (opts.save) lines.push("    save");
    }
    lines.push(`    echo ${SENTINEL_CHANGED}`);
    // A commit (plain or commit-confirm) keeps the session with `exit`; only a
    // non-committing apply discards.
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

/** Single-quote a value if it contains whitespace (e.g. a description). */
export function quoteIfSpaced(v: string): string {
  return /\s/.test(v) ? `'${v}'` : v;
}

/** Minimal logging surface the model relies on from its context. */
export interface Logger {
  debug: (message: string, properties?: Record<string, unknown>) => void;
  info: (message: string, properties?: Record<string, unknown>) => void;
  warning: (message: string, properties?: Record<string, unknown>) => void;
  error: (message: string, properties?: Record<string, unknown>) => void;
}

/** Minimal shape of the execute context this model relies on. */
export interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Minimal shape of the pre-flight check context this model relies on. */
export interface CheckContext {
  globalArgs: GlobalArgs;
  logger: Logger;
}

/** Return shape for every method's execute function. */
export interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

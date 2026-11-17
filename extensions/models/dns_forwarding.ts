/**
 * VyOS DNS forwarding (`service dns forwarding`) model: schemas, reconcile
 * helpers, resource specs, and methods. Assembled into the model in `vyos.ts`.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  buildConfigScript,
  OP_WRAPPER,
  SCRIPT_REDACTED,
  SENTINEL_CHANGED,
  sshExec,
  validateApplyPaths,
} from "./core.ts";
import type { ExecuteContext, ExecuteResult, SshRunner } from "./core.ts";

/**
 * A per-domain forwarding override (`service dns forwarding domain <name>`).
 * `raw` is a deviation from the design doc (which didn't include it at this
 * level) - added per the general "raw at every schema level" build rule since
 * declarative reconcile is round-trip-lossy for any unmodeled leaf.
 */
const DnsDomainSchema = z.object({
  name: z.string(),
  nameServers: z.array(z.string()).default([]),
  recursionDesired: z.boolean().optional().describe(
    "Emits the valueless `recursion-desired` leaf when true",
  ),
  addNta: z.boolean().optional().describe(
    "Emits the valueless `addnta` leaf when true",
  ),
  raw: z.array(z.string()).default([]).describe(
    "Extra leaf fragments appended under the domain path",
  ),
});

/**
 * Typed `service dns forwarding` config - a singleton (instance name always
 * `current`) reconciled as one declarative unit, like router-advert.
 */
const DnsForwardingSchema = z.object({
  host: z.string(),
  exists: z.boolean().describe(
    "Whether `service dns forwarding` is configured at all",
  ),
  listenAddress: z.array(z.string()).default([]),
  allowFrom: z.array(z.string()).default([]),
  nameServer: z.array(z.string()).default([]),
  system: z.boolean().optional().describe(
    "Use the system's own resolvers (valueless `system` leaf)",
  ),
  cacheSize: z.number().int().optional(),
  dhcp: z.array(z.string()).default([]).describe(
    "Interfaces to pull upstream name-servers from via DHCP",
  ),
  dns64Prefix: z.string().optional(),
  domains: z.array(DnsDomainSchema).default([]),
  raw: z.array(z.string()).default([]),
  retrievedAt: z.iso.datetime(),
});

/** Desired state of one domain override for {@link dnsForwardingSetPaths}. */
export interface DnsDomainDesired {
  name: string;
  nameServers?: string[];
  recursionDesired?: boolean;
  addNta?: boolean;
  raw?: string[];
}

/** Desired whole-service DNS forwarding state (subset of DnsForwardingSchema). */
export interface DnsForwardingDesired {
  listenAddress?: string[];
  allowFrom?: string[];
  nameServer?: string[];
  system?: boolean;
  cacheSize?: number;
  dhcp?: string[];
  dns64Prefix?: string;
  domains?: DnsDomainDesired[];
  raw?: string[];
}

/**
 * Translate a desired `service dns forwarding` state into VyOS `set` paths
 * (bare, no leading `set`). Paired with a delete of `service dns forwarding`,
 * this reconciles the service to exactly the desired state.
 */
export function dnsForwardingSetPaths(desired: DnsForwardingDesired): string[] {
  const base = "service dns forwarding";
  const paths: string[] = [];
  for (const a of desired.allowFrom ?? []) {
    paths.push(`${base} allow-from ${a}`);
  }
  if (desired.cacheSize !== undefined) {
    paths.push(`${base} cache-size ${desired.cacheSize}`);
  }
  for (const d of desired.dhcp ?? []) paths.push(`${base} dhcp ${d}`);
  if (desired.dns64Prefix !== undefined) {
    paths.push(`${base} dns64-prefix ${desired.dns64Prefix}`);
  }
  for (const dom of desired.domains ?? []) {
    const db = `${base} domain ${dom.name}`;
    // Emit the (tag-node) domain path itself so a domain with no children
    // still exists post-reconcile, mirroring the router-advert prefix pattern.
    paths.push(db);
    for (const ns of dom.nameServers ?? []) {
      paths.push(`${db} name-server ${ns}`);
    }
    if (dom.recursionDesired === true) paths.push(`${db} recursion-desired`);
    if (dom.addNta === true) paths.push(`${db} addnta`);
    for (const frag of dom.raw ?? []) paths.push(`${db} ${frag}`);
  }
  for (const l of desired.listenAddress ?? []) {
    paths.push(`${base} listen-address ${l}`);
  }
  for (const n of desired.nameServer ?? []) {
    paths.push(`${base} name-server ${n}`);
  }
  if (desired.system === true) paths.push(`${base} system`);
  for (const frag of desired.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/**
 * Normalize a VyOS multi-value leaf to `string[]` regardless of which of the
 * two JSON renderings `show configuration json` used: a plain array (e.g.
 * `allow-from`, `listen-address`, `dhcp`) or an object whose keys are the
 * values (e.g. `name-server`, `domain.<n>.name-server`). A single scalar or a
 * missing leaf are also normalized.
 */
function asList(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (v && typeof v === "object") {
    return Object.keys(v as Record<string, unknown>);
  }
  if (v === undefined) return [];
  return [String(v)];
}

/** Parsed state of `service dns forwarding` (from `show configuration json`). */
export interface DnsForwardingState {
  listenAddress: string[];
  allowFrom: string[];
  nameServer: string[];
  system?: boolean;
  cacheSize?: number;
  dhcp: string[];
  dns64Prefix?: string;
  domains: DnsDomainDesired[];
}

/**
 * Parse the `service.dns.forwarding` node from `show configuration json` into
 * its typed state. Handles both the array-form and object-of-empty-keys form
 * of multi-value leaves (see {@link asList}).
 */
export function parseDnsForwarding(
  node: Record<string, unknown> | undefined,
): DnsForwardingState {
  const n = (node ?? {}) as Record<string, unknown>;
  const domainNode = (n.domain ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  const domains: DnsDomainDesired[] = Object.keys(domainNode).map((name) => {
    const dn = domainNode[name] ?? {};
    const out: DnsDomainDesired = {
      name,
      nameServers: asList(dn["name-server"]),
    };
    if ("recursion-desired" in dn) out.recursionDesired = true;
    if ("addnta" in dn) out.addNta = true;
    return out;
  });
  const out: DnsForwardingState = {
    listenAddress: asList(n["listen-address"]),
    allowFrom: asList(n["allow-from"]),
    nameServer: asList(n["name-server"]),
    dhcp: asList(n.dhcp),
    domains,
  };
  if ("system" in n) out.system = true;
  if (n["cache-size"] !== undefined) out.cacheSize = Number(n["cache-size"]);
  if (n["dns64-prefix"] !== undefined) {
    out.dns64Prefix = String(n["dns64-prefix"]);
  }
  return out;
}

/** Resource specs contributed by the dnsForwarding family. */
export const dnsForwardingResources = {
  "dnsForwarding": {
    description:
      "Typed DNS forwarding config (service dns forwarding), a singleton reconciled as one declarative unit",
    schema: DnsForwardingSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the dnsForwarding family. */
export const dnsForwardingMethods = {
  syncDnsForwarding: {
    description:
      "Read the current `service dns forwarding` config into the typed dnsForwarding resource (instance `current`).",
    arguments: z.object({}),
    execute: async (
      args: { _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading DNS forwarding config on {host}", {
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error(
          "syncDnsForwarding failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `syncDnsForwarding failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncDnsForwarding: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const service = (parsed.service ?? {}) as Record<string, any>;
      // deno-lint-ignore no-explicit-any
      const dnsRoot = (service.dns ?? {}) as Record<string, any>;
      const node = dnsRoot.forwarding as Record<string, unknown> | undefined;
      const dns = parseDnsForwarding(node);
      const handle = await context.writeResource("dnsForwarding", "current", {
        host: cfg.host,
        exists: node !== undefined,
        listenAddress: dns.listenAddress,
        allowFrom: dns.allowFrom,
        nameServer: dns.nameServer,
        system: dns.system,
        cacheSize: dns.cacheSize,
        dhcp: dns.dhcp,
        dns64Prefix: dns.dns64Prefix,
        domains: dns.domains,
        retrievedAt: new Date().toISOString(),
      });
      context.logger.info(
        "DNS forwarding: exists={exists}, {n} domain(s)",
        { exists: node !== undefined, n: dns.domains.length },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureDnsForwarding: {
    description:
      "Declaratively set `service dns forwarding`: reconciles to exactly the desired state (stale entries removed), idempotent.",
    arguments: z.object({
      listenAddress: z.array(z.string()).default([]),
      allowFrom: z.array(z.string()).default([]),
      nameServer: z.array(z.string()).default([]),
      system: z.boolean().optional(),
      cacheSize: z.number().int().optional(),
      dhcp: z.array(z.string()).default([]),
      dns64Prefix: z.string().optional(),
      domains: z.array(DnsDomainSchema).default([]),
      raw: z.array(z.string()).default([]).describe(
        "Extra leaf fragments appended under `service dns forwarding`",
      ),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z
        .boolean()
        .default(false)
        .describe("Preview the diff without committing"),
    }),
    execute: async (
      args: DnsForwardingDesired & {
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const sets = dnsForwardingSetPaths(args);
      if (sets.length === 0) {
        throw new Error(
          "ensureDnsForwarding requires at least one attribute (use removeDnsForwarding to clear)",
        );
      }
      // Reconcile: wipe the whole `service dns forwarding` subtree, then set
      // desired -> the service ends up as exactly `sets`. Net-zero change is a
      // no-op.
      const deletes = ["service dns forwarding"];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring DNS forwarding on {host} ({n} set path(s), dryRun={dryRun})",
        { host: cfg.host, n: sets.length, dryRun: args.dryRun },
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
          "ensureDnsForwarding failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureDnsForwarding failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureDnsForwarding complete (changed={changed}, committed={committed})",
        { changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
  removeDnsForwarding: {
    description: "Delete all `service dns forwarding` config.",
    arguments: z.object({
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args: {
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const deletes = ["service dns forwarding"];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing DNS forwarding config on {host} (dryRun={dryRun})",
        { host: cfg.host, dryRun: args.dryRun },
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
          "removeDnsForwarding failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeDnsForwarding failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeDnsForwarding complete (changed={changed}, committed={committed})",
        { changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const dnsForwardingCheckMethods = [
  "ensureDnsForwarding",
  "removeDnsForwarding",
];

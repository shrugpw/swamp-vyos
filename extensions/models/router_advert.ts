/**
 * VyOS IPv6 router-advertisement (RA/SLAAC) model: schemas, reconcile helpers, resource specs, and
 * methods. Assembled into the model in `vyos.ts`.
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
 * Typed router-advert (IPv6 RA / SLAAC) config for one interface - the first
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

/** Resource specs contributed by the routerAdvert family. */
export const routerAdvertResources = {
  "routerAdvert": {
    description: "Typed IPv6 router-advert (RA/SLAAC) config for one interface",
    schema: RouterAdvertSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the routerAdvert family. */
export const routerAdvertMethods = {
  syncRouterAdvert: {
    description:
      "Read the current router-advert (RA/SLAAC) config for one interface into a typed routerAdvert resource.",
    arguments: z.object({
      interface: z.string().describe("Interface name, e.g. eth1"),
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
};

/** Methods that require the reachable pre-flight check. */
export const routerAdvertCheckMethods = [
  "ensureRouterAdvert",
  "removeRouterAdvert",
];

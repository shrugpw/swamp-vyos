/**
 * VyOS static routes model: schemas, reconcile helpers, resource specs, and
 * methods. Assembled into the model in `vyos.ts`.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  buildConfigScript,
  OP_WRAPPER,
  quoteIfSpaced,
  SCRIPT_REDACTED,
  SENTINEL_CHANGED,
  sshExec,
  validateApplyPaths,
} from "./core.ts";
import type { ExecuteContext, ExecuteResult, SshRunner } from "./core.ts";

/** A single next-hop within a static route (`... next-hop <ip>`). */
const StaticNextHopSchema = z.object({
  nextHop: z.string().describe("Gateway IP address"),
  distance: z.union([z.number().int().positive(), z.string()]).optional()
    .describe("Administrative distance for this next-hop"),
  disable: z.boolean().optional().describe("Emit the valueless `disable` leaf"),
  interface: z.string().optional().describe(
    "Egress interface qualifier (`next-hop <ip> interface <if>`)",
  ),
});

/** A directly-attached / interface route (`... interface <if>`). */
const StaticInterfaceRouteSchema = z.object({
  interface: z.string(),
  distance: z.union([z.number().int().positive(), z.string()]).optional(),
  disable: z.boolean().optional().describe("Emit the valueless `disable` leaf"),
});

/** Discard (`blackhole`) target, optionally with an administrative distance. */
const StaticBlackholeSchema = z.union([
  z.literal(true),
  z.object({
    distance: z.union([z.number().int().positive(), z.string()]).optional(),
    disable: z.boolean().optional(),
  }),
]);

/**
 * Typed static route for one destination prefix (`protocols static route
 * <prefix>` for IPv4 or `protocols static route6 <prefix>` for IPv6 - the
 * family is derived from the prefix). Managed as one declarative unit.
 * Cleartext: a route carries no secrets (prefixes/next-hops/interfaces only).
 */
const StaticRouteSchema = z.object({
  host: z.string(),
  prefix: z.string().describe("Destination prefix (instance name)"),
  family: z.string().describe("ipv4 or ipv6 (derived from the prefix)"),
  exists: z.boolean(),
  nextHops: z.array(StaticNextHopSchema).default([]),
  interfaceRoutes: z.array(StaticInterfaceRouteSchema).default([]),
  blackhole: StaticBlackholeSchema.optional().describe(
    "Discard route (`blackhole`), optionally with distance",
  ),
  dhcpInterface: z.string().optional().describe(
    "Resolve the gateway from DHCP on this interface (`dhcp-interface <if>`)",
  ),
  description: z.string().optional(),
  retrievedAt: z.iso.datetime(),
});

/** A desired next-hop for {@link staticRouteSetPaths}. */
export interface StaticNextHopDesired {
  nextHop: string;
  distance?: number | string;
  disable?: boolean;
  interface?: string;
}

/** A desired interface route for {@link staticRouteSetPaths}. */
export interface StaticInterfaceRouteDesired {
  interface: string;
  distance?: number | string;
  disable?: boolean;
}

/** Desired static-route state for one prefix (subset of StaticRouteSchema). */
export interface StaticRouteDesired {
  nextHops?: StaticNextHopDesired[];
  interfaceRoutes?: StaticInterfaceRouteDesired[];
  blackhole?: { distance?: number | string; disable?: boolean } | true;
  dhcpInterface?: string;
  description?: string;
  raw?: string[];
}

/** Parsed static route (the family-tagged read shape for one prefix). */
export interface StaticRouteParsed {
  family: "ipv4" | "ipv6";
  nextHops: StaticNextHopDesired[];
  interfaceRoutes: StaticInterfaceRouteDesired[];
  blackhole?: { distance?: number | string; disable?: boolean } | true;
  dhcpInterface?: string;
  description?: string;
}

/**
 * Resolve the config-tree base path for a destination prefix, selecting `route`
 * for IPv4 and `route6` for IPv6. Family is auto-detected: a prefix containing
 * ':' is IPv6, otherwise IPv4.
 */
export function staticRouteBasePath(prefix: string): {
  family: "ipv4" | "ipv6";
  routeKey: "route" | "route6";
  base: string;
} {
  const family = prefix.includes(":") ? "ipv6" : "ipv4";
  const routeKey = family === "ipv6" ? "route6" : "route";
  return { family, routeKey, base: `protocols static ${routeKey} ${prefix}` };
}

/**
 * Slug for a prefix used as a swamp data-instance name. Swamp rejects `/` in
 * data names (path-traversal guard), so the prefix length delimiter is replaced
 * with `_` (e.g. `192.0.2.0/24` -> `192.0.2.0_24`). The real prefix is preserved
 * verbatim in the resource's `prefix` field.
 */
export function staticRouteInstanceName(prefix: string): string {
  return prefix.replaceAll("/", "_");
}

/**
 * Translate a desired static-route state into the VyOS `set` paths for one
 * prefix (bare paths, no leading `set`). Paired with a delete of the whole
 * `protocols static <route|route6> <prefix>` subtree, this reconciles the route
 * to exactly the desired state. The route/route6 base is computed internally
 * from the prefix family.
 */
export function staticRouteSetPaths(
  prefix: string,
  desired: StaticRouteDesired,
): string[] {
  const { base } = staticRouteBasePath(prefix);
  const paths: string[] = [];
  for (const nh of desired.nextHops ?? []) {
    const nhBase = `${base} next-hop ${nh.nextHop}`;
    paths.push(nhBase);
    if (nh.distance !== undefined) {
      paths.push(`${nhBase} distance ${nh.distance}`);
    }
    if (nh.interface !== undefined) {
      paths.push(`${nhBase} interface ${nh.interface}`);
    }
    if (nh.disable === true) paths.push(`${nhBase} disable`);
  }
  for (const ir of desired.interfaceRoutes ?? []) {
    const irBase = `${base} interface ${ir.interface}`;
    paths.push(irBase);
    if (ir.distance !== undefined) {
      paths.push(`${irBase} distance ${ir.distance}`);
    }
    if (ir.disable === true) paths.push(`${irBase} disable`);
  }
  if (desired.blackhole !== undefined) {
    paths.push(`${base} blackhole`);
    if (desired.blackhole !== true) {
      if (desired.blackhole.distance !== undefined) {
        paths.push(`${base} blackhole distance ${desired.blackhole.distance}`);
      }
      if (desired.blackhole.disable === true) {
        paths.push(`${base} blackhole disable`);
      }
    }
  }
  if (desired.dhcpInterface !== undefined) {
    paths.push(`${base} dhcp-interface ${desired.dhcpInterface}`);
  }
  if (desired.description !== undefined) {
    paths.push(`${base} description ${quoteIfSpaced(desired.description)}`);
  }
  for (const fragment of desired.raw ?? []) paths.push(`${base} ${fragment}`);
  return paths;
}

/**
 * Parse one prefix node from `show configuration json`
 * (protocols.static.route[<prefix>] or protocols.static.route6[<prefix>]) into
 * the typed static-route shape. Next-hops and interface routes are returned as
 * arrays sorted by key. Family is derived from the prefix.
 */
export function parseStaticRoute(
  prefix: string,
  node: Record<string, unknown> | undefined,
): StaticRouteParsed {
  const { family } = staticRouteBasePath(prefix);
  const n = node ?? {};
  const asNum = (v: unknown) =>
    typeof v === "string" && /^\d+$/.test(v) ? Number(v) : v;
  const nhNode = (n["next-hop"] ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  const nextHops = Object.keys(nhNode).sort().map((ip) => {
    const opts = nhNode[ip] ?? {};
    const out: StaticNextHopDesired = { nextHop: ip };
    if (opts.distance !== undefined) {
      out.distance = asNum(opts.distance) as number | string;
    }
    if (opts.interface !== undefined) out.interface = opts.interface as string;
    if ("disable" in opts) out.disable = true;
    return out;
  });
  const irNode = (n.interface ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  const interfaceRoutes = Object.keys(irNode).sort().map((iface) => {
    const opts = irNode[iface] ?? {};
    const out: StaticInterfaceRouteDesired = { interface: iface };
    if (opts.distance !== undefined) {
      out.distance = asNum(opts.distance) as number | string;
    }
    if ("disable" in opts) out.disable = true;
    return out;
  });
  const result: StaticRouteParsed = { family, nextHops, interfaceRoutes };
  if (n.blackhole !== undefined) {
    const bh = (n.blackhole ?? {}) as Record<string, unknown>;
    if (Object.keys(bh).length === 0) {
      result.blackhole = true;
    } else {
      const b: { distance?: number | string; disable?: boolean } = {};
      if (bh.distance !== undefined) {
        b.distance = asNum(bh.distance) as number | string;
      }
      if ("disable" in bh) b.disable = true;
      result.blackhole = b;
    }
  }
  if (n["dhcp-interface"] !== undefined) {
    result.dhcpInterface = n["dhcp-interface"] as string;
  }
  if (n.description !== undefined) result.description = n.description as string;
  return result;
}

/** Resource specs contributed by the staticRoute family. */
export const staticRouteResources = {
  "staticRoute": {
    description:
      "Typed static route for one destination prefix (protocols static route|route6 <prefix>) managed as one declarative unit",
    schema: StaticRouteSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the staticRoute family. */
export const staticRouteMethods = {
  syncStaticRoute: {
    description:
      "Read the current static route for one destination prefix into a typed staticRoute resource (route vs route6 derived from the prefix).",
    arguments: z.object({
      prefix: z.string().describe(
        "Destination prefix, e.g. 192.0.2.0/24 or 2001:db8::/32",
      ),
    }),
    execute: async (
      args: { prefix: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const { family, routeKey } = staticRouteBasePath(args.prefix);
      context.logger.info("Reading static route for {prefix} on {host}", {
        prefix: args.prefix,
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error(
          "syncStaticRoute failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `syncStaticRoute failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncStaticRoute: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const protocols = (parsed.protocols ?? {}) as Record<string, any>;
      // deno-lint-ignore no-explicit-any
      const staticRoot = (protocols.static ?? {}) as Record<string, any>;
      const routeNode = ((staticRoot[routeKey] ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.prefix];
      const route = parseStaticRoute(args.prefix, routeNode);
      const handle = await context.writeResource(
        "staticRoute",
        staticRouteInstanceName(args.prefix),
        {
          host: cfg.host,
          prefix: args.prefix,
          family,
          exists: routeNode !== undefined,
          nextHops: route.nextHops,
          interfaceRoutes: route.interfaceRoutes,
          blackhole: route.blackhole,
          dhcpInterface: route.dhcpInterface,
          description: route.description,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "static route for {prefix}: exists={exists}, {n} next-hop(s)",
        {
          prefix: args.prefix,
          exists: routeNode !== undefined,
          n: route.nextHops.length,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureStaticRoute: {
    description:
      "Declaratively set the static route for one destination prefix: reconciles to exactly the desired state (stale entries removed), idempotent. route vs route6 is derived from the prefix.",
    arguments: z.object({
      prefix: z.string(),
      nextHops: z.array(StaticNextHopSchema).default([]),
      interfaceRoutes: z.array(StaticInterfaceRouteSchema).default([]),
      blackhole: StaticBlackholeSchema.optional(),
      dhcpInterface: z.string().optional(),
      description: z.string().optional(),
      raw: z.array(z.string()).default([]).describe(
        "Extra leaf fragments appended under the route (e.g. 'reject')",
      ),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z
        .boolean()
        .default(false)
        .describe("Preview the diff without committing"),
    }),
    execute: async (
      args: {
        prefix: string;
        nextHops: StaticNextHopDesired[];
        interfaceRoutes: StaticInterfaceRouteDesired[];
        blackhole?: { distance?: number | string; disable?: boolean } | true;
        dhcpInterface?: string;
        description?: string;
        raw: string[];
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const { base } = staticRouteBasePath(args.prefix);
      const sets = staticRouteSetPaths(args.prefix, args);
      if (sets.length === 0) {
        throw new Error(
          "ensureStaticRoute requires at least one next-hop, interface route, blackhole, or dhcp-interface (use removeStaticRoute to clear)",
        );
      }
      // Reconcile: wipe the prefix's route subtree, then set desired -> the
      // route ends up as exactly `sets`. Net-zero change is a no-op.
      const deletes = [base];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring static route for {prefix} on {host} ({n} set path(s), dryRun={dryRun})",
        {
          prefix: args.prefix,
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
          "ensureStaticRoute failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureStaticRoute failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureStaticRoute for {prefix} complete (changed={changed}, committed={committed})",
        { prefix: args.prefix, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
  removeStaticRoute: {
    description:
      "Delete the whole static route subtree for one destination prefix (route vs route6 derived from the prefix).",
    arguments: z.object({
      prefix: z.string(),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args: {
        prefix: string;
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const { base } = staticRouteBasePath(args.prefix);
      const deletes = [base];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing static route for {prefix} on {host} (dryRun={dryRun})",
        { prefix: args.prefix, host: cfg.host, dryRun: args.dryRun },
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
          "removeStaticRoute failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeStaticRoute failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeStaticRoute for {prefix} complete (changed={changed}, committed={committed})",
        { prefix: args.prefix, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const staticRouteCheckMethods = [
  "ensureStaticRoute",
  "removeStaticRoute",
];

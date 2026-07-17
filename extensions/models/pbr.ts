/**
 * VyOS policy-based routing (`policy route`/`policy route6`) model: schemas,
 * reconcile helpers, resource specs, and methods. Assembled into the model in
 * `vyos.ts`.
 *
 * A `policy route`/`policy route6` ruleset only takes effect once it is BOUND
 * to an interface via `set interfaces <if> policy route <name>` (ipv6:
 * `policy route6`). That binding lives outside this subtree (on the
 * interface) and is NOT managed here — this module models the ruleset itself,
 * including its own (non-activating) `interface` leaf, which some rulesets
 * carry as documentation/hint but which VyOS does not treat as the binding.
 *
 * Scope: `policy route`/`policy route6` only. `policy local-route`/
 * `local-route6` (source-based routing into tables — a different shape) is
 * out of scope for this module.
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
import { FirewallMatchSchema, firewallMatchSetPaths } from "./firewall.ts";
import type { FirewallMatchDesired } from "./firewall.ts";

/** `policy route <name> rule <n> set { table, mark, dscp }`. */
const PbrSetSchema = z.object({
  table: z.union([z.number().int(), z.literal("main")]).optional().describe(
    "Routing table number, or 'main'",
  ),
  mark: z.number().int().optional().describe("Firewall mark to apply"),
  dscp: z.number().int().optional().describe("DSCP value to apply"),
});

/**
 * A single policy-route rule (`policy route[6] <name> rule <n>`). Covers the
 * common match/target leaves; anything unmodeled goes in `raw` (fragments
 * appended verbatim under the rule path).
 */
const PbrRuleSchema = z.object({
  number: z.number().int().positive().describe(
    "Rule number (ordering key within the ruleset; need not be contiguous)",
  ),
  // NOTE: deliberately permissive, NOT `z.enum(["drop"])` — the design doc's
  // drop-only enum does not match live config, which uses action 'reject'
  // (VyOS policy-route accepts accept|drop|reject, matching firewall action
  // semantics). An enum without 'reject' fails round-trip on real rulesets.
  action: z.string().optional().describe(
    "drop (silently discard) | reject (discard + send ICMP/RST)",
  ),
  source: FirewallMatchSchema.optional(),
  destination: FirewallMatchSchema.optional(),
  protocol: z.string().optional().describe("tcp|udp|tcp_udp|icmp|all|<number>"),
  set: PbrSetSchema.optional(),
  disable: z.boolean().optional().describe("Emit the valueless `disable` leaf"),
  log: z.boolean().optional().describe("Emit the valueless `log` leaf"),
  raw: z.array(z.string()).default([]).describe(
    "Extra leaf fragments appended under the rule",
  ),
});

/**
 * Typed named policy-route ruleset (`policy route <name>` / `policy route6
 * <name>`) — a whole ruleset managed as one declarative unit, like firewall.
 * Cleartext: a ruleset carries no secrets (addresses/ports/groups only).
 */
const PbrRulesetSchema = z.object({
  host: z.string(),
  name: z.string(),
  family: z.enum(["ipv4", "ipv6"]),
  exists: z.boolean(),
  interfaces: z.array(z.string()).default([]).describe(
    "In-ruleset `interface` leaf(s) (VyOS renders this multi-value leaf as a " +
      "list). Documentation only; NOT the activation binding, which is " +
      "`set interfaces <if> policy route <name>`",
  ),
  description: z.string().optional(),
  enableDefaultLog: z.boolean().default(false),
  rules: z.array(PbrRuleSchema).default([]),
  raw: z.array(z.string()).default([]),
  retrievedAt: z.iso.datetime(),
});

/** A desired policy-route rule for {@link pbrSetPaths}. */
export interface PbrRuleDesired {
  number: number;
  action?: string;
  source?: FirewallMatchDesired;
  destination?: FirewallMatchDesired;
  protocol?: string;
  set?: { table?: number | "main"; mark?: number; dscp?: number };
  disable?: boolean;
  log?: boolean;
  raw?: string[];
}

/** Desired state of a whole named policy-route ruleset. */
export interface PbrRulesetDesired {
  interfaces?: string[];
  description?: string;
  enableDefaultLog?: boolean;
  rules?: PbrRuleDesired[];
  raw?: string[];
}

/** Resolve the `policy route`/`policy route6` subtree base for a family. */
function pbrBase(family: "ipv4" | "ipv6", name: string): string {
  return family === "ipv4" ? `policy route ${name}` : `policy route6 ${name}`;
}

/**
 * Translate a desired named policy-route ruleset state into VyOS `set` paths
 * (bare, no leading `set`). Paired with a delete of `policy route[6] <name>`,
 * this reconciles the ruleset to exactly the desired state.
 */
export function pbrSetPaths(
  family: "ipv4" | "ipv6",
  name: string,
  desired: PbrRulesetDesired,
): string[] {
  const base = pbrBase(family, name);
  const paths: string[] = [];
  for (const iface of desired.interfaces ?? []) {
    paths.push(`${base} interface ${iface}`);
  }
  if (desired.description !== undefined) {
    paths.push(`${base} description ${quoteIfSpaced(desired.description)}`);
  }
  if (desired.enableDefaultLog === true) {
    paths.push(`${base} enable-default-log`);
  }
  for (const r of desired.rules ?? []) {
    const rb = `${base} rule ${r.number}`;
    if (r.action !== undefined) paths.push(`${rb} action ${r.action}`);
    if (r.source) paths.push(...firewallMatchSetPaths(rb, "source", r.source));
    if (r.destination) {
      paths.push(...firewallMatchSetPaths(rb, "destination", r.destination));
    }
    if (r.protocol !== undefined) paths.push(`${rb} protocol ${r.protocol}`);
    if (r.set) {
      if (r.set.table !== undefined) {
        paths.push(`${rb} set table ${r.set.table}`);
      }
      if (r.set.mark !== undefined) paths.push(`${rb} set mark ${r.set.mark}`);
      if (r.set.dscp !== undefined) paths.push(`${rb} set dscp ${r.set.dscp}`);
    }
    if (r.disable === true) paths.push(`${rb} disable`);
    if (r.log === true) paths.push(`${rb} log`);
    for (const frag of r.raw ?? []) paths.push(`${rb} ${frag}`);
  }
  for (const frag of desired.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/** Parsed state of a named policy-route ruleset (from `show configuration json`). */
export interface PbrRulesetState {
  interfaces: string[];
  description?: string;
  enableDefaultLog: boolean;
  rules: PbrRuleDesired[];
}

/**
 * Parse one named policy-route ruleset node (policy.route[6].<name>) into its
 * typed state. Rules are returned sorted by numeric rule number (non-
 * contiguous numbers preserved).
 */
export function parsePolicyRoute(
  node: Record<string, unknown> | undefined,
): PbrRulesetState {
  const n = (node ?? {}) as Record<string, unknown>;
  const parseMatch = (
    mn: Record<string, unknown> | undefined,
  ): FirewallMatchDesired | undefined => {
    if (!mn) return undefined;
    const g = (mn.group ?? {}) as Record<string, unknown>;
    const m: FirewallMatchDesired = {};
    if (mn.address !== undefined) m.address = String(mn.address);
    if (mn.port !== undefined) m.port = String(mn.port);
    if (g["address-group"] !== undefined) {
      m.addressGroup = String(g["address-group"]);
    }
    if (g["network-group"] !== undefined) {
      m.networkGroup = String(g["network-group"]);
    }
    if (g["port-group"] !== undefined) m.portGroup = String(g["port-group"]);
    return Object.keys(m).length ? m : undefined;
  };
  const ruleNode = (n.rule ?? {}) as Record<string, Record<string, unknown>>;
  const rules: PbrRuleDesired[] = Object.keys(ruleNode)
    .sort((a, b) => Number(a) - Number(b))
    .map((num) => {
      const rn = ruleNode[num] ?? {};
      const out: PbrRuleDesired = { number: Number(num) };
      if (rn.action !== undefined) out.action = String(rn.action);
      const src = parseMatch(rn.source as Record<string, unknown> | undefined);
      if (src) out.source = src;
      const dst = parseMatch(
        rn.destination as Record<string, unknown> | undefined,
      );
      if (dst) out.destination = dst;
      if (rn.protocol !== undefined) out.protocol = String(rn.protocol);
      const setNode = rn.set as Record<string, unknown> | undefined;
      if (setNode) {
        const s: { table?: number | "main"; mark?: number; dscp?: number } = {};
        if (setNode.table !== undefined) {
          s.table = setNode.table === "main" ? "main" : Number(setNode.table);
        }
        if (setNode.mark !== undefined) s.mark = Number(setNode.mark);
        if (setNode.dscp !== undefined) s.dscp = Number(setNode.dscp);
        if (Object.keys(s).length) out.set = s;
      }
      if ("disable" in rn) out.disable = true;
      if ("log" in rn) out.log = true;
      return out;
    });
  // VyOS renders the multi-value `interface` leaf as a JSON array (even for a
  // single value); normalize array/scalar/object-keyed/absent to a full list so
  // a ruleset bound to multiple interfaces round-trips without losing any.
  const iface = n.interface;
  const interfaces = Array.isArray(iface)
    ? iface.map(String)
    : iface && typeof iface === "object"
    ? Object.keys(iface as Record<string, unknown>)
    : iface !== undefined
    ? [String(iface)]
    : [];
  return {
    interfaces,
    description: n.description as string | undefined,
    enableDefaultLog: "enable-default-log" in n,
    rules,
  };
}

/** Resource specs contributed by the PBR family. */
export const pbrResources = {
  "policyRoute": {
    description:
      "Typed named policy-route ruleset (policy route[6] <name>) managed as one declarative unit",
    schema: PbrRulesetSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the PBR family. */
export const pbrMethods = {
  syncPolicyRoute: {
    description:
      "Read one named policy-route ruleset (policy route[6] <name>) into a typed policyRoute resource.",
    arguments: z.object({
      family: z.enum(["ipv4", "ipv6"]).describe(
        "ipv4 -> `policy route`, ipv6 -> `policy route6`",
      ),
      name: z.string().describe("Named policy-route ruleset"),
    }),
    execute: async (
      args: { family: "ipv4" | "ipv6"; name: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info(
        "Reading policy route {family} {name} on {host}",
        { family: args.family, name: args.name, host: cfg.host },
      );
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error(
          "syncPolicyRoute failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `syncPolicyRoute failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncPolicyRoute: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      const policy = (parsed.policy ?? {}) as Record<string, unknown>;
      const familyKey = args.family === "ipv4" ? "route" : "route6";
      const famNode = (policy[familyKey] ?? {}) as Record<
        string,
        Record<string, unknown>
      >;
      const node = famNode[args.name];
      const rs = parsePolicyRoute(node);
      const handle = await context.writeResource(
        "policyRoute",
        `${args.family}-${args.name}`,
        {
          host: cfg.host,
          name: args.name,
          family: args.family,
          exists: node !== undefined,
          interfaces: rs.interfaces,
          description: rs.description,
          enableDefaultLog: rs.enableDefaultLog,
          rules: rs.rules,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "policy route {family} {name}: exists={exists}, {n} rule(s)",
        {
          family: args.family,
          name: args.name,
          exists: node !== undefined,
          n: rs.rules.length,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  ensurePolicyRoute: {
    description:
      "Declaratively set one named policy-route ruleset: reconciles to exactly the desired rules (stale rules removed), idempotent.",
    arguments: z.object({
      family: z.enum(["ipv4", "ipv6"]).describe(
        "ipv4 -> `policy route`, ipv6 -> `policy route6`",
      ),
      name: z.string().describe("Named policy-route ruleset"),
      interfaces: z.array(z.string()).default([]).describe(
        "In-ruleset `interface` leaf(s) (documentation only; does NOT bind the " +
          "ruleset — bind separately via `set interfaces <if> policy route <name>`)",
      ),
      description: z.string().optional(),
      enableDefaultLog: z.boolean().optional(),
      rules: z.array(PbrRuleSchema).default([]),
      raw: z.array(z.string()).default([]).describe(
        "Extra leaf fragments appended under the ruleset path",
      ),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z
        .boolean()
        .default(false)
        .describe("Preview the diff without committing"),
    }),
    execute: async (
      args:
        & PbrRulesetDesired
        & {
          family: "ipv4" | "ipv6";
          name: string;
          commit: boolean;
          save: boolean;
          dryRun: boolean;
          _ssh?: SshRunner;
        },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const sets = pbrSetPaths(args.family, args.name, args);
      if (sets.length === 0) {
        throw new Error(
          "ensurePolicyRoute requires at least one rule or ruleset attribute (use removePolicyRoute to clear)",
        );
      }
      // Reconcile: wipe the whole named-ruleset subtree, then set desired ->
      // the ruleset ends up as exactly `sets`. Net-zero change is a no-op.
      const deletes = [pbrBase(args.family, args.name)];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring policy route {family} {name} on {host} ({n} set path(s), dryRun={dryRun})",
        {
          family: args.family,
          name: args.name,
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
          "ensurePolicyRoute failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensurePolicyRoute failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensurePolicyRoute {family} {name} complete (changed={changed}, committed={committed})",
        {
          family: args.family,
          name: args.name,
          changed,
          committed,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  removePolicyRoute: {
    description: "Delete one named policy-route ruleset (its whole subtree).",
    arguments: z.object({
      family: z.enum(["ipv4", "ipv6"]).describe(
        "ipv4 -> `policy route`, ipv6 -> `policy route6`",
      ),
      name: z.string().describe("Named policy-route ruleset"),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args: {
        family: "ipv4" | "ipv6";
        name: string;
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const deletes = [pbrBase(args.family, args.name)];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing policy route {family} {name} on {host} (dryRun={dryRun})",
        {
          family: args.family,
          name: args.name,
          host: cfg.host,
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
          "removePolicyRoute failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removePolicyRoute failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removePolicyRoute {family} {name} complete (changed={changed}, committed={committed})",
        {
          family: args.family,
          name: args.name,
          changed,
          committed,
        },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const pbrCheckMethods = ["ensurePolicyRoute", "removePolicyRoute"];

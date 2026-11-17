/**
 * VyOS hook-based firewall rulesets model: schemas, reconcile helpers, resource specs, and
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

/** A source/destination match block within a firewall rule. */
export const FirewallMatchSchema = z.object({
  address: z.string().optional().describe(
    "Address/CIDR/range, optionally negated with a leading '!'",
  ),
  port: z.string().optional().describe("Port or comma list, e.g. '80,443'"),
  addressGroup: z.string().optional().describe("VyOS `group address-group`"),
  networkGroup: z.string().optional().describe("VyOS `group network-group`"),
  portGroup: z.string().optional().describe("VyOS `group port-group`"),
});

/**
 * A single firewall rule (`firewall <family> name <n> rule <num>`). Covers the
 * common match/target leaves; anything unmodeled goes in `raw` (fragments
 * appended verbatim under the rule path).
 */
const FirewallRuleSchema = z.object({
  num: z.union([z.number().int().positive(), z.string()]).describe(
    "Rule number (ordering key within the ruleset)",
  ),
  action: z.string().optional().describe(
    "accept|drop|reject|jump|return|continue|offload",
  ),
  description: z.string().optional(),
  protocol: z.string().optional().describe("tcp|udp|tcp_udp|icmp|all|<number>"),
  state: z.array(z.string()).default([]).describe(
    "new|established|related|invalid (each emitted as its own `state` leaf)",
  ),
  source: FirewallMatchSchema.optional(),
  destination: FirewallMatchSchema.optional(),
  inboundInterface: z.string().optional().describe(
    "VyOS `inbound-interface name`",
  ),
  outboundInterface: z.string().optional().describe(
    "VyOS `outbound-interface name`",
  ),
  jumpTarget: z.string().optional().describe(
    "Named ruleset to jump to (with action=jump)",
  ),
  log: z.boolean().optional().describe("Emit the valueless `log` leaf"),
  disable: z.boolean().optional().describe("Emit the valueless `disable` leaf"),
  raw: z.array(z.string()).default([]).describe(
    "Extra leaf fragments appended under the rule (e.g. 'tcp flags SYN')",
  ),
});

/**
 * Typed named firewall ruleset (`firewall <family> name <name>`) - a whole
 * hook-based (VyOS 1.4+) ruleset managed as one declarative unit. Cleartext: a
 * ruleset carries no secrets (addresses/ports/groups only).
 */
const FirewallRulesetSchema = z.object({
  host: z.string(),
  family: z.string().describe("ipv4 or ipv6"),
  name: z.string(),
  exists: z.boolean(),
  defaultAction: z.string().optional(),
  description: z.string().optional(),
  enableDefaultLog: z.boolean().default(false),
  rules: z.array(FirewallRuleSchema).default([]),
  retrievedAt: z.iso.datetime(),
});

/** A source/destination match block for {@link firewallSetPaths}. */
export interface FirewallMatchDesired {
  address?: string;
  port?: string;
  addressGroup?: string;
  networkGroup?: string;
  portGroup?: string;
}

/** A desired firewall rule for {@link firewallSetPaths}. */
export interface FirewallRuleDesired {
  num: number | string;
  action?: string;
  description?: string;
  protocol?: string;
  state?: string[];
  source?: FirewallMatchDesired;
  destination?: FirewallMatchDesired;
  inboundInterface?: string;
  outboundInterface?: string;
  jumpTarget?: string;
  log?: boolean;
  disable?: boolean;
  raw?: string[];
}

/** Desired state of a whole named firewall ruleset. */
export interface FirewallRulesetDesired {
  defaultAction?: string;
  description?: string;
  enableDefaultLog?: boolean;
  rules?: FirewallRuleDesired[];
  raw?: string[];
}

/** Emit the `set` leaves for one rule's source/destination match block. */
export function firewallMatchSetPaths(
  ruleBase: string,
  side: "source" | "destination",
  m: FirewallMatchDesired,
): string[] {
  const b = `${ruleBase} ${side}`;
  const paths: string[] = [];
  if (m.address !== undefined) paths.push(`${b} address ${m.address}`);
  if (m.port !== undefined) paths.push(`${b} port ${m.port}`);
  if (m.addressGroup !== undefined) {
    paths.push(`${b} group address-group ${m.addressGroup}`);
  }
  if (m.networkGroup !== undefined) {
    paths.push(`${b} group network-group ${m.networkGroup}`);
  }
  if (m.portGroup !== undefined) {
    paths.push(`${b} group port-group ${m.portGroup}`);
  }
  return paths;
}

/**
 * Translate a desired named-ruleset state into VyOS `set` paths (bare, no
 * leading `set`). Paired with a delete of `firewall <family> name <name>`, this
 * reconciles the ruleset to exactly the desired state.
 */
export function firewallSetPaths(
  family: string,
  name: string,
  desired: FirewallRulesetDesired,
): string[] {
  const base = `firewall ${family} name ${name}`;
  const paths: string[] = [];
  if (desired.defaultAction !== undefined) {
    paths.push(`${base} default-action ${desired.defaultAction}`);
  }
  if (desired.description !== undefined) {
    paths.push(`${base} description ${quoteIfSpaced(desired.description)}`);
  }
  if (desired.enableDefaultLog === true) {
    paths.push(`${base} enable-default-log`);
  }
  for (const r of desired.rules ?? []) {
    const rb = `${base} rule ${r.num}`;
    if (r.action !== undefined) paths.push(`${rb} action ${r.action}`);
    if (r.description !== undefined) {
      paths.push(`${rb} description ${quoteIfSpaced(r.description)}`);
    }
    if (r.protocol !== undefined) paths.push(`${rb} protocol ${r.protocol}`);
    for (const s of r.state ?? []) paths.push(`${rb} state ${s}`);
    if (r.source) paths.push(...firewallMatchSetPaths(rb, "source", r.source));
    if (r.destination) {
      paths.push(...firewallMatchSetPaths(rb, "destination", r.destination));
    }
    if (r.inboundInterface !== undefined) {
      paths.push(`${rb} inbound-interface name ${r.inboundInterface}`);
    }
    if (r.outboundInterface !== undefined) {
      paths.push(`${rb} outbound-interface name ${r.outboundInterface}`);
    }
    if (r.jumpTarget !== undefined) {
      paths.push(`${rb} jump-target ${r.jumpTarget}`);
    }
    if (r.log === true) paths.push(`${rb} log`);
    if (r.disable === true) paths.push(`${rb} disable`);
    for (const frag of r.raw ?? []) paths.push(`${rb} ${frag}`);
  }
  for (const frag of desired.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/** Parsed state of a named firewall ruleset (from `show configuration json`). */
export interface FirewallRulesetState {
  defaultAction?: string;
  description?: string;
  enableDefaultLog: boolean;
  rules: FirewallRuleDesired[];
}

/**
 * Parse one named ruleset node (firewall.<family>.name[<name>]) into its typed
 * state. Rules are returned sorted by numeric rule number.
 */
export function parseFirewallRuleset(
  node: Record<string, unknown> | undefined,
): FirewallRulesetState {
  const n = (node ?? {}) as Record<string, unknown>;
  const asArr = (v: unknown): string[] =>
    Array.isArray(v) ? v.map(String) : v === undefined ? [] : [String(v)];
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
  const rules: FirewallRuleDesired[] = Object.keys(ruleNode)
    .sort((a, b) => Number(a) - Number(b))
    .map((num) => {
      const rn = ruleNode[num] ?? {};
      const out: FirewallRuleDesired = {
        num: /^\d+$/.test(num) ? Number(num) : num,
      };
      if (rn.action !== undefined) out.action = String(rn.action);
      if (rn.description !== undefined) {
        out.description = String(rn.description);
      }
      if (rn.protocol !== undefined) out.protocol = String(rn.protocol);
      const st = asArr(rn.state);
      if (st.length) out.state = st;
      const src = parseMatch(rn.source as Record<string, unknown> | undefined);
      if (src) out.source = src;
      const dst = parseMatch(
        rn.destination as Record<string, unknown> | undefined,
      );
      if (dst) out.destination = dst;
      const inb = rn["inbound-interface"] as
        | Record<string, unknown>
        | undefined;
      if (inb?.name !== undefined) out.inboundInterface = String(inb.name);
      const oub = rn["outbound-interface"] as
        | Record<string, unknown>
        | undefined;
      if (oub?.name !== undefined) out.outboundInterface = String(oub.name);
      if (rn["jump-target"] !== undefined) {
        out.jumpTarget = String(rn["jump-target"]);
      }
      if ("log" in rn) out.log = true;
      if ("disable" in rn) out.disable = true;
      return out;
    });
  return {
    defaultAction: n["default-action"] as string | undefined,
    description: n.description as string | undefined,
    enableDefaultLog: "enable-default-log" in n,
    rules,
  };
}

/** Resource specs contributed by the firewall family. */
export const firewallResources = {
  "firewallRuleset": {
    description:
      "Typed named firewall ruleset (firewall <family> name <name>) managed as one declarative unit",
    schema: FirewallRulesetSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the firewall family. */
export const firewallMethods = {
  syncFirewall: {
    description:
      "Read one named firewall ruleset (firewall <family> name <name>) into a typed firewallRuleset resource.",
    arguments: z.object({
      family: z.enum(["ipv4", "ipv6"]).describe("Firewall address family"),
      name: z.string().describe("Named ruleset, e.g. GUEST-FWD"),
    }),
    execute: async (
      args: { family: "ipv4" | "ipv6"; name: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info(
        "Reading firewall {family} name {name} on {host}",
        { family: args.family, name: args.name, host: cfg.host },
      );
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error("syncFirewall failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `syncFirewall failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncFirewall: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const fw = (parsed.firewall ?? {}) as Record<string, any>;
      const famNode = (fw[args.family] ?? {}) as Record<string, unknown>;
      const node = ((famNode.name ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.name];
      const rs = parseFirewallRuleset(node);
      const handle = await context.writeResource(
        "firewallRuleset",
        `${args.family}-${args.name}`,
        {
          host: cfg.host,
          family: args.family,
          name: args.name,
          exists: node !== undefined,
          defaultAction: rs.defaultAction,
          description: rs.description,
          enableDefaultLog: rs.enableDefaultLog,
          rules: rs.rules,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "firewall {family} name {name}: exists={exists}, {n} rule(s)",
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
  ensureFirewall: {
    description:
      "Declaratively set one named firewall ruleset: reconciles to exactly the desired rules (stale rules removed), idempotent.",
    arguments: z.object({
      family: z.enum(["ipv4", "ipv6"]).describe("Firewall address family"),
      name: z.string().describe("Named ruleset, e.g. GUEST-FWD"),
      defaultAction: z.string().optional().describe(
        "accept|drop|reject (the ruleset's default-action)",
      ),
      description: z.string().optional(),
      enableDefaultLog: z.boolean().optional(),
      rules: z.array(FirewallRuleSchema).default([]),
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
        & FirewallRulesetDesired
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
      const sets = firewallSetPaths(args.family, args.name, args);
      if (sets.length === 0) {
        throw new Error(
          "ensureFirewall requires at least one rule or ruleset attribute (use removeFirewall to clear)",
        );
      }
      // Reconcile: wipe the whole named-ruleset subtree, then set desired ->
      // the ruleset ends up as exactly `sets`. Net-zero change is a no-op.
      const deletes = [`firewall ${args.family} name ${args.name}`];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring firewall {family} name {name} on {host} ({n} set path(s), dryRun={dryRun})",
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
          "ensureFirewall failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureFirewall failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureFirewall {family} name {name} complete (changed={changed}, committed={committed})",
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
  removeFirewall: {
    description: "Delete one named firewall ruleset (its whole subtree).",
    arguments: z.object({
      family: z.enum(["ipv4", "ipv6"]).describe("Firewall address family"),
      name: z.string().describe("Named ruleset, e.g. GUEST-FWD"),
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
      const deletes = [`firewall ${args.family} name ${args.name}`];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing firewall {family} name {name} on {host} (dryRun={dryRun})",
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
          "removeFirewall failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeFirewall failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeFirewall {family} name {name} complete (changed={changed}, committed={committed})",
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
export const firewallCheckMethods = ["ensureFirewall", "removeFirewall"];

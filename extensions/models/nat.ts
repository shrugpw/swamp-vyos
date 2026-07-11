/**
 * VyOS NAT rule lists model: schemas, reconcile helpers, resource specs, and
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

/** A source/destination match block within a NAT rule. */
const NatMatchSchema = z.object({
  address: z.string().optional().describe(
    "Address/CIDR/range (source or destination match)",
  ),
  port: z.string().optional().describe("Port, range, or comma list"),
  addressGroup: z.string().optional().describe("VyOS `group address-group`"),
  networkGroup: z.string().optional().describe("VyOS `group network-group`"),
  portGroup: z.string().optional().describe("VyOS `group port-group`"),
});

/** The translation block of a NAT rule (`translation address/port`). */
const NatTranslationSchema = z.object({
  address: z.string().optional().describe(
    "Translation address: an IP/range, or the literal 'masquerade' (source NAT)",
  ),
  port: z.string().optional().describe("Translation port (or range)"),
});

/**
 * A single NAT rule (`nat <direction> rule <num>`). Covers the common
 * match/translation leaves; anything unmodeled goes in `raw` (fragments appended
 * verbatim under the rule path).
 */
const NatRuleSchema = z.object({
  num: z.union([z.number().int().positive(), z.string()]).describe(
    "Rule number (ordering key within the direction's rule list)",
  ),
  description: z.string().optional(),
  protocol: z.string().optional().describe("tcp|udp|tcp_udp|icmp|all|<number>"),
  source: NatMatchSchema.optional(),
  destination: NatMatchSchema.optional(),
  inboundInterface: z.string().optional().describe(
    "VyOS `inbound-interface name` (destination NAT)",
  ),
  outboundInterface: z.string().optional().describe(
    "VyOS `outbound-interface name` (source NAT)",
  ),
  translation: NatTranslationSchema.optional(),
  exclude: z.boolean().optional().describe("Emit the valueless `exclude` leaf"),
  disable: z.boolean().optional().describe("Emit the valueless `disable` leaf"),
  log: z.boolean().optional().describe("Emit the valueless `log` leaf"),
  raw: z.array(z.string()).default([]).describe(
    "Extra leaf fragments appended under the rule (e.g. 'translation options ...')",
  ),
});

/**
 * Typed NAT rule list for one direction (`nat source` | `nat destination`) — a
 * whole direction's rules managed as one declarative unit. Cleartext: NAT rules
 * carry no secrets (addresses/ports/interfaces only).
 */
const NatRulesetSchema = z.object({
  host: z.string(),
  direction: z.enum(["source", "destination"]),
  exists: z.boolean(),
  rules: z.array(NatRuleSchema).default([]),
  retrievedAt: z.iso.datetime(),
});

/** A source/destination match block for {@link natSetPaths}. */
export interface NatMatchDesired {
  address?: string;
  port?: string;
  addressGroup?: string;
  networkGroup?: string;
  portGroup?: string;
}

/** The translation block for {@link natSetPaths}. */
export interface NatTranslationDesired {
  address?: string;
  port?: string;
}

/** A desired NAT rule for {@link natSetPaths}. */
export interface NatRuleDesired {
  num: number | string;
  description?: string;
  protocol?: string;
  source?: NatMatchDesired;
  destination?: NatMatchDesired;
  inboundInterface?: string;
  outboundInterface?: string;
  translation?: NatTranslationDesired;
  exclude?: boolean;
  disable?: boolean;
  log?: boolean;
  raw?: string[];
}

/** Desired state of a whole NAT direction's rule list. */
export interface NatRulesetDesired {
  rules?: NatRuleDesired[];
  raw?: string[];
}

/** Emit the `set` leaves for one NAT rule's source/destination match block. */
function natMatchSetPaths(
  ruleBase: string,
  side: "source" | "destination",
  m: NatMatchDesired,
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
 * Translate a desired NAT direction's rule list into VyOS `set` paths (bare, no
 * leading `set`). Paired with a delete of `nat <direction> rule`, this
 * reconciles the direction to exactly the desired rules.
 */
export function natSetPaths(
  direction: "source" | "destination",
  desired: NatRulesetDesired,
): string[] {
  const base = `nat ${direction}`;
  const paths: string[] = [];
  for (const r of desired.rules ?? []) {
    const rb = `${base} rule ${r.num}`;
    if (r.description !== undefined) {
      paths.push(`${rb} description ${quoteIfSpaced(r.description)}`);
    }
    if (r.protocol !== undefined) paths.push(`${rb} protocol ${r.protocol}`);
    if (r.source) paths.push(...natMatchSetPaths(rb, "source", r.source));
    if (r.destination) {
      paths.push(...natMatchSetPaths(rb, "destination", r.destination));
    }
    if (r.inboundInterface !== undefined) {
      paths.push(`${rb} inbound-interface name ${r.inboundInterface}`);
    }
    if (r.outboundInterface !== undefined) {
      paths.push(`${rb} outbound-interface name ${r.outboundInterface}`);
    }
    if (r.translation) {
      if (r.translation.address !== undefined) {
        paths.push(`${rb} translation address ${r.translation.address}`);
      }
      if (r.translation.port !== undefined) {
        paths.push(`${rb} translation port ${r.translation.port}`);
      }
    }
    if (r.exclude === true) paths.push(`${rb} exclude`);
    if (r.disable === true) paths.push(`${rb} disable`);
    if (r.log === true) paths.push(`${rb} log`);
    for (const frag of r.raw ?? []) paths.push(`${rb} ${frag}`);
  }
  for (const frag of desired.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/** Parsed state of a NAT direction's rule list (from `show configuration json`). */
export interface NatRulesetState {
  rules: NatRuleDesired[];
}

/**
 * Parse one NAT direction node (nat.<direction>) into its typed state. Rules are
 * returned sorted by numeric rule number.
 */
export function parseNatRuleset(
  node: Record<string, unknown> | undefined,
): NatRulesetState {
  const n = (node ?? {}) as Record<string, unknown>;
  const parseMatch = (
    mn: Record<string, unknown> | undefined,
  ): NatMatchDesired | undefined => {
    if (!mn) return undefined;
    const g = (mn.group ?? {}) as Record<string, unknown>;
    const m: NatMatchDesired = {};
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
  const rules: NatRuleDesired[] = Object.keys(ruleNode)
    .sort((a, b) => Number(a) - Number(b))
    .map((num) => {
      const rn = ruleNode[num] ?? {};
      const out: NatRuleDesired = {
        num: /^\d+$/.test(num) ? Number(num) : num,
      };
      if (rn.description !== undefined) {
        out.description = String(rn.description);
      }
      if (rn.protocol !== undefined) out.protocol = String(rn.protocol);
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
      const tn = rn.translation as Record<string, unknown> | undefined;
      if (tn) {
        const t: NatTranslationDesired = {};
        if (tn.address !== undefined) t.address = String(tn.address);
        if (tn.port !== undefined) t.port = String(tn.port);
        if (Object.keys(t).length) out.translation = t;
      }
      if ("exclude" in rn) out.exclude = true;
      if ("disable" in rn) out.disable = true;
      if ("log" in rn) out.log = true;
      return out;
    });
  return { rules };
}

/** Resource specs contributed by the nat family. */
export const natResources = {
  "natRuleset": {
    description:
      "Typed NAT rule list for one direction (nat source|destination) managed as one declarative unit",
    schema: NatRulesetSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the nat family. */
export const natMethods = {
  syncNat: {
    description:
      "Read one NAT direction's rule list (nat source|destination) into a typed natRuleset resource.",
    arguments: z.object({
      direction: z.enum(["source", "destination"]).describe(
        "NAT direction",
      ),
    }),
    execute: async (
      args: { direction: "source" | "destination"; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading nat {direction} on {host}", {
        direction: args.direction,
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error("syncNat failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `syncNat failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncNat: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const nat = (parsed.nat ?? {}) as Record<string, any>;
      const node = nat[args.direction] as
        | Record<string, unknown>
        | undefined;
      const rs = parseNatRuleset(node);
      const handle = await context.writeResource(
        "natRuleset",
        args.direction,
        {
          host: cfg.host,
          direction: args.direction,
          exists: node !== undefined,
          rules: rs.rules,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "nat {direction}: exists={exists}, {n} rule(s)",
        {
          direction: args.direction,
          exists: node !== undefined,
          n: rs.rules.length,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureNat: {
    description:
      "Declaratively set one NAT direction's rule list: reconciles to exactly the desired rules (stale rules removed), idempotent.",
    arguments: z.object({
      direction: z.enum(["source", "destination"]).describe(
        "NAT direction",
      ),
      rules: z.array(NatRuleSchema).default([]),
      raw: z.array(z.string()).default([]).describe(
        "Extra leaf fragments appended under the nat <direction> path",
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
        & NatRulesetDesired
        & {
          direction: "source" | "destination";
          commit: boolean;
          save: boolean;
          dryRun: boolean;
          _ssh?: SshRunner;
        },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const sets = natSetPaths(args.direction, args);
      if (sets.length === 0) {
        throw new Error(
          "ensureNat requires at least one rule or raw fragment (use removeNat to clear)",
        );
      }
      // Reconcile: wipe the direction's whole rule list, then set desired ->
      // the direction ends up as exactly `sets`. Net-zero change is a no-op.
      const deletes = [`nat ${args.direction} rule`];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring nat {direction} on {host} ({n} set path(s), dryRun={dryRun})",
        {
          direction: args.direction,
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
          "ensureNat failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureNat failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureNat {direction} complete (changed={changed}, committed={committed})",
        {
          direction: args.direction,
          changed,
          committed,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  removeNat: {
    description: "Delete one NAT direction's whole rule list.",
    arguments: z.object({
      direction: z.enum(["source", "destination"]).describe(
        "NAT direction",
      ),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args: {
        direction: "source" | "destination";
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      const deletes = [`nat ${args.direction} rule`];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing nat {direction} on {host} (dryRun={dryRun})",
        {
          direction: args.direction,
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
          "removeNat failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeNat failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeNat {direction} complete (changed={changed}, committed={committed})",
        {
          direction: args.direction,
          changed,
          committed,
        },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const natCheckMethods = ["ensureNat", "removeNat"];

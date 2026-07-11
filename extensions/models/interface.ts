/**
 * VyOS scoped L3 interface attributes model: schemas, reconcile helpers, resource specs, and
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

/**
 * Typed L3 attributes of one interface (`interfaces <type> <name>`). Scoped on
 * purpose: only the attributes this model manages — NOT bridge members, hw-id,
 * vif, firewall assignments, etc.
 */
const InterfaceSchema = z.object({
  host: z.string(),
  type: z.string(),
  interface: z.string(),
  exists: z.boolean(),
  address: z.array(z.string()).default([]),
  description: z.string().optional(),
  mtu: z.union([z.number().int(), z.string()]).optional(),
  disable: z.boolean().default(false),
  retrievedAt: z.iso.datetime(),
});

/** Current L3 state of an interface, parsed from `show configuration json`. */
export interface InterfaceState {
  address: string[];
  description?: string;
  mtu?: number | string;
  disable: boolean;
}

/** Desired scoped interface attributes for {@link interfaceReconcile}. */
export interface InterfaceDesired {
  address?: string[];
  description?: string;
  mtu?: number | string;
  disable?: boolean;
}

/** Parse one interface node (interfaces.<type>.<name>) into its L3 state. */
export function parseInterfaceNode(
  node: Record<string, unknown> | undefined,
): InterfaceState {
  const n = (node ?? {}) as Record<string, unknown>;
  const asArr = (v: unknown): string[] =>
    Array.isArray(v) ? v as string[] : v === undefined ? [] : [String(v)];
  return {
    address: asArr(n.address),
    description: n.description as string | undefined,
    mtu: n.mtu as string | undefined,
    disable: "disable" in n,
  };
}

/**
 * Compute the SCOPED set/delete paths to reconcile an interface's managed L3
 * attributes to `desired`, given its `current` state. Only touches
 * address/description/mtu/disable — never the rest of the interface subtree.
 * `disable`/`description`/`mtu` left `undefined` in `desired` are not touched.
 */
export function interfaceReconcile(
  type: string,
  name: string,
  current: InterfaceState,
  desired: InterfaceDesired,
): { sets: string[]; deletes: string[] } {
  const base = `interfaces ${type} ${name}`;
  const sets: string[] = [];
  const deletes: string[] = [];
  if (desired.address !== undefined) {
    const want = new Set(desired.address);
    for (const a of current.address) {
      if (!want.has(a)) deletes.push(`${base} address ${a}`);
    }
    for (const a of desired.address) sets.push(`${base} address ${a}`);
  }
  if (desired.description !== undefined) {
    sets.push(`${base} description ${quoteIfSpaced(desired.description)}`);
  }
  if (desired.mtu !== undefined) sets.push(`${base} mtu ${desired.mtu}`);
  if (desired.disable === true) sets.push(`${base} disable`);
  else if (desired.disable === false && current.disable) {
    deletes.push(`${base} disable`);
  }
  return { sets, deletes };
}

/** Resource specs contributed by the interface family. */
export const interfaceResources = {
  "interface": {
    description:
      "Scoped L3 attributes of one interface (address/description/mtu/disable)",
    schema: InterfaceSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the interface family. */
export const interfaceMethods = {
  syncInterface: {
    description:
      "Read the scoped L3 attributes (address/description/mtu/disable) of one interface into a typed interface resource.",
    arguments: z.object({
      type: z.string().describe(
        "Interface type, e.g. ethernet, bridge, loopback, dummy",
      ),
      interface: z.string().describe("Interface name, e.g. br0, eth0"),
    }),
    execute: async (
      args: { type: string; interface: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading interface {type} {iface} on {host}", {
        type: args.type,
        iface: args.interface,
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error("syncInterface failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `syncInterface failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncInterface: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const ifaces = (parsed.interfaces ?? {}) as Record<string, any>;
      const node = ((ifaces[args.type] ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.interface];
      const st = parseInterfaceNode(node);
      const handle = await context.writeResource(
        "interface",
        args.interface,
        {
          host: cfg.host,
          type: args.type,
          interface: args.interface,
          exists: node !== undefined,
          address: st.address,
          description: st.description,
          mtu: st.mtu,
          disable: st.disable,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "interface {iface}: exists={exists}, {n} address(es)",
        {
          iface: args.interface,
          exists: node !== undefined,
          n: st.address.length,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureInterface: {
    description:
      "Declaratively set an interface's scoped L3 attributes (address list reconciled; description/mtu/disable set). Never touches the rest of the interface subtree (members, hw-id, vif, ...).",
    arguments: z.object({
      type: z.string(),
      interface: z.string(),
      address: z.array(z.string()).optional(),
      description: z.string().optional(),
      mtu: z.union([z.number().int(), z.string()]).optional(),
      disable: z.boolean().optional(),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args:
        & InterfaceDesired
        & {
          type: string;
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
      if (
        args.address === undefined && args.description === undefined &&
        args.mtu === undefined && args.disable === undefined
      ) {
        throw new Error(
          "ensureInterface requires at least one of address/description/mtu/disable",
        );
      }
      // Read current state so the address list can be reconciled (scoped —
      // we never wipe the whole interface subtree).
      const read = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (read.code !== 0) {
        context.logger.error(
          "ensureInterface read failed on {host} (exit {code})",
          { host: cfg.host, code: read.code },
        );
        throw new Error(
          `ensureInterface: read config failed on ${cfg.host} (exit ${read.code}): ${read.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(read.stdout);
      } catch (e) {
        throw new Error(
          `ensureInterface: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const ifaces = (parsed.interfaces ?? {}) as Record<string, any>;
      const node = ((ifaces[args.type] ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.interface];
      const current = parseInterfaceNode(node);
      const { sets, deletes } = interfaceReconcile(
        args.type,
        args.interface,
        current,
        args,
      );
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring interface {type} {iface} on {host} ({s} set, {d} delete, dryRun={dryRun})",
        {
          type: args.type,
          iface: args.interface,
          host: cfg.host,
          s: sets.length,
          d: deletes.length,
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
          "ensureInterface failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureInterface failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureInterface {iface} complete (changed={changed}, committed={committed})",
        { iface: args.interface, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const interfaceCheckMethods = ["ensureInterface"];

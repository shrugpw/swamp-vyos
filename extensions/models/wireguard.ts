/**
 * VyOS WireGuard interface model: schemas, reconcile helpers, resource specs, and
 * methods. Assembled into the model in `vyos.ts`.
 *
 * @module
 */
import { z } from "npm:zod@4";
import {
  buildConfigScript,
  OP_WRAPPER,
  quoteIfSpaced,
  SENTINEL_CHANGED,
  sshExec,
  validateApplyPaths,
} from "./core.ts";
import type { ExecuteContext, ExecuteResult, SshRunner } from "./core.ts";

/** A WireGuard peer (VyOS `interfaces wireguard <if> peer <name>`). */
const WgPeerSchema = z.object({
  name: z.string(),
  publicKey: z.string(),
  address: z.string().optional().describe("Endpoint host/IP"),
  port: z.union([z.number().int(), z.string()]).optional().describe(
    "Endpoint port",
  ),
  allowedIps: z.array(z.string()).default([]),
  persistentKeepalive: z.union([z.number().int(), z.string()]).optional(),
  presharedKey: z.string().optional(),
  description: z.string().optional(),
});

/**
 * Typed WireGuard interface config. The whole resource is vaulted
 * (`sensitiveOutput`) because it carries the interface `private-key` and per-peer
 * `preshared-key`.
 */
const WireguardSchema = z.object({
  host: z.string(),
  interface: z.string(),
  exists: z.boolean(),
  privateKey: z.string().optional(),
  address: z.array(z.string()).default([]),
  port: z.union([z.number().int(), z.string()]).optional(),
  mtu: z.union([z.number().int(), z.string()]).optional(),
  adjustMss: z.string().optional().describe("ipv6 adjust-mss value"),
  fwmark: z.union([z.number().int(), z.string()]).optional(),
  description: z.string().optional(),
  peers: z.array(WgPeerSchema).default([]),
  retrievedAt: z.iso.datetime(),
});

/** A desired WireGuard peer for {@link wireguardSetPaths}. */
export interface WgPeerDesired {
  name: string;
  publicKey: string;
  address?: string;
  port?: number | string;
  allowedIps?: string[];
  persistentKeepalive?: number | string;
  presharedKey?: string;
  description?: string;
}

/** Desired WireGuard interface state for {@link wireguardSetPaths}. */
export interface WireguardDesired {
  privateKey?: string;
  address?: string[];
  port?: number | string;
  mtu?: number | string;
  adjustMss?: string;
  fwmark?: number | string;
  description?: string;
  peers?: WgPeerDesired[];
}

/**
 * Translate a desired WireGuard interface state into VyOS `set` paths (bare, no
 * leading `set`). Paired with a delete of `interfaces wireguard <if>`, this
 * reconciles the interface to exactly the desired state.
 */
export function wireguardSetPaths(
  iface: string,
  desired: WireguardDesired,
): string[] {
  const base = `interfaces wireguard ${iface}`;
  const paths: string[] = [];
  if (desired.privateKey) {
    paths.push(`${base} private-key ${desired.privateKey}`);
  }
  for (const a of desired.address ?? []) paths.push(`${base} address ${a}`);
  if (desired.port !== undefined) paths.push(`${base} port ${desired.port}`);
  if (desired.mtu !== undefined) paths.push(`${base} mtu ${desired.mtu}`);
  if (desired.adjustMss !== undefined) {
    paths.push(`${base} ipv6 adjust-mss ${desired.adjustMss}`);
  }
  if (desired.fwmark !== undefined) {
    paths.push(`${base} fwmark ${desired.fwmark}`);
  }
  if (desired.description !== undefined) {
    paths.push(`${base} description ${quoteIfSpaced(desired.description)}`);
  }
  for (const p of desired.peers ?? []) {
    const pb = `${base} peer ${p.name}`;
    paths.push(`${pb} public-key ${p.publicKey}`);
    if (p.address !== undefined) paths.push(`${pb} address ${p.address}`);
    if (p.port !== undefined) paths.push(`${pb} port ${p.port}`);
    for (const aip of p.allowedIps ?? []) {
      paths.push(`${pb} allowed-ips ${aip}`);
    }
    if (p.persistentKeepalive !== undefined) {
      paths.push(`${pb} persistent-keepalive ${p.persistentKeepalive}`);
    }
    if (p.presharedKey) paths.push(`${pb} preshared-key ${p.presharedKey}`);
    if (p.description !== undefined) {
      paths.push(`${pb} description ${quoteIfSpaced(p.description)}`);
    }
  }
  return paths;
}

/**
 * Parse one interface's node from `show configuration json`
 * (interfaces.wireguard[<if>]) into the typed WireGuard shape (secrets included).
 */
export function parseWireguardInterface(
  node: Record<string, unknown> | undefined,
): Omit<WireguardDesired, "peers"> & {
  peers: WgPeerDesired[];
  address: string[];
} {
  const n = (node ?? {}) as Record<string, unknown>;
  const asArr = (v: unknown): string[] =>
    Array.isArray(v) ? v as string[] : v === undefined ? [] : [String(v)];
  const ipv6 = (n.ipv6 ?? {}) as Record<string, unknown>;
  const peerNode = (n.peer ?? {}) as Record<string, Record<string, unknown>>;
  const peers: WgPeerDesired[] = Object.keys(peerNode).map((name) => {
    const p = peerNode[name] ?? {};
    return {
      name,
      publicKey: String(p["public-key"] ?? ""),
      address: p.address as string | undefined,
      port: p.port as string | undefined,
      allowedIps: asArr(p["allowed-ips"]),
      persistentKeepalive: p["persistent-keepalive"] as string | undefined,
      presharedKey: p["preshared-key"] as string | undefined,
      description: p.description as string | undefined,
    };
  });
  return {
    privateKey: n["private-key"] as string | undefined,
    address: asArr(n.address),
    port: n.port as string | undefined,
    mtu: n.mtu as string | undefined,
    adjustMss: ipv6["adjust-mss"] as string | undefined,
    fwmark: n.fwmark as string | undefined,
    description: n.description as string | undefined,
    peers,
  };
}

/** Resource specs contributed by the wireguard family. */
export const wireguardResources = {
  "wireguard": {
    description:
      "Typed WireGuard interface config (whole record vaulted — carries private/preshared keys)",
    schema: WireguardSchema,
    sensitiveOutput: true,
    vaultName: "vyos",
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the wireguard family. */
export const wireguardMethods = {
  syncWireguard: {
    description:
      "Read the current WireGuard config for one interface into a typed (vaulted) wireguard resource.",
    arguments: z.object({
      interface: z.string().describe("WireGuard interface, e.g. wg0"),
    }),
    execute: async (
      args: { interface: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading wireguard {iface} on {host}", {
        iface: args.interface,
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error("syncWireguard failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `syncWireguard failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncWireguard: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      // deno-lint-ignore no-explicit-any
      const ifaces = (parsed.interfaces ?? {}) as Record<string, any>;
      const wgNode = ((ifaces.wireguard ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.interface];
      const wg = parseWireguardInterface(wgNode);
      const handle = await context.writeResource(
        "wireguard",
        args.interface,
        {
          host: cfg.host,
          interface: args.interface,
          exists: wgNode !== undefined,
          privateKey: wg.privateKey,
          address: wg.address,
          port: wg.port,
          mtu: wg.mtu,
          adjustMss: wg.adjustMss,
          fwmark: wg.fwmark,
          description: wg.description,
          peers: wg.peers,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "wireguard {iface}: exists={exists}, {n} peer(s)",
        {
          iface: args.interface,
          exists: wgNode !== undefined,
          n: wg.peers.length,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureWireguard: {
    description:
      "Declaratively set the WireGuard config for one interface (reconciles to exactly the desired state; result is vaulted).",
    arguments: z.object({
      interface: z.string(),
      privateKey: z.string().optional(),
      address: z.array(z.string()).default([]),
      port: z.union([z.number().int(), z.string()]).optional(),
      mtu: z.union([z.number().int(), z.string()]).optional(),
      adjustMss: z.string().optional(),
      fwmark: z.union([z.number().int(), z.string()]).optional(),
      description: z.string().optional(),
      peers: z.array(WgPeerSchema).default([]),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args:
        & WireguardDesired
        & {
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
      const sets = wireguardSetPaths(args.interface, args);
      if (sets.length === 0) {
        throw new Error(
          "ensureWireguard requires at least one field to set (use removeWireguard to clear)",
        );
      }
      const deletes = [`interfaces wireguard ${args.interface}`];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring wireguard {iface} on {host} ({n} path(s), dryRun={dryRun})",
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
      // The set paths + compare diff carry the private/preshared keys, so the
      // whole result is vaulted (sensitiveApplyResult).
      const handle = await context.writeResource(
        "sensitiveApplyResult",
        "last",
        {
          host: cfg.host,
          set: sets,
          delete: deletes,
          dryRun: args.dryRun,
          changed,
          committed,
          saved: committed && args.save,
          script,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          appliedAt: new Date().toISOString(),
        },
      );
      if (result.code !== 0) {
        context.logger.error(
          "ensureWireguard failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureWireguard failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureWireguard {iface} complete (changed={changed}, committed={committed})",
        { iface: args.interface, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
  removeWireguard: {
    description:
      "Delete a WireGuard interface's config (result vaulted — the diff exposes keys).",
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
      const deletes = [`interfaces wireguard ${args.interface}`];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing wireguard {iface} on {host} (dryRun={dryRun})",
        { iface: args.interface, host: cfg.host, dryRun: args.dryRun },
      );
      const result = await ssh(cfg, {
        command: ["/bin/vbash", "-s"],
        stdin: script,
      });
      const changed = result.stdout.includes(SENTINEL_CHANGED);
      const committed = args.commit && changed && !args.dryRun;
      const handle = await context.writeResource(
        "sensitiveApplyResult",
        "last",
        {
          host: cfg.host,
          set: [],
          delete: deletes,
          dryRun: args.dryRun,
          changed,
          committed,
          saved: committed && args.save,
          script,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          appliedAt: new Date().toISOString(),
        },
      );
      if (result.code !== 0) {
        context.logger.error(
          "removeWireguard failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeWireguard failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeWireguard {iface} complete (changed={changed}, committed={committed})",
        { iface: args.interface, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const wireguardCheckMethods = ["ensureWireguard", "removeWireguard"];

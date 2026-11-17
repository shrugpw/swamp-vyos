/**
 * VyOS IPv4 `service dhcp-server` model: schemas, reconcile helpers, resource
 * specs, and methods. Assembled into the model in `vyos.ts`.
 *
 * Reconcile unit is the shared-network (`shared-network-name <SNN>`):
 * `ensureDhcpSharedNetwork` is a whole-subtree declarative reconcile (firewall
 * pattern). `ensureStaticMappings` is a SCOPED fan-out over just the
 * `static-mapping` children of one subnet (interface pattern) - the daily
 * driver for adding/removing a host reservation without touching
 * hand-tuned ranges/options/subnet-id.
 *
 * IPv4 only; `dhcpv6-server` is a distinct tree (prefix-delegation, no
 * ranges) and is out of scope here.
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
 * `option ...` leaves shared by the shared-network level (inherited by all
 * subnets) and the subnet level (overrides/adds to the inherited set).
 */
const DhcpOptionsSchema = z.object({
  defaultRouter: z.string().optional(),
  nameServer: z.array(z.string()).default([]),
  domainName: z.string().optional(),
  domainSearch: z.array(z.string()).default([]),
  raw: z.array(z.string()).default([]).describe(
    "Extra 'option ...' leaf fragments not otherwise modeled",
  ),
});

/** One numbered `range <n> { start, stop }` block within a subnet. */
const DhcpRangeSchema = z.object({
  n: z.number().int().optional().describe("Range index; defaults to 0"),
  start: z.string(),
  stop: z.string(),
});

/** One named `static-mapping <name> { ip-address, mac }` reservation. */
const DhcpStaticMappingSchema = z.object({
  name: z.string(),
  ipAddress: z.string(),
  mac: z.string(),
  description: z.string().optional(),
  raw: z.array(z.string()).default([]),
});

/**
 * One `subnet <cidr>` block. `subnetId` is MANDATORY and must be unique per
 * shared-network (VyOS 1.4+) - always emitted by {@link dhcpSetPaths} so a
 * read-then-ensure round-trip never drops it (an omitted subnet-id fails
 * commit).
 */
const DhcpSubnetSchema = z.object({
  cidr: z.string(),
  subnetId: z.number().int(),
  lease: z.number().int().optional(),
  options: DhcpOptionsSchema.optional(),
  ranges: z.array(DhcpRangeSchema).default([]),
  staticMappings: z.array(DhcpStaticMappingSchema).default([]),
  raw: z.array(z.string()).default([]),
});

/**
 * Typed IPv4 `service dhcp-server shared-network-name <name>` - a whole
 * shared-network managed as one declarative unit. Cleartext: this subtree
 * carries no secrets (leases/addresses only).
 */
const DhcpSharedNetworkSchema = z.object({
  host: z.string(),
  name: z.string(),
  exists: z.boolean(),
  authoritative: z.boolean().optional(),
  options: DhcpOptionsSchema.optional(),
  subnets: z.array(DhcpSubnetSchema).default([]),
  raw: z.array(z.string()).default([]),
  retrievedAt: z.iso.datetime(),
});

/** Desired `option ...` leaves for {@link dhcpSetPaths} / subnet options. */
export interface DhcpOptionsDesired {
  defaultRouter?: string;
  nameServer?: string[];
  domainName?: string;
  domainSearch?: string[];
  raw?: string[];
}

/** A desired numbered range for {@link dhcpSetPaths}. */
export interface DhcpRangeDesired {
  n?: number;
  start: string;
  stop: string;
}

/** A desired static-mapping reservation for {@link dhcpSetPaths}. */
export interface DhcpStaticMappingDesired {
  name: string;
  ipAddress: string;
  mac: string;
  description?: string;
  raw?: string[];
}

/** A desired subnet for {@link dhcpSetPaths}. */
export interface DhcpSubnetDesired {
  cidr: string;
  subnetId: number;
  lease?: number;
  options?: DhcpOptionsDesired;
  ranges?: DhcpRangeDesired[];
  staticMappings?: DhcpStaticMappingDesired[];
  raw?: string[];
}

/** Desired state of a whole shared-network. */
export interface DhcpSharedNetworkDesired {
  authoritative?: boolean;
  options?: DhcpOptionsDesired;
  subnets?: DhcpSubnetDesired[];
  raw?: string[];
}

/** Parsed state of a whole shared-network (from `show configuration json`). */
export interface DhcpSharedNetworkState {
  authoritative?: boolean;
  options?: DhcpOptionsDesired;
  subnets: DhcpSubnetDesired[];
}

/**
 * Normalize a live JSON leaf that may render as a scalar, an array, an
 * object-keyed-by-value (`{ "8.8.8.8": {} }` - VyOS renders some multi-value
 * leaves this way, e.g. `option name-server`/`domain-search`), or absent.
 * Matches the dns_forwarding `asList` helper so the equivalent leaves round-trip
 * regardless of which JSON shape `show configuration json` emits for them.
 */
function asArr(v: unknown): string[] {
  if (Array.isArray(v)) return v.map(String);
  if (v && typeof v === "object") {
    return Object.keys(v as Record<string, unknown>);
  }
  if (v === undefined) return [];
  return [String(v)];
}

/** Emit the `set` leaves for one `option ...` block (SNN- or subnet-scoped). */
function dhcpOptionPaths(
  base: string,
  o: DhcpOptionsDesired | undefined,
): string[] {
  if (!o) return [];
  const paths: string[] = [];
  if (o.defaultRouter !== undefined) {
    paths.push(`${base} option default-router ${o.defaultRouter}`);
  }
  for (const ns of o.nameServer ?? []) {
    paths.push(`${base} option name-server ${ns}`);
  }
  if (o.domainName !== undefined) {
    paths.push(`${base} option domain-name ${quoteIfSpaced(o.domainName)}`);
  }
  for (const ds of o.domainSearch ?? []) {
    paths.push(`${base} option domain-search ${quoteIfSpaced(ds)}`);
  }
  for (const frag of o.raw ?? []) paths.push(`${base} option ${frag}`);
  return paths;
}

/**
 * Emit the `set` leaves for one static-mapping reservation. Private, but
 * shared by both the whole-SNN ensure and the scoped `ensureStaticMappings`
 * fan-out so the two emit byte-identical leaves for the same mapping.
 */
function dhcpStaticMappingPaths(
  subnetBase: string,
  m: DhcpStaticMappingDesired,
): string[] {
  const b = `${subnetBase} static-mapping ${m.name}`;
  const paths: string[] = [
    `${b} ip-address ${m.ipAddress}`,
    `${b} mac ${m.mac}`,
  ];
  if (m.description !== undefined) {
    paths.push(`${b} description ${quoteIfSpaced(m.description)}`);
  }
  for (const frag of m.raw ?? []) paths.push(`${b} ${frag}`);
  return paths;
}

/** Emit the `set` leaves for one subnet, including its mandatory subnet-id. */
function dhcpSubnetPaths(snnBase: string, subnet: DhcpSubnetDesired): string[] {
  const base = `${snnBase} subnet ${subnet.cidr}`;
  // subnet-id is REQUIRED and must always be emitted - omitting it (e.g. if a
  // sync->ensure round-trip dropped the field) would fail commit.
  const paths: string[] = [`${base} subnet-id ${subnet.subnetId}`];
  if (subnet.lease !== undefined) paths.push(`${base} lease ${subnet.lease}`);
  paths.push(...dhcpOptionPaths(base, subnet.options));
  (subnet.ranges ?? []).forEach((r, i) => {
    const n = r.n ?? i;
    paths.push(`${base} range ${n} start ${r.start}`);
    paths.push(`${base} range ${n} stop ${r.stop}`);
  });
  for (const m of subnet.staticMappings ?? []) {
    paths.push(...dhcpStaticMappingPaths(base, m));
  }
  for (const frag of subnet.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/**
 * Translate a desired whole shared-network state into VyOS `set` paths (bare,
 * no leading `set`). Paired with a delete of
 * `service dhcp-server shared-network-name <name>`, this reconciles the
 * shared-network to exactly the desired state (omitted subnet/mapping =
 * deletion).
 */
export function dhcpSetPaths(
  name: string,
  desired: DhcpSharedNetworkDesired,
): string[] {
  const base = `service dhcp-server shared-network-name ${name}`;
  const paths: string[] = [];
  if (desired.authoritative === true) paths.push(`${base} authoritative`);
  paths.push(...dhcpOptionPaths(base, desired.options));
  for (const s of desired.subnets ?? []) {
    paths.push(...dhcpSubnetPaths(base, s));
  }
  for (const frag of desired.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/** Parse one `option` node into the shared options shape. */
function parseDhcpOptions(
  node: Record<string, unknown> | undefined,
): DhcpOptionsDesired | undefined {
  if (!node) return undefined;
  const o: DhcpOptionsDesired = {};
  if (node["default-router"] !== undefined) {
    o.defaultRouter = String(node["default-router"]);
  }
  const ns = asArr(node["name-server"]);
  if (ns.length) o.nameServer = ns;
  if (node["domain-name"] !== undefined) {
    o.domainName = String(node["domain-name"]);
  }
  const ds = asArr(node["domain-search"]);
  if (ds.length) o.domainSearch = ds;
  return Object.keys(o).length ? o : undefined;
}

/** Parse a `range` node (keyed by index) into numbered range entries. */
function parseDhcpRanges(
  node: Record<string, Record<string, unknown>> | undefined,
): DhcpRangeDesired[] {
  const rn = node ?? {};
  return Object.keys(rn)
    .sort((a, b) => Number(a) - Number(b))
    .map((k) => {
      const r = rn[k] ?? {};
      return {
        n: Number(k),
        start: String(r.start),
        stop: String(r.stop),
      };
    });
}

/**
 * Parse the `static-mapping` children of one subnet node into typed
 * reservations, sorted by name for deterministic output. Shared by
 * `syncDhcpSharedNetwork` (via {@link parseDhcpSharedNetwork}) and the scoped
 * `ensureStaticMappings` (to read the current fan-out set before diffing).
 */
export function parseStaticMappings(
  subnetNode: Record<string, unknown> | undefined,
): DhcpStaticMappingDesired[] {
  const mn = ((subnetNode ?? {})["static-mapping"] ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  return Object.keys(mn).sort().map((name) => {
    const m = mn[name] ?? {};
    const out: DhcpStaticMappingDesired = {
      name,
      ipAddress: String(m["ip-address"]),
      mac: String(m.mac),
    };
    if (m.description !== undefined) out.description = String(m.description);
    return out;
  });
}

/** Parse one subnet node (keyed by CIDR) into its typed desired shape. */
function parseDhcpSubnet(
  cidr: string,
  node: Record<string, unknown> | undefined,
): DhcpSubnetDesired {
  const n = node ?? {};
  const out: DhcpSubnetDesired = {
    cidr,
    subnetId: n["subnet-id"] !== undefined ? Number(n["subnet-id"]) : 0,
    ranges: parseDhcpRanges(
      n.range as Record<string, Record<string, unknown>> | undefined,
    ),
    staticMappings: parseStaticMappings(n),
  };
  if (n.lease !== undefined) out.lease = Number(n.lease);
  const opts = parseDhcpOptions(
    n.option as Record<string, unknown> | undefined,
  );
  if (opts) out.options = opts;
  return out;
}

/**
 * Parse one shared-network node
 * (service.dhcp-server.shared-network-name[<name>]) into its typed state.
 * Subnets are returned sorted by CIDR string for deterministic output.
 */
export function parseDhcpSharedNetwork(
  node: Record<string, unknown> | undefined,
): DhcpSharedNetworkState {
  const n = node ?? {};
  const out: DhcpSharedNetworkState = {
    authoritative: "authoritative" in n ? true : undefined,
    subnets: [],
  };
  const opts = parseDhcpOptions(
    n.option as Record<string, unknown> | undefined,
  );
  if (opts) out.options = opts;
  const subnetNode = (n.subnet ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
  out.subnets = Object.keys(subnetNode).sort().map((cidr) =>
    parseDhcpSubnet(cidr, subnetNode[cidr])
  );
  return out;
}

/** Navigate parsed `show configuration json` to the dhcp-server subtree. */
function dhcpServiceNode(
  parsed: Record<string, unknown>,
): Record<string, Record<string, unknown>> {
  // deno-lint-ignore no-explicit-any
  const svc = (parsed.service ?? {}) as Record<string, any>;
  return (svc["dhcp-server"]?.["shared-network-name"] ?? {}) as Record<
    string,
    Record<string, unknown>
  >;
}

/** Resource specs contributed by the dhcp family. */
export const dhcpResources = {
  "dhcpSharedNetwork": {
    description:
      "Typed IPv4 DHCP shared-network (service dhcp-server shared-network-name <name>) managed as one declarative unit",
    schema: DhcpSharedNetworkSchema,
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the dhcp family. */
export const dhcpMethods = {
  syncDhcpSharedNetwork: {
    description:
      "Read one IPv4 DHCP shared-network (service dhcp-server shared-network-name <name>) into a typed dhcpSharedNetwork resource.",
    arguments: z.object({
      name: z.string().describe("Shared-network-name, e.g. SERVERS"),
    }),
    execute: async (
      args: { name: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info(
        "Reading dhcp-server shared-network-name {name} on {host}",
        { name: args.name, host: cfg.host },
      );
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error(
          "syncDhcpSharedNetwork failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `syncDhcpSharedNetwork failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncDhcpSharedNetwork: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      const node = dhcpServiceNode(parsed)[args.name];
      const st = parseDhcpSharedNetwork(node);
      const handle = await context.writeResource(
        "dhcpSharedNetwork",
        args.name,
        {
          host: cfg.host,
          name: args.name,
          exists: node !== undefined,
          authoritative: st.authoritative,
          options: st.options,
          subnets: st.subnets,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "dhcp-server shared-network-name {name}: exists={exists}, {n} subnet(s)",
        { name: args.name, exists: node !== undefined, n: st.subnets.length },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureDhcpSharedNetwork: {
    description:
      "Declaratively set one whole IPv4 DHCP shared-network: reconciles to exactly the desired subnets/options (stale subnets/mappings/ranges removed), idempotent. subnet-id is mandatory per subnet and always emitted.",
    arguments: z.object({
      name: z.string().describe("Shared-network-name, e.g. SERVERS"),
      authoritative: z.boolean().optional(),
      options: DhcpOptionsSchema.optional(),
      subnets: z.array(DhcpSubnetSchema).default([]),
      raw: z.array(z.string()).default([]).describe(
        "Extra leaf fragments appended under the shared-network path",
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
        & DhcpSharedNetworkDesired
        & {
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
      const sets = dhcpSetPaths(args.name, args);
      if (sets.length === 0) {
        throw new Error(
          "ensureDhcpSharedNetwork requires at least one subnet or shared-network attribute (use removeDhcpSharedNetwork to clear)",
        );
      }
      // Reconcile: wipe the whole shared-network subtree, then set desired ->
      // it ends up as exactly `sets`. Net-zero change is a no-op.
      const deletes = [
        `service dhcp-server shared-network-name ${args.name}`,
      ];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring dhcp-server shared-network-name {name} on {host} ({n} set path(s), dryRun={dryRun})",
        {
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
          "ensureDhcpSharedNetwork failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureDhcpSharedNetwork failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureDhcpSharedNetwork {name} complete (changed={changed}, committed={committed})",
        { name: args.name, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
  removeDhcpSharedNetwork: {
    description: "Delete one IPv4 DHCP shared-network (its whole subtree).",
    arguments: z.object({
      name: z.string().describe("Shared-network-name, e.g. SERVERS"),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args: {
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
      const deletes = [
        `service dhcp-server shared-network-name ${args.name}`,
      ];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing dhcp-server shared-network-name {name} on {host} (dryRun={dryRun})",
        { name: args.name, host: cfg.host, dryRun: args.dryRun },
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
          "removeDhcpSharedNetwork failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeDhcpSharedNetwork failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeDhcpSharedNetwork {name} complete (changed={changed}, committed={committed})",
        { name: args.name, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureStaticMappings: {
    description:
      "Declaratively reconcile ONLY the static-mapping reservations under one DHCP subnet (read current, delete stale, set desired). Never touches ranges/options/subnet-id - the safe daily driver for adding/removing a host reservation.",
    arguments: z.object({
      sharedNetwork: z.string().describe("Shared-network-name, e.g. SERVERS"),
      subnet: z.string().describe("Subnet CIDR, e.g. 198.51.100.0/24"),
      mappings: z.array(DhcpStaticMappingSchema).default([]),
      commit: z.boolean().default(true),
      save: z.boolean().default(true),
      dryRun: z.boolean().default(false),
    }),
    execute: async (
      args: {
        sharedNetwork: string;
        subnet: string;
        mappings: DhcpStaticMappingDesired[];
        commit: boolean;
        save: boolean;
        dryRun: boolean;
        _ssh?: SshRunner;
      },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      // Read current state so only the static-mapping children are diffed -
      // scoped, we never wipe the subnet or shared-network subtree.
      const read = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (read.code !== 0) {
        context.logger.error(
          "ensureStaticMappings read failed on {host} (exit {code})",
          { host: cfg.host, code: read.code },
        );
        throw new Error(
          `ensureStaticMappings: read config failed on ${cfg.host} (exit ${read.code}): ${read.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(read.stdout);
      } catch (e) {
        throw new Error(
          `ensureStaticMappings: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      const snnNode = dhcpServiceNode(parsed)[args.sharedNetwork];
      const subnetNode = ((snnNode?.subnet ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.subnet];
      const current = parseStaticMappings(subnetNode);
      const subnetBase =
        `service dhcp-server shared-network-name ${args.sharedNetwork} subnet ${args.subnet}`;
      const desiredNames = new Set(args.mappings.map((m) => m.name));
      const deletes: string[] = [];
      for (const cm of current) {
        if (!desiredNames.has(cm.name)) {
          deletes.push(`${subnetBase} static-mapping ${cm.name}`);
        }
      }
      const sets: string[] = [];
      for (const m of args.mappings) {
        sets.push(...dhcpStaticMappingPaths(subnetBase, m));
      }
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring static-mappings under {snn} subnet {subnet} on {host} ({s} set, {d} delete, dryRun={dryRun})",
        {
          snn: args.sharedNetwork,
          subnet: args.subnet,
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
          "ensureStaticMappings failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureStaticMappings failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureStaticMappings {snn} {subnet} complete (changed={changed}, committed={committed})",
        {
          snn: args.sharedNetwork,
          subnet: args.subnet,
          changed,
          committed,
        },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const dhcpCheckMethods = [
  "ensureDhcpSharedNetwork",
  "removeDhcpSharedNetwork",
  "ensureStaticMappings",
];

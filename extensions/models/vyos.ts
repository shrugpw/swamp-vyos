/**
 * VyOS router management model.
 *
 * Manages a VyOS router over SSH: read the running configuration, apply
 * `set`/`delete` configuration commands through `vbash` (with `commit`/`save`),
 * and run arbitrary operational- or config-mode commands.
 *
 * VyOS is peculiar: configuration mode requires `vbash` sourcing the Vyatta
 * `script-template`; a plain `ssh host 'configure; set ...'` does NOT work.
 * Operational reads go through the `vyatta-op-cmd-wrapper`. This model encodes
 * those requirements so callers work in terms of plain `set`/`delete` paths.
 *
 * The SSH transport is deliberately isolated in {@link sshExec}. Once
 * model-to-model calls (`context.runModel`) land in the distributed binary,
 * that one helper can be swapped to invoke `@swamp/ssh` (`exec`/`script`)
 * instead of shelling out, with no change to the VyOS method logic. Every method
 * also accepts an injectable `_ssh` runner so the logic is unit-testable without
 * a live router.
 *
 * @module
 */
import { z } from "npm:zod@4";

/** Op-mode command wrapper — required for read-only "show ..." commands. */
const OP_WRAPPER = "/opt/vyatta/bin/vyatta-op-cmd-wrapper";

/** Sourced inside every config session so `configure`/`set`/`commit` resolve. */
const SCRIPT_TEMPLATE = "/opt/vyatta/etc/functions/script-template";

/** Emitted by the config script when the session had staged changes. */
const SENTINEL_CHANGED = "SWAMP_APPLY_CHANGED";

/** Emitted by the config script when the session was a no-op (idempotent). */
const SENTINEL_NOCHANGE = "SWAMP_APPLY_NOCHANGE";

/** Placeholder stored in place of the vbash script when `storeScript` is off. */
const SCRIPT_REDACTED =
  "<redacted: pass storeScript=true to persist the script>";

/** Connection/authentication settings for the target VyOS router. */
const GlobalArgsSchema = z.object({
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
});

/** Resolved connection/authentication settings. */
export type GlobalArgs = z.infer<typeof GlobalArgsSchema>;

/** Snapshot of the running configuration as `set` commands. */
const ConfigSchema = z.object({
  host: z.string(),
  command: z.string(),
  commands: z.string().describe("Raw output of the op-mode show command"),
  retrievedAt: z.iso.datetime(),
});

/**
 * Structured running configuration from native `show configuration json`.
 *
 * The well-known top-level sections are declared so CEL expressions can
 * reference them (e.g. `...attributes.interfaces`), and `.passthrough()` keeps
 * any section a given VyOS version emits that isn't listed here (rather than
 * silently dropping it). Nested content is intentionally permissive — the VyOS
 * tree is deep and version-variable.
 */
const treeSection = () => z.record(z.string(), z.unknown()).optional();
const ConfigTreeSchema = z.object({
  host: z.string(),
  container: treeSection(),
  firewall: treeSection(),
  interfaces: treeSection(),
  "load-balancing": treeSection(),
  nat: treeSection(),
  nat64: treeSection(),
  pki: treeSection(),
  policy: treeSection(),
  protocols: treeSection(),
  qos: treeSection(),
  service: treeSection(),
  system: treeSection(),
  vrf: treeSection(),
  retrievedAt: z.iso.datetime(),
}).passthrough();

/** Outcome of an `apply` (config-mode) run. */
const ApplyResultSchema = z.object({
  host: z.string(),
  set: z.array(z.string()),
  delete: z.array(z.string()),
  dryRun: z.boolean().describe(
    "True when changes were previewed, not committed",
  ),
  changed: z.boolean().describe(
    "True when the session had staged config changes",
  ),
  committed: z.boolean(),
  saved: z.boolean(),
  script: z
    .string()
    .describe("The vbash script that was piped (redacted unless storeScript)"),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  appliedAt: z.iso.datetime(),
});

/**
 * Same shape as {@link ApplyResultSchema}, but the secret-bearing fields are
 * marked `sensitive` so they are stored in the `vyos` vault and replaced with
 * vault references at persist time. Operational fields (host, changed,
 * committed, exitCode, ...) stay in cleartext so the record is still glanceable
 * without vault access. Written only when `apply` is called with `sensitive`.
 */
const SensitiveApplyResultSchema = ApplyResultSchema.extend({
  set: z.array(z.string()).meta({ sensitive: true }),
  delete: z.array(z.string()).meta({ sensitive: true }),
  script: z
    .string()
    .meta({ sensitive: true })
    .describe("The vbash script that was piped (vaulted)"),
  stdout: z.string().meta({ sensitive: true }),
  stderr: z.string().meta({ sensitive: true }),
});

/** Preview of the config change a `set`/`delete` would make (VyOS `compare`). */
const DiffResultSchema = z.object({
  host: z.string(),
  set: z.array(z.string()),
  delete: z.array(z.string()),
  changed: z.boolean().describe(
    "True when the staged change differs from the running config",
  ),
  diff: z
    .string()
    .describe(
      "The `compare` output for the staged change (empty if unchanged)",
    ),
  stderr: z.string(),
  exitCode: z.number().int(),
  comparedAt: z.iso.datetime(),
});

/**
 * Same shape as {@link DiffResultSchema} with the secret-bearing fields marked
 * `sensitive` (the `compare` output echoes staged `set` lines, which may include
 * keys). Vaulted; operational fields stay cleartext. Written when `diff` is
 * called with `sensitive`.
 */
const SensitiveDiffResultSchema = DiffResultSchema.extend({
  set: z.array(z.string()).meta({ sensitive: true }),
  delete: z.array(z.string()).meta({ sensitive: true }),
  diff: z
    .string()
    .meta({ sensitive: true })
    .describe("The `compare` output for the staged change (vaulted)"),
  stderr: z.string().meta({ sensitive: true }),
});

/** Outcome of a generic `run` (op- or config-mode) command. */
const CommandResultSchema = z.object({
  host: z.string(),
  command: z.string(),
  opMode: z.boolean(),
  stdout: z.string(),
  stderr: z.string(),
  exitCode: z.number().int(),
  ranAt: z.iso.datetime(),
});

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
 * Typed router-advert (IPv6 RA / SLAAC) config for one interface — the first
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

/** A source/destination match block within a firewall rule. */
const FirewallMatchSchema = z.object({
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
 * Typed named firewall ruleset (`firewall <family> name <name>`) — a whole
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
 * <prefix>` for IPv4 or `protocols static route6 <prefix>` for IPv6 — the
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
    if (opts.commit) lines.push("    commit");
    if (opts.save) lines.push("    save");
    lines.push(`    echo ${SENTINEL_CHANGED}`);
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

/** Single-quote a value if it contains whitespace (e.g. a description). */
function quoteIfSpaced(v: string): string {
  return /\s/.test(v) ? `'${v}'` : v;
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
function firewallMatchSetPaths(
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

/** Minimal LogTape logger surface used by this model. */
interface Logger {
  debug: (message: string, properties?: Record<string, unknown>) => void;
  info: (message: string, properties?: Record<string, unknown>) => void;
  warning: (message: string, properties?: Record<string, unknown>) => void;
  error: (message: string, properties?: Record<string, unknown>) => void;
}

/** Minimal shape of the execute context this model relies on. */
interface ExecuteContext {
  globalArgs: GlobalArgs;
  logger: Logger;
  writeResource: (
    specName: string,
    name: string,
    data: Record<string, unknown>,
  ) => Promise<{ name: string }>;
}

/** Minimal shape of the pre-flight check context this model relies on. */
interface CheckContext {
  globalArgs: GlobalArgs;
  logger: Logger;
}

/** Return shape for every method's execute function. */
interface ExecuteResult {
  dataHandles: Array<{ name: string }>;
}

/** VyOS router management model definition. */
export const model = {
  type: "@shrug/vyos",
  version: "2026.07.10.10",
  description:
    "Manage a VyOS router over SSH: read config, apply set/delete via vbash, run commands.",
  globalArguments: GlobalArgsSchema,
  resources: {
    "config": {
      description: "Running configuration snapshot (as set commands)",
      schema: ConfigSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "applyResult": {
      description: "Outcome of an apply (config-mode) run",
      schema: ApplyResultSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "sensitiveApplyResult": {
      description:
        "Outcome of an apply run with secret-bearing fields vaulted (sensitive=true)",
      schema: SensitiveApplyResultSchema,
      vaultName: "vyos",
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "diff": {
      description:
        "Preview of a set/delete change (VyOS compare), never committed",
      schema: DiffResultSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "sensitiveDiff": {
      description:
        "Preview of a set/delete change with secret-bearing fields vaulted (sensitive=true)",
      schema: SensitiveDiffResultSchema,
      vaultName: "vyos",
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "configTree": {
      description: "Structured running config (native show configuration json)",
      schema: ConfigTreeSchema,
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "sensitiveConfigTree": {
      description:
        "Structured running config with the whole tree vaulted (sensitive=true)",
      schema: ConfigTreeSchema,
      sensitiveOutput: true,
      vaultName: "vyos",
      lifetime: "infinite",
      garbageCollection: 20,
    },
    "commandResult": {
      description: "Outcome of a generic run command",
      schema: CommandResultSchema,
      lifetime: "infinite",
      garbageCollection: 50,
    },
    "routerAdvert": {
      description:
        "Typed IPv6 router-advert (RA/SLAAC) config for one interface",
      schema: RouterAdvertSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "wireguard": {
      description:
        "Typed WireGuard interface config (whole record vaulted — carries private/preshared keys)",
      schema: WireguardSchema,
      sensitiveOutput: true,
      vaultName: "vyos",
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "interface": {
      description:
        "Scoped L3 attributes of one interface (address/description/mtu/disable)",
      schema: InterfaceSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "firewallRuleset": {
      description:
        "Typed named firewall ruleset (firewall <family> name <name>) managed as one declarative unit",
      schema: FirewallRulesetSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "natRuleset": {
      description:
        "Typed NAT rule list for one direction (nat source|destination) managed as one declarative unit",
      schema: NatRulesetSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
    "staticRoute": {
      description:
        "Typed static route for one destination prefix (protocols static route|route6 <prefix>) managed as one declarative unit",
      schema: StaticRouteSchema,
      lifetime: "infinite",
      garbageCollection: 30,
    },
  },
  checks: {
    "reachable": {
      description:
        "Verify the router's config mode is reachable over SSH before applying.",
      labels: ["live"],
      appliesTo: [
        "apply",
        "diff",
        "ensureRouterAdvert",
        "removeRouterAdvert",
        "ensureWireguard",
        "removeWireguard",
        "ensureInterface",
        "ensureFirewall",
        "removeFirewall",
        "ensureNat",
        "removeNat",
        "ensureStaticRoute",
        "removeStaticRoute",
      ],
      execute: async (context: CheckContext): Promise<
        { pass: boolean; errors?: string[] }
      > => {
        const cfg = context.globalArgs;
        context.logger.info("Probing VyOS config mode on {host}", {
          host: cfg.host,
        });
        const probe = `source ${SCRIPT_TEMPLATE}\nconfigure\nexit\n`;
        const result = await sshExec(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: probe,
        });
        if (result.code !== 0) {
          return {
            pass: false,
            errors: [
              `cannot reach VyOS config mode on ${cfg.host}: ${
                result.stderr.trim() || `exit ${result.code}`
              }`,
            ],
          };
        }
        return { pass: true };
      },
    },
  },
  methods: {
    show: {
      description:
        "Read the running config (or any op-mode show command) and snapshot it.",
      arguments: z.object({
        command: z
          .string()
          .default("show configuration commands")
          .describe("Op-mode command to run (without the wrapper prefix)"),
      }),
      execute: async (
        args: { command: string; _ssh?: SshRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        context.logger.info("Reading config from {host}: {command}", {
          host: cfg.host,
          command: args.command,
        });
        const result = await ssh(cfg, {
          command: [OP_WRAPPER, ...args.command.split(/\s+/)],
        });
        if (result.code !== 0) {
          context.logger.error("show failed on {host} (exit {code})", {
            host: cfg.host,
            code: result.code,
          });
          throw new Error(
            `show failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        const handle = await context.writeResource("config", "current", {
          host: cfg.host,
          command: args.command,
          commands: result.stdout,
          retrievedAt: new Date().toISOString(),
        });
        context.logger.info("Snapshotted config from {host}", {
          host: cfg.host,
        });
        return { dataHandles: [handle] };
      },
    },
    tree: {
      description:
        "Read the running config as a structured tree (native show configuration json), queryable via CEL.",
      arguments: z.object({
        sensitive: z
          .boolean()
          .default(false)
          .describe(
            "Vault the whole config tree (it embeds WireGuard/PKI private " +
              "keys) in the 'vyos' vault; requires that vault to be configured",
          ),
      }),
      execute: async (
        args: { sensitive: boolean; _ssh?: SshRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        context.logger.info("Reading config tree from {host}", {
          host: cfg.host,
        });
        const result = await ssh(cfg, {
          command: [OP_WRAPPER, "show", "configuration", "json"],
        });
        if (result.code !== 0) {
          context.logger.error("tree failed on {host} (exit {code})", {
            host: cfg.host,
            code: result.code,
          });
          throw new Error(
            `tree failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        let parsed: Record<string, unknown>;
        try {
          parsed = JSON.parse(result.stdout);
        } catch (e) {
          throw new Error(
            `tree: could not parse 'show configuration json' from ${cfg.host}: ${
              e instanceof Error ? e.message : String(e)
            }`,
          );
        }
        const targetSpec = args.sensitive
          ? "sensitiveConfigTree"
          : "configTree";
        const handle = await context.writeResource(targetSpec, "current", {
          host: cfg.host,
          ...parsed,
          retrievedAt: new Date().toISOString(),
        });
        context.logger.info(
          "Snapshotted config tree from {host} ({sections} sections)",
          { host: cfg.host, sections: Object.keys(parsed).length },
        );
        return { dataHandles: [handle] };
      },
    },
    apply: {
      description:
        "Apply set/delete config commands via vbash, then commit and save.",
      arguments: z.object({
        set: z
          .array(z.string())
          .default([])
          .describe("Config paths to set (without the leading 'set')"),
        delete: z
          .array(z.string())
          .default([])
          .describe("Config paths to delete (without the leading 'delete')"),
        commit: z.boolean().default(true),
        save: z.boolean().default(true),
        dryRun: z
          .boolean()
          .default(false)
          .describe("Stage changes and print the diff without committing"),
        storeScript: z
          .boolean()
          .default(false)
          .describe("Persist the generated vbash script (may contain secrets)"),
        sensitive: z
          .boolean()
          .default(false)
          .describe(
            "Vault the secret-bearing fields (set/delete/script/stdout/stderr) " +
              "in the 'vyos' vault; requires that vault to be configured",
          ),
      }),
      execute: async (
        args: {
          set: string[];
          delete: string[];
          commit: boolean;
          save: boolean;
          dryRun: boolean;
          storeScript: boolean;
          sensitive: boolean;
          _ssh?: SshRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        if (args.set.length === 0 && args.delete.length === 0) {
          throw new Error("apply requires at least one set or delete command");
        }
        validateApplyPaths(args.set, args.delete);
        const script = buildConfigScript({
          sets: args.set,
          deletes: args.delete,
          commit: args.commit,
          save: args.save,
          dryRun: args.dryRun,
        });
        context.logger.info(
          "Applying to {host}: {sets} set, {deletes} delete (dryRun={dryRun})",
          {
            host: cfg.host,
            sets: args.set.length,
            deletes: args.delete.length,
            dryRun: args.dryRun,
          },
        );
        const result = await ssh(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: script,
        });
        const changed = result.stdout.includes(SENTINEL_CHANGED);
        const committed = args.commit && changed && !args.dryRun;
        // When sensitive, the whole record is vaulted, so redacting the script
        // is pointless — persist it in full (it is protected by the vault).
        const persistFullScript = args.sensitive || args.storeScript;
        const targetSpec = args.sensitive
          ? "sensitiveApplyResult"
          : "applyResult";
        const handle = await context.writeResource(targetSpec, "last", {
          host: cfg.host,
          set: args.set,
          delete: args.delete,
          dryRun: args.dryRun,
          changed,
          committed,
          saved: committed && args.save,
          script: persistFullScript ? script : SCRIPT_REDACTED,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          appliedAt: new Date().toISOString(),
        });
        if (result.code !== 0) {
          context.logger.error("apply failed on {host} (exit {code})", {
            host: cfg.host,
            code: result.code,
          });
          throw new Error(
            `apply failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        context.logger.info(
          "apply on {host} complete (changed={changed}, committed={committed})",
          { host: cfg.host, changed, committed },
        );
        return { dataHandles: [handle] };
      },
    },
    diff: {
      description:
        "Preview the config change a set/delete would make (VyOS compare) without committing — read-only.",
      arguments: z.object({
        set: z
          .array(z.string())
          .default([])
          .describe("Config paths to stage as set (without the leading 'set')"),
        delete: z
          .array(z.string())
          .default([])
          .describe(
            "Config paths to stage as delete (without the leading 'delete')",
          ),
        sensitive: z
          .boolean()
          .default(false)
          .describe(
            "Vault the secret-bearing fields (set/delete/diff/stderr) in the " +
              "'vyos' vault; requires that vault to be configured",
          ),
      }),
      execute: async (
        args: {
          set: string[];
          delete: string[];
          sensitive: boolean;
          _ssh?: SshRunner;
        },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        if (args.set.length === 0 && args.delete.length === 0) {
          throw new Error("diff requires at least one set or delete command");
        }
        validateApplyPaths(args.set, args.delete);
        // dryRun stages the change, prints `compare`, and discards — never
        // commits. commit/save are irrelevant in the dryRun branch.
        const script = buildConfigScript({
          sets: args.set,
          deletes: args.delete,
          commit: false,
          save: false,
          dryRun: true,
        });
        context.logger.info(
          "Diffing on {host}: {sets} set, {deletes} delete",
          {
            host: cfg.host,
            sets: args.set.length,
            deletes: args.delete.length,
          },
        );
        const result = await ssh(cfg, {
          command: ["/bin/vbash", "-s"],
          stdin: script,
        });
        const changed = result.stdout.includes(SENTINEL_CHANGED);
        const targetSpec = args.sensitive ? "sensitiveDiff" : "diff";
        const handle = await context.writeResource(targetSpec, "last", {
          host: cfg.host,
          set: args.set,
          delete: args.delete,
          changed,
          diff: extractDiff(result.stdout),
          stderr: result.stderr,
          exitCode: result.code,
          comparedAt: new Date().toISOString(),
        });
        if (result.code !== 0) {
          context.logger.error("diff failed on {host} (exit {code})", {
            host: cfg.host,
            code: result.code,
          });
          throw new Error(
            `diff failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        context.logger.info("diff on {host} complete (changed={changed})", {
          host: cfg.host,
          changed,
        });
        return { dataHandles: [handle] };
      },
    },
    run: {
      description:
        "Run an arbitrary command over SSH (op-mode wrapped when opMode=true).",
      arguments: z.object({
        command: z.string().describe("Command to run on the router"),
        opMode: z
          .boolean()
          .default(false)
          .describe("Prefix with the VyOS op-mode wrapper"),
      }),
      execute: async (
        args: { command: string; opMode: boolean; _ssh?: SshRunner },
        context: ExecuteContext,
      ): Promise<ExecuteResult> => {
        const cfg = context.globalArgs;
        const ssh = args._ssh ?? sshExec;
        context.logger.info("Running on {host} (opMode={opMode}): {command}", {
          host: cfg.host,
          opMode: args.opMode,
          command: args.command,
        });
        const argv = args.opMode
          ? [OP_WRAPPER, ...args.command.split(/\s+/)]
          : ["sh", "-c", args.command];
        const result = await ssh(cfg, { command: argv });
        const handle = await context.writeResource("commandResult", "last", {
          host: cfg.host,
          command: args.command,
          opMode: args.opMode,
          stdout: result.stdout,
          stderr: result.stderr,
          exitCode: result.code,
          ranAt: new Date().toISOString(),
        });
        if (result.code !== 0) {
          context.logger.error("run failed on {host} (exit {code})", {
            host: cfg.host,
            code: result.code,
          });
          throw new Error(
            `run failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
          );
        }
        context.logger.info("run on {host} complete", { host: cfg.host });
        return { dataHandles: [handle] };
      },
    },
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
  },
};

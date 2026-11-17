/**
 * VyOS container model (`container name <name>`): schemas, reconcile helpers,
 * resource specs, and methods. Assembled into the model in `vyos.ts`.
 *
 * Secrets fork: the whole container record is vaulted (`sensitiveOutput` +
 * `vaultName: "vyos"`), wireguard-style. `environment <NAME> value <v>` can
 * carry live secrets (e.g. a Tailscale auth key), and containers in general
 * are secret-laden, so the entire record - image/command/volumes/environment
 * included - becomes vault refs on read rather than modeling secrecy leaf by
 * leaf. Trade-off accepted: image/volumes are not glanceable in cleartext.
 *
 * OPERATIONAL CAVEAT: committing a container change regenerates the
 * container's systemd unit and can pull the image / restart the container -
 * slow and disruptive, akin to the dhclient bounce on interface apply.
 * `ensureContainer`/`removeContainer` may take a while to return; run
 * image-changing applies deliberately.
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

/** A bind-mounted volume (`container name <name> volume <n>`). */
const CVolumeSchema = z.object({
  name: z.string(),
  source: z.string(),
  destination: z.string(),
  mode: z.enum(["ro", "rw"]).optional(),
});

/** A passed-through device node (`container name <name> device <n>`). */
const CDeviceSchema = z.object({
  name: z.string(),
  source: z.string(),
  destination: z.string(),
});

/**
 * An environment variable (`container name <name> environment <NAME> value
 * <v>`). Field-level sensitivity metadata isn't needed because the whole
 * container record is vaulted.
 */
const CEnvSchema = z.object({
  name: z.string(),
  value: z.string(),
});

/** An attached network (`container name <name> network <n>`). */
const CNetworkSchema = z.object({
  name: z.string(),
  address: z.string().optional(),
});

/** A published port (`container name <name> port <n>`). */
const CPortSchema = z.object({
  name: z.string(),
  source: z.string(),
  destination: z.string(),
  protocol: z.enum(["tcp", "udp"]).optional(),
});

/**
 * Typed container config. The whole resource is vaulted (`sensitiveOutput`)
 * because `image`/`command`/`volumes`/`environment` can carry secrets (e.g. a
 * live `TS_AUTH_KEY`).
 */
const ContainerSchema = z.object({
  host: z.string(),
  name: z.string(),
  exists: z.boolean(),
  image: z.string(),
  command: z.string().optional(),
  restart: z.enum(["no", "on-failure", "always"]).optional(),
  hostName: z.string().optional(),
  uid: z.number().int().optional(),
  gid: z.number().int().optional(),
  disable: z.boolean().optional(),
  allowHostNetworks: z.boolean().optional(),
  allowHostPid: z.boolean().optional(),
  capabilities: z.array(z.string()).default([]),
  devices: z.array(CDeviceSchema).default([]),
  environment: z.array(CEnvSchema).default([]),
  volumes: z.array(CVolumeSchema).default([]),
  networks: z.array(CNetworkSchema).default([]),
  ports: z.array(CPortSchema).default([]),
  raw: z.array(z.string()).default([]).describe(
    "Extra leaf fragments appended under the container path (e.g. memory, cpu-quota)",
  ),
  retrievedAt: z.iso.datetime(),
});

/** A desired volume for {@link containerSetPaths}. */
export interface CVolumeDesired {
  name: string;
  source: string;
  destination: string;
  mode?: "ro" | "rw";
}

/** A desired device for {@link containerSetPaths}. */
export interface CDeviceDesired {
  name: string;
  source: string;
  destination: string;
}

/** A desired environment variable for {@link containerSetPaths}. */
export interface CEnvDesired {
  name: string;
  value: string;
}

/** A desired network attachment for {@link containerSetPaths}. */
export interface CNetworkDesired {
  name: string;
  address?: string;
}

/** A desired published port for {@link containerSetPaths}. */
export interface CPortDesired {
  name: string;
  source: string;
  destination: string;
  protocol?: "tcp" | "udp";
}

/** Desired whole-container state for {@link containerSetPaths}. */
export interface ContainerDesired {
  image: string;
  command?: string;
  restart?: "no" | "on-failure" | "always";
  hostName?: string;
  uid?: number;
  gid?: number;
  disable?: boolean;
  allowHostNetworks?: boolean;
  allowHostPid?: boolean;
  capabilities?: string[];
  devices?: CDeviceDesired[];
  environment?: CEnvDesired[];
  volumes?: CVolumeDesired[];
  networks?: CNetworkDesired[];
  ports?: CPortDesired[];
  raw?: string[];
}

/**
 * Translate a desired container state into VyOS `set` paths (bare, no leading
 * `set`). Paired with a delete of `container name <name>`, this reconciles
 * the container to exactly the desired state.
 */
export function containerSetPaths(
  name: string,
  desired: ContainerDesired,
): string[] {
  const base = `container name ${name}`;
  const paths: string[] = [];
  paths.push(`${base} image ${desired.image}`);
  if (desired.command !== undefined) {
    paths.push(`${base} command ${quoteIfSpaced(desired.command)}`);
  }
  if (desired.restart !== undefined) {
    paths.push(`${base} restart ${desired.restart}`);
  }
  if (desired.hostName !== undefined) {
    paths.push(`${base} host-name ${quoteIfSpaced(desired.hostName)}`);
  }
  if (desired.uid !== undefined) paths.push(`${base} uid ${desired.uid}`);
  if (desired.gid !== undefined) paths.push(`${base} gid ${desired.gid}`);
  if (desired.disable === true) paths.push(`${base} disable`);
  if (desired.allowHostNetworks === true) {
    paths.push(`${base} allow-host-networks`);
  }
  if (desired.allowHostPid === true) paths.push(`${base} allow-host-pid`);
  for (const cap of desired.capabilities ?? []) {
    paths.push(`${base} capability ${cap}`);
  }
  for (const d of desired.devices ?? []) {
    const db = `${base} device ${d.name}`;
    paths.push(`${db} source ${d.source}`);
    paths.push(`${db} destination ${d.destination}`);
  }
  for (const e of desired.environment ?? []) {
    paths.push(
      `${base} environment ${e.name} value ${quoteIfSpaced(e.value)}`,
    );
  }
  for (const v of desired.volumes ?? []) {
    const vb = `${base} volume ${v.name}`;
    paths.push(`${vb} source ${v.source}`);
    paths.push(`${vb} destination ${v.destination}`);
    if (v.mode !== undefined) paths.push(`${vb} mode ${v.mode}`);
  }
  for (const n of desired.networks ?? []) {
    // A network node with no address leaf still needs its own `set` so the
    // (otherwise valueless) stanza is created.
    if (n.address !== undefined) {
      paths.push(`${base} network ${n.name} address ${n.address}`);
    } else {
      paths.push(`${base} network ${n.name}`);
    }
  }
  for (const p of desired.ports ?? []) {
    const pb = `${base} port ${p.name}`;
    paths.push(`${pb} source ${p.source}`);
    paths.push(`${pb} destination ${p.destination}`);
    if (p.protocol !== undefined) paths.push(`${pb} protocol ${p.protocol}`);
  }
  for (const frag of desired.raw ?? []) paths.push(`${base} ${frag}`);
  return paths;
}

/** Parsed state of a container (from `show configuration json`). */
export interface ContainerParsed extends ContainerDesired {
  capabilities: string[];
  devices: CDeviceDesired[];
  environment: CEnvDesired[];
  volumes: CVolumeDesired[];
  networks: CNetworkDesired[];
  ports: CPortDesired[];
  raw: string[];
}

/**
 * Parse one container's node from `show configuration json`
 * (container.name[<name>]) into the typed container shape (secrets included).
 */
export function parseContainer(
  node: Record<string, unknown> | undefined,
): ContainerParsed {
  const n = (node ?? {}) as Record<string, unknown>;

  // `capability` is a multi-value leaf; VyOS's JSON renders a single value as
  // a bare string, more than one as an array, but some code paths key it by
  // value instead - normalize all three shapes to string[].
  const asCapabilities = (v: unknown): string[] => {
    if (Array.isArray(v)) return v.map(String);
    if (v && typeof v === "object") {
      return Object.keys(v as Record<string, unknown>);
    }
    if (v === undefined) return [];
    return [String(v)];
  };

  const keyed = (v: unknown): Record<string, Record<string, unknown>> =>
    (v ?? {}) as Record<string, Record<string, unknown>>;

  const deviceNode = keyed(n.device);
  const devices: CDeviceDesired[] = Object.keys(deviceNode).map((name) => {
    const d = deviceNode[name] ?? {};
    return {
      name,
      source: String(d.source ?? ""),
      destination: String(d.destination ?? ""),
    };
  });

  const volumeNode = keyed(n.volume);
  const volumes: CVolumeDesired[] = Object.keys(volumeNode).map((name) => {
    const v = volumeNode[name] ?? {};
    const out: CVolumeDesired = {
      name,
      source: String(v.source ?? ""),
      destination: String(v.destination ?? ""),
    };
    if (v.mode !== undefined) out.mode = v.mode as "ro" | "rw";
    return out;
  });

  const envNode = keyed(n.environment);
  const environment: CEnvDesired[] = Object.keys(envNode).map((name) => ({
    name,
    value: String(envNode[name]?.value ?? ""),
  }));

  const netNode = keyed(n.network);
  const networks: CNetworkDesired[] = Object.keys(netNode).map((name) => {
    const nd = netNode[name] ?? {};
    const out: CNetworkDesired = { name };
    if (nd.address !== undefined) out.address = String(nd.address);
    return out;
  });

  const portNode = keyed(n.port);
  const ports: CPortDesired[] = Object.keys(portNode).map((name) => {
    const p = portNode[name] ?? {};
    const out: CPortDesired = {
      name,
      source: String(p.source ?? ""),
      destination: String(p.destination ?? ""),
    };
    if (p.protocol !== undefined) out.protocol = p.protocol as "tcp" | "udp";
    return out;
  });

  const out: ContainerParsed = {
    image: String(n.image ?? ""),
    capabilities: asCapabilities(n.capability),
    devices,
    environment,
    volumes,
    networks,
    ports,
    raw: [],
  };
  if (n.command !== undefined) out.command = String(n.command);
  if (n.restart !== undefined) {
    out.restart = n.restart as "no" | "on-failure" | "always";
  }
  if (n["host-name"] !== undefined) out.hostName = String(n["host-name"]);
  if (n.uid !== undefined) out.uid = Number(n.uid);
  if (n.gid !== undefined) out.gid = Number(n.gid);
  if ("disable" in n) out.disable = true;
  if ("allow-host-networks" in n) out.allowHostNetworks = true;
  if ("allow-host-pid" in n) out.allowHostPid = true;
  return out;
}

/** Resource specs contributed by the container family. */
export const containerResources = {
  "container": {
    description:
      "Typed container config (whole record vaulted - image/command/volumes/environment may carry secrets)",
    schema: ContainerSchema,
    sensitiveOutput: true,
    vaultName: "vyos",
    lifetime: "infinite",
    garbageCollection: 30,
  },
};

/** Method definitions contributed by the container family. */
export const containerMethods = {
  syncContainer: {
    description:
      "Read one container's config (container name <name>) into a typed (vaulted) container resource.",
    arguments: z.object({
      name: z.string().describe("Container name, e.g. metrics-agent"),
    }),
    execute: async (
      args: { name: string; _ssh?: SshRunner },
      context: ExecuteContext,
    ): Promise<ExecuteResult> => {
      const cfg = context.globalArgs;
      const ssh = args._ssh ?? sshExec;
      context.logger.info("Reading container {name} on {host}", {
        name: args.name,
        host: cfg.host,
      });
      const result = await ssh(cfg, {
        command: [OP_WRAPPER, "show", "configuration", "json"],
      });
      if (result.code !== 0) {
        context.logger.error("syncContainer failed on {host} (exit {code})", {
          host: cfg.host,
          code: result.code,
        });
        throw new Error(
          `syncContainer failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      let parsed: Record<string, unknown>;
      try {
        parsed = JSON.parse(result.stdout);
      } catch (e) {
        throw new Error(
          `syncContainer: could not parse config json from ${cfg.host}: ${
            e instanceof Error ? e.message : String(e)
          }`,
        );
      }
      const containerSection = (parsed.container ?? {}) as Record<
        string,
        unknown
      >;
      const node = ((containerSection.name ?? {}) as Record<
        string,
        Record<string, unknown>
      >)[args.name];
      const c = parseContainer(node);
      const handle = await context.writeResource(
        "container",
        args.name,
        {
          host: cfg.host,
          name: args.name,
          exists: node !== undefined,
          image: c.image,
          command: c.command,
          restart: c.restart,
          hostName: c.hostName,
          uid: c.uid,
          gid: c.gid,
          disable: c.disable,
          allowHostNetworks: c.allowHostNetworks,
          allowHostPid: c.allowHostPid,
          capabilities: c.capabilities,
          devices: c.devices,
          environment: c.environment,
          volumes: c.volumes,
          networks: c.networks,
          ports: c.ports,
          raw: c.raw,
          retrievedAt: new Date().toISOString(),
        },
      );
      context.logger.info(
        "container {name}: exists={exists}, {n} volume(s), {m} env var(s)",
        {
          name: args.name,
          exists: node !== undefined,
          n: c.volumes.length,
          m: c.environment.length,
        },
      );
      return { dataHandles: [handle] };
    },
  },
  ensureContainer: {
    description:
      "Declaratively set one container's whole config (reconciles to exactly the desired state; result is vaulted). " +
      "CAVEAT: committing regenerates the container's systemd unit and can pull the image / restart the " +
      "container - slow and disruptive; this may take a while to return.",
    arguments: z.object({
      name: z.string().describe("Container name, e.g. metrics-agent"),
      image: z.string().describe("Container image reference"),
      command: z.string().optional(),
      restart: z.enum(["no", "on-failure", "always"]).optional(),
      hostName: z.string().optional(),
      uid: z.number().int().optional(),
      gid: z.number().int().optional(),
      disable: z.boolean().optional(),
      allowHostNetworks: z.boolean().optional(),
      allowHostPid: z.boolean().optional(),
      capabilities: z.array(z.string()).default([]),
      devices: z.array(CDeviceSchema).default([]),
      environment: z.array(CEnvSchema).default([]),
      volumes: z.array(CVolumeSchema).default([]),
      networks: z.array(CNetworkSchema).default([]),
      ports: z.array(CPortSchema).default([]),
      raw: z.array(z.string()).default([]).describe(
        "Extra leaf fragments appended under the container path",
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
        & ContainerDesired
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
      const sets = containerSetPaths(args.name, args);
      // Reconcile: wipe the whole container subtree, then set desired -> the
      // container ends up as exactly `sets`. Net-zero change is a no-op.
      const deletes = [`container name ${args.name}`];
      validateApplyPaths(sets, deletes);
      const script = buildConfigScript({
        sets,
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Ensuring container {name} on {host} ({n} path(s), dryRun={dryRun})",
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
      // The set paths + compare diff carry image/command/volumes/environment
      // (which may include secrets), so the whole result is vaulted
      // (sensitiveApplyResult), matching the wireguard pattern.
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
          "ensureContainer failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `ensureContainer failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "ensureContainer {name} complete (changed={changed}, committed={committed})",
        { name: args.name, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
  removeContainer: {
    description:
      "Delete a container's config (its whole subtree; result vaulted). " +
      "CAVEAT: committing regenerates/removes the systemd unit and stops the container - " +
      "this may take a while to return.",
    arguments: z.object({
      name: z.string().describe("Container name, e.g. metrics-agent"),
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
      const deletes = [`container name ${args.name}`];
      validateApplyPaths([], deletes);
      const script = buildConfigScript({
        sets: [],
        deletes,
        commit: args.commit,
        save: args.save,
        dryRun: args.dryRun,
      });
      context.logger.info(
        "Removing container {name} on {host} (dryRun={dryRun})",
        { name: args.name, host: cfg.host, dryRun: args.dryRun },
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
          "removeContainer failed on {host} (exit {code})",
          { host: cfg.host, code: result.code },
        );
        throw new Error(
          `removeContainer failed on ${cfg.host} (exit ${result.code}): ${result.stderr}`,
        );
      }
      context.logger.info(
        "removeContainer {name} complete (changed={changed}, committed={committed})",
        { name: args.name, changed, committed },
      );
      return { dataHandles: [handle] };
    },
  },
};

/** Methods that require the reachable pre-flight check. */
export const containerCheckMethods = ["ensureContainer", "removeContainer"];

/**
 * Unit tests for the @shrug/vyos container family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { containerSetPaths, parseContainer } from "./container.ts";

// deno-lint-ignore no-explicit-any
const syncContainerExec = (model.methods.syncContainer.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureContainerExec = (model.methods.ensureContainer.execute) as any;
// deno-lint-ignore no-explicit-any
const removeContainerExec = (model.methods.removeContainer.execute) as any;

Deno.test("containerSetPaths translates the alloy shape (no secrets)", () => {
  const paths = containerSetPaths("alloy", {
    image: "docker.io/grafana/alloy:v1.17.1",
    command: "run --storage.path=/var/lib/alloy ... /etc/alloy/config.alloy",
    restart: "on-failure",
    allowHostNetworks: true,
    volumes: [
      {
        name: "cfg",
        source: "/config/alloy/config.alloy",
        destination: "/etc/alloy/config.alloy",
        mode: "ro",
      },
      {
        name: "data",
        source: "/config/alloy/data",
        destination: "/var/lib/alloy",
      },
      {
        name: "jrnl",
        source: "/var/log/journal",
        destination: "/var/log/journal",
        mode: "ro",
      },
    ],
  });
  assertEquals(paths, [
    "container name alloy image docker.io/grafana/alloy:v1.17.1",
    "container name alloy command 'run --storage.path=/var/lib/alloy ... /etc/alloy/config.alloy'",
    "container name alloy restart on-failure",
    "container name alloy allow-host-networks",
    "container name alloy volume cfg source /config/alloy/config.alloy",
    "container name alloy volume cfg destination /etc/alloy/config.alloy",
    "container name alloy volume cfg mode ro",
    "container name alloy volume data source /config/alloy/data",
    "container name alloy volume data destination /var/lib/alloy",
    "container name alloy volume jrnl source /var/log/journal",
    "container name alloy volume jrnl destination /var/log/journal",
    "container name alloy volume jrnl mode ro",
  ]);
});

Deno.test("containerSetPaths covers capability/device/environment/network/port/uid/gid/disable/allow-host-pid", () => {
  const paths = containerSetPaths("tailscale", {
    image: "docker.io/tailscale/tailscale:stable",
    restart: "always",
    hostName: "router.example.com",
    uid: 0,
    gid: 0,
    disable: true,
    allowHostPid: true,
    capabilities: ["net-admin", "sys-module"],
    devices: [{
      name: "tun",
      source: "/dev/net/tun",
      destination: "/dev/net/tun",
    }],
    environment: [{ name: "TS_AUTH_KEY", value: "tskey-abc123" }],
    networks: [{ name: "n0", address: "192.0.2.5/24" }, { name: "n1" }],
    ports: [{
      name: "p0",
      source: "8080",
      destination: "80",
      protocol: "tcp",
    }],
  });
  assertEquals(paths, [
    "container name tailscale image docker.io/tailscale/tailscale:stable",
    "container name tailscale restart always",
    "container name tailscale host-name router.example.com",
    "container name tailscale uid 0",
    "container name tailscale gid 0",
    "container name tailscale disable",
    "container name tailscale allow-host-pid",
    "container name tailscale capability net-admin",
    "container name tailscale capability sys-module",
    "container name tailscale device tun source /dev/net/tun",
    "container name tailscale device tun destination /dev/net/tun",
    "container name tailscale environment TS_AUTH_KEY value tskey-abc123",
    "container name tailscale network n0 address 192.0.2.5/24",
    "container name tailscale network n1",
    "container name tailscale port p0 source 8080",
    "container name tailscale port p0 destination 80",
    "container name tailscale port p0 protocol tcp",
  ]);
});

Deno.test("containerSetPaths quotes a spaced environment value and emits raw fragments", () => {
  const paths = containerSetPaths("x", {
    image: "img",
    environment: [{ name: "NOTE", value: "hello world" }],
    raw: ["memory 512", "cpu-quota 50"],
  });
  assertEquals(paths, [
    "container name x image img",
    "container name x environment NOTE value 'hello world'",
    "container name x memory 512",
    "container name x cpu-quota 50",
  ]);
});

Deno.test("parseContainer reads the live alloy JSON shape", () => {
  const parsed = parseContainer({
    "allow-host-networks": {},
    "command": "run --storage.path=/var/lib/alloy ... /etc/alloy/config.alloy",
    "image": "docker.io/grafana/alloy:v1.17.1",
    "restart": "on-failure",
    "volume": {
      "cfg": {
        "destination": "/etc/alloy/config.alloy",
        "mode": "ro",
        "source": "/config/alloy/config.alloy",
      },
      "data": {
        "destination": "/var/lib/alloy",
        "source": "/config/alloy/data",
      },
      "jrnl": {
        "destination": "/var/log/journal",
        "mode": "ro",
        "source": "/var/log/journal",
      },
    },
  });
  assertEquals(parsed.image, "docker.io/grafana/alloy:v1.17.1");
  assertEquals(parsed.restart, "on-failure");
  assertEquals(parsed.allowHostNetworks, true);
  assertEquals(parsed.allowHostPid, undefined);
  assertEquals(parsed.volumes.length, 3);
  const cfg = parsed.volumes.find((v) => v.name === "cfg");
  assertEquals(cfg?.mode, "ro");
  const data = parsed.volumes.find((v) => v.name === "data");
  assertEquals(data?.mode, undefined);
  assertEquals(parsed.capabilities, []);
  assertEquals(parsed.environment, []);
});

Deno.test("parseContainer reads the live tailscale JSON shape (capability array + object-keyed leaves)", () => {
  const parsed = parseContainer({
    "allow-host-pid": {},
    "capability": ["net-admin", "sys-module"],
    "device": {
      "tun": { "source": "/dev/net/tun", "destination": "/dev/net/tun" },
    },
    "disable": {},
    "environment": {
      "TS_AUTH_KEY": { "value": "tskey-secret" },
    },
    "gid": "0",
    "host-name": "router.example.com",
    "image": "docker.io/tailscale/tailscale:stable",
    "restart": "always",
    "uid": "0",
  });
  assertEquals(parsed.allowHostPid, true);
  assertEquals(parsed.disable, true);
  assertEquals(parsed.uid, 0);
  assertEquals(parsed.gid, 0);
  assertEquals(parsed.hostName, "router.example.com");
  assertEquals(parsed.capabilities, ["net-admin", "sys-module"]);
  assertEquals(parsed.devices, [
    { name: "tun", source: "/dev/net/tun", destination: "/dev/net/tun" },
  ]);
  assertEquals(parsed.environment, [
    { name: "TS_AUTH_KEY", value: "tskey-secret" },
  ]);
});

Deno.test("parseContainer normalizes a single object-keyed capability", () => {
  const parsed = parseContainer({
    "image": "img",
    "capability": { "net-admin": null },
  });
  assertEquals(parsed.capabilities, ["net-admin"]);
});

Deno.test("syncContainer writes the vaulted container resource", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncContainerExec(
    {
      name: "alloy",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          container: {
            name: {
              alloy: {
                "allow-host-networks": {},
                "image": "docker.io/grafana/alloy:v1.17.1",
                "restart": "on-failure",
                "volume": {
                  "data": {
                    "destination": "/var/lib/alloy",
                    "source": "/config/alloy/data",
                  },
                },
              },
            },
          },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "container");
  assertEquals(writes[0].name, "alloy");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.image, "docker.io/grafana/alloy:v1.17.1");
  assertEquals(
    (writes[0].data.volumes as Array<{ name: string }>)[0].name,
    "data",
  );
});

Deno.test("syncContainer reports exists=false for a missing container", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncContainerExec(
    {
      name: "missing",
      _ssh: stubSsh({ stdout: JSON.stringify({}) }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.image, "");
});

Deno.test("syncContainer fails on nonzero exit", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      syncContainerExec(
        {
          name: "alloy",
          _ssh: stubSsh({ code: 1, stderr: "no route to host" }, []),
        },
        context,
      ),
    Error,
    "syncContainer failed",
  );
});

Deno.test("ensureContainer reconciles and vaults the result", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureContainerExec(
    {
      name: "alloy",
      image: "docker.io/grafana/alloy:v1.17.1",
      restart: "on-failure",
      volumes: [{
        name: "data",
        source: "/config/alloy/data",
        destination: "/var/lib/alloy",
      }],
      capabilities: [],
      devices: [],
      environment: [],
      networks: [],
      ports: [],
      raw: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(
    script.includes(
      "if cli-shell-api existsActive container name alloy; then delete container name alloy",
    ),
  );
  assert(
    script.includes(
      "set container name alloy image docker.io/grafana/alloy:v1.17.1",
    ),
  );
  // Container results are vaulted (image/command/volumes/environment may
  // carry secrets).
  assertEquals(writes[0].specName, "sensitiveApplyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
});

Deno.test("ensureContainer surfaces a nonzero-exit failure", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureContainerExec(
        {
          name: "alloy",
          image: "docker.io/grafana/alloy:v1.17.1",
          capabilities: [],
          devices: [],
          environment: [],
          volumes: [],
          networks: [],
          ports: [],
          raw: [],
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "commit failed" }, calls),
        },
        context,
      ),
    Error,
    "ensureContainer failed",
  );
});

Deno.test("removeContainer deletes the container, vaults the result", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeContainerExec(
    {
      name: "alloy",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assert(String(calls[0].stdin).includes("delete container name alloy"));
  assertEquals(writes[0].specName, "sensitiveApplyResult");
  assertEquals(writes[0].data.delete, ["container name alloy"]);
});

Deno.test("removeContainer surfaces a nonzero-exit failure", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      removeContainerExec(
        {
          name: "alloy",
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "locked config" }, []),
        },
        context,
      ),
    Error,
    "removeContainer failed",
  );
});

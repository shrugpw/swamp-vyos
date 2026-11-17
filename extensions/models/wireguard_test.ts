/**
 * Unit tests for the @shrug/vyos WireGuard family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { parseWireguardInterface, wireguardSetPaths } from "./wireguard.ts";

// deno-lint-ignore no-explicit-any
const syncWgExec = (model.methods.syncWireguard.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureWgExec = (model.methods.ensureWireguard.execute) as any;
// deno-lint-ignore no-explicit-any
const removeWgExec = (model.methods.removeWireguard.execute) as any;

Deno.test("wireguardSetPaths translates interface + peer paths", () => {
  const paths = wireguardSetPaths("wg0", {
    privateKey: "PRIV=",
    address: ["2001:db8:e::1/126"],
    port: 51821,
    adjustMss: "clamp-mss-to-pmtu",
    peers: [
      {
        name: "hub",
        publicKey: "PUB=",
        address: "203.0.113.1",
        port: 51820,
        allowedIps: ["::/0"],
        persistentKeepalive: 25,
        presharedKey: "PSK=",
      },
    ],
  });
  assertEquals(paths, [
    "interfaces wireguard wg0 private-key PRIV=",
    "interfaces wireguard wg0 address 2001:db8:e::1/126",
    "interfaces wireguard wg0 port 51821",
    "interfaces wireguard wg0 ipv6 adjust-mss clamp-mss-to-pmtu",
    "interfaces wireguard wg0 peer hub public-key PUB=",
    "interfaces wireguard wg0 peer hub address 203.0.113.1",
    "interfaces wireguard wg0 peer hub port 51820",
    "interfaces wireguard wg0 peer hub allowed-ips ::/0",
    "interfaces wireguard wg0 peer hub persistent-keepalive 25",
    "interfaces wireguard wg0 peer hub preshared-key PSK=",
  ]);
});

Deno.test("wireguardSetPaths quotes a spaced description", () => {
  const paths = wireguardSetPaths("wg0", { description: "uplink to hub" });
  assertEquals(paths, [
    "interfaces wireguard wg0 description 'uplink to hub'",
  ]);
});

Deno.test("parseWireguardInterface reads interface + peers", () => {
  const parsed = parseWireguardInterface({
    "address": ["2001:db8:e::1/126"],
    "port": "51821",
    "private-key": "PRIV=",
    "ipv6": { "adjust-mss": "clamp-mss-to-pmtu" },
    "peer": {
      "hub": {
        "address": "203.0.113.1",
        "port": "51820",
        "public-key": "PUB=",
        "allowed-ips": ["::/0"],
        "persistent-keepalive": "25",
      },
    },
  });
  assertEquals(parsed.privateKey, "PRIV=");
  assertEquals(parsed.address, ["2001:db8:e::1/126"]);
  assertEquals(parsed.adjustMss, "clamp-mss-to-pmtu");
  assertEquals(parsed.peers.length, 1);
  assertEquals(parsed.peers[0].name, "hub");
  assertEquals(parsed.peers[0].publicKey, "PUB=");
  assertEquals(parsed.peers[0].allowedIps, ["::/0"]);
});

Deno.test("syncWireguard writes the vaulted wireguard resource per interface", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncWgExec(
    {
      interface: "wg0",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          interfaces: {
            wireguard: {
              wg0: {
                "private-key": "PRIV=",
                "port": "51821",
                "peer": { "hub": { "public-key": "PUB=" } },
              },
            },
          },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "wireguard");
  assertEquals(writes[0].name, "wg0");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.privateKey, "PRIV=");
  assertEquals(
    (writes[0].data.peers as Array<{ name: string }>)[0].name,
    "hub",
  );
});

Deno.test("ensureWireguard reconciles and vaults the result", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureWgExec(
    {
      interface: "wg0",
      privateKey: "PRIV=",
      address: ["2001:db8:e::1/126"],
      port: 51821,
      peers: [{ name: "hub", publicKey: "PUB=", allowedIps: ["::/0"] }],
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
      "if cli-shell-api existsActive interfaces wireguard wg0; then delete interfaces wireguard wg0",
    ),
  );
  assert(script.includes("set interfaces wireguard wg0 private-key PRIV="));
  // WireGuard results are vaulted
  assertEquals(writes[0].specName, "sensitiveApplyResult");
});

Deno.test("ensureWireguard sources the private-key from the wireguardKeys globalArg", async () => {
  const calls: SshCall[] = [];
  // Simulate the engine having resolved `${{ vault.get(...) }}` into the
  // per-interface keyring on globalArgs. The method is called with NO explicit
  // privateKey argument (a vault-backed key can only arrive this way).
  const { context, writes } = fakeContext("192.0.2.1", {
    wireguardKeys: { "wg-bos": "RINGKEY=" },
  });
  await ensureWgExec(
    {
      interface: "wg-bos",
      address: ["2001:db8:e::24/126"],
      peers: [{ name: "hub", publicKey: "PUB=", allowedIps: ["::/0"] }],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(
    script.includes("set interfaces wireguard wg-bos private-key RINGKEY="),
    "keyring private-key should be set on the interface",
  );
  assertEquals(writes[0].specName, "sensitiveApplyResult");
});

Deno.test("ensureWireguard: explicit privateKey argument overrides the keyring", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext("192.0.2.1", {
    wireguardKeys: { "wg-bos": "RINGKEY=" },
  });
  await ensureWgExec(
    {
      interface: "wg-bos",
      privateKey: "ARGKEY=",
      address: ["2001:db8:e::24/126"],
      peers: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(
    script.includes("set interfaces wireguard wg-bos private-key ARGKEY="),
    "explicit argument should win over the keyring",
  );
  assert(
    !script.includes("RINGKEY="),
    "keyring value must not leak when an explicit key is given",
  );
});

Deno.test("ensureWireguard requires at least one field", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureWgExec({
        interface: "wg0",
        address: [],
        peers: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("removeWireguard deletes the interface, vaults the result", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeWgExec(
    {
      interface: "wg0",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assert(String(calls[0].stdin).includes("delete interfaces wireguard wg0"));
  assertEquals(writes[0].specName, "sensitiveApplyResult");
  assertEquals(writes[0].data.delete, ["interfaces wireguard wg0"]);
});

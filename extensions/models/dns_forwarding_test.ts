/**
 * Unit tests for the @shrug/vyos dnsForwarding family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { dnsForwardingSetPaths, parseDnsForwarding } from "./dns_forwarding.ts";

// deno-lint-ignore no-explicit-any
const syncDnsExec = (model.methods.syncDnsForwarding.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureDnsExec = (model.methods.ensureDnsForwarding.execute) as any;
// deno-lint-ignore no-explicit-any
const removeDnsExec = (model.methods.removeDnsForwarding.execute) as any;

// Live shape from the grounding pull (service dns forwarding, 22 set-lines),
// using the object-of-empty-keys rendering for name-server.
const LIVE_NODE = {
  "allow-from": [
    "192.0.2.0/24",
    "10.0.0.0/8",
    "172.16.0.0/12",
    "192.168.0.0/16",
  ],
  "cache-size": "0",
  "dhcp": ["eth0"],
  "dns64-prefix": "64:ff9b::/96",
  "domain": {
    "example.com": {
      "name-server": { "203.0.113.53": {} },
      "recursion-desired": {},
    },
  },
  "listen-address": [
    "192.0.2.1",
    "203.0.113.1",
    "2001:db8::53",
    "fd64::64",
  ],
  "name-server": {
    "203.0.113.53": {},
    "2606:4700:4700::1001": {},
    "2606:4700:4700::1111": {},
  },
};

Deno.test("dnsForwardingSetPaths emits allow-from/listen-address/dhcp/name-server leaves", () => {
  const paths = dnsForwardingSetPaths({
    allowFrom: ["10.0.0.0/8"],
    listenAddress: ["192.0.2.1", "2001:db8::53"],
    nameServer: ["203.0.113.53", "2606:4700:4700::1001"],
    dhcp: ["eth0"],
    cacheSize: 0,
    dns64Prefix: "64:ff9b::/96",
  });
  assert(paths.includes("service dns forwarding allow-from 10.0.0.0/8"));
  assert(paths.includes("service dns forwarding listen-address 192.0.2.1"));
  assert(paths.includes("service dns forwarding listen-address 2001:db8::53"));
  assert(paths.includes("service dns forwarding dhcp eth0"));
  assert(paths.includes("service dns forwarding cache-size 0"));
  assert(paths.includes("service dns forwarding dns64-prefix 64:ff9b::/96"));
  assert(
    paths.includes("service dns forwarding name-server 203.0.113.53"),
  );
  assert(
    paths.includes(
      "service dns forwarding name-server 2606:4700:4700::1001",
    ),
  );
});

Deno.test("dnsForwardingSetPaths emits system leaf only when true", () => {
  assert(
    dnsForwardingSetPaths({ system: true }).includes(
      "service dns forwarding system",
    ),
  );
  assertEquals(dnsForwardingSetPaths({ system: false }), []);
  assertEquals(dnsForwardingSetPaths({}), []);
});

Deno.test("dnsForwardingSetPaths emits domain container + name-server + valueless leaves", () => {
  const paths = dnsForwardingSetPaths({
    domains: [
      {
        name: "example.com",
        nameServers: ["203.0.113.53"],
        recursionDesired: true,
      },
      { name: "example.com", addNta: true, raw: ["forward-only"] },
    ],
  });
  assert(paths.includes("service dns forwarding domain example.com"));
  assert(
    paths.includes(
      "service dns forwarding domain example.com name-server 203.0.113.53",
    ),
  );
  assert(
    paths.includes(
      "service dns forwarding domain example.com recursion-desired",
    ),
  );
  assert(paths.includes("service dns forwarding domain example.com"));
  assert(paths.includes("service dns forwarding domain example.com addnta"));
  assert(
    paths.includes("service dns forwarding domain example.com forward-only"),
  );
});

Deno.test("dnsForwardingSetPaths appends top-level raw fragments", () => {
  const paths = dnsForwardingSetPaths({ raw: ["some-unmodeled-leaf value"] });
  assert(paths.includes("service dns forwarding some-unmodeled-leaf value"));
});

Deno.test("dnsForwardingSetPaths round-trips the live object-form name-servers to identical set-lines", () => {
  // Parse the live (object-form) node, then feed the parsed state straight
  // back through setPaths -- this is the shape the design doc's live proof
  // ("sync current -> ensure --dryRun = NOCHANGE") depends on.
  const parsed = parseDnsForwarding(LIVE_NODE);
  const paths = new Set(dnsForwardingSetPaths(parsed));
  assert(paths.has("service dns forwarding allow-from 192.0.2.0/24"));
  assert(paths.has("service dns forwarding allow-from 10.0.0.0/8"));
  assert(paths.has("service dns forwarding allow-from 172.16.0.0/12"));
  assert(paths.has("service dns forwarding allow-from 192.168.0.0/16"));
  assert(paths.has("service dns forwarding cache-size 0"));
  assert(paths.has("service dns forwarding dhcp eth0"));
  assert(paths.has("service dns forwarding dns64-prefix 64:ff9b::/96"));
  assert(paths.has("service dns forwarding domain example.com"));
  assert(
    paths.has(
      "service dns forwarding domain example.com name-server 203.0.113.53",
    ),
  );
  assert(
    paths.has("service dns forwarding domain example.com recursion-desired"),
  );
  assert(paths.has("service dns forwarding listen-address 192.0.2.1"));
  assert(paths.has("service dns forwarding listen-address 203.0.113.1"));
  assert(paths.has("service dns forwarding listen-address 2001:db8::53"));
  assert(paths.has("service dns forwarding listen-address fd64::64"));
  // object-form name-server (top-level) normalized to individual set-lines
  assert(paths.has("service dns forwarding name-server 203.0.113.53"));
  assert(
    paths.has("service dns forwarding name-server 2606:4700:4700::1001"),
  );
  assert(
    paths.has("service dns forwarding name-server 2606:4700:4700::1111"),
  );
  // exact count -> nothing spurious/missing (4 allow-from + 1 cache-size + 1
  // dhcp + 1 dns64-prefix + 1 domain container + 1 domain name-server + 1
  // recursion-desired + 4 listen-address + 3 name-server = 17)
  assertEquals(paths.size, 17);
});

Deno.test("parseDnsForwarding normalizes both array-form and object-form multi-value leaves", () => {
  const arrayForm = parseDnsForwarding({
    "allow-from": ["10.0.0.0/8"],
    "listen-address": ["192.0.2.1"],
    "dhcp": ["eth0"],
    "name-server": ["192.0.2.53"],
  });
  assertEquals(arrayForm.allowFrom, ["10.0.0.0/8"]);
  assertEquals(arrayForm.listenAddress, ["192.0.2.1"]);
  assertEquals(arrayForm.dhcp, ["eth0"]);
  assertEquals(arrayForm.nameServer, ["192.0.2.53"]);

  const objectForm = parseDnsForwarding(LIVE_NODE);
  assertEquals(
    objectForm.nameServer.sort(),
    [
      "203.0.113.53",
      "2606:4700:4700::1001",
      "2606:4700:4700::1111",
    ].sort(),
  );
  assertEquals(objectForm.domains.length, 1);
  assertEquals(objectForm.domains[0].name, "example.com");
  assertEquals(objectForm.domains[0].nameServers, ["203.0.113.53"]);
  assertEquals(objectForm.domains[0].recursionDesired, true);
  assertEquals(objectForm.domains[0].addNta, undefined);
  assertEquals(objectForm.cacheSize, 0);
  assertEquals(objectForm.dns64Prefix, "64:ff9b::/96");
});

Deno.test("parseDnsForwarding detects valueless system leaf and defaults on a missing node", () => {
  const withSystem = parseDnsForwarding({ "system": {} });
  assertEquals(withSystem.system, true);

  const empty = parseDnsForwarding(undefined);
  assertEquals(empty.allowFrom, []);
  assertEquals(empty.listenAddress, []);
  assertEquals(empty.nameServer, []);
  assertEquals(empty.dhcp, []);
  assertEquals(empty.domains, []);
  assertEquals(empty.system, undefined);
  assertEquals(empty.cacheSize, undefined);
  assertEquals(empty.dns64Prefix, undefined);
});

Deno.test("syncDnsForwarding writes the dnsForwarding resource as instance 'current'", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncDnsExec(
    {
      _ssh: stubSsh({
        stdout: JSON.stringify({
          service: { dns: { forwarding: LIVE_NODE } },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "show",
    "configuration",
    "json",
  ]);
  assertEquals(writes[0].specName, "dnsForwarding");
  assertEquals(writes[0].name, "current");
  assertEquals(writes[0].data.exists, true);
  assertEquals(
    (writes[0].data.allowFrom as string[]).length,
    4,
  );
  assertEquals((writes[0].data.domains as unknown[]).length, 1);
  assertEquals(writes[0].data.cacheSize, 0);
});

Deno.test("syncDnsForwarding marks exists=false and empties collections when the subtree is absent", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncDnsExec(
    { _ssh: stubSsh({ stdout: JSON.stringify({ service: {} }) }, calls) },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.allowFrom, []);
  assertEquals(writes[0].data.listenAddress, []);
  assertEquals(writes[0].data.nameServer, []);
  assertEquals(writes[0].data.domains, []);
});

Deno.test("syncDnsForwarding throws on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext();
  await assertRejects(
    () =>
      syncDnsExec(
        { _ssh: stubSsh({ code: 1, stderr: "boom" }, calls) },
        context,
      ),
    Error,
    "syncDnsForwarding failed",
  );
});

Deno.test("ensureDnsForwarding wipes the whole subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureDnsExec(
    {
      listenAddress: ["192.0.2.1"],
      allowFrom: ["10.0.0.0/8"],
      nameServer: ["203.0.113.53"],
      dhcp: ["eth0"],
      domains: [],
      raw: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("existsActive service dns forwarding"));
  assert(script.includes("delete service dns forwarding"));
  assert(script.includes("set service dns forwarding allow-from 10.0.0.0/8"));
  assert(
    script.includes("set service dns forwarding listen-address 192.0.2.1"),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
});

Deno.test("ensureDnsForwarding requires at least one attribute", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureDnsExec({
        listenAddress: [],
        allowFrom: [],
        nameServer: [],
        dhcp: [],
        domains: [],
        raw: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("ensureDnsForwarding dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureDnsExec(
    {
      listenAddress: [],
      allowFrom: [],
      nameServer: [],
      dhcp: [],
      domains: [],
      raw: [],
      system: true,
      commit: true,
      save: true,
      dryRun: true,
      _ssh: stubSsh({ stdout: "some diff\nSWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, false);
});

Deno.test("ensureDnsForwarding writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      ensureDnsExec(
        {
          listenAddress: [],
          allowFrom: [],
          nameServer: [],
          dhcp: [],
          domains: [],
          raw: [],
          system: true,
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "ensureDnsForwarding failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

Deno.test("removeDnsForwarding deletes the whole service subtree", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeDnsExec(
    {
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete service dns forwarding"));
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.set, []);
  assertEquals(writes[0].data.delete, ["service dns forwarding"]);
});

Deno.test("removeDnsForwarding writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      removeDnsExec(
        {
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "removeDnsForwarding failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

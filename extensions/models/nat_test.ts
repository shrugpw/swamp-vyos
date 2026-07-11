/**
 * Unit tests for the @shrug/vyos NAT family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { natSetPaths, parseNatRuleset } from "./nat.ts";

// deno-lint-ignore no-explicit-any
const syncNatExec = (model.methods.syncNat.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureNatExec = (model.methods.ensureNat.execute) as any;
// deno-lint-ignore no-explicit-any
const removeNatExec = (model.methods.removeNat.execute) as any;

Deno.test("natSetPaths emits source-NAT leaves incl masquerade + interface + valueless", () => {
  const paths = natSetPaths("source", {
    rules: [
      {
        num: 10,
        description: "lan egress",
        source: { address: "192.0.2.0/24" },
        outboundInterface: "eth0",
        translation: { address: "masquerade" },
        disable: true,
        log: true,
      },
    ],
  });
  assertEquals(paths, [
    "nat source rule 10 description 'lan egress'",
    "nat source rule 10 source address 192.0.2.0/24",
    "nat source rule 10 outbound-interface name eth0",
    "nat source rule 10 translation address masquerade",
    "nat source rule 10 disable",
    "nat source rule 10 log",
  ]);
});

Deno.test("natSetPaths emits destination-NAT leaves incl translation address+port + exclude", () => {
  const paths = natSetPaths("destination", {
    rules: [
      {
        num: 100,
        protocol: "tcp",
        destination: { address: "198.51.100.10", port: "443" },
        inboundInterface: "eth1",
        translation: { address: "203.0.113.5", port: "8443" },
        exclude: true,
      },
    ],
  });
  assertEquals(paths, [
    "nat destination rule 100 protocol tcp",
    "nat destination rule 100 destination address 198.51.100.10",
    "nat destination rule 100 destination port 443",
    "nat destination rule 100 inbound-interface name eth1",
    "nat destination rule 100 translation address 203.0.113.5",
    "nat destination rule 100 translation port 8443",
    "nat destination rule 100 exclude",
  ]);
});

Deno.test("natSetPaths emits source group leaves (address/network/port-group)", () => {
  const paths = natSetPaths("source", {
    rules: [
      {
        num: 100,
        source: { networkGroup: "example-nets" },
        outboundInterface: "eth0",
        translation: { address: "masquerade" },
      },
    ],
  });
  assertEquals(paths, [
    "nat source rule 100 source group network-group example-nets",
    "nat source rule 100 outbound-interface name eth0",
    "nat source rule 100 translation address masquerade",
  ]);
});

Deno.test("natSetPaths appends raw fragments at rule and direction scope", () => {
  const paths = natSetPaths("source", {
    raw: ["rule 999 log"],
    rules: [{ num: 10, raw: ["source group address-group hosts"] }],
  });
  assert(
    paths.includes("nat source rule 10 source group address-group hosts"),
  );
  assert(paths.includes("nat source rule 999 log"));
});

Deno.test("parseNatRuleset round-trips a direction node, rules numeric-sorted", () => {
  const node = {
    rule: {
      "100": {
        protocol: "tcp",
        destination: { address: "198.51.100.10", port: "443" },
        "inbound-interface": { name: "eth1" },
        translation: { address: "203.0.113.5", port: "8443" },
        log: {},
      },
      "10": {
        source: { address: "192.0.2.0/24" },
        "outbound-interface": { name: "eth0" },
        translation: { address: "masquerade" },
        disable: {},
      },
      "30": {
        protocol: "udp",
        destination: { port: "50000" },
        "inbound-interface": { name: "eth1" },
        translation: { address: "203.0.113.9" },
      },
      "50": {
        source: { group: { "network-group": "example-nets" } },
        "outbound-interface": { name: "eth0" },
        translation: { address: "masquerade" },
      },
    },
  };
  const rs = parseNatRuleset(node);
  // numeric sort: 10, 30, 50, 100 (not lexical)
  assertEquals(rs.rules.map((r) => r.num), [10, 30, 50, 100]);
  assertEquals(rs.rules[0].source, { address: "192.0.2.0/24" });
  // group leaf round-trips (not just address/port)
  assertEquals(rs.rules[2].source, { networkGroup: "example-nets" });
  assertEquals(rs.rules[0].outboundInterface, "eth0");
  assertEquals(rs.rules[0].translation, { address: "masquerade" });
  assertEquals(rs.rules[0].disable, true);
  // rule 100 is now at index 3 (after 10, 30, 50)
  assertEquals(rs.rules[3].destination, {
    address: "198.51.100.10",
    port: "443",
  });
  assertEquals(rs.rules[3].translation, {
    address: "203.0.113.5",
    port: "8443",
  });
  assertEquals(rs.rules[3].inboundInterface, "eth1");
  assertEquals(rs.rules[3].log, true);
});

Deno.test("parseNatRuleset on a missing node yields an empty rule list", () => {
  const rs = parseNatRuleset(undefined);
  assertEquals(rs.rules, []);
});

Deno.test("syncNat writes the natRuleset resource named for the direction", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncNatExec(
    {
      direction: "destination",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          nat: {
            destination: {
              rule: {
                "100": {
                  protocol: "tcp",
                  destination: { port: "443" },
                  translation: { address: "203.0.113.5" },
                },
              },
            },
          },
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
  assertEquals(writes[0].specName, "natRuleset");
  assertEquals(writes[0].name, "destination");
  assertEquals(writes[0].data.direction, "destination");
  assertEquals(writes[0].data.exists, true);
  assertEquals((writes[0].data.rules as unknown[]).length, 1);
});

Deno.test("syncNat marks a missing direction exists=false", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncNatExec(
    {
      direction: "source",
      _ssh: stubSsh({ stdout: JSON.stringify({ nat: {} }) }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.rules, []);
});

Deno.test("ensureNat wipes the direction rule list then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureNatExec(
    {
      direction: "source",
      rules: [
        {
          num: 10,
          source: { address: "192.0.2.0/24" },
          outboundInterface: "eth0",
          translation: { address: "masquerade" },
        },
      ],
      raw: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  // declarative: the whole direction rule list is deleted (guarded) first
  assert(script.includes("existsActive nat source rule"));
  assert(script.includes("delete nat source rule"));
  // then desired is set
  assert(script.includes("set nat source rule 10 source address 192.0.2.0/24"));
  assert(
    script.includes("set nat source rule 10 translation address masquerade"),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
  assertEquals(writes[0].data.delete, ["nat source rule"]);
});

Deno.test("ensureNat requires at least one rule or raw fragment", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureNatExec({
        direction: "source",
        rules: [],
        raw: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("ensureNat dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureNatExec(
    {
      direction: "destination",
      rules: [{ num: 100, translation: { address: "203.0.113.5" } }],
      raw: [],
      commit: true,
      save: true,
      dryRun: true,
      _ssh: stubSsh({ stdout: "some diff\nSWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(!script.includes("\n    commit"));
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, false);
});

Deno.test("removeNat deletes the whole direction rule list", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeNatExec(
    {
      direction: "destination",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete nat destination rule"));
  assert(!script.includes("\nset "));
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.set, []);
  assertEquals(writes[0].data.delete, ["nat destination rule"]);
});

Deno.test("removeNat writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      removeNatExec(
        {
          direction: "source",
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "removeNat failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

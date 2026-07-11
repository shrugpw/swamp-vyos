/**
 * Unit tests for the @shrug/vyos firewall family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { firewallSetPaths, parseFirewallRuleset } from "./firewall.ts";

// deno-lint-ignore no-explicit-any
const syncFwExec = (model.methods.syncFirewall.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureFwExec = (model.methods.ensureFirewall.execute) as any;
// deno-lint-ignore no-explicit-any
const removeFwExec = (model.methods.removeFirewall.execute) as any;

Deno.test("firewallSetPaths emits ruleset + rule leaves in VyOS syntax", () => {
  const paths = firewallSetPaths("ipv4", "GUEST-FWD", {
    defaultAction: "drop",
    description: "example egress policy",
    enableDefaultLog: true,
    rules: [
      { num: 10, action: "accept", state: ["established", "related"] },
      {
        num: 30,
        action: "accept",
        description: "example service",
        protocol: "tcp",
        state: ["new"],
        destination: { address: "192.0.2.199", port: "1883" },
      },
      {
        num: 100,
        action: "drop",
        state: ["new"],
        destination: { networkGroup: "rfc1918" },
        log: true,
      },
      {
        num: 5,
        action: "jump",
        inboundInterface: "eth0",
        jumpTarget: "UPLINK-IN",
      },
    ],
  });
  // ruleset-level
  assert(paths.includes("firewall ipv4 name GUEST-FWD default-action drop"));
  assert(
    paths.includes(
      "firewall ipv4 name GUEST-FWD description 'example egress policy'",
    ),
  );
  assert(paths.includes("firewall ipv4 name GUEST-FWD enable-default-log"));
  // multi-value state -> one leaf each
  assert(
    paths.includes("firewall ipv4 name GUEST-FWD rule 10 state established"),
  );
  assert(paths.includes("firewall ipv4 name GUEST-FWD rule 10 state related"));
  // structured destination match
  assert(
    paths.includes(
      "firewall ipv4 name GUEST-FWD rule 30 destination address 192.0.2.199",
    ),
  );
  assert(
    paths.includes(
      "firewall ipv4 name GUEST-FWD rule 30 destination port 1883",
    ),
  );
  // group match + valueless log
  assert(
    paths.includes(
      "firewall ipv4 name GUEST-FWD rule 100 destination group network-group rfc1918",
    ),
  );
  assert(paths.includes("firewall ipv4 name GUEST-FWD rule 100 log"));
  // jump target + inbound-interface
  assert(
    paths.includes(
      "firewall ipv4 name GUEST-FWD rule 5 inbound-interface name eth0",
    ),
  );
  assert(
    paths.includes("firewall ipv4 name GUEST-FWD rule 5 jump-target UPLINK-IN"),
  );
});

Deno.test("firewallSetPaths appends raw fragments at ruleset and rule scope", () => {
  const paths = firewallSetPaths("ipv6", "WAN6-IN", {
    raw: ["default-log"],
    rules: [{ num: 10, action: "accept", raw: ["tcp flags SYN"] }],
  });
  assert(paths.includes("firewall ipv6 name WAN6-IN default-log"));
  assert(paths.includes("firewall ipv6 name WAN6-IN rule 10 tcp flags SYN"));
});

Deno.test("parseFirewallRuleset round-trips a ruleset node, rules numeric-sorted", () => {
  const node = {
    "default-action": "drop",
    description: "example egress policy",
    "enable-default-log": {},
    rule: {
      "100": {
        action: "drop",
        state: ["new"],
        destination: { group: { "network-group": "rfc1918" } },
        log: {},
      },
      "10": { action: "accept", state: ["established", "related"] },
      "30": {
        action: "accept",
        protocol: "tcp",
        state: ["new"],
        destination: { address: "192.0.2.199", port: "1883" },
      },
    },
  };
  const rs = parseFirewallRuleset(node);
  assertEquals(rs.defaultAction, "drop");
  assertEquals(rs.enableDefaultLog, true);
  // numeric sort: 10, 30, 100 (not lexical 10, 100, 30)
  assertEquals(rs.rules.map((r) => r.num), [10, 30, 100]);
  assertEquals(rs.rules[0].state, ["established", "related"]);
  assertEquals(rs.rules[1].destination, {
    address: "192.0.2.199",
    port: "1883",
  });
  assertEquals(rs.rules[2].destination, { networkGroup: "rfc1918" });
  assertEquals(rs.rules[2].log, true);
});

Deno.test("parseFirewallRuleset on a missing node yields an empty ruleset", () => {
  const rs = parseFirewallRuleset(undefined);
  assertEquals(rs.rules, []);
  assertEquals(rs.enableDefaultLog, false);
  assertEquals(rs.defaultAction, undefined);
});

Deno.test("syncFirewall writes the firewallRuleset resource per family-name", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncFwExec(
    {
      family: "ipv4",
      name: "GUEST-FWD",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          firewall: {
            ipv4: {
              name: {
                "GUEST-FWD": {
                  "default-action": "drop",
                  rule: { "10": { action: "accept", state: ["new"] } },
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
  assertEquals(writes[0].specName, "firewallRuleset");
  assertEquals(writes[0].name, "ipv4-GUEST-FWD");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.family, "ipv4");
  assertEquals(writes[0].data.defaultAction, "drop");
  assertEquals((writes[0].data.rules as unknown[]).length, 1);
});

Deno.test("syncFirewall marks a missing ruleset exists=false", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncFwExec(
    {
      family: "ipv4",
      name: "NOPE",
      _ssh: stubSsh({
        stdout: JSON.stringify({ firewall: { ipv4: { name: {} } } }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.rules, []);
});

Deno.test("ensureFirewall wipes the ruleset subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureFwExec(
    {
      family: "ipv4",
      name: "GUEST-FWD",
      defaultAction: "drop",
      rules: [{ num: 10, action: "accept", state: ["new"] }],
      raw: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  // declarative: the whole named-ruleset subtree is deleted (guarded) first
  assert(
    script.includes("existsActive firewall ipv4 name GUEST-FWD"),
  );
  assert(script.includes("delete firewall ipv4 name GUEST-FWD"));
  // then desired is set
  assert(
    script.includes("set firewall ipv4 name GUEST-FWD default-action drop"),
  );
  assert(
    script.includes("set firewall ipv4 name GUEST-FWD rule 10 action accept"),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
});

Deno.test("ensureFirewall requires at least one rule or attribute", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureFwExec({
        family: "ipv4",
        name: "GUEST-FWD",
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

Deno.test("ensureFirewall dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureFwExec(
    {
      family: "ipv4",
      name: "GUEST-FWD",
      defaultAction: "drop",
      rules: [],
      raw: [],
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

Deno.test("removeFirewall deletes the whole named-ruleset subtree", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeFwExec(
    {
      family: "ipv4",
      name: "GUEST-FWD",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete firewall ipv4 name GUEST-FWD"));
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.set, []);
  assertEquals(writes[0].data.delete, ["firewall ipv4 name GUEST-FWD"]);
});

Deno.test("removeFirewall writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      removeFwExec(
        {
          family: "ipv4",
          name: "GUEST-FWD",
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "removeFirewall failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

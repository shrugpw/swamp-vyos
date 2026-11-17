/**
 * Unit tests for the @shrug/vyos policy-route (PBR) family.
 *
 * NOTE: `pbr.ts` is not yet wired into `vyos.ts` (that wiring is left to the
 * integrator, alongside the other family modules) - so these tests exercise
 * `pbrMethods` directly rather than via `model.methods`, unlike the other
 * `*_test.ts` files in this directory. `firewallSetPaths`-adjacent behavior
 * (structured match blocks, groups) is already covered by `firewall_test.ts`
 * via the shared `firewallMatchSetPaths`; here we focus on PBR-specific
 * leaves (rule `set table|mark|dscp`, family-based path base, `disable`).
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { parsePolicyRoute, pbrMethods, pbrSetPaths } from "./pbr.ts";

// deno-lint-ignore no-explicit-any
const syncPbrExec = (pbrMethods.syncPolicyRoute.execute) as any;
// deno-lint-ignore no-explicit-any
const ensurePbrExec = (pbrMethods.ensurePolicyRoute.execute) as any;
// deno-lint-ignore no-explicit-any
const removePbrExec = (pbrMethods.removePolicyRoute.execute) as any;

Deno.test("pbrSetPaths emits ruleset + rule leaves under `policy route` for ipv4", () => {
  const paths = pbrSetPaths("ipv4", "dns-redirect", {
    interfaces: ["eth1"],
    description: "redirect DNS",
    enableDefaultLog: true,
    rules: [
      {
        number: 1,
        action: "reject",
        destination: { address: "8.8.8.8/32" },
        source: { address: "10.0.0.180/32" },
      },
      {
        number: 3,
        action: "reject",
        destination: { address: "8.8.8.8/32" },
        source: { address: "10.0.0.188/32" },
        protocol: "udp",
        set: { table: 100, mark: 7, dscp: 10 },
        log: true,
      },
    ],
  });
  assert(
    paths.includes("policy route dns-redirect interface eth1"),
  );
  assert(
    paths.includes(
      "policy route dns-redirect description 'redirect DNS'",
    ),
  );
  assert(paths.includes("policy route dns-redirect enable-default-log"));
  // non-contiguous rule numbers preserved verbatim
  assert(paths.includes("policy route dns-redirect rule 1 action reject"));
  assert(
    paths.includes(
      "policy route dns-redirect rule 1 destination address 8.8.8.8/32",
    ),
  );
  assert(
    paths.includes(
      "policy route dns-redirect rule 1 source address 10.0.0.180/32",
    ),
  );
  assert(paths.includes("policy route dns-redirect rule 3 action reject"));
  assert(paths.includes("policy route dns-redirect rule 3 protocol udp"));
  assert(paths.includes("policy route dns-redirect rule 3 set table 100"));
  assert(paths.includes("policy route dns-redirect rule 3 set mark 7"));
  assert(paths.includes("policy route dns-redirect rule 3 set dscp 10"));
  assert(paths.includes("policy route dns-redirect rule 3 log"));
});

Deno.test("pbrSetPaths uses `policy route6` for the ipv6 family and supports table='main'/disable", () => {
  const paths = pbrSetPaths("ipv6", "v6-pbr", {
    rules: [
      {
        number: 10,
        set: { table: "main" },
        disable: true,
      },
    ],
  });
  assert(paths.includes("policy route6 v6-pbr rule 10 set table main"));
  assert(paths.includes("policy route6 v6-pbr rule 10 disable"));
  assert(!paths.some((p) => p.startsWith("policy route v6-pbr")));
});

Deno.test("pbrSetPaths appends raw fragments at ruleset and rule scope", () => {
  const paths = pbrSetPaths("ipv4", "extra", {
    raw: ["default-log"],
    rules: [{ number: 1, raw: ["disable"] }],
  });
  assert(paths.includes("policy route extra default-log"));
  assert(paths.includes("policy route extra rule 1 disable"));
});

Deno.test("pbrSetPaths throws nothing but yields [] for an empty desired state", () => {
  assertEquals(pbrSetPaths("ipv4", "empty", {}), []);
});

Deno.test("parsePolicyRoute round-trips the live dns-redirect shape, rules numeric-sorted", () => {
  const node = {
    "interface": ["eth1"],
    "rule": {
      "3": {
        action: "reject",
        destination: { address: "8.8.8.8/32" },
        source: { address: "10.0.0.188/32" },
      },
      "1": {
        action: "reject",
        destination: { address: "8.8.8.8/32" },
        source: { address: "10.0.0.180/32" },
      },
    },
  };
  const rs = parsePolicyRoute(node);
  assertEquals(rs.interfaces, ["eth1"]);
  // non-contiguous rule numbers (1, 3), numeric-sorted not insertion order
  assertEquals(rs.rules.map((r) => r.number), [1, 3]);
  assertEquals(rs.rules[0].action, "reject");
  assertEquals(rs.rules[0].destination, { address: "8.8.8.8/32" });
  assertEquals(rs.rules[0].source, { address: "10.0.0.180/32" });
  assertEquals(rs.rules[1].source, { address: "10.0.0.188/32" });
});

Deno.test("parsePolicyRoute parses set{table|mark|dscp}, disable, and log leaves", () => {
  const node = {
    rule: {
      "10": {
        action: "drop",
        set: { table: 100, mark: 7, dscp: 10 },
        disable: {},
        log: {},
      },
      "20": {
        set: { table: "main" },
      },
    },
  };
  const rs = parsePolicyRoute(node);
  assertEquals(rs.rules[0].set, { table: 100, mark: 7, dscp: 10 });
  assertEquals(rs.rules[0].disable, true);
  assertEquals(rs.rules[0].log, true);
  assertEquals(rs.rules[1].set, { table: "main" });
});

Deno.test("parsePolicyRoute + pbrSetPaths round-trip a multi-interface ruleset", () => {
  // VyOS renders the multi-value `interface` leaf as a JSON array; both parse
  // and emit must preserve every binding rather than collapsing to a scalar.
  const node = { "interface": ["eth0", "eth1"], "rule": {} };
  assertEquals(parsePolicyRoute(node).interfaces, ["eth0", "eth1"]);
  const paths = pbrSetPaths("ipv4", "foo", { interfaces: ["eth0", "eth1"] });
  assert(paths.includes("policy route foo interface eth0"));
  assert(paths.includes("policy route foo interface eth1"));
});

Deno.test("parsePolicyRoute on a missing node yields an empty ruleset", () => {
  const rs = parsePolicyRoute(undefined);
  assertEquals(rs.rules, []);
  assertEquals(rs.interfaces, []);
  assertEquals(rs.enableDefaultLog, false);
});

Deno.test("syncPolicyRoute writes the policyRoute resource per family-name (live dns-redirect shape)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncPbrExec(
    {
      family: "ipv4",
      name: "dns-redirect",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          policy: {
            route: {
              "dns-redirect": {
                "interface": ["eth1"],
                "rule": {
                  "1": {
                    action: "reject",
                    destination: { address: "8.8.8.8/32" },
                    source: { address: "10.0.0.180/32" },
                  },
                  "3": {
                    action: "reject",
                    destination: { address: "8.8.8.8/32" },
                    source: { address: "10.0.0.188/32" },
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
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "show",
    "configuration",
    "json",
  ]);
  assertEquals(writes[0].specName, "policyRoute");
  assertEquals(writes[0].name, "ipv4-dns-redirect");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.family, "ipv4");
  assertEquals(writes[0].data.interfaces, ["eth1"]);
  assertEquals((writes[0].data.rules as unknown[]).length, 2);
});

Deno.test("syncPolicyRoute reads `policy.route6` for the ipv6 family", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncPbrExec(
    {
      family: "ipv6",
      name: "v6-pbr",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          policy: { route6: { "v6-pbr": { rule: {} } } },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.family, "ipv6");
});

Deno.test("syncPolicyRoute marks a missing ruleset exists=false", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncPbrExec(
    {
      family: "ipv4",
      name: "nope",
      _ssh: stubSsh({
        stdout: JSON.stringify({ policy: { route: {} } }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.rules, []);
});

Deno.test("syncPolicyRoute throws on nonzero exit", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      syncPbrExec(
        {
          family: "ipv4",
          name: "dns-redirect",
          _ssh: stubSsh({ code: 1, stderr: "boom" }, []),
        },
        context,
      ),
    Error,
    "syncPolicyRoute failed",
  );
});

Deno.test("ensurePolicyRoute wipes the ruleset subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensurePbrExec(
    {
      family: "ipv4",
      name: "dns-redirect",
      interfaces: ["eth1"],
      rules: [
        {
          number: 1,
          action: "reject",
          destination: { address: "8.8.8.8/32" },
          source: { address: "10.0.0.180/32" },
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
  assert(
    script.includes("existsActive policy route dns-redirect"),
  );
  assert(script.includes("delete policy route dns-redirect"));
  assert(
    script.includes("set policy route dns-redirect interface eth1"),
  );
  assert(
    script.includes(
      "set policy route dns-redirect rule 1 action reject",
    ),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
});

Deno.test("ensurePolicyRoute uses the `policy route6` base for the ipv6 family", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext();
  await ensurePbrExec(
    {
      family: "ipv6",
      name: "v6-pbr",
      rules: [{ number: 10, action: "drop" }],
      raw: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete policy route6 v6-pbr"));
  assert(script.includes("set policy route6 v6-pbr rule 10 action drop"));
});

Deno.test("ensurePolicyRoute requires at least one rule or attribute", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensurePbrExec({
        family: "ipv4",
        name: "dns-redirect",
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

Deno.test("ensurePolicyRoute dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensurePbrExec(
    {
      family: "ipv4",
      name: "dns-redirect",
      interfaces: ["eth1"],
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

Deno.test("ensurePolicyRoute writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      ensurePbrExec(
        {
          family: "ipv4",
          name: "dns-redirect",
          interfaces: ["eth1"],
          rules: [],
          raw: [],
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "ensurePolicyRoute failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

Deno.test("removePolicyRoute deletes the whole named-ruleset subtree", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removePbrExec(
    {
      family: "ipv4",
      name: "dns-redirect",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete policy route dns-redirect"));
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.set, []);
  assertEquals(writes[0].data.delete, ["policy route dns-redirect"]);
});

Deno.test("removePolicyRoute writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      removePbrExec(
        {
          family: "ipv4",
          name: "dns-redirect",
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "removePolicyRoute failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

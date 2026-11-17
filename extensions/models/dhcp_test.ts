/**
 * Unit tests for the @shrug/vyos dhcp family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import type { SshRunner } from "./core.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import {
  dhcpCheckMethods,
  dhcpMethods,
  dhcpResources,
  dhcpSetPaths,
  parseDhcpSharedNetwork,
  parseStaticMappings,
} from "./dhcp.ts";

// deno-lint-ignore no-explicit-any
const syncExec = (dhcpMethods.syncDhcpSharedNetwork.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureSnnExec = (dhcpMethods.ensureDhcpSharedNetwork.execute) as any;
// deno-lint-ignore no-explicit-any
const removeSnnExec = (dhcpMethods.removeDhcpSharedNetwork.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureMappingsExec = (dhcpMethods.ensureStaticMappings.execute) as any;

// The live NETA shape from the grounding doc, used across several tests.
const netAJson = {
  service: {
    "dhcp-server": {
      "shared-network-name": {
        NETA: {
          option: { "name-server": ["1.1.1.1", "192.0.2.1"] },
          subnet: {
            "198.51.100.0/24": {
              lease: "86400",
              option: { "default-router": "198.51.100.1" },
              range: {
                "0": { start: "198.51.100.20", stop: "198.51.100.200" },
              },
              "static-mapping": {
                hosta: {
                  "ip-address": "198.51.100.15",
                  mac: "02:00:00:00:00:01",
                },
                hostb: {
                  "ip-address": "198.51.100.170",
                  mac: "00:00:00:00:00:0c",
                },
              },
              "subnet-id": "3",
            },
          },
        },
      },
    },
  },
};

Deno.test("dhcpSetPaths always emits the mandatory subnet-id", () => {
  const paths = dhcpSetPaths("NETA", {
    subnets: [{ cidr: "198.51.100.0/24", subnetId: 3 }],
  });
  assert(
    paths.includes(
      "service dhcp-server shared-network-name NETA subnet 198.51.100.0/24 subnet-id 3",
    ),
  );
});

Deno.test("dhcpSetPaths emits SNN-level and subnet-level options, ranges, and static-mappings", () => {
  const paths = dhcpSetPaths("NETA", {
    options: { nameServer: ["1.1.1.1", "192.0.2.1"] },
    subnets: [
      {
        cidr: "198.51.100.0/24",
        subnetId: 3,
        lease: 86400,
        options: { defaultRouter: "198.51.100.1" },
        ranges: [{ n: 0, start: "198.51.100.20", stop: "198.51.100.200" }],
        staticMappings: [
          {
            name: "hosta",
            ipAddress: "198.51.100.15",
            mac: "02:00:00:00:00:01",
          },
        ],
      },
    ],
  });
  const base = "service dhcp-server shared-network-name NETA";
  assert(paths.includes(`${base} option name-server 1.1.1.1`));
  assert(paths.includes(`${base} option name-server 192.0.2.1`));
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 option default-router 198.51.100.1`,
    ),
  );
  assert(paths.includes(`${base} subnet 198.51.100.0/24 lease 86400`));
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 range 0 start 198.51.100.20`,
    ),
  );
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 range 0 stop 198.51.100.200`,
    ),
  );
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 static-mapping hosta ip-address 198.51.100.15`,
    ),
  );
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 static-mapping hosta mac 02:00:00:00:00:01`,
    ),
  );
});

Deno.test("dhcpSetPaths defaults an un-numbered range to index 0, preserves explicit indices", () => {
  const paths = dhcpSetPaths("NETB", {
    subnets: [{
      cidr: "10.0.0.0/24",
      subnetId: 1,
      ranges: [
        { start: "10.0.0.10", stop: "10.0.0.20" },
        { n: 5, start: "10.0.0.100", stop: "10.0.0.110" },
      ],
    }],
  });
  const base =
    "service dhcp-server shared-network-name NETB subnet 10.0.0.0/24";
  assert(paths.includes(`${base} range 0 start 10.0.0.10`));
  assert(paths.includes(`${base} range 5 start 10.0.0.100`));
});

Deno.test("dhcpSetPaths emits authoritative flag and raw fragments at every level", () => {
  const paths = dhcpSetPaths("NETC", {
    authoritative: true,
    raw: ["disable"],
    subnets: [{
      cidr: "10.0.10.0/24",
      subnetId: 2,
      raw: ["domain-name-server"],
      options: { raw: ["bootfile-name foo"] },
      staticMappings: [{
        name: "host1",
        ipAddress: "10.0.10.5",
        mac: "aa:bb:cc:dd:ee:ff",
        raw: ["static-mapping-exclude"],
      }],
    }],
  });
  assert(
    paths.includes(
      "service dhcp-server shared-network-name NETC authoritative",
    ),
  );
  assert(
    paths.includes("service dhcp-server shared-network-name NETC disable"),
  );
  assert(
    paths.includes(
      "service dhcp-server shared-network-name NETC subnet 10.0.10.0/24 domain-name-server",
    ),
  );
  assert(
    paths.includes(
      "service dhcp-server shared-network-name NETC subnet 10.0.10.0/24 option bootfile-name foo",
    ),
  );
  assert(
    paths.includes(
      "service dhcp-server shared-network-name NETC subnet 10.0.10.0/24 static-mapping host1 static-mapping-exclude",
    ),
  );
});

Deno.test("parseDhcpSharedNetwork round-trips the live NETA shape", () => {
  const node = netAJson.service["dhcp-server"]["shared-network-name"].NETA;
  const st = parseDhcpSharedNetwork(node);
  assertEquals(st.authoritative, undefined);
  assertEquals(st.options?.nameServer, ["1.1.1.1", "192.0.2.1"]);
  assertEquals(st.subnets.length, 1);
  const sn = st.subnets[0];
  assertEquals(sn.cidr, "198.51.100.0/24");
  assertEquals(sn.subnetId, 3);
  assertEquals(sn.lease, 86400);
  assertEquals(sn.options?.defaultRouter, "198.51.100.1");
  assertEquals(sn.ranges, [{
    n: 0,
    start: "198.51.100.20",
    stop: "198.51.100.200",
  }]);
  assertEquals(sn.staticMappings?.length, 2);
  assertEquals(sn.staticMappings?.[0], {
    name: "hosta",
    ipAddress: "198.51.100.15",
    mac: "02:00:00:00:00:01",
  });
});

Deno.test("parseDhcpSharedNetwork -> dhcpSetPaths round-trips subnet-id and every modeled leaf", () => {
  const node = netAJson.service["dhcp-server"]["shared-network-name"].NETA;
  const st = parseDhcpSharedNetwork(node);
  const paths = dhcpSetPaths("NETA", st);
  const base = "service dhcp-server shared-network-name NETA";
  assert(paths.includes(`${base} subnet 198.51.100.0/24 subnet-id 3`));
  assert(paths.includes(`${base} option name-server 1.1.1.1`));
  assert(paths.includes(`${base} subnet 198.51.100.0/24 lease 86400`));
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 option default-router 198.51.100.1`,
    ),
  );
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 range 0 start 198.51.100.20`,
    ),
  );
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 static-mapping hosta ip-address 198.51.100.15`,
    ),
  );
  assert(
    paths.includes(
      `${base} subnet 198.51.100.0/24 static-mapping hostb mac 00:00:00:00:00:0c`,
    ),
  );
});

Deno.test("parseDhcpSharedNetwork normalizes object-keyed multi-value option leaves (name-server / domain-search)", () => {
  // VyOS `show configuration json` renders some multi-value leaves as an
  // object keyed by value ({ "8.8.8.8": {} }) rather than an array. The parse
  // path must normalize both shapes identically - otherwise the object form
  // collapses to ["[object Object]"]. Regression test for the asArr fix.
  const objectFormNode = {
    option: { "name-server": { "8.8.8.8": {}, "1.1.1.1": {} } },
    subnet: {
      "198.51.100.0/24": {
        "subnet-id": "7",
        option: { "domain-search": { "example.com": {}, "corp.example": {} } },
      },
    },
  };
  const st = parseDhcpSharedNetwork(objectFormNode);
  assertEquals(st.options?.nameServer, ["8.8.8.8", "1.1.1.1"]);
  assertEquals(st.subnets.length, 1);
  assertEquals(st.subnets[0].options?.domainSearch, [
    "example.com",
    "corp.example",
  ]);
});

Deno.test("syncDhcpSharedNetwork normalizes object-keyed name-server into a nameServer array", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncExec(
    {
      name: "NETA",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          service: {
            "dhcp-server": {
              "shared-network-name": {
                NETA: {
                  option: {
                    "name-server": { "8.8.8.8": {}, "1.1.1.1": {} },
                  },
                  subnet: {
                    "198.51.100.0/24": { "subnet-id": "3" },
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
  assertEquals(
    (writes[0].data.options as { nameServer: string[] }).nameServer,
    ["8.8.8.8", "1.1.1.1"],
  );
});

Deno.test("parseDhcpSharedNetwork on a missing node yields an empty shared-network", () => {
  const st = parseDhcpSharedNetwork(undefined);
  assertEquals(st.subnets, []);
  assertEquals(st.authoritative, undefined);
  assertEquals(st.options, undefined);
});

Deno.test("parseStaticMappings parses and sorts static-mapping children by name", () => {
  const subnetNode =
    netAJson.service["dhcp-server"]["shared-network-name"].NETA.subnet[
      "198.51.100.0/24"
    ];
  const mappings = parseStaticMappings(subnetNode);
  assertEquals(mappings.map((m) => m.name), ["hosta", "hostb"]);
  assertEquals(mappings[0].ipAddress, "198.51.100.15");
  assertEquals(mappings[1].mac, "00:00:00:00:00:0c");
});

Deno.test("parseStaticMappings on a subnet with none yields an empty array", () => {
  assertEquals(parseStaticMappings(undefined), []);
  assertEquals(parseStaticMappings({}), []);
});

Deno.test("dhcpResources exposes the dhcpSharedNetwork spec", () => {
  assert("dhcpSharedNetwork" in dhcpResources);
});

Deno.test("dhcpCheckMethods lists all ensure*/remove* methods", () => {
  assertEquals(dhcpCheckMethods, [
    "ensureDhcpSharedNetwork",
    "removeDhcpSharedNetwork",
    "ensureStaticMappings",
  ]);
});

Deno.test("syncDhcpSharedNetwork writes the dhcpSharedNetwork resource for NETA", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncExec(
    {
      name: "NETA",
      _ssh: stubSsh({ stdout: JSON.stringify(netAJson) }, calls),
    },
    context,
  );
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "show",
    "configuration",
    "json",
  ]);
  assertEquals(writes[0].specName, "dhcpSharedNetwork");
  assertEquals(writes[0].name, "NETA");
  assertEquals(writes[0].data.exists, true);
  assertEquals((writes[0].data.subnets as unknown[]).length, 1);
});

Deno.test("syncDhcpSharedNetwork marks a missing shared-network exists=false", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncExec(
    {
      name: "NOPE",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          service: { "dhcp-server": { "shared-network-name": {} } },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.subnets, []);
});

Deno.test("syncDhcpSharedNetwork throws on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext();
  await assertRejects(
    () =>
      syncExec(
        {
          name: "NETA",
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "syncDhcpSharedNetwork failed",
  );
});

Deno.test("ensureDhcpSharedNetwork wipes the SNN subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureSnnExec(
    {
      name: "NETA",
      subnets: [{
        cidr: "198.51.100.0/24",
        subnetId: 3,
        ranges: [{ n: 0, start: "198.51.100.20", stop: "198.51.100.200" }],
      }],
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
      "existsActive service dhcp-server shared-network-name NETA",
    ),
  );
  assert(
    script.includes("delete service dhcp-server shared-network-name NETA"),
  );
  assert(
    script.includes(
      "set service dhcp-server shared-network-name NETA subnet 198.51.100.0/24 subnet-id 3",
    ),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
});

Deno.test("ensureDhcpSharedNetwork requires at least one subnet or attribute", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureSnnExec({
        name: "NETA",
        subnets: [],
        raw: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("ensureDhcpSharedNetwork dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureSnnExec(
    {
      name: "NETA",
      authoritative: true,
      subnets: [],
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

Deno.test("ensureDhcpSharedNetwork writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      ensureSnnExec(
        {
          name: "NETA",
          subnets: [{
            cidr: "198.51.100.0/24",
            subnetId: 3,
            ranges: [{ n: 0, start: "198.51.100.20", stop: "198.51.100.200" }],
          }],
          raw: [],
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "ensureDhcpSharedNetwork failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

Deno.test("removeDhcpSharedNetwork deletes the whole shared-network subtree", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeSnnExec(
    {
      name: "NETA",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(
    script.includes("delete service dhcp-server shared-network-name NETA"),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.set, []);
  assertEquals(writes[0].data.delete, [
    "service dhcp-server shared-network-name NETA",
  ]);
});

Deno.test("removeDhcpSharedNetwork writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      removeSnnExec(
        {
          name: "NETA",
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "removeDhcpSharedNetwork failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

Deno.test("ensureStaticMappings reads current, deletes stale, sets desired - never touches ranges/options/subnet-id", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  const ssh: SshRunner = (_cfg, opts) => {
    calls.push({ command: opts.command, stdin: opts.stdin });
    if (opts.stdin !== undefined) {
      return Promise.resolve({
        stdout: "SWAMP_APPLY_CHANGED\n",
        stderr: "",
        code: 0,
      });
    }
    return Promise.resolve({
      stdout: JSON.stringify(netAJson),
      stderr: "",
      code: 0,
    });
  };
  await ensureMappingsExec(
    {
      sharedNetwork: "NETA",
      subnet: "198.51.100.0/24",
      mappings: [
        // keep hosta, drop hostb, add a new host
        { name: "hosta", ipAddress: "198.51.100.15", mac: "02:00:00:00:00:01" },
        {
          name: "newhost",
          ipAddress: "198.51.100.50",
          mac: "11:22:33:44:55:66",
        },
      ],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: ssh,
    },
    context,
  );
  const script = String(calls[1].stdin);
  const base =
    "service dhcp-server shared-network-name NETA subnet 198.51.100.0/24";
  // stale mapping removed (guarded)
  assert(
    script.includes(`existsActive ${base} static-mapping hostb`),
  );
  assert(script.includes(`delete ${base} static-mapping hostb`));
  // kept + new mapping set
  assert(
    script.includes(
      `set ${base} static-mapping hosta ip-address 198.51.100.15`,
    ),
  );
  assert(
    script.includes(
      `set ${base} static-mapping newhost ip-address 198.51.100.50`,
    ),
  );
  // scoped: never touches ranges, options, or subnet-id
  assert(!script.includes("range 0"));
  assert(!script.includes("subnet-id"));
  assert(!script.includes("default-router"));
  assertEquals(writes[0].specName, "applyResult");
});

Deno.test("ensureStaticMappings against an absent subnet sets all desired mappings with no deletes", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  const ssh: SshRunner = (_cfg, opts) => {
    calls.push({ command: opts.command, stdin: opts.stdin });
    if (opts.stdin !== undefined) {
      return Promise.resolve({
        stdout: "SWAMP_APPLY_CHANGED\n",
        stderr: "",
        code: 0,
      });
    }
    return Promise.resolve({
      stdout: JSON.stringify({
        service: { "dhcp-server": { "shared-network-name": {} } },
      }),
      stderr: "",
      code: 0,
    });
  };
  await ensureMappingsExec(
    {
      sharedNetwork: "NETD",
      subnet: "198.51.100.0/24",
      mappings: [
        { name: "host1", ipAddress: "198.51.100.5", mac: "aa:aa:aa:aa:aa:aa" },
      ],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: ssh,
    },
    context,
  );
  assertEquals(writes[0].data.delete, []);
  const script = String(calls[1].stdin);
  assert(
    script.includes(
      "set service dhcp-server shared-network-name NETD subnet 198.51.100.0/24 static-mapping host1 ip-address 198.51.100.5",
    ),
  );
});

Deno.test("ensureStaticMappings failing read propagates before any apply attempt", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureMappingsExec(
        {
          sharedNetwork: "NETA",
          subnet: "198.51.100.0/24",
          mappings: [],
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "read config failed",
  );
  assertEquals(calls.length, 1);
});

Deno.test("ensureStaticMappings writes the result BEFORE throwing on a nonzero apply exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  // Read succeeds (empty shared-network), then the vbash apply exits nonzero.
  const ssh: SshRunner = (_cfg, opts) => {
    calls.push({ command: opts.command, stdin: opts.stdin });
    if (opts.stdin !== undefined) {
      return Promise.resolve({ stdout: "", stderr: "commit failed", code: 1 });
    }
    return Promise.resolve({
      stdout: JSON.stringify({
        service: { "dhcp-server": { "shared-network-name": {} } },
      }),
      stderr: "",
      code: 0,
    });
  };
  await assertRejects(
    () =>
      ensureMappingsExec(
        {
          sharedNetwork: "NETD",
          subnet: "198.51.100.0/24",
          mappings: [
            {
              name: "host1",
              ipAddress: "198.51.100.5",
              mac: "aa:aa:aa:aa:aa:aa",
            },
          ],
          commit: true,
          save: true,
          dryRun: false,
          _ssh: ssh,
        },
        context,
      ),
    Error,
    "ensureStaticMappings failed",
  );
  // Both ssh calls (read + apply) ran, and the diagnostic record was written
  // before the throw so the failed apply is inspectable.
  assertEquals(calls.length, 2);
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

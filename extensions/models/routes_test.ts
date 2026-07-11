/**
 * Unit tests for the @shrug/vyos static-route family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import {
  parseStaticRoute,
  staticRouteBasePath,
  staticRouteInstanceName,
  staticRouteSetPaths,
} from "./routes.ts";

// deno-lint-ignore no-explicit-any
const syncRouteExec = (model.methods.syncStaticRoute.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureRouteExec = (model.methods.ensureStaticRoute.execute) as any;
// deno-lint-ignore no-explicit-any
const removeRouteExec = (model.methods.removeStaticRoute.execute) as any;

Deno.test("staticRouteBasePath selects route for IPv4, route6 for IPv6", () => {
  const v4 = staticRouteBasePath("192.0.2.0/24");
  assertEquals(v4.family, "ipv4");
  assertEquals(v4.routeKey, "route");
  assertEquals(v4.base, "protocols static route 192.0.2.0/24");
  const v6 = staticRouteBasePath("2001:db8::/32");
  assertEquals(v6.family, "ipv6");
  assertEquals(v6.routeKey, "route6");
  assertEquals(v6.base, "protocols static route6 2001:db8::/32");
});

Deno.test("staticRouteSetPaths emits IPv4 route leaves (next-hops, blackhole, description, raw)", () => {
  const paths = staticRouteSetPaths("192.0.2.0/24", {
    nextHops: [
      { nextHop: "198.51.100.1", distance: 5, interface: "eth0" },
      { nextHop: "198.51.100.2", disable: true },
    ],
    interfaceRoutes: [{ interface: "eth1", distance: 1 }],
    blackhole: { distance: 254 },
    dhcpInterface: "eth2",
    description: "example static route",
    raw: ["reject"],
  });
  const base = "protocols static route 192.0.2.0/24";
  assertEquals(paths, [
    `${base} next-hop 198.51.100.1`,
    `${base} next-hop 198.51.100.1 distance 5`,
    `${base} next-hop 198.51.100.1 interface eth0`,
    `${base} next-hop 198.51.100.2`,
    `${base} next-hop 198.51.100.2 disable`,
    `${base} interface eth1`,
    `${base} interface eth1 distance 1`,
    `${base} blackhole`,
    `${base} blackhole distance 254`,
    `${base} dhcp-interface eth2`,
    `${base} description 'example static route'`,
    `${base} reject`,
  ]);
});

Deno.test("staticRouteSetPaths routes a ':' prefix to route6 with IPv6 next-hops", () => {
  const paths = staticRouteSetPaths("2001:db8::/32", {
    nextHops: [{ nextHop: "2001:db8::1", distance: 10 }],
  });
  assertEquals(paths, [
    "protocols static route6 2001:db8::/32 next-hop 2001:db8::1",
    "protocols static route6 2001:db8::/32 next-hop 2001:db8::1 distance 10",
  ]);
});

Deno.test("staticRouteInstanceName slugifies the '/' so the data name is path-safe", () => {
  assertEquals(staticRouteInstanceName("192.0.2.0/24"), "192.0.2.0_24");
  assertEquals(staticRouteInstanceName("2001:db8::/32"), "2001:db8::_32");
});

Deno.test("staticRouteSetPaths emits a valueless blackhole for blackhole=true", () => {
  const paths = staticRouteSetPaths("203.0.113.0/24", { blackhole: true });
  assertEquals(paths, ["protocols static route 203.0.113.0/24 blackhole"]);
});

Deno.test("parseStaticRoute round-trips a node (sorted next-hops, blackhole, family)", () => {
  const parsed = parseStaticRoute("192.0.2.0/24", {
    "next-hop": {
      "198.51.100.2": { disable: {} },
      "198.51.100.1": { distance: "5", interface: "eth0" },
    },
    interface: { "eth1": { distance: "1" } },
    blackhole: { distance: "254" },
    "dhcp-interface": "eth2",
    description: "example static route",
  });
  assertEquals(parsed.family, "ipv4");
  // next-hop map -> array sorted by key
  assertEquals(parsed.nextHops, [
    { nextHop: "198.51.100.1", distance: 5, interface: "eth0" },
    { nextHop: "198.51.100.2", disable: true },
  ]);
  assertEquals(parsed.interfaceRoutes, [{ interface: "eth1", distance: 1 }]);
  assertEquals(parsed.blackhole, { distance: 254 });
  assertEquals(parsed.dhcpInterface, "eth2");
  assertEquals(parsed.description, "example static route");
});

Deno.test("parseStaticRoute derives ipv6 family and treats empty blackhole as true", () => {
  const parsed = parseStaticRoute("2001:db8::/32", {
    "next-hop": { "2001:db8::1": {} },
    blackhole: {},
  });
  assertEquals(parsed.family, "ipv6");
  assertEquals(parsed.nextHops, [{ nextHop: "2001:db8::1" }]);
  assertEquals(parsed.blackhole, true);
});

Deno.test("parseStaticRoute on a missing node yields an empty route", () => {
  const parsed = parseStaticRoute("192.0.2.0/24", undefined);
  assertEquals(parsed.nextHops, []);
  assertEquals(parsed.interfaceRoutes, []);
  assertEquals(parsed.blackhole, undefined);
});

Deno.test("syncStaticRoute writes a typed staticRoute resource named for the prefix", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncRouteExec(
    {
      prefix: "192.0.2.0/24",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          protocols: {
            static: {
              route: {
                "192.0.2.0/24": {
                  "next-hop": { "198.51.100.1": {} },
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
  assertEquals(writes[0].specName, "staticRoute");
  // instance name slugified (no '/'), but the prefix field is verbatim
  assertEquals(writes[0].name, "192.0.2.0_24");
  assertEquals(writes[0].data.prefix, "192.0.2.0/24");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.family, "ipv4");
  assertEquals(writes[0].data.nextHops, [{ nextHop: "198.51.100.1" }]);
});

Deno.test("syncStaticRoute reads route6 and derives ipv6 family for a v6 prefix", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncRouteExec(
    {
      prefix: "2001:db8::/32",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          protocols: {
            static: {
              route6: {
                "2001:db8::/32": { "next-hop": { "2001:db8::1": {} } },
              },
            },
          },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.family, "ipv6");
  assertEquals(writes[0].data.nextHops, [{ nextHop: "2001:db8::1" }]);
});

Deno.test("syncStaticRoute reports exists=false for an unconfigured prefix", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncRouteExec(
    {
      prefix: "203.0.113.0/24",
      _ssh: stubSsh({ stdout: '{"protocols":{}}' }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.family, "ipv4");
  assertEquals(writes[0].data.nextHops, []);
});

Deno.test("ensureStaticRoute wipes the prefix subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureRouteExec(
    {
      prefix: "192.0.2.0/24",
      nextHops: [{ nextHop: "198.51.100.1" }],
      interfaceRoutes: [],
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
      "if cli-shell-api existsActive protocols static route 192.0.2.0/24; then delete protocols static route 192.0.2.0/24",
    ),
  );
  assert(
    script.includes(
      "set protocols static route 192.0.2.0/24 next-hop 198.51.100.1",
    ),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
  assertEquals(writes[0].data.delete, ["protocols static route 192.0.2.0/24"]);
});

Deno.test("ensureStaticRoute requires at least one next-hop/interface/blackhole", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureRouteExec({
        prefix: "192.0.2.0/24",
        nextHops: [],
        interfaceRoutes: [],
        raw: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("ensureStaticRoute dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureRouteExec(
    {
      prefix: "192.0.2.0/24",
      nextHops: [{ nextHop: "198.51.100.1" }],
      interfaceRoutes: [],
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

Deno.test("removeStaticRoute deletes the prefix subtree, no sets", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeRouteExec(
    {
      prefix: "192.0.2.0/24",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete protocols static route 192.0.2.0/24"));
  assert(!script.includes("\nset "));
  assertEquals(writes[0].data.set, []);
  assertEquals(writes[0].data.delete, ["protocols static route 192.0.2.0/24"]);
});

Deno.test("removeStaticRoute picks route6 for an IPv6 prefix", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeRouteExec(
    {
      prefix: "2001:db8::/32",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete protocols static route6 2001:db8::/32"));
  assertEquals(writes[0].data.delete, [
    "protocols static route6 2001:db8::/32",
  ]);
});

Deno.test("removeStaticRoute writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      removeRouteExec(
        {
          prefix: "192.0.2.0/24",
          commit: true,
          save: true,
          dryRun: false,
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "removeStaticRoute failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

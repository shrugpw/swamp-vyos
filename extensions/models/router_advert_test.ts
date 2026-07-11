/**
 * Unit tests for the @shrug/vyos router-advert family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import {
  parseRouterAdvertInterface,
  routerAdvertSetPaths,
} from "./router_advert.ts";

// deno-lint-ignore no-explicit-any
const syncRaExec = (model.methods.syncRouterAdvert.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureRaExec = (model.methods.ensureRouterAdvert.execute) as any;
// deno-lint-ignore no-explicit-any
const removeRaExec = (model.methods.removeRouterAdvert.execute) as any;

Deno.test("routerAdvertSetPaths translates prefixes, routes, options", () => {
  const paths = routerAdvertSetPaths("eth1", {
    defaultLifetime: 3600,
    prefixes: [
      {
        prefix: "2001:db8:1::/64",
        validLifetime: 14400,
        autonomousFlag: false,
      },
    ],
    routes: ["::/0"],
    nat64prefixes: ["64:ff9b::/96"],
  });
  assertEquals(paths, [
    "service router-advert interface eth1 default-lifetime 3600",
    "service router-advert interface eth1 prefix 2001:db8:1::/64",
    "service router-advert interface eth1 prefix 2001:db8:1::/64 valid-lifetime 14400",
    "service router-advert interface eth1 prefix 2001:db8:1::/64 no-autonomous-flag",
    "service router-advert interface eth1 route ::/0",
    "service router-advert interface eth1 nat64prefix 64:ff9b::/96",
  ]);
});

Deno.test("parseRouterAdvertInterface reads the json node", () => {
  const parsed = parseRouterAdvertInterface({
    "default-lifetime": "3600",
    "prefix": { "2001:db8:1::/64": {} },
    "route": { "::/0": {} },
    "nat64prefix": { "64:ff9b::/96": {} },
  });
  assertEquals(parsed.defaultLifetime, "3600");
  assertEquals(parsed.prefixes, [{ prefix: "2001:db8:1::/64" }]);
  assertEquals(parsed.routes, ["::/0"]);
  assertEquals(parsed.nat64prefixes, ["64:ff9b::/96"]);
});

Deno.test("syncRouterAdvert writes a typed routerAdvert resource named for the interface", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncRaExec(
    {
      interface: "eth1",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          service: {
            "router-advert": {
              interface: {
                "eth1": {
                  prefix: { "2001:db8:1::/64": {} },
                  route: { "::/0": {} },
                },
              },
            },
          },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "routerAdvert");
  assertEquals(writes[0].name, "eth1");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.prefixes, [{ prefix: "2001:db8:1::/64" }]);
  assertEquals(writes[0].data.routes, ["::/0"]);
});

Deno.test("syncRouterAdvert reports exists=false for an unconfigured interface", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncRaExec(
    {
      interface: "eth9",
      _ssh: stubSsh({ stdout: '{"service":{}}' }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.exists, false);
  assertEquals(writes[0].data.prefixes, []);
});

Deno.test("ensureRouterAdvert wipes the subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureRaExec(
    {
      interface: "eth1",
      prefixes: [{ prefix: "2001:db8:1::/64" }],
      routes: ["::/0"],
      nat64prefixes: [],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  // deletes the whole interface subtree first, then re-sets the desired paths
  assert(
    script.includes(
      "if cli-shell-api existsActive service router-advert interface eth1; then delete service router-advert interface eth1",
    ),
  );
  assert(
    script.includes(
      "set service router-advert interface eth1 prefix 2001:db8:1::/64",
    ),
  );
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
});

Deno.test("ensureRouterAdvert requires at least one prefix/route/nat64prefix", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureRaExec({
        interface: "eth1",
        prefixes: [],
        routes: [],
        nat64prefixes: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("removeRouterAdvert deletes the interface subtree, no sets", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeRaExec(
    {
      interface: "br0",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  const script = String(calls[0].stdin);
  assert(script.includes("delete service router-advert interface br0"));
  assert(!script.includes("\nset "));
  assertEquals(writes[0].data.delete, [
    "service router-advert interface br0",
  ]);
  assertEquals(writes[0].data.set, []);
});

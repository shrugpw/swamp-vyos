/**
 * Assembly tests for the thin @shrug/vyos entry.
 *
 * The per-family behavior is covered by the family `*_test.ts` files; these
 * tests pin the wiring the entry is responsible for: that every family's
 * resources and methods are spread into the model, and that the reachable
 * check's `appliesTo` is composed from each family's CheckMethods list.
 *
 * @module
 */
import { assert, assertEquals } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";

Deno.test("model identity and global arguments are wired", () => {
  assertEquals(model.type, "@shrug/vyos");
  assertEquals(model.version, "2026.07.11.1");
  assert(model.globalArguments, "globalArguments schema present");
});

Deno.test("every family's methods are spread into the model", () => {
  const expected = [
    // raw
    "show",
    "tree",
    "apply",
    "diff",
    "run",
    // router-advert
    "syncRouterAdvert",
    "ensureRouterAdvert",
    "removeRouterAdvert",
    // wireguard
    "syncWireguard",
    "ensureWireguard",
    "removeWireguard",
    // interface
    "syncInterface",
    "ensureInterface",
    // firewall
    "syncFirewall",
    "ensureFirewall",
    "removeFirewall",
    // nat
    "syncNat",
    "ensureNat",
    "removeNat",
    // static routes
    "syncStaticRoute",
    "ensureStaticRoute",
    "removeStaticRoute",
  ];
  const actual = Object.keys(model.methods).sort();
  assertEquals(actual, [...expected].sort());
  assertEquals(actual.length, 22);
});

Deno.test("every family's resource specs are spread into the model", () => {
  const expected = [
    "config",
    "applyResult",
    "sensitiveApplyResult",
    "diff",
    "sensitiveDiff",
    "configTree",
    "sensitiveConfigTree",
    "commandResult",
    "routerAdvert",
    "wireguard",
    "interface",
    "firewallRuleset",
    "natRuleset",
    "staticRoute",
  ];
  assertEquals(Object.keys(model.resources).sort(), [...expected].sort());
});

Deno.test("reachable appliesTo is composed from every family's CheckMethods", () => {
  const check = model.checks.reachable;
  assert(check, "reachable check present");
  // apply/diff (raw) + ensure/remove for every family; sync* are op-mode reads.
  const expected = [
    "apply",
    "diff",
    "ensureRouterAdvert",
    "removeRouterAdvert",
    "ensureWireguard",
    "removeWireguard",
    "ensureInterface",
    "ensureFirewall",
    "removeFirewall",
    "ensureNat",
    "removeNat",
    "ensureStaticRoute",
    "removeStaticRoute",
  ];
  assertEquals(check.appliesTo, expected);
  // Every gated method must exist in the model; no sync* method is gated.
  for (const name of check.appliesTo) {
    assert(name in model.methods, `${name} is a real method`);
    assert(!name.startsWith("sync"), `${name} is not an op-mode read`);
  }
});

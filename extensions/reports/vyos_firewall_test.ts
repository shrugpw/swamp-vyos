/**
 * Unit tests for the @shrug/vyos-firewall report.
 *
 * @module
 */
// deno-lint-ignore-file no-explicit-any -- report context is stubbed in tests
import { assert, assertEquals } from "jsr:@std/assert@1";
import { parseFirewall, report } from "./vyos_firewall.ts";

const CONFIG = [
  "set firewall group network-group rfc1918 network '10.0.0.0/8'",
  "set firewall ipv4 forward filter default-action 'accept'",
  "set firewall ipv4 forward filter rule 20 action 'jump'",
  "set firewall ipv4 forward filter rule 20 inbound-interface name 'eth1'",
  "set firewall ipv4 forward filter rule 20 jump-target 'GUEST-FWD'",
  "set firewall ipv4 name GUEST-FWD default-action 'drop'",
  "set firewall ipv4 name GUEST-FWD rule 5 action 'drop'",
  "set firewall ipv4 name GUEST-FWD rule 5 state 'invalid'",
  "set firewall ipv4 name GUEST-FWD rule 30 action 'accept'",
  "set firewall ipv4 name GUEST-FWD rule 30 protocol 'tcp'",
  "set firewall ipv4 name GUEST-FWD rule 30 destination address '192.0.2.199'",
  "set firewall ipv4 name GUEST-FWD rule 30 destination port '8080'",
  "set firewall ipv4 name GUEST-FWD rule 30 description 'app server'",
  "set firewall ipv4 name WAN-IN default-action 'drop'",
  "set firewall ipv4 name WAN-IN rule 20 action 'return'",
  "set firewall ipv4 name WAN-IN rule 20 protocol 'tcp'",
  "set firewall ipv4 name WAN-IN rule 20 destination port '443'",
].join("\n");

Deno.test("parseFirewall: chains, bindings, groups", () => {
  const { chains, bindings, groups } = parseFirewall(CONFIG);
  assertEquals(groups.get("network-group rfc1918"), ["10.0.0.0/8"]);
  // one interface→ruleset binding, with the interface backfilled
  assertEquals(bindings.length, 1);
  assertEquals(bindings[0].iface, "eth1");
  assertEquals(bindings[0].target, "GUEST-FWD");
  const iot = chains.get("ipv4/GUEST-FWD")!;
  assertEquals(iot.defaultAction, "drop");
  assertEquals(iot.rules.size, 2);
  assertEquals(iot.rules.get(30)!["destination port"], "8080");
});

const run = (commands: string, method = "show") =>
  report.execute({
    modelType: "@shrug/vyos",
    modelId: "m",
    methodName: method,
    executionStatus: "succeeded",
    dataHandles: [{ name: "current", specName: "config", version: 1 }],
    dataRepository: {
      getContent: () =>
        Promise.resolve(
          new TextEncoder().encode(
            JSON.stringify({
              host: "10.0.0.1",
              commands,
              retrievedAt: new Date(0).toISOString(),
            }),
          ),
        ),
    },
  } as any);

Deno.test("report: renders segment map, WAN exposure, ruleset detail", async () => {
  const out = await run(CONFIG);
  assert(out.markdown.includes("VyOS Firewall — 10.0.0.1"));
  assert(out.markdown.includes("Segment map"));
  assert(out.markdown.includes("eth1"));
  assert(out.markdown.includes("GUEST-FWD"));
  assert(out.markdown.includes("WAN exposure"));
  assert(out.markdown.includes("app server"));
  assertEquals((out.json as { status: string }).status, "ok");
});

Deno.test("report: only runs for the show method", async () => {
  const out = await run(CONFIG, "apply");
  assertEquals(out.markdown, "");
});

Deno.test("report: gracefully handles a non-firewall snapshot", async () => {
  const out = await run("set system host-name 'router'");
  assert(out.markdown.includes("No firewall config"));
});

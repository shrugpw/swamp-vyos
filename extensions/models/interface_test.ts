/**
 * Unit tests for the @shrug/vyos interface family.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import type { SshRunner } from "./core.ts";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";
import { interfaceReconcile, parseInterfaceNode } from "./interface.ts";

// deno-lint-ignore no-explicit-any
const syncIfExec = (model.methods.syncInterface.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureIfExec = (model.methods.ensureInterface.execute) as any;

Deno.test("parseInterfaceNode reads address/description/mtu/disable", () => {
  const st = parseInterfaceNode({
    address: ["10.0.0.1/24"],
    description: "x",
    mtu: "1500",
    disable: {},
  });
  assertEquals(st.address, ["10.0.0.1/24"]);
  assertEquals(st.disable, true);
  const empty = parseInterfaceNode(undefined);
  assertEquals(empty.address, []);
  assertEquals(empty.disable, false);
});

Deno.test("interfaceReconcile reconciles addresses + sets scalars, nothing else", () => {
  const { sets, deletes } = interfaceReconcile(
    "bridge",
    "br0",
    { address: ["10.0.0.1/24", "10.0.0.2/24"], disable: false },
    { address: ["10.0.0.1/24"], description: "MGMT", mtu: 1500 },
  );
  assertEquals(deletes, ["interfaces bridge br0 address 10.0.0.2/24"]);
  assert(sets.includes("interfaces bridge br0 address 10.0.0.1/24"));
  assert(sets.includes("interfaces bridge br0 description MGMT"));
  assert(sets.includes("interfaces bridge br0 mtu 1500"));
  // scoped: never emits a bare subtree delete
  assert(!deletes.includes("interfaces bridge br0"));
});

Deno.test("interfaceReconcile clears disable only when it is active", () => {
  assertEquals(
    interfaceReconcile("ethernet", "eth0", { address: [], disable: true }, {
      disable: false,
    }).deletes,
    ["interfaces ethernet eth0 disable"],
  );
  assertEquals(
    interfaceReconcile("ethernet", "eth0", { address: [], disable: false }, {
      disable: false,
    }).deletes,
    [],
  );
  assertEquals(
    interfaceReconcile("ethernet", "eth0", { address: [], disable: false }, {
      disable: true,
    }).sets,
    ["interfaces ethernet eth0 disable"],
  );
});

Deno.test("syncInterface writes the interface resource per name", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncIfExec(
    {
      type: "bridge",
      interface: "br0",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          interfaces: {
            bridge: {
              br0: { address: ["192.0.2.1/24"], description: "uplink" },
            },
          },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "interface");
  assertEquals(writes[0].name, "br0");
  assertEquals(writes[0].data.type, "bridge");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.address, ["192.0.2.1/24"]);
});

Deno.test("ensureInterface reads current, reconciles addresses, never wipes the subtree", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  // read (no stdin) returns current config; apply (stdin) returns the sentinel
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
        interfaces: {
          bridge: { br0: { address: ["10.0.0.1/24", "10.0.0.9/24"] } },
        },
      }),
      stderr: "",
      code: 0,
    });
  };
  await ensureIfExec(
    {
      type: "bridge",
      interface: "br0",
      address: ["10.0.0.1/24"],
      commit: true,
      save: true,
      dryRun: false,
      _ssh: ssh,
    },
    context,
  );
  const script = String(calls[1].stdin);
  // stale 10.0.0.9 removed (guarded), desired 10.0.0.1 set
  assert(
    script.includes("existsActive interfaces bridge br0 address 10.0.0.9/24"),
  );
  assert(script.includes("set interfaces bridge br0 address 10.0.0.1/24"));
  // safety: it must NOT delete the whole interface subtree
  assert(!script.includes("delete interfaces bridge br0;"));
  assert(!script.includes("delete interfaces bridge br0\n"));
  assertEquals(writes[0].specName, "applyResult");
});

Deno.test("ensureInterface requires at least one attribute", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureIfExec({
        type: "bridge",
        interface: "br0",
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

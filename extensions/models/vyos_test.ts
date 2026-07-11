/**
 * Unit tests for the @shrug/vyos model.
 *
 * The SSH transport is injected via each method's `_ssh` seam so the method
 * logic runs without a live router. The pure script/validation helpers are
 * tested directly.
 *
 * @module
 */
import {
  assert,
  assertEquals,
  assertRejects,
  assertThrows,
} from "jsr:@std/assert@1";
import {
  buildConfigScript,
  extractDiff,
  interfaceReconcile,
  model,
  parseInterfaceNode,
  parseRouterAdvertInterface,
  parseWireguardInterface,
  routerAdvertSetPaths,
  type SshResult,
  type SshRunner,
  validateApplyPaths,
  wireguardSetPaths,
} from "./vyos.ts";

/** A recorded call to the injected SSH runner. */
interface SshCall {
  command?: string[];
  stdin?: string;
}

/** Build an `_ssh` stub returning `result`, recording each invocation. */
function stubSsh(
  result: Partial<SshResult>,
  calls: SshCall[],
): SshRunner {
  return (_cfg, opts) => {
    calls.push({ command: opts.command, stdin: opts.stdin });
    return Promise.resolve({
      stdout: result.stdout ?? "",
      stderr: result.stderr ?? "",
      code: result.code ?? 0,
    });
  };
}

/** Minimal fake execute context capturing writes and logs. */
function fakeContext(host = "192.0.2.1") {
  const writes: Array<
    { specName: string; name: string; data: Record<string, unknown> }
  > = [];
  const logs: Array<{ level: string; message: string }> = [];
  const log = (level: string) => (message: string) =>
    logs.push({ level, message });
  const context = {
    globalArgs: { host, user: "vyos", port: 22 },
    logger: {
      debug: log("debug"),
      info: log("info"),
      warning: log("warning"),
      error: log("error"),
    },
    writeResource: (
      specName: string,
      name: string,
      data: Record<string, unknown>,
    ) => {
      writes.push({ specName, name, data });
      return Promise.resolve({ name });
    },
  };
  return { context, writes, logs };
}

// deno-lint-ignore no-explicit-any
const showExec = (model.methods.show.execute) as any;
// deno-lint-ignore no-explicit-any
const applyExec = (model.methods.apply.execute) as any;
// deno-lint-ignore no-explicit-any
const runExec = (model.methods.run.execute) as any;
// deno-lint-ignore no-explicit-any
const diffExec = (model.methods.diff.execute) as any;
// deno-lint-ignore no-explicit-any
const treeExec = (model.methods.tree.execute) as any;
// deno-lint-ignore no-explicit-any
const syncRaExec = (model.methods.syncRouterAdvert.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureRaExec = (model.methods.ensureRouterAdvert.execute) as any;
// deno-lint-ignore no-explicit-any
const removeRaExec = (model.methods.removeRouterAdvert.execute) as any;
// deno-lint-ignore no-explicit-any
const syncWgExec = (model.methods.syncWireguard.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureWgExec = (model.methods.ensureWireguard.execute) as any;
// deno-lint-ignore no-explicit-any
const removeWgExec = (model.methods.removeWireguard.execute) as any;
// deno-lint-ignore no-explicit-any
const syncIfExec = (model.methods.syncInterface.execute) as any;
// deno-lint-ignore no-explicit-any
const ensureIfExec = (model.methods.ensureInterface.execute) as any;

// --- validateApplyPaths -----------------------------------------------------

Deno.test("validateApplyPaths accepts bare single-line paths", () => {
  validateApplyPaths(["interface eth0 address 192.0.2.1/24"], ["service dns"]);
});

Deno.test("validateApplyPaths rejects an empty path", () => {
  assertThrows(() => validateApplyPaths(["   "], []), Error, "empty path");
});

Deno.test("validateApplyPaths rejects embedded newlines", () => {
  assertThrows(
    () => validateApplyPaths([], ["a\nb"]),
    Error,
    "single-line",
  );
});

Deno.test("validateApplyPaths rejects a leading set/delete prefix", () => {
  assertThrows(
    () => validateApplyPaths(["set interface eth0"], []),
    Error,
    "omit the leading",
  );
  assertThrows(
    () => validateApplyPaths([], ["delete interface eth0"]),
    Error,
    "omit the leading",
  );
});

// --- buildConfigScript ------------------------------------------------------

Deno.test("buildConfigScript guards deletes with existsActive", () => {
  const script = buildConfigScript({
    sets: [],
    deletes: ["service router-advert interface eth1 prefix 2001:db8:1::/64"],
    commit: true,
    save: true,
    dryRun: false,
  });
  assert(
    script.includes(
      "if cli-shell-api existsActive service router-advert interface eth1 prefix 2001:db8:1::/64; then delete",
    ),
  );
});

Deno.test("buildConfigScript commits and saves only under sessionChanged", () => {
  const script = buildConfigScript({
    sets: ["interface eth0 description test"],
    deletes: [],
    commit: true,
    save: true,
    dryRun: false,
  });
  assert(script.includes("if cli-shell-api sessionChanged; then"));
  assert(script.includes("  commit"));
  assert(script.includes("  save"));
  assert(script.includes("  exit"));
  assert(script.includes("SWAMP_APPLY_CHANGED"));
  assert(script.includes("SWAMP_APPLY_NOCHANGE"));
});

Deno.test("buildConfigScript dryRun compares (net) and discards, never commits", () => {
  const script = buildConfigScript({
    sets: ["interface eth0 description test"],
    deletes: [],
    commit: true,
    save: true,
    dryRun: true,
  });
  // gates on the real compare diff, echoes it, never commits/saves
  assert(script.includes('__cmp="$(compare)"'));
  assert(script.includes("No changes between working and active"));
  assert(script.includes('echo "$__cmp"'));
  assert(script.includes("exit discard"));
  assert(!script.includes("commit"));
  assert(!script.includes("\n    save"));
});

Deno.test("buildConfigScript treats a net-zero staged change as no-op", () => {
  // reconcile pattern: delete a subtree then re-set it identically
  const script = buildConfigScript({
    sets: ["service router-advert interface br0 prefix ::/64"],
    deletes: ["service router-advert interface br0"],
    commit: true,
    save: true,
    dryRun: false,
  });
  // the "No changes" branch discards + reports NOCHANGE before committing
  const idx = script.indexOf("No changes between working and active");
  const commitIdx = script.indexOf("commit");
  assert(idx !== -1 && idx < commitIdx);
  assert(script.includes(`${"SWAMP_APPLY_NOCHANGE"}`));
});

Deno.test("buildConfigScript discards the session when commit=false", () => {
  const script = buildConfigScript({
    sets: ["interface eth0 description test"],
    deletes: [],
    commit: false,
    save: false,
    dryRun: false,
  });
  assert(!script.includes("\n  commit"));
  assert(script.includes("  exit discard"));
});

// --- show -------------------------------------------------------------------

Deno.test("show snapshots op-mode output to the config resource", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await showExec(
    {
      command: "show configuration commands",
      _ssh: stubSsh({ stdout: "set x y\n" }, calls),
    },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].specName, "config");
  assertEquals(writes[0].name, "current");
  assertEquals(writes[0].data.commands, "set x y\n");
  // op wrapper is prefixed and the command is split on whitespace
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "show",
    "configuration",
    "commands",
  ]);
});

Deno.test("show throws on nonzero exit and writes nothing", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      showExec(
        {
          command: "show foo",
          _ssh: stubSsh({ code: 1, stderr: "boom" }, calls),
        },
        context,
      ),
    Error,
    "show failed",
  );
  assertEquals(writes.length, 0);
});

// --- tree -------------------------------------------------------------------

Deno.test("tree parses configuration json into the configTree spec", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await treeExec(
    {
      sensitive: false,
      _ssh: stubSsh(
        {
          stdout:
            '{"system":{"host-name":"vyos"},"interfaces":{"ethernet":{"eth0":{}}}}',
        },
        calls,
      ),
    },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].specName, "configTree");
  assertEquals(writes[0].name, "current");
  // native JSON is read through the op-mode wrapper
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "show",
    "configuration",
    "json",
  ]);
  // the parsed sections are spread onto the record
  assertEquals(
    (writes[0].data.system as Record<string, unknown>)["host-name"],
    "vyos",
  );
  assert(writes[0].data.interfaces !== undefined);
  assertEquals(writes[0].data.host, "192.0.2.1");
});

Deno.test("tree sensitive routes to the sensitiveConfigTree spec", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await treeExec(
    {
      sensitive: true,
      _ssh: stubSsh({ stdout: '{"pki":{"key-pair":{"k":{}}}}' }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "sensitiveConfigTree");
});

Deno.test("tree throws on nonzero exit and writes nothing", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      treeExec(
        { sensitive: false, _ssh: stubSsh({ code: 1, stderr: "boom" }, calls) },
        context,
      ),
    Error,
    "tree failed",
  );
  assertEquals(writes.length, 0);
});

Deno.test("tree throws on malformed json without writing", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      treeExec(
        { sensitive: false, _ssh: stubSsh({ stdout: "not json{" }, calls) },
        context,
      ),
    Error,
    "could not parse",
  );
  assertEquals(writes.length, 0);
});

// --- apply ------------------------------------------------------------------

Deno.test("apply requires at least one set or delete", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      applyExec({
        set: [],
        delete: [],
        commit: true,
        save: true,
        dryRun: false,
        storeScript: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("apply records changed+committed and redacts the script by default", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: ["interface eth0 description test"],
      delete: [],
      commit: true,
      save: true,
      dryRun: false,
      storeScript: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].specName, "applyResult");
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, true);
  assertEquals(writes[0].data.saved, true);
  assertEquals(writes[0].data.dryRun, false);
  assert(String(writes[0].data.script).startsWith("<redacted"));
  // script is piped over stdin to vbash
  assertEquals(calls[0].command, ["/bin/vbash", "-s"]);
  assert(
    String(calls[0].stdin).includes("set interface eth0 description test"),
  );
});

Deno.test("apply persists the script when storeScript=true", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: ["interface eth0 description test"],
      delete: [],
      commit: true,
      save: true,
      dryRun: false,
      storeScript: true,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assert(String(writes[0].data.script).includes("configure"));
});

Deno.test("apply sensitive routes to sensitiveApplyResult and stores full script", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: ["interfaces wireguard wg0 private-key SECRET"],
      delete: [],
      commit: true,
      save: true,
      dryRun: false,
      storeScript: false,
      sensitive: true,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].specName, "sensitiveApplyResult");
  // Even with storeScript=false, the script is persisted in full when
  // sensitive (the vault protects it), never the redaction placeholder.
  assert(String(writes[0].data.script).includes("configure"));
  assert(!String(writes[0].data.script).startsWith("<redacted"));
});

Deno.test("apply defaults to the cleartext applyResult spec", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: ["interface eth0 description test"],
      delete: [],
      commit: true,
      save: true,
      dryRun: false,
      storeScript: false,
      sensitive: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "applyResult");
});

Deno.test("apply no-op reports changed=false, committed=false", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: [],
      delete: ["service dns forwarding"],
      commit: true,
      save: true,
      dryRun: false,
      storeScript: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_NOCHANGE\n" }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.changed, false);
  assertEquals(writes[0].data.committed, false);
  assertEquals(writes[0].data.saved, false);
});

Deno.test("apply dryRun never marks committed even when changed", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: ["interface eth0 description test"],
      delete: [],
      commit: true,
      save: true,
      dryRun: true,
      storeScript: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.changed, true);
  assertEquals(writes[0].data.committed, false);
  assertEquals(writes[0].data.dryRun, true);
});

Deno.test("apply writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      applyExec(
        {
          set: ["interface eth0 description test"],
          delete: [],
          commit: true,
          save: true,
          dryRun: false,
          storeScript: false,
          _ssh: stubSsh({ code: 1, stderr: "commit failed" }, calls),
        },
        context,
      ),
    Error,
    "apply failed",
  );
  // The terminal record is still written for diagnosis.
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
  assertEquals(writes[0].data.stderr, "commit failed");
});

Deno.test("apply rejects a malformed path before touching SSH", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      applyExec(
        {
          set: ["set interface eth0"],
          delete: [],
          commit: true,
          save: true,
          dryRun: false,
          storeScript: false,
          _ssh: stubSsh({}, calls),
        },
        context,
      ),
    Error,
    "omit the leading",
  );
  assertEquals(calls.length, 0);
  assertEquals(writes.length, 0);
});

// --- extractDiff ------------------------------------------------------------

Deno.test("extractDiff strips the sentinel and trailing whitespace", () => {
  assertEquals(
    extractDiff("+set x y\n-delete z\nSWAMP_APPLY_CHANGED\n"),
    "+set x y\n-delete z",
  );
});

Deno.test("extractDiff returns empty for a no-op", () => {
  assertEquals(extractDiff("SWAMP_APPLY_NOCHANGE\n"), "");
});

// --- diff -------------------------------------------------------------------

Deno.test("diff requires at least one set or delete", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () => diffExec({ set: [], delete: [], sensitive: false }, context),
    Error,
    "at least one",
  );
});

Deno.test("diff stages a dryRun compare, never commits, writes the diff spec", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await diffExec(
    {
      set: ["interface eth0 description test"],
      delete: [],
      sensitive: false,
      _ssh: stubSsh(
        {
          stdout: "+set interface eth0 description test\nSWAMP_APPLY_CHANGED\n",
        },
        calls,
      ),
    },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].specName, "diff");
  assertEquals(writes[0].data.changed, true);
  assertEquals(
    writes[0].data.diff,
    "+set interface eth0 description test",
  );
  // The generated script previews and discards — it must never commit/save.
  const script = String(calls[0].stdin);
  assert(script.includes("compare"));
  assert(script.includes("exit discard"));
  assert(!script.includes("\n  commit"));
  assert(!script.includes("\n  save"));
});

Deno.test("diff no-op reports changed=false and empty diff", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await diffExec(
    {
      set: [],
      delete: ["service dns forwarding"],
      sensitive: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_NOCHANGE\n" }, calls),
    },
    context,
  );
  assertEquals(writes[0].data.changed, false);
  assertEquals(writes[0].data.diff, "");
});

Deno.test("diff sensitive routes to the sensitiveDiff spec", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await diffExec(
    {
      set: ["interfaces wireguard wg0 private-key SECRET"],
      delete: [],
      sensitive: true,
      _ssh: stubSsh({ stdout: "+set ...\nSWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "sensitiveDiff");
});

Deno.test("diff rejects a malformed path before touching SSH", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      diffExec(
        {
          set: ["set interface eth0"],
          delete: [],
          sensitive: false,
          _ssh: stubSsh({}, calls),
        },
        context,
      ),
    Error,
    "omit the leading",
  );
  assertEquals(calls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("diff writes the result BEFORE throwing on nonzero exit", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      diffExec(
        {
          set: ["interface eth0 description test"],
          delete: [],
          sensitive: false,
          _ssh: stubSsh({ code: 1, stderr: "compare failed" }, calls),
        },
        context,
      ),
    Error,
    "diff failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

// --- router-advert helpers --------------------------------------------------

Deno.test("routerAdvertSetPaths translates prefixes, routes, options", () => {
  const paths = routerAdvertSetPaths("br10.95", {
    defaultLifetime: 3600,
    prefixes: [
      {
        prefix: "2602:f4fb:bed:95::/64",
        validLifetime: 14400,
        autonomousFlag: false,
      },
    ],
    routes: ["::/0"],
    nat64prefixes: ["64:ff9b::/96"],
  });
  assertEquals(paths, [
    "service router-advert interface br10.95 default-lifetime 3600",
    "service router-advert interface br10.95 prefix 2602:f4fb:bed:95::/64",
    "service router-advert interface br10.95 prefix 2602:f4fb:bed:95::/64 valid-lifetime 14400",
    "service router-advert interface br10.95 prefix 2602:f4fb:bed:95::/64 no-autonomous-flag",
    "service router-advert interface br10.95 route ::/0",
    "service router-advert interface br10.95 nat64prefix 64:ff9b::/96",
  ]);
});

Deno.test("parseRouterAdvertInterface reads the json node", () => {
  const parsed = parseRouterAdvertInterface({
    "default-lifetime": "3600",
    "prefix": { "2602:f4fb:bed:95::/64": {} },
    "route": { "::/0": {} },
    "nat64prefix": { "64:ff9b::/96": {} },
  });
  assertEquals(parsed.defaultLifetime, "3600");
  assertEquals(parsed.prefixes, [{ prefix: "2602:f4fb:bed:95::/64" }]);
  assertEquals(parsed.routes, ["::/0"]);
  assertEquals(parsed.nat64prefixes, ["64:ff9b::/96"]);
});

// --- syncRouterAdvert -------------------------------------------------------

Deno.test("syncRouterAdvert writes a typed routerAdvert resource named for the interface", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncRaExec(
    {
      interface: "br10.95",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          service: {
            "router-advert": {
              interface: {
                "br10.95": {
                  prefix: { "2602:f4fb:bed:95::/64": {} },
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
  assertEquals(writes[0].name, "br10.95");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.prefixes, [{ prefix: "2602:f4fb:bed:95::/64" }]);
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

// --- ensureRouterAdvert -----------------------------------------------------

Deno.test("ensureRouterAdvert wipes the subtree then sets desired (declarative)", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureRaExec(
    {
      interface: "br10.95",
      prefixes: [{ prefix: "2602:f4fb:bed:95::/64" }],
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
      "if cli-shell-api existsActive service router-advert interface br10.95; then delete service router-advert interface br10.95",
    ),
  );
  assert(
    script.includes(
      "set service router-advert interface br10.95 prefix 2602:f4fb:bed:95::/64",
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
        interface: "br10.95",
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

// --- removeRouterAdvert -----------------------------------------------------

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

// --- wireguard helpers ------------------------------------------------------

Deno.test("wireguardSetPaths translates interface + peer paths", () => {
  const paths = wireguardSetPaths("wg0", {
    privateKey: "PRIV=",
    address: ["2001:db8:e::1/126"],
    port: 51821,
    adjustMss: "clamp-mss-to-pmtu",
    peers: [
      {
        name: "hub",
        publicKey: "PUB=",
        address: "203.0.113.1",
        port: 51820,
        allowedIps: ["::/0"],
        persistentKeepalive: 25,
        presharedKey: "PSK=",
      },
    ],
  });
  assertEquals(paths, [
    "interfaces wireguard wg0 private-key PRIV=",
    "interfaces wireguard wg0 address 2001:db8:e::1/126",
    "interfaces wireguard wg0 port 51821",
    "interfaces wireguard wg0 ipv6 adjust-mss clamp-mss-to-pmtu",
    "interfaces wireguard wg0 peer hub public-key PUB=",
    "interfaces wireguard wg0 peer hub address 203.0.113.1",
    "interfaces wireguard wg0 peer hub port 51820",
    "interfaces wireguard wg0 peer hub allowed-ips ::/0",
    "interfaces wireguard wg0 peer hub persistent-keepalive 25",
    "interfaces wireguard wg0 peer hub preshared-key PSK=",
  ]);
});

Deno.test("wireguardSetPaths quotes a spaced description", () => {
  const paths = wireguardSetPaths("wg0", { description: "uplink to hub" });
  assertEquals(paths, [
    "interfaces wireguard wg0 description 'uplink to hub'",
  ]);
});

Deno.test("parseWireguardInterface reads interface + peers", () => {
  const parsed = parseWireguardInterface({
    "address": ["2001:db8:e::1/126"],
    "port": "51821",
    "private-key": "PRIV=",
    "ipv6": { "adjust-mss": "clamp-mss-to-pmtu" },
    "peer": {
      "hub": {
        "address": "203.0.113.1",
        "port": "51820",
        "public-key": "PUB=",
        "allowed-ips": ["::/0"],
        "persistent-keepalive": "25",
      },
    },
  });
  assertEquals(parsed.privateKey, "PRIV=");
  assertEquals(parsed.address, ["2001:db8:e::1/126"]);
  assertEquals(parsed.adjustMss, "clamp-mss-to-pmtu");
  assertEquals(parsed.peers.length, 1);
  assertEquals(parsed.peers[0].name, "hub");
  assertEquals(parsed.peers[0].publicKey, "PUB=");
  assertEquals(parsed.peers[0].allowedIps, ["::/0"]);
});

// --- syncWireguard ----------------------------------------------------------

Deno.test("syncWireguard writes the vaulted wireguard resource per interface", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await syncWgExec(
    {
      interface: "wg0",
      _ssh: stubSsh({
        stdout: JSON.stringify({
          interfaces: {
            wireguard: {
              wg0: {
                "private-key": "PRIV=",
                "port": "51821",
                "peer": { "hub": { "public-key": "PUB=" } },
              },
            },
          },
        }),
      }, calls),
    },
    context,
  );
  assertEquals(writes[0].specName, "wireguard");
  assertEquals(writes[0].name, "wg0");
  assertEquals(writes[0].data.exists, true);
  assertEquals(writes[0].data.privateKey, "PRIV=");
  assertEquals(
    (writes[0].data.peers as Array<{ name: string }>)[0].name,
    "hub",
  );
});

// --- ensureWireguard / removeWireguard --------------------------------------

Deno.test("ensureWireguard reconciles and vaults the result", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await ensureWgExec(
    {
      interface: "wg0",
      privateKey: "PRIV=",
      address: ["2001:db8:e::1/126"],
      port: 51821,
      peers: [{ name: "hub", publicKey: "PUB=", allowedIps: ["::/0"] }],
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
      "if cli-shell-api existsActive interfaces wireguard wg0; then delete interfaces wireguard wg0",
    ),
  );
  assert(script.includes("set interfaces wireguard wg0 private-key PRIV="));
  // WireGuard results are vaulted
  assertEquals(writes[0].specName, "sensitiveApplyResult");
});

Deno.test("ensureWireguard requires at least one field", async () => {
  const { context } = fakeContext();
  await assertRejects(
    () =>
      ensureWgExec({
        interface: "wg0",
        address: [],
        peers: [],
        commit: true,
        save: true,
        dryRun: false,
      }, context),
    Error,
    "at least one",
  );
});

Deno.test("removeWireguard deletes the interface, vaults the result", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await removeWgExec(
    {
      interface: "wg0",
      commit: true,
      save: true,
      dryRun: false,
      _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
    },
    context,
  );
  assert(String(calls[0].stdin).includes("delete interfaces wireguard wg0"));
  assertEquals(writes[0].specName, "sensitiveApplyResult");
  assertEquals(writes[0].data.delete, ["interfaces wireguard wg0"]);
});

// --- interface helpers ------------------------------------------------------

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

// --- syncInterface ----------------------------------------------------------

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
              br0: { address: ["10.254.1.1/24"], description: "MGMT-OOB" },
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
  assertEquals(writes[0].data.address, ["10.254.1.1/24"]);
});

// --- ensureInterface --------------------------------------------------------

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

// --- run --------------------------------------------------------------------

Deno.test("run wraps op-mode commands and snapshots output", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await runExec(
    {
      command: "show interfaces",
      opMode: true,
      _ssh: stubSsh({ stdout: "eth0\n" }, calls),
    },
    context,
  );
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "show",
    "interfaces",
  ]);
  assertEquals(writes[0].specName, "commandResult");
  assertEquals(writes[0].data.stdout, "eth0\n");
  assertEquals(writes[0].data.opMode, true);
});

Deno.test("run passes non-op commands through sh -c", async () => {
  const calls: SshCall[] = [];
  const { context } = fakeContext();
  await runExec(
    {
      command: "uptime",
      opMode: false,
      _ssh: stubSsh({ stdout: "up\n" }, calls),
    },
    context,
  );
  assertEquals(calls[0].command, ["sh", "-c", "uptime"]);
});

Deno.test("run throws on nonzero exit and writes the result first", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      runExec(
        {
          command: "false",
          opMode: false,
          _ssh: stubSsh({ code: 1, stderr: "nope" }, calls),
        },
        context,
      ),
    Error,
    "run failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.exitCode, 1);
});

/**
 * Unit tests for the @shrug/vyos raw read/apply/run methods.
 *
 * @module
 */
import { assert, assertEquals, assertRejects } from "jsr:@std/assert@1";
import { model } from "./vyos.ts";
import { fakeContext, type SshCall, stubSsh } from "./test_support.ts";

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
const confirmExec = (model.methods.confirm.execute) as any;

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
  // The generated script previews and discards - it must never commit/save.
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

Deno.test("apply commit-confirm arms the timer, reports confirmPending, and does not save", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await applyExec(
    {
      set: ["firewall ipv4 input filter default-action drop"],
      delete: [],
      commit: true,
      // save=true on purpose: the commit-confirm path must still report
      // saved=false, so the record never claims a save that did not happen.
      save: true,
      confirmMinutes: 5,
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
  assertEquals(writes[0].data.confirmPending, true);
  assertEquals(writes[0].data.confirmMinutes, 5);
  // the key safety invariant: never report saved for an un-confirmed change
  assertEquals(writes[0].data.saved, false);
  // the piped script arms commit-confirm, not a bare commit
  assert(String(calls[0].stdin).includes("commit-confirm 5"));
  assert(!String(calls[0].stdin).includes("\n    commit\n"));
});

Deno.test("apply rejects confirmMinutes with commit=false", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      applyExec(
        {
          set: ["system host-name vyos"],
          delete: [],
          commit: false,
          save: false,
          confirmMinutes: 5,
          dryRun: false,
          storeScript: false,
          _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
        },
        context,
      ),
    Error,
    "requires commit=true",
  );
  // rejected before any ssh call or write
  assertEquals(calls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("apply rejects confirmMinutes with dryRun", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      applyExec(
        {
          set: ["system host-name vyos"],
          delete: [],
          commit: true,
          save: true,
          confirmMinutes: 5,
          dryRun: true,
          storeScript: false,
          _ssh: stubSsh({ stdout: "SWAMP_APPLY_CHANGED\n" }, calls),
        },
        context,
      ),
    Error,
    "cannot be combined with dryRun",
  );
  assertEquals(calls.length, 0);
  assertEquals(writes.length, 0);
});

Deno.test("confirm cancels the timer and saves, recording confirmResult", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await confirmExec(
    { save: true, _ssh: stubSsh({ stdout: "" }, calls) },
    context,
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].specName, "confirmResult");
  assertEquals(writes[0].data.confirmed, true);
  assertEquals(writes[0].data.saved, true);
  // two calls: op-mode confirm, then a config-mode save
  assertEquals(calls.length, 2);
  assertEquals(calls[0].command, [
    "/opt/vyatta/bin/vyatta-op-cmd-wrapper",
    "confirm",
  ]);
  assertEquals(calls[1].command, ["/bin/vbash", "-s"]);
  assert(String(calls[1].stdin).includes("save"));
});

Deno.test("confirm with save=false only cancels the timer", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await confirmExec(
    { save: false, _ssh: stubSsh({ stdout: "" }, calls) },
    context,
  );
  assertEquals(writes[0].data.confirmed, true);
  assertEquals(writes[0].data.saved, false);
  assertEquals(calls.length, 1);
});

Deno.test("confirm throws on confirm failure and writes the result first", async () => {
  const calls: SshCall[] = [];
  const { context, writes } = fakeContext();
  await assertRejects(
    () =>
      confirmExec(
        { save: true, _ssh: stubSsh({ code: 1, stderr: "no pending" }, calls) },
        context,
      ),
    Error,
    "confirm failed",
  );
  assertEquals(writes.length, 1);
  assertEquals(writes[0].data.confirmed, false);
  // save is skipped when confirm fails
  assertEquals(calls.length, 1);
});

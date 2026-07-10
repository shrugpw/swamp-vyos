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
  model,
  type SshResult,
  type SshRunner,
  validateApplyPaths,
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

Deno.test("buildConfigScript dryRun compares and discards, never commits", () => {
  const script = buildConfigScript({
    sets: ["interface eth0 description test"],
    deletes: [],
    commit: true,
    save: true,
    dryRun: true,
  });
  assert(script.includes("  compare"));
  assert(script.includes("  exit discard"));
  assert(!script.includes("\n  commit"));
  assert(!script.includes("\n  save"));
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

/**
 * Unit tests for the @shrug/vyos core transport/script/validation helpers.
 *
 * @module
 */
import { assert, assertEquals, assertThrows } from "jsr:@std/assert@1";
import { buildConfigScript, extractDiff, validateApplyPaths } from "./core.ts";

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

Deno.test("buildConfigScript commit-confirm arms the timer and does not save", () => {
  const script = buildConfigScript({
    sets: ["firewall ipv4 input filter default-action drop"],
    deletes: [],
    commit: true,
    save: true,
    dryRun: false,
    confirmMinutes: 5,
  });
  // commit-confirm replaces a bare commit...
  assert(script.includes("commit-confirm 5"));
  assert(!script.includes("\n    commit\n"));
  // ...and does NOT save even though save=true (no-save-until-confirm, so an
  // un-confirmed config never lands in config.boot ahead of the auto-revert)...
  assert(!script.includes("\n    save"));
  // ...while keeping the committed session with a plain `exit`, not discarding.
  assert(script.includes("echo SWAMP_APPLY_CHANGED\n    exit\n"));
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

Deno.test("extractDiff strips the sentinel and trailing whitespace", () => {
  assertEquals(
    extractDiff("+set x y\n-delete z\nSWAMP_APPLY_CHANGED\n"),
    "+set x y\n-delete z",
  );
});

Deno.test("extractDiff returns empty for a no-op", () => {
  assertEquals(extractDiff("SWAMP_APPLY_NOCHANGE\n"), "");
});

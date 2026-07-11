/**
 * Shared unit-test helpers for the split @shrug/vyos model.
 *
 * @module
 */
import type { SshResult, SshRunner } from "./core.ts";

export /** A recorded call to the injected SSH runner. */
interface SshCall {
  command?: string[];
  stdin?: string;
}

export /** Build an `_ssh` stub returning `result`, recording each invocation. */
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

export /** Minimal fake execute context capturing writes and logs. */
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

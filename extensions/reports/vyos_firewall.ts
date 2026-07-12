/**
 * VyOS firewall report — renders the firewall posture from a `show` config
 * snapshot (specName "config"). VyOS filters by inbound interface: a base
 * forward/input chain jumps to a per-segment named ruleset. This report maps
 * each interface to its ruleset, summarises each ruleset's posture, and breaks
 * out WAN exposure (what the internet can reach) — the useful analog of a
 * zone matrix.
 *
 * Consumes the raw `set firewall ...` config lines in `content.commands`, so it
 * works whether `show` ran the full config or a firewall-scoped command.
 *
 * @module
 */

interface ConfigSnapshot {
  host?: string;
  command?: string;
  commands: string; // newline-joined `set ...` config commands
  retrievedAt?: string;
}

type Rule = Record<string, string>;
interface Chain {
  family: "ipv4" | "ipv6";
  name: string; // named ruleset, or "forward"/"input"/"output" for base chains
  defaultAction?: string;
  rules: Map<number, Rule>;
}
/** interface → ruleset a base chain jumps to */
interface Binding {
  family: "ipv4" | "ipv6";
  base: string; // forward | input | output
  iface: string;
  target: string;
}

// ── parse ─────────────────────────────────────────────────────────────────────

/** Parse `set firewall ...` lines into chains, bindings, and groups. */
export function parseFirewall(commands: string): {
  chains: Map<string, Chain>;
  bindings: Binding[];
  groups: Map<string, string[]>;
} {
  const chains = new Map<string, Chain>();
  const bindings: Binding[] = [];
  const groups = new Map<string, string[]>();

  const chain = (family: "ipv4" | "ipv6", name: string): Chain => {
    const key = `${family}/${name}`;
    let c = chains.get(key);
    if (!c) {
      c = { family, name, rules: new Map() };
      chains.set(key, c);
    }
    return c;
  };
  const rule = (c: Chain, n: number): Rule => {
    let r = c.rules.get(n);
    if (!r) {
      r = {};
      c.rules.set(n, r);
    }
    return r;
  };

  for (let line of commands.split("\n")) {
    line = line.trim();
    if (line.startsWith("set ")) line = line.slice(4);
    if (!line.startsWith("firewall ")) continue;
    // pull a trailing quoted value if present
    const vm = line.match(/^(.*?) '([^']*)'$/);
    const path = vm ? vm[1] : line;
    const value = vm ? vm[2] : "";
    const t = path.split(" "); // e.g. firewall ipv4 forward filter rule 5 action

    if (t[1] === "group") {
      const key = `${t[2]} ${t[3]}`; // network-group rfc1918
      const arr = groups.get(key) ?? [];
      // t[4] is the member leaf (network/address/port/…); skip metadata (description)
      if (value && t[4] !== "description") arr.push(value);
      groups.set(key, arr);
      continue;
    }
    const family = t[1] as "ipv4" | "ipv6";
    if (family !== "ipv4" && family !== "ipv6") continue;

    // base chain: firewall <fam> <forward|input|output> filter ...
    if (["forward", "input", "output"].includes(t[2]) && t[3] === "filter") {
      const c = chain(family, t[2]);
      if (t[4] === "default-action") c.defaultAction = value;
      else if (t[4] === "rule") {
        const n = Number(t[5]);
        const attr = t.slice(6).join(" ");
        const r = rule(c, n);
        r[attr] = value || "true";
        if (attr === "jump-target") {
          bindings.push({
            family,
            base: t[2],
            iface: r["inbound-interface name"] ??
              r["inbound-interface interface-name"] ?? "?",
            target: value,
          });
        }
        if (attr.startsWith("inbound-interface")) {
          // backfill iface on any binding already recorded for this rule
          for (const b of bindings) {
            if (
              b.family === family && b.base === t[2] &&
              b.target === (r["jump-target"] ?? "") && b.iface === "?"
            ) b.iface = value;
          }
        }
      }
      continue;
    }
    // named ruleset: firewall <fam> name <NAME> ...
    if (t[2] === "name") {
      const c = chain(family, t[3]);
      if (t[4] === "default-action") c.defaultAction = value;
      else if (t[4] === "rule") {
        const n = Number(t[5]);
        rule(c, n)[t.slice(6).join(" ")] = value || "true";
      }
      continue;
    }
  }
  return { chains, bindings, groups };
}

// ── render helpers ─────────────────────────────────────────────────────────────

const act = (a?: string) => {
  const u = (a ?? "").toLowerCase();
  if (u === "accept" || u === "return") return `✅ ${u}`;
  if (u === "drop" || u === "reject") return `⛔ ${u}`;
  if (u === "jump") return `↪ jump`;
  return u || "—";
};

const g = (r: Rule, ...ks: string[]) => {
  for (const k of ks) if (r[k]) return r[k];
  return undefined;
};

/** One-line matcher summary for a rule. */
function matchers(r: Rule): string {
  const parts = [
    r["jump-target"] ? `→${r["jump-target"]}` : undefined,
    g(r, "inbound-interface name", "inbound-interface interface-name") &&
    `in=${g(r, "inbound-interface name", "inbound-interface interface-name")}`,
    g(r, "outbound-interface name", "outbound-interface interface-name") &&
    `out=${
      g(r, "outbound-interface name", "outbound-interface interface-name")
    }`,
    r["protocol"] && `proto=${r["protocol"]}`,
    g(
      r,
      "source address",
      "source group network-group",
      "source group address-group",
    ) &&
    `src=${
      g(
        r,
        "source address",
        "source group network-group",
        "source group address-group",
      )
    }`,
    r["destination port"] && `dport=${r["destination port"]}`,
    g(
      r,
      "destination address",
      "destination group network-group",
      "destination group address-group",
    ) &&
    `dst=${
      g(
        r,
        "destination address",
        "destination group network-group",
        "destination group address-group",
      )
    }`,
    stateOf(r) && `state=${stateOf(r)}`,
    r["description"] && `“${r["description"]}”`,
  ].filter(Boolean);
  return parts.join(" ");
}

function stateOf(r: Rule): string | undefined {
  const on = Object.keys(r)
    .filter((k) => k.startsWith("state ") && r[k] !== "disable")
    .map((k) => k.slice(6));
  if (on.length) return on.join(",");
  if (r["state"]) return r["state"];
  return undefined;
}

// ── report ──────────────────────────────────────────────────────────────────

/** VyOS firewall posture — segment map, WAN exposure, per-ruleset detail. */
export const report = {
  name: "@shrug/vyos-firewall",
  description:
    "VyOS firewall posture from a `show` config snapshot: interface→ruleset " +
    "segment map, WAN exposure, and per-ruleset rule detail",
  scope: "method" as const,
  labels: ["networking", "vyos", "firewall", "security"],
  execute: async (context: {
    modelType: string;
    modelId: string;
    methodName: string;
    executionStatus: "succeeded" | "failed";
    errorMessage?: string;
    dataHandles: Array<{ name: string; specName: string; version: number }>;
    dataRepository: {
      getContent(
        type: string,
        modelId: string,
        dataName: string,
        version?: number,
      ): Promise<Uint8Array | null>;
    };
  }) => {
    if (context.methodName !== "show") return { markdown: "", json: {} };
    if (context.executionStatus === "failed") {
      return {
        markdown: `# VyOS Firewall\n\n**Show failed**: ${
          context.errorMessage ?? "unknown error"
        }\n`,
        json: { status: "failed", error: context.errorMessage },
      };
    }
    const handles = context.dataHandles.filter((h) => h.specName === "config");
    if (handles.length === 0) return { markdown: "", json: {} };

    const lines: string[] = [];
    const jsonOut: unknown[] = [];

    for (const handle of handles) {
      const raw = await context.dataRepository.getContent(
        context.modelType,
        context.modelId,
        handle.name,
        handle.version,
      );
      if (!raw) continue;
      const snap = JSON.parse(new TextDecoder().decode(raw)) as ConfigSnapshot;
      if (!snap.commands || !/^(set )?firewall /m.test(snap.commands)) {
        lines.push(
          `# VyOS Firewall — ${snap.host ?? "router"}`,
          "",
          "_No firewall config in this snapshot_ " +
            "(run `show` with the default `show configuration commands`).",
          "",
        );
        continue;
      }

      const { chains, bindings, groups } = parseFirewall(snap.commands);
      const isBase = (name: string) =>
        ["forward", "input", "output"].includes(name);
      const named = [...chains.values()].filter((c) => !isBase(c.name));
      const base = [...chains.values()].filter((c) => isBase(c.name));

      lines.push(
        `# VyOS Firewall — ${snap.host ?? "router"}`,
        "",
        `**Rulesets**: ${named.length}  ·  **Bindings**: ${bindings.length}  ·  ` +
          `**Retrieved**: ${
            snap.retrievedAt ? new Date(snap.retrievedAt).toUTCString() : "?"
          }`,
        "",
      );

      // ── base chains: hook defaults (unmatched traffic) ──
      if (base.length) {
        lines.push(
          "## Base chains (hook defaults)",
          "",
          "| Family | Chain | Default | Rules |",
          "| ------ | ----- | ------- | ----: |",
        );
        for (
          const c of [...base].sort((a, b) =>
            a.family.localeCompare(b.family) || a.name.localeCompare(b.name)
          )
        ) {
          lines.push(
            `| ${c.family} | ${c.name} | ${
              act(c.defaultAction)
            } | ${c.rules.size} |`,
          );
        }
        lines.push("");
      }

      // ── segment map: interface → ruleset ──
      lines.push(
        "## Segment map (inbound interface → ruleset)",
        "",
        "| Family | Chain | Interface | → Ruleset | Default | Rules |",
        "| ------ | ----- | --------- | --------- | ------- | ----: |",
      );
      for (
        const b of [...bindings].sort((a, b) =>
          a.family.localeCompare(b.family) || a.iface.localeCompare(b.iface)
        )
      ) {
        const c = chains.get(`${b.family}/${b.target}`);
        lines.push(
          `| ${b.family} | ${b.base} | \`${b.iface}\` | **${b.target}** | ${
            act(c?.defaultAction)
          } | ${c?.rules.size ?? 0} |`,
        );
      }
      lines.push("");

      // ── WAN exposure ──
      const wan = named.filter((c) => /wan[-_]?(in|local)/i.test(c.name));
      if (wan.length) {
        lines.push("## WAN exposure (what the internet can reach)", "");
        for (const c of wan) {
          lines.push(
            `**${c.family} ${c.name}** — default ${act(c.defaultAction)}`,
          );
          for (const n of [...c.rules.keys()].sort((a, b) => a - b)) {
            const r = c.rules.get(n)!;
            const m = matchers(r);
            // exposure = anything not the boilerplate est/rel + invalid pair
            lines.push(`- \`${n}\` ${act(r["action"])}${m ? ` — ${m}` : ""}`);
          }
          lines.push("");
        }
      }

      // ── per-ruleset detail ──
      lines.push("## Rulesets", "");
      for (
        const c of named.sort((a, b) =>
          a.family.localeCompare(b.family) || a.name.localeCompare(b.name)
        )
      ) {
        if (wan.includes(c)) continue; // already shown above
        lines.push(
          `### ${c.family} ${c.name} — default ${
            act(c.defaultAction)
          } (${c.rules.size} rules)`,
          "",
          "| # | Action | Match |",
          "| - | ------ | ----- |",
        );
        for (const n of [...c.rules.keys()].sort((a, b) => a - b)) {
          const r = c.rules.get(n)!;
          lines.push(`| ${n} | ${act(r["action"])} | ${matchers(r) || "—"} |`);
        }
        lines.push("");
      }

      // ── attention ──
      const notes: string[] = [];
      for (const c of [...named, ...base]) {
        if ((c.defaultAction ?? "").toLowerCase() === "accept") {
          notes.push(
            `⚠️ **${c.family} ${c.name}** default-action is \`accept\` (permissive; unmatched traffic is allowed)`,
          );
        }
        for (const [n, r] of c.rules) {
          if (
            /temp|test|todo|fixme|xxx|for now/i.test(r["description"] ?? "")
          ) {
            notes.push(
              `⚠️ **${c.family} ${c.name}** rule ${n} — description “${
                r["description"]
              }” suggests a temporary rule`,
            );
          }
          const src = g(r, "source address");
          if (src && src.startsWith("!")) {
            notes.push(
              `ℹ️ **${c.family} ${c.name}** rule ${n} — negated source \`${src}\``,
            );
          }
        }
      }
      if (notes.length) {
        lines.push(
          "## Attention",
          "",
          ...notes.map((n) => `- ${n}`),
          "",
        );
      }

      jsonOut.push({
        host: snap.host,
        rulesets: named.length,
        bindings: bindings.map((b) => ({
          ...b,
          default: chains.get(`${b.family}/${b.target}`)?.defaultAction,
        })),
        groups: Object.fromEntries(groups),
        flags: notes.length,
      });
    }

    return {
      markdown: lines.join("\n").trimEnd() + "\n",
      json: { status: "ok", sites: jsonOut },
    };
  },
};

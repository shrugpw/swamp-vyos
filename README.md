# @shrug/vyos

A swamp model for managing a [VyOS](https://vyos.io) router over SSH. It reads
the running configuration, applies `set`/`delete` configuration commands, and
runs arbitrary operational- or config-mode commands — encoding the VyOS quirks
so callers work in terms of plain config paths instead of `vbash` incantations.

VyOS is peculiar: configuration mode requires `vbash` sourcing the Vyatta
`script-template` (a plain `ssh host 'configure; set ...'` does **not** work),
and operational reads go through the `vyatta-op-cmd-wrapper`. This model hides
both requirements behind a set of raw-config methods plus typed, declarative
per-resource methods (starting with router-advert).

## Installation

```sh
swamp extension pull @shrug/vyos
```

## Usage

Create a model instance pointed at your router, then call its methods:

```sh
# Create an instance (host is required; user defaults to "vyos")
swamp model create @shrug/vyos my-router \
  --global host=192.0.2.1 --global user=vyos

# Read the running config (snapshots to the "config" resource)
swamp model method run my-router show

# Read the running config as a structured, CEL-queryable tree
swamp model method run my-router tree

# Preview a change without touching the router (read-only VyOS `compare`)
swamp model method run my-router diff \
  --input set='["interface eth0 description uplink"]'

# Apply a change: delete a config path, then commit + save
swamp model method run my-router apply \
  --input delete='["service router-advert interface eth1 prefix 2001:db8:1::/64"]'

# Run an arbitrary command (opMode=true wraps it for op-mode)
swamp model method run my-router run --input command="show interfaces" --input opMode=true

# Apply secret-bearing config (e.g. a WireGuard private key) with the
# secret fields vaulted instead of stored in cleartext (see "Sensitive output")
swamp vault create local_encryption vyos          # one-time
swamp model method run my-router apply --input sensitive=true \
  --input set='["interfaces wireguard wg0 private-key s3cr3t"]'

# Apply a management-severing change safely with auto-rollback: commit-confirm
# arms a 5-minute revert timer instead of a plain commit (and does NOT save),
# so if the change cuts your path to the router it reverts on its own.
swamp model method run my-router apply --input confirmMinutes=5 \
  --input set='["firewall ipv4 input filter default-action drop"]'
# ...then, once you have confirmed you are still reachable, make it permanent
# (cancels the timer and saves to config.boot):
swamp model method run my-router confirm
```

## Methods

- **`show`** — run an op-mode command (default `show configuration commands`)
  and snapshot the raw output to the `config` resource.
- **`tree`** — read the running config as a **structured** tree via native
  `show configuration json`, so it can be queried with CEL (e.g.
  `…attributes.interfaces.ethernet`). Writes the `configTree` resource (or
  `sensitiveConfigTree` when `sensitive=true` — the tree embeds WireGuard and
  PKI private keys, so it is secret-bearing by nature). Well-known top-level
  sections are declared; unknown ones are preserved.
- **`apply`** — apply `set`/`delete` config paths through `vbash`, then `commit`
  and `save` (both toggleable). Requires at least one `set` or `delete`. Pass
  `dryRun=true` to stage and print the diff without committing,
  `storeScript=true` to persist the generated script, and `sensitive=true` to
  vault the secret-bearing fields (see below). Pass `confirmMinutes=<N>` (with
  `commit=true`, not `dryRun`) to commit with VyOS **`commit-confirm <N>`** — an
  N-minute auto-revert timer — instead of a plain commit, for a
  management-severing change (e.g. a firewall base-chain or mgmt-path interface
  change) that must roll back if it cuts your access. In that path `apply`
  deliberately does **not** `save`: an un-confirmed config must not land in
  `config.boot` ahead of the auto-revert. The result records `confirmPending` /
  `confirmMinutes`. **Caveat:** a change that severs the mgmt path can drop the
  SSH session before `apply` returns, so `apply` may throw and `confirmPending`
  may read false even though the router armed the timer — treat the auto-revert
  timer, not the `confirmPending` field, as the real safety net, verify
  reachability out of band, and only then `confirm`.
- **`confirm`** — make a pending `commit-confirm` permanent: cancel the
  auto-revert timer (op-mode `confirm`), then `save` the now-permanent running
  config to `config.boot` (`save=false` to skip the save). Writes the
  `confirmResult` resource. Run it once you have verified the router is still
  reachable after a `confirmMinutes` apply.
- **`diff`** — **read-only** preview of what a `set`/`delete` would change. It
  stages the change, runs VyOS `compare`, and discards the session — it never
  commits. Writes the `compare` output to the `diff` resource (or
  `sensitiveDiff` when `sensitive=true`). Requires at least one `set` or
  `delete`.
- **`run`** — run an arbitrary command over SSH; set `opMode=true` to prefix the
  VyOS op-mode wrapper.

### Typed resources

On top of the raw config methods, the model exposes **typed, declarative**
methods for specific VyOS resources. The first is IPv6 **router-advert** (RA /
SLAAC):

- **`syncRouterAdvert`** — read the current RA config for one interface into a
  typed `routerAdvert` resource (`prefixes`, `routes`, `nat64prefixes`,
  `defaultLifetime`, `exists`).
- **`ensureRouterAdvert`** — declaratively set the RA config for one interface.
  It reconciles to **exactly** the desired state (wipes the interface's RA
  subtree, then sets the desired paths in one session), so stale entries are
  removed and re-running with the same input is a true no-op (`changed=false`).
  Supports `dryRun`.
- **`removeRouterAdvert`** — delete all RA config for one interface.

**WireGuard** (`syncWireguard` / `ensureWireguard` / `removeWireguard`) manages
one `interfaces wireguard <if>` — address/port/mtu, `ipv6 adjust-mss`, and peers
(public-key, endpoint address/port, allowed-ips, keepalive, preshared-key). It
is **secret-bearing** (interface `private-key`, per-peer `preshared-key`), so
the whole `wireguard` resource is vaulted (`sensitiveOutput`, `vyos` vault) and
`ensure`/`remove` write their result to the vaulted `sensitiveApplyResult`. A
`vyos` vault must be configured. `ensureWireguard` reconciles declaratively like
`ensureRouterAdvert` (idempotent).

**Interface** (`syncInterface` / `ensureInterface`) manages the **scoped** L3
attributes of one `interfaces <type> <name>` — `address` (list, reconciled),
`description`, `mtu`, `disable`. It is deliberately scoped: `ensureInterface`
**never wipes the interface subtree**, so bridge members, `hw-id`, `vif`,
firewall assignments, etc. are left untouched (it reads current state to
reconcile only the address list). Full interface removal is intentionally left
to raw `apply --delete` rather than a typed method.

**Firewall** (`syncFirewall` / `ensureFirewall` / `removeFirewall`) manages one
named ruleset of the hook-based (VyOS 1.4+) firewall — `firewall <family> name
<name>`, where `family` is `ipv4` or `ipv6`. A ruleset is managed as **one
declarative unit**: `ensureFirewall` wipes the named-ruleset subtree and sets the
desired `default-action`, `description`, and numbered `rules` in one session, so
the ruleset ends up **exactly** as specified (rules you omit are removed) and
re-running the same input is a true no-op. Each rule models the common
match/target leaves — `action`, `protocol`, `state[]`, `source`/`destination`
(`address`, `port`, and `group` address-/network-/port-group), `inboundInterface`
/ `outboundInterface`, `jumpTarget`, `log`, `disable` — plus a `raw[]` escape
hatch for any leaf not modeled (appended verbatim under the rule). The
`firewallRuleset` resource is cleartext (a ruleset carries no secrets). Because
the whole ruleset is authoritative, always pass the **complete** set of rules (or
`syncFirewall` first and amend that state) — an omitted rule is a deletion.

```sh
# Preview a whole-ruleset reconcile (add/replace rules; omitted rules removed):
swamp model method run my-router ensureFirewall \
  --input family=ipv4 --input name=GUEST-FWD --input defaultAction=drop \
  --input rules='[
    {"num":10,"action":"accept","state":["established","related"]},
    {"num":30,"action":"accept","protocol":"tcp","state":["new"],
     "destination":{"address":"198.51.100.10","port":"1883"}},
    {"num":100,"action":"drop","state":["new"],
     "destination":{"address":"203.0.113.0/24"},"log":true}
  ]' --input dryRun=true

swamp model method run my-router syncFirewall --input family=ipv4 --input name=GUEST-FWD
```

```sh
# Declaratively pin an interface to a single prefix + default route
# (removes any stale prefixes, e.g. a leftover ::/64) — preview first:
swamp model method run my-router ensureRouterAdvert --input interface=eth1 \
  --input prefixes='[{"prefix":"2001:db8:1::/64"}]' \
  --input routes='["::/0"]' --input dryRun=true

swamp model method run my-router syncRouterAdvert --input interface=eth1
```

**NAT** (`syncNat` / `ensureNat` / `removeNat`) manages one NAT **direction**'s
rule list — `nat source` or `nat destination` (`direction` arg) — declaratively
as one unit, exactly like a firewall ruleset: `ensureNat` wipes the direction's
`rule` subtree and sets the desired rules, so the direction ends up **exactly**
as specified (omitted rules removed) and a repeat is a true no-op. Each rule
models `protocol`, `source`/`destination` (`address`, `port`, and `group`
address-/network-/port-group), `inboundInterface` / `outboundInterface`,
`translation` (`address` — an IP/range or the literal `masquerade` — and `port`),
`exclude`, `disable`, `log`, plus a `raw[]` escape hatch. Cleartext `natRuleset`
resource. As with firewall, pass the **complete** rule list (or `syncNat` first
and amend) — an omitted rule is a deletion.

```sh
# Preview a source-NAT (masquerade) reconcile:
swamp model method run my-router ensureNat --input direction=source \
  --input rules='[
    {"num":100,"outboundInterface":"eth0","source":{"address":"192.0.2.0/24"},
     "translation":{"address":"masquerade"}}
  ]' --input dryRun=true

swamp model method run my-router syncNat --input direction=source
```

**Static routes** (`syncStaticRoute` / `ensureStaticRoute` / `removeStaticRoute`)
manages one destination **prefix** — `protocols static route <prefix>` (IPv4) or
`route6 <prefix>` (IPv6), auto-selected from the prefix — declaratively, like
router-advert manages one interface. `ensureStaticRoute` wipes the prefix's
subtree and sets the desired `nextHops` (each with optional `distance` /
`disable` / `interface`), `interfaceRoutes`, `blackhole`, `dhcpInterface`, and
`description`, so the route ends up exactly as specified; a repeat is a no-op.
Cleartext `staticRoute` resource (its instance name slugifies `/` to `_`, e.g.
`192.0.2.0_24`, while the `prefix` field stays verbatim).

```sh
# Preview a static route with two weighted next-hops:
swamp model method run my-router ensureStaticRoute --input prefix=203.0.113.0/24 \
  --input nextHops='[
    {"nextHop":"192.0.2.1","distance":1},
    {"nextHop":"192.0.2.2","distance":10}
  ]' --input dryRun=true

swamp model method run my-router syncStaticRoute --input prefix=203.0.113.0/24
```

**DNS forwarding** (`syncDnsForwarding` / `ensureDnsForwarding` /
`removeDnsForwarding`) manages the `service dns forwarding` **singleton** (instance
name `current`) declaratively, like router-advert manages one interface:
`ensureDnsForwarding` wipes the `service dns forwarding` subtree and re-sets the
desired `listenAddress[]`, `allowFrom[]`, `nameServer[]`, `system`, `cacheSize`,
`dhcp[]` (interfaces to pull upstreams from), `dns64Prefix`, and per-`domains`
overrides (`nameServers[]`, `recursionDesired`, `addNta`), plus a `raw[]` hatch, so
the service ends up **exactly** as specified and a repeat is a true no-op. VyOS
renders some multi-value leaves as JSON arrays and others as objects keyed by value;
the parser normalizes both. Cleartext `dnsForwarding` resource.

```sh
# Preview the DNS-forwarding reconcile (omitted leaves are removed):
swamp model method run my-router ensureDnsForwarding \
  --input listenAddress='["192.0.2.1","2001:db8::1"]' \
  --input allowFrom='["192.0.2.0/24","2001:db8::/32"]' \
  --input nameServer='["192.0.2.53","2001:db8::53"]' \
  --input domains='[{"name":"example.com","nameServers":["192.0.2.53"],"recursionDesired":true}]' \
  --input dryRun=true

swamp model method run my-router syncDnsForwarding
```

**DHCP server** (`syncDhcpSharedNetwork` / `ensureDhcpSharedNetwork` /
`removeDhcpSharedNetwork` / `ensureStaticMappings`) manages one IPv4
`service dhcp-server shared-network-name <SNN>` (instance = the shared-network
name). `ensureDhcpSharedNetwork` is **whole-SNN declarative** — it wipes the SNN
subtree and re-sets the desired shared-network `options` and `subnets[]` (each with
its **mandatory** `subnetId`, `lease`, `options`, numbered `ranges[]`, and
`staticMappings[]`), so an omitted subnet or mapping is a deletion and a repeat is a
no-op. For the daily driver of adding/removing host reservations without disturbing
hand-edited ranges/options, **`ensureStaticMappings`** is a **scoped** fan-out: it
reconciles only the `static-mapping` children under one subnet (adds desired,
removes stale), never touching ranges/options/`subnet-id`. Cleartext
`dhcpSharedNetwork` resource. (IPv4 only; `dhcpv6-server` is a separate tree.)

```sh
# Whole shared-network reconcile (subnet-id is required per subnet):
swamp model method run my-router ensureDhcpSharedNetwork \
  --input name=SERVERS \
  --input options='{"nameServer":["192.0.2.53"]}' \
  --input subnets='[{"cidr":"198.51.100.0/24","subnetId":1,"lease":86400,
    "options":{"defaultRouter":"198.51.100.1"},
    "ranges":[{"n":0,"start":"198.51.100.100","stop":"198.51.100.200"}],
    "staticMappings":[{"name":"nas","ipAddress":"198.51.100.10","mac":"00:00:5e:00:53:01"}]}]' \
  --input dryRun=true

# Scoped: reconcile just the reservations under one subnet:
swamp model method run my-router ensureStaticMappings \
  --input sharedNetwork=SERVERS --input subnet=198.51.100.0/24 \
  --input mappings='[{"name":"nas","ipAddress":"198.51.100.10","mac":"00:00:5e:00:53:01"}]' \
  --input dryRun=true
```

**Container** (`syncContainer` / `ensureContainer` / `removeContainer`) manages one
`container name <name>` declaratively — `image`, `command`, `restart`, `hostName`,
`uid`/`gid`, the valueless flags (`disable`, `allowHostNetworks`, `allowHostPid`),
`capabilities[]`, `devices[]`, `environment[]`, `volumes[]` (`source`/`destination`
/`mode`), `networks[]`, `ports[]`, plus a `raw[]` hatch. Because a container's
`environment` commonly carries live secrets, the whole `container` resource is
**vaulted** (`sensitiveOutput`, `vyos` vault), exactly like WireGuard, and
`ensure`/`remove` write the vaulted `sensitiveApplyResult`; a `vyos` vault must be
configured. **Note:** committing container config regenerates the systemd unit and
may pull the image / restart the container — slow and disruptive, so run
image-changing `ensure`s deliberately.

```sh
# Preview a container reconcile (dryRun stages + compares, never restarts):
swamp model method run my-router ensureContainer \
  --input name=metrics-agent \
  --input image=docker.io/library/example-agent:1.0.0 \
  --input restart=on-failure --input allowHostNetworks=true \
  --input volumes='[{"name":"cfg","source":"/config/agent.yml",
    "destination":"/etc/agent.yml","mode":"ro"}]' \
  --input dryRun=true

swamp model method run my-router syncContainer --input name=metrics-agent
```

**Policy route (PBR)** (`syncPolicyRoute` / `ensurePolicyRoute` /
`removePolicyRoute`) manages one `policy route <name>` (IPv4) or `policy route6
<name>` (IPv6, auto-selected from the `family` arg) as **one declarative unit**,
like a firewall ruleset — it shares the firewall rule's `source`/`destination`
match schema (`address`, `port`, `group` address-/network-/port-group).
`ensurePolicyRoute` wipes the ruleset subtree and sets the desired `interface`,
`description`, `enableDefaultLog`, and numbered `rules[]` (`action`, `protocol`,
`source`/`destination`, `set` `table`/`mark`/`dscp`, `disable`, `log`, `raw[]`), so
an omitted rule is a deletion and a repeat is a no-op. Instance name is
`<family>-<name>` (e.g. `ipv4-mgmt`). **Note:** a policy-route ruleset only takes
effect once **bound** to an interface via `set interfaces <if> policy route <name>`,
which lives outside this subtree (on the interface) — the in-ruleset `interface`
leaf is modeled but is not that activation binding.

```sh
# Preview a PBR ruleset reconcile (omitted rules removed):
swamp model method run my-router ensurePolicyRoute \
  --input family=ipv4 --input name=mgmt --input interfaces='["eth1"]' \
  --input rules='[
    {"number":1,"action":"drop",
     "source":{"address":"192.0.2.10/32"},"destination":{"address":"203.0.113.5/32"}}
  ]' --input dryRun=true

swamp model method run my-router syncPolicyRoute --input family=ipv4 --input name=mgmt
```

## Sensitive output

By default an `apply` result stores `stdout`/`stderr` in cleartext and redacts
the generated script. When a change carries secrets (WireGuard/PKI private keys,
pre-shared keys), pass `sensitive=true`. The result is then written to the
`sensitiveApplyResult` spec, where the secret-bearing fields (`set`, `delete`,
`script`, `stdout`, `stderr`) are marked sensitive: their values are stored in a
vault named **`vyos`** and replaced with `${{ vault.get('vyos', …) }}`
references at persist time. Operational fields (`host`, `changed`, `committed`,
`exitCode`, …) stay in cleartext so the record is still glanceable.

Create the vault once before using the flag:

```sh
swamp vault create local_encryption vyos
```

`local_encryption` is a built-in, dependency-free AES-GCM backend; any other
configured vault type works too — just name it `vyos`. Without a `vyos` vault
configured, a `sensitive=true` apply fails at persist time.

`diff` takes the same `sensitive=true` flag (its `compare` output echoes the
staged `set` lines, which can include keys) — it writes to the `sensitiveDiff`
spec with `set`/`delete`/`diff`/`stderr` vaulted.

`tree` also takes `sensitive=true`. Because the full config tree is secret-laden
throughout, the sensitive variant vaults the **entire** record
(`sensitiveConfigTree`, `sensitiveOutput: true`) rather than selected fields.

## How it works

The model shells out to the host `ssh` binary. All SSH is deliberately isolated
in a single `sshExec()` helper: `show`/`run` send a remote argv, and `apply`
pipes a generated `vbash` script over stdin to `/bin/vbash -s`. Config sessions
source `/opt/vyatta/etc/functions/script-template` so `configure`/`set`/`commit`
resolve; op-mode reads use `/opt/vyatta/bin/vyatta-op-cmd-wrapper`.

**Prerequisites:** the host running swamp must reach the router over SSH with
key/agent auth (the model uses `BatchMode=yes` — no interactive prompts). Set
`identityFile` in the global arguments to pin a specific key, or rely on your
SSH agent / `~/.ssh/config`. When `identityFile` is set the model also passes
`IdentitiesOnly=yes`, so only that key is offered — this avoids tripping the
router's `MaxAuthTries` when your agent holds many keys (a common cause of "Too
many authentication failures"). The agent is still used to sign if it holds the
key.

**Note:** a `commit` on a router you are actively routing through can briefly
bounce `dhclient`, so an `apply` call may take a while to return.

## License

MIT — see LICENSE.txt for details.

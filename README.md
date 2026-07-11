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
  vault the secret-bearing fields (see below).
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

```sh
# Declaratively pin an interface to a single 0bed prefix + default route
# (removes any stale prefixes, e.g. a leftover ::/64) — preview first:
swamp model method run my-router ensureRouterAdvert --input interface=br10.95 \
  --input prefixes='[{"prefix":"2001:db8:bed:95::/64"}]' \
  --input routes='["::/0"]' --input dryRun=true

swamp model method run my-router syncRouterAdvert --input interface=br10.95
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

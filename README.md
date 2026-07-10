# @shrug/vyos

A swamp model for managing a [VyOS](https://vyos.io) router over SSH. It reads
the running configuration, applies `set`/`delete` configuration commands, and
runs arbitrary operational- or config-mode commands — encoding the VyOS quirks
so callers work in terms of plain config paths instead of `vbash` incantations.

VyOS is peculiar: configuration mode requires `vbash` sourcing the Vyatta
`script-template` (a plain `ssh host 'configure; set ...'` does **not** work),
and operational reads go through the `vyatta-op-cmd-wrapper`. This model hides
both requirements behind three methods.

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

# Apply a change: delete a config path, then commit + save
swamp model method run my-router apply \
  --input delete='["service router-advert interface eth1 prefix 2001:db8:1::/64"]'

# Run an arbitrary command (opMode=true wraps it for op-mode)
swamp model method run my-router run --input command="show interfaces" --input opMode=true
```

## Methods

- **`show`** — run an op-mode command (default `show configuration commands`)
  and snapshot the output to the `config` resource.
- **`apply`** — apply `set`/`delete` config paths through `vbash`, then `commit`
  and `save` (both toggleable). Requires at least one `set` or `delete`.
- **`run`** — run an arbitrary command over SSH; set `opMode=true` to prefix the
  VyOS op-mode wrapper.

## How it works

The model shells out to the host `ssh` binary. All SSH is deliberately isolated
in a single `sshExec()` helper: `show`/`run` send a remote argv, and `apply`
pipes a generated `vbash` script over stdin to `/bin/vbash -s`. Config sessions
source `/opt/vyatta/etc/functions/script-template` so `configure`/`set`/`commit`
resolve; op-mode reads use `/opt/vyatta/bin/vyatta-op-cmd-wrapper`.

**Prerequisites:** the host running swamp must reach the router over SSH with
key/agent auth (the model uses `BatchMode=yes` — no interactive prompts). Set
`identityFile` in the global arguments to pin a specific key, or rely on your
SSH agent / `~/.ssh/config`.

**Note:** a `commit` on a router you are actively routing through can briefly
bounce `dhclient`, so an `apply` call may take a while to return.

## License

MIT — see LICENSE.txt for details.

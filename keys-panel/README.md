# tproxy-keys

`tproxy-keys` manages the client keys of a `tproxy-server` deployment: the
relay's `profiles.json` and the matching official MTProxy `-S` secret list,
applied together and validated by the relay itself before anything goes live.
It ships as a CLI and a small loopback-only web UI on top of the same engine.

It is a separate Go module (`keys-panel/go.mod`) so it builds and versions
independently of the relay; `go build ./...` and `go test ./...` at the
repository root do not descend into it.

## Why this exists

- The relay reads `profiles.json` once at startup and does not reload it — a
  key change always needs a restart, which drops live carrier sessions.
- Adding a second client secret means official MTProxy needs a second `-S`
  argument, but the stock `mtproxy.service` unit passes exactly one secret
  through `-S ${MTPROXY_SECRET}`; systemd always expands `${VAR}` to a single
  argument, so several keys cannot be passed that way.
- The relay's admin listener (`/healthz`, `/readyz`, `/metrics`) has no
  endpoint for changing profiles, and profile metadata such as a human label
  can't live in `profiles.json` — the relay decodes it with
  `DisallowUnknownFields`, so any field it doesn't know about is rejected.

`tproxy-keys` exists to make "add a key," "revoke a key," and "rotate a key"
one operation instead of a multi-file, multi-service manual procedure.

## What it does

`add`, `revoke`, and `rotate` all go through the same apply path:

1. Validate the candidate name, secret, and carrier mode.
2. Write the candidate profile set to a temp file and validate it with the
   relay's own `/usr/local/bin/tproxy-server -config ... -profiles-file ...
   -check` — nothing bad ever reaches the live config.
3. Install it as `/etc/tproxy-server/profiles.json` (mode `0400`,
   `root:tproxy`, matching what the reference installer sets up).
4. Regenerate MTProxy's secret list and restart `mtproxy.service`.
5. Restart `tproxy-server.service` and poll `/readyz` for up to 25s.
6. On failure at step 4 or 5, restore the previous `profiles.json`, resync
   MTProxy from it, and restart again — so a failed apply doesn't leave the
   relay serving a profile set nobody chose.

Panel-only metadata (a label, the creation time) that can't live in
`profiles.json` is kept alongside it in `/etc/tproxy-keys/meta.json`, joined
to profiles by name.

## Install

Requires the same Go toolchain version the relay's own installer uses
(`go.mod` currently declares `go 1.24`) and, obviously, an existing
`tproxy-server` deployment — install that first via `deploy/install.sh` in the
repository root, or manually per the main [`README.md`](../README.md).

```bash
cd keys-panel
go build -trimpath -ldflags='-s -w' -o /usr/local/bin/tproxy-keys .
```

Install the MTProxy drop-in. This switches `mtproxy.service` from a single
`-S ${MTPROXY_SECRET}` to a list read from a file `tproxy-keys` maintains; see
the comment in the file for exactly why:

```bash
sudo install -d -m 0755 /etc/systemd/system/mtproxy.service.d
sudo install -m 0644 deploy/mtproxy-secrets.conf /etc/systemd/system/mtproxy.service.d/secrets.conf
```

Install and start the panel's own service. It runs as root — it writes
mode-`0400` root-owned configuration and restarts units — and binds only
`127.0.0.1:9000`; nothing about it is reachable without the SSH access that
already grants root on the host:

```bash
sudo install -m 0644 deploy/tproxy-keys.service /etc/systemd/system/tproxy-keys.service
sudo systemctl daemon-reload
sudo systemctl enable --now tproxy-keys.service
```

Bring MTProxy's secret list in line with the drop-in immediately, rather than
waiting for the first key change to discover it was out of sync:

```bash
sudo tproxy-keys sync
```

`deploy/install.sh` in the repository root now detects this drop-in
automatically: if you re-run it (for example after editing `--hostname`,
`--mtproxy-workers`, or the site) on a host where `tproxy-keys` is already
installed, it calls `tproxy-keys sync` for you after `profiles.json` is
rewritten. See [Interaction with `deploy/install.sh`](#interaction-with-deployinstallsh)
below for what that does and does not cover.

## Use

### CLI

```
tproxy-keys list                                 show every key with its client link
tproxy-keys add    -name N [-label L] [-mode M]   create a key and apply it
tproxy-keys revoke -name N                        delete a key and apply
tproxy-keys rotate -name N                        issue a new secret for an existing key
tproxy-keys link   -name N                        print the client link for one key
tproxy-keys status                                service and readiness overview
tproxy-keys sync                                  rebuild MTProxy secrets from profiles.json
tproxy-keys serve  [-listen 127.0.0.1:9000]        run the local web panel
tproxy-keys token                                 print the web panel access token
```

Carrier modes are the same ones the relay accepts in a profile: `https`
(default), `https-lanes`, `websocket`, `websocket-lanes`.

`add`, `revoke`, and `rotate` restart `mtproxy` and `tproxy-server`: live
carrier sessions drop, and clients reconnect on their own within a few
seconds.

### Web UI

The web UI binds loopback only — `serve` refuses a non-loopback `-listen` — so
reach it through an SSH tunnel:

```bash
ssh -N -L 9000:127.0.0.1:9000 <user>@<server>
```

Then open `http://localhost:9000` and enter the access token. The token lives
in `/etc/tproxy-keys/panel.token` (mode `0400`, created on first use); print it
with:

```bash
sudo tproxy-keys token
```

A session lasts 12 hours and lives in the panel process's memory, so it does
not survive `systemctl restart tproxy-keys` or a reboot — sign in again with
the same token.

## Security model

- **Loopback-only.** `serve` rejects a `-listen` address that isn't loopback,
  so exposing this beyond an SSH tunnel takes a deliberate code change, not a
  flag.
- **Host allowlist.** Every request must carry a `Host` header matching
  `127.0.0.1:<port>`, `localhost:<port>`, or `[::1]:<port>` for the configured
  port — this defeats DNS rebinding against the loopback listener.
- **CSRF token.** Every state-changing form carries a per-session token
  checked with a constant-time comparison; a request without a valid one is
  refused regardless of origin.
- **Opaque `Origin` is not rejected.** A browser sends `Origin: null` on some
  same-origin form submissions (this panel's `Referrer-Policy: same-origin`
  header avoids that case, but other browser behavior can still produce it);
  the Host allowlist and CSRF token are what actually gate a request, so an
  opaque origin is accepted and a mismatched non-opaque origin is still
  refused.
- **Runs as root.** It has to: it writes mode-`0400` `root:tproxy` config and
  restarts systemd units. This is not a privilege escalation risk beyond what
  SSH access to this host already grants — root over SSH can do everything
  this panel can, directly.

## Interaction with `deploy/install.sh`

Re-running the repository root's `deploy/install.sh` **always resets
`/etc/tproxy-server/profiles.json` to a single `default` profile** with
whatever secret it's given that run — this is existing, documented installer
behavior, not something `tproxy-keys` changes. Any additional keys you'd added
through the panel are gone from `profiles.json` after a reinstall, full stop.

What the installer's `tproxy-keys` integration *does* fix: without it, a
reinstall would leave official MTProxy's actual secret list (which
`tproxy-keys sync` maintains in `/etc/mtproxy/mtproxy-keys.env`, independent of
the installer) out of sync with the freshly-reset `profiles.json` — the relay
would expect one secret while MTProxy kept answering to a stale set. The
installer now calls `tproxy-keys sync` after writing `profiles.json` whenever
it detects the drop-in at `/etc/systemd/system/mtproxy.service.d/secrets.conf`,
so after a reinstall the two are at least consistent with each other, even
though consistent now means back down to one key.

If you want to keep an existing key set across a reinstall, back up first and
restore afterward:

```bash
sudo cp /etc/tproxy-server/profiles.json /etc/tproxy-keys/meta.json /root/tproxy-keys-backup/
# ... run deploy/install.sh ...
sudo cp /root/tproxy-keys-backup/profiles.json /etc/tproxy-server/profiles.json
sudo cp /root/tproxy-keys-backup/meta.json /etc/tproxy-keys/meta.json
sudo tproxy-keys sync
```

## Known limitations

- **No per-key statistics.** The relay's `/metrics` is process-wide, with no
  breakdown by profile, and MTProxy's own stats port is not enabled by the
  reference deployment. `tproxy-keys` can tell you which keys exist, not which
  ones are actually in use or how much traffic each one has carried.
- **No hot reload.** Every add, revoke, or rotate restarts both `mtproxy` and
  `tproxy-server`, briefly dropping every active carrier session on the host,
  not just the one belonging to the changed key.
- **One MTProxy backend.** All profiles in this setup point at the same
  `127.0.0.1:2398` official MTProxy. Giving a profile its own backend process
  for separate quotas or routing (as the main README's "Multiple secrets on
  one hostname" section describes) needs manual `profiles.json` and
  `firewall.nft` edits; `tproxy-keys` doesn't manage multiple backends.

## Troubleshooting

- **`relay rejected the configuration`**: the candidate `profiles.json` failed
  `tproxy-server -check`. The error message from the relay is included
  verbatim; nothing was written.
- **`the relay did not report ready within 25s`**: `mtproxy` or
  `tproxy-server` restarted but didn't come back healthy in time. Check
  `journalctl -u mtproxy -u tproxy-server --since '5 minutes ago'`. The
  previous `profiles.json` and MTProxy secret list are restored automatically;
  confirm with `tproxy-keys list` and `tproxy-keys status`.
- **Web UI shows `cross-origin request refused`**: reach the panel by the same
  host:port you tunneled to (`localhost:9000` and `127.0.0.1:9000` both work;
  a different hostname or port will not).
- **A key you added is missing after maintenance**: check whether
  `deploy/install.sh` was re-run — see
  [Interaction with `deploy/install.sh`](#interaction-with-deployinstallsh).

# Development guide

## Layout

```
cmd/pilens         service + CLI (serve, init, setup, reset-password, rlimit-exec)
cmd/pilens-helper  the only root component: typed network operations over a socket
internal/config    configuration + validation (shared by core and helper)
internal/netgen    renders NetworkManager / dnsmasq / nftables (pure, unit-tested)
internal/helper    core↔helper protocol + parsers
internal/store     SQLite open + migrations
internal/capture   capture engine, pcap/pcapng I/O, tshark, analysis, findings
internal/pcapfile  bounds-checked pcap/pcapng reader/writer
internal/sysinfo   unprivileged host/interface/health probes
internal/auth      Argon2id, TOTP, session tokens, login throttling
internal/api       HTTP API + static UI serving + SSE
web/               React + TypeScript + Vite UI (embedded via go:embed)
migrations/        ordered SQL, embedded
systemd/ scripts/ packaging/ docs/ tests/
```

## Prerequisites

Go ≥ 1.27 (the module pins toolchain 1.27.2), Node ≥ 20, Docker for the
integration suite. On a dev box you do not need tshark/dnsmasq/nftables unless
you run those tests directly.

## Common tasks

```sh
make test          # go vet + go test + tsc --noEmit (no external tools needed)
make test-docker   # tshark/dumpcap tests + netns integration suite (needs Docker)
make package       # cross-compile arm64, bundle UI + docs + scripts -> dist/*.tar.gz
cd web && npm run dev   # UI against a running appliance: PILENS_API=https://<pi>:8443 npm run dev
```

The dev loop used to build this on real hardware: `make package VERSION=x.y.z`,
`scp` the tarball to the Pi, run `install.sh --yes` (it upgrades in place,
keeping data), then drive the API or UI. `install.sh` backs up and rolls back.

## Design rules (that reviewers should enforce)

- **The core never runs as root.** Privileged actions go through the helper,
  which has a fixed set of typed operations and re-validates everything. No
  generic command execution, ever.
- **Never interpolate user input into a shell or SQL.** All execs use argv
  lists; all queries use bound parameters. tshark children run via
  `rlimit-exec` with resource limits and `no_new_privs`.
- **Original captures are immutable.** Packet blocks are copied byte-for-byte;
  derived data (summaries, dissection) is regenerable and clearly separated.
- **Be honest in the UI.** No fabricated data, no controls that do nothing, no
  claims the evidence doesn't support (e.g. TLS version, interception status,
  drop vs. UI-drop). A feature that isn't built is absent, not faked.
- **Validation lives in `internal/config` and runs twice** — in the core and
  again in the root helper, which does not trust the core.

## Adding a migration

Drop `migrations/NNN_name.sql`; it is applied in order on next start and
recorded in `schema_migrations`. Migrations run inside a transaction.

## Releasing

1. `make test && make test-docker` green.
2. `go run golang.org/x/vuln/cmd/govulncheck ./...` and `cd web && npm audit`.
3. `make package VERSION=x.y.z`; the tarball carries its own SHA-256.
4. Record hardware results in `docs/testing.md` only after actually running them.

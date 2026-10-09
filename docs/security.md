# Security and privacy model

Captured traffic can contain credentials, tokens, private messages, and
medical or financial data. PiLens treats the appliance as a privileged,
sensitive system.

## Trust boundaries

| Boundary | Untrusted side | Controls |
|---|---|---|
| Browser ↔ pilens | Management network | TLS, source allow-list (nftables **and** middleware), Argon2id passwords, session cookies `Secure; HttpOnly; SameSite=Strict`, CSRF token header, login throttling, optional TOTP, audit log |
| AP clients ↔ Pi | Wi-Fi network | nftables drops everything except DHCP, DNS and ICMP. Management is unreachable even through the uplink address. |
| pilens ↔ pilens-helper | pilens process | Unix socket 0660 root:pilens. `SO_PEERCRED` uid check. Fixed operations only. The helper re-validates the full config. Requests are capped at 1 MiB. |
| Packet data ↔ parsers | Anyone on the wire / uploaded files | Our pcap/pcapng readers bounds-check every length (16 MiB block cap). tshark runs via `rlimit-exec` (RLIMIT_AS, RLIMIT_CPU, no core dumps, `no_new_privs`) with a timeout and empty environment. |
| Packet data ↔ browser | Packet content | Rendered as text nodes by React. No `dangerouslySetInnerHTML` and no HTML preview. CSP `default-src 'self'`, `frame-ancestors 'none'`. |
| Uploads | Uploaded file | Size limit enforced while streaming. Magic-number check (pcap/pcapng only, no archives, so no decompression bombs). Server-generated file names, so no path traversal. Session IDs are strictly whitelisted (`^[0-9TZ]{16}-[0-9a-f]{6}$`). |

## Privilege separation

- **pilens** (user `pilens`): no root and no ambient capabilities. Capture uses
  `dumpcap`, whose file capabilities are granted to group `wireshark`, which is
  Debian's standard model. The unit's `CapabilityBoundingSet=CAP_NET_RAW
  CAP_NET_ADMIN` limits what any child can ever gain. `NoNewPrivileges` cannot
  be set because it would disable dumpcap's file capabilities.
  `ProtectSystem=strict` leaves only `/var/lib/pilens` writable.
- **pilens-helper** (root): about 400 lines. It can write the PiLens NM
  keyfile, its own state directory and `ip_forward`; run `nft`, `nmcli`, `iw`
  and `systemctl` with fixed argv; and nothing else. There is no generic
  command execution.
- **pilens-dnsmasq**: Debian's dnsmasq, which drops privileges itself.

## Secrets

| Secret | Where | Exposure |
|---|---|---|
| Admin password | Argon2id hash in SQLite (0640 pilens) | Never returned |
| Session tokens | Only the SHA-256 is stored | Cookie only |
| Wi-Fi passphrase | SQLite + helper state (0600 root) + NM keyfile (0600 root) | Write-only in the API. Never in a process argv. Redacted in diagnostics. |
| Setup token | `/var/lib/pilens/setup-token` (0600) | Deleted when the first admin is created |
| Management TLS key | `/var/lib/pilens/tls/mgmt.key` (0600) | Never exported. Separate from any future interception CA. |

## Data protection

- PiLens currently stores no decrypted payloads, because it decrypts nothing.
- Captures are deleted by retention (oldest unpreserved first) or explicitly
  by an admin, who must confirm. Deleting a session removes its files and all
  index rows.
- Exports, deletions, configuration changes, logins (including failures),
  password/TOTP changes and setup are recorded in the audit log.
- No telemetry. The only outbound traffic the appliance generates is what the
  OS already does (apt, NTP) and the DNS forwarding it performs for AP clients.

## Reviewed attack classes

| Class | Mitigation |
|---|---|
| Command injection | All execs use argv lists, never a shell. Filter strings are passed as single arguments and checked for control characters. Interface names are matched against `^[A-Za-z0-9_.-]{1,15}$`. |
| Config injection (dnsmasq/NM keyfile) | Every rendered value is strictly validated (SSID charset, hostnames as RFC 1123 labels, IPs parsed), so newlines cannot reach a config file. |
| SQL injection | Parameterised queries only |
| Path traversal | IDs are server-generated and whitelisted. Segment file names come from the database, not the client. |
| XSS via packet content | React text rendering, CSP, no HTML rendering of captured data |
| SSRF | The server makes no outbound requests based on user input |
| Auth bypass | Every `/api/*` route except health, setup status, first-admin creation and login goes through `requireAuth`. The setup endpoint needs the setup token, and the INSERT is conditional on no user existing (race-safe). |
| Resource exhaustion | Bounded SSE queues (slow clients drop updates, never capture). Bounded tshark feed. Per-process rlimits. Upload and request size limits. Storage quota and reserve. Filter cache capped at 16 entries. |
| Malicious pcap | Bounds-checked block reader, fuzz-style malformed-input tests, tshark resource limits |
| Lock-out | The API refuses a management configuration that would exclude the caller's own address |

Dependency inventory: Go modules `modernc.org/sqlite`, `golang.org/x/crypto`
(Argon2id) and `gopkg.in/yaml.v3`; npm packages `react` and `react-dom`, plus
`vite` and `typescript` at build time. Run `govulncheck ./...` and `npm audit`
before each release.

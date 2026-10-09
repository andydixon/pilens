# API

All endpoints are under `https://<pi>:8443/api/`. Except `GET /health`,
`GET /setup/status`, `POST /setup/admin` and `POST /auth/login`, every request
needs the session cookie. Every non-GET request also needs the
`X-CSRF-Token` header (value from `/auth/session` or the login response).
Unauthenticated POSTs need `X-Requested-With: pilens`. Bodies are JSON, limited
to 1 MiB, and unknown fields are rejected.

| Method & path | Purpose |
|---|---|
| `GET /health` | Liveness `{ok:true}` |
| `GET /setup/status` | `{needs_admin, setup_complete, version}` |
| `POST /setup/admin` | `{token, username, password, authorised:true}` → session |
| `POST /auth/login` | `{username, password, totp?}` → `{user, csrf}`; 401 `totp_required` |
| `POST /auth/logout` · `GET /auth/session` · `POST /auth/password {Current, New}` | |
| `POST /auth/totp/begin` · `/enable {Code}` · `/disable {Password}` | TOTP lifecycle |
| `GET /audit` | Last 500 audit events |
| `GET /events` | SSE stream: `packets` `{session, rows}`, `capture` (session object, every 1 s while capturing), `resync` (`{session}` or `{ui_dropped}`), `ping` |
| `GET /system/interfaces` | Detected interfaces, Wi-Fi capabilities, bootstrap management, caller address |
| `GET /system/health` | System, helper, capture, storage, upstream, forwarding state |
| `GET /network` | Current config (passphrase redacted) |
| `POST /network/validate` | `{valid, errors[]}`, including lock-out detection |
| `POST /network/apply` | Transactional apply. `{result:{applied, rolled_back, steps[], error}}`. 502 on failure (rolled back). |
| `POST /setup/complete` | Marks first-run done |
| `GET /ap/clients` · `PUT /devices/{mac} {Label, Notes}` | AP clients (leases + stations + labels) |
| `GET /captures` · `POST /captures {name, interfaces[], capture_filter, ring_segments}` | List / start |
| `POST /captures/live/stop` · `POST /captures/live/pause {Paused}` | |
| `POST /captures/import?name=` | Raw pcap/pcapng body |
| `GET /captures/{id}` · `PATCH {Name, Description, Tags, Notes, Preserved}` · `DELETE ?confirm={id}` | |
| `GET /captures/{id}/packets?offset&limit&filter` | Page of summary rows. With `filter`, `nums[]` gives packet numbers per position. |
| `GET /captures/{id}/packets/{n}` | `{detail:{row, bytes(hex), tree[], segment, note}, error?}` |
| `GET /captures/{id}/export?filter=` | pcapng (or pcap for pcap imports), original records |
| `GET /captures/{id}/manifest` · `POST /captures/{id}/verify` | Integrity |
| `POST /filters/validate {Kind: display|capture, Filter, Interface}` | tshark / dumpcap compile check |
| `GET/POST /filters/saved` · `DELETE /filters/saved/{id}` | Saved filters |
| `GET /storage` · `PUT /storage {max_bytes, reserve_bytes, segment_bytes, import_bytes}` | |

Tree nodes: `{label, field, show, pos, size, verified, children}`. `verified`
means the frame bytes at `pos..pos+size` were checked against tshark's raw
value, so highlighting them is accurate.

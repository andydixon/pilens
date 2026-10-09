# PiLens architecture

PiLens turns a Raspberry Pi into a routed Wi-Fi test network with packet capture
and analysis. This document records the decisions and the reasons for them.
Anything here that has not been checked on real hardware says so.

## Processes and privilege

```
             management LAN (TLS :8443, allow-listed subnets only)
                                │
┌───────────────────────────────▼────────────────────────────────┐
│ pilens (user "pilens", no root)                                 │
│   HTTP API + embedded React UI, auth, SQLite, SSE               │
│   capture engine: dumpcap ─stdout─▶ pcapng splitter ─▶ segments │
│                                        └─▶ tshark (per segment) │
│   dissection on demand: tshark -T pdml (rlimited child)         │
└───────────────┬─────────────────────────────────────────────────┘
                │ unix socket /run/pilens/helper.sock (SO_PEERCRED)
┌───────────────▼─────────────────────────────────────────────────┐
│ pilens-helper (root, small, fixed operations only)              │
│   apply_network: NM keyfile + dnsmasq conf + nft table, verify, │
│                  roll back on failure                           │
│   ap_stations, leases, status                                   │
└─────────────────────────────────────────────────────────────────┘
pilens-dnsmasq (DHCP + DNS for the AP interface only)
NetworkManager (owns the AP connection "pilens-ap")
```

* **The core never runs as root.** It captures by running `dumpcap`, which
  Debian ships with file capabilities (`cap_net_raw,cap_net_admin`) for members
  of the `wireshark` group. Because file capabilities are lost under
  `NoNewPrivileges`, the core unit does not set it. Instead it restricts its
  `CapabilityBoundingSet` to those two capabilities, so no child can gain more.
* **tshark parses hostile input** (live traffic, uploaded files). Every tshark
  child goes through `pilens rlimit-exec`, which sets `RLIMIT_AS`, `RLIMIT_CPU`
  and `PR_SET_NO_NEW_PRIVS` and then execs tshark. Every call also has a context
  timeout.
* **The helper is the only root component.** It takes typed JSON requests. It
  checks the peer uid, validates every request again (it does not trust the
  core), renders the configuration itself, and runs fixed argv lists. It has no
  generic command API.

## Networking

The Pi is a **router**, not a bridge. The AP interface has a static gateway
address; clients get DHCP and DNS from a dedicated dnsmasq instance bound only
to that interface.

| Concern | Owner | Why |
|---|---|---|
| AP radio | NetworkManager keyfile `pilens-ap` (`mode=ap`, `ipv4.method=manual`, `ipv6.method=disabled`) | NM is the supported network manager on Raspberry Pi OS Bookworm and later. We write a keyfile (0600) and `nmcli connection load` it. The Wi-Fi passphrase never appears in a process argv. |
| DHCP + DNS | `pilens-dnsmasq.service` | NM "shared" mode gives no reservations, query logging or overrides, and it adds its own NAT rules. We use `ipv4.method=manual` so NM runs no DHCP server, which means there are never two competing DHCP servers. Only `dnsmasq-base` is installed, so the distro's `dnsmasq.service` does not exist. |
| Firewall / NAT | nft table `inet pilens` | This is the only table we create or delete. Other tables are never flushed. |
| Forwarding sysctl | helper | It is enabled only after the PiLens table has loaded. It is not persisted in sysctl.d, so after a reboot nothing forwards until the rules are back. |

### Firewall semantics

In nftables a packet must survive every base chain on a hook: `accept` only
ends the current chain, but `drop` is final. Our chains use `policy accept` for
traffic that is not ours, so SSH and other host services are untouched. For
anything that enters through the AP interface we decide explicitly and end with
a `drop`. A permissive table added by someone else (Docker, NM) therefore cannot
open a path that we drop.

* AP → Pi: DHCP, DNS and ICMP echo only. Everything else is dropped, including
  the management port and SSH.
* AP → forward: only out of the uplink interface. Never to RFC 1918, link-local,
  CGNAT, multicast or the management subnets, unless the administrator adds an
  explicit allow CIDR. New connections are permitted only when forwarding mode is
  `internet`.
* IPv6 from AP clients is dropped in `forward`, and IPv6 is disabled on the AP
  interface. That closes the uninspected IPv6 escape path. IPv6 forwarding is
  not implemented.
* Management port: accepted only on the configured management interfaces from
  the configured source subnets, and dropped everywhere else. The core also
  checks the source address in middleware, as defence in depth.
* `pilens-helper.service` loads the last good ruleset in `ExecStartPre`, ordered
  `Before=network-pre.target`, so the rules are in place before NM brings up the
  AP.

### Transactional apply

`apply_network` is one helper operation:

1. Validate.
2. Render the NM keyfile, dnsmasq.conf and nft ruleset.
3. `nft -c` dry run.
4. Snapshot the current files.
5. Write the files atomically, load the ruleset, `nmcli connection load` + `up`,
   and restart dnsmasq.
6. Verify: the connection is `activated`, dnsmasq is active, the table is
   present, and forwarding matches the configured policy.
7. On any failure, restore the snapshot and re-apply it, then report both errors.

Management and uplink NM profiles are never modified.

## Capture engine

```
dumpcap -i IF [-f BPF] -w -  ──pcapng──▶ splitter ──▶ seg-000001.pcapng (sha256 while writing)
                                            │              seg-000002.pcapng …
                                            ├──▶ tshark -r - -T fields (summary, one process per segment)
                                            │         └─▶ SQLite packets(session,num,seg,off,…) ─▶ SSE batches
                                            └──▶ ISB drop counters
```

* **Original bytes are never modified.** Every packet block is written verbatim.
  On rotation, the SHB and IDBs are copied verbatim into the new segment, so
  each segment is a self-contained, valid pcapng file.
* **One tshark per segment** keeps tshark's memory bounded. tshark's
  conversation state otherwise grows without limit on long captures. The cost:
  TCP stream numbers and reassembly restart at segment boundaries. Summary rows,
  filters and the detail view all use the same per-segment dissection, so they
  agree with each other. Segments default to 64 MiB.
* **SQLite holds one summary row per packet** (number, segment, file offset,
  time, addresses, protocol, length, info). It does not hold dissection trees.
  The protocol tree comes from `tshark -T pdml` on demand.
* **Display filters are evaluated by tshark** (`-Y`), segment by segment. The
  results are cached per session and filter. PiLens does not implement its own
  filter language.
* **Hex ↔ field mapping.** The core reads frame bytes from the segment file at
  the indexed offset. A PDML field is highlighted only when the frame bytes at
  `pos..pos+size` equal its `value`. Fields from reassembled or decompressed
  data sources fail that check and are not highlighted.
* **Backpressure.** Each SSE subscriber has a bounded queue. When it is full,
  batches for that subscriber are dropped, counted as *UI drops*, and the client
  is told to resync from SQLite. Capture never waits for a browser. Capture
  drops (from dumpcap/ISB) and ingestion lag (packets written but not yet
  summarised) are reported separately.
* **Storage.** There is a global byte quota and a free-space reserve. When the
  quota is reached, the oldest *unpreserved* sessions are deleted. If nothing
  can be deleted, the capture stops with a visible error. Preserved sessions are
  never deleted automatically. Per-session ring mode (`ring_segments`) deletes
  that session's oldest segments and records which ones were rotated out.
* **Imports** keep the uploaded file unchanged as the session's only segment
  (pcap or pcapng), with its SHA-256. Magic number and size are checked before
  any parsing.

## Web

* TLS only, on `:8443`, with a self-signed management certificate generated on
  first start (ECDSA P-256). It is separate from any interception CA. The
  installer prints its fingerprint.
* Auth: Argon2id (64 MiB, t=2, p=2). Sessions are 256-bit random tokens; only
  their SHA-256 is stored. Cookies are `Secure; HttpOnly; SameSite=Strict`.
  CSRF uses a per-session token in the `X-CSRF-Token` header on every
  state-changing request. Optional TOTP (RFC 6238). Logins are rate-limited per
  IP and per user.
* First run needs a **setup token** that the installer generates and prints.
  Without it, anyone on the management LAN could race to create the admin.
* Live updates use SSE: stdlib only, automatic reconnect, and `Last-Event-ID`
  resync.
* React + TypeScript + Vite. The build is embedded in the Go binary with
  `go:embed`. There are no CDNs or external fonts.

## Decisions taken without a spec answer

| Decision | Default | Reason |
|---|---|---|
| Live transport | SSE | One-way server push is all that is needed. It's stdlib, and reconnect is built in. |
| Config storage | JSON document in SQLite `settings`, with a `last_good` copy | One validated struct, simple rollback. |
| WPA2+WPA3 transition mode | Not offered | NM AP-mode support depends on the driver. We offer WPA2 or WPA3, and WPA3 failure triggers rollback. |
| SSID characters | Printable ASCII without `\` or `;` | Avoids keyfile escaping ambiguity. |
| AP client SSH to Pi | Blocked | The AP network is the untrusted side. |
| Max clients | Not offered | NM has no setting for it. The UI says so. |

## Not yet implemented (phase 3+)

These pages are not in the navigation until they work: conversations / follow
TCP stream, DNS/TLS/HTTP explorers, statistics, findings, TLS interception
(modes B and C), and scheduling.

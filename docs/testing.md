# Testing

## Automated

| Command | What it covers | Needs |
|---|---|---|
| `make test` | Config validation, nft/dnsmasq/NM rendering, Argon2id, TOTP (RFC 6238 vector), throttling, helper parsers, pcap/pcapng reader incl. malformed input, API auth flow (setup token, authorised-use, CSRF, source allow-list, lock-out detection, logout, throttling), TypeScript typecheck | Go, Node |
| `make test-docker` | Everything above that needs tshark/dumpcap (import → index → filter → PDML with verified byte ranges → filtered export re-read by tshark → hash verify; live capture with segment rotation, counts agreement, per-segment validity), **plus** the netns suite below | Docker |

The netns suite (`tests/integration/run.sh`) builds an upstream/Pi/client topology from
veth pairs and runs the real `pilens` binary plus the configuration rendered by `pilens-helper`:
DHCP lease and options, DNS override, NAT to a public address, blocking of RFC 1918 /
management / IPv6 / inbound / Pi-SSH, management reachable only from the allowed subnet (not
from AP clients, not even via the uplink address), first-admin creation, capture on the AP
interface through the API, display filter, packet detail, export opened by tshark, integrity
check, CSRF rejection, deny mode, and survival of an unrelated nft table.

Not covered by automation: NetworkManager AP activation and its rollback (needs a real radio;
`mac80211_hwsim` is not available in containers), systemd unit behaviour, installer.

## Hardware acceptance checklist (Raspberry Pi)

Record date, Pi model, OS, PiLens version and the result for each item.

| # | Test | Expected |
|---|---|---|
| H1 | Fresh install on Pi OS Lite via SSH over Ethernet | Installer completes. Prints URL, fingerprint, token. Existing connections unchanged. |
| H2 | Wizard: create admin, apply AP | Steps all ✓. SSID visible. Ethernet SSH session not interrupted. |
| H3 | Phone joins the AP | Lease in the pool, Pi as DNS, internet works |
| H4 | Phone → LAN host (e.g. router admin page) | Blocked |
| H5 | Phone → `https://<pi-ap-ip>:8443` and SSH to the Pi | Blocked |
| H6 | Capture on wlan0 while browsing | Packets live in the UI. Export opens in desktop Wireshark. Verify = ok. |
| H7 | Cold boot | AP returns. Firewall table loaded before the AP (`journalctl -b -u pilens-firewall -u NetworkManager`). Forwarding works. |
| H8 | Power loss during capture | Session marked interrupted. Segment hashed. Earlier segments verify. |
| H9 | Unplug Ethernet for 1 min, replug | Dashboard shows no default route, then recovers. Clients keep their leases. |
| H10 | Client disconnects and reconnects | Device list updates. Same lease. |
| H11 | `kill -9` of pilens during a capture | systemd restarts it. Session interrupted. Forwarding unaffected. |
| H12 | Storage exhaustion (small quota) | Oldest unpreserved session deleted, or capture stops with an error. Preserved session intact. |
| H13 | Apply an invalid AP config (e.g. WPA3 on a radio without SAE) | Rolled back, previous AP restored, error shown |
| H14 | `uninstall.sh` then `install.sh` | Captures kept. Old Wi-Fi client profile works again after uninstall. |
| H15 | `repair.sh` after `setcap -r /usr/bin/dumpcap` | Capabilities restored |
| H16 | Throughput: iperf3 through the AP while capturing | Record Mbit/s, dumpcap drops, ingest lag |
| H17 | Import a 500 MB pcapng | Indexing time recorded. UI responsive. |

TLS-interception hardware tests belong to phase 4.

## Results log

Only tests that were actually run are listed.

### 2026-10-09 · Raspberry Pi 5 Model B Rev 1.0 (4 GB, NVMe) · Debian 13 trixie · kernel 6.18.34+rpt-rpi-2712 · NM 1.52.1 · tshark 4.4 · PiLens 0.1.0 → 0.1.3

| # | Result | Evidence / notes |
|---|---|---|
| H1 | **pass** | Installed over SSH via eth0. Existing connections untouched. Found a false "no AP mode" warning (check ran before `iw` was installed): fixed in 0.1.1/0.1.2. |
| H2 | **pass** (via API, not the browser wizard) | Apply: all 9 steps ✓. AP `PiLens-Lab` on ch 11 (auto), regdomain GB. Management SSH on eth0 never interrupted. |
| H3 | **pass** | iPhone and Apple Watch associated, leases .101 / .168 from the pool, both shown with randomised-MAC badges |
| H4 | not run | Needs a client to try a LAN address. Netns suite covers the rule. |
| H5 | partial | nft counter: 24 client→Pi packets dropped (mDNS etc.). No explicit SSH/8443 attempt from the phone. |
| H6 | **pass** (tshark), desktop Wireshark not tried | 1,654 packets, 0 drops. Export (1,272 packets at the time) read by tshark 4.4. Verify = ok. Fields from decrypted QUIC Initial CRYPTO frames were correctly marked unverifiable (50/181 verified). |
| H7 | **pass** | Reboot: `pilens-firewall` finished 18:20:33.7, NM started `pilens-ap` 18:20:38.9. All services active, forwarding on. |
| Upgrade with a running capture | **pass after fix** | 0.1.0→0.1.1 left the session marked *failed* (systemd SIGTERMed dumpcap directly). `KillMode=mixed` in 0.1.2 means a reboot now finalises the capture as *stopped* with dumpcap's drop report. Hashes ok. |
| H8 | not run (no hard power cut) | Covered partially by H11 |
| H11 | **pass** | `kill -9` of pilens during a capture: restarted by systemd, no stray dumpcap, segment recovered (4,562 packets), hashed, verify ok, marked *interrupted*. The session packet counter showed 0: fixed in 0.1.3 (reindex on recovery). |
| H12 | **pass** | Quota 64 MiB: the two unpreserved sessions were deleted oldest first (audited), the preserved session was kept, and the capture stopped with "storage limit reached … no unpreserved sessions remain". |
| H13 | **pass** | 5 GHz ch 165 in GB: NM activation failed, rolled back in 26 s, AP back on ch 11 with DHCP active. The error message was made actionable in 0.1.3. |
| H15 | **pass** | `setcap -r dumpcap` → `repair.sh` restored `cap_net_admin,cap_net_raw=eip`, all services ✓ |
| H9, H10, H14, H16, H17 | not run | |

The Raspberry Pi firmware throttle flags (`vcgencmd`) cannot be read by the service user on this
OS (`/dev/vcio` is 0600 root). PiLens reports the world-readable `rpi_volt` under-voltage alarm
instead.

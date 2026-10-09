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

Hardware results are recorded here only after they have actually been run. See the
release notes or commit log for the latest run.

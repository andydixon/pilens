# Network topology and policy

```
 upstream LAN / internet
          │ eth0 (uplink + management, DHCP client as before)
   ┌──────┴───────────────────────────────┐
   │ Raspberry Pi                          │
   │  nft table inet pilens                │
   │  NAT (masquerade) AP subnet → uplink  │
   │  pilens-dnsmasq: DHCP+DNS on wlan0    │
   └──────┬───────────────────────────────┘
          │ wlan0  AP "PiLens-Lab", 192.168.50.1/24 (static, NM keyfile)
     test device(s)  192.168.50.100–199
```

The Pi **routes**: it does not bridge. AP clients are always on their own subnet
behind NAT, so every packet they send crosses the Pi's IP stack. That is what
makes capture and policy enforcement complete.

## Interface discovery

Interface names are discovered, not assumed. The installer picks:

- **Uplink**: the interface holding the IPv4 default route.
- **Management**: the interface your SSH session arrived on, falling back to the
  uplink. The default allowed sources are that interface's connected subnet,
  plus your SSH client's /32 if it lies outside that subnet (for example when
  you connect through NAT or a VPN).
- **AP**: the first interface with `/sys/class/net/<if>/wireless`.

All three can be changed in the wizard or under Network Settings. Validation
rejects an AP interface that is also used for management or uplink, and any AP
subnet that overlaps a management subnet.

## Firewall rules, in words

| Traffic | Decision | Why |
|---|---|---|
| AP client → Pi UDP 67 (DHCP) | accept | Address assignment |
| AP client → Pi gateway :53 (DNS) | accept | Resolution through the Pi, so DNS is observable |
| AP client → Pi ICMP echo / errors | accept | Basic diagnostics |
| AP client → Pi anything else (SSH, :8443, …) | **drop** | The AP network is untrusted |
| AP client IPv6 (to the Pi or forwarded) | **drop** | IPv6 is not inspected, so it is closed rather than left open |
| AP client → private / link-local / CGNAT / multicast / management nets | **drop** | Clients cannot pivot into your LAN |
| AP client → explicit `allow_cidrs` | accept | An opt-in exception, e.g. a lab server |
| AP client → public addresses via uplink | accept when mode = `internet` | The purpose of the gateway |
| AP client → anything, mode = `deny` | **drop** | Observe-only lab mode (DHCP and DNS still work) |
| Anything → AP subnet, not a reply | **drop** | No inbound connections to clients |
| Any interface → :8443 from a non-allowed source | **drop** | Management isolation |
| Everything else | not touched by PiLens | Host SSH and other services keep their policy |

Multicast, broadcast and mDNS from clients are not forwarded. DHCP broadcasts
reach dnsmasq because they are delivered locally, not forwarded. With **client
isolation** enabled, the Wi-Fi driver stops clients talking to each other
directly. Without it, client-to-client frames on the same radio never reach the
IP layer, but they are still visible to a capture on the AP interface.

Rules are applied atomically: one `nft -f` both deletes and recreates the
table. A ruleset that fails `nft -c` is never loaded.

## Failure behaviour

| Event | Result |
|---|---|
| Ethernet unplugged / upstream gateway unreachable | Clients keep DHCP and DNS (answers from cache or overrides; other lookups fail). Forwarded traffic has no route and fails. The dashboard shows "no default route". |
| DNS upstream fails | dnsmasq returns SERVFAIL. Visible in captures. |
| Capture engine crashes | Forwarding is unaffected in capture-only mode. Interrupted segments are hashed and closed on restart, and the session is marked *failed / interrupted*. |
| Storage exhausted | The oldest unpreserved sessions are deleted. If none are left, capture stops with an explicit error. Forwarding continues. |
| Network apply fails | Automatic rollback to the previous NM keyfile, dnsmasq config and nft table, and the failure is reported with each step. |
| Firewall restore fails at boot | `pilens-firewall.service` fails, but **IPv4 forwarding stays disabled** (it is never persisted), so clients cannot be routed. |
| Reboot | `pilens-firewall` loads the last good table before NetworkManager starts the AP. Forwarding is enabled only after that. |
| Helper unavailable | The UI shows forwarding state "unknown". The last loaded table stays in force. |

TLS-proxy related behaviour (mode B/C) belongs to a later phase.

## IPv6

IPv6 forwarding and inspection are not implemented. The AP profile sets
`ipv6.method=disabled`, so clients get no router advertisements from the Pi,
and the firewall drops any IPv6 a client sends. Clients therefore fall back to
IPv4, which is fully routed and captured.

## Regulatory domain

The country code is applied with `iw reg set` on every apply and at boot. Set
it correctly: it determines the legal channels and transmit power.

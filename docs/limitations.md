# Known limitations (v0.1)

**Encryption.** PiLens captures packets; it does not decrypt them. HTTPS, QUIC/HTTP-3, TLS 1.3 with
Encrypted ClientHello, DNS-over-HTTPS/TLS, and VPN traffic are visible only as encrypted
packets plus whatever metadata the protocol exposes in clear (for TLS ≤1.3 without ECH: SNI,
versions, ALPN; for TLS 1.2: certificates). The optional HTTPS inspection mode (client-installed
CA via mitmproxy) is **not implemented** in this version, and even when it is, it will not work
against certificate pinning, private trust stores, mutual TLS, QUIC, or apps that bypass proxies.

**Not yet implemented:** HTTP explorer, findings/diagnostics rules, capture scheduling,
the strict inspection mode, WireGuard, packet comparison. They are not shown in the UI.

**TLS explorer shows metadata only.** SNI, ALPN, negotiated version and cipher, plus any
certificate sent in the clear (TLS ≤1.2). TLS 1.3 encrypts the certificate, so the certificate
tab is usually empty — this is expected, not a fault. "Follow TCP stream" reconstructs the
transport payload, which for TLS is ciphertext.

**IPv6** is blocked for AP clients rather than routed (see network.md).

**AP features.** Max-client limits are not available through NetworkManager. WPA2/WPA3
transition mode is not offered. WPA3 (SAE) in AP mode depends on the Wi-Fi driver and
firmware. On the Raspberry Pi's brcmfmac it may fail, in which case the change is
rolled back.

**Capture.**
- One live capture at a time.
- Display filters on large captures run tshark over every segment. That takes seconds per GiB
  on a Pi 4/5, and results are cached per filter.
- The packet table's scroll height is limited by browser element-size limits (about 1.5 million
  rows at compact density). Use a display filter for larger captures.
- Capture drop counts are reported by dumpcap when the capture stops, not live.

**Performance figures** have not yet been measured on hardware, so none are claimed.
`docs/testing.md` lists the benchmarks to run.

**Single administrator role.** Every account has full rights.

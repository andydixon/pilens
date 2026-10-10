# Known limitations (v0.1)

**Encryption.** PiLens captures packets; it does not decrypt them. HTTPS, QUIC/HTTP-3, TLS 1.3 with
Encrypted ClientHello, DNS-over-HTTPS/TLS, and VPN traffic are visible only as encrypted
packets plus whatever metadata the protocol exposes in clear (for TLS ≤1.3 without ECH: SNI,
versions, ALPN; for TLS 1.2: certificates). The optional HTTPS inspection mode (Mode B) **is** available: enable it on the Certificates page,
install the appliance CA on each authorised test device, and decrypted transactions appear in the
HTTP Explorer. It does **not** work against certificate pinning, private trust stores, mutual TLS,
QUIC/HTTP-3, or apps that bypass the proxy — these are reported honestly as not intercepted, never
bypassed. It is off by default; while off, PiLens is pure capture-only.

**Not yet implemented:** the strict inspection mode (Mode C fail-closed policy), capture scheduling,
WireGuard, packet comparison. They are not shown in the UI.

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

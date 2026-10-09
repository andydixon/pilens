# Encryption: what PiLens can and cannot see

Short version: in capture-only mode PiLens shows you **packets and metadata**,
never decrypted application content. This page explains why, because it is the
single most common misunderstanding about a tool like this.

## Two completely separate kinds of TLS

1. **Management TLS** — the HTTPS you use to reach the PiLens web UI on :8443.
   PiLens generates its own self-signed certificate for this on first start
   (ECDSA P-256, 5-year). It protects *your* connection to the appliance and is
   unrelated to anything captured. The installer prints its SHA-256 fingerprint;
   verify it the first time your browser warns about it.

2. **Interception CA** — a separate authority that *would* let PiLens decrypt a
   test device's HTTPS, by having that device explicitly trust it. **This is not
   implemented in this version** (Phase 4). When it is, it will be opt-in,
   per-device, and require you to install and trust the CA on the client
   yourself. There is no way to do it silently.

The two are kept independent on purpose: compromising or distributing an
interception CA must never affect the management channel.

## Why HTTPS content is unavailable without client trust

TLS exists precisely to stop a device in the middle from reading traffic. To
decrypt it, the middle device must present a certificate the client trusts —
which means the client must have been configured, by its owner, to trust
PiLens's CA. Without that explicit step, PiLens sees only:

- The **TLS handshake** metadata sent in clear: SNI (the server name, unless
  Encrypted ClientHello is used), offered/negotiated version, cipher, ALPN.
- The **certificate** the server sends — but only for TLS 1.2 and earlier. TLS
  1.3 encrypts the certificate, so the TLS Explorer's certificate tab is usually
  empty for modern servers. That is expected.
- Everything after the handshake as **ciphertext**. "Follow TCP stream" will
  show it, clearly labelled as encrypted transport bytes, not content.

## Cannot be sent via DHCP

A trusted root CA **cannot** be delivered or installed through DHCP, a captive
portal, or any network mechanism. No mainstream OS will trust a CA handed to it
by the network — doing so would defeat TLS entirely. Trust is always a manual,
explicit action by the device owner. This is a feature, not a limitation.

## QUIC and HTTP/3

QUIC carries HTTP/3 inside TLS 1.3 over UDP. PiLens captures it and reads the
clear handshake fields (SNI, ALPN), and labels it `TLS 1.3 (QUIC)`. The payload
is encrypted. Many apps prefer QUIC, so a lot of "web" traffic appears as QUIC
rather than TCP/TLS.

## Encrypted DNS (DoH / DoT)

If a client uses DNS-over-HTTPS or DNS-over-TLS, its lookups are inside TLS to a
resolver and do **not** appear in the DNS Explorer — they look like HTTPS/QUIC to
that resolver's address. Only cleartext DNS through the appliance's resolver is
observable. PiLens never presents encrypted DNS as if it were cleartext.

## Certificate pinning

Some apps pin to a specific certificate or key and will refuse *any* substitute,
including a trusted interception CA. When Phase 4 lands, such connections will be
reported honestly as failed/pinned rather than silently bypassed — PiLens will
never weaken a client's TLS to force a connection through.

## IPv6

IPv6 is not inspected, so it is disabled on the AP and dropped in the firewall
(see [network.md](network.md)). Clients fall back to IPv4, which is fully
captured. This avoids an uninspected escape path.

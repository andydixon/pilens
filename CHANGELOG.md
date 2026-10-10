# Changelog

## 0.4.0 — 2026-10-10 (Phase 4: authorised HTTPS inspection, Mode B)
- Toggleable transparent HTTPS interception via mitmdump in a venv. Off by default.
- Own RSA-2048 CA generated in-app (`PiLens Interception CA`), downloadable public
  cert with per-OS install guide + fingerprint; private key never leaves the box.
- nftables redirect accepts only dnat'd connections (never an open proxy); the
  proxy's own upstream never loops.
- HTTP Explorer: transactions with headers and opt-in body viewers (JSON/text/hex/
  image, sandboxed). Bodies off by default. Pinned/untrusting = reported errors.
- Verified on the Pi 5: a CA-trusting client's HTTPS decrypted (TLS 1.3), an
  untrusting client honestly reported as a TLS failure.

All notable changes. Dates are when the work was done on the reference Pi 5.

## 0.3.1 — 2026-10-09
- Benchmark harness (`scripts/benchmark.sh`, python3-only) and measured figures
  in `docs/benchmarks.md`.
- `MemoryAccounting=yes` on `pilens.service`.

## 0.3.0 — 2026-10-09 (Phase 5: hardening)
- **Findings** diagnostics page: observable TCP/DNS/TLS/ICMP events and capture
  drops, each with evidence packets, a reproducing filter and benign-cause notes.
  Explicitly a forensic aid, not an IDS.
- Pinned Go toolchain 1.27.2 — 0 called standard-library vulnerabilities
  (govulncheck); `npm audit` clean.

## 0.2.1 — 2026-10-09
- TLS Explorer reports the true negotiated version from `supported_versions`
  (and labels QUIC as TLS 1.3), instead of the compatibility record version.
  Captures the QUIC server port.

## 0.2.0 — 2026-10-09 (Phase 3: analysis)
- Conversations (TCP/UDP, cross-segment, per-direction bytes) from the index.
- Follow TCP Stream via tshark reassembly, labelled as transport bytes.
- DNS Explorer (cleartext), TLS Explorer (metadata only), Statistics (SVG charts).

## 0.1.3 — 2026-10-09
- Reindex interrupted sessions on restart and correct packet counts.
- Actionable access-point activation errors.

## 0.1.2 — 2026-10-09
- `KillMode=mixed` so shutdown/upgrade finalises a running capture as *stopped*.
- `dumpcap -F pcapng`; installer AP-mode check runs after `iw` is installed.

## 0.1.1 — 2026-10-09
- `rpi_volt` under-voltage fallback where `vcgencmd` is root-only.
- dnsmasq bound to the AP interface only (`except-interface=lo`).

## 0.1.0 — 2026-10-09 (Phases 1–2)
- Installer/uninstaller/repair/diagnose, systemd units, transactional network
  helper with rollback, Argon2id auth + TOTP + CSRF + source allow-list.
- Access point, DHCP/DNS, nftables firewall (default-deny, IPv6 blocked for
  clients), management isolation.
- dumpcap capture to hashed pcapng segments, tshark dissection with verified
  byte ranges, Wireshark display filters, export/import, crash recovery.
- React analyser (packet list / protocol tree / hex), setup wizard, device,
  health, library and settings pages.

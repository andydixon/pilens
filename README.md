# PiLens

PiLens turns a Raspberry Pi into a self-contained Wi-Fi test network with packet
capture and Wireshark-grade analysis in the browser. You connect an **authorised**
test device to the Pi's access point and watch its traffic: live packets, a
protocol tree from TShark, and the original bytes with field highlighting. The
original captures are kept unmodified, with SHA-256 integrity hashes.

No cloud service, account or internet connection is needed for management,
capture or analysis.

> **Use it only on devices and networks you own or are explicitly authorised to
> inspect.** PiLens has no covert, impersonation or credential-harvesting
> features. Encrypted traffic (HTTPS, QUIC, VPNs, encrypted DNS) stays encrypted:
> in this version PiLens shows packets and metadata, not decrypted content.

## Status

| Phase | Scope | State |
|---|---|---|
| 1 | Installer, services, auth, AP / DHCP / DNS / firewall, health | implemented |
| 2 | dumpcap capture, pcapng storage, live analyser, filters, export / import | implemented |
| 3 | Conversations, follow TCP stream, DNS/TLS explorers, statistics | implemented (HTTP explorer deferred) |
| 4 | Optional HTTPS inspection (mitmproxy, client-trusted CA) | not started |
| 5 | Hardening, Findings, benchmarks, dependency audits | implemented |

HTTP Explorer (Phase 3 in the spec) is deferred with Phase 4, since useful HTTP content requires interception. Pages for later phases are not in the UI. PiLens never shows controls that do
nothing. For what was tested and how, see [docs/testing.md](docs/testing.md).

## Quick start

On a Raspberry Pi 4/5 with Raspberry Pi OS Lite (64-bit, Bookworm or Trixie),
connected by **Ethernet**:

```sh
tar xzf pilens-<version>-linux-arm64.tar.gz
cd pilens-<version>-linux-arm64
sudo ./install.sh
```

The installer prints the management URL, the certificate fingerprint and a
one-time setup token. Open the URL from a machine on the management network and
complete the setup wizard. The wizard creates the access point and turns the
Wi-Fi interface into the AP, so **manage the Pi over Ethernet**.

For unattended installation: `sudo ./install.sh --non-interactive --config setup.yaml`
(see `setup.example.yaml`).

## Building

Requirements: Go ≥ 1.24, Node ≥ 20. Docker is used only for the test suite.

```sh
make package            # dist/pilens-<ver>-linux-arm64.tar.gz (cross-compiled, static)
make test               # unit tests + TypeScript typecheck
make test-docker        # tshark/dumpcap tests + network-namespace integration suite
```

## Documentation

- [Architecture and design decisions](docs/architecture.md)
- [Installation, first run, upgrade and recovery](docs/operations.md)
- [Network topology and firewall policy](docs/network.md)
- [Security and privacy model](docs/security.md)
- [Forensic evidence handling](docs/forensics.md)
- [API](docs/api.md)
- [Benchmarks](docs/benchmarks.md)
- [Testing and hardware acceptance checklist](docs/testing.md)
- [Known limitations](docs/limitations.md)

## Licence

AGPL-3.0-or-later. Bundled JavaScript dependencies (React, MIT) are compatible.
TShark/dumpcap (GPL-2.0+), dnsmasq (GPL-2.0/3.0) and nftables (GPL-2.0) are
installed from Debian packages and run as separate programs.

# Operations: install, first run, upgrade, recovery

## Requirements

- Raspberry Pi 4 or 5 (other arm64 Debian systems with NetworkManager and an AP-capable radio
  may work but are untested)
- Raspberry Pi OS Lite 64-bit, Bookworm or Trixie, with NetworkManager (the default)
- Ethernet connected to the network you will manage it from
- ≥ 1 GiB free disk. An SSD (USB 3 or NVMe) is strongly recommended for captures: SD cards
  are slow and wear out.

## Install

```sh
tar xzf pilens-<ver>-linux-arm64.tar.gz && cd pilens-<ver>-linux-arm64
sudo ./install.sh                # explains every change and asks first
```

What it does, in order: checks the platform; detects interfaces and your SSH path; checks AP
support, disk, RAM and conflicting services; shows the plan; backs up
`/etc/NetworkManager/system-connections` and `nft list ruleset` to
`/var/backups/pilens/<time>/`; installs `tshark wireshark-common nftables dnsmasq-base iw`
from apt; installs PiLens to `/opt/pilens`; creates user `pilens`; installs systemd units;
initialises the database and TLS certificate; starts the services and checks they are healthy.
If any step fails, the trap rolls back (on an upgrade, the previous version is restored).

It does **not** touch existing network connections. The access point is created by the
wizard.

Options: `--mgmt-iface eth0 --mgmt-subnet 192.168.1.0/24` to override detection, `--yes`,
`--non-interactive --config setup.yaml`.

## First run

Open the URL printed by the installer and compare the certificate fingerprint. The wizard
asks for the setup token, creates the administrator, and then walks through management access,
uplink, Wi-Fi, client subnet, forwarding, inspection mode and storage. "Apply" performs the
transactional network change. If the browser loses power or the page reloads, the wizard
resumes: progress is kept in the browser, and the server holds what has actually been applied.

## Upgrade

Run the new package's `install.sh`. It detects the existing installation, keeps
`/var/lib/pilens`, replaces the binaries and units, and restarts. Migrations run automatically
on start. If the health check fails, the previous version is restored from the backup.

## Recovery

| Problem | Action |
|---|---|
| Services unhealthy, permissions wrong, dumpcap lost capabilities | `sudo /opt/pilens/repair.sh` |
| Forgotten password | `sudo -u pilens /opt/pilens/bin/pilens reset-password -user admin` (also disables TOTP and revokes sessions) |
| Locked out by the management subnet | On the console: `sudo nft delete table inet pilens`, then fix the subnet in the UI and apply. The table is restored at the next apply or reboot. |
| AP broken after a manual NM change | Re-apply from Network Settings, or `sudo nmcli connection up pilens-ap` |
| Need to return the Wi-Fi to client mode | `sudo nmcli connection down pilens-ap`. Your earlier Wi-Fi profile was never modified. |
| Bug report | `sudo /opt/pilens/diagnose.sh` (secrets redacted) |
| Remove | `sudo /opt/pilens/uninstall.sh` (keeps captures) or `--purge` |

The database is `/var/lib/pilens/pilens.db` (SQLite, WAL). To back it up: stop `pilens`, then
copy `pilens.db*` and `captures/`.

## Capture storage on an SSD

```sh
sudo systemctl stop pilens
sudo mkdir -p /mnt/ssd/pilens-captures && sudo chown pilens:pilens /mnt/ssd/pilens-captures
sudo systemctl edit pilens
#   [Service]
#   ExecStart=
#   ExecStart=/opt/pilens/bin/pilens serve -data /var/lib/pilens -listen :8443 -captures /mnt/ssd/pilens-captures
#   ReadWritePaths=/mnt/ssd/pilens-captures
#   [Unit]
#   RequiresMountsFor=/mnt/ssd/pilens-captures
sudo systemctl start pilens
```

## Service architecture and shutdown

`pilens-firewall` (oneshot, before networking) → `pilens-helper` (root) → `pilens-dnsmasq` →
`pilens` (Type=notify, watchdog 60 s). On SIGTERM, pilens stops accepting requests, stops any
capture (dumpcap flushes, the last segment is fsynced and hashed), and then exits. The timeout
is 60 s.

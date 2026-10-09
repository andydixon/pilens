# Troubleshooting

Run `sudo /opt/pilens/diagnose.sh` first — it bundles logs and state with
secrets redacted. Then:

| Symptom | Check | Fix |
|---|---|---|
| Web UI won't load | `systemctl status pilens`; is your source IP in the management subnet? | `sudo /opt/pilens/repair.sh`; widen the subnet from the console if locked out (see operations.md) |
| Browser certificate warning | Expected (self-signed). Compare the fingerprint the installer printed. | Trust it for this host, or import `/var/lib/pilens/tls/mgmt.crt` |
| Can't log in | — | `sudo -u pilens /opt/pilens/bin/pilens reset-password -user admin` |
| Locked out by `429` | Login throttling after failures | Wait the stated time, or restart `pilens` to clear the limiter |
| No clients get an address | `systemctl status pilens-dnsmasq`; another DHCP server on the AP link? | `repair.sh`; ensure no stray `dnsmasq`/`hostapd` is running |
| AP won't start | `journalctl -u NetworkManager`; radio AP-mode and band/country support | Try WPA2 / 2.4 GHz / a permitted channel; failed applies roll back automatically |
| Clients associate but no internet | Dashboard "forwarding" card; Ethernet default route up? | Check the uplink; `forwarding` must read "forwarding", not "blocked" |
| Capture shows drops | System Health / Findings; CPU or SD-card bound | Use a capture filter; capture to an SSD (operations.md) |
| "interrupted" sessions after power loss | Expected: segments are hashed and re-indexed on restart | Verify hashes in Capture Library → Integrity |
| High CPU / slow filters | Large capture; tshark re-reads segments | Filter narrows after the first run (cached); smaller segment size helps |
| Under-voltage warning on dashboard | `rpi_volt` alarm | Use the official PSU; under-voltage corrupts storage and drops packets |

If a network change ever leaves the appliance unreachable, every apply keeps a
backup and rolls back on failure; the last-known-good firewall is also restored
at boot before the AP starts.

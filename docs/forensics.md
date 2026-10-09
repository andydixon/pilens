# Forensic evidence handling

## What is evidence and what is derived

| Data | Status |
|---|---|
| `captures/<session>/seg-NNNNNN.pcapng` (live) | **Original**. dumpcap's pcapng output, written byte for byte. Each segment starts with the section and interface headers copied verbatim, so it opens on its own. |
| `captures/<session>/original.pcap[ng]` (import) | **Original as received**. The uploaded file, unchanged. |
| SHA-256 per segment | Computed while writing, and over the whole file for imports. Stored in SQLite. |
| Packet summary rows (SQLite) | Derived: tshark output, regenerable |
| Protocol trees, filters, exports with a filter | Derived. A filtered export copies the original packet records verbatim, but as a selection it is a new file. |

PiLens never labels reconstructed or synthetic data as an original capture.

## Recorded metadata (per session)

Session `meta` and the manifest record:

- UTC start/stop (milliseconds), capture interfaces and capture filter
- PiLens and TShark versions, hostname
- `clock_synchronised` from `timedatectl` at start. If this is not `yes`,
  absolute timestamps may be wrong. A Pi has no battery-backed clock, so make
  sure NTP is working before you capture evidence.
- Segment size, ring-buffer setting, pause/resume log, packets discarded while
  paused
- dumpcap's own "received/dropped" report, verbatim (kernel and pcap drops)

## Verifying

- UI: Capture Library → *Integrity* → *Verify hashes now*. This recomputes
  SHA-256 for every complete segment.
- Manifest: *Download manifest* gives JSON with every file, its hash, packet
  count and the metadata above.
- Offline: `sha256sum seg-*.pcapng` and compare with the manifest.

## Caveats

- **Capture loss** happens under load. Check the drop report. A capture with
  drops is incomplete.
- **Segment boundaries**: summaries and dissections are computed per segment,
  so TCP stream indices and reassembly restart at each boundary. The packet
  bytes are unaffected.
- **Interrupted captures** (power loss): on restart, the last segment is
  scanned, counted and hashed as found, and the session is marked
  `interrupted`. A truncated final packet record may be present.
- **Pause capture** discards packets while paused. The pause log in the
  session metadata records when.
- **Randomised MAC addresses** do not identify hardware. PiLens never merges
  device identities automatically.
- DNS answers do not prove which host a later connection went to.

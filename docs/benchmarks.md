# Benchmarks

Numbers below were measured, not estimated. Reproduce them with
`scripts/benchmark.sh https://127.0.0.1:8443 admin <<<"$PASSWORD"` on the
appliance, and `BENCH_MB`/`BENCH_LOOPS` to change the load. Results are
hardware- and load-dependent; treat them as a baseline, not a guarantee.

## Test rig

- Raspberry Pi 5 Model B Rev 1.0, 4 cores, 4.0 GiB RAM, NVMe SSD for captures
- Debian 13 (trixie), kernel 6.18, TShark 4.4, PiLens 0.3.1
- 2026-10-09

## Memory (idle, measured from `/proc/<pid>/status` VmRSS)

| Process | Idle RSS | Peak during 263 MB capture + dissection (VmHWM) |
|---|---|---|
| `pilens` (web + capture engine) | **26 MB** | 185 MB |
| `pilens-helper` (root) | 5 MB | — |
| `pilens-dnsmasq` | 4.5 MB | — |

Idle footprint is ~36 MB total. Peak is bounded by one tshark child per segment
plus SSE batches; it does not grow without limit on long captures.

## Capture throughput (loopback, worst case)

Capturing a 263 MiB bulk transfer over `lo`:

| Metric | Value |
|---|---|
| Packets | 10,186 written |
| Throughput | ~108 MB/s, ~4,000 pkt/s *as written to disk* |
| Capture drops | 14.7% (59,127 dropped, pcap buffer) |
| Export (verbatim) | 263 MiB in 0.84 s = **329 MB/s** |

The loopback test deliberately generates packets faster than any Wi-Fi client
could, to find the ceiling. At that rate **dumpcap's kernel capture buffer
overflows and drops packets** — and PiLens reports exactly that (14.7%), rather
than pretending the capture is complete. This is the headline honesty point: on
a busy link the bottleneck is the kernel→dumpcap handoff, and the drop counters
tell you when you have hit it.

In normal use the AP is 2.4/5 GHz Wi-Fi, where real client throughput is far
below this ceiling, so captures are lossless. If you do saturate it, use a
capture filter to record only what you need, or capture to the SSD not the SD
card.

## Query latency (10,186-packet / 263 MB capture)

| Operation | Time |
|---|---|
| Display filter `tcp` (cold, tshark over all segments) | 1.2 s |
| Display filter `tcp.analysis.retransmission` | 1.2 s |
| Display filter `frame.len>1000` (4,295 matches) | 1.2 s |
| Packet detail (PDML dissection, single packet) | 0.40 s |
| Import + full re-index of the 263 MB file | 3.2 s (≈3,200 pkt/s) |

Filter latency is dominated by tshark reading the segment files; it scales with
capture size, roughly 1 s per 250 MB on this hardware, and results are cached
per filter so repeat views are instant. The unfiltered packet list does **not**
pay this cost: it is served straight from the SQLite index.

## What is not yet benchmarked

- Sustained multi-hour capture memory profile
- Concurrent analysts hitting filters at once
- Wi-Fi radio throughput under real client load (needs H16 with iperf3)
- Capture to SD card vs SSD

These belong to extended soak testing; the figures here come from a single
short run and are intended as a sanity baseline.

import { useMemo, useState } from "react";
import { fmtBytes, type Endpoint, type Session, type Stats, type TimeBucket } from "../api";
import { usePoll } from "../ui";
import { SessionPicker, Bar, PacketsLink } from "../components/chrome";

export default function Statistics({ sessionId }: { sessionId: string }) {
  const [sessions] = usePoll<Session[]>("/api/captures", 5000);
  const id = sessionId || sessions?.[0]?.id || "";
  const [stats, err] = usePoll<Stats>(id ? `/api/captures/${id}/statistics?buckets=300` : null, 0);
  const [eps] = usePoll<Endpoint[]>(id ? `/api/captures/${id}/endpoints?limit=15` : null);
  const [metric, setMetric] = useState<"bytes" | "packets">("bytes");

  const dur = stats ? stats.end - stats.start : 0;
  const bucketS = stats?.counters?.bucket_seconds || 1;
  const maxProto = stats?.protocols[0]?.[metric] ?? 1;
  const maxSize = useMemo(() => Math.max(1, ...(stats?.size_buckets ?? []).map((s) => s[metric])), [stats, metric]);
  const maxEp = eps?.[0]?.bytes ?? 1;

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Statistics</h1><p>Computed from the packet index. Every value is a count of captured packets or bytes, not an estimate.</p></div>
        <SessionPicker sessions={sessions} id={id} base="/statistics">
          <div className="row" style={{ gap: ".25rem" }}>
            <button className={metric === "bytes" ? "on" : ""} onClick={() => setMetric("bytes")}>Bytes</button>
            <button className={metric === "packets" ? "on" : ""} onClick={() => setMetric("packets")}>Packets</button>
          </div>
        </SessionPicker>
      </div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      {!stats ? <div className="empty">Loading…</div> : stats.packets === 0 ? <div className="empty">No packets captured yet.</div> : (
        <>
          <div className="grid g4" style={{ marginBottom: ".9rem" }}>
            <div className="card"><h3>Packets</h3><div className="metric">{stats.packets.toLocaleString()}</div></div>
            <div className="card"><h3>Bytes</h3><div className="metric" style={{ fontSize: "1.4rem" }}>{fmtBytes(stats.bytes)}</div></div>
            <div className="card"><h3>Duration</h3><div className="metric" style={{ fontSize: "1.4rem" }}>{dur > 0 ? dur.toFixed(1) + " s" : "–"}</div><div className="hint">{dur > 0 ? `${Math.round(stats.packets / dur)} pkt/s avg · ${fmtBytes(stats.bytes / dur)}/s` : ""}</div></div>
            <div className="card"><h3>TCP streams</h3><div className="metric">{stats.tcp_streams.toLocaleString()}</div></div>
          </div>

          <div className="card" style={{ marginBottom: ".9rem" }}>
            <div className="row spread"><h3>Traffic over time</h3><span className="hint">{metric} per {bucketS >= 1 ? bucketS + " s" : "bucket"}</span></div>
            <Timeline buckets={stats.timeline} metric={metric} t0={stats.start} />
          </div>

          <div className="grid g2">
            <div className="card"><h3>Protocol hierarchy</h3>
              <table className="data"><tbody>
                {stats.protocols.slice(0, 15).map((p) => (
                  <tr key={p.name}><td className="mono">{p.name}</td>
                    <td style={{ width: "55%" }}><Bar value={p[metric]} max={maxProto} label={metric === "bytes" ? fmtBytes(p.bytes) : p.packets.toLocaleString()} /></td>
                    <td className="hint mono">{((p[metric] / (metric === "bytes" ? stats.bytes : stats.packets)) * 100).toFixed(1)}%</td></tr>
                ))}
              </tbody></table>
            </div>
            <div className="card"><h3>Top talkers</h3>
              <table className="data"><thead><tr><th>Address</th><th>Traffic</th><th>Tx / Rx</th></tr></thead><tbody>
                {eps?.map((e) => (
                  <tr key={e.addr}><td className="mono"><PacketsLink id={id} filter={`${e.addr.includes(":") ? "ipv6" : "ip"}.addr==${e.addr}`}>{e.addr}</PacketsLink></td>
                    <td style={{ width: "45%" }}><Bar value={e.bytes} max={maxEp} /></td>
                    <td className="hint mono">{fmtBytes(e.tx_bytes)} / {fmtBytes(e.rx_bytes)}</td></tr>
                ))}
              </tbody></table>
            </div>
            <div className="card"><h3>Packet size distribution</h3>
              <table className="data"><tbody>
                {stats.size_buckets.map((b) => (
                  <tr key={b.name}><td className="mono">{b.name}</td>
                    <td><Bar value={b[metric]} max={maxSize} label={metric === "bytes" ? fmtBytes(b.bytes) : b.packets.toLocaleString()} kind="var(--accent)" /></td></tr>
                ))}
              </tbody></table>
            </div>
            <div className="card"><h3>Definitions</h3>
              <dl className="kv" style={{ fontSize: ".85rem" }}>
                <dt>Protocol</dt><dd>The highest-layer protocol TShark assigned to each packet (one packet counts once).</dd>
                <dt>TCP streams</dt><dd>Distinct tshark stream indices, counted per segment, so a connection crossing a segment boundary counts more than once.</dd>
                <dt>Tx / Rx</dt><dd>Bytes with this address as source / destination. A packet contributes to both its endpoints.</dd>
                <dt>Bytes</dt><dd>On-the-wire frame length as captured.</dd>
              </dl>
            </div>
          </div>
        </>
      )}
    </div>
  );
}

function Timeline({ buckets, metric, t0 }: { buckets: TimeBucket[]; metric: "bytes" | "packets"; t0: number }) {
  const [hover, setHover] = useState<number | null>(null);
  const W = 1000, H = 160, pad = 4;
  if (!buckets.length) return <div className="empty">No data</div>;
  const max = Math.max(1, ...buckets.map((b) => b[metric]));
  const n = buckets.length;
  const bw = (W - pad * 2) / n;
  const bars = buckets.map((b, i) => {
    const h = (b[metric] / max) * (H - 20);
    return <rect key={i} x={pad + i * bw} y={H - h} width={Math.max(0.5, bw - 0.5)} height={h} fill="var(--cyan)" opacity={hover === i ? 1 : .5}
      onMouseEnter={() => setHover(i)} onMouseLeave={() => setHover(null)} />;
  });
  const hb = hover != null ? buckets[hover] : null;
  return (
    <div style={{ position: "relative" }}>
      <svg viewBox={`0 0 ${W} ${H}`} width="100%" height={H} preserveAspectRatio="none" style={{ display: "block" }} role="img" aria-label="Traffic over time">
        {bars}
        <line x1={pad} y1={H - 0.5} x2={W - pad} y2={H - 0.5} stroke="var(--line-2)" strokeWidth={0.5} />
      </svg>
      <div className="hint" style={{ display: "flex", justifyContent: "space-between" }}>
        <span>0 s</span>
        {hb && <span className="mono">+{(hb.t - t0).toFixed(1)} s: {metric === "bytes" ? fmtBytes(hb.bytes) : hb.packets + " pkts"}</span>}
        <span>{(buckets[n - 1].t - t0).toFixed(0)} s</span>
      </div>
    </div>
  );
}

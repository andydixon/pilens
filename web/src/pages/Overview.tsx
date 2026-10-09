import { useEffect, useRef, useState } from "react";
import { onEvent, fmtBytes, fmtTime, type Session } from "../api";
import { Badge, usePoll, go } from "../ui";

export default function Overview() {
  const [h, herr] = usePoll<any>("/api/system/health", 10000);
  const [clients] = usePoll<{ clients: any[] }>("/api/ap/clients", 15000);
  const [sessions] = usePoll<Session[]>("/api/captures", 10000);
  const [audit] = usePoll<any[]>("/api/audit", 30000);
  const [rate, setRate] = useState<{ pps: number; bps: number } | null>(null);
  const last = useRef<{ t: number; p: number; b: number } | null>(null);

  // Packet and byte rates from live capture counters (only while a capture runs).
  useEffect(() => onEvent((type, d) => {
    if (type !== "capture") return;
    if (d.state !== "running") { setRate(null); last.current = null; return; }
    const now = performance.now();
    if (last.current) {
      const dt = (now - last.current.t) / 1000;
      if (dt > 0.5) setRate({ pps: (d.packets - last.current.p) / dt, bps: (d.bytes - last.current.b) * 8 / dt });
    }
    last.current = { t: now, p: d.packets, b: d.bytes };
  }), []);

  const fwd = h?.forwarding;
  const live = h?.capture?.running ? (h.capture.session as Session) : undefined;
  const assoc = clients?.clients.filter((c) => c.associated) ?? [];
  const alerts: [string, "warn" | "bad"][] = [];
  if (herr) alerts.push(["Health endpoint unavailable: " + herr, "bad"]);
  if (h?.helper_error) alerts.push(["Network helper unreachable: " + h.helper_error, "bad"]);
  if (h?.helper?.last_error) alerts.push(["Last network change failed and was rolled back: " + h.helper.last_error, "warn"]);
  if (h?.system?.throttle_flags?.length) alerts.push(["Raspberry Pi firmware reports: " + h.system.throttle_flags.join(", ") + ". Check the power supply and cooling.", "warn"]);
  if (h?.storage?.low_warning) alerts.push(["Capture storage is nearly full.", "warn"]);
  if (h && h.system?.clock_synchronised !== "yes") alerts.push([`System clock is not NTP-synchronised (${h.system?.clock_synchronised}). Capture timestamps may be inaccurate. This is recorded in each session.`, "warn"]);
  if (live?.error) alerts.push(["Capture: " + live.error, "bad"]);

  const fwdKind = fwd?.state === "forwarding" ? "ok" : fwd?.state === "blocked" ? "warn" : "bad";

  return (
    <div className="page">
      <div className="page-head"><div><h1>Overview</h1><p>Appliance state at a glance</p></div>
        <button className="primary" onClick={() => go("/analyse")}>Open live capture →</button></div>

      {fwd && <div className={"banner " + fwdKind} style={{ marginBottom: "1rem" }}>
        <div><b>Forwarding: {fwd.state.toUpperCase()}</b>{fwd.detail}</div></div>}
      {alerts.map(([m, k], i) => <div key={i} className={"banner " + k} style={{ marginBottom: ".6rem" }}><div>{m}</div></div>)}

      <div className="grid g4" style={{ marginBottom: ".9rem" }}>
        <div className="card"><h3>Capture</h3>
          <div className="metric">{live ? live.packets.toLocaleString() : "idle"}{live && <small>packets</small>}</div>
          <div className="row" style={{ marginTop: ".4rem" }}>{live ? <Badge kind={live.paused ? "warn" : "live"}>{live.paused ? "paused" : "capturing"} on {(live.interfaces ?? []).join(", ")}</Badge> : <Badge>not capturing</Badge>}</div>
        </div>
        <div className="card"><h3>Traffic rate</h3>
          <div className="metric">{rate ? Math.round(rate.pps).toLocaleString() : "–"}<small>pkt/s</small></div>
          <div className="hint">{rate ? `${(rate.bps / 1e6).toFixed(2)} Mbit/s captured` : "Measured from the running capture only"}</div>
        </div>
        <div className="card"><h3>Access point</h3>
          <div className="metric">{assoc.length}<small>associated</small></div>
          <div className="row" style={{ marginTop: ".4rem" }}><Badge kind={h?.helper?.ap_state === "activated" ? "ok" : "bad"}>{h?.helper?.ap_state ?? "unknown"}</Badge>
            <Badge kind={h?.helper?.dnsmasq_active ? "ok" : "bad"}>DHCP/DNS {h?.helper?.dnsmasq_active ? "up" : "down"}</Badge></div>
        </div>
        <div className="card"><h3>Upstream</h3>
          <div className="metric" style={{ fontSize: "1.2rem" }}>{h?.upstream?.interface ?? "–"}</div>
          <div className="row" style={{ marginTop: ".4rem" }}>
            <Badge kind={h?.upstream?.default_route ? "ok" : "bad"}>{h?.upstream?.default_route ? `default route via ${h.upstream.gateway}` : "no default route"}</Badge></div>
        </div>
        <div className="card"><h3>Storage</h3>
          <div className="metric" style={{ fontSize: "1.2rem" }}>{h ? fmtBytes(h.storage.used) : "–"}<small>of {h ? fmtBytes(h.storage.limits.max_bytes) : "–"}</small></div>
          <div className="hint">{h ? fmtBytes(h.storage.free) + " free on disk" : ""}</div>
        </div>
        <div className="card"><h3>System</h3>
          <div className="metric" style={{ fontSize: "1.2rem" }}>{h ? `${h.system.cpu_percent.toFixed(0)}% CPU` : "–"}</div>
          <div className="hint">{h ? `${fmtBytes(h.system.mem_total - h.system.mem_available)} / ${fmtBytes(h.system.mem_total)} RAM${h.system.temp_c ? ` · ${h.system.temp_c.toFixed(1)} °C` : ""}` : ""}</div>
        </div>
      </div>

      <div className="grid g2">
        <div className="card"><h3>Connected clients</h3>
          {assoc.length === 0 ? <div className="empty">No clients associated.</div> :
            <table className="data"><thead><tr><th>Device</th><th>IP</th><th>Signal</th><th>Connected</th></tr></thead><tbody>
              {assoc.map((c) => <tr key={c.mac}><td>{c.label || c.hostname || <span className="mono">{c.mac}</span>}</td><td className="mono">{c.ip}</td><td>{c.signal_dbm ?? "–"} dBm</td><td>{Math.round(c.connected_s / 60)} min</td></tr>)}
            </tbody></table>}
        </div>
        <div className="card"><h3>Recent capture sessions</h3>
          {!sessions?.length ? <div className="empty">None yet.</div> :
            <table className="data"><tbody>{sessions.slice(0, 6).map((s) => <tr key={s.id} style={{ cursor: "pointer" }} onClick={() => go("/analyse/" + s.id)}>
              <td>{s.name}</td><td className="mono">{s.packets.toLocaleString()} pkts</td><td><Badge kind={s.state === "running" ? "live" : s.state === "failed" ? "bad" : "plain"}>{s.state}</Badge></td><td className="hint">{fmtTime(s.started_at)}</td></tr>)}</tbody></table>}
        </div>
        <div className="card"><h3>Recent activity (audit)</h3>
          <table className="data"><tbody>{audit?.slice(0, 8).map((a, i) => <tr key={i}><td className="hint">{fmtTime(a.TS)}</td><td>{a.Actor}</td><td className="mono">{a.Action}</td></tr>)}</tbody></table>
        </div>
      </div>
    </div>
  );
}

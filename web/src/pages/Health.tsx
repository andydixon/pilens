import { fmtBytes, fmtDur } from "../api";
import { Badge, usePoll } from "../ui";

export default function Health() {
  const [h, err] = usePoll<any>("/api/system/health", 5000);
  const [ifs] = usePoll<any>("/api/system/interfaces", 15000);
  if (!h) return <div className="page">{err ? <div className="banner bad"><div>{err}</div></div> : "Loading…"}</div>;
  const s = h.system, hs = h.helper;
  const svc: [string, boolean | null, string][] = [
    ["Network helper (root)", !h.helper_error, h.helper_error || "responding"],
    ["Firewall table inet pilens", hs?.table_loaded ?? null, hs?.table_loaded ? "loaded" : "not loaded"],
    ["Access point (NetworkManager)", hs ? hs.ap_state === "activated" : null, hs?.ap_state ?? "unknown"],
    ["DHCP / DNS (pilens-dnsmasq)", hs?.dnsmasq_active ?? null, hs?.dnsmasq_active ? "active" : "inactive"],
    ["IPv4 forwarding", hs?.ip_forward ?? null, hs?.ip_forward ? "enabled" : "disabled"],
    ["Packet capture (dumpcap)", h.capture.running ? true : null, h.capture.running ? `capturing on ${h.capture.session.interfaces.join(", ")}` : "idle"],
    ["Dissector", !!h.capture.tshark, h.capture.tshark],
    ["Clock synchronisation", s.clock_synchronised === "yes", s.clock_synchronised],
    ["TLS interception proxy", null, "not part of this version"],
  ];
  return (
    <div className="page">
      <div className="page-head"><div><h1>System Health</h1><p>Each check reports what was measured, not just whether a process exists.</p></div></div>
      <div className="grid g4" style={{ marginBottom: ".9rem" }}>
        <div className="card"><h3>CPU</h3><div className="metric">{s.cpu_percent.toFixed(0)}%</div><div className="hint">load {s.load.split(" ").slice(0, 3).join(" ")}</div></div>
        <div className="card"><h3>Memory</h3><div className="metric">{fmtBytes(s.mem_total - s.mem_available)}</div><div className="hint">of {fmtBytes(s.mem_total)}</div></div>
        <div className="card"><h3>Temperature</h3><div className="metric">{s.temp_c != null ? s.temp_c.toFixed(1) + " °C" : "n/a"}</div>
          <div className="hint">{s.throttled ? s.throttled : "throttling status unavailable"}</div></div>
        <div className="card"><h3>Uptime</h3><div className="metric">{fmtDur(s.uptime_s)}</div><div className="hint">{s.model}</div></div>
      </div>
      {s.throttle_flags?.length > 0 && <div className="banner warn" style={{ marginBottom: "1rem" }}><div><b>Firmware reports power or thermal problems</b>{s.throttle_flags.join(" · ")}. Under-voltage on a Pi causes packet loss and storage corruption. Use the official power supply.</div></div>}
      <div className="grid g2">
        <div className="card"><h3>Services</h3>
          <table className="data"><tbody>{svc.map(([n, ok, d]) => <tr key={n}><td>{n}</td><td><Badge kind={ok === null ? "plain" : ok ? "ok" : "bad"}>{d}</Badge></td></tr>)}</tbody></table>
          {hs?.last_error && <p className="err">Last apply error: {hs.last_error}</p>}
        </div>
        <div className="card"><h3>Storage</h3>
          <dl className="kv">
            {Object.entries(s.disks as Record<string, { total: number; free: number }>).map(([k, v]) => <><dt key={k}>{k} filesystem</dt><dd>{fmtBytes(v.free)} free of {fmtBytes(v.total)}</dd></>)}
            <dt>Capture files</dt><dd>{fmtBytes(h.storage.used)} of {fmtBytes(h.storage.limits.max_bytes)} quota</dd>
            <dt>Reserve</dt><dd>{fmtBytes(h.storage.limits.reserve_bytes)} always kept free</dd>
            <dt>Location</dt><dd className="mono">{h.storage.dir}</dd>
          </dl>
          {h.storage.low_warning && <p className="warnc">Storage is low.</p>}
        </div>
        <div className="card"><h3>Network interfaces</h3>
          <table className="data"><thead><tr><th>Name</th><th>Link</th><th>Addresses</th><th>Driver</th><th>rx dropped</th></tr></thead><tbody>
            {ifs?.interfaces?.map((i: any) => <tr key={i.name}><td className="mono">{i.name}{i.wireless && " 📶"}</td><td><Badge kind={i.carrier ? "ok" : "bad"}>{i.up ? (i.carrier ? "up" : "no carrier") : "down"}</Badge></td>
              <td className="mono" style={{ fontSize: ".78rem" }}>{(i.addrs ?? []).join(" ")}</td><td className="mono">{i.driver}</td><td className="mono">{i.rx_dropped}</td></tr>)}
          </tbody></table>
          {ifs?.wifi?.map((w: any, k: number) => <p key={k} className="hint">Radio {w.phy || "?"}: AP mode {w.ap_mode ? "supported" : "NOT supported"}; bands {w.bands?.join(", ") || "unknown"}{w.error ? " · " + w.error : ""}</p>)}
        </div>
        <div className="card"><h3>Software</h3>
          <dl className="kv"><dt>PiLens</dt><dd className="mono">{h.version}</dd><dt>OS</dt><dd>{s.os}</dd><dt>Kernel</dt><dd className="mono">{s.kernel}</dd>
            <dt>NetworkManager</dt><dd className="mono">{s.networkmanager}</dd><dt>TShark</dt><dd className="mono">{h.capture.tshark}</dd><dt>Regulatory domain</dt><dd className="mono">{hs?.regdomain || "unknown"}</dd></dl>
          <p className="hint">For a full diagnostic bundle (secrets redacted), run <code>sudo /opt/pilens/diagnose.sh</code> on the appliance.</p>
        </div>
      </div>
    </div>
  );
}

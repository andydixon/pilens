import { useEffect, useState } from "react";
import { api, type ApplyResult, type Iface, type Network } from "../api";
import { Badge, Steps, toast } from "../ui";
import { ForwardingFields, LanFields, ManagementFields, UplinkField, WifiFields } from "../components/NetForm";

export default function NetworkPage() {
  const [n, setN] = useState<Network | null>(null);
  const [orig, setOrig] = useState("");
  const [passSet, setPassSet] = useState(false);
  const [ifaces, setIfaces] = useState<Iface[]>([]);
  const [remote, setRemote] = useState("");
  const [bands, setBands] = useState<string[]>();
  const [status, setStatus] = useState<any>(null);
  const [errors, setErrors] = useState<string[]>([]);
  const [result, setResult] = useState<ApplyResult | null>(null);
  const [busy, setBusy] = useState(false);

  const load = () => {
    api("/api/network").then((d) => {
      const c = { ...d.config, lan: { ...d.config.lan, reservations: d.config.lan.reservations ?? [], dns_overrides: d.config.lan.dns_overrides ?? [] } };
      setN(c); setOrig(JSON.stringify(c)); setPassSet(d.passphrase_set);
    });
    api("/api/system/interfaces").then((d) => { setIfaces(d.interfaces ?? []); setRemote(d.remote_addr); setBands((d.wifi ?? []).find((w: any) => w.ap_mode)?.bands); });
    api("/api/system/health").then((h) => setStatus(h));
  };
  useEffect(load, []);
  if (!n) return <div className="page">Loading…</div>;
  const set = (f: (n: Network) => Network) => setN((x) => (x ? f(x) : x));
  const dirty = JSON.stringify(n) !== orig;

  const apply = async () => {
    setBusy(true); setErrors([]); setResult(null);
    try {
      const v = await api("/api/network/validate", { body: n });
      if (!v.valid) { setErrors(v.errors); setBusy(false); return; }
      const r = await api("/api/network/apply", { body: n });
      setResult(r.result); toast("Configuration applied and verified");
      load();
    } catch (e: any) { setResult(e.body?.result ?? null); setErrors([e.message]); }
    setBusy(false);
  };

  const res = n.lan.reservations ?? [];
  const ovr = n.lan.dns_overrides ?? [];
  const hs = status?.helper;

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Network Settings</h1><p>Access point, DHCP/DNS, routing and management access. Changes are applied as one transaction and rolled back if any check fails.</p></div>
        <div className="row">
          {dirty && <span className="warnc">Unsaved changes</span>}
          <button onClick={load} disabled={busy}>Revert</button>
          <button className="primary" onClick={apply} disabled={busy || !dirty}>{busy ? "Applying…" : "Validate & apply"}</button>
        </div>
      </div>
      {hs && <div className="row" style={{ marginBottom: "1rem" }}>
        <Badge kind={hs.ap_state === "activated" ? "ok" : "bad"}>AP {hs.ap_state}</Badge>
        <Badge kind={hs.dnsmasq_active ? "ok" : "bad"}>DHCP/DNS {hs.dnsmasq_active ? "active" : "inactive"}</Badge>
        <Badge kind={hs.table_loaded ? "ok" : "bad"}>firewall {hs.table_loaded ? "loaded" : "missing"}</Badge>
        <Badge kind={hs.ip_forward ? "ok" : "warn"}>IPv4 forwarding {hs.ip_forward ? "on" : "off"}</Badge>
        <Badge kind="plain">regdomain {hs.regdomain || "?"}</Badge>
      </div>}
      {status?.helper_error && <div className="banner bad"><div><b>Network helper unavailable</b>{status.helper_error}</div></div>}
      {errors.length > 0 && <div className="banner bad" role="alert" style={{ marginBottom: "1rem" }}><div>{errors.map((e, i) => <div key={i}>{e}</div>)}</div></div>}
      {result && <div style={{ marginBottom: "1rem" }}><Steps steps={result.steps} />{result.rolled_back && <div className="banner warn" style={{ marginTop: ".5rem" }}><div><b>Rolled back</b>The previous working configuration was restored.</div></div>}</div>}

      <div className="grid g2">
        <div className="card stack"><h3>Wi-Fi access point</h3><WifiFields n={n} set={set} ifaces={ifaces} passSet={passSet} bands={bands} /></div>
        <div className="card stack"><h3>Client network (DHCP)</h3><LanFields n={n} set={set} /></div>
        <div className="card stack"><h3>DHCP reservations</h3>
          {res.map((r, i) => <div key={i} className="row">
            <input className="mono" placeholder="MAC" value={r.mac} onChange={(e) => set((x) => ({ ...x, lan: { ...x.lan, reservations: res.map((y, j) => j === i ? { ...y, mac: e.target.value } : y) } }))} />
            <input className="mono" placeholder="IP" value={r.ip} onChange={(e) => set((x) => ({ ...x, lan: { ...x.lan, reservations: res.map((y, j) => j === i ? { ...y, ip: e.target.value } : y) } }))} />
            <input placeholder="hostname" value={r.hostname ?? ""} onChange={(e) => set((x) => ({ ...x, lan: { ...x.lan, reservations: res.map((y, j) => j === i ? { ...y, hostname: e.target.value } : y) } }))} />
            <button className="small ghost" aria-label="Remove" onClick={() => set((x) => ({ ...x, lan: { ...x.lan, reservations: res.filter((_, j) => j !== i) } }))}>✕</button></div>)}
          <div><button className="small" onClick={() => set((x) => ({ ...x, lan: { ...x.lan, reservations: [...res, { mac: "", ip: "" }] } }))}>+ Add reservation</button></div>
        </div>
        <div className="card stack"><h3>Local DNS overrides</h3>
          <p className="hint">Answer an exact name with a fixed address for AP clients, for authorised testing. Subdomains are not affected.</p>
          {ovr.map((o, i) => <div key={i} className="row">
            <input className="mono" placeholder="name.example" value={o.name} onChange={(e) => set((x) => ({ ...x, lan: { ...x.lan, dns_overrides: ovr.map((y, j) => j === i ? { ...y, name: e.target.value } : y) } }))} />
            <input className="mono" placeholder="address" value={o.ip} onChange={(e) => set((x) => ({ ...x, lan: { ...x.lan, dns_overrides: ovr.map((y, j) => j === i ? { ...y, ip: e.target.value } : y) } }))} />
            <button className="small ghost" aria-label="Remove" onClick={() => set((x) => ({ ...x, lan: { ...x.lan, dns_overrides: ovr.filter((_, j) => j !== i) } }))}>✕</button></div>)}
          <div><button className="small" onClick={() => set((x) => ({ ...x, lan: { ...x.lan, dns_overrides: [...ovr, { name: "", ip: "" }] } }))}>+ Add override</button></div>
        </div>
        <div className="card stack"><h3>Forwarding policy</h3><UplinkField n={n} set={set} ifaces={ifaces} /><ForwardingFields n={n} set={set} /></div>
        <div className="card stack"><h3>Management access</h3><ManagementFields n={n} set={set} ifaces={ifaces} remote={remote} /></div>
      </div>
    </div>
  );
}

import { useState } from "react";
import { api, fmtBytes, fmtDur, fmtTime } from "../api";
import { Badge, Modal, go, toast, usePoll } from "../ui";

export default function Devices() {
  const [d, err, reload] = usePoll<{ clients: any[]; errors: string[] }>("/api/ap/clients", 10000);
  const [edit, setEdit] = useState<any>(null);
  const list = [...(d?.clients ?? [])].sort((a, b) => Number(b.associated) - Number(a.associated) || b.last_seen - a.last_seen);
  const now = Date.now() / 1000;

  return (
    <div className="page">
      <div className="page-head"><div><h1>Devices</h1>
        <p>Clients of the PiLens access point, keyed by MAC address. Devices that randomise their MAC address appear as separate entries, and PiLens never merges them automatically.</p></div></div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      {d?.errors?.map((e, i) => <div key={i} className="banner warn" style={{ marginBottom: ".5rem" }}><div>{e}</div></div>)}
      <div className="card" style={{ padding: 0 }}>
        <table className="data">
          <thead><tr><th>Device</th><th>MAC</th><th>IP</th><th>State</th><th>Signal</th><th>Rx / Tx</th><th>Connected</th><th>Lease expires</th><th>First / last seen</th><th></th></tr></thead>
          <tbody>
            {list.map((c) => (
              <tr key={c.mac}>
                <td><b>{c.label || c.hostname || "—"}</b>{c.label && c.hostname && <div className="hint">{c.hostname}</div>}{c.notes && <div className="hint" title={c.notes}>📝 {c.notes.slice(0, 40)}</div>}</td>
                <td className="mono">{c.mac}{c.randomised_mac && <div><Badge kind="plain">randomised</Badge></div>}</td>
                <td className="mono">{c.ip || "—"}</td>
                <td>{c.associated ? <Badge kind="ok">associated</Badge> : <Badge>offline</Badge>}</td>
                <td className="mono">{c.signal_dbm != null ? `${c.signal_dbm} dBm` : "—"}</td>
                <td className="mono">{c.associated ? `${fmtBytes(c.rx_bytes)} / ${fmtBytes(c.tx_bytes)}` : "—"}</td>
                <td className="mono">{c.associated ? fmtDur(c.connected_s) : "—"}{c.associated && c.inactive_ms > 0 && <div className="hint">idle {fmtDur(c.inactive_ms / 1000)}</div>}</td>
                <td className="mono">{c.lease_expiry ? (c.lease_expiry > now ? "in " + fmtDur(c.lease_expiry - now) : "expired") : "—"}</td>
                <td className="hint">{fmtTime(c.first_seen * 1000)}<br />{c.last_seen ? fmtTime(c.last_seen * 1000) : "—"}</td>
                <td><div className="row" style={{ flexWrap: "nowrap" }}>
                  <button className="small" onClick={() => setEdit({ ...c })}>Label</button>
                  <button className="small" onClick={() => go(`/analyse?filter=${encodeURIComponent("eth.addr == " + c.mac)}`)} title="Open the analyser filtered to this MAC">Packets</button>
                </div></td>
              </tr>
            ))}
            {list.length === 0 && <tr><td colSpan={10} className="empty">No devices have connected yet.</td></tr>}
          </tbody>
        </table>
      </div>
      <p className="hint" style={{ marginTop: ".6rem" }}>Rx/Tx are radio-level counters reported by the Wi-Fi driver for the current association. Signal is measured by the Pi's radio.</p>
      <Modal open={!!edit} title={`Device ${edit?.mac ?? ""}`} onClose={() => setEdit(null)} footer={<><button onClick={() => setEdit(null)}>Cancel</button>
        <button className="primary" onClick={async () => { try { await api(`/api/devices/${edit.mac}`, { method: "PUT", body: { Label: edit.label, Notes: edit.notes } }); setEdit(null); reload(); } catch (e) { toast((e as Error).message, true); } }}>Save</button></>}>
        {edit && <><label>Label<input value={edit.label} maxLength={100} onChange={(e) => setEdit({ ...edit, label: e.target.value })} /></label>
          <label>Analyst notes<textarea rows={5} value={edit.notes} onChange={(e) => setEdit({ ...edit, notes: e.target.value })} /></label></>}
      </Modal>
    </div>
  );
}

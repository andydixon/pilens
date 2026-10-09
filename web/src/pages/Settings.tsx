import { useState } from "react";
import { api, fmtBytes, fmtTime, type Limits } from "../api";
import { toast, usePersist, usePoll } from "../ui";
import type { Prefs } from "../App";
import type { ColourRule } from "../components/PacketTable";

interface Props { prefs: Prefs; setPrefs: (p: Prefs) => void; session: { user: string; totp_enabled: boolean }; onChange: () => void }

export default function Settings({ prefs, setPrefs, session, onChange }: Props) {
  const [pw, setPw] = useState({ Current: "", New: "", Confirm: "" });
  const [totp, setTotp] = useState<{ secret: string; uri: string } | null>(null);
  const [code, setCode] = useState("");
  const [disablePw, setDisablePw] = useState("");
  const [storage, , reloadStorage] = usePoll<{ limits: Limits; used: number; free: number }>("/api/storage");
  const [lim, setLim] = useState<Limits | null>(null);
  const [audit] = usePoll<any[]>("/api/audit");
  const [rules, setRules] = usePersist<ColourRule[]>("colour.rules", []);
  const L = lim ?? storage?.limits;

  const act = async (f: () => Promise<any>, ok: string) => { try { await f(); toast(ok); } catch (e) { toast((e as Error).message, true); } };

  return (
    <div className="page">
      <div className="page-head"><div><h1>Settings</h1></div></div>
      <div className="grid g2">
        <div className="card stack"><h3>Appearance</h3>
          <div className="fieldgrid">
            <label>Theme<select value={prefs.theme} onChange={(e) => setPrefs({ ...prefs, theme: e.target.value as Prefs["theme"] })}><option value="dark">Dark</option><option value="light">Light</option><option value="system">Follow system</option></select></label>
            <label>Density<select value={prefs.density} onChange={(e) => setPrefs({ ...prefs, density: e.target.value as Prefs["density"] })}><option value="compact">Compact</option><option value="comfortable">Comfortable</option></select></label>
            <label>Font scale<select value={prefs.scale} onChange={(e) => setPrefs({ ...prefs, scale: +e.target.value })}>{[0.9, 1, 1.1, 1.2, 1.35].map((s) => <option key={s} value={s}>{Math.round(s * 100)}%</option>)}</select></label>
            <label>Motion<select value={prefs.motion} onChange={(e) => setPrefs({ ...prefs, motion: e.target.value as Prefs["motion"] })}><option value="system">Follow system</option><option value="reduce">Reduce</option></select></label>
          </div>
          <p className="hint">Keyboard: <code>/</code> focus filter · <code>↑↓ PgUp PgDn Home End</code> move through packets · <code>←→</code> collapse/expand tree · <code>Space</code> pause view · <code>f</code> follow · <code>Shift+F</code> focus mode · <code>Alt+1…7</code> pages</p>
        </div>

        <div className="card stack"><h3>Packet colouring rules</h3>
          <p className="hint">Rules here are checked first. Otherwise PiLens colours rows using Wireshark's built-in colouring rules, as reported by tshark.</p>
          {rules.map((r, i) => <div key={i} className="row">
            <select value={r.field} onChange={(e) => setRules(rules.map((x, j) => j === i ? { ...x, field: e.target.value as ColourRule["field"] } : x))}><option value="proto">Protocol</option><option value="info">Info</option><option value="src">Source</option><option value="dst">Destination</option></select>
            <span>contains</span>
            <input value={r.contains} onChange={(e) => setRules(rules.map((x, j) => j === i ? { ...x, contains: e.target.value } : x))} />
            <input type="color" value={r.colour.slice(0, 7)} onChange={(e) => setRules(rules.map((x, j) => j === i ? { ...x, colour: e.target.value + "40" } : x))} aria-label="Colour" />
            <button className="small ghost" onClick={() => setRules(rules.filter((_, j) => j !== i))} aria-label="Remove">✕</button>
          </div>)}
          <div><button className="small" onClick={() => setRules([...rules, { field: "proto", contains: "", colour: "#5ccfe040" }])}>+ Add rule</button></div>
        </div>

        <div className="card stack"><h3>Password ({session.user})</h3>
          <input type="password" placeholder="Current password" autoComplete="current-password" value={pw.Current} onChange={(e) => setPw({ ...pw, Current: e.target.value })} />
          <input type="password" placeholder="New password (≥ 12 characters)" autoComplete="new-password" value={pw.New} onChange={(e) => setPw({ ...pw, New: e.target.value })} />
          <input type="password" placeholder="Confirm" autoComplete="new-password" value={pw.Confirm} onChange={(e) => setPw({ ...pw, Confirm: e.target.value })} />
          <div><button disabled={!pw.New || pw.New !== pw.Confirm} onClick={() => act(() => api("/api/auth/password", { body: { Current: pw.Current, New: pw.New } }).then(() => setPw({ Current: "", New: "", Confirm: "" })), "Password changed; other sessions signed out")}>Change password</button></div>
        </div>

        <div className="card stack"><h3>Two-factor authentication (TOTP)</h3>
          {session.totp_enabled ? <>
            <p className="okc">Enabled.</p>
            <input type="password" placeholder="Password to disable" value={disablePw} onChange={(e) => setDisablePw(e.target.value)} />
            <div><button className="danger" onClick={() => act(() => api("/api/auth/totp/disable", { body: { Password: disablePw } }).then(onChange), "TOTP disabled")}>Disable TOTP</button></div>
          </> : totp ? <>
            <p>Add this secret to an authenticator app (manual entry, SHA-1, 6 digits, 30 s):</p>
            <code style={{ fontSize: "1.05rem", letterSpacing: ".08em", wordBreak: "break-all" }}>{totp.secret}</code>
            <details><summary className="hint">otpauth URI</summary><code style={{ wordBreak: "break-all" }}>{totp.uri}</code></details>
            <input className="mono" placeholder="6-digit code" maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} />
            <div><button className="primary" onClick={() => act(() => api("/api/auth/totp/enable", { body: { Code: code } }).then(() => { setTotp(null); onChange(); }), "TOTP enabled")}>Confirm and enable</button></div>
          </> : <div><button onClick={() => act(async () => setTotp(await api("/api/auth/totp/begin", { method: "POST" })), "Secret generated")}>Set up TOTP</button></div>}
        </div>

        {L && <div className="card stack"><h3>Capture storage</h3>
          <p className="hint">Using {fmtBytes(storage!.used)}; {fmtBytes(storage!.free)} free on disk.</p>
          <div className="fieldgrid">
            <label>Quota (GiB)<input type="number" min={1} value={+(L.max_bytes / 2 ** 30).toFixed(2)} onChange={(e) => setLim({ ...L, max_bytes: Math.round(+e.target.value * 2 ** 30) })} /></label>
            <label>Reserve free (GiB)<input type="number" min={0.1} step={0.5} value={+(L.reserve_bytes / 2 ** 30).toFixed(2)} onChange={(e) => setLim({ ...L, reserve_bytes: Math.round(+e.target.value * 2 ** 30) })} /></label>
            <label>Segment size (MiB)<input type="number" min={1} max={1024} value={Math.round(L.segment_bytes / 2 ** 20)} onChange={(e) => setLim({ ...L, segment_bytes: +e.target.value * 2 ** 20 })} /></label>
            <label>Max import (MiB)<input type="number" min={1} value={Math.round(L.import_bytes / 2 ** 20)} onChange={(e) => setLim({ ...L, import_bytes: +e.target.value * 2 ** 20 })} /></label>
          </div>
          <div><button disabled={!lim} onClick={() => act(() => api("/api/storage", { method: "PUT", body: lim }).then(() => { setLim(null); reloadStorage(); }), "Storage limits saved")}>Save limits</button></div>
          <p className="hint">Sensitive-content note: captures contain whatever crossed the network, unencrypted parts included. Delete sessions you no longer need. Exports are recorded in the audit log.</p>
        </div>}

        <div className="card" style={{ gridColumn: "1 / -1" }}><h3>Audit log</h3>
          <div style={{ maxHeight: 360, overflow: "auto" }}>
            <table className="data"><thead><tr><th>Time</th><th>Actor</th><th>Action</th><th>Detail</th><th>Source</th></tr></thead><tbody>
              {audit?.map((a, i) => <tr key={i}><td className="hint" style={{ whiteSpace: "nowrap" }}>{fmtTime(a.TS)}</td><td>{a.Actor}</td><td className="mono">{a.Action}</td><td className="mono" style={{ fontSize: ".78rem", wordBreak: "break-all" }}>{a.Detail}</td><td className="mono">{a.Remote}</td></tr>)}
            </tbody></table>
          </div>
        </div>
      </div>
    </div>
  );
}

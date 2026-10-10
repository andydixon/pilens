import { useEffect, useMemo, useRef, useState } from "react";
import { api, onEvent, fmtBytes, fmtTime, type HttpFlow } from "../api";
import { Badge, Modal, copyText, toast, usePersist } from "../ui";

function statusKind(f: HttpFlow): "ok" | "warn" | "bad" | "plain" {
  if (f.error) return "bad";
  if (f.status >= 500) return "bad";
  if (f.status >= 400) return "warn";
  if (f.status >= 200 && f.status < 400) return "ok";
  return "plain";
}

export default function HttpExplorer() {
  const [flows, setFlows] = useState<HttpFlow[]>([]);
  const [q, setQ] = useState("");
  const [onlyErr, setOnlyErr] = useState(false);
  const [live, setLive] = usePersist("http.live", true);
  const [sel, setSel] = useState<HttpFlow | null>(null);
  const [err, setErr] = useState("");
  const liveRef = useRef(live); liveRef.current = live;

  const load = () => api<HttpFlow[]>("/api/http?limit=2000").then(setFlows).catch((e) => setErr(e.message));
  useEffect(() => { load(); }, []);
  useEffect(() => onEvent((type, d: HttpFlow) => {
    if (type !== "http" || !liveRef.current || !d.id) return;
    setFlows((f) => [d, ...f.filter((x) => x.id !== d.id)].slice(0, 3000));
  }), []);

  const rows = useMemo(() => flows.filter((f) =>
    (!q || `${f.host}${f.path} ${f.client} ${f.method}`.toLowerCase().includes(q.toLowerCase())) &&
    (!onlyErr || f.error || f.status >= 400)), [flows, q, onlyErr]);

  return (
    <div className="page" style={{ display: "flex", flexDirection: "column" }}>
      <div className="page-head">
        <div><h1>HTTP Explorer</h1><p>Decrypted HTTP(S) transactions from trusting devices. Requires interception (Certificates page).</p></div>
        <div className="row">
          <button className={live ? "on" : ""} onClick={() => setLive(!live)} title="Append new transactions live">⚡ Live</button>
          <button onClick={load}>Refresh</button>
          <button className="danger" onClick={async () => { if (confirm("Delete all intercepted HTTP data (flows and any retained bodies)? Captures are untouched.")) { await api("/api/interception/clear", { method: "POST" }); setFlows([]); setSel(null); toast("Cleared"); } }}>Clear</button>
        </div>
      </div>
      <div className="banner info" style={{ marginBottom: ".8rem" }}><div>
        Shown here are connections PiLens could decrypt because the device trusts the CA. Pinned/untrusting connections appear as <b>errors</b>, not content. Nothing here is captured from devices that did not opt in.
      </div></div>
      <div className="row" style={{ marginBottom: ".6rem" }}>
        <input placeholder="Filter host / path / client / method" value={q} onChange={(e) => setQ(e.target.value)} style={{ minWidth: 280 }} />
        <label className="inline"><input type="checkbox" checked={onlyErr} onChange={(e) => setOnlyErr(e.target.checked)} />Errors only</label>
        <span className="hint">{rows.length.toLocaleString()} transactions</span>
      </div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      <div className="card" style={{ padding: 0, flex: 1, overflow: "auto" }}>
        <table className="data">
          <thead><tr><th>Time</th><th>Client</th><th>Method</th><th>Host</th><th>Path</th><th>Status</th><th>Type</th><th>Size</th><th>Time</th><th></th></tr></thead>
          <tbody>
            {rows.map((f) => (
              <tr key={f.id} style={{ cursor: "pointer" }} onClick={() => setSel(f)}>
                <td className="hint" style={{ whiteSpace: "nowrap" }}>{fmtTime(f.ts * 1000).split(", ")[1] ?? fmtTime(f.ts * 1000)}</td>
                <td className="mono">{f.client}</td>
                <td className="mono">{f.method}{f.websocket && " ⇄"}</td>
                <td className="mono">{f.scheme === "https" ? "🔒" : ""}{f.host}</td>
                <td className="mono" style={{ maxWidth: 360, overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{f.path}</td>
                <td>{f.error ? <Badge kind="bad">error</Badge> : <Badge kind={statusKind(f)}>{f.status}</Badge>}</td>
                <td className="mono hint">{(f.resp_ctype || f.req_ctype || "").split(";")[0]}</td>
                <td className="mono">{fmtBytes(f.resp_size)}</td>
                <td className="mono hint">{f.duration_ms} ms</td>
                <td>›</td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={10} className="empty">No transactions. Enable interception and install the CA on a test device.</td></tr>}
          </tbody>
        </table>
      </div>
      {sel && <FlowDetail flow={sel} onClose={() => setSel(null)} />}
    </div>
  );
}

function Headers({ h }: { h: Record<string, string> }) {
  const entries = Object.entries(h || {});
  if (!entries.length) return <div className="hint">none</div>;
  return <table className="data"><tbody>{entries.map(([k, v]) => <tr key={k}><td className="mono" style={{ color: "var(--muted)", whiteSpace: "nowrap", verticalAlign: "top" }}>{k}</td><td className="mono" style={{ wordBreak: "break-all" }}>{v}</td></tr>)}</tbody></table>;
}

function FlowDetail({ flow, onClose }: { flow: HttpFlow; onClose: () => void }) {
  const [tab, setTab] = useState<"req" | "resp">("resp");
  return (
    <Modal open title={<span className="mono" style={{ fontSize: ".95rem" }}>{flow.method} {flow.scheme}://{flow.host}{flow.path}</span>} onClose={onClose}
      footer={<><button onClick={() => copyText(`${flow.method} ${flow.scheme}://${flow.host}${flow.path}`)}>Copy URL</button><button className="primary" onClick={onClose}>Close</button></>}>
      <div className="row" style={{ gap: ".5rem", flexWrap: "wrap" }}>
        <Badge kind={flow.error ? "bad" : statusKind(flow)}>{flow.error ? "error" : `${flow.status} ${flow.reason}`}</Badge>
        {flow.intercepted ? <Badge kind="ok">decrypted</Badge> : <Badge kind="warn">not decrypted</Badge>}
        <span className="hint mono">{flow.client} · {flow.http_version} · {flow.duration_ms} ms</span>
      </div>
      {flow.tls_version && <div className="hint mono">{flow.tls_version}{flow.sni ? ` · SNI ${flow.sni}` : ""}{flow.alpn ? ` · ALPN ${flow.alpn}` : ""}</div>}
      {flow.error && <div className="banner bad" style={{ margin: ".5rem 0" }}><div>{flow.error}</div></div>}

      <div className="row" style={{ gap: ".25rem", marginTop: ".5rem" }}>
        <button className={tab === "req" ? "on" : ""} onClick={() => setTab("req")}>Request</button>
        <button className={tab === "resp" ? "on" : ""} onClick={() => setTab("resp")}>Response</button>
      </div>
      {tab === "req" ? <div className="stack">
        <h3>Request headers</h3><Headers h={flow.req_headers} />
        <Body flow={flow} which="req" has={flow.has_req_body} size={flow.req_size} ctype={flow.req_ctype} />
      </div> : <div className="stack">
        <h3>Response headers</h3><Headers h={flow.resp_headers} />
        <Body flow={flow} which="resp" has={flow.has_resp_body} size={flow.resp_size} ctype={flow.resp_ctype} />
      </div>}
    </Modal>
  );
}

function Body({ flow, which, has, size, ctype }: { flow: HttpFlow; which: "req" | "resp"; has: boolean; size: number; ctype: string }) {
  const [data, setData] = useState<Uint8Array | null>(null);
  const [mode, setMode] = useState<"auto" | "text" | "hex" | "image">("auto");
  const [loading, setLoading] = useState(false);
  const ct = (ctype || "").split(";")[0];

  const load = async () => {
    setLoading(true);
    try {
      const r = await fetch(`/api/http/${flow.id}/body/${which}`, { headers: { "X-Requested-With": "pilens" }, credentials: "same-origin" });
      if (!r.ok) throw new Error(await r.text());
      setData(new Uint8Array(await r.arrayBuffer()));
    } catch (e) { toast((e as Error).message, true); }
    setLoading(false);
  };

  if (!has) return <><h3>Body</h3><div className="hint">{size > 0 ? `${fmtBytes(size)} not retained (body capture is off for privacy). Enable it on the Certificates page for a specific investigation.` : "empty"}</div></>;

  const view = mode === "auto" ? (ct.startsWith("image/") ? "image" : /json|text|xml|javascript|html|urlencoded/.test(ct) ? "text" : "hex") : mode;

  return <><div className="row spread"><h3>Body ({fmtBytes(size)}, {ct || "unknown"})</h3>
    <div className="row" style={{ gap: ".25rem" }}>
      {["auto", "text", "hex", "image"].map((m) => <button key={m} className={"small" + (mode === m ? " on" : "")} onClick={() => setMode(m as any)}>{m}</button>)}
    </div></div>
    {!data ? <button disabled={loading} onClick={load}>{loading ? "Loading…" : "Load body"}</button> : <BodyView data={data} view={view} id={flow.id} which={which} ct={ct} />}
  </>;
}

function BodyView({ data, view, id, which, ct }: { data: Uint8Array; view: string; id: string; which: string; ct: string }) {
  const text = useMemo(() => { try { return new TextDecoder().decode(data); } catch { return ""; } }, [data]);
  if (view === "image") {
    // Sandboxed: served as application/octet-stream with nosniff; render via blob URL.
    const url = useMemo(() => URL.createObjectURL(new Blob([data as BlobPart], { type: ct || "application/octet-stream" })), [data, ct]);
    return <img src={url} alt="response body" style={{ maxWidth: "100%", maxHeight: "50vh", background: "var(--panel-2)" }} />;
  }
  if (view === "hex") {
    const lines = [];
    for (let o = 0; o < Math.min(data.length, 16384); o += 16) {
      const slice = Array.from(data.slice(o, o + 16));
      lines.push(o.toString(16).padStart(6, "0") + "  " + slice.map((b) => b.toString(16).padStart(2, "0")).join(" ").padEnd(47) + "  " + slice.map((b) => b >= 32 && b < 127 ? String.fromCharCode(b) : ".").join(""));
    }
    return <pre style={preStyle}>{lines.join("\n")}{data.length > 16384 ? "\n… truncated" : ""}</pre>;
  }
  let pretty = text;
  if (/json/.test(ct)) { try { pretty = JSON.stringify(JSON.parse(text), null, 2); } catch { /* keep raw */ } }
  return <><pre style={preStyle}>{pretty.slice(0, 200000)}{pretty.length > 200000 ? "\n… truncated" : ""}</pre>
    <a className="btn small" href={`/api/http/${id}/body/${which}`} download>Download raw</a></>;
}

const preStyle: React.CSSProperties = { maxHeight: "48vh", overflow: "auto", background: "var(--panel-2)", padding: ".6rem", borderRadius: 6, fontSize: ".82rem", whiteSpace: "pre-wrap", wordBreak: "break-all", margin: 0 };

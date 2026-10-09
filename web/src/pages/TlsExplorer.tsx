import { useMemo, useState } from "react";
import { fmtTime, type CertRecord, type Session, type TLSRecord } from "../api";
import { Badge, usePoll } from "../ui";
import { SessionPicker, PacketsLink, EncryptedNote } from "../components/chrome";

interface TLSResp { handshakes: TLSRecord[]; certificates: CertRecord[]; note: string }

export default function TlsExplorer({ sessionId }: { sessionId: string }) {
  const [sessions] = usePoll<Session[]>("/api/captures", 5000);
  const id = sessionId || sessions?.[0]?.id || "";
  const [data, err] = usePoll<TLSResp>(id ? `/api/captures/${id}/tls?limit=5000` : null);
  const [q, setQ] = useState("");
  const [tab, setTab] = useState<"handshakes" | "certs">("handshakes");

  const hs = useMemo(() => (data?.handshakes ?? []).filter((r) => !q || `${r.sni} ${r.server} ${r.client} ${r.version} ${r.alpn}`.toLowerCase().includes(q.toLowerCase())), [data, q]);
  const certs = useMemo(() => (data?.certificates ?? []).filter((r) => !q || `${r.subject} ${r.sans} ${r.server}`.toLowerCase().includes(q.toLowerCase())), [data, q]);
  const verCount = useMemo(() => { const m: Record<string, number> = {}; for (const r of data?.handshakes ?? []) if (r.version) m[r.version] = (m[r.version] || 0) + 1; return m; }, [data]);

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>TLS Explorer</h1><p>Observed TLS handshakes and any certificates sent in the clear.</p></div>
        <SessionPicker sessions={sessions} id={id} base="/tls" />
      </div>
      <EncryptedNote />
      {Object.keys(verCount).length > 0 && <div className="row" style={{ marginBottom: ".8rem" }}>{Object.entries(verCount).map(([v, n]) => <Badge key={v} kind="plain">{v}: {n}</Badge>)}</div>}
      <div className="row" style={{ marginBottom: ".8rem" }}>
        <div className="row" style={{ gap: ".25rem" }}>
          <button className={tab === "handshakes" ? "on" : ""} onClick={() => setTab("handshakes")}>Handshakes ({data?.handshakes.length ?? 0})</button>
          <button className={tab === "certs" ? "on" : ""} onClick={() => setTab("certs")}>Certificates ({data?.certificates.length ?? 0})</button>
        </div>
        <input placeholder="Filter SNI / server / subject" value={q} onChange={(e) => setQ(e.target.value)} />
      </div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      <div className="card" style={{ padding: 0 }}>
        {tab === "handshakes" ? (
          <table className="data"><thead><tr><th>Time</th><th>Client</th><th>Server</th><th>SNI</th><th>Version</th><th>Cipher</th><th>ALPN</th><th>Status</th><th></th></tr></thead>
            <tbody>
              {hs.map((r, i) => (
                <tr key={i}>
                  <td className="hint">{fmtTime(r.time * 1000)}</td>
                  <td className="mono">{r.client}</td>
                  <td className="mono">{r.server}:{r.server_port}</td>
                  <td className="mono">{r.sni || <span className="hint">— (none / ECH)</span>}</td>
                  <td>{r.version ? <Badge kind="plain">{r.version}</Badge> : <span className="hint">?</span>}</td>
                  <td className="mono">{r.cipher}</td>
                  <td className="mono">{r.alpn}</td>
                  <td><Badge kind="plain">encrypted pass-through</Badge></td>
                  <td>{r.stream != null ? <PacketsLink id={id} filter={`tcp.stream==${r.stream}`}><button className="small ghost" onClick={(e) => e.preventDefault()}>Packets</button></PacketsLink> : <PacketsLink id={id} filter={`frame.number==${r.num}`}>↗</PacketsLink>}</td>
                </tr>
              ))}
              {hs.length === 0 && <tr><td colSpan={9} className="empty">No TLS handshakes observed.</td></tr>}
            </tbody>
          </table>
        ) : (
          <table className="data"><thead><tr><th>Time</th><th>Server</th><th>Subject</th><th>Subject alt names</th><th>Valid from</th><th>Valid to</th><th></th></tr></thead>
            <tbody>
              {certs.map((r, i) => (
                <tr key={i}>
                  <td className="hint">{fmtTime(r.time * 1000)}</td>
                  <td className="mono">{r.server}</td>
                  <td className="mono">{r.subject}</td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>{r.sans}</td>
                  <td className="mono hint">{r.not_before}</td><td className="mono hint">{r.not_after}</td>
                  <td><PacketsLink id={id} filter={`frame.number==${r.num}`}>↗</PacketsLink></td>
                </tr>
              ))}
              {certs.length === 0 && <tr><td colSpan={7} className="empty">No certificates seen in the clear. TLS 1.3 encrypts the certificate, so this is expected for modern servers.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

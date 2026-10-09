import { useMemo, useState } from "react";
import { fmtTime, type DNSRecord, type Session } from "../api";
import { Badge, usePoll } from "../ui";
import { SessionPicker, PacketsLink } from "../components/chrome";

export default function DnsExplorer({ sessionId }: { sessionId: string }) {
  const [sessions] = usePoll<Session[]>("/api/captures", 5000);
  const id = sessionId || sessions?.[0]?.id || "";
  const [recs, err] = usePoll<DNSRecord[]>(id ? `/api/captures/${id}/dns?limit=5000` : null);
  const [q, setQ] = useState("");
  const [onlyErr, setOnlyErr] = useState(false);
  const [grouped, setGrouped] = useState(true);

  const rows = useMemo(() => (recs ?? []).filter((r) =>
    (!q || `${r.query} ${r.client} ${r.answers}`.toLowerCase().includes(q.toLowerCase())) &&
    (!onlyErr || (r.response && r.rcode && r.rcode !== "NOERROR"))), [recs, q, onlyErr]);

  // Group queries with their most useful response per (client, name, type).
  const names = useMemo(() => {
    const m = new Map<string, { name: string; type: string; count: number; clients: Set<string>; answers: Set<string>; rcodes: Set<string>; last: number }>();
    for (const r of rows) {
      const k = r.query + "|" + r.type;
      let g = m.get(k);
      if (!g) { g = { name: r.query, type: r.type, count: 0, clients: new Set(), answers: new Set(), rcodes: new Set(), last: 0 }; m.set(k, g); }
      g.count++; if (r.client) g.clients.add(r.client); g.last = Math.max(g.last, r.time);
      if (r.answers) r.answers.split(/\s+/).filter(Boolean).forEach((a) => g!.answers.add(a));
      if (r.response && r.rcode) g.rcodes.add(r.rcode);
    }
    return [...m.values()].sort((a, b) => b.count - a.count);
  }, [rows]);

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>DNS Explorer</h1><p>Cleartext DNS observed through the appliance. Encrypted DNS (DoH/DoT) is not shown here; it appears as TLS/HTTPS to the resolver.</p></div>
        <SessionPicker sessions={sessions} id={id} base="/dns" />
      </div>
      <div className="row" style={{ marginBottom: ".8rem" }}>
        <input placeholder="Filter name / client / answer" value={q} onChange={(e) => setQ(e.target.value)} />
        <label className="inline"><input type="checkbox" checked={grouped} onChange={(e) => setGrouped(e.target.checked)} />Group by name</label>
        <label className="inline"><input type="checkbox" checked={onlyErr} onChange={(e) => setOnlyErr(e.target.checked)} />Errors only</label>
        <span className="hint">{rows.length.toLocaleString()} messages</span>
      </div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      <div className="card" style={{ padding: 0 }}>
        {grouped ? (
          <table className="data"><thead><tr><th>Name</th><th>Type</th><th>Queries</th><th>Clients</th><th>Answers</th><th>Result</th><th>Last seen</th></tr></thead>
            <tbody>
              {names.map((g, i) => (
                <tr key={i}>
                  <td className="mono"><PacketsLink id={id} filter={`dns.qry.name=="${g.name}"`}>{g.name || "(root)"}</PacketsLink></td>
                  <td><Badge kind="plain">{g.type}</Badge></td>
                  <td className="mono">{g.count}</td>
                  <td className="mono">{[...g.clients].join(", ")}</td>
                  <td className="mono" style={{ fontSize: ".8rem", wordBreak: "break-all" }}>{[...g.answers].slice(0, 6).join(", ")}{g.answers.size > 6 ? ` +${g.answers.size - 6}` : ""}</td>
                  <td>{[...g.rcodes].map((rc) => <Badge key={rc} kind={rc === "NOERROR" ? "ok" : "bad"}>{rc}</Badge>)}</td>
                  <td className="hint">{fmtTime(g.last * 1000)}</td>
                </tr>
              ))}
              {names.length === 0 && <tr><td colSpan={7} className="empty">No cleartext DNS observed.</td></tr>}
            </tbody>
          </table>
        ) : (
          <table className="data"><thead><tr><th>Time</th><th></th><th>Client</th><th>Resolver</th><th>Name</th><th>Type</th><th>Result / answers</th></tr></thead>
            <tbody>
              {rows.map((r, i) => (
                <tr key={i}>
                  <td className="hint">{fmtTime(r.time * 1000)}</td>
                  <td>{r.response ? <Badge kind={r.rcode && r.rcode !== "NOERROR" ? "bad" : "ok"} >resp</Badge> : <Badge kind="plain">query</Badge>}</td>
                  <td className="mono">{r.client}</td><td className="mono">{r.server}</td>
                  <td className="mono"><PacketsLink id={id} filter={`frame.number==${r.num}`}>{r.query}</PacketsLink></td>
                  <td>{r.type}</td>
                  <td className="mono" style={{ wordBreak: "break-all" }}>{r.response ? (r.rcode && r.rcode !== "NOERROR" ? r.rcode : r.answers) : ""}</td>
                </tr>
              ))}
              {rows.length === 0 && <tr><td colSpan={7} className="empty">No cleartext DNS observed.</td></tr>}
            </tbody>
          </table>
        )}
      </div>
    </div>
  );
}

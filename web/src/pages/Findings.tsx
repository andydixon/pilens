import { type Finding, type Session } from "../api";
import { Badge, go, usePoll } from "../ui";
import { SessionPicker } from "../components/chrome";

const sevRank: Record<string, number> = { medium: 0, low: 1, info: 2 };

export default function Findings({ sessionId }: { sessionId: string }) {
  const [sessions] = usePoll<Session[]>("/api/captures", 5000);
  const id = sessionId || sessions?.[0]?.id || "";
  const [findings, err] = usePoll<Finding[]>(id ? `/api/captures/${id}/findings?min=1` : null);
  const sorted = [...(findings ?? [])].sort((a, b) => (sevRank[a.severity] - sevRank[b.severity]) || b.count - a.count);

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Findings</h1><p>Observable network events with evidence. These are facts about the capture, not judgements: each one lists benign explanations.</p></div>
        <SessionPicker sessions={sessions} id={id} base="/findings" />
      </div>
      <div className="banner info" style={{ marginBottom: "1rem" }}><div>
        <b>This is a forensic aid, not an intrusion-detection system.</b>
        A finding means a pattern was observed (a retransmission, a SERVFAIL). It does not imply an attack or a fault. Use the evidence to investigate.
      </div></div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      {findings && sorted.length === 0 && <div className="empty">No notable events observed in this capture.</div>}
      <div className="stack">
        {sorted.map((f) => (
          <div className="card" key={f.rule}>
            <div className="row spread">
              <div className="row"><Badge kind={f.severity === "medium" ? "warn" : f.severity === "low" ? "plain" : "ok"}>{f.severity}</Badge><h2 style={{ fontSize: "1rem" }}>{f.title}</h2></div>
              <div className="row">
                <span className="mono">{f.count.toLocaleString()} packet{f.count === 1 ? "" : "s"}{f.flows ? ` · ${f.flows} flow${f.flows === 1 ? "" : "s"}` : ""}</span>
                {f.filter && <button className="small" onClick={() => go(`/analyse/${id}?filter=${encodeURIComponent(f.filter)}`)}>View packets</button>}
              </div>
            </div>
            <p className="hint" style={{ margin: ".5rem 0 .3rem" }}>{f.note}</p>
            <div className="row" style={{ gap: ".4rem" }}>
              <span className="hint">Detection:</span><code style={{ fontSize: ".8rem" }}>{f.filter || "capture drop counters"}</code>
              {f.examples.length > 0 && <><span className="hint">· e.g. packets</span>{f.examples.slice(0, 8).map((n) => (
                <a key={n} href="#" className="mono" onClick={(e) => { e.preventDefault(); go(`/analyse/${id}?filter=frame.number==${n}`); }}>#{n}</a>
              ))}</>}
            </div>
          </div>
        ))}
      </div>
    </div>
  );
}

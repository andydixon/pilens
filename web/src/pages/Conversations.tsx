import { useEffect, useMemo, useState } from "react";
import { api, fmtBytes, fmtDur, type Conversation, type FollowResult, type Session, type StreamChunk } from "../api";
import { Badge, Modal, copyText, go, usePoll, usePersist } from "../ui";
import { SessionPicker, Bar, PacketsLink } from "../components/chrome";

export default function Conversations({ sessionId }: { sessionId: string }) {
  const [sessions] = usePoll<Session[]>("/api/captures", 5000);
  const id = sessionId || sessions?.[0]?.id || "";
  const [transport, setTransport] = usePersist<"tcp" | "udp">("conv.transport", "tcp");
  const [convs, err] = usePoll<Conversation[]>(id ? `/api/captures/${id}/conversations?transport=${transport}` : null);
  const [q, setQ] = useState("");
  const [sort, setSort] = useState<keyof Conversation>("bytes");
  const [follow, setFollow] = useState<Conversation | null>(null);

  const rows = useMemo(() => {
    let r = (convs ?? []).filter((c) => !q || `${c.a_addr}:${c.a_port} ${c.b_addr}:${c.b_port} ${c.protocols}`.toLowerCase().includes(q.toLowerCase()));
    r = [...r].sort((a, b) => (b[sort] as number) - (a[sort] as number) || 0);
    return r;
  }, [convs, q, sort, transport]);
  const maxBytes = rows[0]?.bytes ?? 1;

  const convFilter = (c: Conversation) => {
    const ipA = c.a_addr.includes(":") ? "ipv6.addr" : "ip.addr";
    const p = c.transport;
    return `${ipA}==${c.a_addr} && ${ipA}==${c.b_addr} && ${p}.port==${c.a_port} && ${p}.port==${c.b_port}`;
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Conversations</h1><p>Traffic grouped by endpoint pair, from the packet index. Counts agree with the packet list (subject to capture drops).</p></div>
        <SessionPicker sessions={sessions} id={id} base="/conversations" />
      </div>
      <div className="row" style={{ marginBottom: ".8rem" }}>
        <div className="row" role="tablist" style={{ gap: ".25rem" }}>
          <button className={transport === "tcp" ? "on" : ""} onClick={() => setTransport("tcp")}>TCP</button>
          <button className={transport === "udp" ? "on" : ""} onClick={() => setTransport("udp")}>UDP</button>
        </div>
        <input placeholder="Filter endpoints / protocols" value={q} onChange={(e) => setQ(e.target.value)} />
        <span className="hint">{rows.length.toLocaleString()} conversations</span>
      </div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      <div className="card" style={{ padding: 0 }}>
        <table className="data">
          <thead><tr>
            <th>Endpoint A</th><th>Endpoint B</th><th>Protocols</th>
            {([["packets", "Packets"], ["bytes", "Bytes"], ["bytes_a_to_b", "A→B"], ["bytes_b_to_a", "B→A"]] as [keyof Conversation, string][]).map(([k, l]) =>
              <th key={k} style={{ cursor: "pointer" }} onClick={() => setSort(k)}>{l}{sort === k ? " ▾" : ""}</th>)}
            <th>Duration</th><th></th>
          </tr></thead>
          <tbody>
            {rows.map((c, i) => (
              <tr key={i}>
                <td className="mono">{c.a_addr}:{c.a_port}</td>
                <td className="mono">{c.b_addr}:{c.b_port}</td>
                <td>{c.protocols.split(",").map((p) => <Badge key={p} kind="plain">{p}</Badge>)}</td>
                <td className="mono">{c.packets.toLocaleString()}</td>
                <td style={{ minWidth: 130 }}><Bar value={c.bytes} max={maxBytes} /></td>
                <td className="mono">{fmtBytes(c.bytes_a_to_b)}</td>
                <td className="mono">{fmtBytes(c.bytes_b_to_a)}</td>
                <td className="mono">{fmtDur(c.end - c.start)}</td>
                <td><div className="row" style={{ flexWrap: "nowrap" }}>
                  {transport === "tcp" && c.stream != null && <button className="small" onClick={() => setFollow(c)}>Follow</button>}
                  <PacketsLink id={id} filter={convFilter(c)}><button className="small ghost" onClick={(e) => e.preventDefault()}>Packets</button></PacketsLink>
                </div></td>
              </tr>
            ))}
            {rows.length === 0 && <tr><td colSpan={9} className="empty">No {transport.toUpperCase()} conversations.</td></tr>}
          </tbody>
        </table>
      </div>
      {follow && <FollowModal id={id} conv={follow} onClose={() => setFollow(null)} onPackets={(f) => go(`/analyse/${id}?filter=${encodeURIComponent(f)}`)} />}
    </div>
  );
}

const printable = (b: number) => (b >= 0x20 && b < 0x7f) || b === 0x0a || b === 0x09;
function hexToText(hex: string) {
  let s = "";
  for (let i = 0; i < hex.length; i += 2) { const b = parseInt(hex.substr(i, 2), 16); s += printable(b) ? String.fromCharCode(b) : "."; }
  return s;
}
function hexDump(hex: string) {
  const out: string[] = [];
  for (let off = 0; off < hex.length; off += 32) {
    const slice = hex.substr(off, 32);
    const pairs = slice.match(/../g) ?? [];
    out.push((off / 2).toString(16).padStart(6, "0") + "  " + pairs.join(" ").padEnd(47) + "  " + hexToText(slice));
  }
  return out.join("\n");
}

function FollowModal({ id, conv, onClose, onPackets }: { id: string; conv: Conversation; onClose: () => void; onPackets: (f: string) => void }) {
  const [res, setRes] = useState<FollowResult | null>(null);
  const [err, setErr] = useState("");
  const [view, setView] = useState<"ascii" | "hex">("ascii");
  const [dir, setDir] = useState<"both" | "ab" | "ba">("both");

  useEffect(() => {
    setRes(null); setErr("");
    api<FollowResult>(`/api/captures/${id}/follow?seg=${conv.seg}&stream=${conv.stream}`)
      .then(setRes).catch((e) => setErr(e.message));
  }, [id, conv]);

  const shown = (res?.chunks ?? []).filter((c) => dir === "both" || c.dir === dir);
  const copyAll = () => copyText(shown.map((c) => view === "hex" ? c.hex : hexToText(c.hex)).join(""));

  return (
    <Modal open title={`Follow TCP stream ${conv.stream}`} onClose={onClose} footer={<>
      <button onClick={() => onPackets(`tcp.stream==${conv.stream}`)}>Show packets</button>
      <button onClick={copyAll}>Copy {dir === "both" ? "stream" : dir === "ab" ? "A→B" : "B→A"}</button>
      <button className="primary" onClick={onClose}>Close</button></>}>
      <div className="row spread">
        <span className="hint mono">{conv.a_addr}:{conv.a_port} ↔ {conv.b_addr}:{conv.b_port}</span>
        <div className="row" style={{ gap: ".25rem" }}>
          <select value={dir} onChange={(e) => setDir(e.target.value as any)} className="small"><option value="both">Both</option><option value="ab">A→B (client)</option><option value="ba">B→A (server)</option></select>
          <button className={"small" + (view === "ascii" ? " on" : "")} onClick={() => setView("ascii")}>ASCII</button>
          <button className={"small" + (view === "hex" ? " on" : "")} onClick={() => setView("hex")}>Hex</button>
        </div>
      </div>
      {res && <div className="hint">{fmtBytes(res.a_to_b)} client→server · {fmtBytes(res.b_to_a)} server→client{res.note ? " · " + res.note : ""}</div>}
      {err && <div className="err">{err}</div>}
      {!res && !err && <div className="empty">Reassembling…</div>}
      {res && (
        <pre style={{ maxHeight: "56vh", overflow: "auto", background: "var(--panel-2)", padding: ".6rem", borderRadius: 6, margin: 0, fontSize: ".82rem", whiteSpace: "pre-wrap", wordBreak: "break-all" }}>
          {shown.map((c, i) => <ChunkView key={i} chunk={c} view={view} />)}
          {shown.length === 0 && <span className="hint">No payload in this direction (handshake/empty).</span>}
        </pre>
      )}
      <p className="hint">Reconstructed from the captured TCP payload by tshark. This is the transport stream, not decrypted application content: for TLS it is ciphertext.</p>
    </Modal>
  );
}

function ChunkView({ chunk, view }: { chunk: StreamChunk; view: "ascii" | "hex" }) {
  const col = chunk.dir === "ab" ? "var(--cyan)" : "var(--accent)";
  const text = view === "hex" ? hexDump(chunk.hex) : hexToText(chunk.hex);
  return <span style={{ color: col }}>{text}{view === "ascii" ? "" : "\n"}</span>;
}

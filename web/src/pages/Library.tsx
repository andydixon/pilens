import { useRef, useState } from "react";
import { api, fmtBytes, fmtTime, type Session, type Segment } from "../api";
import { Badge, Modal, go, toast, usePoll } from "../ui";

export default function Library() {
  const [sessions, err, reload] = usePoll<Session[]>("/api/captures", 5000);
  const [q, setQ] = useState("");
  const [edit, setEdit] = useState<Session | null>(null);
  const [del, setDel] = useState<Session | null>(null);
  const [info, setInfo] = useState<{ s: Session; segs: Segment[]; verify?: any[] } | null>(null);
  const [uploading, setUploading] = useState(false);
  const file = useRef<HTMLInputElement>(null);

  const list = (sessions ?? []).filter((s) => !q || (s.name + " " + s.tags + " " + s.description + " " + s.notes).toLowerCase().includes(q.toLowerCase()));

  const upload = async (f: File) => {
    setUploading(true);
    try {
      const s = await api<Session>(`/api/captures/import?name=${encodeURIComponent(f.name)}`, { raw: f });
      toast(`Imported ${f.name}; indexing…`);
      reload();
      go("/analyse/" + s.id);
    } catch (e) { toast((e as Error).message, true); }
    setUploading(false);
  };

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Capture Library</h1><p>Stored sessions. Original packet files are kept unmodified, with SHA-256 hashes.</p></div>
        <div className="row">
          <input placeholder="Search name, tags, notes" value={q} onChange={(e) => setQ(e.target.value)} />
          <input ref={file} type="file" accept=".pcap,.pcapng,.cap" hidden onChange={(e) => e.target.files?.[0] && upload(e.target.files[0])} />
          <button onClick={() => file.current?.click()} disabled={uploading}>{uploading ? "Uploading…" : "Import pcap/pcapng"}</button>
        </div>
      </div>
      {err && <div className="banner bad"><div>{err}</div></div>}
      <div className="card" style={{ padding: 0 }}>
        <table className="data">
          <thead><tr><th>Name</th><th>State</th><th>Started</th><th>Duration</th><th>Packets</th><th>Size</th><th>Source</th><th></th></tr></thead>
          <tbody>
            {list.map((s) => (
              <tr key={s.id}>
                <td><a href={"#/analyse/" + s.id}>{s.name}</a>{s.preserved && <> <Badge kind="ok">preserved</Badge></>}{s.tags && <div className="hint">{s.tags}</div>}</td>
                <td><Badge kind={s.state === "running" ? "live" : s.state === "failed" ? "bad" : s.state === "importing" ? "warn" : "plain"}>{s.state}</Badge>{s.error && <div className="err hint" title={s.error}>{s.error.slice(0, 60)}</div>}</td>
                <td className="hint">{fmtTime(s.started_at)}</td>
                <td className="mono">{s.ended_at ? ((s.ended_at - s.started_at) / 1000).toFixed(0) + " s" : "–"}</td>
                <td className="mono">{s.packets.toLocaleString()}</td>
                <td className="mono">{fmtBytes(s.bytes)}</td>
                <td className="mono">{s.kind === "import" ? "import" : (s.interfaces ?? []).join(",")}{s.capture_filter && <div className="hint" title="capture filter">{s.capture_filter}</div>}</td>
                <td><div className="row" style={{ flexWrap: "nowrap" }}>
                  <button className="small" onClick={async () => setInfo({ s, segs: (await api(`/api/captures/${s.id}`)).segments ?? [] })}>Integrity</button>
                  <a className="btn small" href={`/api/captures/${s.id}/export`} download>Export</a>
                  <button className="small" onClick={() => setEdit({ ...s })}>Edit</button>
                  <button className="small danger" disabled={s.state === "running"} onClick={() => setDel(s)}>Delete</button>
                </div></td>
              </tr>
            ))}
            {list.length === 0 && <tr><td colSpan={8} className="empty">No sessions.</td></tr>}
          </tbody>
        </table>
      </div>

      <Modal open={!!edit} title="Edit session" onClose={() => setEdit(null)} footer={<><button onClick={() => setEdit(null)}>Cancel</button>
        <button className="primary" onClick={async () => { try { await api(`/api/captures/${edit!.id}`, { method: "PATCH", body: { Name: edit!.name, Description: edit!.description, Tags: edit!.tags, Notes: edit!.notes, Preserved: edit!.preserved } }); setEdit(null); reload(); } catch (e) { toast((e as Error).message, true); } }}>Save</button></>}>
        {edit && <>
          <label>Name<input value={edit.name} onChange={(e) => setEdit({ ...edit, name: e.target.value })} /></label>
          <label>Description<input value={edit.description} onChange={(e) => setEdit({ ...edit, description: e.target.value })} /></label>
          <label>Tags<input value={edit.tags} placeholder="comma separated" onChange={(e) => setEdit({ ...edit, tags: e.target.value })} /></label>
          <label>Operator notes<textarea rows={5} value={edit.notes} onChange={(e) => setEdit({ ...edit, notes: e.target.value })} /></label>
          <label className="inline"><input type="checkbox" checked={edit.preserved} onChange={(e) => setEdit({ ...edit, preserved: e.target.checked })} />Preserve: never delete automatically (retention or ring buffer)</label>
        </>}
      </Modal>

      <Modal open={!!del} title="Delete capture session?" onClose={() => setDel(null)} footer={<><button onClick={() => setDel(null)}>Cancel</button>
        <button className="danger" onClick={async () => { try { await api(`/api/captures/${del!.id}?confirm=${del!.id}`, { method: "DELETE" }); setDel(null); reload(); toast("Session deleted"); } catch (e) { toast((e as Error).message, true); } }}>Delete permanently</button></>}>
        <p>This permanently deletes <b>{del?.name}</b>: {del?.packets.toLocaleString()} packets, {fmtBytes(del?.bytes ?? 0)} of original capture files, and all derived indexes. It cannot be undone.</p>
        {del?.preserved && <div className="banner warn"><div>This session is marked <b>preserved</b>.</div></div>}
      </Modal>

      <Modal open={!!info} title="Integrity" onClose={() => setInfo(null)} footer={<>
        <a className="btn" href={`/api/captures/${info?.s.id}/manifest`} download>Download manifest</a>
        <button className="primary" onClick={async () => { const v = await api(`/api/captures/${info!.s.id}/verify`, { method: "POST" }); setInfo({ ...info!, verify: v }); }}>Verify hashes now</button></>}>
        {info && <>
          <dl className="kv">
            <dt>Session</dt><dd className="mono">{info.s.id}</dd>
            <dt>Clock synced</dt><dd>{String(info.s.meta?.clock_synchronised ?? "unknown")}</dd>
            <dt>Software</dt><dd className="mono">PiLens {info.s.meta?.pilens_version} · {info.s.meta?.tshark_version}</dd>
            {info.s.drops && <><dt>Drops</dt><dd className="mono" style={{ whiteSpace: "pre-wrap" }}>{info.s.drops}</dd></>}
          </dl>
          <table className="data"><thead><tr><th>#</th><th>File</th><th>Packets</th><th>SHA-256</th><th>Check</th></tr></thead><tbody>
            {info.segs.map((g) => { const v = info.verify?.find((x) => x.seq === g.seq); return (
              <tr key={g.seq}><td>{g.seq}</td><td className="mono">{g.file}{g.deleted && " (rotated out)"}</td><td className="mono">{g.count}</td>
                <td className="mono" style={{ fontSize: ".72rem", wordBreak: "break-all" }}>{g.sha256 || "(still being written)"}</td>
                <td>{v ? <Badge kind={v.status === "ok" ? "ok" : v.status === "mismatch" || v.status === "missing" ? "bad" : "warn"}>{v.status}</Badge> : ""}</td></tr>); })}
          </tbody></table>
          <p className="hint">Segment files are the original captured bytes. Packet summaries and dissections are derived on demand and are not evidence.</p>
        </>}
      </Modal>
    </div>
  );
}

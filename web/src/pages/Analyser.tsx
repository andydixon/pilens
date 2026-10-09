import { useCallback, useEffect, useMemo, useRef, useState } from "react";
import { api, onEvent, fmtBytes, type Detail, type Page, type Row, type Session, type TreeNode, type Iface } from "../api";
import PacketTable, { COLUMNS, defaultCols, type ColState, type ColourRule } from "../components/PacketTable";
import ProtoTree, { nodeAt, pathForByte } from "../components/ProtoTree";
import HexView from "../components/HexView";
import { Badge, ContextMenu, Modal, copyText, go, toast, usePersist, usePoll, type CtxItem } from "../ui";

const PAGE = 500;

interface Props { sessionId: string; initialFilter: string; focus: boolean; setFocus: (f: boolean) => void }

/** Quote a value for a Wireshark display filter. */
const dq = (s: string) => '"' + s.replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
const isAddr = (s: string) => /^[0-9.]+$/.test(s) || /^[0-9a-f:]+$/i.test(s);
function addrFilter(a: string) {
  if (/^\d+\.\d+\.\d+\.\d+$/.test(a)) return "ip.addr == " + a;
  if (/^([0-9a-f]{2}:){5}[0-9a-f]{2}$/i.test(a)) return "eth.addr == " + a;
  return "ipv6.addr == " + a;
}

export default function Analyser({ sessionId, initialFilter, focus, setFocus }: Props) {
  const [sessions, , reloadSessions] = usePoll<Session[]>("/api/captures", 5000);
  const live = sessions?.find((s) => s.state === "running");
  const id = sessionId || live?.id || sessions?.[0]?.id || "";
  const [sess, setSess] = useState<Session | null>(null);

  // filter state
  const [filterText, setFilterText] = useState(initialFilter);
  const [filter, setFilter] = useState(initialFilter);
  const [filterErr, setFilterErr] = useState("");
  const [filterValid, setFilterValid] = useState<boolean | null>(null);
  const [history, setHistory] = usePersist<string[]>("filter.history", []);
  const [saved, , reloadSaved] = usePoll<{ ID: number; Name: string; Kind: string; Expr: string }[]>("/api/filters/saved");

  // packet data
  const cache = useRef(new Map<number, Row>());
  const pages = useRef(new Set<number>());
  const nums = useRef<number[]>([]);
  const firstNum = useRef(1);
  const [total, setTotal] = useState(0);
  const [version, setVersion] = useState(0);
  const [loadingFilter, setLoadingFilter] = useState(false);
  const [frozen, setFrozen] = useState(false);
  const [pending, setPending] = useState(0);
  const [follow, setFollow] = usePersist("follow", true);
  const [uiDropped, setUiDropped] = useState(0);
  const [t0, setT0] = useState(0);

  // selection / detail
  const [sel, setSel] = useState(-1);
  const [detail, setDetail] = useState<Detail | null>(null);
  const [detailErr, setDetailErr] = useState("");
  const [treeSel, setTreeSel] = useState("");

  // layout
  const [cols, setCols] = usePersist<ColState[]>("columns", defaultCols);
  const [absTime, setAbsTime] = usePersist("abstime", false);
  const [split, setSplit] = usePersist("split", [0.5, 0.28]);
  const [rules] = usePersist<ColourRule[]>("colour.rules", []);
  const [prefs] = usePersist<{ density?: string }>("prefs", {});
  const rowH = prefs.density === "comfortable" ? 27 : 22;
  const [colsOpen, setColsOpen] = useState(false);
  const [startOpen, setStartOpen] = useState(false);
  const [ctx, setCtx] = useState<{ at: { x: number; y: number }; items: CtxItem[] } | null>(null);
  const filterRef = useRef<HTMLInputElement>(null);

  const reset = useCallback(() => {
    cache.current.clear(); pages.current.clear(); nums.current = [];
    setVersion((v) => v + 1);
  }, []);

  const loadPage = useCallback(async (pg: number, force = false) => {
    if (!id || (!force && pages.current.has(pg))) return;
    pages.current.add(pg);
    try {
      const p = await api<Page>(`/api/captures/${id}/packets?offset=${pg * PAGE}&limit=${PAGE}&filter=${encodeURIComponent(filter)}`);
      if (p.filtered) {
        (p.nums ?? []).forEach((n, i) => { nums.current[pg * PAGE + i] = n; });
        const byNum = new Map(p.rows.map((r) => [r.n, r]));
        (p.nums ?? []).forEach((n, i) => { const r = byNum.get(n); if (r) cache.current.set(pg * PAGE + i, r); });
      } else {
        firstNum.current = p.first || 1;
        p.rows.forEach((r) => cache.current.set(r.n - firstNum.current, r));
      }
      if (pg === 0 && p.rows[0]) setT0((t) => t || p.rows[0].t);
      setTotal(p.total);
      setVersion((v) => v + 1);
      setFilterErr("");
    } catch (e) {
      pages.current.delete(pg);
      setFilterErr((e as Error).message);
    }
  }, [id, filter]);

  // (re)load when session or filter changes
  useEffect(() => {
    reset(); setSel(-1); setDetail(null); setTotal(0); setT0(0);
    if (!id) return;
    setLoadingFilter(!!filter);
    loadPage(0, true).finally(() => setLoadingFilter(false));
  }, [id, filter]); // eslint-disable-line

  useEffect(() => {
    if (!id) { setSess(null); return; }
    api<{ session: Session }>(`/api/captures/${id}`).then((d) => setSess(d.session)).catch(() => setSess(null));
  }, [id, sessions]);

  const need = useCallback((a: number, b: number) => {
    for (let pg = Math.floor(a / PAGE); pg <= Math.floor((b - 1) / PAGE); pg++) {
      if (pages.current.has(pg)) continue; // live rows for loaded pages arrive via events
      for (let i = Math.max(a, pg * PAGE); i < Math.min(b, (pg + 1) * PAGE); i++) if (!cache.current.has(i)) { loadPage(pg); break; }
    }
  }, [loadPage]);

  // live updates
  const frozenRef = useRef(frozen); frozenRef.current = frozen;
  useEffect(() => {
    let raf = 0, dirty = false, maxPos = -1;
    const flush = () => { raf = 0; if (dirty) { dirty = false; setTotal((t) => Math.max(t, maxPos + 1)); setVersion((v) => v + 1); } };
    return onEvent((type, d) => {
      if (type === "capture" && d.id === id) setSess(d);
      if (d.session !== id) return;
      if (type === "resync") { if (d.ui_dropped) setUiDropped(d.ui_dropped); if (!frozenRef.current) { reset(); loadPage(0, true); } return; }
      if (type !== "packets" || filter) return;
      if (frozenRef.current) { setPending((n) => n + d.rows.length); return; }
      for (const r of d.rows as Row[]) {
        const pos = r.n - firstNum.current;
        cache.current.set(pos, r);
        maxPos = Math.max(maxPos, pos);
        if (!t0 && pos === 0) setT0(r.t);
      }
      dirty = true;
      if (!raf) raf = window.setTimeout(flush, 200) as unknown as number; // ≤5 renders/s regardless of packet rate
    });
  }, [id, filter, reset, loadPage, t0]);

  // filtered live views: re-evaluate periodically (tshark runs server-side)
  useEffect(() => {
    if (!filter || sess?.state !== "running" || frozen) return;
    const t = setInterval(() => { pages.current.clear(); loadPage(Math.max(0, Math.floor((total - 1) / PAGE)), true); }, 3000);
    return () => clearInterval(t);
  }, [filter, sess?.state, frozen, total, loadPage]);

  // load detail for selection
  useEffect(() => {
    const r = cache.current.get(sel);
    if (sel < 0 || !r || !id) { setDetail(null); return; }
    const ctl = new AbortController();
    setDetailErr("");
    api<{ detail: Detail; error?: string }>(`/api/captures/${id}/packets/${r.n}`, { signal: ctl.signal })
      .then((d) => { setDetail(d.detail); setDetailErr(d.error ?? ""); setTreeSel(""); })
      .catch((e) => { if (e.name !== "AbortError") { setDetail(null); setDetailErr(e.message); } });
    return () => ctl.abort();
  }, [sel, id, version > 0 && cache.current.has(sel)]); // eslint-disable-line

  const bytes = useMemo(() => {
    const h = detail?.bytes ?? "";
    const b = new Uint8Array(h.length / 2);
    for (let i = 0; i < b.length; i++) b[i] = parseInt(h.substr(i * 2, 2), 16);
    return b;
  }, [detail]);
  const selNode = detail?.tree && treeSel ? nodeAt(detail.tree, treeSel) : undefined;
  const hl: [number, number] | null = selNode && selNode.verified && selNode.size > 0 ? [selNode.pos, selNode.size] : null;

  // filter validation (debounced, via tshark)
  useEffect(() => {
    if (!filterText.trim()) { setFilterValid(null); return; }
    const t = setTimeout(() => {
      api("/api/filters/validate", { body: { kind: "display", filter: filterText } })
        .then((r) => { setFilterValid(r.valid); setFilterErr(r.valid ? "" : r.error); }).catch(() => {});
    }, 350);
    return () => clearTimeout(t);
  }, [filterText]);

  const applyFilter = (f = filterText) => {
    setFilterText(f);
    setFilter(f.trim());
    if (f.trim()) setHistory((h) => [f.trim(), ...h.filter((x) => x !== f.trim())].slice(0, 30));
  };

  // keyboard shortcuts
  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (e.key === "/" && !/INPUT|TEXTAREA|SELECT/.test(t.tagName)) { filterRef.current?.focus(); e.preventDefault(); }
      if (e.key === "Escape" && t === filterRef.current) { filterRef.current?.blur(); }
      if (/INPUT|TEXTAREA|SELECT/.test(t.tagName)) return;
      if (e.key === " " && !e.ctrlKey) { setFrozen((f) => !f); e.preventDefault(); }
      if (e.key === "f" && !e.ctrlKey && !e.metaKey) { setFollow((f) => !f); }
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [setFollow]);

  const unfreeze = () => { setFrozen(false); setPending(0); reset(); loadPage(Math.max(0, Math.floor((total - 1) / PAGE)), true); loadPage(0, true); };

  const control = async (path: string, body?: any) => {
    try { await api(path, { method: "POST", body }); reloadSessions(); } catch (e) { toast((e as Error).message, true); }
  };

  const dragSplit = (which: 0 | 1, e: React.MouseEvent) => {
    e.preventDefault();
    const box = (e.currentTarget.parentElement as HTMLElement).getBoundingClientRect();
    const target = e.currentTarget as HTMLElement;
    target.classList.add("drag");
    const move = (ev: MouseEvent) => {
      const f = Math.min(.85, Math.max(.1, (ev.clientY - box.top) / box.height));
      setSplit((s) => which === 0 ? [f, Math.min(s[1], .9 - f)] : [s[0], Math.max(.08, f - s[0])]);
    };
    const up = () => { target.classList.remove("drag"); removeEventListener("mousemove", move); removeEventListener("mouseup", up); };
    addEventListener("mousemove", move); addEventListener("mouseup", up);
  };

  const rowMenu = (pos: number, e: React.MouseEvent) => {
    const r = cache.current.get(pos);
    if (!r) return;
    const and = (f: string) => filter ? `(${filter}) && ${f}` : f;
    const conv = r.sp !== undefined && r.dp !== undefined && isAddr(r.s) && isAddr(r.d)
      ? `${addrFilter(r.s).replace("addr ==", "addr eq")} && ${addrFilter(r.d).replace("addr ==", "addr eq")} && ${r.st !== undefined ? "tcp" : "udp"}.port in {${r.sp} ${r.dp}}` : "";
    const items: CtxItem[] = [
      ...(isAddr(r.s) ? [{ label: `Filter: ${addrFilter(r.s)}`, onClick: () => applyFilter(addrFilter(r.s)) }] : []),
      ...(isAddr(r.d) ? [{ label: `Filter: ${addrFilter(r.d)}`, onClick: () => applyFilter(addrFilter(r.d)) }] : []),
      ...(r.st !== undefined ? [{ label: `Filter: tcp.stream == ${r.st}`, onClick: () => applyFilter(`tcp.stream == ${r.st}`) }] : []),
      ...(conv ? [{ label: "Filter: this conversation", onClick: () => applyFilter(conv) }] : []),
      ...(filter ? [{ label: "Exclude source from current filter", onClick: () => isAddr(r.s) && applyFilter(and(`!(${addrFilter(r.s)})`)) }] : []),
      { label: "", sep: true },
      { label: "Copy summary", onClick: () => copyText(`${r.n}\t${r.t}\t${r.s}\t${r.d}\t${r.p}\t${r.l}\t${r.i}`) },
      { label: "Copy bytes as hex", onClick: () => detail && copyText(detail.bytes) },
    ];
    setCtx({ at: { x: e.clientX, y: e.clientY }, items });
  };

  const treeMenu = (n: TreeNode, e: React.MouseEvent) => {
    if (!n.field) return;
    const v = n.show ?? "";
    const expr = !v ? n.field : /^-?[0-9.]+$|^0x[0-9a-f]+$/i.test(v) || /^[0-9a-f:.]+$/i.test(v) && v.length > 3 ? `${n.field} == ${v}` : `${n.field} == ${dq(v)}`;
    setCtx({
      at: { x: e.clientX, y: e.clientY }, items: [
        { label: `Apply as filter: ${expr.length > 60 ? expr.slice(0, 60) + "…" : expr}`, onClick: () => applyFilter(expr) },
        { label: `Prepare filter (edit first)`, onClick: () => { setFilterText(expr); filterRef.current?.focus(); } },
        { label: `Filter: field present (${n.field})`, onClick: () => applyFilter(n.field!) },
        { label: "", sep: true },
        { label: "Copy value", onClick: () => copyText(v) },
        { label: "Copy line", onClick: () => copyText(n.label) },
        { label: "Copy field name", onClick: () => copyText(n.field!) },
      ],
    });
  };

  const running = sess?.state === "running";
  const lag = sess?.ingest_lag ?? 0;

  return (
    <div className="analyser">
      <div className="toolbar" role="toolbar" aria-label="Capture controls">
        <select value={id} onChange={(e) => go("/analyse/" + e.target.value)} aria-label="Capture session" style={{ maxWidth: 280 }}>
          {!id && <option value="">No capture sessions</option>}
          {sessions?.map((s) => <option key={s.id} value={s.id}>{s.state === "running" ? "● " : ""}{s.name} ({s.packets.toLocaleString()} pkts)</option>)}
        </select>
        <div className="divider" />
        {!live && <button className="primary" onClick={() => setStartOpen(true)}>● Start capture</button>}
        {live && <>
          <button className="danger" onClick={() => control("/api/captures/live/stop")} title="Stop capture and finalise files">■ Stop</button>
          <button className={live.paused ? "on" : ""} onClick={() => control("/api/captures/live/pause", { paused: !live.paused })}
            title="Pause capture: dumpcap keeps running but packets are discarded and not stored. Recorded in the session log.">
            {live.paused ? "▶ Resume capture" : "❚❚ Pause capture"}</button>
        </>}
        <button className={frozen ? "on" : ""} onClick={() => frozen ? unfreeze() : setFrozen(true)} title="Pause view (Space): stop updating this table. Capture continues.">
          {frozen ? `Resume view${pending ? ` (+${pending.toLocaleString()})` : ""}` : "Pause view"}</button>
        <button className={follow ? "on" : ""} onClick={() => setFollow(!follow)} title="Auto-scroll to newest packet (f)">⤓ Follow</button>
        <div className="divider" />
        <button onClick={() => setColsOpen(true)}>Columns</button>
        <button onClick={() => setAbsTime(!absTime)} title="Toggle relative / absolute UTC time">{absTime ? "UTC time" : "Relative time"}</button>
        {id && <>
          <a className="btn" href={`/api/captures/${id}/export`} download>Export all</a>
          {filter && <a className="btn" href={`/api/captures/${id}/export?filter=${encodeURIComponent(filter)}`} download>Export displayed</a>}
        </>}
        <span style={{ flex: 1 }} />
        <button className="ghost" onClick={() => setFocus(!focus)} title="Focus mode (Shift+F)">{focus ? "Exit focus" : "Focus"}</button>
      </div>

      <div className="filterbar">
        <span className="kind" title="Display filters select stored packets after capture. They are evaluated by tshark and use Wireshark syntax.">Display filter</span>
        <input ref={filterRef} list="filter-hist" value={filterText} placeholder="e.g. dns || tls.handshake.type == 1 · press / to focus"
          className={filterValid === false ? "invalid" : filterValid ? "valid" : ""} spellCheck={false} aria-label="Display filter"
          onChange={(e) => setFilterText(e.target.value)} onKeyDown={(e) => e.key === "Enter" && applyFilter()} />
        <datalist id="filter-hist">{history.map((h) => <option key={h} value={h} />)}{saved?.filter((s) => s.Kind === "display").map((s) => <option key={s.ID} value={s.Expr}>{s.Name}</option>)}</datalist>
        <button onClick={() => applyFilter()} disabled={filterValid === false}>Apply</button>
        {filter && <button className="ghost" onClick={() => applyFilter("")}>Clear</button>}
        <button className="ghost" disabled={!filterText || filterValid === false} onClick={async () => {
          const name = prompt("Save filter as:", filterText.slice(0, 40));
          if (name) { await api("/api/filters/saved", { body: { Name: name, Kind: "display", Expr: filterText } }); reloadSaved(); toast("Filter saved"); }
        }}>Save</button>
        {saved && saved.filter((s) => s.Kind === "display").length > 0 && (
          <select value="" onChange={(e) => e.target.value && applyFilter(e.target.value)} aria-label="Saved filters" style={{ maxWidth: 160 }}>
            <option value="">Saved…</option>
            {saved.filter((s) => s.Kind === "display").map((s) => <option key={s.ID} value={s.Expr}>{s.Name}</option>)}
          </select>
        )}
      </div>
      {filterErr && <div className="filtererr" role="alert">{filterErr}</div>}

      {!id ? (
        <div className="page"><div className="empty"><h2>No captures yet</h2><p>Start a live capture on the access-point interface, or import a pcap/pcapng file in the Capture Library.</p><button className="primary" onClick={() => setStartOpen(true)}>Start capture</button></div></div>
      ) : (
        <div className="panes">
          <div className="pane" style={{ flex: `0 0 ${split[0] * 100}%` }}>
            <PacketTable total={total} rowAt={(i) => cache.current.get(i)} need={need} selected={sel} onSelect={(i) => { setSel(i); if (running) setFollow(false); }}
              onContext={rowMenu} cols={cols} setCols={setCols} rowH={rowH} follow={follow && running && !frozen && !filter} t0={t0} absTime={absTime} rules={rules} version={version} />
          </div>
          <div className="splitter" role="separator" aria-orientation="horizontal" onMouseDown={(e) => dragSplit(0, e)} />
          <div className="pane" style={{ flex: `0 0 ${split[1] * 100}%` }}>
            <div className="pane-title"><span>Packet details{detail ? ` · #${detail.row.n}` : ""}</span><span className="sp" />{detail?.note && <span title={detail.note}>ⓘ segment {detail.segment}</span>}</div>
            {detailErr && <div className="filtererr">{detailErr}</div>}
            {detail?.tree ? <ProtoTree tree={detail.tree} selected={treeSel} onSelect={setTreeSel} onContext={treeMenu} />
              : <div className="empty">{sel < 0 ? "Select a packet." : "Dissecting…"}</div>}
          </div>
          <div className="splitter" role="separator" aria-orientation="horizontal" onMouseDown={(e) => dragSplit(1, e)} />
          <div className="pane" style={{ flex: 1 }}>
            {detail ? <HexView bytes={bytes} hl={hl} onByte={(b) => { const p = detail.tree && pathForByte(detail.tree, b); if (p) setTreeSel(p); }} />
              : <><div className="pane-title">Bytes</div><div className="empty">–</div></>}
          </div>
        </div>
      )}

      <div className="statusbar" aria-live="off">
        {sess ? <>
          <Badge kind={running ? (sess.paused ? "warn" : "live") : sess.state === "failed" ? "bad" : "plain"}>{running ? (sess.paused ? "capture paused" : "capturing") : sess.state}</Badge>
          <span>Captured <b>{sess.packets.toLocaleString()}</b></span>
          <span title="Packets written to disk but not yet summarised by tshark">Ingest lag <b>{lag.toLocaleString()}</b></span>
          <span>Displayed <b>{total.toLocaleString()}</b>{loadingFilter ? " (filtering…)" : ""}</span>
          <span title="Live updates this browser missed because it fell behind. Captured packets are unaffected; the view re-synchronised.">UI updates dropped <b>{uiDropped}</b></span>
          <span title="Packets the kernel or dumpcap could not capture. Reported by dumpcap when the capture stops.">Capture drops <b>{running ? "reported at stop" : (sess.drops.match(/(\d+)\/(\d+)/g)?.map((x) => x.split("/")[1]).join("+") ?? "n/a")}</b></span>
          <span>{fmtBytes(sess.bytes)}</span>
          {sess.error && <span className="err" title={sess.error}>⚠ {sess.error.slice(0, 80)}</span>}
          <span style={{ flex: 1 }} />
          <span className="hint">Encrypted payloads are shown as captured: still encrypted.</span>
        </> : <span>No session selected</span>}
      </div>

      <ColumnsDialog open={colsOpen} cols={cols} setCols={setCols} onClose={() => setColsOpen(false)} />
      <StartDialog open={startOpen} onClose={() => setStartOpen(false)} onStarted={(s) => { setStartOpen(false); reloadSessions(); go("/analyse/" + s.id); }} />
      <ContextMenu at={ctx?.at ?? null} items={ctx?.items ?? []} onClose={() => setCtx(null)} />
    </div>
  );
}

function ColumnsDialog({ open, cols, setCols, onClose }: { open: boolean; cols: ColState[]; setCols: (c: ColState[]) => void; onClose: () => void }) {
  // add any columns introduced since the layout was saved
  const all = [...cols, ...defaultCols.filter((d) => !cols.some((c) => c.id === d.id)).map((d) => ({ ...d, on: false }))];
  const mv = (i: number, d: number) => { const a = [...all]; const [x] = a.splice(i, 1); a.splice(Math.max(0, Math.min(a.length, i + d)), 0, x); setCols(a); };
  return (
    <Modal open={open} title="Columns" onClose={onClose} footer={<><button onClick={() => setCols(defaultCols)}>Reset</button><button className="primary" onClick={onClose}>Done</button></>}>
      <p className="hint">Show, hide and reorder columns. Drag the edge of a column header to resize it. The layout is saved in this browser.</p>
      <div className="stack" style={{ gap: ".25rem" }}>
        {all.map((c, i) => (
          <div key={c.id} className="row spread">
            <label className="inline"><input type="checkbox" checked={c.on} onChange={(e) => setCols(all.map((x) => x.id === c.id ? { ...x, on: e.target.checked } : x))} />{COLUMNS.find((d) => d.id === c.id)?.title}</label>
            <span className="row"><button className="small" onClick={() => mv(i, -1)} aria-label="Move up">↑</button><button className="small" onClick={() => mv(i, 1)} aria-label="Move down">↓</button></span>
          </div>
        ))}
      </div>
    </Modal>
  );
}

function StartDialog({ open, onClose, onStarted }: { open: boolean; onClose: () => void; onStarted: (s: Session) => void }) {
  const [ifaces, setIfaces] = useState<Iface[]>([]);
  const [chosen, setChosen] = useState<string[]>([]);
  const [name, setName] = useState("");
  const [bpf, setBpf] = useState("");
  const [bpfErr, setBpfErr] = useState("");
  const [ring, setRing] = useState(0);
  const [busy, setBusy] = useState(false);
  const [err, setErr] = useState("");

  useEffect(() => {
    if (!open) return;
    Promise.all([api("/api/system/interfaces"), api("/api/network").catch(() => null)]).then(([d, n]) => {
      setIfaces(d.interfaces ?? []);
      const ap = n?.config?.ap?.interface;
      setChosen((c) => c.length ? c : ap ? [ap] : []);
    });
  }, [open]);

  useEffect(() => {
    if (!bpf.trim()) { setBpfErr(""); return; }
    const t = setTimeout(() => api("/api/filters/validate", { body: { kind: "capture", filter: bpf, interface: chosen[0] ?? "any" } }).then((r) => setBpfErr(r.valid ? "" : r.error)), 400);
    return () => clearTimeout(t);
  }, [bpf, chosen]);

  const start = async () => {
    setBusy(true); setErr("");
    try { onStarted(await api<Session>("/api/captures", { body: { name, interfaces: chosen, capture_filter: bpf, ring_segments: ring } })); }
    catch (e) { setErr((e as Error).message); }
    setBusy(false);
  };

  return (
    <Modal open={open} title="Start capture" onClose={onClose} footer={<><button onClick={onClose}>Cancel</button><button className="primary" disabled={busy || !chosen.length || !!bpfErr} onClick={start}>{busy ? "Starting…" : "Start"}</button></>}>
      <label>Name<input value={name} placeholder="optional" onChange={(e) => setName(e.target.value)} /></label>
      <div><span className="hint">Interfaces</span>
        <div className="choice">{ifaces.map((i) => (
          <label key={i.name}><input type="checkbox" checked={chosen.includes(i.name)} onChange={(e) => setChosen(e.target.checked ? [...chosen, i.name] : chosen.filter((x) => x !== i.name))} />
            <span className="mono">{i.name}{i.wireless ? " (Wi-Fi)" : ""}<small>{(i.addrs ?? []).join(" ")}</small></span></label>))}
        </div>
      </div>
      <label>Capture filter (BPF, applied by the kernel while capturing)
        <input className={"mono" + (bpfErr ? " invalid" : "")} value={bpf} placeholder="e.g. not port 22" onChange={(e) => setBpf(e.target.value)} />
        <span className="hint">Packets excluded here are never stored. To narrow what you see after capture, use a display filter instead.</span>
        {bpfErr && <span className="err mono">{bpfErr}</span>}
      </label>
      <label>Ring buffer: keep only the newest N segment files (0 = keep all, within the storage quota)
        <input type="number" min={0} value={ring} onChange={(e) => setRing(+e.target.value)} /></label>
      {err && <div className="err">{err}</div>}
    </Modal>
  );
}

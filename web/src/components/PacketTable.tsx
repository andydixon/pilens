// Virtualised packet list. Only visible rows are rendered; rows arrive lazily.
import { useEffect, useLayoutEffect, useRef, useState } from "react";
import type { Row } from "../api";

export interface ColDef { id: string; title: string; w: number; get: (r: Row, ctx: { t0: number; abs: boolean }) => string | number | undefined; right?: boolean }

export const COLUMNS: ColDef[] = [
  { id: "no", title: "No.", w: 72, get: (r) => r.n, right: true },
  { id: "time", title: "Time", w: 128, get: (r, c) => c.abs ? new Date(r.t * 1000).toISOString().slice(11, 26) : (r.t - c.t0).toFixed(6), right: true },
  { id: "src", title: "Source", w: 170, get: (r) => r.s },
  { id: "dst", title: "Destination", w: 170, get: (r) => r.d },
  { id: "proto", title: "Protocol", w: 86, get: (r) => r.p },
  { id: "len", title: "Length", w: 64, get: (r) => r.l, right: true },
  { id: "info", title: "Info", w: 640, get: (r) => r.i },
  { id: "sport", title: "Src port", w: 72, get: (r) => r.sp, right: true },
  { id: "dport", title: "Dst port", w: 72, get: (r) => r.dp, right: true },
  { id: "stream", title: "TCP stream", w: 84, get: (r) => r.st, right: true },
  { id: "flags", title: "TCP flags", w: 120, get: (r) => r.tf },
  { id: "ttl", title: "TTL/Hop", w: 64, get: (r) => r.ttl, right: true },
  { id: "vlan", title: "VLAN", w: 56, get: (r) => r.vl, right: true },
];

export interface ColState { id: string; w: number; on: boolean }
export const defaultCols: ColState[] = COLUMNS.map((c) => ({ id: c.id, w: c.w, on: ["no", "time", "src", "dst", "proto", "len", "info"].includes(c.id) }));

export interface ColourRule { field: "proto" | "info" | "src" | "dst"; contains: string; colour: string }

// Wireshark's default colouring-rule names (reported by tshark --color) mapped to our palette.
export function rowClass(r: Row): string {
  const p = r.p.toUpperCase();
  switch (r.c) {
    case "Bad TCP": case "ICMP errors": case "Checksum Errors": case "TTL low or unexpected": return "c-bad";
    case "TCP RST": case "SCTP ABORT": return "c-rst";
    case "TCP SYN/FIN": return "c-synfin";
    case "ARP": return "c-arp";
    case "ICMP": return "c-icmp";
    case "HTTP": return "c-http";
    case "Broadcast": return "c-bcast";
  }
  if (/^(DNS|MDNS|LLMNR|NBNS)/.test(p)) return "c-dns";
  if (/^(TLS|SSL|QUIC|DTLS)/.test(p)) return "c-tls";
  if (/^HTTP/.test(p)) return "c-http";
  if (r.c === "UDP") return "c-udp";
  return "c-tcp";
}

interface Props {
  total: number;
  rowAt: (pos: number) => Row | undefined;
  need: (start: number, end: number) => void;
  selected: number;
  onSelect: (pos: number) => void;
  onContext: (pos: number, e: React.MouseEvent) => void;
  cols: ColState[];
  setCols: (c: ColState[]) => void;
  rowH: number;
  follow: boolean;
  t0: number;
  absTime: boolean;
  rules: ColourRule[];
  version: number; // bumps when row data changes
}

export default function PacketTable(p: Props) {
  const ref = useRef<HTMLDivElement>(null);
  const [scroll, setScroll] = useState({ top: 0, h: 400 });
  const defs = p.cols.filter((c) => c.on).map((c) => ({ ...COLUMNS.find((d) => d.id === c.id)!, w: c.w }));
  const HDR = 24;

  const first = Math.max(0, Math.floor((scroll.top) / p.rowH) - 10);
  const last = Math.min(p.total, Math.ceil((scroll.top + scroll.h) / p.rowH) + 10);

  useEffect(() => { if (last > first) p.need(first, last); }, [first, last, p.total, p.version]); // eslint-disable-line

  useLayoutEffect(() => {
    const el = ref.current!;
    const ro = new ResizeObserver(() => setScroll((s) => ({ ...s, h: el.clientHeight })));
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  useLayoutEffect(() => {
    if (p.follow && ref.current) ref.current.scrollTop = ref.current.scrollHeight;
  }, [p.follow, p.total]);

  // keep the selection visible when moved by keyboard
  useEffect(() => {
    const el = ref.current;
    if (!el || p.selected < 0) return;
    const y = p.selected * p.rowH;
    if (y < el.scrollTop) el.scrollTop = y;
    else if (y + p.rowH > el.scrollTop + el.clientHeight - HDR) el.scrollTop = y + p.rowH - el.clientHeight + HDR;
  }, [p.selected]); // eslint-disable-line

  const onKey = (e: React.KeyboardEvent) => {
    const page = Math.max(1, Math.floor((ref.current?.clientHeight ?? 400) / p.rowH) - 1);
    const mv: Record<string, number> = { ArrowDown: 1, ArrowUp: -1, PageDown: page, PageUp: -page, j: 1, k: -1 };
    let n = p.selected;
    if (e.key in mv) n = Math.max(0, Math.min(p.total - 1, (n < 0 ? 0 : n) + mv[e.key]));
    else if (e.key === "Home") n = 0;
    else if (e.key === "End") n = p.total - 1;
    else return;
    e.preventDefault();
    p.onSelect(n);
  };

  const startResize = (i: number, e: React.MouseEvent) => {
    e.preventDefault(); e.stopPropagation();
    const x0 = e.clientX, id = defs[i].id, w0 = defs[i].w;
    const move = (ev: MouseEvent) => p.setCols(p.cols.map((c) => c.id === id ? { ...c, w: Math.max(40, w0 + ev.clientX - x0) } : c));
    const up = () => { removeEventListener("mousemove", move); removeEventListener("mouseup", up); };
    addEventListener("mousemove", move); addEventListener("mouseup", up);
  };

  const width = defs.reduce((a, c) => a + c.w, 0);
  const custom = (r: Row) => p.rules.find((x) => x.contains && String((x.field === "proto" ? r.p : x.field === "info" ? r.i : x.field === "src" ? r.s : r.d) ?? "").toLowerCase().includes(x.contains.toLowerCase()));
  const rows = [];
  for (let i = first; i < last; i++) {
    const r = p.rowAt(i);
    const style: React.CSSProperties = { top: HDR + i * p.rowH, width };
    if (!r) {
      rows.push(<div key={i} className="prow ph" style={style}><div style={{ width: defs[0]?.w }}>…</div><div>not yet indexed</div></div>);
      continue;
    }
    const cr = custom(r);
    if (cr) style.background = cr.colour;
    rows.push(
      <div key={i} role="row" aria-selected={i === p.selected} className={"prow " + (cr ? "" : rowClass(r)) + (i === p.selected ? " sel" : "")} style={style}
        onMouseDown={() => p.onSelect(i)} onContextMenu={(e) => { e.preventDefault(); p.onSelect(i); p.onContext(i, e); }}>
        {defs.map((c) => <div key={c.id} style={{ width: c.w, textAlign: c.right ? "right" : undefined }}>{c.get(r, { t0: p.t0, abs: p.absTime }) ?? ""}</div>)}
      </div>,
    );
  }

  return (
    <div ref={ref} className="ptable" tabIndex={0} role="grid" aria-label="Packet list" aria-rowcount={p.total} onKeyDown={onKey}
      onScroll={(e) => setScroll({ top: e.currentTarget.scrollTop, h: e.currentTarget.clientHeight })}>
      <div className="hdr" role="row" style={{ width }}>
        {defs.map((c, i) => <div key={c.id} role="columnheader" style={{ width: c.w, justifyContent: c.right ? "flex-end" : undefined }}>{c.title}<span className="rz" onMouseDown={(e) => startResize(i, e)} /></div>)}
      </div>
      <div style={{ height: p.total * p.rowH, width }} />
      {rows}
      {p.total === 0 && <div className="empty" style={{ position: "absolute", top: 60, width: "100%" }}>No packets.</div>}
    </div>
  );
}

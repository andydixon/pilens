// Hex / ASCII inspector over the original captured bytes.
import { useEffect, useMemo, useRef, useState } from "react";
import { copyText } from "../ui";

interface Props { bytes: Uint8Array; hl: [number, number] | null; onByte: (b: number) => void }

const printable = (b: number) => b >= 0x20 && b < 0x7f;

function findAll(bytes: Uint8Array, needle: number[]): Set<number> {
  const out = new Set<number>();
  if (!needle.length) return out;
  outer: for (let i = 0; i + needle.length <= bytes.length; i++) {
    for (let j = 0; j < needle.length; j++) if (bytes[i + j] !== needle[j]) continue outer;
    for (let j = 0; j < needle.length; j++) out.add(i + j);
  }
  return out;
}

export default function HexView({ bytes, hl, onByte }: Props) {
  const [decOff, setDecOff] = useState(false);
  const [q, setQ] = useState("");
  const [mode, setMode] = useState<"hex" | "text">("text");
  const ref = useRef<HTMLDivElement>(null);

  const matches = useMemo(() => {
    if (!q) return new Set<number>();
    if (mode === "text") return findAll(bytes, [...new TextEncoder().encode(q)]);
    const h = q.replace(/[^0-9a-f]/gi, "");
    if (h.length % 2) return new Set<number>();
    return findAll(bytes, h.match(/../g)!.map((x) => parseInt(x, 16)));
  }, [q, mode, bytes]);

  useEffect(() => {
    if (hl) ref.current?.querySelector(`[data-line="${Math.floor(hl[0] / 16)}"]`)?.scrollIntoView({ block: "nearest" });
  }, [hl]);

  const on = (i: number) => hl !== null && i >= hl[0] && i < hl[0] + hl[1];
  const lines = [];
  for (let off = 0; off < bytes.length; off += 16) {
    const hexes = [], ascs = [];
    for (let i = off; i < off + 16; i++) {
      if (i >= bytes.length) { hexes.push(<span key={i} className="b" />); continue; }
      const b = bytes[i];
      const cls = (on(i) ? " on" : "") + (matches.has(i) ? " match" : "");
      hexes.push(<span key={i} className={"b" + cls} onMouseDown={() => onByte(i)}>{b.toString(16).padStart(2, "0")}</span>);
      ascs.push(<span key={i} className={"a" + cls + (printable(b) ? "" : " np")} onMouseDown={() => onByte(i)}>{printable(b) ? String.fromCharCode(b) : "·"}</span>);
    }
    lines.push(
      <div key={off} className="hl" data-line={off / 16}>
        <span className="off">{decOff ? String(off).padStart(5, "0") : off.toString(16).padStart(4, "0")}</span>
        <span className="bytes">{hexes}</span>
        <span className="asc">{ascs}</span>
      </div>,
    );
  }

  const sel = hl ? bytes.slice(hl[0], hl[0] + hl[1]) : bytes;
  const asHex = () => [...sel].map((b) => b.toString(16).padStart(2, "0")).join(" ");
  const asText = () => [...sel].map((b) => (printable(b) ? String.fromCharCode(b) : ".")).join("");

  return (
    <>
      <div className="pane-title">
        <span>Bytes · {bytes.length}{hl ? ` · selection ${hl[1]} @ ${decOff ? hl[0] : "0x" + hl[0].toString(16)}` : ""}</span>
        <span className="sp" />
        <select className="small" value={mode} onChange={(e) => setMode(e.target.value as "hex" | "text")} aria-label="Search mode" style={{ padding: "0 .3rem", fontSize: ".75rem" }}>
          <option value="text">text</option><option value="hex">hex</option>
        </select>
        <input placeholder="find in bytes" value={q} onChange={(e) => setQ(e.target.value)} style={{ padding: "0 .4rem", fontSize: ".75rem", width: 140 }} aria-label="Find in bytes" />
        {q && <span>{matches.size ? `${matches.size} bytes matched` : "no match"}</span>}
        <button className="small ghost" onClick={() => setDecOff(!decOff)}>{decOff ? "dec" : "hex"} offsets</button>
        <button className="small ghost" onClick={() => copyText(asHex())}>Copy hex</button>
        <button className="small ghost" onClick={() => copyText(asText())}>Copy text</button>
      </div>
      <div className="hex" ref={ref} tabIndex={0} aria-label="Packet bytes">{lines}</div>
    </>
  );
}

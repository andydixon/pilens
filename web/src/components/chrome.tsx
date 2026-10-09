// Shared chrome for the analysis pages: a session picker header, and a tiny
// decode-vs-encrypted banner used so the UI is honest about what is being shown.
import { fmtBytes, type Session } from "../api";
import { Badge, go } from "../ui";

export function SessionPicker({ sessions, id, base, children }: { sessions?: Session[]; id: string; base: string; children?: React.ReactNode }) {
  return (
    <div className="row" style={{ gap: ".5rem" }}>
      <select value={id} onChange={(e) => go(`${base}/${e.target.value}`)} aria-label="Capture session" style={{ maxWidth: 320 }}>
        {!id && <option value="">No capture sessions</option>}
        {sessions?.map((s) => <option key={s.id} value={s.id}>{s.state === "running" ? "● " : ""}{s.name} ({s.packets.toLocaleString()} pkts)</option>)}
      </select>
      {children}
    </div>
  );
}

export function PacketsLink({ id, filter, children }: { id: string; filter: string; children: React.ReactNode }) {
  return <a href="#" onClick={(e) => { e.preventDefault(); go(`/analyse/${id}?filter=${encodeURIComponent(filter)}`); }} title={filter}>{children}</a>;
}

export function Bar({ value, max, label, kind }: { value: number; max: number; label?: string; kind?: string }) {
  const pct = max > 0 ? Math.max(1.5, (value / max) * 100) : 0;
  return (
    <div style={{ position: "relative", background: "var(--panel-2)", borderRadius: 4, height: 18, overflow: "hidden", minWidth: 80 }}>
      <div style={{ width: pct + "%", height: "100%", background: kind || "var(--cyan)", opacity: .35 }} />
      <span style={{ position: "absolute", inset: 0, padding: "0 .4rem", fontSize: ".78rem", display: "flex", alignItems: "center" }} className="mono">{label ?? fmtBytes(value)}</span>
    </div>
  );
}

export function EncryptedNote() {
  return <div className="banner info" style={{ marginBottom: "1rem" }}><div>
    <b>Encrypted traffic is shown as metadata only.</b>
    In capture-only mode PiLens does not decrypt TLS/QUIC. You see endpoints, SNI, versions, ciphers, ALPN and certificates where they are sent in the clear — not application content. <Badge kind="plain">interception: encrypted pass-through</Badge>
  </div></div>;
}

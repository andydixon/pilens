// Small shared UI pieces and hooks.
import { useCallback, useEffect, useRef, useState, type ReactNode } from "react";
import { api } from "./api";

export function useHash(): [string, URLSearchParams] {
  const read = () => {
    const h = location.hash.replace(/^#/, "") || "/";
    const [p, q] = h.split("?");
    return [p, new URLSearchParams(q ?? "")] as [string, URLSearchParams];
  };
  const [v, setV] = useState(read);
  useEffect(() => {
    const f = () => setV(read());
    addEventListener("hashchange", f);
    return () => removeEventListener("hashchange", f);
  }, []);
  return v;
}

export const go = (path: string) => { location.hash = path; };

/** Polls an API path; returns [data, error, reload]. */
export function usePoll<T>(path: string | null, ms = 0): [T | undefined, string, () => void] {
  const [data, setData] = useState<T>();
  const [err, setErr] = useState("");
  const [tick, setTick] = useState(0);
  const reload = useCallback(() => setTick((t) => t + 1), []);
  useEffect(() => {
    if (!path) return;
    let alive = true;
    const ctl = new AbortController();
    const run = () => api<T>(path, { signal: ctl.signal }).then((d) => { if (alive) { setData(d); setErr(""); } }, (e) => { if (alive && e.name !== "AbortError") setErr(e.message); });
    run();
    const t = ms ? setInterval(run, ms) : undefined;
    return () => { alive = false; ctl.abort(); if (t) clearInterval(t); };
  }, [path, ms, tick]);
  return [data, err, reload];
}

export function usePersist<T>(key: string, init: T): [T, (v: T | ((p: T) => T)) => void] {
  const [v, setV] = useState<T>(() => {
    try { const s = localStorage.getItem("pilens." + key); return s ? JSON.parse(s) : init; } catch { return init; }
  });
  const set = useCallback((x: T | ((p: T) => T)) => {
    setV((p) => {
      const n = typeof x === "function" ? (x as (p: T) => T)(p) : x;
      try { localStorage.setItem("pilens." + key, JSON.stringify(n)); } catch { /* storage unavailable */ }
      return n;
    });
  }, [key]);
  return [v, set];
}

let toastSet: ((t: { msg: string; bad?: boolean } | null) => void) | null = null;
export function toast(msg: string, bad = false) { toastSet?.({ msg, bad }); }
export function Toaster() {
  const [t, setT] = useState<{ msg: string; bad?: boolean } | null>(null);
  useEffect(() => { toastSet = setT; return () => { toastSet = null; }; }, []);
  useEffect(() => { if (t) { const x = setTimeout(() => setT(null), t.bad ? 8000 : 3500); return () => clearTimeout(x); } }, [t]);
  return t ? <div className={"toast" + (t.bad ? " bad" : "")} role="status" onClick={() => setT(null)}>{t.msg}</div> : null;
}

export function Modal({ open, title, children, footer, onClose }: { open: boolean; title: ReactNode; children: ReactNode; footer?: ReactNode; onClose: () => void }) {
  const ref = useRef<HTMLDialogElement>(null);
  useEffect(() => {
    const d = ref.current!;
    if (open && !d.open) d.showModal();
    if (!open && d.open) d.close();
  }, [open]);
  return (
    <dialog ref={ref} onClose={onClose} onCancel={onClose}>
      <div className="dh"><h2>{title}</h2></div>
      <div className="db">{children}</div>
      {footer && <div className="df">{footer}</div>}
    </dialog>
  );
}

export function Badge({ kind, children }: { kind?: "ok" | "warn" | "bad" | "live" | "plain"; children: ReactNode }) {
  return <span className={"badge " + (kind ?? "")}>{children}</span>;
}

export function Steps({ steps, error }: { steps?: string[]; error?: string }) {
  if (!steps?.length && !error) return null;
  return (
    <div className="steps" aria-live="polite">
      {steps?.map((s, i) => <div key={i} className={/FAILED|failed/.test(s) ? "fail" : ""}>{s.startsWith("FAILED") ? "✗ " : "✓ "}{s}</div>)}
      {error && <div className="fail">✗ {error}</div>}
    </div>
  );
}

export interface CtxItem { label: string; onClick?: () => void; sep?: boolean }
export function ContextMenu({ at, items, onClose }: { at: { x: number; y: number } | null; items: CtxItem[]; onClose: () => void }) {
  useEffect(() => {
    if (!at) return;
    const f = () => onClose();
    const k = (e: KeyboardEvent) => e.key === "Escape" && onClose();
    setTimeout(() => addEventListener("click", f), 0);
    addEventListener("keydown", k);
    return () => { removeEventListener("click", f); removeEventListener("keydown", k); };
  }, [at, onClose]);
  if (!at) return null;
  return (
    <div className="ctx" role="menu" style={{ left: Math.min(at.x, innerWidth - 240), top: Math.min(at.y, innerHeight - items.length * 32 - 10) }}>
      {items.map((it, i) => it.sep ? <hr key={i} /> : <button key={i} role="menuitem" onClick={() => { it.onClick?.(); onClose(); }}>{it.label}</button>)}
    </div>
  );
}

export async function copyText(s: string) {
  try { await navigator.clipboard.writeText(s); toast("Copied to clipboard"); } catch { toast("Clipboard unavailable (requires HTTPS and permission)", true); }
}

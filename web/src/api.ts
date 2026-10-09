// Thin API client. All state-changing requests carry the per-session CSRF token.

let csrf = "";
export const setCSRF = (t: string) => { csrf = t; };

export class ApiError extends Error {
  constructor(public status: number, message: string, public body?: any) { super(message); }
}

export async function api<T = any>(path: string, opts: { method?: string; body?: any; raw?: BodyInit; signal?: AbortSignal } = {}): Promise<T> {
  const headers: Record<string, string> = { "X-Requested-With": "pilens" };
  const method = opts.method ?? (opts.body !== undefined || opts.raw ? "POST" : "GET");
  if (method !== "GET") headers["X-CSRF-Token"] = csrf;
  let body: BodyInit | undefined = opts.raw;
  if (opts.body !== undefined) { headers["Content-Type"] = "application/json"; body = JSON.stringify(opts.body); }
  const r = await fetch(path, { method, headers, body, credentials: "same-origin", signal: opts.signal });
  const text = await r.text();
  let data: any = undefined;
  try { data = text ? JSON.parse(text) : undefined; } catch { data = text; }
  if (!r.ok) {
    if (r.status === 401 && path !== "/api/auth/login") window.dispatchEvent(new Event("pilens:unauthorised"));
    throw new ApiError(r.status, (data && data.error) || r.statusText, data);
  }
  return data as T;
}

// ---- types mirroring the Go API ----

export interface Row { n: number; t: number; s: string; d: string; p: string; l: number; i: string; sp?: number; dp?: number; st?: number; tf?: string; ttl?: number; vl?: number; c?: string }
export interface Page { total: number; first: number; offset: number; rows: Row[]; nums?: number[]; filtered: boolean }
export interface TreeNode { label: string; field?: string; show?: string; pos: number; size: number; verified: boolean; children?: TreeNode[] }
export interface Detail { row: Row; bytes: string; tree: TreeNode[] | null; segment: number; note?: string }
export interface Session {
  id: string; name: string; description: string; kind: "live" | "import"; state: string; interfaces: string[]; capture_filter: string;
  started_at: number; ended_at: number; packets: number; bytes: number; drops: string; error: string; preserved: boolean;
  tags: string; notes: string; ring_segments: number; meta: any; paused: boolean; ingest_lag: number;
}
export interface Segment { seq: number; file: string; format: string; base: number; count: number; bytes: number; sha256: string; complete: boolean; deleted: boolean }
export interface Iface { name: string; mac: string; addrs: string[] | null; up: boolean; carrier: boolean; wireless: boolean; driver: string; default_gateway?: string; virtual: boolean; speed_mbps?: number }
export interface Network {
  management: { interfaces: string[]; allowed_subnets: string[]; port: number };
  uplink: string;
  ap: { enabled: boolean; interface: string; ssid: string; passphrase?: string; security: string; band: string; channel: number; hidden: boolean; country: string; client_isolation: boolean };
  lan: { address: string; dhcp_start: string; dhcp_end: string; lease_minutes: number; upstream_dns: string[] | null; reservations: { mac: string; ip: string; hostname?: string }[] | null; dns_overrides: { name: string; ip: string }[] | null };
  forwarding: { mode: string; allow_cidrs: string[] | null };
}
export interface ApplyResult { applied: boolean; rolled_back: boolean; steps: string[]; error?: string }
export interface Limits { max_bytes: number; reserve_bytes: number; segment_bytes: number; import_bytes: number }

// ---- live events (SSE) ----

type Handler = (type: string, data: any) => void;
const handlers = new Set<Handler>();
let es: EventSource | null = null;

export function connectEvents() {
  if (es) return;
  es = new EventSource("/api/events");
  for (const t of ["hello", "packets", "capture", "resync", "ping"]) {
    es.addEventListener(t, (e) => {
      let d: any = {};
      try { d = JSON.parse((e as MessageEvent).data); } catch { /* ignore */ }
      handlers.forEach((h) => h(t, d));
    });
  }
  es.onerror = () => handlers.forEach((h) => h("disconnected", {})); // EventSource reconnects by itself
}

export function disconnectEvents() { es?.close(); es = null; }

export function onEvent(h: Handler) { handlers.add(h); return () => { handlers.delete(h); }; }

// ---- formatting ----

export const fmtBytes = (n: number) => {
  if (!isFinite(n)) return "–";
  const u = ["B", "KiB", "MiB", "GiB", "TiB"]; let i = 0;
  while (Math.abs(n) >= 1024 && i < u.length - 1) { n /= 1024; i++; }
  return `${n.toFixed(i ? 1 : 0)} ${u[i]}`;
};
export const fmtTime = (ms: number) => ms ? new Date(ms).toLocaleString() : "–";
export const fmtDur = (s: number) => {
  if (!isFinite(s) || s < 0) return "–";
  const h = Math.floor(s / 3600), m = Math.floor((s % 3600) / 60), x = Math.floor(s % 60);
  return h ? `${h}h ${m}m` : m ? `${m}m ${x}s` : `${x}s`;
};

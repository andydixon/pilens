import { useCallback, useEffect, useState } from "react";
import { api, setCSRF, connectEvents, disconnectEvents } from "./api";
import { useHash, usePersist, Toaster, go } from "./ui";
import Login from "./pages/Login";
import Setup from "./pages/Setup";
import Overview from "./pages/Overview";
import Analyser from "./pages/Analyser";
import Library from "./pages/Library";
import NetworkPage from "./pages/Network";
import Devices from "./pages/Devices";
import Health from "./pages/Health";
import Conversations from "./pages/Conversations";
import DnsExplorer from "./pages/DnsExplorer";
import TlsExplorer from "./pages/TlsExplorer";
import Statistics from "./pages/Statistics";
import Settings from "./pages/Settings";

export interface Prefs { theme: "dark" | "light" | "system"; density: "compact" | "comfortable"; scale: number; motion: "system" | "reduce" }
export const defaultPrefs: Prefs = { theme: "dark", density: "compact", scale: 1, motion: "system" };

interface Sess { user: string; csrf: string; totp_enabled: boolean; setup_complete: boolean; version: string }

// Only implemented features appear here. Later-phase pages are added when they work.
const NAV: [string, string, string][] = [
  ["/", "Overview", "◉"],
  ["/analyse", "Live Capture", "≋"],
  ["/conversations", "Conversations", "⇌"],
  ["/dns", "DNS Explorer", "◇"],
  ["/tls", "TLS Explorer", "⛨"],
  ["/statistics", "Statistics", "▦"],
  ["/library", "Capture Library", "▤"],
  ["/devices", "Devices", "⌬"],
  ["", "", ""],
  ["/network", "Network Settings", "⇄"],
  ["/health", "System Health", "♥"],
  ["/settings", "Settings", "⚙"],
];

export default function App() {
  const [prefs, setPrefs] = usePersist<Prefs>("prefs", defaultPrefs);
  const [sess, setSess] = useState<Sess | null>(null);
  const [status, setStatus] = useState<{ needs_admin: boolean; setup_complete: boolean; version: string } | null>(null);
  const [loading, setLoading] = useState(true);
  const [focus, setFocus] = usePersist("focus", false);
  const [path, query] = useHash();

  useEffect(() => {
    const r = document.documentElement;
    const theme = prefs.theme === "system" ? (matchMedia("(prefers-color-scheme: light)").matches ? "light" : "dark") : prefs.theme;
    r.dataset.theme = theme;
    r.dataset.density = prefs.density;
    r.dataset.motion = prefs.motion;
    r.style.setProperty("--scale", String(prefs.scale));
  }, [prefs]);

  const refresh = useCallback(async () => {
    try {
      const st = await api("/api/setup/status");
      setStatus(st);
      try {
        const s = await api<Sess>("/api/auth/session");
        setCSRF(s.csrf);
        setSess(s);
      } catch { setSess(null); }
    } catch { setStatus(null); }
    setLoading(false);
  }, []);

  useEffect(() => { refresh(); }, [refresh]);
  useEffect(() => {
    const f = () => { setSess(null); disconnectEvents(); };
    addEventListener("pilens:unauthorised", f);
    return () => removeEventListener("pilens:unauthorised", f);
  }, []);
  useEffect(() => { if (sess) connectEvents(); }, [sess]);

  useEffect(() => {
    const k = (e: KeyboardEvent) => {
      const t = e.target as HTMLElement;
      if (/INPUT|TEXTAREA|SELECT/.test(t.tagName)) return;
      if (e.key === "F" && e.shiftKey) { setFocus((f) => !f); e.preventDefault(); }
      if (e.altKey && /^[1-7]$/.test(e.key)) { const n = NAV.filter((x) => x[0])[+e.key - 1]; if (n) { go(n[0]); e.preventDefault(); } }
    };
    addEventListener("keydown", k);
    return () => removeEventListener("keydown", k);
  }, [setFocus]);

  if (loading) return <div className="center"><span className="hint">Connecting to appliance…</span></div>;
  if (!status) return <div className="center"><div className="card authcard"><h2>Appliance unreachable</h2><p className="hint">The PiLens service did not respond. Check that pilens.service is running (<code>sudo ./diagnose.sh</code>).</p><button onClick={refresh}>Retry</button></div></div>;
  if (status.needs_admin || (sess && !sess.setup_complete)) return <><Setup status={status} session={sess} onDone={refresh} /><Toaster /></>;
  if (!sess) return <><Login onLogin={refresh} /><Toaster /></>;

  const page = (() => {
    if (path === "/" ) return <Overview />;
    if (path.startsWith("/analyse")) return <Analyser sessionId={path.split("/")[2] ?? ""} initialFilter={query.get("filter") ?? ""} focus={focus} setFocus={setFocus} />;
    if (path.startsWith("/conversations")) return <Conversations sessionId={path.split("/")[2] ?? ""} />;
    if (path.startsWith("/dns")) return <DnsExplorer sessionId={path.split("/")[2] ?? ""} />;
    if (path.startsWith("/tls")) return <TlsExplorer sessionId={path.split("/")[2] ?? ""} />;
    if (path.startsWith("/statistics")) return <Statistics sessionId={path.split("/")[2] ?? ""} />;
    if (path === "/library") return <Library />;
    if (path === "/devices") return <Devices />;
    if (path === "/network") return <NetworkPage />;
    if (path === "/health") return <Health />;
    if (path === "/settings") return <Settings prefs={prefs} setPrefs={setPrefs} session={sess} onChange={refresh} />;
    return <div className="page"><h1>Not found</h1></div>;
  })();

  return (
    <div className={"shell" + (focus && path.startsWith("/analyse") ? " focus" : "")}>
      <aside className="nav">
        <div className="brand"><img src="/favicon.svg" alt="" /><div><b>PiLens</b><span>network forensics</span></div></div>
        <nav aria-label="Main">
          {NAV.map(([href, label, icon], i) => href === "" ? <div className="sep" key={i} /> :
            <a key={href} href={"#" + href} className={(href === "/" ? path === "/" : path.startsWith(href)) ? "active" : ""}><span aria-hidden style={{ width: "1.1rem", textAlign: "center", opacity: .8 }}>{icon}</span>{label}</a>)}
        </nav>
        <div className="foot">
          <span>Signed in as <b>{sess.user}</b></span>
          <span className="row spread"><span>v{sess.version}</span><button className="small ghost" onClick={async () => { await api("/api/auth/logout", { method: "POST" }).catch(() => {}); setSess(null); disconnectEvents(); }}>Sign out</button></span>
        </div>
      </aside>
      <main className="main">{page}</main>
      <Toaster />
    </div>
  );
}

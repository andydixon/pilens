import { useState } from "react";
import { api, ApiError } from "../api";

export default function Login({ onLogin }: { onLogin: () => void }) {
  const [u, setU] = useState("");
  const [p, setP] = useState("");
  const [code, setCode] = useState("");
  const [needTotp, setNeedTotp] = useState(false);
  const [err, setErr] = useState("");
  const [busy, setBusy] = useState(false);

  const submit = async (e: React.FormEvent) => {
    e.preventDefault();
    setBusy(true); setErr("");
    try {
      await api("/api/auth/login", { body: { username: u, password: p, totp: code } });
      onLogin();
    } catch (x) {
      if (x instanceof ApiError && x.message === "totp_required") { setNeedTotp(true); setErr(""); }
      else setErr((x as Error).message);
    }
    setBusy(false);
  };

  return (
    <div className="center">
      <form className="card authcard stack" onSubmit={submit}>
        <div className="row"><img src="/favicon.svg" width={34} alt="" /><div><h1>PiLens</h1><span className="hint">Appliance sign-in</span></div></div>
        <label>Username<input autoFocus autoComplete="username" value={u} onChange={(e) => setU(e.target.value)} /></label>
        <label>Password<input type="password" autoComplete="current-password" value={p} onChange={(e) => setP(e.target.value)} /></label>
        {needTotp && <label>Authenticator code<input className="mono" inputMode="numeric" autoComplete="one-time-code" autoFocus maxLength={6} value={code} onChange={(e) => setCode(e.target.value.replace(/\D/g, ""))} /></label>}
        {err && <div className="err" role="alert">{err}</div>}
        <button className="primary" disabled={busy || !u || !p}>{busy ? "Signing in…" : "Sign in"}</button>
        <p className="hint">Captured traffic may contain sensitive personal data. Access is logged.</p>
      </form>
    </div>
  );
}

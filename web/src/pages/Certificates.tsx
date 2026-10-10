import { useState } from "react";
import { api, type ApplyResult, type InterceptionStatus } from "../api";
import { Badge, Modal, Steps, toast, usePoll } from "../ui";

const INSTALL: Record<string, string[]> = {
  "iOS / iPadOS": [
    "Download the CA to the device (or AirDrop it).",
    "Settings opens a profile prompt → Install → enter your passcode.",
    "Then Settings → General → About → Certificate Trust Settings → turn ON full trust for ‘PiLens Interception CA’.",
    "Without that second step iOS will NOT trust it. This is deliberate on Apple's part.",
  ],
  "Android": [
    "Settings → Security → Encryption & credentials → Install a certificate → CA certificate.",
    "Pick the downloaded .crt.",
    "Note: Android apps only trust user-added CAs if they opt in. Many apps (and all of Chrome's pinned sites) will not be decryptable. That is expected.",
  ],
  "Windows": [
    "Double-click the .crt → Install Certificate → Local Machine → ‘Trusted Root Certification Authorities’.",
    "Browsers using the system store (Edge, Chrome) will then trust it; Firefox uses its own store (below).",
  ],
  "macOS": [
    "Double-click the .crt → add to the ‘login’ or ‘System’ keychain.",
    "Open Keychain Access → find ‘PiLens Interception CA’ → Get Info → Trust → ‘Always Trust’.",
  ],
  "Firefox": [
    "Settings → Privacy & Security → Certificates → View Certificates → Authorities → Import.",
    "Tick ‘Trust this CA to identify websites’.",
  ],
};

export default function Certificates() {
  const [st, err, reload] = usePoll<InterceptionStatus>("/api/interception", 8000);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ApplyResult | null>(null);
  const [applyErr, setApplyErr] = useState("");
  const [os, setOs] = useState("iOS / iPadOS");
  const [confirmBodies, setConfirmBodies] = useState(false);
  const [draft, setDraft] = useState<InterceptionStatus["config"] | null>(null);

  const cfg = draft ?? st?.config;
  const dirty = draft !== null && JSON.stringify(draft) !== JSON.stringify(st?.config);

  const set = (p: Partial<InterceptionStatus["config"]>) => setDraft({ ...(cfg as any), ...p });

  const apply = async (override?: Partial<InterceptionStatus["config"]>) => {
    const body = { ...(cfg as any), ...override };
    setBusy(true); setApplyErr(""); setResult(null);
    try {
      const r = await api<{ result: ApplyResult }>("/api/interception", { method: "PUT", body });
      setResult(r.result); setDraft(null); reload();
      toast(body.enabled ? "Interception enabled" : "Interception disabled");
    } catch (e: any) {
      setApplyErr(e.message); setResult(e.body?.result ?? null); reload();
    }
    setBusy(false);
  };

  const ca = st?.ca;

  return (
    <div className="page">
      <div className="page-head">
        <div><h1>Certificates &amp; HTTPS Inspection</h1>
          <p>Authorised HTTPS interception (Mode B). Decrypts only for devices whose owner has installed and trusted the CA below.</p></div>
      </div>

      <div className="banner warn" style={{ marginBottom: "1rem" }}><div>
        <b>Consent is required, by design.</b> PiLens can only decrypt a device after <em>you</em> install this CA on it and turn on trust.
        A trusted certificate can never be pushed over the network or via DHCP. Pinned apps, private trust stores and QUIC are reported as
        not intercepted — never silently bypassed. The CA private key never leaves the appliance and is not downloadable.
      </div></div>

      {err && <div className="banner bad"><div>{err}</div></div>}

      <div className="grid g2">
        <div className="card stack">
          <h3>Interception</h3>
          <label className="inline" style={{ fontSize: "1rem" }}>
            <input type="checkbox" checked={!!cfg?.enabled} disabled={busy || !ca?.present}
              onChange={(e) => apply({ enabled: e.target.checked })} />
            <b>{cfg?.enabled ? "Enabled" : "Disabled"}</b> — redirect AP clients' HTTP/HTTPS through the proxy
          </label>
          {st && <div className="row">
            <Badge kind={st.running ? "ok" : "plain"}>{st.running ? "proxy active" : "proxy stopped"}</Badge>
            <span className="hint">transparent, port {st.port}</span>
          </div>}
          {!ca?.present && <div className="banner bad"><div>The interception CA is not available. Is the mitmproxy venv installed? Run <code>sudo /opt/pilens/repair.sh</code>.</div></div>}
          {applyErr && <div className="err">{applyErr}</div>}
          {result && <Steps steps={result.steps} />}
          <p className="hint">Enabling adds an nftables redirect for ports 80/443 from the Wi-Fi only. The proxy never becomes a direct open proxy for clients (it accepts only redirected connections).</p>
        </div>

        <div className="card stack">
          <h3>The appliance CA</h3>
          {ca?.present ? <>
            <dl className="kv">
              <dt>Subject</dt><dd className="mono">{ca.subject}</dd>
              <dt>Key</dt><dd>{ca.key_type}</dd>
              <dt>Fingerprint</dt><dd className="mono" style={{ fontSize: ".75rem", wordBreak: "break-all" }}>SHA-256 {ca.sha256}</dd>
              <dt>Valid</dt><dd>{ca.not_before} → {ca.not_after} <span className="hint">({ca.days_left} days left)</span></dd>
            </dl>
            <div className="row">
              <a className="btn primary" href="/api/interception/ca.crt" download>Download CA certificate</a>
              <button disabled={cfg?.enabled || busy} title={cfg?.enabled ? "Disable interception first" : ""}
                onClick={async () => { if (confirm("Rotate the CA? Every device must install the new one; current interception breaks until they do.")) { await api("/api/interception/ca/rotate", { method: "POST" }); reload(); toast("CA rotated"); } }}>Rotate CA</button>
            </div>
            <p className="hint">Install this on each authorised test device, then verify the fingerprint above matches before trusting it.</p>
          </> : <p className="hint">No CA yet.</p>}
        </div>
      </div>

      <div className="card stack" style={{ marginTop: ".9rem" }}>
        <h3>Install instructions</h3>
        <div className="row" role="tablist">
          {Object.keys(INSTALL).map((k) => <button key={k} className={os === k ? "on" : ""} onClick={() => setOs(k)}>{k}</button>)}
        </div>
        <ol style={{ margin: 0, paddingLeft: "1.2rem" }}>{INSTALL[os].map((s, i) => <li key={i} style={{ marginBottom: ".3rem" }}>{s}</li>)}</ol>
      </div>

      {cfg && <div className="card stack" style={{ marginTop: ".9rem" }}>
        <h3>Options</h3>
        <label>Excluded hosts (not decrypted — passed straight through)
          <textarea rows={3} className="mono" value={cfg.exclude_hosts.join("\n")} placeholder={"one host/regex per line\n(?i)\\.apple\\.com$\nexample\\.com"}
            onChange={(e) => set({ exclude_hosts: e.target.value.split("\n").map((x) => x.trim()).filter(Boolean) })} />
          <span className="hint">Use for pinned apps or privacy-sensitive hosts. Matched hosts keep working but stay encrypted.</span>
        </label>
        <label className="inline">
          <input type="checkbox" checked={cfg.capture_bodies} onChange={(e) => { if (e.target.checked) setConfirmBodies(true); else set({ capture_bodies: false }); }} />
          Retain request/response bodies on disk
        </label>
        <div className="row">
          <label>Max body size (KiB)<input type="number" min={0} max={10240} value={cfg.max_body_kb} onChange={(e) => set({ max_body_kb: +e.target.value })} /></label>
        </div>
        {dirty && <div className="row"><button className="primary" disabled={busy} onClick={() => apply()}>Apply options</button>
          <button disabled={busy} onClick={() => setDraft(null)}>Discard</button></div>}
      </div>}

      <Modal open={confirmBodies} title="Retain decrypted bodies?" onClose={() => setConfirmBodies(false)}
        footer={<><button onClick={() => setConfirmBodies(false)}>Cancel</button>
          <button className="danger" onClick={() => { set({ capture_bodies: true }); setConfirmBodies(false); }}>I understand, retain bodies</button></>}>
        <p>Response and request bodies can contain passwords, tokens, messages and personal data in clear text. They will be written to the appliance's disk until you clear them.</p>
        <p className="hint">Off by default. Only enable for a specific investigation, and clear the data (HTTP Explorer → Clear) when done. Exports and body views are audited.</p>
      </Modal>
    </div>
  );
}

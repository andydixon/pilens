import { useEffect, useState } from "react";
import { api, setCSRF, type ApplyResult, type Iface, type Network, type Limits, fmtBytes } from "../api";
import { usePersist, Steps } from "../ui";
import { ForwardingFields, LanFields, ManagementFields, UplinkField, WifiFields } from "../components/NetForm";

const STEPS = ["Welcome", "Authorised use", "Administrator", "Management access", "Uplink", "Wi-Fi", "Client network", "Forwarding", "Inspection mode", "Storage", "Review & apply", "Finish"];

interface Props { status: { needs_admin: boolean }; session: { user: string } | null; onDone: () => void }

export default function Setup({ status, session, onDone }: Props) {
  // Progress survives reloads and power loss; the server decides what is actually done.
  const [step, setStep] = usePersist("wizard.step", 0);
  const [net, setNet] = usePersist<Network | null>("wizard.net", null);
  const [ack, setAck] = useState(false);
  const [admin, setAdmin] = useState({ token: "", username: "admin", password: "", confirm: "" });
  const [ifaces, setIfaces] = useState<Iface[]>([]);
  const [remote, setRemote] = useState("");
  const [bands, setBands] = useState<string[] | undefined>();
  const [errors, setErrors] = useState<string[]>([]);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<ApplyResult | null>(null);
  const [limits, setLimits] = useState<Limits | null>(null);
  const [expert, setExpert] = usePersist("wizard.expert", false);

  const authed = !!session;
  const cur = status.needs_admin ? Math.min(step, 2) : Math.max(step, 3);

  useEffect(() => {
    if (!authed) return;
    api("/api/system/interfaces").then((d) => {
      setIfaces(d.interfaces ?? []);
      setRemote(d.remote_addr);
      const wifi = (d.wifi ?? []).find((w: any) => w.ap_mode);
      setBands(wifi?.bands);
    });
    api("/api/storage").then((s) => setLimits(s.limits));
    if (!net) api("/api/network").then((d) => {
      const n: Network = d.config;
      const list: Iface[] = [];
      api("/api/system/interfaces").then((x) => {
        list.push(...(x.interfaces ?? []));
        const wl = list.find((i) => i.wireless);
        const up = list.find((i) => i.default_gateway && !i.wireless) ?? list.find((i) => !i.wireless && !i.virtual);
        setNet({ ...n, ap: { ...n.ap, interface: n.ap.interface || wl?.name || "" }, uplink: n.uplink || up?.name || "",
          lan: { ...n.lan, reservations: n.lan.reservations ?? [], dns_overrides: n.lan.dns_overrides ?? [] } });
      });
    });
  }, [authed]); // eslint-disable-line

  const set = (f: (n: Network) => Network) => setNet((n) => (n ? f(n) : n));

  const createAdmin = async () => {
    setBusy(true); setErrors([]);
    try {
      const r = await api("/api/setup/admin", { body: { token: admin.token, username: admin.username, password: admin.password, authorised: ack } });
      setCSRF(r.csrf);
      setStep(3);
      onDone();
    } catch (e) { setErrors([(e as Error).message]); }
    setBusy(false);
  };

  const validate = async () => {
    if (!net) return false;
    const r = await api("/api/network/validate", { body: net });
    setErrors(r.errors ?? []);
    return r.valid as boolean;
  };

  const apply = async () => {
    setBusy(true); setResult(null); setErrors([]);
    try {
      if (!(await validate())) { setBusy(false); return; }
      if (limits) await api("/api/storage", { method: "PUT", body: limits });
      const r = await api("/api/network/apply", { body: net });
      setResult(r.result);
      setStep(11);
    } catch (e: any) {
      setResult(e.body?.result ?? null);
      setErrors([e.message]);
    }
    setBusy(false);
  };

  const finish = async () => {
    await api("/api/setup/complete", { method: "POST" });
    for (const k of ["wizard.step", "wizard.net", "wizard.expert"]) localStorage.removeItem("pilens." + k);
    onDone();
  };

  const next = () => { setErrors([]); setStep(cur + 1); };
  const back = () => { setErrors([]); setStep(Math.max(status.needs_admin ? 0 : 3, cur - 1)); };

  const pwOk = admin.password.length >= 12 && admin.password === admin.confirm;
  const n = net;

  const body = () => {
    switch (cur) {
      case 0: return <>
        <h1>Welcome to PiLens</h1>
        <p>This appliance turns the Raspberry Pi into a separate, routed Wi-Fi network. Devices you connect to it are captured and analysed.</p>
        <div className="grid g2">
          <div className="card"><h3>What it does</h3><ul className="hint">
            <li>Runs a WPA2/WPA3 access point with its own DHCP and DNS</li>
            <li>Routes clients to the internet through Ethernet, with a default-deny firewall</li>
            <li>Captures complete packets (pcapng) with SHA-256 integrity hashes</li>
            <li>Dissects protocols with TShark, the Wireshark engine</li></ul></div>
          <div className="card"><h3>What it cannot do</h3><ul className="hint">
            <li>Read encrypted content (HTTPS, QUIC, VPNs, encrypted DNS). It sees packets and metadata only.</li>
            <li>TLS interception is not part of this version</li>
            <li>Forward IPv6 (it is blocked rather than left uninspected)</li></ul></div>
        </div>
        <label className="inline"><input type="checkbox" checked={expert} onChange={(e) => setExpert(e.target.checked)} />Expert mode (show all options, fewer explanations)</label>
      </>;
      case 1: return <>
        <h1>Authorised use</h1>
        <p>Network traffic routinely contains passwords, tokens, personal messages and health or financial data. Intercepting other people's communications without authority is unlawful in most jurisdictions.</p>
        <div className="banner warn"><div><b>Only connect devices you own or are explicitly authorised to inspect.</b>This appliance has no covert or impersonation features, and it must not be used to capture third-party traffic.</div></div>
        <label className="inline"><input type="checkbox" checked={ack} onChange={(e) => setAck(e.target.checked)} />I confirm this appliance will only be used on devices and networks I am authorised to inspect.</label>
      </>;
      case 2: return <>
        <h1>Create the administrator</h1>
        <p className="hint">The installer printed a one-time setup token. It is also stored in <code>/var/lib/pilens/setup-token</code> (readable only by root and the pilens service).</p>
        <label>Setup token<input className="mono" autoFocus value={admin.token} onChange={(e) => setAdmin({ ...admin, token: e.target.value.trim() })} /></label>
        <label>Username<input autoComplete="username" value={admin.username} onChange={(e) => setAdmin({ ...admin, username: e.target.value })} /></label>
        <div className="fieldgrid">
          <label>Password<input type="password" autoComplete="new-password" value={admin.password} onChange={(e) => setAdmin({ ...admin, password: e.target.value })} /><span className="hint">At least 12 characters. A passphrase is ideal.</span></label>
          <label>Confirm<input type="password" autoComplete="new-password" className={admin.confirm && admin.confirm !== admin.password ? "invalid" : ""} value={admin.confirm} onChange={(e) => setAdmin({ ...admin, confirm: e.target.value })} /></label>
        </div>
        {!ack && <p className="err">Go back and confirm authorised use first.</p>}
      </>;
      case 3: return n && <>
        <h1>Management access</h1>
        <p>Choose where the management UI can be reached from. It is never reachable from the Wi-Fi access point, and it should never be exposed to the internet.</p>
        <ManagementFields n={n} set={set} ifaces={ifaces} remote={remote} />
      </>;
      case 4: return n && <><h1>Upstream connection</h1><UplinkField n={n} set={set} ifaces={ifaces} />
        {n.uplink && ifaces.find((i) => i.name === n.uplink)?.wireless && <div className="banner warn"><div>Using Wi-Fi as the uplink is unusual. The access point needs a dedicated radio.</div></div>}</>;
      case 5: return n && <><h1>Wi-Fi access point</h1><WifiFields n={n} set={set} ifaces={ifaces} passSet={false} bands={bands} />
        {ifaces.some((i) => i.name === n.ap.interface && (i.addrs ?? []).some((a) => !a.includes(":") && remote && a.startsWith(remote.split(".").slice(0, 3).join(".")))) &&
          <div className="banner warn"><div><b>{n.ap.interface} is currently connected to your network.</b>Turning it into an access point disconnects that link. Make sure you reach this page through the management interface.</div></div>}</>;
      case 6: return n && <><h1>Client network</h1><p className="hint">AP clients get addresses from this subnet. It must not overlap the management or upstream networks.</p><LanFields n={n} set={set} /></>;
      case 7: return n && <><h1>Forwarding policy</h1><ForwardingFields n={n} set={set} /></>;
      case 8: return <>
        <h1>Inspection mode</h1>
        <div className="choice">
          <label><input type="radio" checked readOnly /><span>Capture only<small>Packets are captured unmodified. Encrypted payloads stay encrypted. You see addresses, ports, DNS where unencrypted, TLS handshake metadata and timing.</small></span></label>
          <label className="disabled"><input type="radio" disabled /><span>Authorised HTTP/HTTPS inspection<small>Not available in this version. It requires a client-installed CA and is planned for a later release.</small></span></label>
          <label className="disabled"><input type="radio" disabled /><span>Strict inspection policy<small>Not available in this version.</small></span></label>
        </div>
      </>;
      case 9: return limits && <>
        <h1>Storage and retention</h1>
        <div className="fieldgrid">
          <label>Capture storage quota (GiB)<input type="number" min={1} value={Math.round(limits.max_bytes / 2 ** 30)} onChange={(e) => setLimits({ ...limits, max_bytes: +e.target.value * 2 ** 30 })} /></label>
          <label>Always keep free (GiB)<input type="number" min={1} value={Math.round(limits.reserve_bytes / 2 ** 30)} onChange={(e) => setLimits({ ...limits, reserve_bytes: +e.target.value * 2 ** 30 })} /></label>
          <label>Segment file size (MiB)<input type="number" min={1} max={1024} value={Math.round(limits.segment_bytes / 2 ** 20)} onChange={(e) => setLimits({ ...limits, segment_bytes: +e.target.value * 2 ** 20 })} /></label>
        </div>
        <p className="hint">When the quota is reached, the oldest sessions that are <b>not</b> marked preserved are deleted. If none are left, capture stops with an error. Preserved captures are never overwritten.</p>
      </>;
      case 10: return n && <>
        <h1>Review and apply</h1>
        <dl className="kv">
          <dt>Management</dt><dd className="mono">{n.management.interfaces.join(", ")} from {n.management.allowed_subnets.join(", ")}</dd>
          <dt>Uplink</dt><dd className="mono">{n.uplink}</dd>
          <dt>Access point</dt><dd className="mono">{n.ap.interface} “{n.ap.ssid}” {n.ap.security.toUpperCase()} {n.ap.band === "a" ? "5 GHz" : "2.4 GHz"} ch {n.ap.channel || "auto"} {n.ap.country}</dd>
          <dt>Client network</dt><dd className="mono">{n.lan.address} pool {n.lan.dhcp_start}–{n.lan.dhcp_end}</dd>
          <dt>Forwarding</dt><dd>{n.forwarding.mode === "internet" ? "Internet access (private ranges blocked)" : "Disabled"}</dd>
          {limits && <><dt>Storage</dt><dd>{fmtBytes(limits.max_bytes)} quota, {fmtBytes(limits.reserve_bytes)} reserve</dd></>}
        </dl>
        <p className="hint">Applying writes the NetworkManager profile, DHCP/DNS service and firewall table, then checks that each is healthy. If any check fails, the previous state is restored automatically.</p>
        <Steps steps={result?.steps} />
      </>;
      case 11: return <>
        <h1>Ready</h1>
        <Steps steps={result?.steps} />
        <div className="banner ok"><div><b>The access point is up.</b>Connect an authorised test device to “{n?.ap.ssid}”, then open <b>Live Capture</b> and start a capture on <code>{n?.ap.interface}</code>.</div></div>
        <div className="banner info"><div><b>About HTTPS</b>In capture-only mode, HTTPS content stays encrypted. You will see TLS handshakes (SNI, versions, certificates where visible), not page contents. That is expected.</div></div>
      </>;
    }
  };

  const canNext = cur === 1 ? ack : cur === 2 ? pwOk && ack && admin.token.length > 0 : !!n || cur < 3;

  return (
    <div className="center">
      <div className="wizard">
        <aside aria-label="Setup steps">
          {STEPS.map((s, i) => <div key={s} className={i === cur ? "cur" : i < cur ? "done" : ""}><i>{i < cur ? "✓" : i + 1}</i>{s}</div>)}
        </aside>
        <section>
          {body()}
          {errors.length > 0 && <div className="banner bad" role="alert"><div>{errors.map((e, i) => <div key={i}>{e}</div>)}</div></div>}
          <div className="actions">
            <button onClick={back} disabled={cur === 0 || cur === 3 || cur === 11 || busy}>Back</button>
            {cur === 2 ? <button className="primary" disabled={!canNext || busy} onClick={createAdmin}>{busy ? "Creating…" : "Create administrator"}</button>
              : cur === 10 ? <button className="primary" disabled={busy} onClick={apply}>{busy ? "Applying… (up to a minute)" : "Apply configuration"}</button>
              : cur === 11 ? <button className="primary" onClick={finish}>Open dashboard</button>
              : <button className="primary" disabled={!canNext} onClick={async () => { if (cur >= 3 && cur <= 7 && cur === 7 && !(await validate())) return; next(); }}>Continue</button>}
          </div>
        </section>
      </div>
    </div>
  );
}

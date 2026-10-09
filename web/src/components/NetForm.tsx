// Network configuration fields shared by the setup wizard and Network Settings.
import type { Iface, Network } from "../api";

export type SetNet = (f: (n: Network) => Network) => void;
const list = (s: string) => s.split(/[\s,]+/).map((x) => x.trim()).filter(Boolean);

export function ifaceLabel(i: Iface) {
  const a = (i.addrs ?? []).filter((x) => !x.includes(":")).join(", ");
  return `${i.name}${i.wireless ? " (Wi-Fi)" : ""}${a ? " — " + a : ""}${i.carrier ? "" : " — no link"}`;
}

export function ManagementFields({ n, set, ifaces, remote }: { n: Network; set: SetNet; ifaces: Iface[]; remote?: string }) {
  const toggle = (name: string) => set((x) => {
    const has = x.management.interfaces.includes(name);
    return { ...x, management: { ...x.management, interfaces: has ? x.management.interfaces.filter((i) => i !== name) : [...x.management.interfaces, name] } };
  });
  return (
    <div className="stack">
      <div className="choice">
        {ifaces.filter((i) => !i.virtual || i.name.startsWith("eth") || i.name.includes(".")).map((i) => (
          <label key={i.name}>
            <input type="checkbox" checked={n.management.interfaces.includes(i.name)} onChange={() => toggle(i.name)} disabled={i.name === n.ap.interface} />
            <span><span className="mono">{ifaceLabel(i)}</span><small>{i.name === n.ap.interface ? "This is the access-point interface; it can never carry management." : i.default_gateway ? "Has the default route." : ""}</small></span>
          </label>
        ))}
      </div>
      <label>Allowed management source subnets
        <input className="mono" value={n.management.allowed_subnets.join(", ")} onChange={(e) => set((x) => ({ ...x, management: { ...x.management, allowed_subnets: list(e.target.value) } }))} placeholder="192.168.1.0/24" />
        <span className="hint">Only these source addresses can reach the web UI (port {n.management.port}). {remote && <>Your browser connects from <code>{remote}</code>; it must be inside one of them.</>} Being wired does not make a network trusted: keep this as narrow as you can.</span>
      </label>
    </div>
  );
}

export function UplinkField({ n, set, ifaces }: { n: Network; set: SetNet; ifaces: Iface[] }) {
  return (
    <label>Upstream (uplink) interface
      <select value={n.uplink} onChange={(e) => set((x) => ({ ...x, uplink: e.target.value }))}>
        <option value="">— choose —</option>
        {ifaces.filter((i) => i.name !== n.ap.interface).map((i) => <option key={i.name} value={i.name}>{ifaceLabel(i)}</option>)}
      </select>
      <span className="hint">AP client traffic is NATed out of this interface. Usually the Ethernet port with the default route.</span>
    </label>
  );
}

export function WifiFields({ n, set, ifaces, passSet, bands }: { n: Network; set: SetNet; ifaces: Iface[]; passSet: boolean; bands?: string[] }) {
  const ap = n.ap;
  const upd = (p: Partial<Network["ap"]>) => set((x) => ({ ...x, ap: { ...x.ap, ...p } }));
  const chans = ap.band === "a" ? [36, 40, 44, 48, 149, 153, 157, 161, 165] : [1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13];
  return (
    <div className="stack">
      <div className="fieldgrid">
        <label>Wi-Fi interface
          <select value={ap.interface} onChange={(e) => upd({ interface: e.target.value })}>
            <option value="">— choose —</option>
            {ifaces.filter((i) => i.wireless).map((i) => <option key={i.name} value={i.name}>{i.name}{i.driver ? ` (${i.driver})` : ""}</option>)}
          </select>
        </label>
        <label>SSID<input value={ap.ssid} maxLength={32} onChange={(e) => upd({ ssid: e.target.value })} /></label>
        <label>Security
          <select value={ap.security} onChange={(e) => upd({ security: e.target.value })}>
            <option value="wpa2">WPA2-Personal (widest compatibility)</option>
            <option value="wpa3">WPA3-Personal (SAE; depends on driver/firmware)</option>
          </select>
        </label>
        <label>Passphrase
          <input type="password" autoComplete="new-password" value={ap.passphrase ?? ""} placeholder={passSet ? "unchanged (stored)" : "8–63 characters"} onChange={(e) => upd({ passphrase: e.target.value })} />
        </label>
        <label>Country (regulatory domain)<input className="mono" maxLength={2} value={ap.country} onChange={(e) => upd({ country: e.target.value.toUpperCase() })} /></label>
        <label>Band
          <select value={ap.band} onChange={(e) => upd({ band: e.target.value, channel: 0 })}>
            <option value="bg">2.4 GHz</option>
            <option value="a" disabled={bands && !bands.includes("5GHz")}>5 GHz{bands && !bands.includes("5GHz") ? " (not supported by this radio)" : ""}</option>
          </select>
        </label>
        <label>Channel
          <select value={ap.channel} onChange={(e) => upd({ channel: +e.target.value })}>
            <option value={0}>Automatic</option>
            {chans.map((c) => <option key={c} value={c}>{c}</option>)}
          </select>
        </label>
      </div>
      <div className="row">
        <label className="inline"><input type="checkbox" checked={ap.enabled} onChange={(e) => upd({ enabled: e.target.checked })} />Access point enabled (starts automatically at boot)</label>
        <label className="inline"><input type="checkbox" checked={ap.hidden} onChange={(e) => upd({ hidden: e.target.checked })} />Hide SSID</label>
        <label className="inline"><input type="checkbox" checked={ap.client_isolation} onChange={(e) => upd({ client_isolation: e.target.checked })} />Client isolation</label>
      </div>
      <p className="hint">The maximum number of clients cannot be set through NetworkManager, so it is not offered. WPA3 is verified when applied: if the radio cannot start the AP, the previous configuration is restored.</p>
    </div>
  );
}

export function LanFields({ n, set }: { n: Network; set: SetNet }) {
  const l = n.lan;
  const upd = (p: Partial<Network["lan"]>) => set((x) => ({ ...x, lan: { ...x.lan, ...p } }));
  return (
    <div className="fieldgrid">
      <label>Gateway address / prefix<input className="mono" value={l.address} onChange={(e) => upd({ address: e.target.value })} /><span className="hint">The Pi's address on the AP network.</span></label>
      <label>DHCP pool start<input className="mono" value={l.dhcp_start} onChange={(e) => upd({ dhcp_start: e.target.value })} /></label>
      <label>DHCP pool end<input className="mono" value={l.dhcp_end} onChange={(e) => upd({ dhcp_end: e.target.value })} /></label>
      <label>Lease duration (minutes)<input type="number" min={2} value={l.lease_minutes} onChange={(e) => upd({ lease_minutes: +e.target.value })} /></label>
      <label>Upstream DNS servers<input className="mono" value={(l.upstream_dns ?? []).join(", ")} placeholder="system resolvers" onChange={(e) => upd({ upstream_dns: list(e.target.value) })} /><span className="hint">Empty: use the Pi's own resolvers.</span></label>
    </div>
  );
}

export function ForwardingFields({ n, set }: { n: Network; set: SetNet }) {
  const f = n.forwarding;
  return (
    <div className="stack">
      <div className="choice" role="radiogroup">
        <label><input type="radio" checked={f.mode === "internet"} onChange={() => set((x) => ({ ...x, forwarding: { ...x.forwarding, mode: "internet" } }))} />
          <span>Internet access<small>AP clients reach public destinations through the uplink. Private ranges (RFC 1918, link-local, CGNAT), multicast and the management network stay blocked.</small></span></label>
        <label><input type="radio" checked={f.mode === "deny"} onChange={() => set((x) => ({ ...x, forwarding: { ...x.forwarding, mode: "deny" } }))} />
          <span>No forwarding<small>Clients get an address and DNS from the Pi but nothing is routed. Useful for observing what a device tries to reach.</small></span></label>
      </div>
      <label>Explicitly allowed private destinations (CIDR)
        <input className="mono" value={(f.allow_cidrs ?? []).join(", ")} placeholder="none" onChange={(e) => set((x) => ({ ...x, forwarding: { ...x.forwarding, allow_cidrs: list(e.target.value) } }))} />
        <span className="hint">For example a lab server on the upstream LAN. Applies only in Internet access mode.</span>
      </label>
      <p className="hint">IPv6 forwarding is not implemented, so IPv6 is disabled on the AP and IPv6 from clients is dropped. This means it cannot become an uninspected path.</p>
    </div>
  );
}

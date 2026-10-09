// Package netgen renders NetworkManager, dnsmasq and nftables configuration from
// a validated config.Network. Pure functions: no I/O, fully unit-tested.
package netgen

import (
	"fmt"
	"net"
	"strings"

	"pilens.dev/pilens/internal/config"
)

const (
	ConnName  = "pilens-ap"
	ConnUUID  = "6f1c3a2e-9d4b-4e57-8a51-0c7e1b2d9f30" // stable so reloads replace, not duplicate
	TableName = "pilens"
)

// keyfileEscape escapes a GKeyFile string value (NM keyfile format).
func keyfileEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	if strings.HasPrefix(s, " ") {
		s = `\s` + s[1:]
	}
	return s
}

// NMKeyfile renders /etc/NetworkManager/system-connections/pilens-ap.nmconnection.
func NMKeyfile(n config.Network) string {
	a := n.AP
	var b strings.Builder
	w := func(f string, v ...any) { fmt.Fprintf(&b, f+"\n", v...) }
	w("# Managed by PiLens. Changes are overwritten; use the PiLens UI.")
	w("[connection]")
	w("id=%s", ConnName)
	w("uuid=%s", ConnUUID)
	w("type=wifi")
	w("interface-name=%s", a.Interface)
	w("autoconnect=%t", a.Enabled)
	w("autoconnect-priority=100")
	w("")
	w("[wifi]")
	w("mode=ap")
	w("ssid=%s", keyfileEscape(a.SSID))
	w("band=%s", a.Band)
	if a.Channel != 0 {
		w("channel=%d", a.Channel)
	}
	w("hidden=%t", a.Hidden)
	if a.ClientIsolation {
		w("ap-isolation=1")
	} else {
		w("ap-isolation=0")
	}
	w("")
	w("[wifi-security]")
	if a.Security == "wpa3" {
		w("key-mgmt=sae")
		w("pmf=3") // required for SAE
	} else {
		w("key-mgmt=wpa-psk")
		w("pmf=1") // disabled: broadest client compatibility for WPA2-only
	}
	w("proto=rsn")
	w("pairwise=ccmp")
	w("group=ccmp")
	w("psk=%s", keyfileEscape(a.Passphrase))
	w("")
	w("[ipv4]")
	w("method=manual")
	w("address1=%s", n.LAN.Address)
	w("never-default=true")
	w("")
	w("[ipv6]")
	w("method=disabled")
	return b.String()
}

// Paths used by the rendered dnsmasq config.
const (
	LeaseFile = "/var/lib/pilens-helper/dnsmasq.leases"
)

// DnsmasqConf renders the dedicated dnsmasq instance for the AP interface.
func DnsmasqConf(n config.Network) string {
	l := n.LAN
	sub := l.Subnet()
	mask := net.CIDRMask(sub.Bits(), 32)
	gw := l.Gateway().String()
	var b strings.Builder
	w := func(f string, v ...any) { fmt.Fprintf(&b, f+"\n", v...) }
	w("# Managed by PiLens. Changes are overwritten; use the PiLens UI.")
	w("interface=%s", n.AP.Interface)
	w("bind-dynamic")        // only the AP interface; survives the address appearing late
	w("except-interface=lo") // dnsmasq otherwise adds loopback implicitly
	w("no-hosts")
	w("domain-needed")
	w("bogus-priv")
	w("cache-size=1000")
	if len(l.UpstreamDNS) == 0 {
		w("resolv-file=/etc/resolv.conf")
	} else {
		w("no-resolv")
		for _, s := range l.UpstreamDNS {
			w("server=%s", s)
		}
	}
	w("dhcp-authoritative")
	w("dhcp-range=%s,%s,%s,%dm", l.DHCPStart, l.DHCPEnd, net.IP(mask).String(), l.LeaseMinutes)
	w("dhcp-option=option:router,%s", gw)
	w("dhcp-option=option:dns-server,%s", gw)
	w("dhcp-leasefile=%s", LeaseFile)
	for _, r := range l.Reservations {
		hw, _ := net.ParseMAC(r.MAC)
		if r.Hostname != "" {
			w("dhcp-host=%s,%s,%s", hw, r.IP, r.Hostname)
		} else {
			w("dhcp-host=%s,%s", hw, r.IP)
		}
	}
	for _, o := range l.DNSOverrides {
		w("host-record=%s,%s", strings.ToLower(o.Name), o.IP) // exact name only, unlike address=/x/
	}
	w("log-queries=extra")
	w("log-dhcp")
	w("log-facility=-")
	return b.String()
}

func q(s string) string { return `"` + s + `"` } // inputs are validated interface names

// Nftables renders the complete inet pilens table. The output begins by
// (re)creating and deleting the table so `nft -f` replaces it atomically while
// leaving every other table untouched.
func Nftables(n config.Network) string {
	ap, up := q(n.AP.Interface), q(n.Uplink)
	sub := n.LAN.Subnet().String()
	var mgmtIf []string
	for _, i := range n.Management.Interfaces {
		mgmtIf = append(mgmtIf, q(i))
	}
	var v4, v6 []string
	for _, s := range n.Management.AllowedSubnets {
		if strings.Contains(s, ":") {
			v6 = append(v6, s)
		} else {
			v4 = append(v4, s)
		}
	}
	blocked := append(append([]string{}, config.PrivateRanges...), v4...)
	blocked = append(blocked, "255.255.255.255/32")

	var b strings.Builder
	w := func(f string, v ...any) { fmt.Fprintf(&b, f+"\n", v...) }
	w("# Managed by PiLens. Only this table is ever created or deleted by PiLens.")
	w("table inet %s", TableName)
	w("delete table inet %s", TableName)
	w("table inet %s {", TableName)
	set := func(name, typ string, elems []string) {
		w("\tset %s {", name)
		w("\t\ttype %s; flags interval; auto-merge", typ)
		if len(elems) > 0 {
			w("\t\telements = { %s }", strings.Join(elems, ", "))
		}
		w("\t}")
	}
	set("mgmt_v4", "ipv4_addr", v4)
	set("mgmt_v6", "ipv6_addr", v6)
	set("blocked_v4", "ipv4_addr", blocked)
	set("allow_v4", "ipv4_addr", n.Forwarding.AllowCIDRs)

	// Input: decide everything from the AP side; restrict only the management port elsewhere.
	w("\tchain input {")
	w("\t\ttype filter hook input priority filter - 10; policy accept;")
	w("\t\tiifname \"lo\" accept")
	w("\t\tiifname %s jump ap_input", ap)
	w("\t\ttcp dport %d iifname { %s } ip saddr @mgmt_v4 accept", n.Management.Port, strings.Join(mgmtIf, ", "))
	w("\t\ttcp dport %d iifname { %s } ip6 saddr @mgmt_v6 accept", n.Management.Port, strings.Join(mgmtIf, ", "))
	w("\t\ttcp dport %d counter drop comment \"management not allowed from here\"", n.Management.Port)
	w("\t}")
	w("\tchain ap_input {")
	w("\t\tmeta nfproto ipv6 counter drop")
	w("\t\tct state established,related accept")
	w("\t\tct state invalid drop")
	w("\t\tudp dport 67 accept")
	w("\t\tip daddr %s udp dport 53 accept", n.LAN.Gateway())
	w("\t\tip daddr %s tcp dport 53 accept", n.LAN.Gateway())
	w("\t\ticmp type { echo-request, destination-unreachable, time-exceeded } accept")
	w("\t\tcounter drop comment \"AP clients cannot reach the appliance\"")
	w("\t}")

	w("\tchain forward {")
	w("\t\ttype filter hook forward priority filter - 10; policy accept;")
	w("\t\tiifname %s jump ap_forward", ap)
	w("\t\toifname %s jump ap_return", ap)
	w("\t}")
	w("\tchain ap_forward {")
	w("\t\tmeta nfproto ipv6 counter drop comment \"IPv6 forwarding not implemented: blocked\"")
	w("\t\tct state invalid counter drop")
	w("\t\tip saddr != %s counter drop comment \"spoofed source\"", sub)
	w("\t\toifname != %s counter drop comment \"only the uplink\"", up)
	if n.Forwarding.Mode != "internet" {
		w("\t\tcounter drop comment \"forwarding disabled\"")
	} else {
		w("\t\tip daddr @allow_v4 ct state { new, established, related } accept")
		w("\t\tip daddr @blocked_v4 counter drop comment \"private/management destinations\"")
		w("\t\tct state { new, established, related } accept")
	}
	w("\t\tcounter drop")
	w("\t}")
	w("\tchain ap_return {")
	w("\t\tiifname %s ct state established,related accept", up)
	w("\t\tcounter drop")
	w("\t}")

	w("\tchain postrouting {")
	w("\t\ttype nat hook postrouting priority srcnat; policy accept;")
	w("\t\tip saddr %s oifname %s masquerade", sub, up)
	w("\t}")
	w("}")
	return b.String()
}

// DenyAll renders the fail-closed table used before any configuration exists:
// AP-side traffic is dropped entirely, nothing else is touched.
func DenyAll(apIface string) string {
	ap := q(apIface)
	return fmt.Sprintf(`# Managed by PiLens: fail-closed placeholder.
table inet %[1]s
delete table inet %[1]s
table inet %[1]s {
	chain input {
		type filter hook input priority filter - 10; policy accept;
		iifname %[2]s counter drop
	}
	chain forward {
		type filter hook forward priority filter - 10; policy accept;
		iifname %[2]s counter drop
		oifname %[2]s counter drop
	}
}
`, TableName, ap)
}

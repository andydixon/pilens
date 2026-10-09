// Package config holds the appliance configuration and its validation.
// The same validation runs in the unprivileged core and again in the root helper.
package config

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"regexp"
	"strings"
)

// Network is everything the root helper needs to render AP, DHCP/DNS and firewall state.
type Network struct {
	Management Management `json:"management" yaml:"management"`
	Uplink     string     `json:"uplink" yaml:"uplink"` // interface name, e.g. eth0
	AP         AP         `json:"ap" yaml:"ap"`
	LAN        LAN        `json:"lan" yaml:"lan"`
	Forwarding Forwarding `json:"forwarding" yaml:"forwarding"`
}

type Management struct {
	Interfaces     []string `json:"interfaces" yaml:"interfaces"`
	AllowedSubnets []string `json:"allowed_subnets" yaml:"allowed_subnets"`
	Port           int      `json:"port" yaml:"port"`
}

type AP struct {
	Enabled         bool   `json:"enabled" yaml:"enabled"`
	Interface       string `json:"interface" yaml:"interface"`
	SSID            string `json:"ssid" yaml:"ssid"`
	Passphrase      string `json:"passphrase,omitempty" yaml:"passphrase"`
	Security        string `json:"security" yaml:"security"` // wpa2 | wpa3
	Band            string `json:"band" yaml:"band"`         // bg (2.4 GHz) | a (5 GHz)
	Channel         int    `json:"channel" yaml:"channel"`   // 0 = automatic
	Hidden          bool   `json:"hidden" yaml:"hidden"`
	Country         string `json:"country" yaml:"country"`
	ClientIsolation bool   `json:"client_isolation" yaml:"client_isolation"`
}

type LAN struct {
	Address      string        `json:"address" yaml:"address"` // gateway CIDR, e.g. 192.168.50.1/24
	DHCPStart    string        `json:"dhcp_start" yaml:"dhcp_start"`
	DHCPEnd      string        `json:"dhcp_end" yaml:"dhcp_end"`
	LeaseMinutes int           `json:"lease_minutes" yaml:"lease_minutes"`
	UpstreamDNS  []string      `json:"upstream_dns" yaml:"upstream_dns"` // empty = system resolvers
	Reservations []Reservation `json:"reservations" yaml:"reservations"`
	DNSOverrides []DNSOverride `json:"dns_overrides" yaml:"dns_overrides"`
}

type Reservation struct {
	MAC      string `json:"mac" yaml:"mac"`
	IP       string `json:"ip" yaml:"ip"`
	Hostname string `json:"hostname,omitempty" yaml:"hostname"`
}

type DNSOverride struct {
	Name string `json:"name" yaml:"name"`
	IP   string `json:"ip" yaml:"ip"`
}

type Forwarding struct {
	// Mode: "deny" forwards nothing; "internet" forwards to non-private destinations via the uplink.
	Mode string `json:"mode" yaml:"mode"`
	// AllowCIDRs are private destinations explicitly opened to AP clients.
	AllowCIDRs []string `json:"allow_cidrs" yaml:"allow_cidrs"`
}

func DefaultNetwork() Network {
	return Network{
		Management: Management{Port: 8443},
		AP: AP{Enabled: true, SSID: "PiLens-Lab", Security: "wpa2", Band: "bg", Channel: 0, Country: "GB"},
		LAN: LAN{Address: "192.168.50.1/24", DHCPStart: "192.168.50.100", DHCPEnd: "192.168.50.199", LeaseMinutes: 720},
		Forwarding: Forwarding{Mode: "internet"},
	}
}

var (
	ifaceRe    = regexp.MustCompile(`^[A-Za-z0-9_.-]{1,15}$`)
	countryRe  = regexp.MustCompile(`^[A-Z]{2}$`)
	hostnameRe = regexp.MustCompile(`^(?i)[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?(\.[a-z0-9]([a-z0-9-]{0,61}[a-z0-9])?)*$`)
)

// PrivateRanges are never reachable from AP clients unless explicitly allowed.
var PrivateRanges = []string{"10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16", "169.254.0.0/16", "100.64.0.0/10", "0.0.0.0/8", "224.0.0.0/4", "240.0.0.0/4"}

func ValidInterface(s string) bool { return ifaceRe.MatchString(s) && s != "." && s != ".." }

// ValidSSID: 1-32 printable ASCII bytes, no backslash/semicolon, no edge spaces (keeps NM keyfile unambiguous).
func ValidSSID(s string) error {
	if len(s) < 1 || len(s) > 32 {
		return errors.New("SSID must be 1-32 characters")
	}
	if strings.TrimSpace(s) != s {
		return errors.New("SSID must not start or end with a space")
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e || r == '\\' || r == ';' {
			return errors.New("SSID may contain printable ASCII except \\ and ;")
		}
	}
	return nil
}

func ValidPassphrase(s string) error {
	if len(s) < 8 || len(s) > 63 {
		return errors.New("passphrase must be 8-63 characters")
	}
	for _, r := range s {
		if r < 0x20 || r > 0x7e {
			return errors.New("passphrase must be printable ASCII")
		}
	}
	return nil
}

func ValidChannel(band string, ch int) error {
	if ch == 0 {
		return nil
	}
	switch band {
	case "bg":
		if ch >= 1 && ch <= 13 {
			return nil
		}
	case "a":
		for _, c := range []int{36, 40, 44, 48, 52, 56, 60, 64, 100, 104, 108, 112, 116, 120, 124, 128, 132, 136, 140, 144, 149, 153, 157, 161, 165} {
			if c == ch {
				return nil
			}
		}
	}
	return fmt.Errorf("channel %d is not valid for band %q", ch, band)
}

// Validate checks n for internal consistency. requirePassphrase is false when the
// caller keeps the stored passphrase.
func (n *Network) Validate(requirePassphrase bool) error {
	var errs []error
	add := func(f string, a ...any) { errs = append(errs, fmt.Errorf(f, a...)) }

	if n.Management.Port < 1 || n.Management.Port > 65535 {
		add("management.port out of range")
	}
	if len(n.Management.Interfaces) == 0 {
		add("at least one management interface is required")
	}
	for _, i := range n.Management.Interfaces {
		if !ValidInterface(i) {
			add("invalid management interface %q", i)
		}
	}
	if len(n.Management.AllowedSubnets) == 0 {
		add("at least one management source subnet is required")
	}
	var mgmtNets []netip.Prefix
	for _, s := range n.Management.AllowedSubnets {
		p, err := netip.ParsePrefix(s)
		if err != nil {
			add("invalid management subnet %q", s)
			continue
		}
		mgmtNets = append(mgmtNets, p.Masked())
	}
	if !ValidInterface(n.Uplink) {
		add("invalid uplink interface %q", n.Uplink)
	}

	a := n.AP
	if !ValidInterface(a.Interface) {
		add("invalid AP interface %q", a.Interface)
	}
	if a.Interface == n.Uplink {
		add("AP and uplink must be different interfaces")
	}
	for _, m := range n.Management.Interfaces {
		if m == a.Interface {
			add("the AP interface cannot be a management interface")
		}
	}
	if err := ValidSSID(a.SSID); err != nil {
		add("%v", err)
	}
	if requirePassphrase || a.Passphrase != "" {
		if err := ValidPassphrase(a.Passphrase); err != nil {
			add("%v", err)
		}
	}
	if a.Security != "wpa2" && a.Security != "wpa3" {
		add("security must be wpa2 or wpa3")
	}
	if a.Band != "bg" && a.Band != "a" {
		add("band must be bg (2.4 GHz) or a (5 GHz)")
	}
	if err := ValidChannel(a.Band, a.Channel); err != nil {
		add("%v", err)
	}
	if !countryRe.MatchString(a.Country) {
		add("country must be a two-letter ISO 3166 code")
	}

	l := n.LAN
	gw, err := netip.ParsePrefix(l.Address)
	if err != nil || !gw.Addr().Is4() || gw.Bits() < 16 || gw.Bits() > 30 {
		add("lan.address must be an IPv4 CIDR between /16 and /30, e.g. 192.168.50.1/24")
	} else {
		subnet := gw.Masked()
		if gw.Addr() == subnet.Addr() || gw.Addr() == broadcast(subnet) {
			add("gateway address cannot be the network or broadcast address")
		}
		for _, m := range mgmtNets {
			if m.Overlaps(subnet) {
				add("AP subnet %s overlaps management subnet %s", subnet, m)
			}
		}
		start, e1 := netip.ParseAddr(l.DHCPStart)
		end, e2 := netip.ParseAddr(l.DHCPEnd)
		switch {
		case e1 != nil || e2 != nil:
			add("invalid DHCP range")
		case !subnet.Contains(start) || !subnet.Contains(end) || end.Less(start):
			add("DHCP range must be inside %s and start <= end", subnet)
		case !gw.Addr().Less(start) && !end.Less(gw.Addr()):
			add("DHCP range must not include the gateway address")
		case start == subnet.Addr() || end == broadcast(subnet):
			add("DHCP range must not include network or broadcast addresses")
		}
		seen := map[string]bool{}
		for _, r := range l.Reservations {
			hw, err := net.ParseMAC(r.MAC)
			ip, err2 := netip.ParseAddr(r.IP)
			if err != nil || len(hw) != 6 {
				add("invalid reservation MAC %q", r.MAC)
			} else if seen[hw.String()] {
				add("duplicate reservation for %s", hw)
			} else {
				seen[hw.String()] = true
			}
			if err2 != nil || !subnet.Contains(ip) || ip == gw.Addr() {
				add("reservation IP %q must be inside %s and not the gateway", r.IP, subnet)
			}
			if r.Hostname != "" && !hostnameRe.MatchString(r.Hostname) {
				add("invalid reservation hostname %q", r.Hostname)
			}
		}
	}
	if l.LeaseMinutes < 2 || l.LeaseMinutes > 60*24*30 {
		add("lease duration must be 2 minutes to 30 days")
	}
	for _, s := range l.UpstreamDNS {
		if _, err := netip.ParseAddr(s); err != nil {
			add("invalid upstream DNS server %q", s)
		}
	}
	for _, o := range l.DNSOverrides {
		if !hostnameRe.MatchString(o.Name) || len(o.Name) > 253 {
			add("invalid DNS override name %q", o.Name)
		}
		if _, err := netip.ParseAddr(o.IP); err != nil {
			add("invalid DNS override address %q", o.IP)
		}
	}

	if n.Forwarding.Mode != "deny" && n.Forwarding.Mode != "internet" {
		add("forwarding.mode must be deny or internet")
	}
	for _, c := range n.Forwarding.AllowCIDRs {
		if p, err := netip.ParsePrefix(c); err != nil || !p.Addr().Is4() {
			add("invalid IPv4 allow CIDR %q", c)
		}
	}
	return errors.Join(errs...)
}

func broadcast(p netip.Prefix) netip.Addr {
	a := p.Masked().Addr().As4()
	host := uint32(1)<<(32-p.Bits()) - 1
	v := uint32(a[0])<<24 | uint32(a[1])<<16 | uint32(a[2])<<8 | uint32(a[3]) | host
	return netip.AddrFrom4([4]byte{byte(v >> 24), byte(v >> 16), byte(v >> 8), byte(v)})
}

// Subnet returns the AP subnet (masked) for a validated config.
func (l LAN) Subnet() netip.Prefix { return netip.MustParsePrefix(l.Address).Masked() }

// Gateway returns the AP gateway address for a validated config.
func (l LAN) Gateway() netip.Addr { return netip.MustParsePrefix(l.Address).Addr() }

// Redacted returns a copy safe to send to the browser or logs.
func (n Network) Redacted() Network {
	n.AP.Passphrase = ""
	return n
}

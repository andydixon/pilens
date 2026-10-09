package netgen

import (
	"strings"
	"testing"

	"pilens.dev/pilens/internal/config"
)

func testNet() config.Network {
	n := config.DefaultNetwork()
	n.Management.Interfaces = []string{"eth0"}
	n.Management.AllowedSubnets = []string{"10.1.0.0/24"}
	n.Uplink = "eth0"
	n.AP.Interface = "wlan0"
	n.AP.Passphrase = `pass\word 123`
	n.LAN.Reservations = []config.Reservation{{MAC: "AA:BB:CC:00:11:22", IP: "192.168.50.20", Hostname: "phone"}}
	n.LAN.DNSOverrides = []config.DNSOverride{{Name: "Api.Test.Local", IP: "192.168.50.1"}}
	return n
}

func TestValidate(t *testing.T) {
	n := testNet()
	if err := n.Validate(true); err != nil {
		t.Fatal(err)
	}
	bad := []func(*config.Network){
		func(n *config.Network) { n.AP.Interface = "eth0" },
		func(n *config.Network) { n.AP.SSID = "a;b" },
		func(n *config.Network) { n.AP.SSID = "bad\nname" },
		func(n *config.Network) { n.AP.Passphrase = "short" },
		func(n *config.Network) { n.AP.Channel = 36 },
		func(n *config.Network) { n.LAN.DHCPStart = "192.168.50.1" },
		func(n *config.Network) { n.LAN.DHCPEnd = "192.168.51.10" },
		func(n *config.Network) { n.Management.AllowedSubnets = []string{"192.168.50.0/25"} },
		func(n *config.Network) { n.LAN.DNSOverrides[0].Name = "x\nserver=1.2.3.4" },
		func(n *config.Network) { n.Uplink = "eth0; rm -rf" },
		func(n *config.Network) { n.Forwarding.Mode = "open" },
		func(n *config.Network) { n.LAN.Address = "192.168.50.0/24" },
	}
	for i, f := range bad {
		c := testNet()
		f(&c)
		if c.Validate(true) == nil {
			t.Errorf("case %d: expected validation error", i)
		}
	}
}

func TestKeyfile(t *testing.T) {
	k := NMKeyfile(testNet())
	for _, want := range []string{"mode=ap", "interface-name=wlan0", `psk=pass\\word 123`, "key-mgmt=wpa-psk", "method=disabled", "address1=192.168.50.1/24", "ssid=PiLens-Lab"} {
		if !strings.Contains(k, want) {
			t.Errorf("keyfile missing %q", want)
		}
	}
}

func TestDnsmasq(t *testing.T) {
	d := DnsmasqConf(testNet())
	for _, want := range []string{"interface=wlan0", "dhcp-range=192.168.50.100,192.168.50.199,255.255.255.0,720m", "dhcp-host=aa:bb:cc:00:11:22,192.168.50.20,phone", "host-record=api.test.local,192.168.50.1", "option:router,192.168.50.1"} {
		if !strings.Contains(d, want) {
			t.Errorf("dnsmasq missing %q\n%s", want, d)
		}
	}
}

func TestNftables(t *testing.T) {
	s := Nftables(testNet())
	for _, want := range []string{
		"delete table inet pilens",
		`iifname "wlan0" jump ap_forward`,
		"meta nfproto ipv6 counter drop",
		`ip saddr 192.168.50.0/24 oifname "eth0" masquerade`,
		"10.1.0.0/24",
		`tcp dport 8443 counter drop`,
	} {
		if !strings.Contains(s, want) {
			t.Errorf("ruleset missing %q", want)
		}
	}
	if strings.Contains(s, "flush ruleset") {
		t.Error("must never flush the whole ruleset")
	}
	n := testNet()
	n.Forwarding.Mode = "deny"
	if !strings.Contains(Nftables(n), `"forwarding disabled"`) {
		t.Error("deny mode must drop forwarded traffic")
	}
}

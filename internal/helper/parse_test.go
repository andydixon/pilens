package helper

import "testing"

func TestParseStationDump(t *testing.T) {
	s := ParseStationDump(`Station AA:bb:cc:dd:ee:ff (on wlan0)
	inactive time:	1200 ms
	rx bytes:	5000
	tx bytes:	7000
	signal:  	-47 [-47, -49] dBm
	connected time:	33 seconds
Station 11:22:33:44:55:66 (on wlan0)
	rx bytes:	1
`)
	if len(s) != 2 || s[0].MAC != "aa:bb:cc:dd:ee:ff" || *s[0].SignalDBm != -47 || s[0].RxBytes != 5000 || s[0].ConnectedS != 33 || s[1].SignalDBm != nil {
		t.Fatalf("%+v", s)
	}
}

func TestParseLeases(t *testing.T) {
	l := ParseLeases("1700000000 AA:BB:CC:DD:EE:FF 192.168.50.101 phone 01:aa\n1700000001 11:22:33:44:55:66 192.168.50.102 * *\ngarbage\n")
	if len(l) != 2 || l[0].Hostname != "phone" || l[1].Hostname != "" || l[0].MAC != "aa:bb:cc:dd:ee:ff" {
		t.Fatalf("%+v", l)
	}
}

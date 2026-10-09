package helper

import (
	"bufio"
	"strconv"
	"strings"
)

// ParseStationDump parses `iw dev X station dump` output.
func ParseStationDump(s string) []Station {
	var out []Station
	var cur *Station
	sc := bufio.NewScanner(strings.NewReader(s))
	for sc.Scan() {
		line := sc.Text()
		if strings.HasPrefix(line, "Station ") {
			f := strings.Fields(line)
			if len(f) >= 2 {
				out = append(out, Station{MAC: strings.ToLower(f[1])})
				cur = &out[len(out)-1]
			}
			continue
		}
		if cur == nil {
			continue
		}
		k, v, ok := strings.Cut(strings.TrimSpace(line), ":")
		if !ok {
			continue
		}
		f := strings.Fields(v)
		if len(f) == 0 {
			continue
		}
		n, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		switch k {
		case "inactive time":
			cur.InactiveMS = n
		case "rx bytes":
			cur.RxBytes = uint64(n)
		case "tx bytes":
			cur.TxBytes = uint64(n)
		case "signal":
			v := int(n)
			cur.SignalDBm = &v
		case "connected time":
			cur.ConnectedS = n
		}
	}
	return out
}

// ParseLeases parses a dnsmasq lease file: "expiry mac ip hostname clientid".
func ParseLeases(s string) []Lease {
	var out []Lease
	for _, line := range strings.Split(s, "\n") {
		f := strings.Fields(line)
		if len(f) < 4 {
			continue
		}
		exp, err := strconv.ParseInt(f[0], 10, 64)
		if err != nil {
			continue
		}
		h := f[3]
		if h == "*" {
			h = ""
		}
		out = append(out, Lease{Expiry: exp, MAC: strings.ToLower(f[1]), IP: f[2], Hostname: h})
	}
	return out
}

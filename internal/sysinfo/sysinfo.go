// Package sysinfo discovers interfaces and reads host health without privileges.
package sysinfo

import (
	"bufio"
	"context"
	"encoding/hex"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"
)

type Interface struct {
	Name      string   `json:"name"`
	MAC       string   `json:"mac"`
	Addrs     []string `json:"addrs"`
	Up        bool     `json:"up"`
	Carrier   bool     `json:"carrier"`
	Wireless  bool     `json:"wireless"`
	Driver    string   `json:"driver"`
	DefaultGW string   `json:"default_gateway,omitempty"`
	SpeedMbps int      `json:"speed_mbps,omitempty"`
	Virtual   bool     `json:"virtual"`
	RxDropped uint64   `json:"rx_dropped"`
}

func readTrim(p string) string {
	b, _ := os.ReadFile(p)
	return strings.TrimSpace(string(b))
}

// DefaultRoutes maps interface -> IPv4 default gateway from /proc/net/route.
func DefaultRoutes() map[string]string {
	out := map[string]string{}
	f, err := os.Open("/proc/net/route")
	if err != nil {
		return out
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Scan()
	for sc.Scan() {
		x := strings.Fields(sc.Text())
		if len(x) < 3 || x[1] != "00000000" {
			continue
		}
		b, err := hex.DecodeString(x[2])
		if err != nil || len(b) != 4 {
			continue
		}
		if _, ok := out[x[0]]; !ok {
			out[x[0]] = net.IPv4(b[3], b[2], b[1], b[0]).String()
		}
	}
	return out
}

func Interfaces() []Interface {
	ifs, _ := net.Interfaces()
	routes := DefaultRoutes()
	var out []Interface
	for _, i := range ifs {
		if i.Flags&net.FlagLoopback != 0 {
			continue
		}
		base := "/sys/class/net/" + i.Name
		x := Interface{Name: i.Name, MAC: i.HardwareAddr.String(), Up: i.Flags&net.FlagUp != 0, DefaultGW: routes[i.Name]}
		x.Carrier = readTrim(base+"/carrier") == "1"
		_, err := os.Stat(base + "/wireless")
		x.Wireless = err == nil
		if _, err := os.Stat(base + "/phy80211"); err == nil {
			x.Wireless = true
		}
		if d, err := os.Readlink(base + "/device/driver"); err == nil {
			x.Driver = filepath.Base(d)
		}
		_, err = os.Stat(base + "/device")
		x.Virtual = err != nil
		x.SpeedMbps, _ = strconv.Atoi(readTrim(base + "/speed"))
		x.RxDropped, _ = strconv.ParseUint(readTrim(base+"/statistics/rx_dropped"), 10, 64)
		addrs, _ := i.Addrs()
		for _, a := range addrs {
			x.Addrs = append(x.Addrs, a.String())
		}
		out = append(out, x)
	}
	return out
}

type WifiCaps struct {
	Phy   string   `json:"phy"`
	AP    bool     `json:"ap_mode"`
	Bands []string `json:"bands"` // "2.4GHz", "5GHz"
	Raw   string   `json:"-"`
	Error string   `json:"error,omitempty"`
}

// WifiCapabilities parses `iw list` (runs unprivileged).
func WifiCapabilities() []WifiCaps {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "iw", "list").Output()
	if err != nil {
		return []WifiCaps{{Error: "iw list failed: " + err.Error()}}
	}
	return ParseIWList(string(out))
}

func ParseIWList(s string) []WifiCaps {
	var res []WifiCaps
	var cur *WifiCaps
	inModes := false
	for _, line := range strings.Split(s, "\n") {
		t := strings.TrimSpace(line)
		if strings.HasPrefix(line, "Wiphy ") {
			res = append(res, WifiCaps{Phy: strings.TrimPrefix(line, "Wiphy ")})
			cur = &res[len(res)-1]
			inModes = false
			continue
		}
		if cur == nil {
			continue
		}
		switch {
		case strings.HasPrefix(t, "Supported interface modes"):
			inModes = true
			continue
		case strings.HasPrefix(t, "Band 1:"):
			cur.Bands = append(cur.Bands, "2.4GHz")
		case strings.HasPrefix(t, "Band 2:"):
			cur.Bands = append(cur.Bands, "5GHz")
		}
		if inModes {
			if strings.HasPrefix(t, "* ") {
				if t == "* AP" {
					cur.AP = true
				}
			} else {
				inModes = false
			}
		}
	}
	return res
}

type Health struct {
	CPUPercent   float64         `json:"cpu_percent"`
	MemTotal     uint64          `json:"mem_total"`
	MemAvail     uint64          `json:"mem_available"`
	TempC        *float64        `json:"temp_c,omitempty"`
	Throttled    string          `json:"throttled,omitempty"` // vcgencmd get_throttled, raw
	ThrottleBits []string        `json:"throttle_flags,omitempty"`
	Load         string          `json:"load"`
	UptimeS      float64         `json:"uptime_s"`
	Disks        map[string]Disk `json:"disks"`
	ClockSync    string          `json:"clock_synchronised"`
	OS           string          `json:"os"`
	Kernel       string          `json:"kernel"`
	Model        string          `json:"model"`
	NMVersion    string          `json:"networkmanager"`
}

type Disk struct {
	Total uint64 `json:"total"`
	Free  uint64 `json:"free"`
}

func cpuSample() (idle, total uint64) {
	f := strings.Fields(strings.SplitN(readTrim("/proc/stat"), "\n", 2)[0])
	for i, v := range f[1:] {
		n, _ := strconv.ParseUint(v, 10, 64)
		total += n
		if i == 3 || i == 4 {
			idle += n
		}
	}
	return
}

func cmdOut(name string, args ...string) string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	b, err := exec.CommandContext(ctx, name, args...).Output()
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(b))
}

// throttle bit meanings from the Raspberry Pi firmware documentation.
var throttleNames = map[int]string{0: "under-voltage now", 1: "ARM frequency capped now", 2: "throttled now", 3: "soft temperature limit now",
	16: "under-voltage has occurred", 17: "frequency capping has occurred", 18: "throttling has occurred", 19: "soft temperature limit has occurred"}

func ReadHealth(paths map[string]string) Health {
	var h Health
	i1, t1 := cpuSample()
	time.Sleep(200 * time.Millisecond)
	i2, t2 := cpuSample()
	if t2 > t1 {
		h.CPUPercent = 100 * (1 - float64(i2-i1)/float64(t2-t1))
	}
	for _, l := range strings.Split(readTrim("/proc/meminfo"), "\n") {
		f := strings.Fields(l)
		if len(f) < 2 {
			continue
		}
		v, _ := strconv.ParseUint(f[1], 10, 64)
		switch f[0] {
		case "MemTotal:":
			h.MemTotal = v * 1024
		case "MemAvailable:":
			h.MemAvail = v * 1024
		}
	}
	if t, err := strconv.ParseFloat(readTrim("/sys/class/thermal/thermal_zone0/temp"), 64); err == nil {
		c := t / 1000
		h.TempC = &c
	}
	if s := cmdOut("vcgencmd", "get_throttled"); strings.HasPrefix(s, "throttled=") {
		h.Throttled = s
		if v, err := strconv.ParseUint(strings.TrimPrefix(s, "throttled="), 0, 32); err == nil {
			for bit, name := range throttleNames {
				if v&(1<<bit) != 0 {
					h.ThrottleBits = append(h.ThrottleBits, name)
				}
			}
		}
	}
	h.Load = readTrim("/proc/loadavg")
	up := strings.Fields(readTrim("/proc/uptime"))
	if len(up) > 0 {
		h.UptimeS, _ = strconv.ParseFloat(up[0], 64)
	}
	h.Disks = map[string]Disk{}
	for name, p := range paths {
		var st syscall.Statfs_t
		if syscall.Statfs(p, &st) == nil {
			h.Disks[name] = Disk{Total: st.Blocks * uint64(st.Bsize), Free: st.Bavail * uint64(st.Bsize)}
		}
	}
	h.ClockSync = cmdOut("timedatectl", "show", "-p", "NTPSynchronized", "--value")
	if h.ClockSync == "" {
		h.ClockSync = "unknown"
	}
	for _, l := range strings.Split(readTrim("/etc/os-release"), "\n") {
		if v, ok := strings.CutPrefix(l, "PRETTY_NAME="); ok {
			h.OS = strings.Trim(v, `"`)
		}
	}
	h.Kernel = readTrim("/proc/sys/kernel/osrelease")
	h.Model = strings.TrimRight(readTrim("/proc/device-tree/model"), "\x00")
	h.NMVersion = cmdOut("nmcli", "--version")
	return h
}

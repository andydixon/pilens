// pilens-helper is the only root component of PiLens. It accepts a fixed set of
// typed requests from the pilens service user over a unix socket and applies
// network configuration transactionally. It never executes caller-supplied commands.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"os/signal"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"syscall"
	"time"

	"pilens.dev/pilens/internal/config"
	"pilens.dev/pilens/internal/helper"
	"pilens.dev/pilens/internal/netgen"
)

var (
	stateDir    = "/var/lib/pilens-helper"
	keyfilePath = "/etc/NetworkManager/system-connections/" + netgen.ConnName + ".nmconnection"
)

func statePath(n string) string { return filepath.Join(stateDir, n) }

type server struct {
	mu        sync.Mutex // one network transaction at a time
	allowUID  uint32
	lastError string
}

func main() {
	socket := flag.String("socket", helper.DefaultSocket, "unix socket path")
	group := flag.String("user", "pilens", "service user allowed to connect")
	boot := flag.Bool("boot", false, "load the last good firewall ruleset and exit (ExecStartPre)")
	render := flag.String("render", "", "render config JSON file to stdout sections and exit (diagnostics)")
	flag.Parse()
	log := slog.New(slog.NewJSONHandler(os.Stderr, nil))
	slog.SetDefault(log)

	if *render != "" {
		os.Exit(renderCmd(*render))
	}
	if *boot {
		if err := bootLoad(); err != nil {
			log.Error("boot load failed", "err", err)
			os.Exit(1)
		}
		return
	}

	u, err := user.Lookup(*group)
	if err != nil {
		log.Error("service user missing", "user", *group, "err", err)
		os.Exit(1)
	}
	uid, _ := strconv.Atoi(u.Uid)
	gid, _ := strconv.Atoi(u.Gid)
	s := &server{allowUID: uint32(uid)}

	os.MkdirAll(filepath.Dir(*socket), 0o750)
	os.Chown(filepath.Dir(*socket), 0, gid)
	os.Remove(*socket)
	ln, err := net.Listen("unix", *socket)
	if err != nil {
		log.Error("listen", "err", err)
		os.Exit(1)
	}
	os.Chown(*socket, 0, gid)
	os.Chmod(*socket, 0o660)

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() { <-ctx.Done(); ln.Close() }()
	log.Info("pilens-helper ready", "socket", *socket)
	for {
		c, err := ln.Accept()
		if err != nil {
			if ctx.Err() != nil {
				return
			}
			continue
		}
		go s.handle(ctx, c.(*net.UnixConn))
	}
}

func peerUID(c *net.UnixConn) (uint32, error) {
	raw, err := c.SyscallConn()
	if err != nil {
		return 0, err
	}
	var cred *syscall.Ucred
	var cerr error
	raw.Control(func(fd uintptr) {
		cred, cerr = syscall.GetsockoptUcred(int(fd), syscall.SOL_SOCKET, syscall.SO_PEERCRED)
	})
	if cerr != nil {
		return 0, cerr
	}
	return cred.Uid, nil
}

func (s *server) handle(ctx context.Context, c *net.UnixConn) {
	defer c.Close()
	uid, err := peerUID(c)
	if err != nil || (uid != s.allowUID && uid != 0) {
		slog.Warn("rejected helper connection", "uid", uid, "err", err)
		return
	}
	c.SetDeadline(time.Now().Add(3 * time.Minute))
	var req helper.Request
	if err := json.NewDecoder(&limitedReader{c, 1 << 20}).Decode(&req); err != nil {
		writeResp(c, nil, errors.New("bad request"))
		return
	}
	slog.Info("helper request", "op", req.Op, "uid", uid)
	var data any
	switch req.Op {
	case helper.OpApplyNetwork:
		if req.Network == nil {
			err = errors.New("network config required")
			break
		}
		r := s.apply(ctx, *req.Network)
		data = r
		if r.Error != "" {
			err = errors.New(r.Error)
		}
	case helper.OpStatus:
		data = s.status(ctx)
	case helper.OpStations:
		data, err = stations(ctx)
	case helper.OpLeases:
		b, rerr := os.ReadFile(netgen.LeaseFile)
		if rerr != nil && !os.IsNotExist(rerr) {
			err = rerr
		}
		data = helper.ParseLeases(string(b))
	default:
		err = fmt.Errorf("unknown op %q", req.Op)
	}
	writeResp(c, data, err)
}

type limitedReader struct {
	c *net.UnixConn
	n int
}

func (l *limitedReader) Read(p []byte) (int, error) {
	if l.n <= 0 {
		return 0, errors.New("request too large")
	}
	if len(p) > l.n {
		p = p[:l.n]
	}
	n, err := l.c.Read(p)
	l.n -= n
	return n, err
}

func writeResp(c net.Conn, data any, err error) {
	r := helper.Response{OK: err == nil}
	if err != nil {
		r.Error = err.Error()
	}
	if data != nil {
		r.Data, _ = json.Marshal(data)
	}
	json.NewEncoder(c).Encode(r)
}

// run executes a fixed program with an argv list (never a shell).
func run(ctx context.Context, timeout time.Duration, name string, args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	out, err := exec.CommandContext(ctx, name, args...).CombinedOutput()
	if err != nil {
		return string(out), fmt.Errorf("%s %s: %v: %s", name, strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return string(out), nil
}

func writeAtomic(path string, data []byte, mode os.FileMode) error {
	os.MkdirAll(filepath.Dir(path), 0o755)
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, mode); err != nil {
		return err
	}
	if err := os.Chmod(tmp, mode); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

// snapshot of the files a transaction touches; nil content = file absent.
type snapshot map[string][]byte

func takeSnapshot(paths ...string) snapshot {
	s := snapshot{}
	for _, p := range paths {
		b, err := os.ReadFile(p)
		if err == nil {
			s[p] = b
		} else {
			s[p] = nil
		}
	}
	return s
}

func (s *server) apply(ctx context.Context, n config.Network) helper.ApplyResult {
	s.mu.Lock()
	defer s.mu.Unlock()
	var r helper.ApplyResult
	step := func(f string, a ...any) { r.Steps = append(r.Steps, fmt.Sprintf(f, a...)) }

	if err := n.Validate(true); err != nil {
		r.Error = "validation: " + err.Error()
		return r
	}
	step("validated configuration")
	ruleset := netgen.Nftables(n)
	tmp := statePath("ruleset.check.nft")
	if err := writeAtomic(tmp, []byte(ruleset), 0o600); err != nil {
		r.Error = err.Error()
		return r
	}
	if _, err := run(ctx, 20*time.Second, "nft", "-c", "-f", tmp); err != nil {
		r.Error = "firewall ruleset rejected by nft -c: " + err.Error()
		return r
	}
	step("nft dry-run passed")

	files := map[string][]byte{
		statePath("ruleset.nft"):  []byte(ruleset),
		statePath("dnsmasq.conf"): []byte(netgen.DnsmasqConf(n)),
		keyfilePath:               []byte(netgen.NMKeyfile(n)),
	}
	var paths []string
	for p := range files {
		paths = append(paths, p)
	}
	snap := takeSnapshot(paths...)
	prevCfg, _ := os.ReadFile(statePath("last-good.json"))
	step("saved previous configuration")

	err := activate(ctx, n, files, step)
	if err == nil {
		err = verify(ctx, n, step)
	}
	if err != nil {
		r.Error = err.Error()
		step("FAILED: %v", err)
		step("rolling back")
		if rbErr := rollback(ctx, snap, prevCfg); rbErr != nil {
			r.Error += "; ROLLBACK ALSO FAILED: " + rbErr.Error()
			step("rollback failed: %v", rbErr)
		} else {
			step("previous configuration restored")
		}
		r.RolledBack = true
		s.lastError = r.Error
		return r
	}
	b, _ := json.Marshal(n)
	writeAtomic(statePath("last-good.json"), b, 0o600)
	s.lastError = ""
	r.Applied = true
	step("configuration committed")
	return r
}

func activate(ctx context.Context, n config.Network, files map[string][]byte, step func(string, ...any)) error {
	for p, b := range files {
		if err := writeAtomic(p, b, 0o600); err != nil {
			return err
		}
	}
	if _, err := run(ctx, 20*time.Second, "nft", "-f", statePath("ruleset.nft")); err != nil {
		return err
	}
	step("firewall table inet pilens loaded")
	if n.Forwarding.Mode == "internet" {
		// Only ever enabled here, after the ruleset is in place. We never disable it:
		// other host services may rely on it and the pilens table drops AP traffic in deny mode.
		if err := os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644); err != nil {
			return err
		}
		step("IPv4 forwarding enabled")
	}
	if _, err := run(ctx, 10*time.Second, "iw", "reg", "set", n.AP.Country); err != nil {
		step("warning: could not set regulatory domain: %v", err)
	}
	if _, err := run(ctx, 20*time.Second, "nmcli", "connection", "load", keyfilePath); err != nil {
		return err
	}
	if n.AP.Enabled {
		if _, err := run(ctx, 60*time.Second, "nmcli", "--wait", "45", "connection", "up", netgen.ConnName); err != nil {
			return err
		}
		step("access point %q activated", n.AP.SSID)
		if _, err := run(ctx, 30*time.Second, "systemctl", "restart", "pilens-dnsmasq.service"); err != nil {
			return err
		}
		step("DHCP/DNS restarted")
	} else {
		run(ctx, 30*time.Second, "nmcli", "connection", "down", netgen.ConnName)
		run(ctx, 30*time.Second, "systemctl", "stop", "pilens-dnsmasq.service")
		step("access point disabled")
	}
	return nil
}

func verify(ctx context.Context, n config.Network, step func(string, ...any)) error {
	if _, err := run(ctx, 10*time.Second, "nft", "list", "table", "inet", netgen.TableName); err != nil {
		return errors.New("firewall table missing after apply")
	}
	if !n.AP.Enabled {
		return nil
	}
	deadline := time.Now().Add(15 * time.Second)
	for {
		st := apState(ctx)
		dn := unitActive(ctx, "pilens-dnsmasq.service")
		if st == "activated" && dn {
			step("verified: AP activated, DHCP/DNS active")
			return nil
		}
		if time.Now().After(deadline) {
			return fmt.Errorf("health check failed: AP state %q, dnsmasq active=%v", st, dn)
		}
		time.Sleep(time.Second)
	}
}

func rollback(ctx context.Context, snap snapshot, prevCfg []byte) error {
	var errs []error
	for p, b := range snap {
		if b == nil {
			os.Remove(p)
		} else if err := writeAtomic(p, b, 0o600); err != nil {
			errs = append(errs, err)
		}
	}
	rs := statePath("ruleset.nft")
	if snap[rs] != nil {
		if _, err := run(ctx, 20*time.Second, "nft", "-f", rs); err != nil {
			errs = append(errs, err)
		}
	} else {
		// No previous policy: fail closed on the AP side.
		var n config.Network
		ap := "wlan0"
		if json.Unmarshal(prevCfg, &n) == nil && n.AP.Interface != "" {
			ap = n.AP.Interface
		}
		writeAtomic(rs, []byte(netgen.DenyAll(ap)), 0o600)
		if _, err := run(ctx, 20*time.Second, "nft", "-f", rs); err != nil {
			errs = append(errs, err)
		}
	}
	if snap[keyfilePath] != nil {
		run(ctx, 20*time.Second, "nmcli", "connection", "load", keyfilePath)
		var n config.Network
		if json.Unmarshal(prevCfg, &n) == nil && n.AP.Enabled {
			if _, err := run(ctx, 60*time.Second, "nmcli", "--wait", "45", "connection", "up", netgen.ConnName); err != nil {
				errs = append(errs, err)
			}
			run(ctx, 30*time.Second, "systemctl", "restart", "pilens-dnsmasq.service")
		}
	} else {
		run(ctx, 20*time.Second, "nmcli", "connection", "delete", netgen.ConnName)
		run(ctx, 30*time.Second, "systemctl", "stop", "pilens-dnsmasq.service")
	}
	return errors.Join(errs...)
}

func apState(ctx context.Context) string {
	out, err := run(ctx, 10*time.Second, "nmcli", "-g", "GENERAL.STATE", "connection", "show", netgen.ConnName)
	if err != nil {
		return "absent"
	}
	if s := strings.TrimSpace(out); s != "" {
		return s
	}
	return "inactive"
}

func unitActive(ctx context.Context, unit string) bool {
	_, err := run(ctx, 10*time.Second, "systemctl", "is-active", "--quiet", unit)
	return err == nil
}

func (s *server) status(ctx context.Context) helper.Status {
	st := helper.Status{LastError: s.lastError}
	_, err := run(ctx, 10*time.Second, "nft", "list", "table", "inet", netgen.TableName)
	st.TableLoaded = err == nil
	st.APState = apState(ctx)
	st.DnsmasqActive = unitActive(ctx, "pilens-dnsmasq.service")
	b, _ := os.ReadFile("/proc/sys/net/ipv4/ip_forward")
	st.IPForward = strings.TrimSpace(string(b)) == "1"
	if out, err := run(ctx, 5*time.Second, "iw", "reg", "get"); err == nil {
		for _, l := range strings.Split(out, "\n") {
			if strings.HasPrefix(l, "country ") {
				st.Regdomain = strings.TrimSuffix(strings.Fields(l)[1], ":")
				break
			}
		}
	}
	_, err = os.Stat(statePath("last-good.json"))
	st.Configured = err == nil
	return st
}

func stations(ctx context.Context) ([]helper.Station, error) {
	b, err := os.ReadFile(statePath("last-good.json"))
	if err != nil {
		return nil, nil
	}
	var n config.Network
	if err := json.Unmarshal(b, &n); err != nil || !config.ValidInterface(n.AP.Interface) {
		return nil, errors.New("stored configuration unreadable")
	}
	out, err := run(ctx, 10*time.Second, "iw", "dev", n.AP.Interface, "station", "dump")
	if err != nil {
		return nil, err
	}
	return helper.ParseStationDump(out), nil
}

// bootLoad restores the last good ruleset (or a fail-closed one) before networking starts.
func bootLoad() error {
	ctx := context.Background()
	rs := statePath("ruleset.nft")
	if _, err := os.Stat(rs); err != nil {
		slog.Info("no ruleset yet; nothing to load")
		return nil
	}
	if _, err := run(ctx, 20*time.Second, "nft", "-f", rs); err != nil {
		return err
	}
	b, err := os.ReadFile(statePath("last-good.json"))
	var n config.Network
	if err == nil && json.Unmarshal(b, &n) == nil {
		if n.Forwarding.Mode == "internet" {
			os.WriteFile("/proc/sys/net/ipv4/ip_forward", []byte("1"), 0o644)
		}
		if n.AP.Country != "" {
			run(ctx, 10*time.Second, "iw", "reg", "set", n.AP.Country)
		}
	}
	slog.Info("firewall restored at boot")
	return nil
}

func renderCmd(path string) int {
	b, err := os.ReadFile(path)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	var n config.Network
	if err := json.Unmarshal(b, &n); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	if err := n.Validate(true); err != nil {
		fmt.Fprintln(os.Stderr, err)
		return 1
	}
	fmt.Printf("### nftables\n%s\n### dnsmasq.conf\n%s\n### %s (psk redacted)\n%s", netgen.Nftables(n), netgen.DnsmasqConf(n), keyfilePath, netgen.NMKeyfile(n.Redacted()))
	return 0
}

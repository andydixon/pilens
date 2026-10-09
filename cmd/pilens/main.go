// pilens is the PiLens management service (runs as the unprivileged "pilens" user).
package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log/slog"
	"math/big"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"

	"pilens.dev/pilens/internal/api"
	"pilens.dev/pilens/internal/auth"
	"pilens.dev/pilens/internal/capture"
	"pilens.dev/pilens/internal/config"
	"pilens.dev/pilens/internal/helper"
	"pilens.dev/pilens/internal/pcapfile"
	"pilens.dev/pilens/internal/store"
	"pilens.dev/pilens/web"
)

// Version is set at build time with -ldflags "-X main.Version=...".
var Version = "dev"

func usage() {
	fmt.Fprintf(os.Stderr, `PiLens %s

usage:
  pilens serve   [-data DIR] [-listen ADDR] [-captures DIR]
  pilens init    [-data DIR] -mgmt-iface IF[,IF] -mgmt-subnet CIDR[,CIDR]
  pilens setup   [-data DIR] -config setup.yaml     (non-interactive first-run)
  pilens reset-password [-data DIR] -user NAME      (reads new password from stdin)
  pilens version
`, Version)
	os.Exit(2)
}

func main() {
	if len(os.Args) < 2 {
		usage()
	}
	cmd, args := os.Args[1], os.Args[2:]
	var err error
	switch cmd {
	case "serve":
		err = serve(args)
	case "init":
		err = initCmd(args)
	case "setup":
		err = setupCmd(args)
	case "reset-password":
		err = resetPassword(args)
	case "rlimit-exec":
		err = rlimitExec(args)
	case "version":
		fmt.Println(Version)
	default:
		usage()
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "pilens:", err)
		os.Exit(1)
	}
}

const defaultData = "/var/lib/pilens"

func openStore(data string) (*store.Store, error) {
	if err := os.MkdirAll(data, 0o750); err != nil {
		return nil, err
	}
	return store.Open(filepath.Join(data, "pilens.db"))
}

// ---------------------------------------------------------------- serve

func serve(args []string) error {
	fs := flag.NewFlagSet("serve", flag.ExitOnError)
	data := fs.String("data", defaultData, "state directory")
	listen := fs.String("listen", ":8443", "HTTPS listen address")
	caps := fs.String("captures", "", "capture storage directory (default DATA/captures)")
	sock := fs.String("helper-socket", helper.DefaultSocket, "root helper socket")
	fs.Parse(args)
	slog.SetDefault(slog.New(slog.NewJSONHandler(os.Stderr, nil)))
	if *caps == "" {
		*caps = filepath.Join(*data, "captures")
	}
	if err := os.MkdirAll(*caps, 0o750); err != nil {
		return err
	}
	db, err := openStore(*data)
	if err != nil {
		return err
	}
	defer db.Close()

	self, _ := os.Executable()
	tools := &capture.Tools{Self: self}
	if tools.TShark, err = exec.LookPath("tshark"); err != nil {
		return errors.New("tshark not found: install the tshark package")
	}
	if tools.Dumpcap, err = exec.LookPath("dumpcap"); err != nil {
		return errors.New("dumpcap not found: install wireshark-common")
	}
	if err := tools.Init(*data); err != nil {
		return err
	}
	eng := &capture.Engine{DB: db, Dir: *caps, Tools: tools, Hub: capture.NewHub(), Version: Version}
	lim := capture.DefaultLimits()
	db.GetJSON("capture_limits", &lim)
	eng.SetLimits(lim)
	for _, id := range recoverSessions(db, *caps) {
		go eng.Reindex(id)
	}

	cert, fp, err := ensureCert(*data)
	if err != nil {
		return err
	}
	slog.Info("management certificate", "sha256", fp)
	srv := &api.Server{DB: db, Engine: eng, Helper: helper.Client{Socket: *sock}, Version: Version, Web: web.FS(),
		SetupTokenPath: filepath.Join(*data, "setup-token"), DataDir: *data}
	hs := &http.Server{
		Addr:              *listen,
		Handler:           srv.Handler(),
		TLSConfig:         &tls.Config{Certificates: []tls.Certificate{cert}, MinVersion: tls.VersionTLS12},
		ReadHeaderTimeout: 10 * time.Second,
		IdleTimeout:       2 * time.Minute,
		ErrorLog:          slog.NewLogLogger(slog.Default().Handler(), slog.LevelWarn),
	}
	ln, err := net.Listen("tcp", *listen)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGTERM, syscall.SIGINT)
	defer stop()
	go func() {
		if err := hs.ServeTLS(ln, "", ""); err != nil && err != http.ErrServerClosed {
			slog.Error("http server", "err", err)
			stop()
		}
	}()
	sdNotify("READY=1")
	go watchdog(ctx, db)
	slog.Info("pilens serving", "listen", *listen, "version", Version)
	<-ctx.Done()

	// Shutdown order: stop accepting requests, finalise any capture (flush, hash),
	// then close the database. systemd TimeoutStopSec must cover this.
	sdNotify("STOPPING=1")
	shCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	hs.Shutdown(shCtx)
	if _, running := eng.Live(); running {
		slog.Info("stopping capture for shutdown")
		eng.Stop()
	}
	return nil
}

// recoverSessions finalises sessions left running by a crash or power loss.
// It returns the IDs of the sessions it marked interrupted.
func recoverSessions(db *store.Store, dir string) (ids []string) {
	rows, err := db.Query(`SELECT s.id, g.seq, g.file, g.format FROM segments g JOIN capture_sessions s ON s.id=g.session_id WHERE g.complete=0 AND g.deleted=0`)
	if err == nil {
		type seg struct {
			id, file, format string
			seq              int
		}
		var segs []seg
		for rows.Next() {
			var s seg
			rows.Scan(&s.id, &s.seq, &s.file, &s.format)
			segs = append(segs, s)
		}
		rows.Close()
		for _, s := range segs {
			p := filepath.Join(dir, s.id, s.file)
			n := 0
			scanErr := pcapfile.Scan(p, s.format, func(int, int64, []byte) error { n++; return nil })
			f, err := os.Open(p)
			if err != nil {
				continue
			}
			h := sha256.New()
			size, _ := f.Seek(0, 2)
			f.Seek(0, 0)
			buf := make([]byte, 1<<20)
			for {
				k, err := f.Read(buf)
				h.Write(buf[:k])
				if err != nil {
					break
				}
			}
			f.Close()
			db.Exec(`UPDATE segments SET count=?,bytes=?,sha256=?,complete=1 WHERE session_id=? AND seq=?`, n, size, hex.EncodeToString(h.Sum(nil)), s.id, s.seq)
			slog.Warn("recovered interrupted segment", "session", s.id, "segment", s.seq, "packets", n, "truncated_tail", scanErr != nil)
		}
	}
	if r, err := db.Query(`SELECT id FROM capture_sessions WHERE state IN ('running','importing')`); err == nil {
		for r.Next() {
			var id string
			r.Scan(&id)
			ids = append(ids, id)
		}
		r.Close()
	}
	db.Exec(`UPDATE capture_sessions SET state='failed', error='interrupted: the service stopped unexpectedly (power loss or crash); segments were finalised on restart and summaries may be incomplete', ended_at=? WHERE state IN ('running','importing')`, time.Now().UnixMilli())
	return ids
}

func sdNotify(state string) {
	addr := os.Getenv("NOTIFY_SOCKET")
	if addr == "" {
		return
	}
	c, err := net.Dial("unixgram", addr)
	if err != nil {
		return
	}
	defer c.Close()
	c.Write([]byte(state))
}

// watchdog pings systemd only while the database answers, so a wedged service is restarted.
func watchdog(ctx context.Context, db *store.Store) {
	us, err := strconv.Atoi(os.Getenv("WATCHDOG_USEC"))
	if err != nil || us <= 0 {
		return
	}
	t := time.NewTicker(time.Duration(us/3) * time.Microsecond)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			c, cancel := context.WithTimeout(ctx, 5*time.Second)
			if db.PingContext(c) == nil {
				sdNotify("WATCHDOG=1")
			}
			cancel()
		}
	}
}

// ensureCert loads or creates the self-signed management certificate. It is
// independent of any TLS-interception CA.
func ensureCert(data string) (tls.Certificate, string, error) {
	dir := filepath.Join(data, "tls")
	cp, kp := filepath.Join(dir, "mgmt.crt"), filepath.Join(dir, "mgmt.key")
	if c, err := tls.LoadX509KeyPair(cp, kp); err == nil {
		sum := sha256.Sum256(c.Certificate[0])
		return c, fingerprint(sum[:]), nil
	}
	os.MkdirAll(dir, 0o700)
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	host, _ := os.Hostname()
	serial, _ := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 127))
	tpl := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: host + " PiLens management", Organization: []string{"PiLens appliance"}},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().AddDate(5, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		DNSNames:     []string{host, host + ".local", "localhost"},
	}
	if ifs, err := net.InterfaceAddrs(); err == nil {
		for _, a := range ifs {
			if ipn, ok := a.(*net.IPNet); ok {
				tpl.IPAddresses = append(tpl.IPAddresses, ipn.IP)
			}
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, tpl, tpl, &key.PublicKey, key)
	if err != nil {
		return tls.Certificate{}, "", err
	}
	kb, _ := x509.MarshalECPrivateKey(key)
	if err := os.WriteFile(kp, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: kb}), 0o600); err != nil {
		return tls.Certificate{}, "", err
	}
	os.WriteFile(cp, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644)
	c, err := tls.LoadX509KeyPair(cp, kp)
	sum := sha256.Sum256(der)
	return c, fingerprint(sum[:]), err
}

func fingerprint(b []byte) string {
	h := strings.ToUpper(hex.EncodeToString(b))
	var parts []string
	for i := 0; i < len(h); i += 2 {
		parts = append(parts, h[i:i+2])
	}
	return strings.Join(parts, ":")
}

// ---------------------------------------------------------------- init / setup

func splitList(s string) []string {
	var out []string
	for _, x := range strings.Split(s, ",") {
		if x = strings.TrimSpace(x); x != "" {
			out = append(out, x)
		}
	}
	return out
}

func initCmd(args []string) error {
	fs := flag.NewFlagSet("init", flag.ExitOnError)
	data := fs.String("data", defaultData, "state directory")
	ifs := fs.String("mgmt-iface", "", "management interface(s), comma separated")
	subs := fs.String("mgmt-subnet", "", "management source subnet(s), comma separated")
	fs.Parse(args)
	m := config.Management{Interfaces: splitList(*ifs), AllowedSubnets: splitList(*subs), Port: 8443}
	if len(m.Interfaces) == 0 || len(m.AllowedSubnets) == 0 {
		return errors.New("-mgmt-iface and -mgmt-subnet are required")
	}
	for _, i := range m.Interfaces {
		if !config.ValidInterface(i) {
			return fmt.Errorf("invalid interface %q", i)
		}
	}
	for _, s := range m.AllowedSubnets {
		if _, _, err := net.ParseCIDR(s); err != nil {
			return fmt.Errorf("invalid subnet %q", s)
		}
	}
	db, err := openStore(*data)
	if err != nil {
		return err
	}
	defer db.Close()
	if err := db.PutJSON("bootstrap_management", m); err != nil {
		return err
	}
	_, fp, err := ensureCert(*data)
	if err != nil {
		return err
	}
	fmt.Println("certificate_sha256=" + fp)
	var users int
	db.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&users)
	if users == 0 {
		tp := filepath.Join(*data, "setup-token")
		tok, err := os.ReadFile(tp)
		if err != nil {
			tok = []byte(auth.RandomToken(12))
			if err := os.WriteFile(tp, tok, 0o600); err != nil {
				return err
			}
		}
		fmt.Println("setup_token=" + strings.TrimSpace(string(tok)))
	}
	return nil
}

type setupFile struct {
	Admin struct {
		Username     string `yaml:"username"`
		Password     string `yaml:"password"`
		PasswordFile string `yaml:"password_file"`
	} `yaml:"admin"`
	AuthorisedUse bool            `yaml:"authorised_use"`
	Network       config.Network  `yaml:"network"`
	Storage       *capture.Limits `yaml:"storage"`
}

func setupCmd(args []string) error {
	fs := flag.NewFlagSet("setup", flag.ExitOnError)
	data := fs.String("data", defaultData, "state directory")
	cfgPath := fs.String("config", "", "setup YAML")
	sock := fs.String("helper-socket", helper.DefaultSocket, "root helper socket")
	fs.Parse(args)
	b, err := os.ReadFile(*cfgPath)
	if err != nil {
		return err
	}
	var sf setupFile
	sf.Network = config.DefaultNetwork()
	dec := yaml.NewDecoder(strings.NewReader(string(b)))
	dec.KnownFields(true)
	if err := dec.Decode(&sf); err != nil {
		return fmt.Errorf("%s: %w", *cfgPath, err)
	}
	if !sf.AuthorisedUse {
		return errors.New("authorised_use: true is required (confirms the appliance will only inspect traffic you are authorised to inspect)")
	}
	pw := sf.Admin.Password
	if sf.Admin.PasswordFile != "" {
		p, err := os.ReadFile(sf.Admin.PasswordFile)
		if err != nil {
			return err
		}
		pw = strings.TrimRight(string(p), "\r\n")
	}
	if err := auth.PasswordPolicy(pw); err != nil {
		return err
	}
	if err := sf.Network.Validate(true); err != nil {
		return err
	}
	db, err := openStore(*data)
	if err != nil {
		return err
	}
	defer db.Close()
	h, _ := auth.HashPassword(pw)
	res, err := db.Exec(`INSERT INTO users(username,password_hash,created_at) SELECT ?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`, sf.Admin.Username, h, time.Now().Unix())
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		fmt.Println("an administrator already exists; leaving accounts unchanged")
	} else {
		os.Remove(filepath.Join(*data, "setup-token"))
		db.Audit(sf.Admin.Username, "setup.admin_created", "non-interactive setup; authorised-use confirmation recorded", "local")
	}
	if sf.Storage != nil {
		db.PutJSON("capture_limits", *sf.Storage)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()
	var r helper.ApplyResult
	err = helper.Client{Socket: *sock}.Call(ctx, helper.Request{Op: helper.OpApplyNetwork, Network: &sf.Network}, &r)
	for _, s := range r.Steps {
		fmt.Println("  " + s)
	}
	if err != nil {
		return fmt.Errorf("network apply failed: %w", err)
	}
	db.PutJSON("network", sf.Network)
	db.PutJSON("setup_complete", true)
	db.Audit("local", "setup.completed", "non-interactive", "local")
	fmt.Println("setup complete")
	return nil
}

func resetPassword(args []string) error {
	fs := flag.NewFlagSet("reset-password", flag.ExitOnError)
	data := fs.String("data", defaultData, "state directory")
	user := fs.String("user", "", "username")
	fs.Parse(args)
	var pw string
	fmt.Fprint(os.Stderr, "new password: ")
	fmt.Fscanln(os.Stdin, &pw)
	if err := auth.PasswordPolicy(pw); err != nil {
		return err
	}
	db, err := openStore(*data)
	if err != nil {
		return err
	}
	defer db.Close()
	h, _ := auth.HashPassword(pw)
	res, err := db.Exec(`UPDATE users SET password_hash=?, totp_enabled=0, totp_secret='' WHERE username=?`, h, *user)
	if err != nil {
		return err
	}
	if n, _ := res.RowsAffected(); n == 0 {
		return errors.New("no such user")
	}
	db.Exec(`DELETE FROM sessions`)
	db.Audit("local", "auth.password_reset", *user+" (TOTP disabled, all sessions revoked)", "console")
	fmt.Println("password reset; TOTP disabled; all sessions revoked")
	return nil
}

// rlimitExec applies resource limits and no_new_privs, then execs tshark.
func rlimitExec(args []string) error {
	if len(args) < 4 || args[2] != "--" || filepath.Base(args[3]) != "tshark" {
		return errors.New("usage: rlimit-exec MEM_MB CPU_SECONDS -- /path/to/tshark ARGS")
	}
	mb, err1 := strconv.ParseUint(args[0], 10, 64)
	cpu, err2 := strconv.ParseUint(args[1], 10, 64)
	if err1 != nil || err2 != nil {
		return errors.New("invalid limits")
	}
	if mb > 0 {
		lim := mb << 20
		if err := syscall.Setrlimit(syscall.RLIMIT_AS, &syscall.Rlimit{Cur: lim, Max: lim}); err != nil {
			return err
		}
	}
	if cpu > 0 {
		syscall.Setrlimit(syscall.RLIMIT_CPU, &syscall.Rlimit{Cur: cpu, Max: cpu + 5})
	}
	syscall.Setrlimit(syscall.RLIMIT_CORE, &syscall.Rlimit{})
	const prSetNoNewPrivs = 38
	if _, _, e := syscall.RawSyscall(syscall.SYS_PRCTL, prSetNoNewPrivs, 1, 0); e != 0 {
		return e
	}
	return syscall.Exec(args[3], args[3:], os.Environ())
}

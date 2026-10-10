package proxy

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"io"
	"log/slog"
	"net/netip"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"sync"
	"time"

	"pilens.dev/pilens/internal/store"
)

// Config is the interception toggle and its options. Stored in settings.
type Config struct {
	Enabled       bool     `json:"enabled"`
	CaptureBodies bool     `json:"capture_bodies"` // default false: sensitive content off by default
	MaxBodyKB     int      `json:"max_body_kb"`
	ExcludeHosts  []string `json:"exclude_hosts"` // host regexes NOT decrypted (passed through)
}

func DefaultConfig() Config { return Config{Enabled: false, CaptureBodies: false, MaxBodyKB: 256} }

const ListenPort = 8081

var hostRe = regexp.MustCompile(`^[A-Za-z0-9.*?+()\[\]{}|\\^$_:-]{1,200}$`)

func (c Config) Validate() error {
	if c.MaxBodyKB < 0 || c.MaxBodyKB > 10240 {
		return errors.New("max_body_kb must be 0-10240")
	}
	for _, h := range c.ExcludeHosts {
		if !hostRe.MatchString(h) {
			return errors.New("invalid exclude-host pattern: " + h)
		}
		if _, err := regexp.Compile(h); err != nil {
			return errors.New("invalid exclude-host regex " + h + ": " + err.Error())
		}
	}
	return nil
}

// Sink receives live events for the browser (adapts the capture Hub).
type Sink interface{ Publish(eventType string, data []byte) }

// Flow is one HTTP(S) transaction, as emitted by the mitmdump addon and stored.
type Flow struct {
	ID          string            `json:"id"`
	TS          float64           `json:"ts"`
	Client      string            `json:"client"`
	Method      string            `json:"method"`
	Scheme      string            `json:"scheme"`
	Host        string            `json:"host"`
	Port        int               `json:"port"`
	Path        string            `json:"path"`
	HTTPVersion string            `json:"http_version"`
	Status      int               `json:"status"`
	Reason      string            `json:"reason"`
	ReqCType    string            `json:"req_ctype"`
	RespCType   string            `json:"resp_ctype"`
	ReqSize     int64             `json:"req_size"`
	RespSize    int64             `json:"resp_size"`
	DurationMS  int64             `json:"duration_ms"`
	TLSVersion  string            `json:"tls_version"`
	SNI         string            `json:"sni"`
	ALPN        string            `json:"alpn"`
	Intercepted bool              `json:"intercepted"`
	Error       string            `json:"error"`
	WebSocket   bool              `json:"websocket"`
	HasReqBody  bool              `json:"has_req_body"`
	HasRespBody bool              `json:"has_resp_body"`
	ReqHeaders  map[string]string `json:"req_headers"`
	RespHeaders map[string]string `json:"resp_headers"`
}

// Manager owns interception state, the flow ingester and queries.
type Manager struct {
	DB       *store.Store
	Dir      string // /var/lib/pilens/proxy
	Hostname string
	Sink     Sink

	mu     sync.Mutex
	cfg    Config
	cancel context.CancelFunc
}

func New(db *store.Store, dir, hostname string, sink Sink) *Manager {
	m := &Manager{DB: db, Dir: dir, Hostname: hostname, Sink: sink, cfg: DefaultConfig()}
	db.GetJSON("interception", &m.cfg)
	return m
}

func (m *Manager) Config() Config { m.mu.Lock(); defer m.mu.Unlock(); return m.cfg }

func (m *Manager) SetConfig(c Config) error {
	if err := c.Validate(); err != nil {
		return err
	}
	m.mu.Lock()
	m.cfg = c
	m.mu.Unlock()
	return m.DB.PutJSON("interception", c)
}

func (m *Manager) flowsPath() string  { return filepath.Join(m.Dir, "flows.ndjson") }
func (m *Manager) bodiesDir() string  { return filepath.Join(m.Dir, "bodies") }
func (m *Manager) ConfDir() string    { return filepath.Join(m.Dir, "ca") }

func (m *Manager) EnsureCA() error { return EnsureCA(m.ConfDir(), m.Hostname) }
func (m *Manager) CAInfo() CAInfo  { return Info(m.ConfDir()) }
func (m *Manager) CACertPEM() ([]byte, error) { return PublicCertPEM(m.ConfDir()) }
func (m *Manager) RotateCA() error { return Rotate(m.ConfDir(), m.Hostname) }

// Start begins tailing the flow file. It runs for the service lifetime; the
// mitmdump service is started/stopped by the helper, this just ingests.
func (m *Manager) Start(ctx context.Context) {
	os.MkdirAll(m.bodiesDir(), 0o750)
	ctx, cancel := context.WithCancel(ctx)
	m.cancel = cancel
	go m.tail(ctx)
}

// tail follows flows.ndjson, inserting new lines. Survives file rotation/truncation.
func (m *Manager) tail(ctx context.Context) {
	path := m.flowsPath()
	var offset int64
	m.DB.GetJSON("interception_flow_offset", &offset)
	for ctx.Err() == nil {
		f, err := os.Open(path)
		if err != nil {
			select {
			case <-ctx.Done():
				return
			case <-time.After(2 * time.Second):
			}
			continue
		}
		if fi, _ := f.Stat(); fi != nil && fi.Size() < offset {
			offset = 0 // file was rotated/truncated
		}
		f.Seek(offset, io.SeekStart)
		r := bufio.NewReaderSize(f, 1<<20)
		for ctx.Err() == nil {
			line, rerr := r.ReadBytes('\n')
			if len(line) > 0 && line[len(line)-1] == '\n' {
				offset += int64(len(line))
				m.ingest(line)
				m.DB.PutJSON("interception_flow_offset", offset)
				continue
			}
			_ = rerr // partial/EOF: keep offset, re-read after the wait
			break
		}
		f.Close()
		select {
		case <-ctx.Done():
			return
		case <-time.After(500 * time.Millisecond):
		}
	}
}

func (m *Manager) ingest(line []byte) {
	var fl Flow
	if err := json.Unmarshal(line, &fl); err != nil || fl.ID == "" {
		return
	}
	rh, _ := json.Marshal(fl.ReqHeaders)
	sh, _ := json.Marshal(fl.RespHeaders)
	_, err := m.DB.Exec(`INSERT OR REPLACE INTO http_flows
		(id,ts,client,method,scheme,host,port,path,http_version,status,reason,req_ctype,resp_ctype,req_size,resp_size,duration_ms,tls_version,sni,alpn,intercepted,error,websocket,has_req_body,has_resp_body,req_headers,resp_headers)
		VALUES (?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`,
		fl.ID, fl.TS, fl.Client, fl.Method, fl.Scheme, fl.Host, fl.Port, fl.Path, fl.HTTPVersion, fl.Status, fl.Reason,
		fl.ReqCType, fl.RespCType, fl.ReqSize, fl.RespSize, fl.DurationMS, fl.TLSVersion, fl.SNI, fl.ALPN,
		b2i(fl.Intercepted), fl.Error, b2i(fl.WebSocket), b2i(fl.HasReqBody), b2i(fl.HasRespBody), string(rh), string(sh))
	if err != nil {
		slog.Warn("http flow insert", "err", err)
		return
	}
	if m.Sink != nil {
		m.Sink.Publish("http", line)
	}
}

func b2i(b bool) int {
	if b {
		return 1
	}
	return 0
}

// --- queries ---

const flowCols = `id,ts,client,method,scheme,host,port,path,http_version,status,reason,req_ctype,resp_ctype,req_size,resp_size,duration_ms,tls_version,sni,alpn,intercepted,error,websocket,has_req_body,has_resp_body,req_headers,resp_headers`

func scanFlow(sc interface{ Scan(...any) error }) (Flow, error) {
	var f Flow
	var rh, sh string
	var intercept, ws, hrb, hsb int
	err := sc.Scan(&f.ID, &f.TS, &f.Client, &f.Method, &f.Scheme, &f.Host, &f.Port, &f.Path, &f.HTTPVersion, &f.Status, &f.Reason,
		&f.ReqCType, &f.RespCType, &f.ReqSize, &f.RespSize, &f.DurationMS, &f.TLSVersion, &f.SNI, &f.ALPN,
		&intercept, &f.Error, &ws, &hrb, &hsb, &rh, &sh)
	f.Intercepted, f.WebSocket, f.HasReqBody, f.HasRespBody = intercept == 1, ws == 1, hrb == 1, hsb == 1
	json.Unmarshal([]byte(rh), &f.ReqHeaders)
	json.Unmarshal([]byte(sh), &f.RespHeaders)
	return f, err
}

// Flows returns recent transactions, newest first, optionally filtered by a
// substring over host/path/client and a client IP.
func (m *Manager) Flows(ctx context.Context, q, client string, limit int) ([]Flow, error) {
	if limit <= 0 || limit > 5000 {
		limit = 1000
	}
	where := "1=1"
	args := []any{}
	if q != "" {
		where += " AND (host LIKE ? OR path LIKE ? OR client LIKE ?)"
		like := "%" + q + "%"
		args = append(args, like, like, like)
	}
	if client != "" {
		where += " AND client = ?"
		args = append(args, client)
	}
	args = append(args, limit)
	rows, err := m.DB.QueryContext(ctx, `SELECT `+flowCols+` FROM http_flows WHERE `+where+` ORDER BY ts DESC LIMIT ?`, args...)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Flow{}
	for rows.Next() {
		f, err := scanFlow(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

func (m *Manager) Flow(ctx context.Context, id string) (Flow, error) {
	return scanFlow(m.DB.QueryRowContext(ctx, `SELECT `+flowCols+` FROM http_flows WHERE id=?`, id))
}

// Body returns a stored request/response body. which is "req" or "resp".
// Bodies exist only when body capture was enabled for that flow.
func (m *Manager) Body(id, which string) ([]byte, error) {
	if which != "req" && which != "resp" || !flowIDRe.MatchString(id) {
		return nil, errors.New("invalid body request")
	}
	return os.ReadFile(filepath.Join(m.bodiesDir(), id+"."+which))
}

var flowIDRe = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)

// Clear deletes all intercepted HTTP data (flows + bodies). Captures are untouched.
func (m *Manager) Clear() error {
	m.DB.Exec(`DELETE FROM http_flows`)
	os.RemoveAll(m.bodiesDir())
	os.MkdirAll(m.bodiesDir(), 0o750)
	os.Truncate(m.flowsPath(), 0)
	m.DB.PutJSON("interception_flow_offset", int64(0))
	return nil
}

// ClientIP validates a client filter value.
func ClientIP(s string) bool { _, err := netip.ParseAddr(s); return err == nil || s == "" }

// ExcludeRegex joins exclude hosts into one mitmdump --ignore-hosts pattern.
func (c Config) ExcludeRegex() string {
	var parts []string
	for _, h := range c.ExcludeHosts {
		parts = append(parts, "(?:"+h+")")
	}
	return strings.Join(parts, "|")
}

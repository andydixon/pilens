package capture

import (
	"bytes"
	"context"
	hexpkg "encoding/hex"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"pilens.dev/pilens/internal/pcapfile"
	"pilens.dev/pilens/internal/store"
)

const fixture = "../../tests/fixtures/sample-loopback-http-dns.pcapng"

func newEngine(t *testing.T) *Engine {
	ts, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not installed (run `make test-docker`)")
	}
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	tools := &Tools{TShark: ts, Dumpcap: "dumpcap"}
	if err := tools.Init(dir); err != nil {
		t.Fatal(err)
	}
	e := &Engine{DB: db, Dir: filepath.Join(dir, "cap"), Tools: tools, Hub: NewHub(), Version: "test"}
	e.SetLimits(Limits{MaxBytes: 1 << 30, ReserveBytes: 0, SegmentBytes: 1 << 20, ImportBytes: 10 << 20})
	os.MkdirAll(e.Dir, 0o750)
	return e
}

func TestImportQueryExport(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	f, err := os.Open(fixture)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	s, err := e.Import(ctx, "fixture", f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100; i++ {
		s, _ = e.Get(s.ID)
		if s.State != "importing" {
			break
		}
		time.Sleep(100 * time.Millisecond)
	}
	if s.State != "ready" || s.Error != "" || s.Packets < 20 {
		t.Fatalf("import: %+v", s)
	}
	p, err := e.Packets(ctx, s.ID, "", 0, 1000)
	if err != nil || int64(len(p.Rows)) != s.Packets || p.Rows[0].Num != 1 {
		t.Fatalf("page: %v %+v", err, p)
	}
	fp, err := e.Packets(ctx, s.ID, "http.request", 0, 100)
	if err != nil || fp.Total != 2 || len(fp.Rows) != 2 || !strings.HasPrefix(fp.Rows[0].Info, "GET") {
		t.Fatalf("filter: %v %+v", err, fp)
	}
	if _, err := e.Packets(ctx, s.ID, "http.request ==", 0, 10); err == nil {
		t.Fatal("bad filter accepted")
	}
	if err := e.Tools.ValidateDisplayFilter(ctx, "tcp.port == 443 && dns"); err != nil {
		t.Fatal(err)
	}

	d, err := e.Packet(ctx, s.ID, fp.Rows[0].Num)
	if err != nil {
		t.Fatal(err)
	}
	var sawIP, sawHTTP bool
	var walk func([]Node)
	walk = func(ns []Node) {
		for _, n := range ns {
			if n.Field == "ip.src" && n.Verified && n.Size == 4 {
				sawIP = true
			}
			if n.Field == "http" {
				sawHTTP = true
			}
			walk(n.Children)
		}
	}
	walk(d.Tree)
	if !sawIP || !sawHTTP || len(d.Bytes) == 0 {
		t.Fatalf("detail tree incomplete: ip=%v http=%v", sawIP, sawHTTP)
	}

	var buf bytes.Buffer
	n, err := e.Export(ctx, &buf, s.ID, "udp")
	if err != nil || n != 4 {
		t.Fatalf("export: %d %v", n, err)
	}
	out := filepath.Join(t.TempDir(), "x.pcapng")
	os.WriteFile(out, buf.Bytes(), 0o600)
	count := 0
	if err := pcapfile.Scan(out, "pcapng", func(int, int64, []byte) error { count++; return nil }); err != nil || count != 4 {
		t.Fatalf("re-read export: %d %v", count, err)
	}
	if b, err := exec.Command(e.Tools.TShark, "-r", out).CombinedOutput(); err != nil {
		t.Fatalf("tshark rejects export: %s", b)
	}
	v, _ := e.Verify(s.ID)
	if len(v) != 1 || v[0].Status != "ok" {
		t.Fatalf("verify: %+v", v)
	}
}

func TestImportRejectsGarbage(t *testing.T) {
	e := newEngine(t)
	if _, err := e.Import(context.Background(), "x", strings.NewReader("PK\x03\x04 not a capture")); err == nil {
		t.Fatal("garbage accepted")
	}
}

func TestLiveCaptureRotation(t *testing.T) {
	e := newEngine(t)
	if os.Getenv("PILENS_LIVE_TEST") == "" {
		t.Skip("set PILENS_LIVE_TEST=1 where dumpcap may capture on lo")
	}
	ctx := context.Background()
	sub := e.Hub.Subscribe()
	defer e.Hub.Unsubscribe(sub)
	s, err := e.Start(ctx, StartOptions{Name: "live", Interfaces: []string{"lo"}, CaptureFilter: "udp port 9999"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.Start(ctx, StartOptions{Interfaces: []string{"lo"}}); err == nil {
		t.Fatal("second concurrent capture allowed")
	}
	time.Sleep(time.Second)
	c, err := net.Dial("udp", "127.0.0.1:9999")
	if err != nil {
		t.Fatal(err)
	}
	payload := bytes.Repeat([]byte("x"), 1000)
	for i := 0; i < 3000; i++ {
		c.Write(payload)
		if i%200 == 0 {
			time.Sleep(10 * time.Millisecond)
		}
	}
	c.Close()
	time.Sleep(2 * time.Second)
	if err := e.Stop(); err != nil {
		t.Fatal(err)
	}
	s, _ = e.Get(s.ID)
	if s.State != "stopped" || s.Packets < 1000 || !strings.Contains(s.Drops, fmt.Sprintf("%d/0", s.Packets)) {
		t.Fatalf("session: %+v", s)
	}
	segs, _ := e.Segments(s.ID)
	if len(segs) < 2 {
		t.Fatalf("expected rotation, got %d segments", len(segs))
	}
	var total int64
	for _, sg := range segs {
		if !sg.Complete || sg.SHA256 == "" {
			t.Fatalf("segment not finalised: %+v", sg)
		}
		total += sg.Count
		// every segment must be a standalone valid capture
		if b, err := exec.Command(e.Tools.TShark, "-r", filepath.Join(e.Dir, s.ID, sg.File), "-c", "1").CombinedOutput(); err != nil {
			t.Fatalf("segment %d unreadable: %s", sg.Seq, b)
		}
	}
	p, _ := e.Packets(ctx, s.ID, "", 0, 2000)
	if total != s.Packets || p.Total != s.Packets {
		t.Fatalf("counts disagree: segments %d session %d index %d", total, s.Packets, p.Total)
	}
	last, err := e.Packet(ctx, s.ID, s.Packets)
	if err != nil || len(last.Bytes) == 0 {
		t.Fatalf("last packet detail: %v", err)
	}
	if v, _ := e.Verify(s.ID); v[0].Status != "ok" {
		t.Fatalf("verify %+v", v)
	}
	got := 0
	for len(sub.C) > 0 {
		if ev := <-sub.C; ev.Type == "packets" {
			got++
		}
	}
	if got == 0 && sub.Dropped.Load() == 0 {
		t.Fatal("no live packet events")
	}
}

func TestAnalysisFromFixture(t *testing.T) {
	e := newEngine(t)
	ctx := context.Background()
	f, _ := os.Open(fixture)
	defer f.Close()
	s, err := e.Import(ctx, "fixture", f)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 100 && func() bool { x, _ := e.Get(s.ID); return x.State == "importing" }(); i++ {
		time.Sleep(50 * time.Millisecond)
	}
	conv, err := e.Conversations(ctx, s.ID, "tcp")
	if err != nil || len(conv) == 0 {
		t.Fatalf("tcp conversations: %v %d", err, len(conv))
	}
	c := conv[0]
	if c.Packets == 0 || c.Bytes == 0 || c.Stream == nil || (c.BytesAtoB+c.BytesBtoA) != c.Bytes {
		t.Fatalf("conversation sums wrong: %+v", c)
	}
	// Follow the first TCP stream and check both directions carry payload.
	fr, err := e.FollowTCP(ctx, s.ID, c.Seg, *c.Stream)
	if err != nil || fr.AtoB == 0 || fr.BtoA == 0 {
		t.Fatalf("follow: %v %+v", err, fr)
	}
	// The HTTP request bytes must appear in the client->server direction.
	var ab string
	for _, ch := range fr.Chunks {
		if ch.Dir == "ab" {
			ab += ch.Hex
		}
	}
	raw, _ := hexpkg.DecodeString(ab)
	if !strings.Contains(string(raw), "GET /") {
		t.Fatalf("stream payload missing HTTP request")
	}
	st, err := e.Statistics(ctx, s.ID, 50)
	if err != nil || st.Packets == 0 || len(st.Protocols) == 0 || len(st.Timeline) == 0 || st.TCPStreams == 0 {
		t.Fatalf("stats: %v %+v", err, st)
	}
	eps, _ := e.Endpoints(ctx, s.ID, 10)
	if len(eps) == 0 || eps[0].Bytes == 0 {
		t.Fatalf("endpoints: %+v", eps)
	}
	if _, err := e.DNS(ctx, s.ID, 100); err != nil { // fixture uses mDNS; real DNS checked on hardware
		t.Fatalf("dns: %v", err)
	}
	if _, _, err := e.TLS(ctx, s.ID, 100); err != nil {
		t.Fatalf("tls: %v", err)
	}
	// Findings must run without error; the fixture has a 404 and some resets.
	fs, err := e.Findings(ctx, s.ID, 1)
	if err != nil {
		t.Fatalf("findings: %v", err)
	}
	for _, f := range fs {
		if f.Count < 1 || f.Severity == "" || f.Title == "" {
			t.Fatalf("malformed finding: %+v", f)
		}
	}
}

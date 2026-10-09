// Package capture runs dumpcap, stores original packets as pcapng segments,
// indexes per-packet summaries in SQLite and serves on-demand dissection.
package capture

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"hash"
	"io"
	"log/slog"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"time"

	"pilens.dev/pilens/internal/auth"
	"pilens.dev/pilens/internal/config"
	"pilens.dev/pilens/internal/pcapfile"
	"pilens.dev/pilens/internal/store"
)

type Limits struct {
	MaxBytes     int64 `json:"max_bytes" yaml:"max_bytes"`         // total bytes of capture files
	ReserveBytes int64 `json:"reserve_bytes" yaml:"reserve_bytes"` // free space that must remain on the filesystem
	SegmentBytes int64 `json:"segment_bytes" yaml:"segment_bytes"` // rotate segment files at this size
	ImportBytes  int64 `json:"import_bytes" yaml:"import_bytes"`   // largest accepted upload
}

func DefaultLimits() Limits {
	return Limits{MaxBytes: 8 << 30, ReserveBytes: 1 << 30, SegmentBytes: 64 << 20, ImportBytes: 1 << 30}
}

type Engine struct {
	DB      *store.Store
	Dir     string // root of capture storage
	Tools   *Tools
	Hub     *Hub
	Version string

	limMu  sync.Mutex
	limits Limits

	mu   sync.Mutex
	live *live

	fcMu   sync.Mutex
	fcache map[string]*filterEntry
}

func (e *Engine) Limits() Limits     { e.limMu.Lock(); defer e.limMu.Unlock(); return e.limits }
func (e *Engine) SetLimits(l Limits) { e.limMu.Lock(); e.limits = l; e.limMu.Unlock() }

// Session is the API view of a capture session.
type Session struct {
	ID            string          `json:"id"`
	Name          string          `json:"name"`
	Description   string          `json:"description"`
	Kind          string          `json:"kind"`
	State         string          `json:"state"`
	Interfaces    []string        `json:"interfaces"`
	CaptureFilter string          `json:"capture_filter"`
	StartedAt     int64           `json:"started_at"`
	EndedAt       int64           `json:"ended_at"`
	Packets       int64           `json:"packets"`
	Bytes         int64           `json:"bytes"`
	Drops         string          `json:"drops"`
	Error         string          `json:"error"`
	Preserved     bool            `json:"preserved"`
	Tags          string          `json:"tags"`
	Notes         string          `json:"notes"`
	RingSegments  int             `json:"ring_segments"`
	Meta          json.RawMessage `json:"meta"`
	Paused        bool            `json:"paused"`
	Lag           int64           `json:"ingest_lag"` // packets written but not yet summarised
}

type Segment struct {
	Seq      int    `json:"seq"`
	File     string `json:"file"`
	Format   string `json:"format"`
	Base     int64  `json:"base"`
	Count    int64  `json:"count"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	Complete bool   `json:"complete"`
	Deleted  bool   `json:"deleted"`
}

func newID() string {
	return time.Now().UTC().Format("20060102T150405Z") + "-" + auth.RandomToken(3)
}

const sessCols = `id,name,description,kind,state,interfaces,capture_filter,started_at,ended_at,packets,bytes,drops,error,preserved,tags,notes,ring_segments,meta`

func scanSession(sc interface{ Scan(...any) error }) (Session, error) {
	var s Session
	var ifs, meta string
	err := sc.Scan(&s.ID, &s.Name, &s.Description, &s.Kind, &s.State, &ifs, &s.CaptureFilter, &s.StartedAt, &s.EndedAt, &s.Packets, &s.Bytes, &s.Drops, &s.Error, &s.Preserved, &s.Tags, &s.Notes, &s.RingSegments, &meta)
	json.Unmarshal([]byte(ifs), &s.Interfaces)
	s.Meta = json.RawMessage(meta)
	return s, err
}

func (e *Engine) withLive(s Session) Session {
	e.mu.Lock()
	l := e.live
	e.mu.Unlock()
	if l != nil && l.id == s.ID {
		s.Packets = l.packets.Load()
		s.Bytes = l.bytes.Load()
		s.Paused = l.paused.Load()
		s.Lag = s.Packets - l.summarised.Load()
	}
	return s
}

func (e *Engine) Sessions() ([]Session, error) {
	rows, err := e.DB.Query(`SELECT ` + sessCols + ` FROM capture_sessions ORDER BY started_at DESC`)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Session{}
	for rows.Next() {
		s, err := scanSession(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, e.withLive(s))
	}
	return out, rows.Err()
}

func (e *Engine) Get(id string) (Session, error) {
	s, err := scanSession(e.DB.QueryRow(`SELECT `+sessCols+` FROM capture_sessions WHERE id=?`, id))
	if err == sql.ErrNoRows {
		return s, ErrNotFound
	}
	return e.withLive(s), err
}

var ErrNotFound = errors.New("not found")

func (e *Engine) Segments(id string) ([]Segment, error) {
	rows, err := e.DB.Query(`SELECT seq,file,format,base,count,bytes,sha256,complete,deleted FROM segments WHERE session_id=? ORDER BY seq`, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []Segment
	for rows.Next() {
		var s Segment
		if err := rows.Scan(&s.Seq, &s.File, &s.Format, &s.Base, &s.Count, &s.Bytes, &s.SHA256, &s.Complete, &s.Deleted); err != nil {
			return nil, err
		}
		out = append(out, s)
	}
	return out, rows.Err()
}

func (e *Engine) sessionDir(id string) string { return filepath.Join(e.Dir, id) }

// Update edits analyst metadata.
func (e *Engine) Update(id, name, desc, tags, notes string, preserved bool) error {
	r, err := e.DB.Exec(`UPDATE capture_sessions SET name=?,description=?,tags=?,notes=?,preserved=? WHERE id=?`, name, desc, tags, notes, preserved, id)
	if err != nil {
		return err
	}
	if n, _ := r.RowsAffected(); n == 0 {
		return ErrNotFound
	}
	return nil
}

func (e *Engine) Delete(id string) error {
	e.mu.Lock()
	running := e.live != nil && e.live.id == id
	e.mu.Unlock()
	if running {
		return errors.New("stop the capture before deleting it")
	}
	if _, err := e.Get(id); err != nil {
		return err
	}
	if err := os.RemoveAll(e.sessionDir(id)); err != nil {
		return err
	}
	e.DB.Exec(`DELETE FROM packets WHERE session_id=?`, id)
	_, err := e.DB.Exec(`DELETE FROM capture_sessions WHERE id=?`, id)
	e.dropFilterCache(id)
	return err
}

// ---------------------------------------------------------------- live capture

type StartOptions struct {
	Name          string   `json:"name"`
	Interfaces    []string `json:"interfaces"`
	CaptureFilter string   `json:"capture_filter"`
	RingSegments  int      `json:"ring_segments"`
}

type live struct {
	id         string
	cmd        *exec.Cmd
	done       chan struct{}
	stopping   atomic.Bool
	paused     atomic.Bool
	discarded  atomic.Int64 // packets discarded while paused
	packets    atomic.Int64
	bytes      atomic.Int64
	summarised atomic.Int64
	stderr     limitedBuffer

	mu  sync.Mutex // guards seg
	seg *segWriter
	wg  sync.WaitGroup // summarisers
}

type segWriter struct {
	seq   int
	base  int64
	path  string
	f     *os.File
	bw    *bufio.Writer
	h     hash.Hash
	size  int64
	count int64
	offs  []int64

	feed     chan []byte
	feedLost bool
}

type limitedBuffer struct {
	mu sync.Mutex
	b  bytes.Buffer
}

func (l *limitedBuffer) Write(p []byte) (int, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.b.Len() < 64<<10 {
		l.b.Write(p)
	}
	return len(p), nil
}

func (l *limitedBuffer) String() string { l.mu.Lock(); defer l.mu.Unlock(); return l.b.String() }

func clockSynced() string {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "timedatectl", "show", "-p", "NTPSynchronized", "--value").Output()
	if err != nil {
		return "unknown"
	}
	return strings.TrimSpace(string(out))
}

func (e *Engine) meta(extra map[string]any) string {
	host, _ := os.Hostname()
	m := map[string]any{
		"pilens_version":     e.Version,
		"tshark_version":     e.Tools.Version(),
		"clock_synchronised": clockSynced(),
		"hostname":           host,
		"recorded_utc":       time.Now().UTC().Format(time.RFC3339Nano),
	}
	for k, v := range extra {
		m[k] = v
	}
	b, _ := json.Marshal(m)
	return string(b)
}

func (e *Engine) Live() (Session, bool) {
	e.mu.Lock()
	l := e.live
	e.mu.Unlock()
	if l == nil {
		return Session{}, false
	}
	s, err := e.Get(l.id)
	return s, err == nil
}

func (e *Engine) Start(ctx context.Context, o StartOptions) (Session, error) {
	if len(o.Interfaces) == 0 || len(o.Interfaces) > 8 {
		return Session{}, errors.New("choose 1-8 interfaces")
	}
	for _, i := range o.Interfaces {
		if i == "any" {
			continue
		}
		if !config.ValidInterface(i) {
			return Session{}, fmt.Errorf("invalid interface %q", i)
		}
		if _, err := net.InterfaceByName(i); err != nil {
			return Session{}, fmt.Errorf("interface %q not found", i)
		}
	}
	if o.CaptureFilter != "" {
		if err := e.Tools.ValidateCaptureFilter(ctx, o.Interfaces[0], o.CaptureFilter); err != nil {
			return Session{}, fmt.Errorf("capture filter: %v", err)
		}
	}
	if o.RingSegments < 0 || o.RingSegments > 100000 {
		return Session{}, errors.New("invalid ring size")
	}
	if strings.TrimSpace(o.Name) == "" {
		o.Name = "Capture " + time.Now().Format("2006-01-02 15:04")
	}
	if len(o.Name) > 200 {
		return Session{}, errors.New("name too long")
	}

	e.mu.Lock()
	defer e.mu.Unlock()
	if e.live != nil {
		return Session{}, errors.New("a capture is already running")
	}
	if err := e.enforceStorage(""); err != nil {
		return Session{}, err
	}
	id := newID()
	dir := e.sessionDir(id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Session{}, err
	}
	ifs, _ := json.Marshal(o.Interfaces)
	lim := e.Limits()
	meta := e.meta(map[string]any{"segment_bytes": lim.SegmentBytes, "snaplen": "dumpcap default (full)"})
	_, err := e.DB.Exec(`INSERT INTO capture_sessions(id,name,kind,state,interfaces,capture_filter,started_at,dir,meta,ring_segments) VALUES(?,?,?,?,?,?,?,?,?,?)`,
		id, o.Name, "live", "running", string(ifs), o.CaptureFilter, time.Now().UnixMilli(), dir, meta, o.RingSegments)
	if err != nil {
		return Session{}, err
	}

	args := []string{"-q", "-F", "pcapng", "-w", "-"}
	for _, i := range o.Interfaces {
		args = append(args, "-i", i)
		if o.CaptureFilter != "" {
			args = append(args, "-f", o.CaptureFilter) // applies to the preceding -i
		}
	}
	cmd := exec.Command(e.Tools.Dumpcap, args...)
	l := &live{id: id, cmd: cmd, done: make(chan struct{})}
	cmd.Stderr = &l.stderr
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return Session{}, err
	}
	if err := cmd.Start(); err != nil {
		e.finishSession(id, "failed", "dumpcap failed to start: "+err.Error(), "")
		return Session{}, err
	}
	e.live = l
	go e.runLive(l, stdout)
	slog.Info("capture started", "session", id, "interfaces", o.Interfaces)
	s, err := scanSession(e.DB.QueryRow(`SELECT `+sessCols+` FROM capture_sessions WHERE id=?`, id))
	return s, err // e.mu is held: must not call e.Get (withLive locks it)
}

func (e *Engine) SetPaused(p bool) error {
	e.mu.Lock()
	l := e.live
	e.mu.Unlock()
	if l == nil {
		return errors.New("no capture running")
	}
	if l.paused.Swap(p) != p {
		ev := "resumed"
		if p {
			ev = "paused"
		}
		e.DB.Exec(`UPDATE capture_sessions SET meta=json_insert(meta,'$.pause_log[#]',json_object('event',?,'utc',?)) WHERE id=?`, ev, time.Now().UTC().Format(time.RFC3339Nano), l.id)
	}
	return nil
}

func (e *Engine) Stop() error {
	e.mu.Lock()
	l := e.live
	e.mu.Unlock()
	if l == nil {
		return errors.New("no capture running")
	}
	l.stopping.Store(true)
	l.cmd.Process.Signal(syscall.SIGINT) // dumpcap flushes and reports statistics
	select {
	case <-l.done:
	case <-time.After(30 * time.Second):
		l.cmd.Process.Kill()
		<-l.done
	}
	return nil
}

func (e *Engine) runLive(l *live, stdout io.Reader) {
	defer close(l.done)
	rowsC := make(chan []Row, 64)
	insDone := make(chan struct{})
	go func() { e.inserter(l, rowsC); close(insDone) }()

	// Periodic flush so on-demand reads of the active segment see recent packets,
	// and status events for the UI.
	stopTick := make(chan struct{})
	go func() {
		t := time.NewTicker(time.Second)
		defer t.Stop()
		for {
			select {
			case <-stopTick:
				return
			case <-t.C:
				l.mu.Lock()
				if l.seg != nil {
					l.seg.bw.Flush()
				}
				l.mu.Unlock()
				e.publishStatus(l)
			}
		}
	}()

	var failure string
	br := pcapfile.NewBlockReader(bufio.NewReaderSize(stdout, 1<<20))
	var hdrs [][]byte
	for {
		b, err := br.Next()
		if err != nil {
			if err != io.EOF && !l.stopping.Load() {
				failure = "capture stream error: " + err.Error()
			}
			break
		}
		switch b.Type {
		case pcapfile.BlockSHB:
			hdrs = [][]byte{b.Raw}
		case pcapfile.BlockIDB:
			hdrs = append(hdrs, b.Raw)
		}
		if b.IsPacket() && l.paused.Load() {
			l.discarded.Add(1)
			continue
		}
		if err := e.writeBlock(l, b, hdrs, rowsC); err != nil {
			failure = err.Error()
			l.stopping.Store(true)
			l.cmd.Process.Signal(syscall.SIGINT)
			io.Copy(io.Discard, stdout)
			break
		}
	}
	waitErr := l.cmd.Wait()
	l.mu.Lock()
	e.closeSegment(l, rowsC)
	l.mu.Unlock()
	l.wg.Wait()
	close(rowsC)
	<-insDone
	close(stopTick)

	state := "stopped"
	if failure == "" && !l.stopping.Load() {
		failure = "dumpcap exited unexpectedly"
		if waitErr != nil {
			failure += ": " + waitErr.Error()
		}
		failure += ": " + strings.TrimSpace(l.stderr.String())
	}
	if failure != "" {
		state = "failed"
	}
	e.DB.Exec(`UPDATE capture_sessions SET packets=?,bytes=?,meta=json_set(meta,'$.discarded_while_paused',?) WHERE id=?`, l.packets.Load(), l.bytes.Load(), l.discarded.Load(), l.id)
	e.finishSession(l.id, state, failure, dropLines(l.stderr.String()))
	e.mu.Lock()
	e.live = nil
	e.mu.Unlock()
	e.publishStatus(l)
	slog.Info("capture finished", "session", l.id, "state", state, "packets", l.packets.Load(), "error", failure)
}

// dropLines keeps dumpcap's per-interface "Packets received/dropped" report verbatim.
func dropLines(s string) string {
	var out []string
	for _, l := range strings.Split(s, "\n") {
		if strings.Contains(l, "received/dropped") {
			out = append(out, strings.TrimSpace(l))
		}
	}
	return strings.Join(out, "\n")
}

func (e *Engine) finishSession(id, state, errMsg, drops string) {
	e.DB.Exec(`UPDATE capture_sessions SET state=?,error=?,drops=?,ended_at=? WHERE id=?`, state, errMsg, drops, time.Now().UnixMilli(), id)
	e.dropFilterCache(id)
}

// writeBlock is called only from the splitter goroutine.
func (e *Engine) writeBlock(l *live, b pcapfile.Block, hdrs [][]byte, rowsC chan []Row) error {
	l.mu.Lock()
	defer l.mu.Unlock()
	lim := e.Limits()
	if b.IsPacket() && l.seg != nil && l.seg.size >= lim.SegmentBytes {
		e.closeSegment(l, rowsC)
		if err := e.enforceStorage(l.id); err != nil {
			return err
		}
	}
	if l.seg == nil {
		if !b.IsPacket() {
			return nil // headers are written when the first packet opens a segment
		}
		if err := e.openSegment(l, hdrs, rowsC); err != nil {
			return err
		}
	}
	s := l.seg
	if b.IsPacket() {
		s.offs = append(s.offs, s.size)
		s.count++
		l.packets.Add(1)
		if d, err := pcapfile.PacketData(b); err == nil {
			l.bytes.Add(int64(len(d)))
		}
	}
	if _, err := s.bw.Write(b.Raw); err != nil {
		return fmt.Errorf("writing capture file: %w", err)
	}
	s.size += int64(len(b.Raw))
	s.sendFeed(b.Raw)
	return nil
}

func (s *segWriter) sendFeed(raw []byte) {
	if s.feedLost {
		return
	}
	select {
	case s.feed <- raw:
	default:
		// tshark cannot keep up. Never block capture: stop live summaries for this
		// segment; they are regenerated from the file when the segment closes.
		s.feedLost = true
		close(s.feed)
	}
}

func (e *Engine) openSegment(l *live, hdrs [][]byte, rowsC chan []Row) error {
	var seq int
	var base int64
	e.DB.QueryRow(`SELECT COALESCE(MAX(seq),0)+1 FROM segments WHERE session_id=?`, l.id).Scan(&seq)
	base = l.packets.Load() + 1
	name := fmt.Sprintf("seg-%06d.pcapng", seq)
	path := filepath.Join(e.sessionDir(l.id), name)
	f, err := os.OpenFile(path, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		return err
	}
	h := sha256.New()
	s := &segWriter{seq: seq, base: base, path: path, f: f, h: h, bw: bufio.NewWriterSize(io.MultiWriter(f, h), 1<<20), feed: make(chan []byte, 2048)}
	if _, err := e.DB.Exec(`INSERT INTO segments(session_id,seq,file,format,base) VALUES(?,?,?,?,?)`, l.id, seq, name, "pcapng", base); err != nil {
		f.Close()
		return err
	}
	for _, hb := range hdrs {
		s.bw.Write(hb)
		s.size += int64(len(hb))
		s.sendFeed(hb)
	}
	l.seg = s
	l.wg.Add(1)
	go e.summarise(l, s, rowsC)
	return nil
}

// closeSegment finalises the current segment. Caller holds l.mu.
func (e *Engine) closeSegment(l *live, rowsC chan []Row) {
	s := l.seg
	if s == nil {
		return
	}
	l.seg = nil
	s.bw.Flush()
	s.f.Sync()
	s.f.Close()
	if !s.feedLost {
		close(s.feed)
	}
	sum := hex.EncodeToString(s.h.Sum(nil))
	e.DB.Exec(`UPDATE segments SET count=?,bytes=?,sha256=?,complete=1 WHERE session_id=? AND seq=?`, s.count, s.size, sum, l.id, s.seq)
	e.DB.Exec(`UPDATE capture_sessions SET packets=?,bytes=? WHERE id=?`, l.packets.Load(), l.bytes.Load(), l.id)
	e.applyRing(l.id)
}

// summarise runs one tshark per segment fed from the splitter, then backfills
// from the completed file if the live feed was cut short.
func (e *Engine) summarise(l *live, s *segWriter, rowsC chan []Row) {
	defer l.wg.Done()
	offAt := func(local int64) int64 {
		l.mu.Lock()
		defer l.mu.Unlock()
		if local < 1 || local > int64(len(s.offs)) {
			return -1
		}
		return s.offs[local-1]
	}
	var got int64
	emit := func(batch *[]Row, r Row) {
		r.Off = offAt(r.Num)
		if r.Off < 0 {
			return
		}
		r.Num = s.base + r.Num - 1
		r.Seg = s.seq
		got++
		*batch = append(*batch, r)
		if len(*batch) >= 500 {
			rowsC <- *batch
			*batch = nil
		}
	}

	ctx := context.Background()
	cmd := e.Tools.Command(ctx, 0, e.Tools.SummaryArgs("-")...)
	stdin, _ := cmd.StdinPipe()
	stdout, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		slog.Error("tshark start", "err", err)
		for range s.feed {
		}
	} else {
		go func() {
			for b := range s.feed {
				if _, err := stdin.Write(b); err != nil {
					break
				}
			}
			stdin.Close()
			for range s.feed { // drain if tshark died
			}
		}()
		var batch []Row
		lines := make(chan Row, 1024)
		go func() { ReadSummaries(stdout, func(r Row) { lines <- r }); close(lines) }()
		tick := time.NewTicker(300 * time.Millisecond)
	loop:
		for {
			select {
			case r, ok := <-lines:
				if !ok {
					break loop
				}
				emit(&batch, r)
			case <-tick.C:
				if len(batch) > 0 {
					rowsC <- batch
					batch = nil
				}
			}
		}
		tick.Stop()
		if len(batch) > 0 {
			rowsC <- batch
		}
		cmd.Wait()
	}

	// Backfill from the finished file if live summaries are incomplete.
	l.mu.Lock()
	closed := l.seg != s
	count := s.count
	l.mu.Unlock()
	if closed && got < count {
		slog.Info("backfilling summaries", "session", l.id, "segment", s.seq, "have", got, "want", count)
		cmd := e.Tools.Command(ctx, 3600, e.Tools.SummaryArgs(s.path)...)
		out, _ := cmd.StdoutPipe()
		if cmd.Start() == nil {
			var batch []Row
			ReadSummaries(out, func(r Row) { emit(&batch, r) })
			if len(batch) > 0 {
				rowsC <- batch
			}
			cmd.Wait()
		}
		e.Hub.Publish(Event{Type: "resync", Data: []byte(`{"session":"` + l.id + `"}`)})
	}
}

func insertRows(tx *sql.Tx, session string, rows []Row) error {
	st, err := tx.Prepare(`INSERT OR IGNORE INTO packets(session_id,num,seg,off,ts,src,dst,proto,len,info,sport,dport,stream,tcpflags,ttl,vlan,color) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)`)
	if err != nil {
		return err
	}
	defer st.Close()
	for _, r := range rows {
		if _, err := st.Exec(session, r.Num, r.Seg, r.Off, r.TS, r.Src, r.Dst, r.Proto, r.Len, r.Info, r.SPort, r.DPort, r.Stream, r.TCPFlags, r.TTL, r.VLAN, r.Color); err != nil {
			return err
		}
	}
	return nil
}

func (e *Engine) inserter(l *live, rowsC chan []Row) {
	for batch := range rowsC {
		tx, err := e.DB.Begin()
		if err != nil {
			slog.Error("index insert", "err", err)
			continue
		}
		if err := insertRows(tx, l.id, batch); err != nil {
			tx.Rollback()
			slog.Error("index insert", "err", err)
			continue
		}
		tx.Commit()
		l.summarised.Add(int64(len(batch)))
		data, _ := json.Marshal(map[string]any{"session": l.id, "rows": batch})
		e.Hub.Publish(Event{Type: "packets", Data: data})
	}
}

func (e *Engine) publishStatus(l *live) {
	s, err := e.Get(l.id)
	if err != nil {
		return
	}
	data, _ := json.Marshal(s)
	e.Hub.Publish(Event{Type: "capture", Data: data})
}

// ---------------------------------------------------------------- storage

func (e *Engine) usedBytes() int64 {
	var n int64
	e.DB.QueryRow(`SELECT COALESCE(SUM(bytes),0) FROM segments WHERE deleted=0`).Scan(&n)
	return n
}

func freeBytes(dir string) int64 {
	var st syscall.Statfs_t
	if syscall.Statfs(dir, &st) != nil {
		return 0
	}
	return int64(st.Bavail) * int64(st.Bsize)
}

type StorageInfo struct {
	Used       int64  `json:"used"`
	Free       int64  `json:"free"`
	Limits     Limits `json:"limits"`
	Dir        string `json:"dir"`
	LowWarning bool   `json:"low_warning"`
}

func (e *Engine) Storage() StorageInfo {
	lim := e.Limits()
	i := StorageInfo{Used: e.usedBytes(), Free: freeBytes(e.Dir), Limits: lim, Dir: e.Dir}
	i.LowWarning = i.Free < 2*lim.ReserveBytes || i.Used > lim.MaxBytes*9/10
	return i
}

// enforceStorage deletes the oldest unpreserved, finished sessions until within
// limits. If that is not possible it returns an error and nothing is overwritten.
func (e *Engine) enforceStorage(activeID string) error {
	lim := e.Limits()
	for {
		used, free := e.usedBytes(), freeBytes(e.Dir)
		if used+lim.SegmentBytes <= lim.MaxBytes && free-lim.SegmentBytes >= lim.ReserveBytes {
			return nil
		}
		var victim string
		e.DB.QueryRow(`SELECT id FROM capture_sessions WHERE preserved=0 AND id!=? AND state NOT IN ('running','importing') ORDER BY started_at LIMIT 1`, activeID).Scan(&victim)
		if victim == "" {
			return fmt.Errorf("storage limit reached (used %d of %d bytes, %d free, reserve %d) and no unpreserved sessions remain to delete", used, lim.MaxBytes, free, lim.ReserveBytes)
		}
		slog.Warn("storage limit: deleting oldest unpreserved session", "session", victim)
		e.DB.Audit("system", "capture.retention_delete", victim, "")
		if err := os.RemoveAll(e.sessionDir(victim)); err != nil {
			return err
		}
		e.DB.Exec(`DELETE FROM packets WHERE session_id=?`, victim)
		e.DB.Exec(`DELETE FROM capture_sessions WHERE id=?`, victim)
		e.dropFilterCache(victim)
	}
}

func (e *Engine) applyRing(id string) {
	var ring int
	var preserved bool
	e.DB.QueryRow(`SELECT ring_segments,preserved FROM capture_sessions WHERE id=?`, id).Scan(&ring, &preserved)
	if ring <= 0 || preserved {
		return
	}
	segs, _ := e.Segments(id)
	var live []Segment
	for _, s := range segs {
		if s.Complete && !s.Deleted {
			live = append(live, s)
		}
	}
	for len(live) > ring {
		s := live[0]
		live = live[1:]
		os.Remove(filepath.Join(e.sessionDir(id), s.File))
		e.DB.Exec(`UPDATE segments SET deleted=1 WHERE session_id=? AND seq=?`, id, s.Seq)
		e.DB.Exec(`DELETE FROM packets WHERE session_id=? AND num>=? AND num<?`, id, s.Base, s.Base+s.Count)
	}
	e.dropFilterCache(id)
}

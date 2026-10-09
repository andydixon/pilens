package capture

import (
	"bufio"
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"pilens.dev/pilens/internal/pcapfile"
)

const rowCols = `num,seg,off,ts,src,dst,proto,len,info,sport,dport,stream,tcpflags,ttl,vlan,color`

func scanRows(rows *sql.Rows) ([]Row, error) {
	defer rows.Close()
	out := []Row{}
	for rows.Next() {
		var r Row
		var flags, color sql.NullString
		if err := rows.Scan(&r.Num, &r.Seg, &r.Off, &r.TS, &r.Src, &r.Dst, &r.Proto, &r.Len, &r.Info, &r.SPort, &r.DPort, &r.Stream, &flags, &r.TTL, &r.VLAN, &color); err != nil {
			return nil, err
		}
		r.TCPFlags, r.Color = flags.String, color.String
		out = append(out, r)
	}
	return out, rows.Err()
}

// Page is a window of packet rows. Position i in the (filtered) list is
// Offset+i; rows may be missing where summaries are still being generated.
type Page struct {
	Total    int64   `json:"total"`
	First    int64   `json:"first"` // packet number at position 0 (unfiltered views)
	Offset   int64   `json:"offset"`
	Rows     []Row   `json:"rows"`
	Nums     []int64 `json:"nums,omitempty"` // packet numbers for each position (filtered views)
	Filtered bool    `json:"filtered"`
	Partial  bool    `json:"partial"` // filter results cover only part of the capture
}

func (e *Engine) Packets(ctx context.Context, id, filter string, offset, limit int64) (Page, error) {
	if limit <= 0 || limit > 2000 {
		limit = 500
	}
	if offset < 0 {
		offset = 0
	}
	p := Page{Offset: offset}
	if strings.TrimSpace(filter) == "" {
		var first, last sql.NullInt64
		e.DB.QueryRow(`SELECT MIN(num),MAX(num) FROM packets WHERE session_id=?`, id).Scan(&first, &last)
		if !first.Valid {
			return p, nil
		}
		p.First = first.Int64
		p.Total = last.Int64 - first.Int64 + 1
		from := first.Int64 + offset
		rows, err := e.DB.QueryContext(ctx, `SELECT `+rowCols+` FROM packets WHERE session_id=? AND num>=? AND num<? ORDER BY num`, id, from, from+limit)
		if err != nil {
			return p, err
		}
		p.Rows, err = scanRows(rows)
		return p, err
	}
	nums, err := e.filterNums(ctx, id, filter)
	if err != nil {
		return p, err
	}
	p.Filtered = true
	p.Total = int64(len(nums))
	if offset >= p.Total {
		return p, nil
	}
	end := min(offset+limit, p.Total)
	p.Nums = nums[offset:end]
	if len(p.Nums) == 0 {
		return p, nil
	}
	rows, err := e.DB.QueryContext(ctx, `SELECT `+rowCols+` FROM packets WHERE session_id=? AND num>=? AND num<=? ORDER BY num`, id, p.Nums[0], p.Nums[len(p.Nums)-1])
	if err != nil {
		return p, err
	}
	all, err := scanRows(rows)
	if err != nil {
		return p, err
	}
	want := map[int64]bool{}
	for _, n := range p.Nums {
		want[n] = true
	}
	for _, r := range all {
		if want[r.Num] {
			p.Rows = append(p.Rows, r)
		}
	}
	return p, nil
}

// ---------------------------------------------------------------- display filter cache

type filterEntry struct {
	perSeg map[int]segResult
	used   time.Time
}

type segResult struct {
	count int64 // segment packet count when evaluated
	nums  []int64
}

func (e *Engine) dropFilterCache(id string) {
	e.fcMu.Lock()
	defer e.fcMu.Unlock()
	for k := range e.fcache {
		if strings.HasPrefix(k, id+"\x00") {
			delete(e.fcache, k)
		}
	}
}

// filterNums evaluates a display filter with tshark segment by segment. Complete
// segments are cached; the segment being written is re-evaluated when it grows.
func (e *Engine) filterNums(ctx context.Context, id, filter string) ([]int64, error) {
	if err := sanityFilter(filter); err != nil {
		return nil, err
	}
	segs, err := e.Segments(id)
	if err != nil {
		return nil, err
	}
	key := id + "\x00" + filter
	e.fcMu.Lock()
	if e.fcache == nil {
		e.fcache = map[string]*filterEntry{}
	}
	ent := e.fcache[key]
	if ent == nil {
		if len(e.fcache) >= 16 { // ponytail: evict oldest of a tiny cache
			var oldK string
			var oldT time.Time
			for k, v := range e.fcache {
				if oldK == "" || v.used.Before(oldT) {
					oldK, oldT = k, v.used
				}
			}
			delete(e.fcache, oldK)
		}
		ent = &filterEntry{perSeg: map[int]segResult{}}
		e.fcache[key] = ent
	}
	ent.used = time.Now()
	e.fcMu.Unlock()

	var out []int64
	for _, s := range segs {
		if s.Deleted {
			continue
		}
		count := s.Count
		if !s.Complete {
			count = -1 // live: always re-evaluate
			e.flushLive(id)
		}
		e.fcMu.Lock()
		r, ok := ent.perSeg[s.Seq]
		e.fcMu.Unlock()
		if !ok || r.count != count || count == -1 {
			local, err := e.Tools.MatchFrames(ctx, filepath.Join(e.sessionDir(id), s.File), filter)
			if err != nil {
				return nil, err
			}
			r = segResult{count: count}
			for _, n := range local {
				r.nums = append(r.nums, s.Base+n-1)
			}
			e.fcMu.Lock()
			ent.perSeg[s.Seq] = r
			e.fcMu.Unlock()
		}
		out = append(out, r.nums...)
	}
	return out, nil
}

func (e *Engine) flushLive(id string) {
	e.mu.Lock()
	l := e.live
	e.mu.Unlock()
	if l != nil && l.id == id {
		l.mu.Lock()
		if l.seg != nil {
			l.seg.bw.Flush()
		}
		l.mu.Unlock()
	}
}

// ---------------------------------------------------------------- packet detail

type Detail struct {
	Row     Row    `json:"row"`
	Bytes   string `json:"bytes"` // hex of the original captured bytes
	Tree    []Node `json:"tree"`
	Segment int    `json:"segment"`
	Note    string `json:"note,omitempty"`
}

func (e *Engine) segmentFor(id string, seq int) (Segment, error) {
	segs, err := e.Segments(id)
	if err != nil {
		return Segment{}, err
	}
	for _, s := range segs {
		if s.Seq == seq && !s.Deleted {
			return s, nil
		}
	}
	return Segment{}, errors.New("segment no longer stored (ring buffer or retention)")
}

func (e *Engine) Packet(ctx context.Context, id string, num int64) (Detail, error) {
	rows, err := e.DB.QueryContext(ctx, `SELECT `+rowCols+` FROM packets WHERE session_id=? AND num=?`, id, num)
	if err != nil {
		return Detail{}, err
	}
	rs, err := scanRows(rows)
	if err != nil {
		return Detail{}, err
	}
	if len(rs) == 0 {
		return Detail{}, ErrNotFound
	}
	d := Detail{Row: rs[0], Segment: rs[0].Seg}
	seg, err := e.segmentFor(id, d.Row.Seg)
	if err != nil {
		return d, err
	}
	path := filepath.Join(e.sessionDir(id), seg.File)
	e.flushLive(id)
	data, err := pcapfile.ReadPacketAt(path, seg.Format, d.Row.Off)
	if err != nil {
		return d, fmt.Errorf("reading packet bytes: %w", err)
	}
	d.Bytes = hex.EncodeToString(data)
	pdml, err := e.Tools.PDML(ctx, path, num-seg.Base+1)
	if err != nil {
		return d, fmt.Errorf("dissection failed: %w", err)
	}
	d.Tree, err = ParsePDML(pdml, data)
	if err != nil {
		return d, fmt.Errorf("dissection output: %w", err)
	}
	if seg.Seq > 1 || !seg.Complete {
		d.Note = "Dissected within segment " + fmt.Sprint(seg.Seq) + ": TCP stream numbers and reassembly restart at segment boundaries."
	}
	return d, nil
}

// ---------------------------------------------------------------- export

// ExportFormat reports the container format an export of id will use.
func (e *Engine) ExportFormat(id string) string {
	segs, _ := e.Segments(id)
	for _, s := range segs {
		if s.Format == "pcap" {
			return "pcap"
		}
	}
	return "pcapng"
}

// Export writes original packet records (all, or those matching filter) to w.
// Packet data is copied byte-for-byte from the stored segments.
func (e *Engine) Export(ctx context.Context, w io.Writer, id, filter string) (int, error) {
	segs, err := e.Segments(id)
	if err != nil {
		return 0, err
	}
	var keep map[int64]bool
	if strings.TrimSpace(filter) != "" {
		nums, err := e.filterNums(ctx, id, filter)
		if err != nil {
			return 0, err
		}
		keep = make(map[int64]bool, len(nums))
		for _, n := range nums {
			keep[n] = true
		}
	}
	e.flushLive(id)
	bw := bufio.NewWriterSize(w, 1<<20)
	total, first := 0, true
	for _, s := range segs {
		if s.Deleted {
			continue
		}
		base := s.Base
		n, err := pcapfile.CopySelected(bw, filepath.Join(e.sessionDir(id), s.File), s.Format, first, func(idx int) bool {
			return keep == nil || keep[base+int64(idx)]
		})
		total += n
		first = false
		if err != nil && !s.Complete && errors.Is(err, io.ErrUnexpectedEOF) {
			continue // live segment: the last block is still being written
		}
		if err != nil {
			bw.Flush()
			return total, err
		}
	}
	return total, bw.Flush()
}

// ---------------------------------------------------------------- integrity

type Manifest struct {
	Session   Session   `json:"session"`
	Segments  []Segment `json:"segments"`
	Generated string    `json:"generated_utc"`
	Note      string    `json:"note"`
}

func (e *Engine) Manifest(id string) (Manifest, error) {
	s, err := e.Get(id)
	if err != nil {
		return Manifest{}, err
	}
	segs, err := e.Segments(id)
	return Manifest{Session: s, Segments: segs, Generated: time.Now().UTC().Format(time.RFC3339Nano),
		Note: "Segment files are original capture data written verbatim from dumpcap output (live) or the uploaded file (import). SHA-256 covers each complete file. Summary rows and dissections are derived data and are not part of the evidence."}, err
}

type VerifyResult struct {
	Seq    int    `json:"seq"`
	File   string `json:"file"`
	Status string `json:"status"` // ok | mismatch | missing | incomplete | deleted
	Actual string `json:"actual,omitempty"`
}

func (e *Engine) Verify(id string) ([]VerifyResult, error) {
	segs, err := e.Segments(id)
	if err != nil {
		return nil, err
	}
	var out []VerifyResult
	for _, s := range segs {
		r := VerifyResult{Seq: s.Seq, File: s.File}
		switch {
		case s.Deleted:
			r.Status = "deleted"
		case !s.Complete:
			r.Status = "incomplete"
		default:
			f, err := os.Open(filepath.Join(e.sessionDir(id), s.File))
			if err != nil {
				r.Status = "missing"
				break
			}
			h := sha256.New()
			io.Copy(h, f)
			f.Close()
			r.Actual = hex.EncodeToString(h.Sum(nil))
			r.Status = "ok"
			if r.Actual != s.SHA256 {
				r.Status = "mismatch"
			}
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Seq < out[j].Seq })
	return out, nil
}

// ---------------------------------------------------------------- import

// Import stores an uploaded capture unchanged and indexes it in the background.
// The upload is hostile input: size-limited, magic-checked, and parsed only by
// bounds-checked code and resource-limited tshark.
func (e *Engine) Import(ctx context.Context, name string, r io.Reader) (Session, error) {
	lim := e.Limits()
	name = strings.TrimSpace(name)
	if name == "" || len(name) > 200 {
		name = "Import " + time.Now().Format("2006-01-02 15:04")
	}
	if err := e.enforceStorage(""); err != nil {
		return Session{}, err
	}
	id := newID()
	dir := e.sessionDir(id)
	if err := os.MkdirAll(dir, 0o750); err != nil {
		return Session{}, err
	}
	br := bufio.NewReader(io.LimitReader(r, lim.ImportBytes+1))
	head, _ := br.Peek(4)
	format, err := pcapfile.Sniff(head)
	if err != nil {
		os.RemoveAll(dir)
		return Session{}, errors.New("file is not pcap or pcapng (compressed captures are not accepted)")
	}
	file := "original." + format
	f, err := os.OpenFile(filepath.Join(dir, file), os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o640)
	if err != nil {
		os.RemoveAll(dir)
		return Session{}, err
	}
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), br)
	f.Sync()
	f.Close()
	if err != nil || n > lim.ImportBytes {
		os.RemoveAll(dir)
		if err == nil {
			err = fmt.Errorf("file exceeds import limit of %d bytes", lim.ImportBytes)
		}
		return Session{}, err
	}
	sum := hex.EncodeToString(h.Sum(nil))
	meta := e.meta(map[string]any{"import_sha256": sum, "import_bytes": n})
	tx, err := e.DB.Begin()
	if err != nil {
		return Session{}, err
	}
	tx.Exec(`INSERT INTO capture_sessions(id,name,kind,state,started_at,dir,meta,bytes) VALUES(?,?,?,?,?,?,?,?)`, id, name, "import", "importing", time.Now().UnixMilli(), dir, meta, n)
	tx.Exec(`INSERT INTO segments(session_id,seq,file,format,base,bytes,sha256,complete) VALUES(?,?,?,?,?,?,?,1)`, id, 1, file, format, 1, n, sum)
	if err := tx.Commit(); err != nil {
		return Session{}, err
	}
	go e.indexImport(id, filepath.Join(dir, file), format)
	return e.Get(id)
}

func (e *Engine) indexImport(id, path, format string) {
	fail := func(err error) { e.finishSession(id, "failed", err.Error(), "") }
	var offs []int64
	if err := pcapfile.Scan(path, format, func(idx int, off int64, _ []byte) error {
		if len(offs) >= 50_000_000 {
			return errors.New("too many packets")
		}
		offs = append(offs, off)
		return nil
	}); err != nil {
		fail(fmt.Errorf("malformed capture after packet %d: %v", len(offs), err))
		return
	}
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Hour)
	defer cancel()
	cmd := e.Tools.Command(ctx, 3600, e.Tools.SummaryArgs(path)...)
	out, err := cmd.StdoutPipe()
	var stderr limitedBuffer
	cmd.Stderr = &stderr
	if err == nil {
		err = cmd.Start()
	}
	if err != nil {
		fail(err)
		return
	}
	var batch []Row
	var count int64
	flush := func() {
		tx, err := e.DB.Begin()
		if err == nil {
			insertRows(tx, id, batch)
			tx.Commit()
		}
		batch = batch[:0]
	}
	ReadSummaries(out, func(r Row) {
		if r.Num < 1 || r.Num > int64(len(offs)) {
			return
		}
		r.Off, r.Seg = offs[r.Num-1], 1
		batch = append(batch, r)
		count++
		if len(batch) >= 2000 {
			flush()
		}
	})
	flush()
	werr := cmd.Wait()
	e.DB.Exec(`UPDATE segments SET count=? WHERE session_id=? AND seq=1`, len(offs), id)
	e.DB.Exec(`UPDATE capture_sessions SET packets=? WHERE id=?`, len(offs), id)
	msg := ""
	if werr != nil {
		msg = "tshark: " + strings.TrimSpace(stderr.String())
	}
	if count < int64(len(offs)) {
		msg = strings.TrimSpace(fmt.Sprintf("%s; summarised %d of %d packets", msg, count, len(offs)))
	}
	e.finishSession(id, "ready", msg, "")
	data, _ := json.Marshal(map[string]string{"session": id})
	e.Hub.Publish(Event{Type: "resync", Data: data})
}

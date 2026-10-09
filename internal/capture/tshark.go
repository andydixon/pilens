package capture

import (
	"bufio"
	"bytes"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"time"
)

// Tools locates and runs Wireshark command-line tools. All tshark children run
// through `pilens rlimit-exec` so hostile input cannot exhaust the appliance.
type Tools struct {
	Self    string // path to the pilens binary (for rlimit-exec)
	TShark  string
	Dumpcap string
	MemMB   int // RLIMIT_AS for tshark children

	cols    []string // summary -e fields, version dependent
	emptyNG string   // path to an empty pcapng used for filter validation
}

// summaryFields; the column fields are filled in by Init (names changed in Wireshark 4.2).
var summaryTail = []string{
	"frame.len", "tcp.srcport", "udp.srcport", "tcp.dstport", "udp.dstport",
	"tcp.stream", "tcp.flags.str", "ip.ttl", "ipv6.hlim", "vlan.id", "frame.coloring_rule.name",
}

// EmptyPcapng is a valid pcapng with one Ethernet interface and no packets.
func EmptyPcapng() []byte {
	var b bytes.Buffer
	le := binary.LittleEndian
	w32 := func(v uint32) { binary.Write(&b, le, v) }
	// SHB
	w32(0x0A0D0D0A)
	w32(28)
	w32(0x1A2B3C4D)
	binary.Write(&b, le, uint16(1))
	binary.Write(&b, le, uint16(0))
	binary.Write(&b, le, int64(-1))
	w32(28)
	// IDB: linktype 1 (Ethernet), snaplen 262144
	w32(1)
	w32(20)
	binary.Write(&b, le, uint16(1))
	binary.Write(&b, le, uint16(0))
	w32(262144)
	w32(20)
	return b.Bytes()
}

func (t *Tools) Init(stateDir string) error {
	if t.MemMB == 0 {
		t.MemMB = 1536
	}
	p := stateDir + "/empty.pcapng"
	if err := os.WriteFile(p, EmptyPcapng(), 0o640); err != nil {
		return err
	}
	t.emptyNG = p
	newCols := []string{"_ws.col.def_src", "_ws.col.def_dst", "_ws.col.protocol", "_ws.col.info"}
	oldCols := []string{"_ws.col.Source", "_ws.col.Destination", "_ws.col.Protocol", "_ws.col.Info"}
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	if _, err := t.run(ctx, "-n", "-r", p, "-T", "fields", "-e", newCols[3]); err == nil {
		t.cols = newCols
	} else if _, err2 := t.run(ctx, "-n", "-r", p, "-T", "fields", "-e", oldCols[3]); err2 == nil {
		t.cols = oldCols
	} else {
		return fmt.Errorf("tshark unusable: %v", err)
	}
	return nil
}

// Command builds a resource-limited tshark command. cpuSec 0 = no CPU limit.
func (t *Tools) Command(ctx context.Context, cpuSec int, args ...string) *exec.Cmd {
	var cmd *exec.Cmd
	if t.Self == "" { // tests only
		cmd = exec.CommandContext(ctx, t.TShark, args...)
	} else {
		a := append([]string{"rlimit-exec", strconv.Itoa(t.MemMB), strconv.Itoa(cpuSec), "--", t.TShark}, args...)
		cmd = exec.CommandContext(ctx, t.Self, a...)
	}
	cmd.Env = []string{"PATH=/usr/bin:/bin", "HOME=/nonexistent", "LANG=C.UTF-8"}
	cmd.WaitDelay = 5 * time.Second
	return cmd
}

func (t *Tools) run(ctx context.Context, args ...string) ([]byte, error) {
	cmd := t.Command(ctx, 300, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		msg := strings.TrimSpace(stderr.String())
		if msg == "" {
			msg = err.Error()
		}
		return out, errors.New(msg)
	}
	return out, nil
}

// SummaryArgs returns tshark arguments that print one tab-separated summary row per packet.
func (t *Tools) SummaryArgs(input string) []string {
	a := []string{"-n", "-l", "--color", "-r", input, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=f", "-E", "quote=n",
		"-e", "frame.number", "-e", "frame.time_epoch", "-e", t.cols[0], "-e", t.cols[1], "-e", t.cols[2]}
	for _, f := range summaryTail {
		a = append(a, "-e", f)
	}
	return append(a, "-e", t.cols[3]) // info last: it may contain anything
}

// Row is one packet summary.
type Row struct {
	Num      int64   `json:"n"`
	TS       float64 `json:"t"`
	Src      string  `json:"s"`
	Dst      string  `json:"d"`
	Proto    string  `json:"p"`
	Len      int     `json:"l"`
	Info     string  `json:"i"`
	SPort    *int    `json:"sp,omitempty"`
	DPort    *int    `json:"dp,omitempty"`
	Stream   *int    `json:"st,omitempty"`
	TCPFlags string  `json:"tf,omitempty"`
	TTL      *int    `json:"ttl,omitempty"`
	VLAN     *int    `json:"vl,omitempty"`
	Color    string  `json:"c,omitempty"`
	Seg      int     `json:"-"`
	Off      int64   `json:"-"`
}

func atoiPtr(s string) *int {
	if s == "" {
		return nil
	}
	v, err := strconv.Atoi(s)
	if err != nil {
		return nil
	}
	return &v
}

func firstNonEmpty(a, b string) string {
	if a != "" {
		return a
	}
	return b
}

// ParseSummaryLine parses one line of SummaryArgs output. Frame numbers are local to the input.
func ParseSummaryLine(line string) (Row, error) {
	f := strings.SplitN(line, "\t", 17)
	if len(f) != 17 {
		return Row{}, fmt.Errorf("unexpected tshark summary line (%d fields)", len(f))
	}
	var r Row
	var err error
	if r.Num, err = strconv.ParseInt(f[0], 10, 64); err != nil {
		return r, err
	}
	r.TS, _ = strconv.ParseFloat(f[1], 64)
	r.Src, r.Dst, r.Proto = f[2], f[3], f[4]
	r.Len, _ = strconv.Atoi(f[5])
	r.SPort = atoiPtr(firstNonEmpty(f[6], f[7]))
	r.DPort = atoiPtr(firstNonEmpty(f[8], f[9]))
	r.Stream = atoiPtr(f[10])
	r.TCPFlags = f[11]
	r.TTL = atoiPtr(firstNonEmpty(f[12], f[13]))
	r.VLAN = atoiPtr(f[14])
	r.Color = f[15]
	r.Info = strings.TrimSpace(f[16])
	return r, nil
}

// ReadSummaries parses tshark summary output, calling fn per row.
func ReadSummaries(r io.Reader, fn func(Row)) error {
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 64*1024), 4<<20)
	for sc.Scan() {
		row, err := ParseSummaryLine(sc.Text())
		if err != nil {
			continue // ponytail: skip malformed lines rather than abort a capture; count if it ever matters
		}
		fn(row)
	}
	return sc.Err()
}

// ValidateDisplayFilter asks tshark to compile the filter against an empty file.
func (t *Tools) ValidateDisplayFilter(ctx context.Context, f string) error {
	if err := sanityFilter(f); err != nil {
		return err
	}
	_, err := t.run(ctx, "-n", "-r", t.emptyNG, "-Y", f)
	return err
}

// ValidateCaptureFilter asks dumpcap to compile a BPF filter for iface.
func (t *Tools) ValidateCaptureFilter(ctx context.Context, iface, f string) error {
	if err := sanityFilter(f); err != nil {
		return err
	}
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, t.Dumpcap, "-d", "-i", iface, "-f", f).CombinedOutput()
	if err != nil {
		return errors.New(strings.TrimSpace(string(out)))
	}
	return nil
}

func sanityFilter(f string) error {
	if len(f) > 2048 {
		return errors.New("filter too long")
	}
	for _, r := range f {
		if r < 0x20 && r != '\t' {
			return errors.New("filter contains control characters")
		}
	}
	return nil
}

// MatchFrames returns the local frame numbers in file that match a display filter.
// Truncated trailing data (a segment still being written) is tolerated.
func (t *Tools) MatchFrames(ctx context.Context, file, filter string) ([]int64, error) {
	cmd := t.Command(ctx, 600, "-n", "-r", file, "-Y", filter, "-T", "fields", "-e", "frame.number")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && !strings.Contains(stderr.String(), "cut short") {
		return nil, errors.New(strings.TrimSpace(stderr.String() + " " + err.Error()))
	}
	var nums []int64
	for _, l := range strings.Split(string(out), "\n") {
		if n, err := strconv.ParseInt(strings.TrimSpace(l), 10, 64); err == nil {
			nums = append(nums, n)
		}
	}
	return nums, nil
}

// PDML returns the PDML dissection for one local frame of file.
func (t *Tools) PDML(ctx context.Context, file string, local int64) ([]byte, error) {
	cmd := t.Command(ctx, 120, "-n", "-r", file, "-Y", "frame.number=="+strconv.FormatInt(local, 10), "-T", "pdml")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil && !strings.Contains(stderr.String(), "cut short") {
		return nil, errors.New(strings.TrimSpace(stderr.String() + " " + err.Error()))
	}
	return out, nil
}

func (t *Tools) Version() string {
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, t.TShark, "--version").Output()
	if err != nil {
		return "unknown"
	}
	l, _, _ := strings.Cut(string(out), "\n")
	return l
}

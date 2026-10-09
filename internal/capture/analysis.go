package capture

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// This file derives higher-level views (conversations, streams, DNS, TLS,
// statistics) from data already captured. Conversations and statistics come
// from the SQLite summary index, so they work across segments. Stream payloads
// and DNS/TLS field detail come from tshark over the relevant segment files.

// ---------------------------------------------------------------- conversations

type Conversation struct {
	Transport string  `json:"transport"` // tcp | udp
	AAddr     string  `json:"a_addr"`
	APort     int     `json:"a_port"`
	BAddr     string  `json:"b_addr"`
	BPort     int     `json:"b_port"`
	Packets   int64   `json:"packets"`
	Bytes     int64   `json:"bytes"`
	BytesAtoB int64   `json:"bytes_a_to_b"`
	BytesBtoA int64   `json:"bytes_b_to_a"`
	Start     float64 `json:"start"`
	End       float64 `json:"end"`
	Protos    string  `json:"protocols"`
	Seg       int     `json:"seg"`    // segment of the first packet (for Follow)
	Stream    *int    `json:"stream"` // tcp.stream within that segment
	FirstNum  int64   `json:"first_num"`
}

// Conversations aggregates TCP or UDP conversations from the summary index.
// Endpoints are ordered canonically (A is the lexicographically smaller
// address, or the lower port when addresses match) so each conversation
// appears once regardless of who initiated it.
func (e *Engine) Conversations(ctx context.Context, id, transport string) ([]Conversation, error) {
	var where string
	switch transport {
	case "tcp":
		where = "stream IS NOT NULL"
	case "udp":
		where = "stream IS NULL AND sport IS NOT NULL"
	default:
		return nil, errors.New("transport must be tcp or udp")
	}
	// fwd = row is already in canonical (A->B) orientation.
	const fwd = "(src<dst OR (src=dst AND sport<=dport))"
	q := `
SELECT
  CASE WHEN ` + fwd + ` THEN src ELSE dst END AS a_addr,
  CASE WHEN ` + fwd + ` THEN sport ELSE dport END AS a_port,
  CASE WHEN ` + fwd + ` THEN dst ELSE src END AS b_addr,
  CASE WHEN ` + fwd + ` THEN dport ELSE sport END AS b_port,
  COUNT(*), SUM(len),
  SUM(CASE WHEN ` + fwd + ` THEN len ELSE 0 END),
  SUM(CASE WHEN ` + fwd + ` THEN 0 ELSE len END),
  MIN(ts), MAX(ts),
  GROUP_CONCAT(DISTINCT proto),
  MIN(num)
FROM packets
WHERE session_id=? AND ` + where + ` AND sport IS NOT NULL AND dport IS NOT NULL
GROUP BY a_addr, a_port, b_addr, b_port
ORDER BY SUM(len) DESC
LIMIT 5000`
	rows, err := e.DB.QueryContext(ctx, q, id)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Conversation{}
	for rows.Next() {
		c := Conversation{Transport: transport}
		var protos string
		if err := rows.Scan(&c.AAddr, &c.APort, &c.BAddr, &c.BPort, &c.Packets, &c.Bytes, &c.BytesAtoB, &c.BytesBtoA, &c.Start, &c.End, &protos, &c.FirstNum); err != nil {
			return nil, err
		}
		c.Protos = tidyProtos(protos)
		out = append(out, c)
	}
	if err := rows.Err(); err != nil {
		return nil, err
	}
	// Attach segment + stream of the first packet so the UI can Follow directly.
	for i := range out {
		var seg int
		var stream *int
		e.DB.QueryRowContext(ctx, `SELECT seg, stream FROM packets WHERE session_id=? AND num=?`, id, out[i].FirstNum).Scan(&seg, &stream)
		out[i].Seg, out[i].Stream = seg, stream
	}
	return out, nil
}

func tidyProtos(csv string) string {
	seen := map[string]bool{}
	var keep []string
	for _, p := range strings.Split(csv, ",") {
		base := p
		// collapse TLSv1.2/TLSv1.3 -> TLS, etc.
		for _, pre := range []string{"TLSv", "SSLv"} {
			if strings.HasPrefix(p, pre) {
				base = "TLS"
			}
		}
		if base != "" && !seen[base] {
			seen[base] = true
			keep = append(keep, base)
		}
	}
	sort.Strings(keep)
	return strings.Join(keep, ",")
}

// ---------------------------------------------------------------- top talkers

type Endpoint struct {
	Addr    string  `json:"addr"`
	Packets int64   `json:"packets"`
	Bytes   int64   `json:"bytes"`
	TxBytes int64   `json:"tx_bytes"`
	RxBytes int64   `json:"rx_bytes"`
	Start   float64 `json:"start"`
	End     float64 `json:"end"`
}

func (e *Engine) Endpoints(ctx context.Context, id string, limit int) ([]Endpoint, error) {
	if limit <= 0 || limit > 1000 {
		limit = 100
	}
	// Union of per-direction aggregates keyed by address.
	q := `
SELECT addr, SUM(pk), SUM(by), SUM(tx), SUM(rx), MIN(st), MAX(en) FROM (
  SELECT src AS addr, COUNT(*) pk, SUM(len) by, SUM(len) tx, 0 rx, MIN(ts) st, MAX(ts) en FROM packets WHERE session_id=? GROUP BY src
  UNION ALL
  SELECT dst AS addr, COUNT(*) pk, SUM(len) by, 0 tx, SUM(len) rx, MIN(ts) st, MAX(ts) en FROM packets WHERE session_id=? GROUP BY dst
) GROUP BY addr ORDER BY SUM(by) DESC LIMIT ?`
	rows, err := e.DB.QueryContext(ctx, q, id, id, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	out := []Endpoint{}
	for rows.Next() {
		var p Endpoint
		if err := rows.Scan(&p.Addr, &p.Packets, &p.Bytes, &p.TxBytes, &p.RxBytes, &p.Start, &p.End); err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ---------------------------------------------------------------- statistics

type Stats struct {
	Packets     int64            `json:"packets"`
	Bytes       int64            `json:"bytes"`
	Start       float64          `json:"start"`
	End         float64          `json:"end"`
	Protocols   []NameCount      `json:"protocols"`
	SizeBuckets []NameCount      `json:"size_buckets"`
	Timeline    []TimeBucket     `json:"timeline"`
	TCPStreams  int64            `json:"tcp_streams"`
	Counters    map[string]int64 `json:"counters"`
}

type NameCount struct {
	Name    string `json:"name"`
	Packets int64  `json:"packets"`
	Bytes   int64  `json:"bytes"`
}

type TimeBucket struct {
	T       float64 `json:"t"`
	Packets int64   `json:"packets"`
	Bytes   int64   `json:"bytes"`
}

func (e *Engine) Statistics(ctx context.Context, id string, buckets int) (Stats, error) {
	if buckets <= 0 || buckets > 2000 {
		buckets = 300
	}
	var s Stats
	s.Counters = map[string]int64{}
	err := e.DB.QueryRowContext(ctx, `SELECT COUNT(*), COALESCE(SUM(len),0), COALESCE(MIN(ts),0), COALESCE(MAX(ts),0) FROM packets WHERE session_id=?`, id).
		Scan(&s.Packets, &s.Bytes, &s.Start, &s.End)
	if err != nil || s.Packets == 0 {
		return s, err
	}
	e.DB.QueryRowContext(ctx, `SELECT COUNT(DISTINCT seg||'/'||stream) FROM packets WHERE session_id=? AND stream IS NOT NULL`, id).Scan(&s.TCPStreams)

	rows, _ := e.DB.QueryContext(ctx, `SELECT proto, COUNT(*), SUM(len) FROM packets WHERE session_id=? GROUP BY proto ORDER BY 2 DESC LIMIT 40`, id)
	for rows.Next() {
		var n NameCount
		rows.Scan(&n.Name, &n.Packets, &n.Bytes)
		s.Protocols = append(s.Protocols, n)
	}
	rows.Close()

	// Packet-size distribution (Wireshark's standard buckets).
	sizeCase := `CASE
	 WHEN len<=63 THEN '0-63' WHEN len<=127 THEN '64-127' WHEN len<=255 THEN '128-255'
	 WHEN len<=511 THEN '256-511' WHEN len<=1023 THEN '512-1023' WHEN len<=1513 THEN '1024-1513'
	 ELSE '1514+' END`
	rows, _ = e.DB.QueryContext(ctx, `SELECT `+sizeCase+` b, COUNT(*), SUM(len) FROM packets WHERE session_id=? GROUP BY b`, id)
	order := map[string]int{"0-63": 0, "64-127": 1, "128-255": 2, "256-511": 3, "512-1023": 4, "1024-1513": 5, "1514+": 6}
	for rows.Next() {
		var n NameCount
		rows.Scan(&n.Name, &n.Packets, &n.Bytes)
		s.SizeBuckets = append(s.SizeBuckets, n)
	}
	rows.Close()
	sort.Slice(s.SizeBuckets, func(i, j int) bool { return order[s.SizeBuckets[i].Name] < order[s.SizeBuckets[j].Name] })

	// Timeline: fixed number of equal time buckets.
	span := s.End - s.Start
	if span <= 0 {
		span = 1
	}
	width := span / float64(buckets)
	rows, _ = e.DB.QueryContext(ctx, `SELECT CAST((ts-?)/? AS INTEGER) b, COUNT(*), SUM(len) FROM packets WHERE session_id=? GROUP BY b ORDER BY b`, s.Start, width, id)
	for rows.Next() {
		var b int
		var n TimeBucket
		rows.Scan(&b, &n.Packets, &n.Bytes)
		if b >= buckets {
			b = buckets - 1
		}
		n.T = s.Start + (float64(b)+0.5)*width
		s.Timeline = append(s.Timeline, n)
	}
	rows.Close()
	s.Counters["bucket_seconds"] = int64(width)
	return s, nil
}

// ---------------------------------------------------------------- follow TCP stream

type StreamChunk struct {
	Dir   string `json:"dir"` // "ab" client→server, "ba" server→client
	Hex   string `json:"hex"`
	Bytes int    `json:"bytes"`
}

type FollowResult struct {
	Seg      int           `json:"seg"`
	Stream   int           `json:"stream"`
	Chunks   []StreamChunk `json:"chunks"`
	AtoB     int           `json:"a_to_b"`
	BtoA     int           `json:"b_to_a"`
	Note     string        `json:"note,omitempty"`
	Endpoint string        `json:"endpoint,omitempty"`
}

// FollowTCP reconstructs one TCP stream's payload using tshark's own reassembly
// (`-z follow,tcp,raw`). Stream numbers are per-segment, so seg selects the file.
func (e *Engine) FollowTCP(ctx context.Context, id string, seg, stream int) (FollowResult, error) {
	s, err := e.segmentFor(id, seg)
	if err != nil {
		return FollowResult{}, err
	}
	e.flushLive(id)
	path := filepath.Join(e.sessionDir(id), s.File)
	cmd := e.Tools.Command(ctx, 300, "-n", "-q", "-r", path, "-z", "follow,tcp,raw,"+strconv.Itoa(stream))
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil && !strings.Contains(errb.String(), "cut short") {
		return FollowResult{}, errors.New(strings.TrimSpace(errb.String() + " " + err.Error()))
	}
	r := parseFollow(string(out))
	r.Seg, r.Stream = seg, stream
	if seg > 1 || !s.Complete {
		r.Note = "Reconstructed within segment " + strconv.Itoa(seg) + "; a stream spanning segment boundaries is shown only in part."
	}
	return r, nil
}

// parseFollow parses `-z follow,tcp,raw` output. Lines of hex are payload;
// server→client lines are indented with a tab.
func parseFollow(s string) FollowResult {
	var r FollowResult
	for _, line := range strings.Split(s, "\n") {
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, "=") || strings.HasPrefix(line, "Follow:") || strings.HasPrefix(line, "Filter:") || strings.HasPrefix(line, "Node ") {
			if strings.HasPrefix(line, "Node ") {
				if r.Endpoint != "" {
					r.Endpoint += " ↔ "
				}
				r.Endpoint += strings.TrimSpace(strings.TrimPrefix(line, "Node"))[2:]
			}
			continue
		}
		dir := "ab"
		h := line
		if strings.HasPrefix(line, "\t") {
			dir = "ba"
			h = strings.TrimPrefix(line, "\t")
		}
		h = strings.TrimSpace(h)
		if _, err := hex.DecodeString(h); err != nil || h == "" {
			continue
		}
		n := len(h) / 2
		if dir == "ab" {
			r.AtoB += n
		} else {
			r.BtoA += n
		}
		// merge consecutive same-direction chunks for a cleaner view
		if len(r.Chunks) > 0 && r.Chunks[len(r.Chunks)-1].Dir == dir {
			last := &r.Chunks[len(r.Chunks)-1]
			last.Hex += h
			last.Bytes += n
		} else {
			r.Chunks = append(r.Chunks, StreamChunk{Dir: dir, Hex: h, Bytes: n})
		}
	}
	return r
}

// ---------------------------------------------------------------- field extraction (DNS, TLS)

// extractFields runs tshark over every live segment with a display filter and a
// set of fields, returning rows of field values keyed with the global packet
// number. Used by the DNS and TLS explorers. Results are not cached (these are
// opened on demand and the captures are bounded); callers may paginate in the UI.
func (e *Engine) extractFields(ctx context.Context, id, filter string, fields []string, limit int) ([][]string, error) {
	segs, err := e.Segments(id)
	if err != nil {
		return nil, err
	}
	e.flushLive(id)
	args := []string{"-n", "-r", "", "-Y", filter, "-T", "fields", "-E", "separator=/t", "-E", "occurrence=a", "-E", "aggregator=,", "-E", "quote=n", "-e", "frame.number", "-e", "frame.time_epoch"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	var out [][]string
	for _, s := range segs {
		if s.Deleted {
			continue
		}
		a := append([]string{}, args...)
		a[2] = filepath.Join(e.sessionDir(id), s.File)
		cmd := e.Tools.Command(ctx, 600, a...)
		var errb bytes.Buffer
		cmd.Stderr = &errb
		data, err := cmd.Output()
		if err != nil && !strings.Contains(errb.String(), "cut short") {
			return nil, fmt.Errorf("%s: %s", s.File, strings.TrimSpace(errb.String()))
		}
		for _, line := range strings.Split(string(data), "\n") {
			if line == "" {
				continue
			}
			cells := strings.Split(line, "\t")
			// global packet number = segment base + local - 1
			if local, err := strconv.ParseInt(cells[0], 10, 64); err == nil {
				cells[0] = strconv.FormatInt(s.Base+local-1, 10)
			}
			cells[0] = cells[0] + "\x00" + strconv.Itoa(s.Seq) // keep seg for linking
			out = append(out, cells)
			if len(out) >= limit {
				return out, nil
			}
		}
	}
	return out, nil
}

// ---------------------------------------------------------------- DNS explorer

type DNSRecord struct {
	Num      int64   `json:"num"`
	Seg      int     `json:"seg"`
	Time     float64 `json:"time"`
	Client   string  `json:"client"`
	Server   string  `json:"server"`
	Query    string  `json:"query"`
	Type     string  `json:"type"`
	Response bool    `json:"response"`
	RCode    string  `json:"rcode"`
	Answers  string  `json:"answers"`
}

func splitNumSeg(s string) (int64, int) {
	id, seg, _ := strings.Cut(s, "\x00")
	n, _ := strconv.ParseInt(id, 10, 64)
	sq, _ := strconv.Atoi(seg)
	return n, sq
}

var dnsTypes = map[string]string{"1": "A", "28": "AAAA", "5": "CNAME", "15": "MX", "16": "TXT", "33": "SRV", "12": "PTR", "65": "HTTPS", "64": "SVCB", "2": "NS", "6": "SOA", "255": "ANY", "257": "CAA", "35": "NAPTR", "43": "DS", "48": "DNSKEY"}
var dnsRcodes = map[string]string{"0": "NOERROR", "1": "FORMERR", "2": "SERVFAIL", "3": "NXDOMAIN", "4": "NOTIMP", "5": "REFUSED"}

func (e *Engine) DNS(ctx context.Context, id string, limit int) ([]DNSRecord, error) {
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	fields := []string{"ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "dns.flags.response", "dns.qry.name", "dns.qry.type", "dns.flags.rcode", "dns.a", "dns.aaaa", "dns.cname", "dns.resp.name", "dns.ptr.domain_name"}
	rowsF, err := e.extractFields(ctx, id, "dns && !mdns", fields, limit)
	if err != nil {
		return nil, err
	}
	out := []DNSRecord{}
	for _, c := range rowsF {
		if len(c) < 2+len(fields) {
			continue
		}
		r := DNSRecord{}
		r.Num, r.Seg = splitNumSeg(c[0])
		r.Time, _ = strconv.ParseFloat(c[1], 64)
		r.Client = firstNonEmpty(c[2], c[3])
		r.Server = firstNonEmpty(c[4], c[5])
		r.Response = c[6] == "1"
		r.Query = c[7]
		if t, ok := dnsTypes[c[8]]; ok {
			r.Type = t
		} else {
			r.Type = c[8]
		}
		if rc, ok := dnsRcodes[c[9]]; ok {
			r.RCode = rc
		} else if c[9] != "" {
			r.RCode = "rcode " + c[9]
		}
		// For a query the "client" is src and "server" is dst; for a response swap for readability.
		if r.Response {
			r.Client, r.Server = r.Server, r.Client
			r.Answers = strings.Trim(strings.Join([]string{c[10], c[11], c[12], c[16]}, " "), " ")
		}
		out = append(out, r)
	}
	return out, nil
}

// ---------------------------------------------------------------- TLS explorer (metadata only)

type TLSRecord struct {
	Num        int64   `json:"num"`
	Seg        int     `json:"seg"`
	Time       float64 `json:"time"`
	Client     string  `json:"client"`
	Server     string  `json:"server"`
	ServerPort int     `json:"server_port"`
	SNI        string  `json:"sni"`
	Version    string  `json:"version"`
	Cipher     string  `json:"cipher"`
	ALPN       string  `json:"alpn"`
	Stream     *int    `json:"stream"`
}

type CertRecord struct {
	Num       int64   `json:"num"`
	Seg       int     `json:"seg"`
	Time      float64 `json:"time"`
	Server    string  `json:"server"`
	Subject   string  `json:"subject"`
	Issuer    string  `json:"issuer"`
	SANs      string  `json:"sans"`
	NotBefore string  `json:"not_before"`
	NotAfter  string  `json:"not_after"`
}

var tlsVersions = map[string]string{"0x0300": "SSL 3.0", "0x0301": "TLS 1.0", "0x0302": "TLS 1.1", "0x0303": "TLS 1.2", "0x0304": "TLS 1.3"}

// TLS returns observed TLS handshakes: ClientHello (SNI/ALPN) joined with the
// server's chosen version and cipher. This is metadata only; no payload is
// decrypted. The interception status is always "encrypted pass-through" in this
// version, which the UI states plainly.
func (e *Engine) TLS(ctx context.Context, id string, limit int) ([]TLSRecord, []CertRecord, error) {
	if limit <= 0 || limit > 20000 {
		limit = 5000
	}
	// ClientHello: SNI, ALPN, offered; ServerHello: negotiated version + cipher.
	// The true negotiated version for TLS 1.3 is in the supported_versions
	// extension of the ServerHello; the record/handshake version stays 0x0303
	// for middlebox compatibility, so reading only those would mislabel 1.3 as 1.2.
	chFields := []string{"ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.dstport", "udp.dstport", "tcp.srcport", "tcp.stream", "tls.handshake.type", "tls.handshake.extensions_server_name", "tls.handshake.version", "tls.record.version", "tls.handshake.ciphersuite", "tls.handshake.extensions_alpn_str", "tls.handshake.extensions.supported_version"}
	// c offsets: 0=num,1=time, then 2+index into chFields.
	const (
		cType = 10
		cSNI  = 11
		cHV   = 12
		cRV   = 13
		cCS   = 14
		cALPN = 15
		cSV   = 16
	)
	rowsF, err := e.extractFields(ctx, id, "tls.handshake.type==1 || tls.handshake.type==2", chFields, limit)
	if err != nil {
		return nil, nil, err
	}
	need := 2 + len(chFields)
	// Index ServerHello (type 2) by stream to join onto the ClientHello.
	type sh struct{ version, cipher string }
	byStream := map[string]sh{}
	for _, c := range rowsF {
		if len(c) < need || c[cType] != "2" {
			continue
		}
		// supported_version in a ServerHello may be a list; take the last (chosen).
		sv := c[cSV]
		if i := strings.LastIndex(sv, ","); i >= 0 {
			sv = sv[i+1:]
		}
		byStream[c[9]] = sh{version: firstNonEmpty(sv, firstNonEmpty(c[cHV], c[cRV])), cipher: c[cCS]}
	}
	recs := []TLSRecord{}
	for _, c := range rowsF {
		if len(c) < need || c[cType] != "1" {
			continue
		}
		r := TLSRecord{}
		r.Num, r.Seg = splitNumSeg(c[0])
		r.Time, _ = strconv.ParseFloat(c[1], 64)
		r.Client = firstNonEmpty(c[2], c[3])
		r.Server = firstNonEmpty(c[4], c[5])
		r.ServerPort, _ = strconv.Atoi(firstNonEmpty(c[6], c[7])) // tcp or udp (QUIC)
		r.SNI = c[cSNI]
		r.ALPN = c[cALPN]
		if st := c[9]; st != "" {
			if v, err := strconv.Atoi(st); err == nil {
				r.Stream = &v
			}
			if s, ok := byStream[st]; ok {
				r.Version = tlsVersion(s.version)
				r.Cipher = cipherName(s.cipher)
			}
		}
		if r.Version == "" {
			if c[7] != "" { // over UDP: QUIC, which mandates TLS 1.3
				r.Version = "TLS 1.3 (QUIC)"
			} else {
				// No ServerHello captured: report what the client offered, not a guess.
				r.Version = tlsVersion(firstNonEmpty(c[cHV], c[cRV])) + " (offered)"
			}
		}
		recs = append(recs, r)
	}

	// Certificates (visible in TLS 1.2 and earlier; encrypted in TLS 1.3).
	certFields := []string{"ip.src", "ipv6.src", "x509if.printableString", "x509sat.uTF8String", "x509ce.dNSName", "x509af.notBefore", "x509af.notAfter"}
	certRows, err := e.extractFields(ctx, id, "tls.handshake.type==11", certFields, limit)
	if err != nil {
		return recs, nil, nil // handshake records are still useful
	}
	certs := []CertRecord{}
	for _, c := range certRows {
		if len(c) < 2+len(certFields) {
			continue
		}
		cr := CertRecord{}
		cr.Num, cr.Seg = splitNumSeg(c[0])
		cr.Time, _ = strconv.ParseFloat(c[1], 64)
		cr.Server = firstNonEmpty(c[2], c[3])
		subs := strings.Split(firstNonEmpty(c[4], c[5]), ",")
		if len(subs) > 0 {
			cr.Subject = subs[0]
		}
		cr.SANs = c[6]
		cr.NotBefore, cr.NotAfter = c[7], c[8]
		certs = append(certs, cr)
	}
	return recs, certs, nil
}

func tlsVersion(code string) string {
	if v, ok := tlsVersions[strings.ToLower(code)]; ok {
		return v
	}
	return code
}

// cipherName renders a cipher-suite code. tshark prints the IANA code number;
// we keep the hex for precision rather than ship a full lookup table.
func cipherName(code string) string {
	if code == "" {
		return ""
	}
	if n, err := strconv.Atoi(code); err == nil {
		return fmt.Sprintf("0x%04x", n)
	}
	return code
}

// ---------------------------------------------------------------- findings (diagnostics)

// Finding is one observed, evidence-backed diagnostic. These are facts about the
// capture (a retransmission happened, a SERVFAIL was returned), never a claim of
// malicious intent; the Note spells out benign explanations.
type Finding struct {
	Rule     string  `json:"rule"`
	Title    string  `json:"title"`
	Severity string  `json:"severity"` // info | low | medium
	Count    int64   `json:"count"`
	Flows    int     `json:"flows"`
	Examples []int64 `json:"examples"` // packet numbers
	Filter   string  `json:"filter"`   // display filter reproducing the evidence
	Note     string  `json:"note"`
}

type findingRule struct {
	rule, title, sev, filter, note string
}

var findingRules = []findingRule{
	{"tcp.retransmission", "TCP retransmissions", "medium", "tcp.analysis.retransmission || tcp.analysis.fast_retransmission",
		"The sender re-sent data it believed was lost. Usually packet loss or congestion on the path, not an attack. A high rate degrades throughput."},
	{"tcp.syn_retransmission", "Connection-setup retries (SYN retransmissions)", "medium", "tcp.flags.syn==1 && tcp.flags.ack==0 && tcp.analysis.retransmission",
		"A client retried the opening SYN, so the first attempt(s) got no reply. Indicates an unreachable or slow service, a filtered port, or loss."},
	{"tcp.zero_window", "TCP zero window", "medium", "tcp.analysis.zero_window",
		"A receiver advertised a full buffer, pausing the sender. Often a slow or overloaded endpoint."},
	{"tcp.reset", "TCP resets", "low", "tcp.flags.reset==1",
		"A connection was aborted with RST. Common and often normal (a server closing an idle socket), but a burst can indicate refused connections."},
	{"tcp.dup_ack", "Duplicate ACKs", "low", "tcp.analysis.duplicate_ack",
		"Repeated ACKs for the same sequence, the receiver's signal that it is missing a segment. Correlates with retransmissions and loss."},
	{"tcp.lost_segment", "Missing segments (not captured)", "low", "tcp.analysis.lost_segment",
		"tshark saw a gap in the TCP sequence. On an appliance this often means the capture itself dropped packets, not the network — check the capture drop counters."},
	{"tcp.out_of_order", "Out-of-order segments", "info", "tcp.analysis.out_of_order",
		"Segments arrived out of sequence. Normal on multipath or reordering networks."},
	{"dns.servfail", "DNS SERVFAIL responses", "medium", "dns.flags.rcode==2",
		"The resolver reported a server failure. Can mean DNSSEC validation failure, an upstream outage, or a misconfigured name."},
	{"dns.nxdomain", "DNS NXDOMAIN responses", "info", "dns.flags.rcode==3 && !mdns",
		"The name does not exist. Extremely common (typos, telemetry probing non-existent names); only an unusual volume is noteworthy."},
	{"tls.fatal_alert", "Fatal TLS alerts", "medium", "tls.alert_message.level==2",
		"A TLS session ended with a fatal alert (e.g. handshake_failure, bad_certificate). The connection did not establish a secure channel."},
	{"icmp.unreachable", "ICMP destination unreachable", "low", "icmp.type==3 || icmpv6.type==1",
		"A router or host reported a destination or port could not be reached."},
}

func (e *Engine) Findings(ctx context.Context, id string, minCount int64) ([]Finding, error) {
	if minCount < 1 {
		minCount = 1
	}
	fields := []string{"ip.src", "ipv6.src", "ip.dst", "ipv6.dst", "tcp.stream"}
	var out []Finding
	for _, fr := range findingRules {
		rows, err := e.extractFields(ctx, id, fr.filter, fields, 50000)
		if err != nil {
			// A rule referencing a field this tshark build lacks shouldn't fail the page.
			continue
		}
		if int64(len(rows)) < minCount {
			continue
		}
		f := Finding{Rule: fr.rule, Title: fr.title, Severity: fr.sev, Filter: fr.filter, Note: fr.note, Count: int64(len(rows))}
		flows := map[string]bool{}
		for i, c := range rows {
			if i < 12 {
				n, _ := splitNumSeg(c[0])
				f.Examples = append(f.Examples, n)
			}
			if len(c) >= 7 {
				key := c[6] // tcp.stream when present
				if key == "" {
					key = firstNonEmpty(c[2], c[3]) + ">" + firstNonEmpty(c[4], c[5])
				}
				flows[key] = true
			}
		}
		f.Flows = len(flows)
		out = append(out, f)
	}
	// Capture drops are a finding of their own, read from the session record.
	var drops string
	e.DB.QueryRowContext(ctx, `SELECT drops FROM capture_sessions WHERE id=?`, id).Scan(&drops)
	if total := parseDropTotal(drops); total > 0 {
		out = append(out, Finding{Rule: "capture.drops", Title: "Packets dropped during capture", Severity: "medium", Count: total,
			Note: "The kernel or dumpcap could not keep up and discarded packets before they were written. The capture is incomplete; analysis counts are lower bounds. Reduce load or use a capture filter.", Filter: ""})
	}
	return out, nil
}

// parseDropTotal sums the "dropped" figures from dumpcap's per-interface report.
func parseDropTotal(s string) int64 {
	var total int64
	for _, line := range strings.Split(s, "\n") {
		// ...received/dropped on interface 'X': 1654/3 (...)
		if i := strings.Index(line, ": "); i >= 0 {
			frac := strings.Fields(line[i+2:])
			if len(frac) > 0 {
				if parts := strings.SplitN(frac[0], "/", 2); len(parts) == 2 {
					if d, err := strconv.ParseInt(parts[1], 10, 64); err == nil {
						total += d
					}
				}
			}
		}
	}
	return total
}

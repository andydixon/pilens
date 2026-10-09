package pcapfile

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
)

const fixture = "../../tests/fixtures/sample-loopback-http-dns.pcapng"

func TestScanAndCopy(t *testing.T) {
	var offs []int64
	var first []byte
	if err := Scan(fixture, "pcapng", func(i int, off int64, d []byte) error {
		offs = append(offs, off)
		if i == 0 {
			first = append([]byte(nil), d...)
		}
		return nil
	}); err != nil || len(offs) < 20 {
		t.Fatalf("scan: %v %d", err, len(offs))
	}
	d, err := ReadPacketAt(fixture, "pcapng", offs[0])
	if err != nil || !bytes.Equal(d, first) {
		t.Fatalf("ReadPacketAt: %v", err)
	}
	var buf bytes.Buffer
	n, err := CopySelected(&buf, fixture, "pcapng", true, func(i int) bool { return i%2 == 0 })
	if err != nil || n != (len(offs)+1)/2 {
		t.Fatalf("copy: %d %v", n, err)
	}
	p := filepath.Join(t.TempDir(), "o.pcapng")
	os.WriteFile(p, buf.Bytes(), 0o600)
	c := 0
	if err := Scan(p, "pcapng", func(int, int64, []byte) error { c++; return nil }); err != nil || c != n {
		t.Fatalf("rescan %d %v", c, err)
	}
}

func TestMalformed(t *testing.T) {
	good, _ := os.ReadFile(fixture)
	p := filepath.Join(t.TempDir(), "bad.pcapng")
	// truncated, and a block with an absurd length
	for _, b := range [][]byte{good[:len(good)-7], append(append([]byte{}, good[:28]...), 6, 0, 0, 0, 0xff, 0xff, 0xff, 0x7f)} {
		os.WriteFile(p, b, 0o600)
		if err := Scan(p, "pcapng", func(int, int64, []byte) error { return nil }); err == nil {
			t.Fatal("malformed file accepted")
		}
	}
	if _, err := Sniff([]byte("PK\x03\x04")); err == nil {
		t.Fatal("zip accepted")
	}
}

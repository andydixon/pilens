// Package pcapfile reads and copies pcap/pcapng files at the block/record level.
// It never re-encodes packet data: blocks are copied byte-for-byte.
// All input is treated as hostile: every length is bounds-checked.
package pcapfile

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
)

const (
	BlockSHB = 0x0A0D0D0A
	BlockIDB = 1
	BlockPB  = 2 // obsolete Packet Block
	BlockSPB = 3
	BlockEPB = 6
	BlockISB = 5

	MaxBlock = 16 << 20 // refuse blocks larger than this
)

var ErrFormat = errors.New("not a pcap or pcapng file")

// Sniff identifies the format from the first 4 bytes.
func Sniff(b []byte) (string, error) {
	if len(b) < 4 {
		return "", ErrFormat
	}
	switch binary.LittleEndian.Uint32(b) {
	case BlockSHB:
		return "pcapng", nil
	case 0xa1b2c3d4, 0xd4c3b2a1, 0xa1b23c4d, 0x4d3cb2a1:
		return "pcap", nil
	}
	return "", ErrFormat
}

// Block is one raw pcapng block.
type Block struct {
	Type  uint32
	Raw   []byte // the complete block, verbatim
	Order binary.ByteOrder
}

func (b Block) IsPacket() bool {
	return b.Type == BlockEPB || b.Type == BlockSPB || b.Type == BlockPB
}

// BlockReader reads pcapng blocks from a stream, tracking section byte order.
type BlockReader struct {
	r     io.Reader
	order binary.ByteOrder
}

func NewBlockReader(r io.Reader) *BlockReader { return &BlockReader{r: r} }

func (br *BlockReader) Next() (Block, error) {
	var hdr [12]byte
	if _, err := io.ReadFull(br.r, hdr[:8]); err != nil {
		return Block{}, err
	}
	typ := binary.LittleEndian.Uint32(hdr[:4]) // SHB type is a palindrome
	if typ == BlockSHB {
		if _, err := io.ReadFull(br.r, hdr[8:12]); err != nil {
			return Block{}, io.ErrUnexpectedEOF
		}
		switch binary.LittleEndian.Uint32(hdr[8:12]) {
		case 0x1A2B3C4D:
			br.order = binary.LittleEndian
		case 0x4D3C2B1A:
			br.order = binary.BigEndian
		default:
			return Block{}, errors.New("pcapng: bad byte-order magic")
		}
	} else if br.order == nil {
		return Block{}, errors.New("pcapng: data before section header")
	} else {
		typ = br.order.Uint32(hdr[:4])
	}
	n := br.order.Uint32(hdr[4:8])
	if n < 12 || n%4 != 0 || n > MaxBlock {
		return Block{}, fmt.Errorf("pcapng: invalid block length %d", n)
	}
	raw := make([]byte, n)
	got := 8
	copy(raw, hdr[:8])
	if typ == BlockSHB {
		copy(raw[8:], hdr[8:12])
		got = 12
	}
	if _, err := io.ReadFull(br.r, raw[got:]); err != nil {
		return Block{}, io.ErrUnexpectedEOF
	}
	if br.order.Uint32(raw[n-4:]) != n {
		return Block{}, errors.New("pcapng: trailing length mismatch")
	}
	return Block{Type: typ, Raw: raw, Order: br.order}, nil
}

// PacketData extracts captured bytes from a packet block.
func PacketData(b Block) ([]byte, error) {
	r := b.Raw
	o := b.Order
	switch b.Type {
	case BlockEPB, BlockPB:
		if len(r) < 32 {
			return nil, errors.New("short packet block")
		}
		cl := o.Uint32(r[20:24])
		if int(cl) > len(r)-32 {
			return nil, errors.New("captured length exceeds block")
		}
		return r[28 : 28+cl], nil
	case BlockSPB:
		if len(r) < 16 {
			return nil, errors.New("short simple packet block")
		}
		cl := min(int(o.Uint32(r[8:12])), len(r)-16)
		return r[12 : 12+cl], nil
	}
	return nil, errors.New("not a packet block")
}

// pcap (classic) --------------------------------------------------------------

type pcapHeader struct {
	order binary.ByteOrder
	raw   [24]byte
}

func readPcapHeader(r io.Reader) (pcapHeader, error) {
	var h pcapHeader
	if _, err := io.ReadFull(r, h.raw[:]); err != nil {
		return h, ErrFormat
	}
	switch binary.LittleEndian.Uint32(h.raw[:4]) {
	case 0xa1b2c3d4, 0xa1b23c4d:
		h.order = binary.LittleEndian
	case 0xd4c3b2a1, 0x4d3cb2a1:
		h.order = binary.BigEndian
	default:
		return h, ErrFormat
	}
	return h, nil
}

func readPcapRecord(r io.Reader, o binary.ByteOrder) ([]byte, error) {
	var rh [16]byte
	if _, err := io.ReadFull(r, rh[:]); err != nil {
		return nil, err
	}
	n := o.Uint32(rh[8:12])
	if n > MaxBlock {
		return nil, fmt.Errorf("pcap: record length %d too large", n)
	}
	rec := make([]byte, 16+n)
	copy(rec, rh[:])
	if _, err := io.ReadFull(r, rec[16:]); err != nil {
		return nil, io.ErrUnexpectedEOF
	}
	return rec, nil
}

// Scan calls fn for each packet in a file with its 0-based index, byte offset and data.
func Scan(path, format string, fn func(idx int, off int64, data []byte) error) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	cr := &countingReader{r: bufio.NewReaderSize(f, 1<<16)}
	idx := 0
	if format == "pcap" {
		h, err := readPcapHeader(cr)
		if err != nil {
			return err
		}
		for {
			off := cr.n
			rec, err := readPcapRecord(cr, h.order)
			if err == io.EOF {
				return nil
			}
			if err != nil {
				return err
			}
			if err := fn(idx, off, rec[16:]); err != nil {
				return err
			}
			idx++
		}
	}
	br := NewBlockReader(cr)
	for {
		off := cr.n
		b, err := br.Next()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		if b.IsPacket() {
			d, err := PacketData(b)
			if err != nil {
				return err
			}
			if err := fn(idx, off, d); err != nil {
				return err
			}
			idx++
		}
	}
}

// ReadPacketAt returns the captured bytes of the packet stored at off.
func ReadPacketAt(path, format string, off int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if format == "pcap" {
		h, err := readPcapHeader(f)
		if err != nil {
			return nil, err
		}
		if _, err := f.Seek(off, io.SeekStart); err != nil {
			return nil, err
		}
		rec, err := readPcapRecord(f, h.order)
		if err != nil {
			return nil, err
		}
		return rec[16:], nil
	}
	var hdr [8]byte
	if _, err := f.ReadAt(hdr[:], off); err != nil {
		return nil, err
	}
	var o binary.ByteOrder = binary.LittleEndian
	if t := binary.BigEndian.Uint32(hdr[:4]); t == BlockEPB || t == BlockSPB || t == BlockPB {
		o = binary.BigEndian
	}
	t, n := o.Uint32(hdr[:4]), o.Uint32(hdr[4:8])
	if (t != BlockEPB && t != BlockSPB && t != BlockPB) || n < 12 || n > MaxBlock {
		return nil, errors.New("no packet block at offset")
	}
	raw := make([]byte, n)
	if _, err := f.ReadAt(raw, off); err != nil {
		return nil, err
	}
	return PacketData(Block{Type: t, Raw: raw, Order: o})
}

// CopySelected writes the packets of src whose 0-based index satisfies keep to w,
// together with the section and interface headers they depend on. Packet records
// are copied verbatim. If writeHeader is false, a pcap global header is not
// repeated (used when appending further pcap segments to the same output).
func CopySelected(w io.Writer, path, format string, writeHeader bool, keep func(idx int) bool) (int, error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, err
	}
	defer f.Close()
	r := bufio.NewReaderSize(f, 1<<16)
	n, idx := 0, 0
	if format == "pcap" {
		h, err := readPcapHeader(r)
		if err != nil {
			return 0, err
		}
		if writeHeader {
			if _, err := w.Write(h.raw[:]); err != nil {
				return 0, err
			}
		}
		for {
			rec, err := readPcapRecord(r, h.order)
			if err == io.EOF {
				return n, nil
			}
			if err != nil {
				return n, err
			}
			if keep(idx) {
				if _, err := w.Write(rec); err != nil {
					return n, err
				}
				n++
			}
			idx++
		}
	}
	br := NewBlockReader(r)
	for {
		b, err := br.Next()
		if err == io.EOF {
			return n, nil
		}
		if err != nil {
			return n, err
		}
		switch {
		case b.Type == BlockSHB, b.Type == BlockIDB:
			// Always emitted, even when appending: repeated sections are valid
			// pcapng and keep each segment's interface IDs resolvable.
			if _, err := w.Write(b.Raw); err != nil {
				return n, err
			}
		case b.IsPacket():
			if keep(idx) {
				if _, err := w.Write(b.Raw); err != nil {
					return n, err
				}
				n++
			}
			idx++
		}
	}
}

type countingReader struct {
	r io.Reader
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

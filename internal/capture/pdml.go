package capture

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"errors"
	"strconv"
)

// Node is one line of the protocol tree sent to the browser.
type Node struct {
	Label    string `json:"label"`
	Field    string `json:"field,omitempty"`
	Pos      int    `json:"pos"`
	Size     int    `json:"size"`
	Verified bool   `json:"verified"` // bytes at pos..pos+size are proven to belong to this field
	Children []Node `json:"children,omitempty"`
}

type pdmlNode struct {
	XMLName  xml.Name
	Name     string     `xml:"name,attr"`
	Show     string     `xml:"show,attr"`
	Showname string     `xml:"showname,attr"`
	Value    string     `xml:"value,attr"`
	Unmasked string     `xml:"unmaskedvalue,attr"`
	Pos      string     `xml:"pos,attr"`
	Size     string     `xml:"size,attr"`
	Hide     string     `xml:"hide,attr"`
	Children []pdmlNode `xml:",any"`
}

// ParsePDML converts tshark PDML for a single packet into a tree. frame holds
// the original captured bytes, used to verify each field's byte range.
func ParsePDML(b []byte, frame []byte) ([]Node, error) {
	var doc struct {
		Packets []struct {
			Protos []pdmlNode `xml:",any"`
		} `xml:"packet"`
	}
	d := xml.NewDecoder(bytes.NewReader(b))
	d.Strict = false
	if err := d.Decode(&doc); err != nil {
		return nil, err
	}
	if len(doc.Packets) == 0 {
		return nil, errors.New("packet not found")
	}
	var out []Node
	for _, p := range doc.Packets[0].Protos {
		if p.Name == "geninfo" || p.Hide == "yes" {
			continue
		}
		n, _ := convert(p, frame)
		out = append(out, n)
	}
	return out, nil
}

// convert returns the node and whether any field in its subtree contradicts the frame bytes.
func convert(p pdmlNode, frame []byte) (Node, bool) {
	n := Node{Field: p.Name}
	n.Label = p.Showname
	if n.Label == "" {
		n.Label = p.Show
	}
	if n.Label == "" {
		n.Label = p.Name
	}
	n.Pos, _ = strconv.Atoi(p.Pos)
	n.Size, _ = strconv.Atoi(p.Size)
	inRange := n.Size > 0 && n.Pos >= 0 && n.Pos+n.Size <= len(frame)
	raw := p.Value
	if p.Unmasked != "" {
		raw = p.Unmasked // bitfields: value is the masked number, unmaskedvalue the bytes
	}
	contradicts := false
	if v, err := hex.DecodeString(raw); err == nil && len(v) > 0 && len(v) == n.Size {
		if inRange && bytes.Equal(v, frame[n.Pos:n.Pos+n.Size]) {
			n.Verified = true
		} else {
			contradicts = true
		}
	}
	matched, mismatched := false, contradicts
	for _, c := range p.Children {
		if c.Hide == "yes" {
			continue
		}
		cn, cm := convert(c, frame)
		if c.XMLName.Local != "proto" { // a nested (e.g. reassembled) protocol is judged on its own
			matched = matched || cn.Verified
			mismatched = mismatched || cm
		}
		n.Children = append(n.Children, cn)
	}
	// Protocols carry no value: trust their range only if their own fields verify
	// against the frame bytes and none contradict it (rules out reassembled sources).
	if raw == "" && inRange && matched && !mismatched {
		n.Verified = true
	}
	if p.Name == "frame" && inRange {
		n.Verified = true
	}
	return n, mismatched
}

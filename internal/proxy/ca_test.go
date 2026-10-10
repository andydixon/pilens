package proxy

import (
	"strings"
	"testing"
)

func TestCAGeneration(t *testing.T) {
	dir := t.TempDir()
	if err := EnsureCA(dir, "testpi"); err != nil {
		t.Fatal(err)
	}
	// Public cert must never contain a private key.
	pub, err := PublicCertPEM(dir)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(pub), "PRIVATE KEY") {
		t.Fatal("public cert leaked the private key")
	}
	if !strings.Contains(string(pub), "BEGIN CERTIFICATE") {
		t.Fatal("not a certificate")
	}
	info := Info(dir)
	if !info.Present || !strings.Contains(info.Subject, "PiLens") || len(info.SHA256) != 95 || info.DaysLeft < 1000 {
		t.Fatalf("bad CA info: %+v", info)
	}
	// Idempotent: second call keeps the same CA.
	before := info.SHA256
	EnsureCA(dir, "testpi")
	if Info(dir).SHA256 != before {
		t.Fatal("EnsureCA regenerated an existing CA")
	}
	// Rotate produces a different CA.
	if err := Rotate(dir, "testpi"); err != nil {
		t.Fatal(err)
	}
	if Info(dir).SHA256 == before {
		t.Fatal("rotate did not change the CA")
	}
}

func TestConfigValidate(t *testing.T) {
	bad := []Config{
		{MaxBodyKB: -1},
		{MaxBodyKB: 999999},
		{ExcludeHosts: []string{"ok.com", "bad regex ("}},
		{ExcludeHosts: []string{"has space"}},
	}
	for i, c := range bad {
		if c.Validate() == nil {
			t.Errorf("case %d accepted invalid config", i)
		}
	}
	good := Config{MaxBodyKB: 256, ExcludeHosts: []string{`(?i)\.apple\.com$`, "example\\.com"}}
	if err := good.Validate(); err != nil {
		t.Fatal(err)
	}
	if r := good.ExcludeRegex(); !strings.Contains(r, "apple") || !strings.Contains(r, "|") {
		t.Fatalf("exclude regex wrong: %s", r)
	}
}

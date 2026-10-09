package api

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"pilens.dev/pilens/internal/capture"
	"pilens.dev/pilens/internal/config"
	"pilens.dev/pilens/internal/store"
)

type client struct {
	t      *testing.T
	h      http.Handler
	remote string
	cookie *http.Cookie
	csrf   string
}

func (c *client) do(method, path string, body any, hdr map[string]string) (int, map[string]any) {
	var b bytes.Buffer
	if body != nil {
		json.NewEncoder(&b).Encode(body)
	}
	r := httptest.NewRequest(method, path, &b)
	r.RemoteAddr = c.remote
	r.Header.Set("X-Requested-With", "pilens")
	if c.cookie != nil {
		r.AddCookie(c.cookie)
	}
	if c.csrf != "" {
		r.Header.Set("X-CSRF-Token", c.csrf)
	}
	for k, v := range hdr {
		r.Header.Set(k, v)
	}
	w := httptest.NewRecorder()
	c.h.ServeHTTP(w, r)
	for _, ck := range w.Result().Cookies() {
		if ck.Name == cookieName {
			c.cookie = ck
		}
	}
	var out map[string]any
	json.Unmarshal(w.Body.Bytes(), &out)
	return w.Code, out
}

func newServer(t *testing.T) *Server {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "t.db"))
	if err != nil {
		t.Fatal(err)
	}
	db.PutJSON(keyBootstrap, config.Management{Interfaces: []string{"eth0"}, AllowedSubnets: []string{"10.9.0.0/24"}, Port: 8443})
	tok := filepath.Join(dir, "setup-token")
	os.WriteFile(tok, []byte("secret-token\n"), 0o600)
	return &Server{DB: db, Engine: &capture.Engine{DB: db, Hub: capture.NewHub()}, SetupTokenPath: tok, DataDir: dir}
}

func TestSetupAuthFlow(t *testing.T) {
	s := newServer(t)
	h := s.Handler()
	c := &client{t: t, h: h, remote: "10.9.0.5:5555"}

	if code, _ := (&client{h: h, remote: "192.168.50.20:1"}).do("GET", "/api/setup/status", nil, nil); code != 403 {
		t.Fatalf("non-management source allowed: %d", code)
	}
	if code, _ := c.do("GET", "/api/network", nil, nil); code != 401 {
		t.Fatalf("unauthenticated access: %d", code)
	}
	admin := map[string]any{"token": "wrong", "username": "admin", "password": "a-very-long-password", "authorised": true}
	if code, _ := c.do("POST", "/api/setup/admin", admin, nil); code != 403 {
		t.Fatalf("bad token accepted: %d", code)
	}
	admin["token"] = "secret-token"
	admin["authorised"] = false
	if code, _ := c.do("POST", "/api/setup/admin", admin, nil); code != 400 {
		t.Fatalf("missing authorisation accepted: %d", code)
	}
	admin["authorised"] = true
	admin["password"] = "short"
	if code, _ := c.do("POST", "/api/setup/admin", admin, nil); code != 400 {
		t.Fatal("weak password accepted")
	}
	admin["password"] = "a-very-long-password"
	code, out := c.do("POST", "/api/setup/admin", admin, nil)
	if code != 200 || out["csrf"] == "" {
		t.Fatalf("setup failed: %d %v", code, out)
	}
	if _, err := os.Stat(s.SetupTokenPath); err == nil {
		t.Fatal("setup token not consumed")
	}
	if code, _ := c.do("POST", "/api/setup/admin", admin, nil); code != 409 {
		t.Fatal("second admin creation allowed")
	}

	// Authenticated GET works; state change without CSRF token is refused.
	if code, _ := c.do("GET", "/api/network", nil, nil); code != 200 {
		t.Fatalf("session not usable: %d", code)
	}
	if code, _ := c.do("PUT", "/api/devices/aa:bb:cc:dd:ee:ff", map[string]string{"Label": "x"}, nil); code != 403 {
		t.Fatalf("CSRF not enforced: %d", code)
	}
	c.csrf = out["csrf"].(string)
	if code, _ := c.do("PUT", "/api/devices/aa:bb:cc:dd:ee:ff", map[string]string{"Label": "phone"}, nil); code != 200 {
		t.Fatalf("device label: %d", code)
	}

	// Lock-out protection: management subnets must include the caller.
	n := config.DefaultNetwork()
	n.Management = config.Management{Interfaces: []string{"eth0"}, AllowedSubnets: []string{"10.8.0.0/24"}, Port: 8443}
	n.Uplink, n.AP.Interface, n.AP.Passphrase = "eth0", "wlan0", "passphrase123"
	_, v := c.do("POST", "/api/network/validate", n, nil)
	if v["valid"] != false || !strings.Contains(strings.Join(toStrings(v["errors"]), " "), "lock you out") {
		t.Fatalf("lock-out not detected: %v", v)
	}

	// Logout invalidates the session.
	c.do("POST", "/api/auth/logout", nil, nil)
	if code, _ := c.do("GET", "/api/network", nil, nil); code != 401 {
		t.Fatal("session survived logout")
	}

	// Login throttling.
	bad := &client{h: h, remote: "10.9.0.7:1"}
	for i := 0; i < 5; i++ {
		bad.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "nope"}, nil)
	}
	if code, _ := bad.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "a-very-long-password"}, nil); code != 429 {
		t.Fatalf("no throttling: %d", code)
	}
	// Login requires the XHR header (blocks cross-site form posts).
	if code, _ := c.do("POST", "/api/auth/login", map[string]string{"username": "admin", "password": "a-very-long-password"}, map[string]string{"X-Requested-With": ""}); code != 403 {
		t.Fatalf("form post accepted: %d", code)
	}
}

func toStrings(v any) []string {
	var out []string
	if a, ok := v.([]any); ok {
		for _, x := range a {
			out = append(out, x.(string))
		}
	}
	return out
}

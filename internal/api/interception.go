package api

import (
	"context"
	"fmt"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"pilens.dev/pilens/internal/helper"
	"pilens.dev/pilens/internal/proxy"
)

// interceptionRoutes wires the Mode-B (authorised HTTPS inspection) endpoints.
func (s *Server) interceptionRoutes(priv func(string, http.HandlerFunc)) {
	priv("GET /api/interception", s.getInterception)
	priv("PUT /api/interception", s.setInterception)
	priv("POST /api/interception/ca/rotate", s.rotateCA)
	priv("POST /api/interception/clear", s.clearFlows)
	priv("GET /api/interception/ca.crt", s.downloadCA)
	priv("GET /api/http", s.httpFlows)
	priv("GET /api/http/{id}", s.httpFlow)
	priv("GET /api/http/{id}/body/{which}", s.httpBody)
}

func (s *Server) interceptionStatus(ctx context.Context) map[string]any {
	cfg := s.Proxy.Config()
	running := false
	st, herr := s.helperStatus(ctx)
	_ = st
	// proxy liveness: ask the helper-independent systemd via the health probe is
	// overkill; infer from config + a quick check of the flows file growth is not
	// reliable. Report configured-enabled; the dashboard shows service health.
	running = cfg.Enabled && herr == ""
	return map[string]any{
		"config":  cfg,
		"ca":      s.Proxy.CAInfo(),
		"running": running,
		"port":    proxy.ListenPort,
		"note": "Interception decrypts HTTPS only for devices whose owner has installed and trusted the PiLens CA. " +
			"Pinned apps, private trust stores and QUIC are reported as not intercepted, never bypassed. The CA private key is never downloadable.",
	}
}

func (s *Server) getInterception(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.interceptionStatus(r.Context()))
}

// proxyEnvPath is read by the pilens-proxy systemd unit via proxy-run.sh.
func (s *Server) proxyDir() string  { return filepath.Join(s.DataDir, "proxy") }
func (s *Server) proxyEnv() string  { return filepath.Join(s.proxyDir(), "proxy.env") }

func shellQuote(v string) string { return "'" + strings.ReplaceAll(v, "'", `'\''`) + "'" }

func (s *Server) writeProxyEnv(cfg proxy.Config) error {
	bodies := "0"
	if cfg.CaptureBodies {
		bodies = "1"
	}
	env := strings.Join([]string{
		"PILENS_VENV=" + shellQuote("/opt/pilens/proxy-venv"),
		fmt.Sprintf("PILENS_PROXY_PORT=%d", proxy.ListenPort),
		"PILENS_CONFDIR=" + shellQuote(s.Proxy.ConfDir()),
		"PILENS_ADDON=" + shellQuote("/opt/pilens/mitm_addon.py"),
		"PILENS_FLOWS=" + shellQuote(filepath.Join(s.proxyDir(), "flows.ndjson")),
		"PILENS_BODIES=" + shellQuote(filepath.Join(s.proxyDir(), "bodies")),
		"PILENS_CAPTURE_BODIES=" + bodies,
		fmt.Sprintf("PILENS_MAX_BODY_KB=%d", cfg.MaxBodyKB),
		"PILENS_IGNORE=" + shellQuote(cfg.ExcludeRegex()),
	}, "\n") + "\n"
	os.MkdirAll(s.proxyDir(), 0o750)
	return os.WriteFile(s.proxyEnv(), []byte(env), 0o640)
}

func (s *Server) setInterception(w http.ResponseWriter, r *http.Request) {
	var cfg proxy.Config
	if !readJSON(w, r, &cfg) {
		return
	}
	if err := cfg.Validate(); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if err := s.Proxy.EnsureCA(); err != nil {
		httpErr(w, 500, "CA generation failed: "+err.Error())
		return
	}
	if err := s.writeProxyEnv(cfg); err != nil {
		httpErr(w, 500, "writing proxy config failed: "+err.Error())
		return
	}
	if err := s.Proxy.SetConfig(cfg); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 60*time.Second)
	defer cancel()
	var res helper.ApplyResult
	err := s.Helper.Call(ctx, helper.Request{Op: helper.OpSetInterception, InterceptEnabled: cfg.Enabled, InterceptPort: proxy.ListenPort}, &res)
	detail := fmt.Sprintf("enabled=%v capture_bodies=%v excludes=%d", cfg.Enabled, cfg.CaptureBodies, len(cfg.ExcludeHosts))
	if err != nil {
		s.audit(r, "interception.apply_failed", detail+": "+err.Error())
		w.WriteHeader(http.StatusBadGateway)
		writeJSON(w, map[string]any{"error": err.Error(), "result": res, "status": s.interceptionStatus(r.Context())})
		return
	}
	s.audit(r, "interception.changed", detail)
	writeJSON(w, map[string]any{"result": res, "status": s.interceptionStatus(r.Context())})
}

func (s *Server) rotateCA(w http.ResponseWriter, r *http.Request) {
	if s.Proxy.Config().Enabled {
		httpErr(w, http.StatusConflict, "disable interception before rotating the CA, so devices are not left mid-session")
		return
	}
	if err := s.Proxy.RotateCA(); err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	s.audit(r, "interception.ca_rotated", s.Proxy.CAInfo().SHA256)
	writeJSON(w, map[string]any{"ca": s.Proxy.CAInfo()})
}

func (s *Server) downloadCA(w http.ResponseWriter, r *http.Request) {
	pem, err := s.Proxy.CACertPEM()
	if err != nil {
		httpErr(w, http.StatusNotFound, err.Error())
		return
	}
	s.audit(r, "interception.ca_downloaded", s.Proxy.CAInfo().SHA256)
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", `attachment; filename="pilens-ca.crt"`)
	w.Write(pem)
}

func (s *Server) clearFlows(w http.ResponseWriter, r *http.Request) {
	s.Proxy.Clear()
	s.audit(r, "interception.flows_cleared", "")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) httpFlows(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	client := q.Get("client")
	if !proxy.ClientIP(client) {
		httpErr(w, http.StatusBadRequest, "invalid client filter")
		return
	}
	flows, err := s.Proxy.Flows(r.Context(), q.Get("q"), client, qint(r, "limit", 1000))
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	writeJSON(w, flows)
}

func (s *Server) httpFlow(w http.ResponseWriter, r *http.Request) {
	f, err := s.Proxy.Flow(r.Context(), r.PathValue("id"))
	if err != nil {
		httpErr(w, http.StatusNotFound, "flow not found")
		return
	}
	writeJSON(w, f)
}

// httpBody serves a stored body as an opaque download. It is never served with a
// content type that a browser would execute; the UI renders it in a sandbox.
func (s *Server) httpBody(w http.ResponseWriter, r *http.Request) {
	body, err := s.Proxy.Body(r.PathValue("id"), r.PathValue("which"))
	if err != nil {
		httpErr(w, http.StatusNotFound, "body not retained (body capture was off, or it was cleared)")
		return
	}
	w.Header().Set("X-Content-Type-Options", "nosniff")
	w.Header().Set("Content-Type", "application/octet-stream")
	w.Header().Set("Content-Disposition", "attachment")
	w.Header().Set("Content-Security-Policy", "default-src 'none'; sandbox")
	s.audit(r, "interception.body_viewed", r.PathValue("id")+"/"+r.PathValue("which"))
	w.Write(body)
}

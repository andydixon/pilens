// Package api is the authenticated management HTTP API and static UI server.
package api

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"io/fs"
	"log/slog"
	"net"
	"net/http"
	"net/netip"
	"os"
	"strings"
	"sync"
	"time"

	"pilens.dev/pilens/internal/auth"
	"pilens.dev/pilens/internal/capture"
	"pilens.dev/pilens/internal/config"
	"pilens.dev/pilens/internal/helper"
	"pilens.dev/pilens/internal/store"
)

const (
	cookieName   = "pilens_session"
	sessionIdle  = 60 * time.Minute
	sessionMax   = 12 * time.Hour
	keyNetwork   = "network"
	keyBootstrap = "bootstrap_management"
	keySetupDone = "setup_complete"
	keyLimits    = "capture_limits"
)

type Server struct {
	DB             *store.Store
	Engine         *capture.Engine
	Helper         helper.Client
	Version        string
	Web            fs.FS // built UI; may be nil in tests
	SetupTokenPath string
	DataDir        string

	limiter  *auth.Limiter
	mgmtMu   sync.RWMutex
	mgmtNets []netip.Prefix
	apGW     netip.Addr
}

type user struct {
	ID          int64
	Name        string
	CSRF        string
	TOTPEnabled bool
	TokenHash   string
}

type ctxKey struct{}

func (s *Server) Handler() http.Handler {
	s.limiter = auth.NewLimiter()
	s.reloadMgmt()
	mux := http.NewServeMux()
	pub := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, h) }
	priv := func(pattern string, h http.HandlerFunc) { mux.Handle(pattern, s.requireAuth(h)) }

	pub("GET /api/health", func(w http.ResponseWriter, r *http.Request) { writeJSON(w, map[string]bool{"ok": true}) })
	pub("GET /api/setup/status", s.setupStatus)
	pub("POST /api/setup/admin", s.setupAdmin)
	pub("POST /api/auth/login", s.login)
	priv("POST /api/auth/logout", s.logout)
	priv("GET /api/auth/session", s.session)
	priv("POST /api/auth/password", s.changePassword)
	priv("POST /api/auth/totp/begin", s.totpBegin)
	priv("POST /api/auth/totp/enable", s.totpEnable)
	priv("POST /api/auth/totp/disable", s.totpDisable)
	priv("GET /api/audit", s.auditLog)
	priv("GET /api/events", s.events)

	s.networkRoutes(priv)
	s.captureRoutes(priv)
	s.analysisRoutes(priv)

	if s.Web != nil {
		files := http.FileServerFS(s.Web)
		mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
			if strings.HasPrefix(r.URL.Path, "/api/") {
				http.NotFound(w, r)
				return
			}
			if _, err := fs.Stat(s.Web, strings.TrimPrefix(r.URL.Path, "/")); err != nil || r.URL.Path == "/" {
				r.URL.Path = "/" // SPA fallback
			}
			files.ServeHTTP(w, r)
		})
	}
	return s.secureHeaders(s.sourceCheck(mux))
}

// ---------------------------------------------------------------- middleware

func (s *Server) secureHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h := w.Header()
		// Captured content is never rendered as HTML by the app; previews use sandboxed blob iframes.
		h.Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data: blob:; style-src 'self' 'unsafe-inline'; frame-src blob:; object-src 'none'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")
		h.Set("X-Content-Type-Options", "nosniff")
		h.Set("Referrer-Policy", "no-referrer")
		h.Set("X-Frame-Options", "DENY")
		h.Set("Strict-Transport-Security", "max-age=31536000")
		h.Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		if strings.HasPrefix(r.URL.Path, "/api/") {
			h.Set("Cache-Control", "no-store")
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) reloadMgmt() {
	var nets []netip.Prefix
	var apGW netip.Addr
	var n config.Network
	if ok, _ := s.DB.GetJSON(keyNetwork, &n); ok {
		for _, c := range n.Management.AllowedSubnets {
			if p, err := netip.ParsePrefix(c); err == nil {
				nets = append(nets, p.Masked())
			}
		}
		if p, err := netip.ParsePrefix(n.LAN.Address); err == nil {
			apGW = p.Addr()
		}
	} else {
		var b config.Management
		s.DB.GetJSON(keyBootstrap, &b)
		for _, c := range b.AllowedSubnets {
			if p, err := netip.ParsePrefix(c); err == nil {
				nets = append(nets, p.Masked())
			}
		}
	}
	s.mgmtMu.Lock()
	s.mgmtNets, s.apGW = nets, apGW
	s.mgmtMu.Unlock()
}

func remoteAddr(r *http.Request) netip.Addr {
	ap, err := netip.ParseAddrPort(r.RemoteAddr)
	if err != nil {
		return netip.Addr{}
	}
	return ap.Addr().Unmap()
}

// sourceCheck is defence in depth behind the nftables rules: only allow-listed
// management subnets, and never a request that arrived on the AP gateway address.
func (s *Server) sourceCheck(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		ra := remoteAddr(r)
		s.mgmtMu.RLock()
		nets, apGW := s.mgmtNets, s.apGW
		s.mgmtMu.RUnlock()
		if la, ok := r.Context().Value(http.LocalAddrContextKey).(net.Addr); ok && apGW.IsValid() {
			if lap, err := netip.ParseAddrPort(la.String()); err == nil && lap.Addr().Unmap() == apGW {
				http.Error(w, "management is not available on the access-point network", http.StatusForbidden)
				return
			}
		}
		allowed := ra.IsLoopback()
		for _, p := range nets {
			if p.Contains(ra) {
				allowed = true
			}
		}
		if !allowed {
			slog.Warn("management request from non-allowed source", "remote", ra)
			http.Error(w, "source address not allowed for management", http.StatusForbidden)
			return
		}
		next.ServeHTTP(w, r)
	})
}

func (s *Server) requireAuth(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie(cookieName)
		if err != nil {
			httpErr(w, http.StatusUnauthorized, "not logged in")
			return
		}
		th := auth.TokenHash(c.Value)
		now := time.Now()
		var u user
		var lastSeen, expires int64
		err = s.DB.QueryRow(`SELECT u.id,u.username,s.csrf,u.totp_enabled,s.last_seen,s.expires_at FROM sessions s JOIN users u ON u.id=s.user_id WHERE s.token_hash=?`, th).
			Scan(&u.ID, &u.Name, &u.CSRF, &u.TOTPEnabled, &lastSeen, &expires)
		if err != nil || now.Unix() > expires || now.Unix()-lastSeen > int64(sessionIdle.Seconds()) {
			if err == nil {
				s.DB.Exec(`DELETE FROM sessions WHERE token_hash=?`, th)
			}
			httpErr(w, http.StatusUnauthorized, "session expired")
			return
		}
		u.TokenHash = th
		if r.Method != http.MethodGet && r.Method != http.MethodHead {
			if subtle.ConstantTimeCompare([]byte(r.Header.Get("X-CSRF-Token")), []byte(u.CSRF)) != 1 {
				httpErr(w, http.StatusForbidden, "missing or invalid CSRF token")
				return
			}
		}
		if now.Unix()-lastSeen > 30 && r.URL.Path != "/api/events" {
			s.DB.Exec(`UPDATE sessions SET last_seen=? WHERE token_hash=?`, now.Unix(), th)
		}
		next.ServeHTTP(w, r.WithContext(context.WithValue(r.Context(), ctxKey{}, &u)))
	})
}

func currentUser(r *http.Request) *user { u, _ := r.Context().Value(ctxKey{}).(*user); return u }

func (s *Server) audit(r *http.Request, action, detail string) {
	actor := "anonymous"
	if u := currentUser(r); u != nil {
		actor = u.Name
	}
	s.DB.Audit(actor, action, detail, remoteAddr(r).String())
}

// ---------------------------------------------------------------- helpers

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func httpErr(w http.ResponseWriter, code int, msg string) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	json.NewEncoder(w).Encode(map[string]string{"error": msg})
}

func readJSON(w http.ResponseWriter, r *http.Request, v any) bool {
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	d := json.NewDecoder(r.Body)
	d.DisallowUnknownFields()
	if err := d.Decode(v); err != nil {
		httpErr(w, http.StatusBadRequest, "invalid request body: "+err.Error())
		return false
	}
	return true
}

// requireXHR blocks cross-site form posts to unauthenticated endpoints: a custom
// header cannot be sent cross-origin without a CORS preflight, which we never allow.
func requireXHR(w http.ResponseWriter, r *http.Request) bool {
	if r.Header.Get("X-Requested-With") != "pilens" {
		httpErr(w, http.StatusForbidden, "missing X-Requested-With header")
		return false
	}
	return true
}

// ---------------------------------------------------------------- setup + auth

func (s *Server) adminExists() bool {
	var n int
	s.DB.QueryRow(`SELECT COUNT(*) FROM users`).Scan(&n)
	return n > 0
}

func (s *Server) setupComplete() bool {
	var done bool
	s.DB.GetJSON(keySetupDone, &done)
	return done
}

func (s *Server) setupStatus(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, map[string]any{"needs_admin": !s.adminExists(), "setup_complete": s.setupComplete(), "version": s.Version})
}

func (s *Server) setupAdmin(w http.ResponseWriter, r *http.Request) {
	if !requireXHR(w, r) {
		return
	}
	var req struct {
		Token      string `json:"token"`
		Username   string `json:"username"`
		Password   string `json:"password"`
		Authorised bool   `json:"authorised"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	ra := remoteAddr(r).String()
	if ok, wait := s.limiter.Allowed("setup:"+ra, time.Now()); !ok {
		httpErr(w, http.StatusTooManyRequests, "too many attempts; retry in "+wait.Round(time.Second).String())
		return
	}
	want, err := os.ReadFile(s.SetupTokenPath)
	if err != nil || s.adminExists() {
		httpErr(w, http.StatusConflict, "setup already completed")
		return
	}
	if subtle.ConstantTimeCompare([]byte(strings.TrimSpace(string(want))), []byte(strings.TrimSpace(req.Token))) != 1 {
		s.limiter.Fail("setup:"+ra, time.Now())
		httpErr(w, http.StatusForbidden, "invalid setup token (printed by the installer; also in "+s.SetupTokenPath+")")
		return
	}
	if !req.Authorised {
		httpErr(w, http.StatusBadRequest, "you must confirm this appliance will only inspect traffic you are authorised to inspect")
		return
	}
	if !validUsername(req.Username) {
		httpErr(w, http.StatusBadRequest, "username must be 1-32 letters, digits, '.', '_' or '-'")
		return
	}
	if err := auth.PasswordPolicy(req.Password); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h, err := auth.HashPassword(req.Password)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	// The INSERT is conditional so two racing requests cannot both create an admin.
	res, err := s.DB.Exec(`INSERT INTO users(username,password_hash,created_at) SELECT ?,?,? WHERE NOT EXISTS (SELECT 1 FROM users)`, req.Username, h, time.Now().Unix())
	if n, _ := res.RowsAffected(); err != nil || n == 0 {
		httpErr(w, http.StatusConflict, "setup already completed")
		return
	}
	os.Remove(s.SetupTokenPath)
	s.DB.Audit(req.Username, "setup.admin_created", "authorised-use confirmation recorded", ra)
	s.startSession(w, r, req.Username)
}

func validUsername(u string) bool {
	if len(u) < 1 || len(u) > 32 {
		return false
	}
	for _, c := range u {
		if !(c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c >= '0' && c <= '9' || c == '.' || c == '_' || c == '-') {
			return false
		}
	}
	return true
}

func (s *Server) startSession(w http.ResponseWriter, r *http.Request, username string) {
	var uid int64
	if err := s.DB.QueryRow(`SELECT id FROM users WHERE username=?`, username).Scan(&uid); err != nil {
		httpErr(w, 500, "user lookup failed")
		return
	}
	tok := auth.RandomToken(32)
	csrf := auth.RandomToken(32)
	now := time.Now().Unix()
	s.DB.Exec(`DELETE FROM sessions WHERE expires_at<?`, now)
	if _, err := s.DB.Exec(`INSERT INTO sessions(token_hash,user_id,csrf,created_at,last_seen,expires_at,remote) VALUES(?,?,?,?,?,?,?)`,
		auth.TokenHash(tok), uid, csrf, now, now, now+int64(sessionMax.Seconds()), remoteAddr(r).String()); err != nil {
		httpErr(w, 500, "session failed")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: tok, Path: "/", HttpOnly: true, Secure: true, SameSite: http.SameSiteStrictMode, MaxAge: int(sessionMax.Seconds())})
	writeJSON(w, map[string]any{"user": username, "csrf": csrf})
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	if !requireXHR(w, r) {
		return
	}
	var req struct {
		Username string `json:"username"`
		Password string `json:"password"`
		TOTP     string `json:"totp"`
	}
	if !readJSON(w, r, &req) {
		return
	}
	now := time.Now()
	ipKey, userKey := "ip:"+remoteAddr(r).String(), "user:"+strings.ToLower(req.Username)
	for _, k := range []string{ipKey, userKey} {
		if ok, wait := s.limiter.Allowed(k, now); !ok {
			httpErr(w, http.StatusTooManyRequests, "too many failed attempts; retry in "+wait.Round(time.Second).String())
			return
		}
	}
	var hash, secret string
	var totp bool
	err := s.DB.QueryRow(`SELECT password_hash,totp_secret,totp_enabled FROM users WHERE username=?`, req.Username).Scan(&hash, &secret, &totp)
	if err == sql.ErrNoRows {
		hash = "$argon2id$v=19$m=65536,t=2,p=2$c2FsdHNhbHRzYWx0c2FsdA$AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA" // equalise timing
	}
	ok := auth.CheckPassword(req.Password, hash) && err == nil
	if ok && totp {
		if req.TOTP == "" {
			httpErr(w, http.StatusUnauthorized, "totp_required")
			return
		}
		ok = auth.CheckTOTP(secret, req.TOTP, now)
	}
	if !ok {
		s.limiter.Fail(ipKey, now)
		s.limiter.Fail(userKey, now)
		s.DB.Audit(req.Username, "auth.login_failed", "", remoteAddr(r).String())
		httpErr(w, http.StatusUnauthorized, "invalid credentials")
		return
	}
	s.limiter.Success(ipKey)
	s.limiter.Success(userKey)
	s.DB.Audit(req.Username, "auth.login", "", remoteAddr(r).String())
	s.startSession(w, r, req.Username)
}

func (s *Server) logout(w http.ResponseWriter, r *http.Request) {
	s.DB.Exec(`DELETE FROM sessions WHERE token_hash=?`, currentUser(r).TokenHash)
	http.SetCookie(w, &http.Cookie{Name: cookieName, Value: "", Path: "/", MaxAge: -1, Secure: true, HttpOnly: true, SameSite: http.SameSiteStrictMode})
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) session(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	writeJSON(w, map[string]any{"user": u.Name, "csrf": u.CSRF, "totp_enabled": u.TOTPEnabled, "setup_complete": s.setupComplete(), "version": s.Version})
}

func (s *Server) checkPassword(u *user, pw string) bool {
	var hash string
	s.DB.QueryRow(`SELECT password_hash FROM users WHERE id=?`, u.ID).Scan(&hash)
	return auth.CheckPassword(pw, hash)
}

func (s *Server) changePassword(w http.ResponseWriter, r *http.Request) {
	var req struct{ Current, New string }
	if !readJSON(w, r, &req) {
		return
	}
	u := currentUser(r)
	if !s.checkPassword(u, req.Current) {
		httpErr(w, http.StatusForbidden, "current password is wrong")
		return
	}
	if err := auth.PasswordPolicy(req.New); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	h, _ := auth.HashPassword(req.New)
	s.DB.Exec(`UPDATE users SET password_hash=? WHERE id=?`, h, u.ID)
	s.DB.Exec(`DELETE FROM sessions WHERE user_id=? AND token_hash!=?`, u.ID, u.TokenHash)
	s.audit(r, "auth.password_changed", "other sessions revoked")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) totpBegin(w http.ResponseWriter, r *http.Request) {
	u := currentUser(r)
	if u.TOTPEnabled {
		httpErr(w, http.StatusConflict, "TOTP already enabled")
		return
	}
	sec := auth.NewTOTPSecret()
	s.DB.Exec(`UPDATE users SET totp_secret=? WHERE id=?`, sec, u.ID)
	writeJSON(w, map[string]string{"secret": sec, "uri": auth.TOTPURI("PiLens", u.Name, sec)})
}

func (s *Server) totpEnable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Code string }
	if !readJSON(w, r, &req) {
		return
	}
	u := currentUser(r)
	var sec string
	s.DB.QueryRow(`SELECT totp_secret FROM users WHERE id=?`, u.ID).Scan(&sec)
	if sec == "" || !auth.CheckTOTP(sec, req.Code, time.Now()) {
		httpErr(w, http.StatusBadRequest, "code does not match; check the device clock")
		return
	}
	s.DB.Exec(`UPDATE users SET totp_enabled=1 WHERE id=?`, u.ID)
	s.audit(r, "auth.totp_enabled", "")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) totpDisable(w http.ResponseWriter, r *http.Request) {
	var req struct{ Password string }
	if !readJSON(w, r, &req) {
		return
	}
	u := currentUser(r)
	if !s.checkPassword(u, req.Password) {
		httpErr(w, http.StatusForbidden, "password is wrong")
		return
	}
	s.DB.Exec(`UPDATE users SET totp_enabled=0, totp_secret='' WHERE id=?`, u.ID)
	s.audit(r, "auth.totp_disabled", "")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) auditLog(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(`SELECT ts,actor,action,detail,remote FROM audit ORDER BY id DESC LIMIT 500`)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type ev struct {
		TS                            int64
		Actor, Action, Detail, Remote string
	}
	out := []ev{}
	for rows.Next() {
		var e ev
		rows.Scan(&e.TS, &e.Actor, &e.Action, &e.Detail, &e.Remote)
		out = append(out, e)
	}
	writeJSON(w, out)
}

// events streams live updates (SSE). Slow clients lose events and are told to resync.
func (s *Server) events(w http.ResponseWriter, r *http.Request) {
	fl, ok := w.(http.Flusher)
	if !ok {
		httpErr(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("X-Accel-Buffering", "no")
	sub := s.Engine.Hub.Subscribe()
	defer s.Engine.Hub.Unsubscribe(sub)
	rc := http.NewResponseController(w)
	keep := time.NewTicker(15 * time.Second)
	defer keep.Stop()
	write := func(typ string, data []byte) error {
		rc.SetWriteDeadline(time.Now().Add(10 * time.Second))
		if _, err := w.Write([]byte("event: " + typ + "\ndata: ")); err != nil {
			return err
		}
		w.Write(data)
		_, err := w.Write([]byte("\n\n"))
		fl.Flush()
		return err
	}
	write("hello", []byte(`{}`))
	for {
		select {
		case <-r.Context().Done():
			return
		case ev := <-sub.C:
			if sub.Resync.Swap(false) {
				d, _ := json.Marshal(map[string]int64{"ui_dropped": sub.Dropped.Load()})
				if write("resync", d) != nil {
					return
				}
			}
			if write(ev.Type, ev.Data) != nil {
				return
			}
		case <-keep.C:
			if write("ping", []byte(`{}`)) != nil {
				return
			}
		}
	}
}

var errNoNetwork = errors.New("network not configured")

package api

import (
	"net/http"
	"strconv"
)

func (s *Server) analysisRoutes(priv func(string, http.HandlerFunc)) {
	priv("GET /api/captures/{id}/conversations", s.withSession(s.conversations))
	priv("GET /api/captures/{id}/endpoints", s.withSession(s.endpoints))
	priv("GET /api/captures/{id}/statistics", s.withSession(s.statistics))
	priv("GET /api/captures/{id}/follow", s.withSession(s.follow))
	priv("GET /api/captures/{id}/dns", s.withSession(s.dns))
	priv("GET /api/captures/{id}/tls", s.withSession(s.tls))
}

func qint(r *http.Request, k string, def int) int {
	if v, err := strconv.Atoi(r.URL.Query().Get(k)); err == nil {
		return v
	}
	return def
}

func (s *Server) conversations(w http.ResponseWriter, r *http.Request, id string) {
	t := r.URL.Query().Get("transport")
	if t == "" {
		t = "tcp"
	}
	c, err := s.Engine.Conversations(r.Context(), id, t)
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, c)
}

func (s *Server) endpoints(w http.ResponseWriter, r *http.Request, id string) {
	c, err := s.Engine.Endpoints(r.Context(), id, qint(r, "limit", 100))
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, c)
}

func (s *Server) statistics(w http.ResponseWriter, r *http.Request, id string) {
	st, err := s.Engine.Statistics(r.Context(), id, qint(r, "buckets", 300))
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, st)
}

func (s *Server) follow(w http.ResponseWriter, r *http.Request, id string) {
	seg := qint(r, "seg", 0)
	stream := qint(r, "stream", -1)
	if stream < 0 {
		httpErr(w, http.StatusBadRequest, "seg and stream are required")
		return
	}
	res, err := s.Engine.FollowTCP(r.Context(), id, seg, stream)
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, res)
}

func (s *Server) dns(w http.ResponseWriter, r *http.Request, id string) {
	recs, err := s.Engine.DNS(r.Context(), id, qint(r, "limit", 5000))
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, recs)
}

func (s *Server) tls(w http.ResponseWriter, r *http.Request, id string) {
	handshakes, certs, err := s.Engine.TLS(r.Context(), id, qint(r, "limit", 5000))
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, map[string]any{"handshakes": handshakes, "certificates": certs,
		"note": "Observed metadata only. In capture-only mode TLS payloads are not decrypted; interception status is 'encrypted pass-through' for every session."})
}

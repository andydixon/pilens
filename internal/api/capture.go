package api

import (
	"errors"
	"fmt"
	"net/http"
	"net/netip"
	"regexp"
	"strconv"
	"strings"
	"time"

	"pilens.dev/pilens/internal/capture"
)

func parsePrefix(s string) (netip.Prefix, error) {
	p, err := netip.ParsePrefix(s)
	return p.Masked(), err
}

var idRe = regexp.MustCompile(`^[0-9TZ]{16}-[0-9a-f]{6}$`)

func (s *Server) captureRoutes(priv func(string, http.HandlerFunc)) {
	priv("GET /api/captures", s.listCaptures)
	priv("POST /api/captures", s.startCapture)
	priv("POST /api/captures/live/stop", s.stopCapture)
	priv("POST /api/captures/live/pause", s.pauseCapture)
	priv("POST /api/captures/import", s.importCapture)
	priv("GET /api/captures/{id}", s.withSession(s.getCapture))
	priv("PATCH /api/captures/{id}", s.withSession(s.patchCapture))
	priv("DELETE /api/captures/{id}", s.withSession(s.deleteCapture))
	priv("GET /api/captures/{id}/packets", s.withSession(s.packets))
	priv("GET /api/captures/{id}/packets/{num}", s.withSession(s.packet))
	priv("GET /api/captures/{id}/export", s.withSession(s.export))
	priv("GET /api/captures/{id}/manifest", s.withSession(s.manifest))
	priv("POST /api/captures/{id}/verify", s.withSession(s.verify))
	priv("POST /api/filters/validate", s.validateFilter)
	priv("GET /api/filters/saved", s.savedFilters)
	priv("POST /api/filters/saved", s.saveFilter)
	priv("DELETE /api/filters/saved/{fid}", s.deleteFilter)
	priv("GET /api/storage", s.storage)
	priv("PUT /api/storage", s.setStorage)
}

func (s *Server) withSession(h func(http.ResponseWriter, *http.Request, string)) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		id := r.PathValue("id")
		if !idRe.MatchString(id) { // ids become directory names: strict whitelist
			httpErr(w, http.StatusBadRequest, "invalid session id")
			return
		}
		if _, err := s.Engine.Get(id); err != nil {
			httpErr(w, http.StatusNotFound, "capture session not found")
			return
		}
		h(w, r, id)
	}
}

func engineErr(w http.ResponseWriter, err error) {
	if errors.Is(err, capture.ErrNotFound) {
		httpErr(w, http.StatusNotFound, err.Error())
		return
	}
	httpErr(w, http.StatusBadRequest, err.Error())
}

func (s *Server) listCaptures(w http.ResponseWriter, r *http.Request) {
	ss, err := s.Engine.Sessions()
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, ss)
}

func (s *Server) startCapture(w http.ResponseWriter, r *http.Request) {
	var o capture.StartOptions
	if !readJSON(w, r, &o) {
		return
	}
	sess, err := s.Engine.Start(r.Context(), o)
	if err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.started", fmt.Sprintf("%s interfaces=%v filter=%q", sess.ID, o.Interfaces, o.CaptureFilter))
	writeJSON(w, sess)
}

func (s *Server) stopCapture(w http.ResponseWriter, r *http.Request) {
	if err := s.Engine.Stop(); err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.stopped", "")
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) pauseCapture(w http.ResponseWriter, r *http.Request) {
	var req struct{ Paused bool }
	if !readJSON(w, r, &req) {
		return
	}
	if err := s.Engine.SetPaused(req.Paused); err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.paused", strconv.FormatBool(req.Paused))
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) importCapture(w http.ResponseWriter, r *http.Request) {
	lim := s.Engine.Limits()
	if r.ContentLength > lim.ImportBytes {
		httpErr(w, http.StatusRequestEntityTooLarge, fmt.Sprintf("file exceeds the import limit of %d bytes", lim.ImportBytes))
		return
	}
	r.Body = http.MaxBytesReader(w, r.Body, lim.ImportBytes+1)
	sess, err := s.Engine.Import(r.Context(), r.URL.Query().Get("name"), r.Body)
	if err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.imported", sess.ID)
	writeJSON(w, sess)
}

func (s *Server) getCapture(w http.ResponseWriter, r *http.Request, id string) {
	sess, _ := s.Engine.Get(id)
	segs, _ := s.Engine.Segments(id)
	writeJSON(w, map[string]any{"session": sess, "segments": segs})
}

func (s *Server) patchCapture(w http.ResponseWriter, r *http.Request, id string) {
	var req struct {
		Name, Description, Tags, Notes string
		Preserved                      bool
	}
	if !readJSON(w, r, &req) {
		return
	}
	if strings.TrimSpace(req.Name) == "" || len(req.Name) > 200 || len(req.Description) > 5000 || len(req.Tags) > 500 || len(req.Notes) > 50000 {
		httpErr(w, http.StatusBadRequest, "invalid field lengths")
		return
	}
	if err := s.Engine.Update(id, req.Name, req.Description, req.Tags, req.Notes, req.Preserved); err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.updated", id)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) deleteCapture(w http.ResponseWriter, r *http.Request, id string) {
	if r.URL.Query().Get("confirm") != id {
		httpErr(w, http.StatusBadRequest, "confirm deletion by passing ?confirm=<session id>")
		return
	}
	if err := s.Engine.Delete(id); err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.deleted", id)
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) packets(w http.ResponseWriter, r *http.Request, id string) {
	q := r.URL.Query()
	off, _ := strconv.ParseInt(q.Get("offset"), 10, 64)
	lim, _ := strconv.ParseInt(q.Get("limit"), 10, 64)
	p, err := s.Engine.Packets(r.Context(), id, q.Get("filter"), off, lim)
	if err != nil {
		engineErr(w, err)
		return
	}
	writeJSON(w, p)
}

func (s *Server) packet(w http.ResponseWriter, r *http.Request, id string) {
	n, err := strconv.ParseInt(r.PathValue("num"), 10, 64)
	if err != nil {
		httpErr(w, http.StatusBadRequest, "invalid packet number")
		return
	}
	d, err := s.Engine.Packet(r.Context(), id, n)
	if err != nil && d.Bytes == "" {
		engineErr(w, err)
		return
	}
	resp := map[string]any{"detail": d}
	if err != nil {
		resp["error"] = err.Error() // bytes available, dissection failed
	}
	writeJSON(w, resp)
}

func (s *Server) export(w http.ResponseWriter, r *http.Request, id string) {
	filter := r.URL.Query().Get("filter")
	format := s.Engine.ExportFormat(id)
	name := id
	if filter != "" {
		name += "-filtered"
	}
	if format == "pcap" {
		w.Header().Set("Content-Type", "application/vnd.tcpdump.pcap")
	} else {
		w.Header().Set("Content-Type", "application/x-pcapng")
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+name+"."+format+`"`)
	s.audit(r, "capture.exported", fmt.Sprintf("%s filter=%q", id, filter))
	if _, err := s.Engine.Export(r.Context(), w, id, filter); err != nil {
		// Headers are gone; the truncated download is the signal. Log it.
		s.audit(r, "capture.export_failed", err.Error())
	}
}

func (s *Server) manifest(w http.ResponseWriter, r *http.Request, id string) {
	m, err := s.Engine.Manifest(id)
	if err != nil {
		engineErr(w, err)
		return
	}
	w.Header().Set("Content-Disposition", `attachment; filename="`+id+`-manifest.json"`)
	s.audit(r, "capture.manifest_exported", id)
	writeJSON(w, m)
}

func (s *Server) verify(w http.ResponseWriter, r *http.Request, id string) {
	v, err := s.Engine.Verify(id)
	if err != nil {
		engineErr(w, err)
		return
	}
	s.audit(r, "capture.verified", id)
	writeJSON(w, v)
}

func (s *Server) validateFilter(w http.ResponseWriter, r *http.Request) {
	var req struct{ Kind, Filter, Interface string }
	if !readJSON(w, r, &req) {
		return
	}
	var err error
	switch req.Kind {
	case "display":
		err = s.Engine.Tools.ValidateDisplayFilter(r.Context(), req.Filter)
	case "capture":
		if req.Interface == "" {
			req.Interface = "any"
		}
		err = s.Engine.Tools.ValidateCaptureFilter(r.Context(), req.Interface, req.Filter)
	default:
		httpErr(w, http.StatusBadRequest, "kind must be display or capture")
		return
	}
	resp := map[string]any{"valid": err == nil}
	if err != nil {
		resp["error"] = err.Error()
	}
	writeJSON(w, resp)
}

func (s *Server) savedFilters(w http.ResponseWriter, r *http.Request) {
	rows, err := s.DB.Query(`SELECT id,name,kind,expr FROM saved_filters ORDER BY name`)
	if err != nil {
		httpErr(w, 500, err.Error())
		return
	}
	defer rows.Close()
	type f struct {
		ID               int64
		Name, Kind, Expr string
	}
	out := []f{}
	for rows.Next() {
		var x f
		rows.Scan(&x.ID, &x.Name, &x.Kind, &x.Expr)
		out = append(out, x)
	}
	writeJSON(w, out)
}

func (s *Server) saveFilter(w http.ResponseWriter, r *http.Request) {
	var req struct{ Name, Kind, Expr string }
	if !readJSON(w, r, &req) {
		return
	}
	if req.Name == "" || len(req.Name) > 100 || len(req.Expr) > 2048 || (req.Kind != "display" && req.Kind != "capture") {
		httpErr(w, http.StatusBadRequest, "invalid filter")
		return
	}
	s.DB.Exec(`INSERT INTO saved_filters(name,kind,expr,created_at) VALUES(?,?,?,?)`, req.Name, req.Kind, req.Expr, time.Now().Unix())
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) deleteFilter(w http.ResponseWriter, r *http.Request) {
	s.DB.Exec(`DELETE FROM saved_filters WHERE id=?`, r.PathValue("fid"))
	writeJSON(w, map[string]bool{"ok": true})
}

func (s *Server) storage(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.Engine.Storage())
}

func (s *Server) setStorage(w http.ResponseWriter, r *http.Request) {
	var l capture.Limits
	if !readJSON(w, r, &l) {
		return
	}
	const mib = 1 << 20
	if l.MaxBytes < 64*mib || l.ReserveBytes < 64*mib || l.SegmentBytes < 1*mib || l.SegmentBytes > 1024*mib || l.ImportBytes < mib || l.ImportBytes > 64<<30 {
		httpErr(w, http.StatusBadRequest, "limits out of range (quota ≥ 64 MiB, reserve ≥ 64 MiB, segment 1-1024 MiB)")
		return
	}
	s.Engine.SetLimits(l)
	s.DB.PutJSON(keyLimits, l)
	s.audit(r, "storage.limits_changed", fmt.Sprintf("%+v", l))
	writeJSON(w, map[string]bool{"ok": true})
}

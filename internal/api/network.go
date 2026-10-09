package api

import (
	"context"
	"encoding/json"
	"net"
	"net/http"
	"strings"
	"time"

	"pilens.dev/pilens/internal/config"
	"pilens.dev/pilens/internal/helper"
	"pilens.dev/pilens/internal/sysinfo"
)

func (s *Server) networkRoutes(priv func(string, http.HandlerFunc)) {
	priv("GET /api/system/interfaces", s.interfaces)
	priv("GET /api/system/health", s.health)
	priv("GET /api/network", s.getNetwork)
	priv("POST /api/network/validate", s.validateNetwork)
	priv("POST /api/network/apply", s.applyNetwork)
	priv("POST /api/setup/complete", s.completeSetup)
	priv("GET /api/ap/clients", s.apClients)
	priv("PUT /api/devices/{mac}", s.updateDevice)
}

func (s *Server) interfaces(w http.ResponseWriter, r *http.Request) {
	var boot config.Management
	s.DB.GetJSON(keyBootstrap, &boot)
	writeJSON(w, map[string]any{
		"interfaces":  sysinfo.Interfaces(),
		"wifi":        sysinfo.WifiCapabilities(),
		"bootstrap":   boot,
		"remote_addr": remoteAddr(r).String(),
	})
}

func (s *Server) helperStatus(ctx context.Context) (helper.Status, string) {
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	var st helper.Status
	if err := s.Helper.Call(ctx, helper.Request{Op: helper.OpStatus}, &st); err != nil {
		return st, err.Error()
	}
	return st, ""
}

func (s *Server) health(w http.ResponseWriter, r *http.Request) {
	h := sysinfo.ReadHealth(map[string]string{"data": s.DataDir, "captures": s.Engine.Dir})
	st, herr := s.helperStatus(r.Context())
	live, running := s.Engine.Live()
	var n config.Network
	configured, _ := s.DB.GetJSON(keyNetwork, &n)
	upstream := map[string]any{"configured": configured}
	if configured {
		routes := sysinfo.DefaultRoutes()
		gw, ok := routes[n.Uplink]
		upstream["interface"] = n.Uplink
		upstream["default_route"] = ok
		upstream["gateway"] = gw
		if i, err := net.InterfaceByName(n.Uplink); err == nil {
			upstream["up"] = i.Flags&net.FlagUp != 0
		}
	}
	writeJSON(w, map[string]any{
		"system":       h,
		"helper":       st,
		"helper_error": herr,
		"capture":      map[string]any{"running": running, "session": live, "tshark": s.Engine.Tools.Version()},
		"storage":      s.Engine.Storage(),
		"upstream":     upstream,
		"version":      s.Version,
		"forwarding":   forwardingState(configured, n, st, herr),
	})
}

// forwardingState is the single prominent answer to "is AP traffic being forwarded?".
func forwardingState(configured bool, n config.Network, st helper.Status, herr string) map[string]string {
	switch {
	case herr != "":
		return map[string]string{"state": "unknown", "detail": "network helper unavailable: " + herr + ". The last loaded firewall table remains in force."}
	case !configured || !st.Configured:
		return map[string]string{"state": "blocked", "detail": "No network configuration has been applied. AP traffic is not forwarded."}
	case !st.TableLoaded:
		return map[string]string{"state": "unprotected", "detail": "The PiLens firewall table is not loaded."}
	case n.Forwarding.Mode != "internet":
		return map[string]string{"state": "blocked", "detail": "Forwarding is disabled by policy."}
	case !st.IPForward:
		return map[string]string{"state": "blocked", "detail": "Kernel IPv4 forwarding is off."}
	}
	return map[string]string{"state": "forwarding", "detail": "AP clients reach public destinations via " + n.Uplink + ". Private and management networks are blocked. IPv6 is blocked."}
}

func (s *Server) getNetwork(w http.ResponseWriter, r *http.Request) {
	var n config.Network
	ok, _ := s.DB.GetJSON(keyNetwork, &n)
	if !ok {
		n = config.DefaultNetwork()
		var b config.Management
		if found, _ := s.DB.GetJSON(keyBootstrap, &b); found {
			n.Management = b
		}
	}
	pass := n.AP.Passphrase != ""
	writeJSON(w, map[string]any{"config": n.Redacted(), "saved": ok, "passphrase_set": pass})
}

// mergeNetwork keeps the stored passphrase when the client leaves it blank.
func (s *Server) mergeNetwork(n *config.Network) {
	if n.AP.Passphrase == "" {
		var old config.Network
		if ok, _ := s.DB.GetJSON(keyNetwork, &old); ok {
			n.AP.Passphrase = old.AP.Passphrase
		}
	}
}

func (s *Server) validateNetwork(w http.ResponseWriter, r *http.Request) {
	var n config.Network
	if !readJSON(w, r, &n) {
		return
	}
	s.mergeNetwork(&n)
	errs := []string{}
	if err := n.Validate(true); err != nil {
		errs = strings.Split(err.Error(), "\n")
	}
	errs = append(errs, s.managementWarnings(r, n)...)
	writeJSON(w, map[string]any{"valid": len(errs) == 0, "errors": errs})
}

// managementWarnings refuses configurations that would lock out the current admin.
func (s *Server) managementWarnings(r *http.Request, n config.Network) []string {
	ra := remoteAddr(r)
	if ra.IsLoopback() {
		return nil
	}
	ok := false
	for _, c := range n.Management.AllowedSubnets {
		if p, err := parsePrefix(c); err == nil && p.Contains(ra) {
			ok = true
		}
	}
	if !ok {
		return []string{"your current address " + ra.String() + " is not inside any management subnet: applying would lock you out"}
	}
	return nil
}

func (s *Server) applyNetwork(w http.ResponseWriter, r *http.Request) {
	var n config.Network
	if !readJSON(w, r, &n) {
		return
	}
	s.mergeNetwork(&n)
	if err := n.Validate(true); err != nil {
		httpErr(w, http.StatusBadRequest, err.Error())
		return
	}
	if warn := s.managementWarnings(r, n); len(warn) > 0 {
		httpErr(w, http.StatusBadRequest, warn[0])
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()
	var res helper.ApplyResult
	err := s.Helper.Call(ctx, helper.Request{Op: helper.OpApplyNetwork, Network: &n}, &res)
	red, _ := json.Marshal(n.Redacted())
	if err != nil {
		s.audit(r, "network.apply_failed", err.Error())
		w.WriteHeader(http.StatusBadGateway)
		writeJSON(w, map[string]any{"error": err.Error(), "result": res})
		return
	}
	s.DB.PutJSON(keyNetwork, n)
	s.reloadMgmt()
	s.audit(r, "network.applied", string(red))
	writeJSON(w, map[string]any{"result": res})
}

func (s *Server) completeSetup(w http.ResponseWriter, r *http.Request) {
	var n config.Network
	if ok, _ := s.DB.GetJSON(keyNetwork, &n); !ok {
		httpErr(w, http.StatusConflict, "apply a network configuration first")
		return
	}
	s.DB.PutJSON(keySetupDone, true)
	s.audit(r, "setup.completed", "")
	writeJSON(w, map[string]bool{"ok": true})
}

type apClient struct {
	MAC         string `json:"mac"`
	IP          string `json:"ip"`
	Hostname    string `json:"hostname"`
	Label       string `json:"label"`
	Notes       string `json:"notes"`
	Associated  bool   `json:"associated"`
	SignalDBm   *int   `json:"signal_dbm,omitempty"`
	RxBytes     uint64 `json:"rx_bytes"`
	TxBytes     uint64 `json:"tx_bytes"`
	ConnectedS  int64  `json:"connected_s"`
	InactiveMS  int64  `json:"inactive_ms"`
	LeaseExpiry int64  `json:"lease_expiry"`
	FirstSeen   int64  `json:"first_seen"`
	LastSeen    int64  `json:"last_seen"`
	Randomised  bool   `json:"randomised_mac"`
}

func (s *Server) apClients(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 15*time.Second)
	defer cancel()
	var leases []helper.Lease
	var stations []helper.Station
	var errs []string
	if err := s.Helper.Call(ctx, helper.Request{Op: helper.OpLeases}, &leases); err != nil {
		errs = append(errs, "leases: "+err.Error())
	}
	if err := s.Helper.Call(ctx, helper.Request{Op: helper.OpStations}, &stations); err != nil {
		errs = append(errs, "stations: "+err.Error())
	}
	now := time.Now().Unix()
	by := map[string]*apClient{}
	get := func(mac string) *apClient {
		if c := by[mac]; c != nil {
			return c
		}
		c := &apClient{MAC: mac}
		if hw, err := net.ParseMAC(mac); err == nil && len(hw) > 0 {
			c.Randomised = hw[0]&0x02 != 0 // locally administered bit
		}
		by[mac] = c
		return c
	}
	for _, l := range leases {
		c := get(l.MAC)
		c.IP, c.Hostname, c.LeaseExpiry = l.IP, l.Hostname, l.Expiry
	}
	for _, st := range stations {
		c := get(st.MAC)
		c.Associated = true
		c.SignalDBm, c.RxBytes, c.TxBytes, c.ConnectedS, c.InactiveMS = st.SignalDBm, st.RxBytes, st.TxBytes, st.ConnectedS, st.InactiveMS
	}
	for mac, c := range by {
		seen := now
		if !c.Associated {
			seen = 0
		}
		s.DB.Exec(`INSERT INTO devices(mac,hostname,last_ip,first_seen,last_seen) VALUES(?,?,?,?,?)
			ON CONFLICT(mac) DO UPDATE SET hostname=CASE WHEN excluded.hostname!='' THEN excluded.hostname ELSE hostname END,
			last_ip=CASE WHEN excluded.last_ip!='' THEN excluded.last_ip ELSE last_ip END,
			last_seen=MAX(last_seen,excluded.last_seen)`, mac, c.Hostname, c.IP, now, seen)
		s.DB.QueryRow(`SELECT label,notes,first_seen,last_seen FROM devices WHERE mac=?`, mac).Scan(&c.Label, &c.Notes, &c.FirstSeen, &c.LastSeen)
	}
	out := []apClient{}
	for _, c := range by {
		out = append(out, *c)
	}
	// Known devices not currently present.
	rows, err := s.DB.Query(`SELECT mac,label,notes,hostname,last_ip,first_seen,last_seen FROM devices ORDER BY last_seen DESC LIMIT 200`)
	if err == nil {
		defer rows.Close()
		for rows.Next() {
			var c apClient
			rows.Scan(&c.MAC, &c.Label, &c.Notes, &c.Hostname, &c.IP, &c.FirstSeen, &c.LastSeen)
			if by[c.MAC] == nil {
				out = append(out, c)
			}
		}
	}
	writeJSON(w, map[string]any{"clients": out, "errors": errs})
}

func (s *Server) updateDevice(w http.ResponseWriter, r *http.Request) {
	hw, err := net.ParseMAC(r.PathValue("mac"))
	if err != nil {
		httpErr(w, http.StatusBadRequest, "invalid MAC")
		return
	}
	var req struct{ Label, Notes string }
	if !readJSON(w, r, &req) {
		return
	}
	if len(req.Label) > 100 || len(req.Notes) > 10000 {
		httpErr(w, http.StatusBadRequest, "label or notes too long")
		return
	}
	now := time.Now().Unix()
	s.DB.Exec(`INSERT INTO devices(mac,label,notes,first_seen,last_seen) VALUES(?,?,?,?,0) ON CONFLICT(mac) DO UPDATE SET label=excluded.label, notes=excluded.notes`, hw.String(), req.Label, req.Notes, now)
	s.audit(r, "device.updated", hw.String())
	writeJSON(w, map[string]bool{"ok": true})
}

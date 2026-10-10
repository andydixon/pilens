// Package helper defines the request protocol between the unprivileged core and
// the root pilens-helper. Every operation is fixed and typed; there is no generic
// command execution.
package helper

import (
	"context"
	"encoding/json"
	"errors"
	"net"
	"time"

	"pilens.dev/pilens/internal/config"
)

const DefaultSocket = "/run/pilens/helper.sock"

type Request struct {
	Op               string          `json:"op"`
	Network          *config.Network `json:"network,omitempty"`
	InterceptEnabled bool            `json:"intercept_enabled,omitempty"`
	InterceptPort    int             `json:"intercept_port,omitempty"`
}

type Response struct {
	OK    bool            `json:"ok"`
	Error string          `json:"error,omitempty"`
	Data  json.RawMessage `json:"data,omitempty"`
}

// Operation names.
const (
	OpApplyNetwork = "apply_network"
	OpStatus       = "status"
	OpStations     = "stations"
	OpLeases       = "leases"
	OpSetInterception = "set_interception"
)

type ApplyResult struct {
	Applied    bool     `json:"applied"`
	RolledBack bool     `json:"rolled_back"`
	Steps      []string `json:"steps"`
	Error      string   `json:"error,omitempty"`
}

type Status struct {
	TableLoaded   bool   `json:"table_loaded"`
	APState       string `json:"ap_state"` // NM GENERAL.STATE or "absent"
	DnsmasqActive bool   `json:"dnsmasq_active"`
	IPForward     bool   `json:"ip_forward"`
	Regdomain     string `json:"regdomain"`
	Configured    bool   `json:"configured"`
	LastError     string `json:"last_error,omitempty"`
}

type Station struct {
	MAC        string `json:"mac"`
	SignalDBm  *int   `json:"signal_dbm,omitempty"`
	RxBytes    uint64 `json:"rx_bytes"`
	TxBytes    uint64 `json:"tx_bytes"`
	ConnectedS int64  `json:"connected_s"`
	InactiveMS int64  `json:"inactive_ms"`
}

type Lease struct {
	Expiry   int64  `json:"expiry"` // unix seconds; 0 = infinite
	MAC      string `json:"mac"`
	IP       string `json:"ip"`
	Hostname string `json:"hostname"`
}

// Client talks to the helper socket.
type Client struct{ Socket string }

func (c Client) Call(ctx context.Context, req Request, out any) error {
	d := net.Dialer{}
	conn, err := d.DialContext(ctx, "unix", c.Socket)
	if err != nil {
		return errors.New("network helper unavailable: " + err.Error())
	}
	defer conn.Close()
	dl, ok := ctx.Deadline()
	if !ok {
		dl = time.Now().Add(2 * time.Minute)
	}
	conn.SetDeadline(dl)
	if err := json.NewEncoder(conn).Encode(req); err != nil {
		return err
	}
	var resp Response
	if err := json.NewDecoder(conn).Decode(&resp); err != nil {
		return err
	}
	if out != nil && len(resp.Data) > 0 {
		if err := json.Unmarshal(resp.Data, out); err != nil {
			return err
		}
	}
	if !resp.OK {
		return errors.New(resp.Error)
	}
	return nil
}

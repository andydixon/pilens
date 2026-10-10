-- Intercepted HTTP(S) transactions (Mode B). Populated only while interception
-- is enabled and only for devices that trust the installed CA.
CREATE TABLE http_flows (
	id TEXT PRIMARY KEY,
	ts REAL NOT NULL,
	client TEXT NOT NULL DEFAULT '',
	method TEXT NOT NULL DEFAULT '',
	scheme TEXT NOT NULL DEFAULT '',
	host TEXT NOT NULL DEFAULT '',
	port INTEGER NOT NULL DEFAULT 0,
	path TEXT NOT NULL DEFAULT '',
	http_version TEXT NOT NULL DEFAULT '',
	status INTEGER NOT NULL DEFAULT 0,
	reason TEXT NOT NULL DEFAULT '',
	req_ctype TEXT NOT NULL DEFAULT '',
	resp_ctype TEXT NOT NULL DEFAULT '',
	req_size INTEGER NOT NULL DEFAULT 0,
	resp_size INTEGER NOT NULL DEFAULT 0,
	duration_ms INTEGER NOT NULL DEFAULT 0,
	tls_version TEXT NOT NULL DEFAULT '',
	sni TEXT NOT NULL DEFAULT '',
	alpn TEXT NOT NULL DEFAULT '',
	intercepted INTEGER NOT NULL DEFAULT 0,  -- 1 = decrypted, 0 = passthrough/failed
	error TEXT NOT NULL DEFAULT '',
	websocket INTEGER NOT NULL DEFAULT 0,
	has_req_body INTEGER NOT NULL DEFAULT 0,
	has_resp_body INTEGER NOT NULL DEFAULT 0,
	req_headers TEXT NOT NULL DEFAULT '{}',
	resp_headers TEXT NOT NULL DEFAULT '{}'
);
CREATE INDEX http_flows_ts ON http_flows(ts);
CREATE INDEX http_flows_host ON http_flows(host);
CREATE INDEX http_flows_client ON http_flows(client);

CREATE TABLE settings (
	key TEXT PRIMARY KEY,
	value TEXT NOT NULL,
	updated_at INTEGER NOT NULL
);

CREATE TABLE users (
	id INTEGER PRIMARY KEY,
	username TEXT NOT NULL UNIQUE,
	password_hash TEXT NOT NULL,
	totp_secret TEXT NOT NULL DEFAULT '',
	totp_enabled INTEGER NOT NULL DEFAULT 0,
	created_at INTEGER NOT NULL
);

CREATE TABLE sessions (
	token_hash TEXT PRIMARY KEY,
	user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
	csrf TEXT NOT NULL,
	created_at INTEGER NOT NULL,
	last_seen INTEGER NOT NULL,
	expires_at INTEGER NOT NULL,
	remote TEXT NOT NULL DEFAULT ''
);

CREATE TABLE audit (
	id INTEGER PRIMARY KEY,
	ts INTEGER NOT NULL,
	actor TEXT NOT NULL,
	action TEXT NOT NULL,
	detail TEXT NOT NULL DEFAULT '',
	remote TEXT NOT NULL DEFAULT ''
);
CREATE INDEX audit_ts ON audit(ts);

-- A device is keyed by observed MAC address. Randomised MACs mean a physical
-- device may appear as several rows; nothing here merges them automatically.
CREATE TABLE devices (
	mac TEXT PRIMARY KEY,
	label TEXT NOT NULL DEFAULT '',
	notes TEXT NOT NULL DEFAULT '',
	hostname TEXT NOT NULL DEFAULT '',
	last_ip TEXT NOT NULL DEFAULT '',
	first_seen INTEGER NOT NULL,
	last_seen INTEGER NOT NULL
);

CREATE TABLE capture_sessions (
	id TEXT PRIMARY KEY,
	name TEXT NOT NULL,
	description TEXT NOT NULL DEFAULT '',
	kind TEXT NOT NULL,              -- live | import
	state TEXT NOT NULL,             -- running | stopped | failed | ready
	interfaces TEXT NOT NULL DEFAULT '[]',
	capture_filter TEXT NOT NULL DEFAULT '',
	started_at INTEGER NOT NULL,     -- unix ms UTC
	ended_at INTEGER NOT NULL DEFAULT 0,
	packets INTEGER NOT NULL DEFAULT 0,
	bytes INTEGER NOT NULL DEFAULT 0,
	drops TEXT NOT NULL DEFAULT '',  -- capture-engine drop report, verbatim
	error TEXT NOT NULL DEFAULT '',
	preserved INTEGER NOT NULL DEFAULT 0,
	tags TEXT NOT NULL DEFAULT '',
	notes TEXT NOT NULL DEFAULT '',
	dir TEXT NOT NULL,
	meta TEXT NOT NULL DEFAULT '{}', -- versions, clock sync, parameters
	ring_segments INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE segments (
	session_id TEXT NOT NULL REFERENCES capture_sessions(id) ON DELETE CASCADE,
	seq INTEGER NOT NULL,
	file TEXT NOT NULL,
	format TEXT NOT NULL,            -- pcapng | pcap
	base INTEGER NOT NULL,           -- global number of the first packet
	count INTEGER NOT NULL DEFAULT 0,
	bytes INTEGER NOT NULL DEFAULT 0,
	sha256 TEXT NOT NULL DEFAULT '',
	complete INTEGER NOT NULL DEFAULT 0,
	deleted INTEGER NOT NULL DEFAULT 0,
	PRIMARY KEY (session_id, seq)
);

-- One summary row per packet. Full dissection is produced on demand by tshark.
CREATE TABLE packets (
	session_id TEXT NOT NULL,
	num INTEGER NOT NULL,
	seg INTEGER NOT NULL,
	off INTEGER NOT NULL,
	ts REAL NOT NULL,
	src TEXT NOT NULL,
	dst TEXT NOT NULL,
	proto TEXT NOT NULL,
	len INTEGER NOT NULL,
	info TEXT NOT NULL,
	sport INTEGER,
	dport INTEGER,
	stream INTEGER,
	tcpflags TEXT,
	ttl INTEGER,
	vlan INTEGER,
	color TEXT,
	PRIMARY KEY (session_id, num)
) WITHOUT ROWID;

CREATE TABLE saved_filters (
	id INTEGER PRIMARY KEY,
	name TEXT NOT NULL,
	kind TEXT NOT NULL,              -- display | capture
	expr TEXT NOT NULL,
	created_at INTEGER NOT NULL
);

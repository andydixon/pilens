// Package store opens the SQLite database and applies migrations.
package store

import (
	"database/sql"
	"encoding/json"
	"fmt"
	"io/fs"
	"sort"
	"time"

	_ "modernc.org/sqlite"

	"pilens.dev/pilens/migrations"
)

type Store struct{ *sql.DB }

func Open(path string) (*Store, error) {
	dsn := "file:" + path + "?_pragma=journal_mode(WAL)&_pragma=foreign_keys(1)&_pragma=busy_timeout(5000)&_pragma=synchronous(NORMAL)"
	db, err := sql.Open("sqlite", dsn)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(4)
	s := &Store{db}
	if err := s.migrate(); err != nil {
		db.Close()
		return nil, err
	}
	return s, nil
}

func (s *Store) migrate() error {
	if _, err := s.Exec(`CREATE TABLE IF NOT EXISTS schema_migrations (name TEXT PRIMARY KEY, applied_at INTEGER NOT NULL)`); err != nil {
		return err
	}
	names, err := fs.Glob(migrations.FS, "*.sql")
	if err != nil {
		return err
	}
	sort.Strings(names)
	for _, n := range names {
		var x int
		if s.QueryRow(`SELECT 1 FROM schema_migrations WHERE name=?`, n).Scan(&x) == nil {
			continue
		}
		b, _ := migrations.FS.ReadFile(n)
		tx, err := s.Begin()
		if err != nil {
			return err
		}
		if _, err := tx.Exec(string(b)); err != nil {
			tx.Rollback()
			return fmt.Errorf("migration %s: %w", n, err)
		}
		tx.Exec(`INSERT INTO schema_migrations VALUES (?,?)`, n, time.Now().Unix())
		if err := tx.Commit(); err != nil {
			return err
		}
	}
	return nil
}

func (s *Store) GetJSON(key string, v any) (bool, error) {
	var raw string
	err := s.QueryRow(`SELECT value FROM settings WHERE key=?`, key).Scan(&raw)
	if err == sql.ErrNoRows {
		return false, nil
	}
	if err != nil {
		return false, err
	}
	return true, json.Unmarshal([]byte(raw), v)
}

func (s *Store) PutJSON(key string, v any) error {
	b, err := json.Marshal(v)
	if err != nil {
		return err
	}
	_, err = s.Exec(`INSERT INTO settings(key,value,updated_at) VALUES(?,?,?) ON CONFLICT(key) DO UPDATE SET value=excluded.value, updated_at=excluded.updated_at`, key, string(b), time.Now().Unix())
	return err
}

func (s *Store) Audit(actor, action, detail, remote string) {
	s.Exec(`INSERT INTO audit(ts,actor,action,detail,remote) VALUES(?,?,?,?,?)`, time.Now().UnixMilli(), actor, action, detail, remote)
}

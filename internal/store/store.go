package store

import (
	"context"
	"crypto/sha256"
	"database/sql"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"time"

	"github.com/ErzenXz/fortmend/internal/model"
	_ "modernc.org/sqlite"
)

type Retention struct {
	RawEvents time.Duration
	Findings  time.Duration
	Audit     time.Duration
}

type Store struct {
	db        *sql.DB
	retention Retention
}

func Open(path string, retention Retention) (*Store, error) {
	if retention.RawEvents <= 0 {
		retention.RawEvents = 30 * 24 * time.Hour
	}
	if retention.Findings <= 0 {
		retention.Findings = 180 * 24 * time.Hour
	}
	if retention.Audit <= 0 {
		retention.Audit = 180 * 24 * time.Hour
	}
	db, err := sql.Open("sqlite", path)
	if err != nil {
		return nil, err
	}
	db.SetMaxOpenConns(1)
	store := &Store{db: db, retention: retention}
	if err := store.migrate(context.Background()); err != nil {
		db.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) Close() error { return s.db.Close() }

func (s *Store) migrate(ctx context.Context) error {
	_, err := s.db.ExecContext(ctx, `
PRAGMA journal_mode=WAL;
PRAGMA foreign_keys=ON;
CREATE TABLE IF NOT EXISTS events (
  id TEXT PRIMARY KEY,
  observed_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS findings (
  id TEXT PRIMARY KEY,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL,
  payload BLOB NOT NULL
);
CREATE TABLE IF NOT EXISTS audit (
  sequence INTEGER PRIMARY KEY AUTOINCREMENT,
  recorded_at TEXT NOT NULL,
  kind TEXT NOT NULL,
  object_id TEXT NOT NULL,
  previous_hash TEXT NOT NULL,
  hash TEXT NOT NULL UNIQUE
);`)
	return err
}

func (s *Store) Ingest(ctx context.Context, event model.SecurityEvent, findings []model.Finding) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	var exists int
	if err := tx.QueryRowContext(ctx, `SELECT 1 FROM events WHERE id = ?`, event.ID).Scan(&exists); err == nil {
		return tx.Commit()
	} else if err != sql.ErrNoRows {
		return err
	}
	eventPayload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	eventExpiry := event.ObservedAt.Add(s.retention.RawEvents)
	if _, err := tx.ExecContext(ctx, `INSERT INTO events(id, observed_at, expires_at, payload) VALUES(?,?,?,?)`,
		event.ID, formatTime(event.ObservedAt), formatTime(eventExpiry), eventPayload); err != nil {
		return fmt.Errorf("insert event: %w", err)
	}
	previousHash, err := latestAuditHash(ctx, tx)
	if err != nil {
		return err
	}
	previousHash, err = appendAudit(ctx, tx, previousHash, "security_event", event.ID, eventPayload)
	if err != nil {
		return err
	}
	for _, finding := range findings {
		payload, err := json.Marshal(finding)
		if err != nil {
			return err
		}
		expiresAt := finding.CreatedAt.Add(s.retention.Findings)
		if _, err := tx.ExecContext(ctx, `INSERT INTO findings(id, created_at, expires_at, payload) VALUES(?,?,?,?)`,
			finding.ID, formatTime(finding.CreatedAt), formatTime(expiresAt), payload); err != nil {
			return fmt.Errorf("insert finding: %w", err)
		}
		previousHash, err = appendAudit(ctx, tx, previousHash, "finding", finding.ID, payload)
		if err != nil {
			return err
		}
	}
	return tx.Commit()
}

func (s *Store) ListEvents(ctx context.Context, limit int) ([]model.SecurityEvent, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM events ORDER BY observed_at DESC LIMIT ?`, boundedLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.SecurityEvent
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var event model.SecurityEvent
		if err := json.Unmarshal(payload, &event); err != nil {
			return nil, err
		}
		result = append(result, event)
	}
	return result, rows.Err()
}

func (s *Store) ListFindings(ctx context.Context, limit int) ([]model.Finding, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT payload FROM findings ORDER BY created_at DESC LIMIT ?`, boundedLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.Finding
	for rows.Next() {
		var payload []byte
		if err := rows.Scan(&payload); err != nil {
			return nil, err
		}
		var finding model.Finding
		if err := json.Unmarshal(payload, &finding); err != nil {
			return nil, err
		}
		result = append(result, finding)
	}
	return result, rows.Err()
}

func (s *Store) ListAudit(ctx context.Context, limit int) ([]model.AuditRecord, error) {
	rows, err := s.db.QueryContext(ctx, `SELECT sequence, recorded_at, kind, object_id, previous_hash, hash FROM audit ORDER BY sequence ASC LIMIT ?`, boundedLimit(limit))
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var result []model.AuditRecord
	for rows.Next() {
		var record model.AuditRecord
		var at string
		if err := rows.Scan(&record.Sequence, &at, &record.Kind, &record.ObjectID, &record.PreviousHash, &record.Hash); err != nil {
			return nil, err
		}
		record.RecordedAt, err = time.Parse(time.RFC3339Nano, at)
		if err != nil {
			return nil, err
		}
		result = append(result, record)
	}
	return result, rows.Err()
}

func (s *Store) Prune(ctx context.Context, now time.Time) error {
	tx, err := s.db.BeginTx(ctx, nil)
	if err != nil {
		return err
	}
	defer tx.Rollback()
	if _, err := tx.ExecContext(ctx, `DELETE FROM events WHERE expires_at < ?`, formatTime(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM findings WHERE expires_at < ?`, formatTime(now)); err != nil {
		return err
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM audit WHERE recorded_at < ?`, formatTime(now.Add(-s.retention.Audit))); err != nil {
		return err
	}
	return tx.Commit()
}

func latestAuditHash(ctx context.Context, tx *sql.Tx) (string, error) {
	var hash string
	err := tx.QueryRowContext(ctx, `SELECT hash FROM audit ORDER BY sequence DESC LIMIT 1`).Scan(&hash)
	if err == sql.ErrNoRows {
		return "", nil
	}
	return hash, err
}

func appendAudit(ctx context.Context, tx *sql.Tx, previousHash, kind, objectID string, payload []byte) (string, error) {
	digest := sha256.Sum256(append([]byte(previousHash+"\n"+kind+"\n"+objectID+"\n"), payload...))
	hash := hex.EncodeToString(digest[:])
	_, err := tx.ExecContext(ctx, `INSERT INTO audit(recorded_at, kind, object_id, previous_hash, hash) VALUES(?,?,?,?,?)`,
		formatTime(time.Now().UTC()), kind, objectID, previousHash, hash)
	return hash, err
}

func formatTime(value time.Time) string { return value.UTC().Format(time.RFC3339Nano) }

func boundedLimit(limit int) int {
	if limit <= 0 {
		return 100
	}
	if limit > 1000 {
		return 1000
	}
	return limit
}

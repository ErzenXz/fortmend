package store_test

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/store"
)

func TestSQLiteStoreIngestsEventFindingAndAuditChain(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "fortmend.db"), store.Retention{
		RawEvents: 30 * 24 * time.Hour,
		Findings:  180 * 24 * time.Hour,
	})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	event := model.SecurityEvent{
		SchemaVersion: model.SchemaVersion,
		ID:            "event-1",
		DeviceID:      "device-1",
		ObservedAt:    time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC),
		Source:        "fixture",
		Kind:          "malware.signature_match",
		Severity:      model.SeverityCritical,
		Confidence:    1,
	}
	finding := model.Finding{
		SchemaVersion: model.SchemaVersion,
		ID:            "finding-1",
		DeviceID:      "device-1",
		CreatedAt:     event.ObservedAt,
		Title:         "Known malware signature detected",
		Severity:      model.SeverityCritical,
		Confidence:    1,
		Deterministic: true,
		EventIDs:      []string{event.ID},
	}
	if err := db.Ingest(context.Background(), event, []model.Finding{finding}); err != nil {
		t.Fatal(err)
	}

	events, err := db.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events=%#v err=%v", events, err)
	}
	findings, err := db.ListFindings(context.Background(), 10)
	if err != nil || len(findings) != 1 || findings[0].ID != finding.ID {
		t.Fatalf("findings=%#v err=%v", findings, err)
	}
	audit, err := db.ListAudit(context.Background(), 10)
	if err != nil || len(audit) != 2 || audit[0].Hash == "" || audit[1].PreviousHash != audit[0].Hash {
		t.Fatalf("audit chain=%#v err=%v", audit, err)
	}
}

func TestDuplicateEventIngestionIsIdempotent(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "fortmend.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := model.SecurityEvent{SchemaVersion: model.SchemaVersion, ID: "event-1", DeviceID: "device-1", ObservedAt: time.Now().UTC(), Source: "fixture", Kind: "host.inventory", Confidence: 1}
	if err := db.Ingest(context.Background(), event, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Ingest(context.Background(), event, nil); err != nil {
		t.Fatalf("duplicate ingest failed: %v", err)
	}
	events, _ := db.ListEvents(context.Background(), 10)
	audit, _ := db.ListAudit(context.Background(), 10)
	if len(events) != 1 || len(audit) != 1 {
		t.Fatalf("duplicate created records: events=%d audit=%d", len(events), len(audit))
	}
}

func TestPruneAppliesConfiguredRetention(t *testing.T) {
	now := time.Now().UTC()
	db, err := store.Open(filepath.Join(t.TempDir(), "fortmend.db"), store.Retention{RawEvents: time.Hour, Findings: time.Hour, Audit: 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	event := model.SecurityEvent{SchemaVersion: model.SchemaVersion, ID: "expired-event", DeviceID: "device-1", ObservedAt: now.Add(-2 * time.Hour), Source: "fixture", Kind: "host.inventory", Confidence: 1}
	if err := db.Ingest(context.Background(), event, nil); err != nil {
		t.Fatal(err)
	}
	if err := db.Prune(context.Background(), now); err != nil {
		t.Fatal(err)
	}
	events, _ := db.ListEvents(context.Background(), 10)
	audit, _ := db.ListAudit(context.Background(), 10)
	if len(events) != 0 || len(audit) != 1 {
		t.Fatalf("retention mismatch: events=%d audit=%d", len(events), len(audit))
	}
}

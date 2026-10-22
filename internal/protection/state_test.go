package protection

import (
	"context"
	"encoding/json"
	"github.com/ErzenXz/aegis/internal/agent"
	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
	"os"
	"path/filepath"
	"testing"
	"time"
)

func TestResponseOutboxSurvivesQueueCapacityFailure(t *testing.T) {
	state := t.TempDir()
	queuePath := filepath.Join(state, "queue.jsonl")
	q, err := agent.OpenQueue(queuePath, 1)
	if err != nil {
		t.Fatal(err)
	}
	r := &Runtime{DeviceID: "vm", StateDir: state, Queue: q, Post: func(context.Context, model.SecurityEvent) error { return nil }, PollInterval: time.Second, AssessmentInterval: time.Minute}
	if err := r.initialize(); err != nil {
		t.Fatal(err)
	}
	result := sensors.Observation{Kind: "remediation.quarantined", Confidence: 1, Attributes: map[string]string{"status": "contained", "receiptPath": "/private/receipt"}}
	if err := r.saveResponse(context.Background(), result); err == nil {
		t.Fatal("capacity failure expected")
	}
	if _, err := os.Stat(filepath.Join(state, "response-outbox.json")); err != nil {
		t.Fatal("result lost despite durable action receipt", err)
	}
	q, err = agent.OpenQueue(queuePath, 1<<20)
	if err != nil {
		t.Fatal(err)
	}
	r.Queue = q
	if err := r.flushResponse(context.Background()); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(state, "response-outbox.json")); !os.IsNotExist(err) {
		t.Fatal("staged result not acknowledged")
	}
	var delivered []model.SecurityEvent
	if err := q.Drain(context.Background(), func(_ context.Context, e model.SecurityEvent) error { delivered = append(delivered, e); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(delivered) != 1 || delivered[0].Kind != "remediation.quarantined" || delivered[0].Attributes["status"] != "contained" {
		t.Fatal("wrong replay", delivered)
	}
}

func TestEventHistoryRotationIsBoundedAndPreservesEvents(t *testing.T) {
	path := filepath.Join(t.TempDir(), "history.jsonl")
	log := &EventLog{Path: path, MaxBytes: 256}
	for _, id := range []string{"one", "two", "three", "four"} {
		if err := log.Append(context.Background(), model.SecurityEvent{ID: id, ObservedAt: time.Now()}); err != nil {
			t.Fatal(err)
		}
	}
	for _, p := range []string{path, path + ".previous"} {
		data, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		if len(data) > 256 {
			t.Fatal("log bound exceeded")
		}
		var event model.SecurityEvent
		if err := json.Unmarshal(data, &event); err != nil {
			t.Fatal("partial log record", err)
		}
	}
}

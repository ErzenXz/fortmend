package agent_test

import (
	"context"
	"errors"
	"path/filepath"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/agent"
	"github.com/ErzenXz/aegis/internal/model"
)

func TestOfflineQueueRetainsFailedEventsAndDrainsInOrder(t *testing.T) {
	queue, err := agent.OpenQueue(filepath.Join(t.TempDir(), "events.jsonl"), 1024*1024)
	if err != nil {
		t.Fatal(err)
	}
	for _, id := range []string{"event-1", "event-2"} {
		if err := queue.Push(model.SecurityEvent{SchemaVersion: model.SchemaVersion, ID: id, DeviceID: "device-1", ObservedAt: time.Now().UTC(), Source: "fixture", Kind: "host.inventory", Confidence: 1}); err != nil {
			t.Fatal(err)
		}
	}
	if err := queue.Drain(context.Background(), func(context.Context, model.SecurityEvent) error { return errors.New("offline") }); err == nil {
		t.Fatal("expected offline drain error")
	}
	var sent []string
	if err := queue.Drain(context.Background(), func(_ context.Context, event model.SecurityEvent) error {
		sent = append(sent, event.ID)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(sent) != 2 || sent[0] != "event-1" || sent[1] != "event-2" || queue.Len() != 0 {
		t.Fatalf("sent=%v remaining=%d", sent, queue.Len())
	}
}

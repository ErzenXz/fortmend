package sensors_test

import (
	"context"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

type oneShotAdapter struct{}

func (oneShotAdapter) Name() string { return "fixture" }

func (oneShotAdapter) Run(_ context.Context, emit func(sensors.Observation) error) error {
	return emit(sensors.Observation{
		ObservedAt: time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC),
		Kind:       "host.posture",
		Severity:   model.SeverityInfo,
		Confidence: 1,
		Attributes: map[string]string{"os": "test"},
	})
}

func TestStreamNormalizesAdapterObservation(t *testing.T) {
	stream := sensors.NewStream("device-1", oneShotAdapter{})
	var got []model.SecurityEvent
	err := stream.Start(context.Background(), func(event model.SecurityEvent) error {
		got = append(got, event)
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatalf("expected one event, got %d", len(got))
	}
	if got[0].SchemaVersion != model.SchemaVersion || got[0].DeviceID != "device-1" || got[0].Source != "fixture" || got[0].ID == "" {
		t.Fatalf("observation was not normalized: %#v", got[0])
	}
}

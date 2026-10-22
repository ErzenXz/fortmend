package sensors

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"time"

	"github.com/ErzenXz/fortmend/internal/model"
)

type Observation struct {
	ObservedAt  time.Time
	Kind        string
	Severity    model.Severity
	Confidence  float64
	DetectorIDs []string
	Attributes  map[string]string
}

type Adapter interface {
	Name() string
	Run(context.Context, func(Observation) error) error
}

type Sink func(model.SecurityEvent) error

type Stream struct {
	deviceID string
	adapters []Adapter
}

func NewStream(deviceID string, adapters ...Adapter) *Stream {
	return &Stream{deviceID: deviceID, adapters: adapters}
}

// Start is the sensor module's interface. Platform adapters emit observations;
// callers receive only normalized, versioned security events.
func (s *Stream) Start(ctx context.Context, sink Sink) error {
	for _, adapter := range s.adapters {
		err := adapter.Run(ctx, func(observation Observation) error {
			observedAt := observation.ObservedAt
			if observedAt.IsZero() {
				observedAt = time.Now().UTC()
			}
			return sink(model.SecurityEvent{
				SchemaVersion: model.SchemaVersion,
				ID:            newEventID(),
				DeviceID:      s.deviceID,
				ObservedAt:    observedAt,
				Source:        adapter.Name(),
				Kind:          observation.Kind,
				Severity:      observation.Severity,
				Confidence:    observation.Confidence,
				DetectorIDs:   append([]string(nil), observation.DetectorIDs...),
				Attributes:    cloneMap(observation.Attributes),
			})
		})
		if err != nil {
			return fmt.Errorf("sensor %s: %w", adapter.Name(), err)
		}
	}
	return nil
}

func newEventID() string {
	var bytes [16]byte
	if _, err := rand.Read(bytes[:]); err != nil {
		panic(fmt.Sprintf("secure event id: %v", err))
	}
	return "event-" + hex.EncodeToString(bytes[:])
}

func cloneMap(input map[string]string) map[string]string {
	if input == nil {
		return nil
	}
	output := make(map[string]string, len(input))
	for key, value := range input {
		output[key] = value
	}
	return output
}

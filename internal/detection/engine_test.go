package detection_test

import (
	"fmt"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/detection"
	"github.com/ErzenXz/fortmend/internal/model"
)

func TestKnownMalwareEventBecomesCriticalDeterministicFinding(t *testing.T) {
	engine := detection.New(detection.DefaultPolicy())
	event := model.SecurityEvent{
		SchemaVersion: model.SchemaVersion,
		ID:            "event-1",
		DeviceID:      "device-1",
		ObservedAt:    time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC),
		Source:        "yara",
		Kind:          "malware.signature_match",
		Severity:      model.SeverityCritical,
		Confidence:    1,
		DetectorIDs:   []string{"yara:EICAR-Test-File"},
		Attributes:    map[string]string{"path": "/tmp/eicar.com", "sha256": "fixture"},
	}

	findings := engine.Evaluate(event)
	if len(findings) != 1 {
		t.Fatalf("expected one finding, got %d", len(findings))
	}
	finding := findings[0]
	if finding.Severity != model.SeverityCritical || finding.Confidence != 1 {
		t.Fatalf("unexpected risk: severity=%s confidence=%v", finding.Severity, finding.Confidence)
	}
	if !finding.Deterministic {
		t.Fatal("signature-backed finding must be deterministic")
	}
	if finding.EventIDs[0] != event.ID || finding.DeviceID != event.DeviceID {
		t.Fatalf("finding lost event provenance: %#v", finding)
	}
}

func TestBurstOfFileChangesCorrelatesIntoRansomwareFinding(t *testing.T) {
	engine := detection.New(detection.DefaultPolicy())
	base := time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC)
	var findings []model.Finding
	for i := 0; i < 50; i++ {
		findings = engine.Evaluate(model.SecurityEvent{
			SchemaVersion: model.SchemaVersion,
			ID:            fmt.Sprintf("event-%d", i),
			DeviceID:      "device-1",
			ObservedAt:    base.Add(time.Duration(i) * 100 * time.Millisecond),
			Source:        "file-integrity",
			Kind:          "file.modified",
			Severity:      model.SeverityMedium,
			Confidence:    1,
			DetectorIDs:   []string{"behavior:file-write-burst"},
			Attributes:    map[string]string{"processId": "4242", "path": fmt.Sprintf("/data/file-%d", i)},
		})
	}

	if len(findings) != 1 {
		t.Fatalf("expected a finding at the 50-event threshold, got %d", len(findings))
	}
	if findings[0].Title != "Ransomware-like file modification burst" || findings[0].Confidence < 0.95 {
		t.Fatalf("unexpected ransomware finding: %#v", findings[0])
	}
}

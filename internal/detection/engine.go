package detection

import (
	"crypto/sha256"
	"encoding/hex"
	"sync"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
)

type Policy struct {
	DeterministicKinds map[string]string
	FileBurstThreshold int
	FileBurstWindow    time.Duration
}

func DefaultPolicy() Policy {
	return Policy{
		DeterministicKinds: map[string]string{
			"malware.signature_match":  "Known malware signature detected",
			"vulnerability.detected":   "Vulnerable software requires remediation",
			"persistence.suspicious":   "Suspicious persistence change detected",
			"authentication.anomaly":   "Suspicious authentication activity detected",
			"webshell.suspicious":      "Suspicious PHP execution pattern detected",
			"process.suspicious":       "Suspicious process activity detected",
			"autonomy.audit_requested": "Scheduled autonomous VM security audit",
			"response.failed":          "Automated response requires investigation",
			"patching.failed":          "Security update or verification failed",
		},
		FileBurstThreshold: 50,
		FileBurstWindow:    10 * time.Second,
	}
}

type Engine struct {
	policy Policy
	mu     sync.Mutex
	bursts map[string][]burstEvent
}

func New(policy Policy) *Engine {
	return &Engine{policy: policy, bursts: make(map[string][]burstEvent)}
}

type burstEvent struct {
	id string
	at time.Time
}

// Evaluate is the detection module's interface. It returns findings derived
// from one normalized event and never performs host mutations.
func (e *Engine) Evaluate(event model.SecurityEvent) []model.Finding {
	if event.Kind == "file.modified" {
		if finding := e.evaluateFileBurst(event); finding != nil {
			return []model.Finding{*finding}
		}
	}
	title, ok := e.policy.DeterministicKinds[event.Kind]
	if !ok {
		return nil
	}
	digest := sha256.Sum256([]byte(event.DeviceID + "\x00" + event.ID + "\x00" + event.Kind))
	return []model.Finding{{
		SchemaVersion: model.SchemaVersion,
		ID:            "finding-" + hex.EncodeToString(digest[:8]),
		DeviceID:      event.DeviceID,
		CreatedAt:     event.ObservedAt,
		Title:         title,
		Severity:      event.Severity,
		Confidence:    event.Confidence,
		Deterministic: true,
		DetectorIDs:   append([]string(nil), event.DetectorIDs...),
		EventIDs:      []string{event.ID},
	}}
}

func (e *Engine) evaluateFileBurst(event model.SecurityEvent) *model.Finding {
	processID := event.Attributes["processId"]
	if processID == "" || e.policy.FileBurstThreshold <= 0 || e.policy.FileBurstWindow <= 0 {
		return nil
	}
	key := event.DeviceID + "\x00" + processID
	cutoff := event.ObservedAt.Add(-e.policy.FileBurstWindow)

	e.mu.Lock()
	defer e.mu.Unlock()
	window := e.bursts[key][:0]
	for _, previous := range e.bursts[key] {
		if !previous.at.Before(cutoff) {
			window = append(window, previous)
		}
	}
	window = append(window, burstEvent{id: event.ID, at: event.ObservedAt})
	e.bursts[key] = window
	if len(window) < e.policy.FileBurstThreshold {
		return nil
	}
	delete(e.bursts, key)
	eventIDs := make([]string, len(window))
	for i := range window {
		eventIDs[i] = window[i].id
	}
	digest := sha256.Sum256([]byte(key + "\x00" + window[0].at.UTC().Format(time.RFC3339Nano)))
	return &model.Finding{
		SchemaVersion: model.SchemaVersion,
		ID:            "finding-" + hex.EncodeToString(digest[:8]),
		DeviceID:      event.DeviceID,
		CreatedAt:     event.ObservedAt,
		Title:         "Ransomware-like file modification burst",
		Severity:      model.SeverityCritical,
		Confidence:    0.98,
		Deterministic: true,
		DetectorIDs:   []string{"behavior:file-write-burst"},
		EventIDs:      eventIDs,
	}
}

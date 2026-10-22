// Package remediation provides narrowly scoped, recoverable containment.
// Quarantining an indicator never establishes that a host is uncompromised.
package remediation

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"sync"

	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/sensors"
)

type Quarantine struct {
	StateDir   string
	WebRoots   []string
	mu         sync.Mutex
	beforeMove func() // Internal synchronization seam for deterministic race tests.
}

func (q *Quarantine) Apply(ctx context.Context, event model.SecurityEvent) (sensors.Observation, error) {
	q.mu.Lock()
	defer q.mu.Unlock()
	if err := ctx.Err(); err != nil {
		return sensors.Observation{}, err
	}
	path, err := q.validate(event)
	if err != nil {
		return sensors.Observation{}, err
	}
	return q.apply(ctx, event, path)
}

// Replay delivers durable containment receipts after a crash, then records
// delivery only after emit succeeds. Apply deliberately never acknowledges
// receipt delivery; duplicate observations after a crash are possible.
func (q *Quarantine) Replay(ctx context.Context, emit func(sensors.Observation) error) error {
	q.mu.Lock()
	defer q.mu.Unlock()
	if emit == nil {
		return errors.New("quarantine replay requires an observation sink")
	}
	return q.replay(ctx, emit)
}

func within(root, path string) bool {
	return path != root && strings.HasPrefix(path, root+string(filepath.Separator))
}
func (q *Quarantine) validate(event model.SecurityEvent) (string, error) {
	if event.Kind != "webshell.suspicious" || !(event.Confidence >= .99 && event.Confidence <= 1) || event.Attributes["quarantineEligible"] != "true" {
		return "", errors.New("quarantine requires a high confidence eligible webshell event")
	}
	path := event.Attributes["path"]
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return "", errors.New("quarantine requires a clean absolute file path")
	}
	ext := strings.ToLower(filepath.Ext(path))
	if ext != ".php" && ext != ".phtml" && ext != ".php3" && ext != ".php5" && ext != ".inc" {
		return "", errors.New("quarantine target must be a configured PHP file")
	}
	if !filepath.IsAbs(q.StateDir) || filepath.Clean(q.StateDir) != q.StateDir {
		return "", errors.New("quarantine requires a clean absolute state directory")
	}
	switch q.StateDir {
	case "/", "/etc", "/usr", "/var", "/tmp", "/home":
		return "", errors.New("quarantine refuses broad state directory")
	}
	matched := false
	for _, root := range q.WebRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) != root {
			return "", errors.New("webroot must be a clean absolute directory")
		}
		switch root {
		case "/", "/etc", "/usr", "/var", "/tmp", "/home":
			return "", fmt.Errorf("quarantine refuses broad webroot %s", root)
		}
		if q.StateDir == root || within(root, q.StateDir) {
			return "", errors.New("quarantine state must be outside all served webroots")
		}
		if within(root, path) {
			matched = true
		}
	}
	if !matched {
		return "", errors.New("target is outside configured webroots")
	}
	digest, err := hex.DecodeString(event.Attributes["sha256"])
	if err != nil || len(digest) != 32 {
		return "", errors.New("event requires a SHA-256 digest")
	}
	if event.Attributes["signature"] != "php-request-command-execution" && event.Attributes["signature"] != "php-request-decoded-eval" {
		return "", errors.New("event signature is not eligible for containment")
	}
	return path, nil
}

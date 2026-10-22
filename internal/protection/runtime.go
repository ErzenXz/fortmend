// Package protection coordinates independent collection, assessment, delivery,
// and AI investigation loops. Hub outages never disable local protection.
package protection

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"

	"github.com/ErzenXz/aegis/internal/agent"
	"github.com/ErzenXz/aegis/internal/detection"
	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/reasoner"
	"github.com/ErzenXz/aegis/internal/sensors"
)

type Runtime struct {
	DeviceID, StateDir               string
	Queue                            *agent.Queue
	Post                             func(context.Context, model.SecurityEvent) error
	Monitor, Assessment, Updater     sensors.Adapter
	Reasoner                         reasoner.Reasoner
	Contain                          func(context.Context, model.SecurityEvent) (sensors.Observation, error)
	Verify                           func(context.Context) error
	VerifyEvent                      func(context.Context, model.SecurityEvent) error
	Reconcile                        func(context.Context) error
	FullControl                      bool
	AuditInterval                    time.Duration
	PollInterval, AssessmentInterval time.Duration
	Report                           func(error)
	heavy                            sync.Mutex
	jobsMu                           sync.Mutex
	jobs                             map[string]job
	wake                             chan struct{}
	engine                           *detection.Engine
	responseMu                       sync.Mutex
}

type job struct {
	Event       model.SecurityEvent   `json:"event"`
	CompletedAt time.Time             `json:"completedAt,omitempty"`
	RetryAt     time.Time             `json:"retryAt,omitempty"`
	Related     []model.SecurityEvent `json:"related,omitempty"`
}

func (r *Runtime) initialize() error {
	if r.DeviceID == "" || r.Queue == nil || r.Post == nil || r.PollInterval <= 0 || r.AssessmentInterval <= 0 {
		return errors.New("invalid protection runtime configuration")
	}
	if !filepath.IsAbs(r.StateDir) {
		return errors.New("absolute runtime state directory required")
	}
	if err := os.MkdirAll(r.StateDir, 0700); err != nil {
		return err
	}
	r.wake = make(chan struct{}, 1)
	r.engine = detection.New(detection.DefaultPolicy())
	r.jobs = map[string]job{}
	data, err := os.ReadFile(filepath.Join(r.StateDir, "investigations.json"))
	if err != nil && !os.IsNotExist(err) {
		return err
	}
	if len(data) > 4*1024*1024 {
		return errors.New("investigation state exceeds bound")
	}
	if len(data) > 0 {
		if err := json.Unmarshal(data, &r.jobs); err != nil {
			return err
		}
	}
	return nil
}

func (r *Runtime) saveJobs() error {
	data, err := json.Marshal(r.jobs)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(r.StateDir, ".investigations-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(f.Name(), filepath.Join(r.StateDir, "investigations.json"))
}

func fingerprint(e model.SecurityEvent) string {
	p, _ := json.Marshal(struct {
		Kind       string
		Attributes map[string]string
	}{e.Kind, e.Attributes})
	sum := sha256.Sum256(p)
	return hex.EncodeToString(sum[:])
}

func (r *Runtime) emit(ctx context.Context, source string, o sensors.Observation) error {
	return sensors.NewStream(r.DeviceID, observationAdapter{source, o}).Start(ctx, func(e model.SecurityEvent) error {
		if err := r.Queue.Push(e); err != nil {
			return err
		}
		if r.Reasoner != nil && len(r.engine.Evaluate(e)) > 0 && (e.Severity == model.SeverityHigh || e.Severity == model.SeverityCritical) {
			r.jobsMu.Lock()
			defer r.jobsMu.Unlock()
			key := fingerprint(e)
			if r.FullControl {
				seenKey := "seen:" + key
				ttl := 6 * time.Hour
				if e.Kind == "autonomy.audit_requested" && r.AuditInterval > 0 {
					ttl = r.AuditInterval
				}
				if seen, ok := r.jobs[seenKey]; ok && time.Since(seen.CompletedAt) < ttl {
					return nil
				}
				for k, j := range r.jobs {
					if !j.CompletedAt.IsZero() && time.Since(j.CompletedAt) >= 6*time.Hour {
						delete(r.jobs, k)
					}
				}
				// Group by incident kind so a CVE burst cannot crowd out an urgent
				// webshell or authentication incident. Full batches are not marked seen.
				key = "full-control:" + e.Kind
				pending := r.jobs[key]
				if pending.Event.ID == "" || !pending.CompletedAt.IsZero() {
					pending = job{Event: e}
				} else if len(pending.Related) < 63 {
					pending.Related = append(pending.Related, e)
				} else {
					if e.Kind == "vulnerability.detected" || e.Kind == "autonomy.audit_requested" {
						return r.emit(ctx, "codex", sensors.Observation{Kind: "investigation.deferred", Severity: model.SeverityMedium, Confidence: 1, Attributes: map[string]string{"eventId": e.ID, "reason": "bounded CVE context full; event retained and not marked investigated; next assessment retries"}})
					}
					// Preserve additional urgent incidents in bounded overflow batches.
					retained := false
					for i := 1; i <= 8; i++ {
						overflow := fmt.Sprintf("%s:%d", key, i)
						next := r.jobs[overflow]
						if next.Event.ID == "" || !next.CompletedAt.IsZero() {
							next = job{Event: e}
						} else if len(next.Related) < 63 {
							next.Related = append(next.Related, e)
						} else {
							continue
						}
						key, pending, retained = overflow, next, true
						break
					}
					if !retained {
						return fmt.Errorf("urgent investigation backlog full; collection must retry")
					}
				}
				r.jobs[key] = pending
				if len(r.jobs) < 512 {
					r.jobs[seenKey] = job{CompletedAt: time.Now().UTC()}
				}
				if err := r.saveJobs(); err != nil {
					return err
				}
				select {
				case r.wake <- struct{}{}:
				default:
				}
				return nil
			}
			if old, ok := r.jobs[key]; ok && (old.CompletedAt.IsZero() || time.Since(old.CompletedAt) < 6*time.Hour) {
				return nil
			}
			for k, j := range r.jobs {
				if !j.CompletedAt.IsZero() && time.Since(j.CompletedAt) > 6*time.Hour {
					delete(r.jobs, k)
				}
			}
			if len(r.jobs) >= 128 {
				// Preserve telemetry even when optional AI capacity is exhausted.
				return r.emit(ctx, "codex", sensors.Observation{Kind: "investigation.deferred", Severity: model.SeverityMedium, Confidence: 1, Attributes: map[string]string{"eventId": e.ID, "reason": "AI backlog full; observation retained; next assessment retries"}})
			}
			r.jobs[key] = job{Event: e}
			if err := r.saveJobs(); err != nil {
				delete(r.jobs, key)
				return err
			}
			select {
			case r.wake <- struct{}{}:
			default:
			}
		}
		return nil
	})
}

type observationAdapter struct {
	source string
	o      sensors.Observation
}

func (a observationAdapter) Name() string { return a.source }
func (a observationAdapter) Run(_ context.Context, emit func(sensors.Observation) error) error {
	return emit(a.o)
}

func (r *Runtime) collect(ctx context.Context, a sensors.Adapter) error {
	if a == nil {
		return nil
	}
	if err := r.flushResponse(ctx); err != nil {
		return err
	}
	if r.Reconcile != nil {
		if err := r.Reconcile(ctx); err != nil {
			return err
		}
	}
	err := a.Run(ctx, func(o sensors.Observation) error {
		if err := r.emit(ctx, a.Name(), o); err != nil {
			return err
		}
		if r.Contain != nil && o.Kind == "webshell.suspicious" && o.Attributes["quarantineEligible"] == "true" {
			e := model.SecurityEvent{ID: o.Attributes["occurrenceId"], Kind: o.Kind, Confidence: o.Confidence, Attributes: o.Attributes}
			result, err := r.Contain(ctx, e)
			if err != nil {
				if result.Kind != "" {
					if emitErr := r.saveResponse(ctx, result); emitErr != nil {
						return errors.Join(err, emitErr)
					}
				}
				emitErr := r.emit(ctx, "quarantine", sensors.Observation{Kind: "response.failed", Severity: model.SeverityHigh, Confidence: 1, Attributes: map[string]string{"action": "file.quarantine", "error": err.Error(), "path": o.Attributes["path"]}})
				return errors.Join(err, emitErr)
			}
			return r.saveResponse(ctx, result)
		}
		return nil
	})
	if err != nil && ctx.Err() == nil {
		_ = r.emit(ctx, a.Name(), sensors.Observation{Kind: "sensor.failed", Severity: model.SeverityMedium, Confidence: 1, Attributes: map[string]string{"error": err.Error(), "sensor": a.Name(), "status": "degraded"}})
	}
	return err
}

func (r *Runtime) assess(ctx context.Context) error {
	r.heavy.Lock()
	defer r.heavy.Unlock()
	// Inventory failure does not prevent security updates, and an updater failure
	// does not prevent the post-update assessment. All failures remain visible.
	before := r.collect(ctx, r.Assessment)
	patch := r.collect(ctx, r.Updater)
	var after error
	if r.Updater != nil {
		after = r.collect(ctx, r.Assessment)
	}
	var audit error
	if r.FullControl {
		audit = r.emit(ctx, "autonomy", sensors.Observation{Kind: "autonomy.audit_requested", Severity: model.SeverityHigh, Confidence: 1, Attributes: map[string]string{"scope": "this VM; installed services, exposed ports, application dependencies, persistence and recent security events"}})
	}
	return errors.Join(before, patch, after, audit)
}

var ErrUnresolved = errors.New("original finding is unresolved")

func unresolvedOnly(err error) bool {
	if err == ErrUnresolved {
		return true
	}
	if joined, ok := err.(interface{ Unwrap() []error }); ok {
		items := joined.Unwrap()
		if len(items) == 0 {
			return false
		}
		for _, item := range items {
			if !unresolvedOnly(item) {
				return false
			}
		}
		return true
	}
	if wrapped, ok := err.(interface{ Unwrap() error }); ok {
		return unresolvedOnly(wrapped.Unwrap())
	}
	return false
}

func (r *Runtime) investigate(ctx context.Context) error {
	var failures []error
	for {
		r.jobsMu.Lock()
		var key string
		var current job
		for k, j := range r.jobs {
			if j.Event.ID != "" && j.CompletedAt.IsZero() && !time.Now().Before(j.RetryAt) {
				key, current = k, j
				break
			}
		}
		r.jobsMu.Unlock()
		if key == "" {
			return errors.Join(failures...)
		}
		r.heavy.Lock()
		e := current.Event
		incident := model.IncidentCase{SchemaVersion: model.SchemaVersion, ID: "case-" + e.ID, DeviceID: r.DeviceID, FindingIDs: []string{e.ID}, Evidence: []model.Evidence{{Kind: e.Kind, CollectedAt: e.ObservedAt, Summary: "Normalized endpoint observation", Attributes: e.Attributes, Redacted: true}}}
		for _, related := range current.Related {
			incident.FindingIDs = append(incident.FindingIDs, related.ID)
			incident.Evidence = append(incident.Evidence, model.Evidence{Kind: related.Kind, CollectedAt: related.ObservedAt, Summary: "Related normalized endpoint observation", Attributes: related.Attributes, Redacted: true})
		}
		timeout := 3 * time.Minute
		if r.FullControl {
			timeout = 15 * time.Minute
		}
		callCtx, cancel := context.WithTimeout(ctx, timeout)
		proposal, err := r.Reasoner.Investigate(callCtx, incident)
		cancel()
		if err == nil {
			payload, _ := json.Marshal(proposal)
			err = r.emit(ctx, "codex", sensors.Observation{Kind: "investigation.completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"eventId": e.ID, "proposal": string(payload), "verification": "pending"}})
			// The model's completion alone is not verification. Always inspect the
			// actual host again, including newly installed package versions.
			if err == nil {
				targets := append([]model.SecurityEvent{e}, current.Related...)
				var checks []error
				checks = append(checks, r.verifyAssessment(ctx, targets...))
				if r.Verify != nil {
					checks = append(checks, r.Verify(ctx))
				}
				if r.VerifyEvent != nil {
					for _, target := range targets {
						checks = append(checks, r.VerifyEvent(ctx, target))
					}
				}
				err = errors.Join(checks...)
			}
			if err == nil {
				kind := "investigation.checked"
				if e.Kind == "vulnerability.detected" || e.Kind == "webshell.suspicious" && r.VerifyEvent != nil {
					kind = "investigation.verified"
				}
				err = r.emit(ctx, "verification", sensors.Observation{Kind: kind, Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"eventId": e.ID, "scope": "original finding checked against fresh assessment and configured host health; residual findings remain visible", "hostClean": "not_asserted"}})
			}
		}
		r.heavy.Unlock()
		r.jobsMu.Lock()
		latest := r.jobs[key]
		if err == nil || unresolvedOnly(err) {
			current.CompletedAt = time.Now().UTC()
			if len(latest.Related) > len(current.Related) {
				extra := latest.Related[len(current.Related):]
				current = job{Event: extra[0], Related: extra[1:]}
			}
		} else {
			current = latest
			current.RetryAt = time.Now().Add(5 * time.Minute)
		}
		r.jobs[key] = current
		saveErr := r.saveJobs()
		r.jobsMu.Unlock()
		if err != nil {
			failures = append(failures, err)
			kind, retry := "investigation.failed", "5m"
			if unresolvedOnly(err) {
				kind, retry = "investigation.unresolved", "next changed evidence or 6h"
			}
			_ = r.emit(ctx, "codex", sensors.Observation{Kind: kind, Severity: model.SeverityMedium, Confidence: 1, Attributes: map[string]string{"eventId": e.ID, "error": err.Error(), "retry": retry}})
			r.report(err)
		}
		if saveErr != nil {
			r.report(saveErr)
			return errors.Join(append(failures, saveErr)...)
		}
		if ctx.Err() != nil {
			return errors.Join(append(failures, ctx.Err())...)
		}
	}
}

func (r *Runtime) verifyAssessment(ctx context.Context, originals ...model.SecurityEvent) error {
	if r.Assessment == nil {
		return errors.New("verification assessment is unavailable")
	}
	completed := false
	unresolved := false
	err := r.Assessment.Run(ctx, func(o sensors.Observation) error {
		if o.Kind == "vulnerability.scan_completed" && (o.Attributes["status"] == "complete" || o.Attributes["status"] == "complete_with_unknowns") {
			completed = true
		}
		for _, original := range originals {
			sameSource := original.Attributes["sourcePackage"] != "" && o.Attributes["sourcePackage"] == original.Attributes["sourcePackage"]
			if original.Kind == "vulnerability.detected" && (o.Kind == "vulnerability.detected" || o.Kind == "vulnerability.unknown") && o.Attributes["vulnerabilityId"] == original.Attributes["vulnerabilityId"] && (sameSource || o.Attributes["package"] == original.Attributes["package"]) {
				unresolved = true
			}
			if original.Kind == "vulnerability.detected" && o.Kind == "vulnerability.coverage_unknown" && sameSource {
				unresolved = true
			}
		}
		// Verification records residual findings without recursively scheduling new
		// AI work from its own rescan. The next scheduled assessment can retry.
		return sensors.NewStream(r.DeviceID, observationAdapter{r.Assessment.Name(), o}).Start(ctx, r.Queue.Push)
	})
	if err != nil {
		return err
	}
	if !completed {
		return errors.New("verification scan did not establish completed package coverage")
	}
	if unresolved {
		return fmt.Errorf("%w: one or more batch vulnerabilities remain affected or undetermined after investigation", ErrUnresolved)
	}
	return nil
}

func (r *Runtime) report(err error) {
	if err != nil && r.Report != nil {
		r.Report(err)
	}
}

func (r *Runtime) RecordActivity(ctx context.Context, attributes map[string]string) error {
	kind := "autonomy.tool_completed"
	if attributes["phase"] == "item/started" {
		kind = "autonomy.tool_started"
	}
	return r.emit(ctx, "codex", sensors.Observation{Kind: kind, Severity: model.SeverityInfo, Confidence: 1, Attributes: attributes})
}

func (r *Runtime) RecordResponse(ctx context.Context, o sensors.Observation) error {
	return r.saveResponse(ctx, o)
}

func (r *Runtime) Run(ctx context.Context, once bool) error {
	if err := r.initialize(); err != nil {
		return err
	}
	if once {
		monitorErr := r.collect(ctx, r.Monitor)
		assessmentErr := r.assess(ctx)
		var investigationErr error
		if r.Reasoner != nil {
			investigationErr = r.investigate(ctx)
		}
		return errors.Join(monitorErr, assessmentErr, investigationErr, r.Queue.Drain(ctx, r.Post))
	}
	var wg sync.WaitGroup
	loop := func(interval time.Duration, task func() error) {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(interval)
			defer ticker.Stop()
			for {
				r.report(task())
				select {
				case <-ctx.Done():
					return
				case <-ticker.C:
				}
			}
		}()
	}
	loop(r.PollInterval, func() error { return r.collect(ctx, r.Monitor) })
	loop(r.AssessmentInterval, func() error { return r.assess(ctx) })
	loop(r.PollInterval, func() error { return r.Queue.Drain(ctx, r.Post) })
	if r.Reasoner != nil {
		wg.Add(1)
		go func() {
			defer wg.Done()
			ticker := time.NewTicker(time.Minute)
			defer ticker.Stop()
			for {
				r.investigate(ctx)
				select {
				case <-ctx.Done():
					return
				case <-r.wake:
				case <-ticker.C:
				}
			}
		}()
	}
	<-ctx.Done()
	wg.Wait()
	return nil
}

func ValidateIntervals(poll, assessment time.Duration) error {
	if poll < time.Second || assessment < time.Minute {
		return fmt.Errorf("poll must be >=1s and assessment >=1m")
	}
	return nil
}

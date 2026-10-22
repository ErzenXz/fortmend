package protection_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"reflect"
	"sync/atomic"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/agent"
	"github.com/ErzenXz/fortmend/internal/detection"
	"github.com/ErzenXz/fortmend/internal/hub"
	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/monitor"
	"github.com/ErzenXz/fortmend/internal/protection"
	"github.com/ErzenXz/fortmend/internal/sensors"
	"github.com/ErzenXz/fortmend/internal/store"
)

type adapter struct {
	name string
	run  func(context.Context, func(sensors.Observation) error) error
}

func (a adapter) Name() string { return a.name }
func (a adapter) Run(ctx context.Context, emit func(sensors.Observation) error) error {
	return a.run(ctx, emit)
}

type investigateFunc func(context.Context, model.IncidentCase) (model.ResponseProposal, error)

func (f investigateFunc) Investigate(ctx context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
	return f(ctx, c)
}

type emptyJournal struct{}

func (emptyJournal) Run(_ context.Context, name string, _ ...string) ([]byte, error) {
	if name != "journalctl" {
		return nil, fmt.Errorf("unexpected command %s", name)
	}
	return nil, nil
}

func queueAt(t *testing.T, path string) *agent.Queue {
	t.Helper()
	q, err := agent.OpenQueue(path, 4<<20)
	if err != nil {
		t.Fatal(err)
	}
	return q
}
func fixtureRuntime(t *testing.T, state string, post func(context.Context, model.SecurityEvent) error) *protection.Runtime {
	t.Helper()
	return &protection.Runtime{DeviceID: "fixture-vm", StateDir: state, Queue: queueAt(t, filepath.Join(state, "events.ndjson")), Post: post, PollInterval: 5 * time.Millisecond, AssessmentInterval: time.Hour}
}
func eventAdapter(o sensors.Observation) sensors.Adapter {
	return adapter{"fixture", func(_ context.Context, emit func(sensors.Observation) error) error { return emit(o) }}
}
func shellObservation() sensors.Observation {
	return sensors.Observation{Kind: "webshell.suspicious", Severity: model.SeverityHigh, Confidence: .99, DetectorIDs: []string{"fortmend:fixture-shell"}, Attributes: map[string]string{"path": "/var/www/fixture/hack.php", "sha256": "fixture-sha", "occurrenceId": "fixture-occurrence", "signature": "php-request-command-execution", "quarantineEligible": "true"}}
}
func containsKind(events []model.SecurityEvent, kind string) bool {
	for _, e := range events {
		if e.Kind == kind {
			return true
		}
	}
	return false
}

func TestRuntimeMonitorOfflineQueueRestartAndRealHubFindings(t *testing.T) {
	root := t.TempDir()
	path := filepath.Join(root, "hack.php")
	if err := os.WriteFile(path, []byte("<?php system($_GET['cmd']);"), 0600); err != nil {
		t.Fatal(err)
	}
	state := t.TempDir()
	monitorConfig := monitor.Config{StateDir: filepath.Join(state, "monitor"), WebRoots: []string{root}, Runner: emptyJournal{}, PersistencePaths: []string{}}
	r := fixtureRuntime(t, filepath.Join(state, "runtime"), func(context.Context, model.SecurityEvent) error { return errors.New("hub offline") })
	r.Monitor = monitor.New(monitorConfig)
	if err := r.Run(context.Background(), true); err == nil {
		t.Fatal("offline delivery was not reported")
	}
	if r.Queue.Len() != 1 {
		t.Fatalf("detected shell not durably queued: %d", r.Queue.Len())
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "hub.db"), store.Retention{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := httptest.NewServer(hub.New(db, detection.New(detection.DefaultPolicy())))
	defer server.Close()
	post := func(ctx context.Context, event model.SecurityEvent) error {
		payload, err := json.Marshal(event)
		if err != nil {
			return err
		}
		req, err := http.NewRequestWithContext(ctx, http.MethodPost, server.URL+"/api/v1/events", bytes.NewReader(payload))
		if err != nil {
			return err
		}
		req.Header.Set("Content-Type", "application/json")
		response, err := server.Client().Do(req)
		if err != nil {
			return err
		}
		defer response.Body.Close()
		if response.StatusCode != http.StatusAccepted {
			return fmt.Errorf("ingest status %d", response.StatusCode)
		}
		return nil
	}
	restarted := fixtureRuntime(t, r.StateDir, post)
	restarted.Monitor = monitor.New(monitorConfig)
	if restarted.Queue.Len() != 1 {
		t.Fatal("queue did not survive restart")
	}
	if err := restarted.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if restarted.Queue.Len() != 0 {
		t.Fatal("hub-accepted event remained queued")
	}
	response, err := server.Client().Get(server.URL + "/api/v1/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var findings []model.Finding
	if err := json.NewDecoder(response.Body).Decode(&findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || len(findings[0].EventIDs) != 1 || findings[0].DeviceID != "fixture-vm" {
		t.Fatalf("missing actual hub finding: %+v", findings)
	}
	events, err := db.ListEvents(context.Background(), 10)
	if err != nil {
		t.Fatal(err)
	}
	if len(events) != 1 || events[0].Kind != "webshell.suspicious" || events[0].Attributes["path"] != path || len(events[0].Attributes["sha256"]) != 64 || len(events[0].Attributes["occurrenceId"]) != 64 || findings[0].EventIDs[0] != events[0].ID {
		t.Fatalf("evidence/finding linkage lost: %+v", events)
	}
}

func TestRuntimeSecurityUpdateTriggersFreshInstalledVersionAssessment(t *testing.T) {
	var version atomic.Value
	version.Store("1.0-vulnerable")
	var events []model.SecurityEvent
	r := fixtureRuntime(t, t.TempDir(), func(_ context.Context, e model.SecurityEvent) error { events = append(events, e); return nil })
	r.Assessment = adapter{"package-scanner", func(_ context.Context, emit func(sensors.Observation) error) error {
		return emit(sensors.Observation{Kind: "host.package_inventory", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"package": "php8.3", "installedVersion": version.Load().(string)}})
	}}
	r.Updater = adapter{"security-updater", func(_ context.Context, emit func(sensors.Observation) error) error {
		version.Store("1.1-fixed")
		return emit(sensors.Observation{Kind: "patching.completed", Severity: model.SeverityInfo, Confidence: 1})
	}}
	if err := r.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if len(events) != 3 || events[0].Attributes["installedVersion"] != "1.0-vulnerable" || events[1].Kind != "patching.completed" || events[2].Attributes["installedVersion"] != "1.1-fixed" {
		t.Fatalf("before/update/after ordering broken: %+v", events)
	}
}

func TestRuntimeReasonerReceivesEvidenceAndFailedChecksNeverVerify(t *testing.T) {
	for _, failure := range []string{"assessment", "health"} {
		t.Run(failure, func(t *testing.T) {
			var events []model.SecurityEvent
			var incident model.IncidentCase
			calls := 0
			checks := 0
			r := fixtureRuntime(t, t.TempDir(), func(_ context.Context, e model.SecurityEvent) error { events = append(events, e); return nil })
			observation := shellObservation()
			r.Monitor = eventAdapter(observation)
			r.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
				incident = c
				calls++
				return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "Fixture investigation completed"}, nil
			})
			r.Assessment = adapter{"assessment", func(_ context.Context, emit func(sensors.Observation) error) error {
				if failure == "assessment" {
					return errors.New("installed-package query failed")
				}
				return emit(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete"}})
			}}
			r.Verify = func(context.Context) error { checks++; return errors.New("PHP service health check failed") }
			_ = r.Run(context.Background(), true)
			if calls != 1 || len(incident.Evidence) != 1 || incident.Evidence[0].Kind != observation.Kind || !reflect.DeepEqual(incident.Evidence[0].Attributes, observation.Attributes) {
				t.Fatalf("wrong model evidence: %+v calls=%d", incident, calls)
			}
			if !containsKind(events, "investigation.completed") || !containsKind(events, "investigation.failed") || containsKind(events, "investigation.verified") {
				t.Fatalf("failed verification misreported: %+v", events)
			}
			if checks != 1 {
				t.Fatal("independent configured health verifier was skipped")
			}
			for _, event := range events {
				if event.Kind == "webshell.suspicious" {
					if len(incident.FindingIDs) != 1 || incident.FindingIDs[0] != event.ID || incident.ID != "case-"+event.ID {
						t.Fatal("normalized evidence event ID not cited")
					}
				}
			}
		})
	}
}

func TestRuntimeBlockedHubDoesNotStallMonitoring(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	entered := make(chan struct{}, 1)
	var polls atomic.Int32
	r := fixtureRuntime(t, t.TempDir(), func(ctx context.Context, _ model.SecurityEvent) error {
		select {
		case entered <- struct{}{}:
		default:
		}
		<-ctx.Done()
		return ctx.Err()
	})
	r.Monitor = adapter{"live", func(_ context.Context, emit func(sensors.Observation) error) error {
		polls.Add(1)
		return emit(sensors.Observation{Kind: "host.inventory", Severity: model.SeverityInfo, Confidence: 1})
	}}
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, false) }()
	select {
	case <-entered:
	case <-time.After(2 * time.Second):
		cancel()
		t.Fatal("delivery never started")
	}
	deadline := time.Now().Add(time.Second)
	for polls.Load() < 5 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if polls.Load() < 5 {
		cancel()
		t.Fatal("blocked network delivery stalled attack monitoring")
	}
	if r.Queue.Len() < 4 {
		cancel()
		t.Fatal("offline observations were not buffered")
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("runtime failed to stop after cancellation")
	}
}

func TestRuntimeDurableInvestigationRetryRestartAndCompletedDedup(t *testing.T) {
	state := t.TempDir()
	post := func(context.Context, model.SecurityEvent) error { return nil }
	observation := shellObservation()
	firstCalls := 0
	r := fixtureRuntime(t, state, post)
	r.Monitor = eventAdapter(observation)
	r.Reasoner = investigateFunc(func(context.Context, model.IncidentCase) (model.ResponseProposal, error) {
		firstCalls++
		return model.ResponseProposal{}, errors.New("AI auth temporarily unavailable")
	})
	if err := r.Run(context.Background(), true); err == nil {
		t.Fatal("failed one-shot AI investigation was not surfaced")
	}
	if firstCalls != 1 {
		t.Fatal("initial investigation was not attempted")
	}
	type savedJob struct {
		Event       model.SecurityEvent `json:"event"`
		CompletedAt time.Time           `json:"completedAt,omitempty"`
		RetryAt     time.Time           `json:"retryAt,omitempty"`
	}
	path := filepath.Join(state, "investigations.json")
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var pending map[string]savedJob
	if err := json.Unmarshal(data, &pending); err != nil {
		t.Fatal(err)
	}
	if len(pending) != 1 {
		t.Fatalf("pending investigation not durable: %s", data)
	}
	// Advance the persisted retry deadline without slowing this restart test by
	// the production five-minute backoff.
	originalID := ""
	for key, j := range pending {
		if !j.CompletedAt.IsZero() || j.RetryAt.IsZero() {
			t.Fatal("failed investigation incorrectly completed")
		}
		originalID = j.Event.ID
		j.RetryAt = time.Now().Add(-time.Second)
		pending[key] = j
	}
	data, err = json.Marshal(pending)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	completed := 0
	verified := 0
	var delivered []model.SecurityEvent
	restarted := fixtureRuntime(t, state, func(_ context.Context, e model.SecurityEvent) error { delivered = append(delivered, e); return nil })
	restarted.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
		completed++
		if len(c.FindingIDs) != 1 || c.FindingIDs[0] != originalID {
			t.Error("restart changed incident identity")
		}
		return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "Recovered job"}, nil
	})
	restarted.Verify = func(context.Context) error { verified++; return nil }
	restarted.Assessment = eventAdapter(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete"}})
	if err := restarted.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if completed != 1 || verified != 1 || !containsKind(delivered, "investigation.checked") || containsKind(delivered, "investigation.verified") {
		t.Fatalf("durable pending job did not finish: calls=%d checks=%d events=%+v", completed, verified, delivered)
	}
	third := fixtureRuntime(t, state, post)
	third.Monitor = eventAdapter(observation)
	third.Reasoner = investigateFunc(func(context.Context, model.IncidentCase) (model.ResponseProposal, error) {
		t.Error("recently completed identical evidence investigated twice")
		return model.ResponseProposal{}, nil
	})
	if err := third.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
}

func TestRuntimeVulnerabilityVerificationRequiresFreshCompleteScanAndOriginalAbsent(t *testing.T) {
	for _, status := range []string{"fixed", "affected", "unknown", "source-sibling-unknown", "source-coverage-unknown", "missing-scan-completion"} {
		t.Run(status, func(t *testing.T) {
			original := sensors.Observation{Kind: "vulnerability.detected", Severity: model.SeverityHigh, Confidence: 1, Attributes: map[string]string{"package": "php8.3-cli", "sourcePackage": "php8.3", "vulnerabilityId": "CVE-2026-12345", "installedVersion": "1.0", "status": "affected"}}
			var events []model.SecurityEvent
			r := fixtureRuntime(t, t.TempDir(), func(_ context.Context, e model.SecurityEvent) error { events = append(events, e); return nil })
			r.Monitor = eventAdapter(original)
			r.Assessment = adapter{"vendor-assessment", func(_ context.Context, emit func(sensors.Observation) error) error {
				if status == "affected" || status == "unknown" || status == "source-sibling-unknown" || status == "source-coverage-unknown" {
					current := original
					if status == "unknown" || status == "source-sibling-unknown" {
						current.Kind = "vulnerability.unknown"
						current.Severity = model.SeverityMedium
					}
					if status == "source-sibling-unknown" {
						current.Attributes = map[string]string{}
						for k, v := range original.Attributes {
							current.Attributes[k] = v
						}
						current.Attributes["package"] = "php8.3-fpm"
					}
					if status == "source-coverage-unknown" {
						current.Kind = "vulnerability.coverage_unknown"
						current.Severity = model.SeverityMedium
					}
					if err := emit(current); err != nil {
						return err
					}
				}
				if status != "missing-scan-completion" {
					return emit(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete", "packages": "1", "detected": "0", "unknown": "0"}})
				}
				return nil
			}}
			r.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
				return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "AI believes the fix is complete"}, nil
			})
			r.Verify = func(context.Context) error { return nil }
			_ = r.Run(context.Background(), true)
			if status == "fixed" {
				if !containsKind(events, "investigation.verified") {
					t.Fatalf("fresh confirmed remediation not verified: %+v", events)
				}
			} else if containsKind(events, "investigation.verified") || !(containsKind(events, "investigation.failed") || containsKind(events, "investigation.unresolved")) {
				t.Fatalf("unresolved %s incorrectly verified: %+v", status, events)
			}
		})
	}
}

func TestRuntimeFullControlGroupsLargeFindingBatchWithoutStoppingCollection(t *testing.T) {
	var delivered []model.SecurityEvent
	calls := 0
	r := fixtureRuntime(t, t.TempDir(), func(_ context.Context, e model.SecurityEvent) error { delivered = append(delivered, e); return nil })
	r.FullControl = true
	r.Monitor = adapter{"large-vendor-report", func(_ context.Context, emit func(sensors.Observation) error) error {
		for i := 0; i < 300; i++ {
			if err := emit(sensors.Observation{Kind: "vulnerability.detected", Severity: model.SeverityHigh, Confidence: 1, Attributes: map[string]string{"package": "php8.3", "sourcePackage": "php8.3", "vulnerabilityId": fmt.Sprintf("CVE-2026-%05d", i)}}); err != nil {
				return err
			}
		}
		return nil
	}}
	r.Assessment = eventAdapter(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete", "detected": "0", "unknown": "0"}})
	r.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
		calls++
		return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "One VM investigation"}, nil
	})
	r.Verify = func(context.Context) error { return nil }
	if err := r.Run(context.Background(), true); err != nil {
		t.Fatalf("AI backlog stopped collection: %v", err)
	}
	findings := 0
	for _, e := range delivered {
		if e.Kind == "vulnerability.detected" {
			findings++
		}
	}
	if findings != 300 {
		t.Fatalf("finding batch truncated: %d", findings)
	}
	if calls != 2 {
		t.Fatalf("full-control batch produced %d investigations, want CVE batch and proactive audit", calls)
	}
}

func TestRuntimeFullControlAuditsFollowAssessmentSchedule(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	audits := make(chan struct{}, 16)
	r := fixtureRuntime(t, t.TempDir(), func(context.Context, model.SecurityEvent) error { return nil })
	r.FullControl = true
	r.AssessmentInterval = 25 * time.Millisecond
	r.AuditInterval = 25 * time.Millisecond
	r.Assessment = eventAdapter(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete"}})
	r.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
		// A slow filesystem can let several scheduled audits accumulate before
		// the worker reads them. Grouping those audits is expected behavior.
		if len(c.Evidence) == 0 {
			t.Errorf("unexpected scheduled audit evidence: %+v", c)
		}
		for _, evidence := range c.Evidence {
			if evidence.Kind != "autonomy.audit_requested" {
				t.Errorf("unexpected scheduled audit evidence: %+v", evidence)
			}
		}
		audits <- struct{}{}
		return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "Scheduled VM audit"}, nil
	})
	r.Verify = func(context.Context) error { return nil }
	done := make(chan error, 1)
	go func() { done <- r.Run(ctx, false) }()
	deadline := time.After(5 * time.Second)
	count := 0
	for count < 2 {
		select {
		case <-audits:
			count++
		case <-deadline:
			cancel()
			<-done
			t.Fatalf("scheduled autonomous audits suppressed: got %d, want at least 2", count)
		}
	}
	cancel()
	select {
	case err := <-done:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("scheduled runtime did not stop")
	}
}

func TestRuntimeFullControlUrgentWebshellSurvivesLargeCVEBatch(t *testing.T) {
	seen := map[string]bool{}
	r := fixtureRuntime(t, t.TempDir(), func(context.Context, model.SecurityEvent) error { return nil })
	r.FullControl = true
	r.Monitor = adapter{"mixed-findings", func(_ context.Context, emit func(sensors.Observation) error) error {
		for i := 0; i < 300; i++ {
			if err := emit(sensors.Observation{Kind: "vulnerability.detected", Severity: model.SeverityHigh, Confidence: 1, Attributes: map[string]string{"package": "php8.3", "sourcePackage": "php8.3", "vulnerabilityId": fmt.Sprintf("CVE-2026-%05d", i)}}); err != nil {
				return err
			}
		}
		return emit(shellObservation())
	}}
	r.Assessment = eventAdapter(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete"}})
	r.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
		for _, e := range c.Evidence {
			seen[e.Kind] = true
		}
		return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "Bounded findings grouped by incident kind"}, nil
	})
	r.VerifyEvent = func(context.Context, model.SecurityEvent) error { return nil }
	if err := r.Run(context.Background(), true); err != nil {
		t.Fatal(err)
	}
	if !seen["webshell.suspicious"] || !seen["vulnerability.detected"] || !seen["autonomy.audit_requested"] {
		t.Fatalf("large CVE set crowded out urgent incident: %+v", seen)
	}
}

func TestRuntimeRelatedUnresolvedCVENeverVerifiesWholeBatch(t *testing.T) {
	makeCVE := func(id string) sensors.Observation {
		return sensors.Observation{Kind: "vulnerability.detected", Severity: model.SeverityHigh, Confidence: 1, Attributes: map[string]string{"package": "php8.3-cli", "sourcePackage": "php8.3", "vulnerabilityId": id}}
	}
	first, second := makeCVE("CVE-2026-10101"), makeCVE("CVE-2026-10102")
	var events []model.SecurityEvent
	r := fixtureRuntime(t, t.TempDir(), func(_ context.Context, e model.SecurityEvent) error { events = append(events, e); return nil })
	r.FullControl = true
	r.Monitor = adapter{"two-cves", func(_ context.Context, emit func(sensors.Observation) error) error {
		if err := emit(first); err != nil {
			return err
		}
		return emit(second)
	}}
	r.Assessment = adapter{"fresh-assessment", func(_ context.Context, emit func(sensors.Observation) error) error {
		remaining := second
		remaining.Kind = "vulnerability.unknown"
		remaining.Severity = model.SeverityMedium
		if err := emit(remaining); err != nil {
			return err
		}
		return emit(sensors.Observation{Kind: "vulnerability.scan_completed", Severity: model.SeverityInfo, Confidence: 1, Attributes: map[string]string{"status": "complete_with_unknowns", "unknown": "1"}})
	}}
	r.Reasoner = investigateFunc(func(_ context.Context, c model.IncidentCase) (model.ResponseProposal, error) {
		return model.ResponseProposal{SchemaVersion: model.SchemaVersion, CaseID: c.ID, Summary: "First CVE cleared, related CVE uncertain"}, nil
	})
	_ = r.Run(context.Background(), true)
	if containsKind(events, "investigation.verified") || !containsKind(events, "investigation.unresolved") {
		t.Fatalf("unresolved related CVE batch claimed verified: %+v", events)
	}
}

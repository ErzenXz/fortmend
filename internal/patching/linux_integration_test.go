//go:build linux

package patching

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/sensors"
)

// TestDisposableVMRealSecurityUpdates intentionally changes installed packages.
// Never enable it on a real host. It requires both an explicit opt-in and a
// marker created while provisioning a disposable Ubuntu/Debian test VM.
func TestDisposableVMRealSecurityUpdates(t *testing.T) {
	if os.Getenv("FORTMEND_PATCHING_INTEGRATION") != "1" {
		t.Skip("requires disposable Linux VM and explicit opt-in")
	}
	if os.Geteuid() != 0 {
		t.Fatal("integration test requires root in a disposable VM")
	}
	marker, err := os.ReadFile("/etc/fortmend-disposable-integration")
	if err != nil || strings.TrimSpace(string(marker)) != "fortmend-disposable-security-update-test" {
		t.Fatal("disposable VM marker is missing")
	}
	state, err := os.MkdirTemp("/var/lib", "fortmend-patching-test-")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(state)
	u := &Updater{Config: Config{StateDir: state, HealthServices: []string{"ssh.service"}, CommandTimeout: 10 * time.Minute}, Runner: sensors.ExecRunner{}}
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()
	events := []sensors.Observation{}
	emit := func(event sensors.Observation) error {
		events = append(events, event)
		data, _ := json.Marshal(event)
		t.Log(string(data))
		return nil
	}
	if err = u.Run(ctx, emit); err != nil {
		t.Fatalf("real security dry run: %v", err)
	}
	if len(events) != 1 || events[0].Kind != "patching.planned" {
		t.Fatalf("unexpected dry-run events: %+v", events)
	}
	// Check the native updater's effective policy, not just our generated file.
	policy, err := u.policy()
	if err != nil {
		t.Fatal(err)
	}
	allowed := map[string]bool{}
	for _, line := range strings.Split(policy, "\n") {
		if strings.HasPrefix(line, "Unattended-Upgrade::Origins-Pattern") {
			for i, part := range strings.Split(line, "\"") {
				if i%2 == 1 {
					allowed[part] = true
				}
			}
		}
	}
	var effective string
	for _, line := range strings.Split(events[0].Attributes["output"], "\n") {
		if strings.HasPrefix(line, "Allowed origins are: ") {
			effective = strings.TrimPrefix(line, "Allowed origins are: ")
		}
	}
	if effective == "" {
		t.Fatal("native updater did not report its effective allowed origins")
	}
	origins := strings.Split(effective, ", origin=")
	for i, origin := range origins {
		if i > 0 {
			origin = "origin=" + origin
		}
		if !allowed[origin] {
			t.Fatalf("native updater permits unexpected origin %q", origin)
		}
	}
	if len(origins) != len(allowed) {
		t.Fatalf("native origins differ from security-only policy: %s", effective)
	}
	if _, err = os.Stat(filepath.Join(state, "receipt.json")); !os.IsNotExist(err) {
		t.Fatal("dry run recorded an apply receipt")
	}
	events = nil
	u.Config.Apply = true
	if err = u.Run(ctx, emit); err != nil {
		t.Fatalf("real security apply: %v", err)
	}
	complete := false
	for _, event := range events {
		if event.Kind == "patching.completed" {
			complete = true
		}
		if event.Kind == "patching.failed" || event.Kind == "patching.blocked" {
			t.Fatalf("unexpected failure event: %+v", event)
		}
	}
	if !complete {
		t.Fatal("missing completion event after real transaction and health checks")
	}
	data, err := os.ReadFile(filepath.Join(state, "receipt.json"))
	if err != nil {
		t.Fatal(err)
	}
	var r receipt
	if err = json.Unmarshal(data, &r); err != nil || r.Status != "completed" {
		t.Fatalf("completion receipt: %s; %v", data, err)
	}
	if err = u.health(ctx); err != nil {
		t.Fatalf("independent final health verification: %v", err)
	}
}

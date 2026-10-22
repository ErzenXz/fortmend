//go:build !windows

package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func TestLinuxPolicyDefaultsAndExplicitAuthority(t *testing.T) {
	path := filepath.Join(t.TempDir(), "policy.json")
	if err := os.WriteFile(path, []byte(`{"schemaVersion":"fortmend.linux/v1","ai":{"enabled":true,"mode":"full-control"},"securityUpdates":true}`), 0600); err != nil {
		t.Fatal(err)
	}
	p, err := loadLinuxPolicy(path)
	if err != nil {
		t.Fatal(err)
	}
	if p.AI.Mode != "full-control" || !p.SecurityUpdates || p.AutomaticReboot || p.StateDir != "/var/lib/fortmend/protection" || p.PollSeconds != 5 || p.AssessmentMinutes != 60 {
		t.Fatalf("unexpected policy %+v", p)
	}
}
func TestLinuxPolicyRejectsAmbiguousOrUnsafeInputs(t *testing.T) {
	for _, body := range []string{`{}`, `{"schemaVersion":"fortmend.linux/v1","securityUpdate":true}`, `{"schemaVersion":"fortmend.linux/v1"} {}`, `{"schemaVersion":"fortmend.linux/v1","stateDir":"/"}`, `{"schemaVersion":"fortmend.linux/v1","pollSeconds":-1}`, `{"schemaVersion":"fortmend.linux/v1","ai":{"enabled":true,"mode":"typo"}}`, `{"schemaVersion":"fortmend.linux/v1","ai":{"binary":"codex"}}`, `{"schemaVersion":"fortmend.linux/v1","webRoots":["/"]}`, `{"schemaVersion":"fortmend.linux/v1","healthServices":["--all.service"]}`} {
		path := filepath.Join(t.TempDir(), "policy.json")
		if err := os.WriteFile(path, []byte(body), 0600); err != nil {
			t.Fatal(err)
		}
		if _, err := loadLinuxPolicy(path); err == nil {
			t.Errorf("accepted %s", body)
		}
	}
}
func TestShippedLinuxPolicyParses(t *testing.T) {
	p, err := loadLinuxPolicy("../../packaging/linux/linux.example.json")
	if err != nil {
		t.Fatal(err)
	}
	if !p.AI.Enabled || p.AI.Mode != "full-control" || !p.AutoQuarantine {
		t.Fatal("example doesn't enable requested autonomous VM mode")
	}
	if _, err := json.Marshal(p); err != nil {
		t.Fatal(err)
	}
}

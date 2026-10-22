//go:build linux

package monitor

import (
	"context"
	"os"
	"os/exec"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/sensors"
)

func TestLiveDisposableJournalSSHAttack(t *testing.T) {
	if os.Getenv("FORTMEND_MONITOR_INTEGRATION") != "1" {
		t.Skip("set FORTMEND_MONITOR_INTEGRATION=1 in a marked disposable VM")
	}
	if _, err := os.Stat("/etc/fortmend-disposable-integration"); err != nil {
		t.Fatal("refusing live integration without disposable VM marker")
	}
	if os.Geteuid() != 0 {
		t.Fatal("live journal integration requires root")
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	c := Config{StateDir: t.TempDir(), PersistencePaths: []string{}}
	ip := "198.51.100.249"
	var got []sensors.Observation
	emit := func(o sensors.Observation) error {
		if o.Attributes["sourceIp"] == ip {
			got = append(got, o)
		}
		return nil
	}
	if err := New(c).Run(ctx, emit); err != nil {
		t.Fatal(err)
	}
	got = nil
	for i := 0; i < 10; i++ {
		if b, err := exec.CommandContext(ctx, "logger", "-t", "sshd", "--", "Failed password for invalid user fortmend-fixture from "+ip+" port 42000 ssh2").CombinedOutput(); err != nil {
			t.Fatalf("logger: %v %s", err, b)
		}
	}
	if b, err := exec.CommandContext(ctx, "logger", "-t", "sshd", "--", "Accepted publickey for fortmend-fixture from "+ip+" port 42000 ssh2").CombinedOutput(); err != nil {
		t.Fatalf("logger accepted: %v %s", err, b)
	}
	if b, err := exec.CommandContext(ctx, "journalctl", "--sync").CombinedOutput(); err != nil {
		t.Fatalf("journal sync: %v %s", err, b)
	}
	for i := 0; i < 20 && len(got) < 2; i++ {
		if err := New(c).Run(ctx, emit); err != nil {
			t.Fatal(err)
		}
		if len(got) < 2 {
			time.Sleep(100 * time.Millisecond)
		}
	}
	if len(got) != 2 || got[0].Attributes["reason"] != "ssh_failure_burst" || got[1].Attributes["reason"] != "ssh_success_after_failure_burst" {
		t.Fatalf("live auth attack evidence missing: %+v", got)
	}
	got = nil
	if err := New(c).Run(ctx, emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("restarted monitor repeated acknowledged journal evidence: %+v", got)
	}
}

func TestLiveDisposableInvalidCursorRecovery(t *testing.T) {
	if os.Getenv("FORTMEND_MONITOR_INTEGRATION") != "1" {
		t.Skip("requires marked disposable VM")
	}
	if _, err := os.Stat("/etc/fortmend-disposable-integration"); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() != 0 {
		t.Fatal("journal integration requires root")
	}
	m := New(Config{StateDir: t.TempDir(), PersistencePaths: []string{}})
	s := diskState{Cursor: "invalid-fortmend-cursor", Files: map[string]string{}, Failures: map[string][]int64{}}
	if err := m.save(&s); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
	defer cancel()
	gap := false
	if err := m.Run(ctx, func(o sensors.Observation) error {
		if o.Kind == "sensor.coverage_gap" {
			gap = true
		}
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	stored, err := m.load()
	if err != nil {
		t.Fatal(err)
	}
	if !gap || stored.Cursor == "invalid-fortmend-cursor" {
		t.Fatalf("actual journal cursor did not recover: gap=%v cursor=%q", gap, stored.Cursor)
	}
}

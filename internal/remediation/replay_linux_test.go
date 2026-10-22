//go:build linux

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ErzenXz/aegis/internal/sensors"
	"golang.org/x/sys/unix"
)

func replayFixture(t *testing.T) (*Quarantine, string) {
	t.Helper()
	rootTest(t)
	root := t.TempDir()
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "hack.php")
	content := []byte("<?php system($_GET['cmd']);")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	q := &Quarantine{StateDir: state, WebRoots: []string{root}}
	obs, err := q.Apply(context.Background(), shellEvent(path, content))
	if err != nil {
		t.Fatal(err)
	}
	return q, obs.Attributes["receiptPath"]
}

func TestLinuxReplayApplyCrashAndFailedSinkRetainsUndeliveredReceipt(t *testing.T) {
	q, receiptPath := replayFixture(t)
	fresh := &Quarantine{StateDir: q.StateDir, WebRoots: q.WebRoots}
	marker := filepath.Join(filepath.Dir(receiptPath), "delivery.json")
	calls := 0
	if err := fresh.Replay(context.Background(), func(sensors.Observation) error { calls++; return errors.New("outbox full") }); err == nil {
		t.Fatal("failed delivery hidden")
	}
	if _, err := os.Lstat(marker); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("failed sink incorrectly acknowledged receipt")
	}
	var got []sensors.Observation
	if err := fresh.Replay(context.Background(), func(o sensors.Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if calls != 1 || len(got) != 1 || got[0].Kind != "remediation.quarantined" || got[0].Attributes["replayed"] != "true" || got[0].Attributes["hostClean"] != "false" {
		t.Fatalf("crash receipt not recovered: %+v", got)
	}
	info, err := os.Stat(marker)
	if err != nil || info.Mode().Perm() != 0600 {
		t.Fatalf("unsafe delivery marker: %v %v", info, err)
	}
	got = nil
	if err := fresh.Replay(context.Background(), func(o sensors.Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("acknowledged receipt repeatedly replayed")
	}
}

func TestLinuxReplaySourceReappearedNeverClaimsCurrentContainment(t *testing.T) {
	q, receiptPath := replayFixture(t)
	path := filepath.Join(q.WebRoots[0], "hack.php")
	content := []byte("<?php system($_GET['cmd']);")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	var got sensors.Observation
	if err := q.Replay(context.Background(), func(o sensors.Observation) error { got = o; return nil }); err != nil {
		t.Fatal(err)
	}
	if got.Kind != "remediation.quarantine_failed" || got.Attributes["status"] != "source_reappeared" {
		t.Fatalf("reinfected path claimed contained: %+v receipt%s", got, receiptPath)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != string(content) {
		t.Fatal("receipt replay modified the reinfected source")
	}
}

func TestLinuxReplayRefusesSymlinkAndUnprotectedMetadata(t *testing.T) {
	for _, kind := range []string{"receipt-symlink", "receipt-world-readable", "action-symlink"} {
		t.Run(kind, func(t *testing.T) {
			q, path := replayFixture(t)
			switch kind {
			case "receipt-symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "receipt-world-readable":
				if err := os.Chmod(path, 0644); err != nil {
					t.Fatal(err)
				}
			case "action-symlink":
				dir := filepath.Dir(path)
				if err := os.Rename(dir, dir+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(dir+".original", dir); err != nil {
					t.Fatal(err)
				}
			}
			calls := 0
			if err := q.Replay(context.Background(), func(sensors.Observation) error { calls++; return nil }); err == nil {
				t.Fatal("unsafe replay metadata accepted")
			}
			if calls != 0 {
				t.Fatal("unsafe receipt emitted")
			}
		})
	}
}

func TestLinuxReplayPreparedMoveFinalizesAfterCrash(t *testing.T) {
	q, path := replayFixture(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var r receipt
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	r.Status = "prepared"
	fd, err := openDirectory(filepath.Dir(path), false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	if err := writeReceipt(fd, r); err != nil {
		t.Fatal(err)
	}
	var got sensors.Observation
	if err := q.Replay(context.Background(), func(o sensors.Observation) error { got = o; return nil }); err != nil {
		t.Fatal(err)
	}
	if got.Kind != "remediation.quarantined" {
		t.Fatalf("prepared moved evidence not finalized: %+v", got)
	}
	data, err = os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(data, &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != "quarantined" {
		t.Fatal("prepared receipt was not durably finalized")
	}
}

func TestLinuxReplayActualFailedContainmentReceipt(t *testing.T) {
	rootTest(t)
	root, state := t.TempDir(), t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "hack.php")
	content := []byte("<?php system($_GET['cmd']);")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	q := &Quarantine{StateDir: state, WebRoots: []string{root}}
	q.beforeMove = func() {
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte("<?php echo 'replacement';"), 0600); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := q.Apply(context.Background(), shellEvent(path, content)); err == nil {
		t.Fatal("fixture replacement race did not fail")
	}
	fresh := &Quarantine{StateDir: state, WebRoots: []string{root}}
	var got []sensors.Observation
	if err := fresh.Replay(context.Background(), func(o sensors.Observation) error { got = append(got, o); return nil }); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Kind != "remediation.quarantine_failed" || got[0].Attributes["status"] != "restored_after_verification_failure" {
		t.Fatalf("failed containment receipt lost: %+v", got)
	}
}

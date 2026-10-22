//go:build linux

package remediation

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/ErzenXz/aegis/internal/monitor"

	"golang.org/x/sys/unix"
)

func rootTest(t *testing.T) {
	t.Helper()
	if os.Geteuid() != 0 {
		t.Skip("Linux quarantine integration requires root; validation tests remain unprivileged")
	}
}
func TestLinuxQuarantineAndIdempotentReplay(t *testing.T) {
	rootTest(t)
	root := t.TempDir()
	state := t.TempDir()
	if err := os.Chmod(state, 0700); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(root, "hack.php")
	content := []byte("<?php eval(base64_decode($_POST['cmd']));")
	if err := os.WriteFile(path, content, 0755); err != nil {
		t.Fatal(err)
	}
	event := shellEvent(path, content)
	q := Quarantine{StateDir: state, WebRoots: []string{root}}
	obs, err := q.Apply(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("source remains: %v", err)
	}
	payload := obs.Attributes["quarantinePath"]
	b, err := os.ReadFile(payload)
	if err != nil || string(b) != string(content) {
		t.Fatalf("evidence changed: %q %v", b, err)
	}
	fi, err := os.Stat(payload)
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("unsafe evidence permissions: %v %v", fi, err)
	}
	b, err = os.ReadFile(obs.Attributes["receiptPath"])
	if err != nil {
		t.Fatal(err)
	}
	var r receipt
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	if r.Status != "quarantined" || r.OriginalMode&0777 != 0755 {
		t.Fatalf("invalid receipt: %+v", r)
	}
	replay, err := q.Apply(context.Background(), event)
	if err != nil || replay.Attributes["quarantinePath"] != payload {
		t.Fatalf("idempotent replay failed: %+v %v", replay, err)
	}
	if obs.Attributes["hostClean"] != "false" {
		t.Fatal("containment falsely claims host clean")
	}
}
func TestLinuxRefusesChangedHashSymlinksAndHardlinks(t *testing.T) {
	rootTest(t)
	for _, kind := range []string{"hash", "symlink", "ancestor-symlink", "hardlink"} {
		t.Run(kind, func(t *testing.T) {
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
			event := shellEvent(path, content)
			q := Quarantine{StateDir: state, WebRoots: []string{root}}
			switch kind {
			case "hash":
				if err := os.WriteFile(path, []byte("<?php echo 'safe';"), 0600); err != nil {
					t.Fatal(err)
				}
			case "symlink":
				if err := os.Rename(path, path+".original"); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(path+".original", path); err != nil {
					t.Fatal(err)
				}
			case "ancestor-symlink":
				link := filepath.Join(t.TempDir(), "web")
				if err := os.Symlink(root, link); err != nil {
					t.Fatal(err)
				}
				q.WebRoots = []string{link}
				event.Attributes["path"] = filepath.Join(link, "hack.php")
			case "hardlink":
				if err := os.Link(path, path+".hardlink"); err != nil {
					t.Fatal(err)
				}
			}
			if _, err := q.Apply(context.Background(), event); err == nil {
				t.Fatal("unsafe target quarantined")
			}
			if _, err := os.Lstat(path); err != nil {
				t.Fatal("target removed on refusal")
			}
		})
	}
}
func TestLinuxResumePreparedReceipt(t *testing.T) {
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
	event := shellEvent(path, content)
	q := Quarantine{StateDir: state, WebRoots: []string{root}}
	obs, err := q.Apply(context.Background(), event)
	if err != nil {
		t.Fatal(err)
	}
	fd, err := openDirectory(filepath.Dir(obs.Attributes["receiptPath"]), false)
	if err != nil {
		t.Fatal(err)
	}
	defer unix.Close(fd)
	b, err := os.ReadFile(obs.Attributes["receiptPath"])
	if err != nil {
		t.Fatal(err)
	}
	var r receipt
	if err := json.Unmarshal(b, &r); err != nil {
		t.Fatal(err)
	}
	r.Status = "prepared"
	if err := writeReceipt(fd, r); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Apply(context.Background(), event); err != nil {
		t.Fatalf("failed crash recovery: %v", err)
	}
}

func TestLinuxTargetReplacementRaceRestoresWithoutOverwrite(t *testing.T) {
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
	event := shellEvent(path, content)
	q := Quarantine{StateDir: state, WebRoots: []string{root}}
	replacement := []byte("<?php echo 'replacement';")
	q.beforeMove = func() {
		if err := os.Rename(path, path+".original"); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, replacement, 0644); err != nil {
			t.Fatal(err)
		}
	}
	obs, err := q.Apply(context.Background(), event)
	if err == nil {
		t.Fatal("path replacement race was not detected")
	}
	if obs.Kind != "remediation.quarantine_failed" || obs.Attributes["status"] != "restored_after_verification_failure" {
		t.Fatalf("race status: %+v %v", obs, err)
	}
	b, err := os.ReadFile(path)
	if err != nil || string(b) != string(replacement) {
		t.Fatalf("replacement not restored: %q %v", b, err)
	}
	b, err = os.ReadFile(path + ".original")
	if err != nil || string(b) != string(content) {
		t.Fatalf("original evidence lost: %q %v", b, err)
	}
}

func TestLiveDisposableQuarantine(t *testing.T) {
	if os.Getenv("AEGIS_MONITOR_INTEGRATION") != "1" {
		t.Skip("set AEGIS_MONITOR_INTEGRATION=1 in marked disposable VM")
	}
	if _, err := os.Stat("/etc/aegis-disposable-integration"); err != nil {
		t.Fatal("refusing live integration without disposable VM marker")
	}
	TestLinuxQuarantineAndIdempotentReplay(t)
	TestLinuxTargetReplacementRaceRestoresWithoutOverwrite(t)
}

func TestLinuxOccurrenceRetryReinfectionAndDelayedEvent(t *testing.T) {
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
	old := shellEvent(path, content)
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	old.Attributes["occurrenceId"] = monitor.OccurrenceID(path, old.Attributes["sha256"], info)
	q := Quarantine{StateDir: state, WebRoots: []string{root}}
	first, err := q.Apply(context.Background(), old)
	if err != nil {
		t.Fatal(err)
	}
	retry := old
	retry.ID = "new-delivery-id"
	again, err := q.Apply(context.Background(), retry)
	if err != nil || again.Attributes["quarantinePath"] != first.Attributes["quarantinePath"] {
		t.Fatalf("occurrence retry not stable: %+v %v", again, err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	if _, err := q.Apply(context.Background(), old); err == nil {
		t.Fatal("delayed original event quarantined a new occurrence")
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("new occurrence removed: %v", err)
	}
	current := shellEvent(path, content)
	currentInfo, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	current.Attributes["occurrenceId"] = monitor.OccurrenceID(path, current.Attributes["sha256"], currentInfo)
	if current.Attributes["occurrenceId"] == old.Attributes["occurrenceId"] {
		t.Fatal("reinfection occurrence did not change")
	}
	second, err := q.Apply(context.Background(), current)
	if err != nil {
		t.Fatal(err)
	}
	if second.Attributes["quarantinePath"] == first.Attributes["quarantinePath"] {
		t.Fatal("reinfection evidence overwrote original occurrence")
	}
}

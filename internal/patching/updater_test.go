package patching

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/sensors"
)

type fakeRunner struct {
	calls     []string
	policy    string
	fail      string
	auditBad  bool
	healthBad bool
	cancelled bool
}

func (f *fakeRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	call := name + " " + strings.Join(args, " ")
	f.calls = append(f.calls, call)
	if name != "/usr/bin/env" {
		panic("commands must use clean environment")
	}
	if _, ok := ctx.Deadline(); !ok {
		panic("missing command timeout")
	}
	for _, arg := range args {
		if strings.HasPrefix(arg, "APT_CONFIG=") {
			data, err := os.ReadFile(strings.TrimPrefix(arg, "APT_CONFIG="))
			if err != nil {
				panic(err)
			}
			f.policy = string(data)
		}
	}
	if f.cancelled {
		<-ctx.Done()
		return nil, ctx.Err()
	}
	if f.fail != "" && strings.Contains(call, f.fail) {
		return []byte("failed fixture"), errors.New("fixture command failure")
	}
	if strings.Contains(call, "dpkg --audit") && f.auditBad {
		return []byte("php half-configured"), nil
	}
	if strings.Contains(call, "systemctl is-active") {
		if f.healthBad && len(f.calls) > 4 {
			return []byte("failed"), nil
		}
		return []byte("active\n"), nil
	}
	return []byte(""), nil
}

func fixture(t *testing.T) (*Updater, *fakeRunner) {
	t.Helper()
	r := &fakeRunner{}
	stateDir, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	u := &Updater{Config: Config{StateDir: stateDir, Apply: true, HealthServices: []string{"nginx.service"}}, Runner: r, platform: "linux", euid: func() int { return 0 }, sourceFiles: func() ([]string, error) { return nil, nil }}
	u.readFile = func(p string) ([]byte, error) {
		if p == "/etc/os-release" {
			return []byte("ID=ubuntu\nVERSION_CODENAME=noble\n"), nil
		}
		return nil, os.ErrNotExist
	}
	return u, r
}
func collect() (*[]sensors.Observation, func(sensors.Observation) error) {
	events := []sensors.Observation{}
	return &events, func(o sensors.Observation) error { events = append(events, o); return nil }
}

func TestSecurityOnlyApplyAndHealth(t *testing.T) {
	u, r := fixture(t)
	events, emit := collect()
	if err := u.Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	calls := strings.Join(r.calls, "\n")
	if len(r.calls) != 7 {
		t.Fatalf("unexpected commands (%d): %s", len(r.calls), calls)
	}
	if !strings.Contains(calls, "apt-get -o APT::Update::Error-Mode=any update") || !strings.Contains(calls, "unattended-upgrade --dry-run --verbose") {
		t.Fatal(calls)
	}
	for _, required := range []string{`Dir::Etc::parts "-"`, `Dir::Etc::main "-"`, `#clear Unattended-Upgrade`, `codename=noble-security`, `Automatic-Reboot "false"`, `AllowUnauthenticated "false"`} {
		if !strings.Contains(r.policy, required) {
			t.Fatalf("missing policy %s", required)
		}
	}
	if strings.Contains(r.policy, "noble-updates") || strings.Contains(calls, "shutdown") {
		t.Fatal("widened update/reboot policy")
	}
	if (*events)[len(*events)-1].Kind != "patching.completed" {
		t.Fatal(*events)
	}
	b, err := os.ReadFile(u.statePath())
	if err != nil || !strings.Contains(string(b), `"completed"`) {
		t.Fatalf("receipt: %s %v", b, err)
	}
}

func TestDryRunDoesNotApply(t *testing.T) {
	u, r := fixture(t)
	u.Config.Apply = false
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 4 {
		t.Fatal(r.calls)
	}
	if _, err := os.Stat(u.statePath()); !os.IsNotExist(err) {
		t.Fatal("dry run wrote apply receipt")
	}
}

func TestFailureBlocksRestartUntilAcknowledged(t *testing.T) {
	u, r := fixture(t)
	r.fail = "unattended-upgrade --verbose"
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("expected failure")
	}
	r.fail = ""
	r.calls = nil
	events, emit2 := collect()
	if err := u.Run(context.Background(), emit2); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 || (*events)[0].Kind != "patching.blocked" {
		t.Fatalf("retried blocked apply: %v %v", r.calls, *events)
	}
	if err := u.ClearFailure(); err != nil {
		t.Fatal(err)
	}
	if err := u.Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
}

func TestInterruptedReceiptBlocks(t *testing.T) {
	u, r := fixture(t)
	if err := u.save(receipt{Status: "applying"}); err != nil {
		t.Fatal(err)
	}
	events, emit := collect()
	if err := u.Run(context.Background(), emit); err != nil {
		t.Fatal(err)
	}
	if len(r.calls) != 0 || (*events)[0].Kind != "patching.blocked" {
		t.Fatal(*events)
	}
}
func TestUnhealthyAfterApplyBlocks(t *testing.T) {
	u, r := fixture(t)
	r.healthBad = true
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("expected post-health error")
	}
	b, _ := os.ReadFile(u.statePath())
	if !strings.Contains(string(b), `"failed"`) {
		t.Fatal(string(b))
	}
}
func TestPreflightDpkgAudit(t *testing.T) {
	u, r := fixture(t)
	r.auditBad = true
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("expected audit error")
	}
	if len(r.calls) != 1 {
		t.Fatal(r.calls)
	}
}
func TestAptLockFailureNeverApplies(t *testing.T) {
	u, r := fixture(t)
	r.fail = "apt-get"
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("expected lock/error")
	}
	if strings.Contains(strings.Join(r.calls, "\n"), "unattended-upgrade") {
		t.Fatal(r.calls)
	}
}
func TestHostGuardsAndServices(t *testing.T) {
	for _, tc := range []string{"platform", "nonroot", "service", "path"} {
		t.Run(tc, func(t *testing.T) {
			u, r := fixture(t)
			switch tc {
			case "platform":
				u.platform = "darwin"
			case "nonroot":
				u.euid = func() int { return 501 }
			case "service":
				u.Config.HealthServices = []string{"--all; reboot"}
			case "path":
				u.Config.StateDir = "."
			}
			_, emit := collect()
			if err := u.Run(context.Background(), emit); err == nil {
				t.Fatal("expected guard")
			}
			if len(r.calls) != 0 {
				t.Fatal(r.calls)
			}
		})
	}
}
func TestCancellationBounded(t *testing.T) {
	u, r := fixture(t)
	r.cancelled = true
	u.Config.CommandTimeout = time.Millisecond
	_, emit := collect()
	start := time.Now()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("expected timeout")
	}
	if time.Since(start) > time.Second {
		t.Fatal("unbounded command")
	}
}
func TestRebootExplicitOnly(t *testing.T) {
	for _, enabled := range []bool{false, true} {
		u, r := fixture(t)
		u.Config.Reboot = enabled
		prev := u.readFile
		u.readFile = func(p string) ([]byte, error) {
			if p == "/run/reboot-required" {
				return nil, nil
			}
			return prev(p)
		}
		_, emit := collect()
		if err := u.Run(context.Background(), emit); err != nil {
			t.Fatal(err)
		}
		got := strings.Contains(strings.Join(r.calls, "\n"), "shutdown -r +1")
		if got != enabled {
			t.Fatalf("reboot got %v want %v", got, enabled)
		}
	}
}
func TestDebianPolicy(t *testing.T) {
	u, _ := fixture(t)
	u.readFile = func(string) ([]byte, error) { return []byte("ID=debian\nVERSION_CODENAME=trixie\n"), nil }
	p, err := u.policy()
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(p, "origin=Debian,codename=trixie-security,label=Debian-Security") || strings.Contains(p, "Ubuntu") {
		t.Fatal(p)
	}
}
func TestUnsafeSources(t *testing.T) {
	for _, source := range []string{"deb [trusted=yes] http://evil.invalid stable main", "Trusted: yes", "Check-Valid-Until: no", "deb [allow-insecure=true] http://evil.invalid stable main"} {
		u, r := fixture(t)
		u.sourceFiles = func() ([]string, error) { return []string{"/fixture.sources"}, nil }
		old := u.readFile
		u.readFile = func(p string) ([]byte, error) {
			if p == "/fixture.sources" {
				return []byte(source), nil
			}
			return old(p)
		}
		_, emit := collect()
		if err := u.Run(context.Background(), emit); err == nil {
			t.Fatalf("accepted %s", source)
		}
		if len(r.calls) != 0 {
			t.Fatal(r.calls)
		}
	}
}
func TestSymlinkStateRejected(t *testing.T) {
	u, _ := fixture(t)
	root := t.TempDir()
	link := filepath.Join(root, "link")
	if err := os.Symlink(u.Config.StateDir, link); err != nil {
		t.Fatal(err)
	}
	u.Config.StateDir = link
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("accepted symlink")
	}
}
func TestRunLock(t *testing.T) {
	u, r := fixture(t)
	unlock, err := lockState(filepath.Join(u.Config.StateDir, "run.lock"))
	if err != nil {
		t.Fatal(err)
	}
	defer unlock()
	_, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("ignored lock")
	}
	if len(r.calls) != 0 {
		t.Fatal(r.calls)
	}
	if err := u.ClearFailure(); err == nil {
		t.Fatal("acknowledgement raced running updater")
	}
}

func TestUntrustedRepositoryFailureStopsBeforePlan(t *testing.T) {
	u, r := fixture(t)
	r.fail = "apt-get"
	events, emit := collect()
	if err := u.Run(context.Background(), emit); err == nil {
		t.Fatal("repository failure accepted")
	}
	if len(*events) != 0 {
		t.Fatal("reported a plan despite failed authenticated refresh")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "unattended-upgrade") {
			t.Fatal("ran with stale package indexes")
		}
	}
}

func TestPlanSinkFailureStopsApply(t *testing.T) {
	u, r := fixture(t)
	if err := u.Run(context.Background(), func(sensors.Observation) error { return errors.New("receipt sink unavailable") }); err == nil {
		t.Fatal("expected sink failure")
	}
	for _, call := range r.calls {
		if strings.Contains(call, "unattended-upgrade --verbose") {
			t.Fatal("applied without durable plan delivery")
		}
	}
}

func TestUnsupportedDistroAndUnsafeCodename(t *testing.T) {
	for _, release := range []string{"ID=alpine\nVERSION_CODENAME=trixie\n", "ID=debian\nVERSION_CODENAME=trixie\";evil\n"} {
		u, r := fixture(t)
		u.readFile = func(string) ([]byte, error) { return []byte(release), nil }
		_, emit := collect()
		if err := u.Run(context.Background(), emit); err == nil {
			t.Fatalf("accepted unsafe release %q", release)
		}
		if len(r.calls) != 0 {
			t.Fatal(r.calls)
		}
	}
}

func TestCancelledBeforeRunHasNoSideEffects(t *testing.T) {
	u, r := fixture(t)
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, emit := collect()
	if err := u.Run(ctx, emit); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
	if len(r.calls) != 0 {
		t.Fatal(r.calls)
	}
	if _, err := os.Stat(filepath.Join(u.Config.StateDir, "run.lock")); !os.IsNotExist(err) {
		t.Fatal("created lock for cancelled run")
	}
}

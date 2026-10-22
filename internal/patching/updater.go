// Package patching runs the distribution's authenticated, security-only updater.
// A failed or interrupted application requires an explicit administrator acknowledgement.
package patching

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
	"strings"
	"sync"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

type Config struct {
	StateDir       string
	Apply          bool
	Reboot         bool
	HealthServices []string
	CommandTimeout time.Duration
}

type Updater struct {
	Config Config
	Runner sensors.CommandRunner
	mu     sync.Mutex
	// Test seams remain private: production always uses the actual host identity.
	platform    string
	euid        func() int
	readFile    func(string) ([]byte, error)
	sourceFiles func() ([]string, error)
}

type receipt struct {
	Status string    `json:"status"`
	At     time.Time `json:"at"`
	Detail string    `json:"detail,omitempty"`
}

func (*Updater) Name() string { return "security-updater" }

var serviceName = regexp.MustCompile(`^[a-zA-Z0-9][a-zA-Z0-9_.@:-]{0,127}\.service$`)
var codenameName = regexp.MustCompile(`^[a-z][a-z0-9]+$`)

func (u *Updater) validate() error {
	platform := u.platform
	if platform == "" {
		platform = runtime.GOOS
	}
	euid := u.euid
	if euid == nil {
		euid = os.Geteuid
	}
	if platform != "linux" || euid() != 0 {
		return errors.New("security updater requires root on Linux")
	}
	if u.Runner == nil {
		return errors.New("command runner is required")
	}
	if !filepath.IsAbs(u.Config.StateDir) || filepath.Clean(u.Config.StateDir) == "/" {
		return errors.New("absolute dedicated patch state directory is required")
	}
	for _, service := range u.Config.HealthServices {
		if !serviceName.MatchString(service) {
			return fmt.Errorf("invalid health service %q: use a literal .service unit", service)
		}
	}
	return nil
}

func (u *Updater) read(path string) ([]byte, error) {
	if u.readFile != nil {
		return u.readFile(path)
	}
	return os.ReadFile(path)
}

func (u *Updater) command(ctx context.Context, aptConfig, name string, args ...string) ([]byte, error) {
	timeout := u.Config.CommandTimeout
	if timeout <= 0 {
		timeout = 20 * time.Minute
	}
	callCtx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	// A clean environment prevents APT_CONFIG, PYTHONPATH and shell environment
	// injection into privileged distribution tools. No shell is involved.
	envArgs := []string{"-i", "PATH=/usr/sbin:/usr/bin:/sbin:/bin", "HOME=/root", "LC_ALL=C", "DEBIAN_FRONTEND=noninteractive"}
	if aptConfig != "" {
		envArgs = append(envArgs, "APT_CONFIG="+aptConfig)
	}
	envArgs = append(envArgs, name)
	envArgs = append(envArgs, args...)
	out, err := u.Runner.Run(callCtx, "/usr/bin/env", envArgs...)
	if err != nil {
		return out, fmt.Errorf("%s: %w: %s", name, err, truncate(out))
	}
	return out, nil
}

func truncate(b []byte) string {
	if len(b) > 8192 {
		b = b[len(b)-8192:]
	}
	return strings.TrimSpace(string(b))
}

func (u *Updater) statePath() string { return filepath.Join(u.Config.StateDir, "receipt.json") }

func (u *Updater) save(r receipt) error {
	r.At = time.Now().UTC()
	data, err := json.Marshal(r)
	if err != nil {
		return err
	}
	f, err := os.CreateTemp(u.Config.StateDir, ".receipt-")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(data); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, u.statePath()); err != nil {
		return err
	}
	dir, err := os.Open(u.Config.StateDir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

// ClearFailure acknowledges an administrator's investigation. It does not repair
// dpkg or roll back packages; the next run still repeats all health checks.
func (u *Updater) ClearFailure() error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.validate(); err != nil {
		return err
	}
	if err := u.secureDirectory(); err != nil {
		return err
	}
	unlock, err := lockState(filepath.Join(u.Config.StateDir, "run.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	return u.save(receipt{Status: "acknowledged", Detail: "administrator acknowledged previous attempt"})
}

func (u *Updater) secureDirectory() error {
	if err := os.MkdirAll(u.Config.StateDir, 0700); err != nil {
		return err
	}
	// Reject symlinked or writable ancestors: state and executable policy must not
	// be replaceable by an unprivileged account, including between service restarts.
	for p := filepath.Clean(u.Config.StateDir); ; p = filepath.Dir(p) {
		st, err := os.Lstat(p)
		if err != nil {
			return err
		}
		if !st.IsDir() || st.Mode()&os.ModeSymlink != 0 {
			return fmt.Errorf("unsafe state directory component %s", p)
		}
		if err := secureOwner(st, p, u.euid != nil); err != nil {
			return err
		}
		if p == "/" {
			break
		}
	}
	return os.Chmod(u.Config.StateDir, 0700)
}

// Reject repository declarations that explicitly bypass apt-secure. Global APT
// options alone cannot override a per-source trusted=yes declaration.
func (u *Updater) verifySources() error {
	files := []string{"/etc/apt/sources.list"}
	if u.sourceFiles != nil {
		var err error
		files, err = u.sourceFiles()
		if err != nil {
			return err
		}
	} else {
		entries, err := os.ReadDir("/etc/apt/sources.list.d")
		if err != nil && !os.IsNotExist(err) {
			return err
		}
		for _, entry := range entries {
			if strings.HasSuffix(entry.Name(), ".list") || strings.HasSuffix(entry.Name(), ".sources") {
				files = append(files, filepath.Join("/etc/apt/sources.list.d", entry.Name()))
			}
		}
	}
	unsafe := regexp.MustCompile(`(?i)(trusted|allow-insecure|allow-weak|allow-downgrade-to-insecure|check-valid-until)\s*(=|:)\s*(yes|true|no|false)`)
	for _, file := range files {
		data, err := u.read(file)
		if os.IsNotExist(err) {
			continue
		}
		if err != nil {
			return err
		}
		for _, line := range strings.Split(string(data), "\n") {
			line = strings.TrimSpace(strings.SplitN(line, "#", 2)[0])
			for _, match := range unsafe.FindAllStringSubmatch(line, -1) {
				key, value := strings.ToLower(match[1]), strings.ToLower(match[3])
				enabled := value == "yes" || value == "true"
				if (key == "check-valid-until" && !enabled) || (key != "check-valid-until" && enabled) {
					return fmt.Errorf("unsafe APT source trust override in %s", file)
				}
			}
		}
	}
	return nil
}

func (u *Updater) policy() (string, error) {
	data, err := u.read("/etc/os-release")
	if err != nil {
		return "", err
	}
	values := map[string]string{}
	for _, line := range strings.Split(string(data), "\n") {
		k, v, ok := strings.Cut(line, "=")
		if ok {
			values[k] = strings.Trim(v, "\"'")
		}
	}
	suite := values["VERSION_CODENAME"]
	if !codenameName.MatchString(suite) {
		return "", errors.New("missing or unsafe VERSION_CODENAME")
	}
	var origins string
	switch values["ID"] {
	case "ubuntu":
		origins = fmt.Sprintf("\"origin=Ubuntu,codename=%s-security,label=Ubuntu\"; \"origin=UbuntuESMApps,codename=%s-apps-security\"; \"origin=UbuntuESM,codename=%s-infra-security\";", suite, suite, suite)
	case "debian":
		origins = fmt.Sprintf("\"origin=Debian,codename=%s-security,label=Debian-Security\";", suite)
	default:
		return "", errors.New("only Ubuntu and Debian are supported")
	}
	return `Dir::Etc::parts "-";
Dir::Etc::main "-";
#clear Unattended-Upgrade;
Unattended-Upgrade::Origins-Pattern { ` + origins + ` };
Unattended-Upgrade::Automatic-Reboot "false";
Unattended-Upgrade::Remove-Unused-Dependencies "false";
Unattended-Upgrade::Remove-New-Unused-Dependencies "false";
Unattended-Upgrade::Allow-downgrade "false";
Unattended-Upgrade::MinimalSteps "true";
APT::Get::AllowUnauthenticated "false";
Acquire::AllowInsecureRepositories "false";
Acquire::AllowDowngradeToInsecureRepositories "false";
Acquire::Check-Valid-Until "true";
Acquire::Retries "0";
DPkg::Lock::Timeout "0";
Dpkg::Options { "--force-confdef"; "--force-confold"; };
`, nil
}

func (u *Updater) health(ctx context.Context) error {
	out, err := u.command(ctx, "", "/usr/bin/dpkg", "--audit")
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "" {
		return fmt.Errorf("dpkg audit is not clean: %s", truncate(out))
	}
	for _, service := range u.Config.HealthServices {
		out, err = u.command(ctx, "", "/usr/bin/systemctl", "is-active", "--", service)
		if err != nil {
			return err
		}
		if strings.TrimSpace(string(out)) != "active" {
			return fmt.Errorf("service %s is not active: %s", service, truncate(out))
		}
	}
	return nil
}

func (u *Updater) Run(ctx context.Context, emit func(sensors.Observation) error) error {
	u.mu.Lock()
	defer u.mu.Unlock()
	if err := u.validate(); err != nil {
		return err
	}
	if err := ctx.Err(); err != nil {
		return err
	}
	if err := u.secureDirectory(); err != nil {
		return err
	}
	// An advisory OS lock serializes updater instances and releases on process
	// death. The durable applying receipt independently detects interrupted work.
	unlock, err := lockState(filepath.Join(u.Config.StateDir, "run.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	event := func(kind string, severity model.Severity, attributes map[string]string) error {
		return emit(sensors.Observation{Kind: kind, Severity: severity, Confidence: 1, DetectorIDs: []string{"aegis:security-update"}, Attributes: attributes})
	}
	if data, err := os.ReadFile(u.statePath()); err == nil {
		var r receipt
		if err = json.Unmarshal(data, &r); err != nil {
			return fmt.Errorf("invalid patch receipt: %w", err)
		}
		if r.Status == "applying" || r.Status == "failed" {
			return event("patching.blocked", model.SeverityHigh, map[string]string{"reason": r.Detail, "status": r.Status, "action": "repair and acknowledge with patch-ack before retrying"})
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	if err := u.verifySources(); err != nil {
		return err
	}
	policy, err := u.policy()
	if err != nil {
		return err
	}
	// A new file inside the private root directory prevents policy symlink attacks.
	policyFile, err := os.CreateTemp(u.Config.StateDir, "apt-security-*.conf")
	if err != nil {
		return err
	}
	policyPath := policyFile.Name()
	defer os.Remove(policyPath)
	if _, err = policyFile.WriteString(policy); err != nil {
		policyFile.Close()
		return err
	}
	if err = policyFile.Close(); err != nil {
		return err
	}
	fail := func(err error) error {
		saveErr := u.save(receipt{Status: "failed", Detail: err.Error()})
		emitErr := event("patching.failed", model.SeverityHigh, map[string]string{"error": err.Error(), "rollback": "not available; inspect package and service state"})
		return errors.Join(err, saveErr, emitErr)
	}
	if err = u.health(ctx); err != nil {
		return fail(err)
	}
	if _, err = u.command(ctx, policyPath, "/usr/bin/apt-get", "-o", "APT::Update::Error-Mode=any", "update"); err != nil {
		return err
	}
	plan, err := u.command(ctx, policyPath, "/usr/bin/unattended-upgrade", "--dry-run", "--verbose")
	if err != nil {
		return err
	}
	if err = event("patching.planned", model.SeverityInfo, map[string]string{"output": truncate(plan), "apply": fmt.Sprint(u.Config.Apply)}); err != nil {
		return err
	}
	if !u.Config.Apply {
		return nil
	}
	if err = u.save(receipt{Status: "applying", Detail: "security package transaction started; incomplete attempts need review"}); err != nil {
		return err
	}
	out, err := u.command(ctx, policyPath, "/usr/bin/unattended-upgrade", "--verbose")
	if err != nil {
		return fail(err)
	}
	if err = u.health(ctx); err != nil {
		return fail(err)
	}
	if err = u.save(receipt{Status: "completed", Detail: truncate(out)}); err != nil {
		return err
	}
	if err = event("patching.completed", model.SeverityInfo, map[string]string{"output": truncate(out), "verification": "dpkg audit and configured systemd services passed"}); err != nil {
		return err
	}
	if _, err = u.read("/run/reboot-required"); err == nil {
		if err = event("patching.reboot_required", model.SeverityMedium, map[string]string{"automatic": fmt.Sprint(u.Config.Reboot)}); err != nil {
			return err
		}
		if u.Config.Reboot {
			_, err = u.command(ctx, "", "/sbin/shutdown", "-r", "+1", "Aegis security updates: verified services; reboot required")
			return err
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	return nil
}

// Package monitor collects bounded Linux host evidence. It never executes
// content found in logs or files, and never modifies monitored files.
package monitor

import (
	"bufio"
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

type Config struct {
	StateDir string
	WebRoots []string
	Runner   sensors.CommandRunner
	// Nil selects standard systemd/cron paths; an empty slice disables scanning.
	PersistencePaths []string
}

type Monitor struct {
	config Config
	mu     sync.Mutex
}
type diskState struct {
	Cursor          string             `json:"cursor"`
	Failures        map[string][]int64 `json:"failures"`
	Files           map[string]string  `json:"files"`
	FileOccurrences map[string]string  `json:"fileOccurrences,omitempty"`
	Baseline        bool               `json:"baseline"`
}

func New(config Config) *Monitor {
	if config.Runner == nil {
		config.Runner = boundedRunner{}
	}
	if config.PersistencePaths == nil {
		config.PersistencePaths = []string{"/etc/systemd/system", "/etc/cron.d", "/etc/crontab", "/var/spool/cron/crontabs"}
	}
	return &Monitor{config: config}
}
func (*Monitor) Name() string { return "aegis.linux-monitor" }

// Run polls at most 1,000 journal records and a bounded set of scoped files.
// Errors are coverage failures, never evidence that the host is clean.
func (m *Monitor) Run(ctx context.Context, emit func(sensors.Observation) error) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	if m.config.StateDir == "" {
		return errors.New("monitor state directory is required")
	}
	state, err := m.load()
	if err != nil {
		return err
	}
	journalErr := m.journal(ctx, &state, emit)
	fileErr := m.files(ctx, &state, emit)
	return errors.Join(journalErr, fileErr)
}

func (m *Monitor) load() (diskState, error) {
	s := diskState{Failures: map[string][]int64{}, Files: map[string]string{}}
	b, err := os.ReadFile(filepath.Join(m.config.StateDir, "monitor.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	if len(b) > 4<<20 {
		return s, errors.New("monitor state exceeds limit")
	}
	if err := json.Unmarshal(b, &s); err != nil {
		return s, fmt.Errorf("decode monitor state: %w", err)
	}
	if s.Failures == nil {
		s.Failures = map[string][]int64{}
	}
	if s.Files == nil {
		s.Files = map[string]string{}
	}
	if s.FileOccurrences == nil {
		s.FileOccurrences = map[string]string{}
	}
	return s, nil
}
func (m *Monitor) save(s *diskState) error {
	if err := os.MkdirAll(m.config.StateDir, 0700); err != nil {
		return err
	}
	b, err := json.Marshal(s)
	if err != nil {
		return err
	}
	if len(b) > 4<<20 {
		return errors.New("monitor state exceeds 4 MiB limit; narrow configured roots")
	}
	f, err := os.CreateTemp(m.config.StateDir, ".monitor-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if _, err = f.Write(b); err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err != nil {
		return err
	}
	if closeErr != nil {
		return closeErr
	}
	return os.Rename(name, filepath.Join(m.config.StateDir, "monitor.json"))
}

type boundedRunner struct{}
type cappedBuffer struct {
	bytes.Buffer
	limit int
}

func (b *cappedBuffer) Write(p []byte) (int, error) {
	limit := b.limit
	if limit == 0 {
		limit = 8 << 20
	}
	if b.Len()+len(p) > limit {
		return 0, errors.New("journal command output exceeds limit")
	}
	return b.Buffer.Write(p)
}
func (boundedRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C")
	var out cappedBuffer
	stderr := cappedBuffer{limit: 16 << 10}
	cmd.Stdout = &out
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil && stderr.Len() > 0 {
		err = fmt.Errorf("%w: %s", err, strings.TrimSpace(stderr.String()))
	}
	return out.Bytes(), err
}

var failedIP = regexp.MustCompile(`(?i)(?:Failed (?:password|publickey|keyboard-interactive).*? from |authentication failure;.*?rhost=)([a-fA-F0-9:.]+)`)
var acceptedIP = regexp.MustCompile(`Accepted (?:password|publickey|keyboard-interactive).*? from ([a-fA-F0-9:.]+)`)

func (m *Monitor) journal(ctx context.Context, s *diskState, emit func(sensors.Observation) error) error {
	args := []string{"--no-pager", "--output=json", "--all", "--quiet", "--lines=+1000", "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd-session"}
	if s.Cursor != "" {
		args = append(args, "--after-cursor="+s.Cursor)
	} else {
		args = append(args, "--since=-10min")
	}
	output, err := m.config.Runner.Run(ctx, "journalctl", args...)
	if err != nil && s.Cursor != "" && ctx.Err() == nil && invalidJournalCursor(err) {
		previous := sha256.Sum256([]byte(s.Cursor))
		if emitErr := emit(sensors.Observation{Kind: "sensor.coverage_gap", Severity: model.SeverityHigh, Confidence: 1, DetectorIDs: []string{"aegis:journal-cursor-recovery"}, Attributes: map[string]string{"reason": "journal_cursor_invalid_or_expired", "previousCursorSha256": hex.EncodeToString(previous[:]), "replayWindowSeconds": "300", "replayRecordLimit": "1000", "status": "degraded", "coverage": "lost journal history cannot be reconstructed; replay may duplicate previous observations"}}); emitErr != nil {
			return emitErr
		}
		// Commit the disclosed reset before replaying. A failed gap emission
		// above leaves the old cursor and correlation state unchanged.
		s.Cursor = ""
		s.Failures = map[string][]int64{}
		if saveErr := m.save(s); saveErr != nil {
			return saveErr
		}
		replay := []string{"--no-pager", "--output=json", "--all", "--quiet", "--lines=1000", "--since=-5min", "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd-session", "+", "_COMM=sshd-session"}
		output, err = m.config.Runner.Run(ctx, "journalctl", replay...)
	}
	if err != nil {
		return fmt.Errorf("read SSH journal: %w", err)
	}
	if len(output) > 8<<20 {
		return errors.New("journal output exceeds limit")
	}
	scan := bufio.NewScanner(bytes.NewReader(output))
	scan.Buffer(make([]byte, 4096), 256<<10)
	count := 0
	for scan.Scan() {
		if err := ctx.Err(); err != nil {
			return err
		}
		count++
		if count > 1000 {
			return errors.New("journal record limit exceeded")
		}
		var row map[string]json.RawMessage
		if err := json.Unmarshal(scan.Bytes(), &row); err != nil {
			return fmt.Errorf("decode journal: %w", err)
		}
		str := func(k string) string { var v string; _ = json.Unmarshal(row[k], &v); return v }
		cursor := str("__CURSOR")
		if cursor == "" {
			return errors.New("journal record has no cursor")
		}
		if cursor == s.Cursor {
			continue
		}
		message := str("MESSAGE")
		at := time.Now().UTC()
		if n, e := strconv.ParseInt(str("__REALTIME_TIMESTAMP"), 10, 64); e == nil {
			at = time.UnixMicro(n).UTC()
		}
		var ip, reason string
		severity := model.SeverityHigh
		if match := failedIP.FindStringSubmatch(message); len(match) > 0 {
			ip = match[1]
			prior := s.Failures[ip]
			recent := make([]int64, 0, 10)
			for _, n := range prior {
				if n >= at.Add(-5*time.Minute).Unix() {
					recent = append(recent, n)
				}
			}
			recent = append(recent, at.Unix())
			if len(recent) == 10 {
				reason = "ssh_failure_burst"
			}
			if len(recent) > 11 {
				recent = recent[len(recent)-11:]
			}
			if reason != "" {
				if err := emit(authObservation(at, ip, reason, severity)); err != nil {
					return err
				}
			}
			s.Failures[ip] = recent
		} else if match := acceptedIP.FindStringSubmatch(message); len(match) > 0 {
			ip = match[1]
			n := 0
			for _, stamp := range s.Failures[ip] {
				if stamp >= at.Add(-5*time.Minute).Unix() {
					n++
				}
			}
			if n >= 10 {
				if err := emit(authObservation(at, ip, "ssh_success_after_failure_burst", model.SeverityCritical)); err != nil {
					return err
				}
			}
			delete(s.Failures, ip)
		}
		for address, stamps := range s.Failures {
			if len(stamps) == 0 || stamps[len(stamps)-1] < at.Add(-5*time.Minute).Unix() {
				delete(s.Failures, address)
			}
		}
		if len(s.Failures) > 4096 {
			return errors.New("SSH source tracking limit exceeded")
		}
		s.Cursor = cursor
		if err := m.save(s); err != nil {
			return err
		}
	}
	return scan.Err()
}

// Recover only diagnostics identifying a cursor failure. Authentication,
// permissions, command availability and generic I/O failures retain state.
func invalidJournalCursor(err error) bool {
	message := strings.ToLower(err.Error())
	for _, denied := range []string{"permission denied", "access denied", "operation not permitted"} {
		if strings.Contains(message, denied) {
			return false
		}
	}
	if strings.Contains(message, "invalid cursor") || strings.Contains(message, "cursor expired") || strings.Contains(message, "cursor has expired") || strings.Contains(message, "cursor not found") {
		return true
	}
	if strings.Contains(message, "failed to seek to cursor") || strings.Contains(message, "failed to seek cursor") {
		for _, reason := range []string{"invalid argument", "cannot assign requested address", "no such file or directory", "not found", "expired"} {
			if strings.Contains(message, reason) {
				return true
			}
		}
	}
	return false
}
func authObservation(at time.Time, ip, reason string, severity model.Severity) sensors.Observation {
	return sensors.Observation{ObservedAt: at, Kind: "authentication.anomaly", Severity: severity, Confidence: .95, DetectorIDs: []string{"aegis:" + reason}, Attributes: map[string]string{"sourceIp": ip, "reason": reason, "windowSeconds": "300", "threshold": "10"}}
}

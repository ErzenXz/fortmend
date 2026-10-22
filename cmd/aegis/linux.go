package main

import (
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/ErzenXz/aegis/internal/agent"
	"github.com/ErzenXz/aegis/internal/codexapp"
	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/monitor"
	"github.com/ErzenXz/aegis/internal/patching"
	"github.com/ErzenXz/aegis/internal/protection"
	"github.com/ErzenXz/aegis/internal/reasoner"
	"github.com/ErzenXz/aegis/internal/remediation"
	"github.com/ErzenXz/aegis/internal/sensors"
	"github.com/ErzenXz/aegis/internal/vulnerability"
)

type linuxPolicy struct {
	SchemaVersion     string   `json:"schemaVersion"`
	DeviceID          string   `json:"deviceId"`
	StateDir          string   `json:"stateDir"`
	HubConfig         string   `json:"hubConfig,omitempty"`
	PollSeconds       int      `json:"pollSeconds"`
	AssessmentMinutes int      `json:"assessmentMinutes"`
	SecurityUpdates   bool     `json:"securityUpdates"`
	AutomaticReboot   bool     `json:"automaticReboot"`
	AutoQuarantine    bool     `json:"autoQuarantine"`
	WebRoots          []string `json:"webRoots"`
	HealthServices    []string `json:"healthServices"`
	AI                struct {
		Enabled bool   `json:"enabled"`
		Mode    string `json:"mode"`
		Binary  string `json:"binary"`
		Model   string `json:"model,omitempty"`
		WorkDir string `json:"workDir"`
	} `json:"ai"`
}

func loadLinuxPolicy(path string) (linuxPolicy, error) {
	var p linuxPolicy
	f, err := os.Open(path)
	if err != nil {
		return p, err
	}
	defer f.Close()
	d := json.NewDecoder(io.LimitReader(f, 64*1024))
	d.DisallowUnknownFields()
	if err := d.Decode(&p); err != nil {
		return p, err
	}
	var extra any
	if err := d.Decode(&extra); err != io.EOF {
		return p, fmt.Errorf("policy must contain one JSON object")
	}
	if p.SchemaVersion != "aegis.linux/v1" {
		return p, fmt.Errorf("unsupported Linux policy schema")
	}
	if p.StateDir == "" {
		p.StateDir = "/var/lib/aegis/protection"
	}
	if !filepath.IsAbs(p.StateDir) || filepath.Clean(p.StateDir) == "/" {
		return p, fmt.Errorf("absolute dedicated stateDir required")
	}
	if p.PollSeconds == 0 {
		p.PollSeconds = 5
	}
	if p.AssessmentMinutes == 0 {
		p.AssessmentMinutes = 60
	}
	if p.PollSeconds > 3600 || p.AssessmentMinutes > 10080 {
		return p, fmt.Errorf("policy interval exceeds limit")
	}
	if err := protection.ValidateIntervals(time.Duration(p.PollSeconds)*time.Second, time.Duration(p.AssessmentMinutes)*time.Minute); err != nil {
		return p, err
	}
	if p.AI.Enabled && p.AI.Mode != "investigate" && p.AI.Mode != "full-control" {
		return p, fmt.Errorf("ai.mode must be investigate or full-control")
	}
	if p.AI.WorkDir == "" {
		p.AI.WorkDir = "/"
	}
	if !filepath.IsAbs(p.AI.WorkDir) {
		return p, fmt.Errorf("absolute AI workDir required")
	}
	if p.AI.Binary == "" {
		p.AI.Binary = "/usr/local/bin/codex"
	}
	if !filepath.IsAbs(p.AI.Binary) {
		return p, fmt.Errorf("absolute Codex binary path required")
	}
	for _, root := range p.WebRoots {
		if !filepath.IsAbs(root) || filepath.Clean(root) == "/" || strings.Contains(root, "\x00") {
			return p, fmt.Errorf("explicit absolute webRoots required")
		}
	}
	for _, service := range p.HealthServices {
		if !strings.HasSuffix(service, ".service") || strings.ContainsAny(service, " /\\\n\r\x00") || strings.HasPrefix(service, "-") {
			return p, fmt.Errorf("literal .service health unit required")
		}
	}
	return p, nil
}

func runProtect(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("protect", flag.ContinueOnError)
	flags.SetOutput(stderr)
	path := flags.String("config", "/etc/aegis/linux.json", "root-owned Linux policy JSON")
	once := flags.Bool("once", false, "run monitor, assessment, updates and verification once")
	status := flags.Bool("status", false, "show local state without starting protection")
	ack := flags.Bool("acknowledge-update-failure", false, "acknowledge investigated update failure; does not repair packages")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if flags.NArg() != 0 {
		return fmt.Errorf("unexpected protect arguments")
	}
	if runtime.GOOS != "linux" || os.Geteuid() != 0 {
		return fmt.Errorf("protect runs as root inside an Ubuntu/Debian VM")
	}
	if err := protection.ValidateRootPath(*path, false); err != nil {
		return err
	}
	p, err := loadLinuxPolicy(*path)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(p.StateDir, 0700); err != nil {
		return err
	}
	if err := protection.ValidateRootPath(p.StateDir, true); err != nil {
		return err
	}
	runner := sensors.SystemRunner{}
	updater := &patching.Updater{Config: patching.Config{StateDir: filepath.Join(p.StateDir, "patching"), Apply: p.SecurityUpdates, Reboot: p.AutomaticReboot, HealthServices: p.HealthServices}, Runner: runner}
	if *ack {
		return updater.ClearFailure()
	}
	if *status {
		result := map[string]any{"deviceId": p.DeviceID, "stateDir": p.StateDir, "securityUpdates": p.SecurityUpdates, "automaticReboot": p.AutomaticReboot, "autoQuarantine": p.AutoQuarantine, "aiMode": p.AI.Mode, "aiEnabled": p.AI.Enabled, "hostClean": "not_asserted"}
		if data, err := os.ReadFile(filepath.Join(p.StateDir, "patching", "receipt.json")); err == nil {
			result["lastUpdate"] = json.RawMessage(data)
		}
		return json.NewEncoder(stdout).Encode(result)
	}
	unlock, err := protection.AcquireLock(filepath.Join(p.StateDir, "protect.lock"))
	if err != nil {
		return err
	}
	defer unlock()
	if p.DeviceID == "" {
		p.DeviceID, _ = os.Hostname()
	}
	queue, err := agent.OpenQueue(filepath.Join(p.StateDir, "events.jsonl"), 16*1024*1024)
	if err != nil {
		return err
	}
	r := &protection.Runtime{DeviceID: p.DeviceID, StateDir: p.StateDir, Queue: queue, Monitor: monitor.New(monitor.Config{StateDir: filepath.Join(p.StateDir, "monitor"), WebRoots: p.WebRoots}), Assessment: &vulnerability.Scanner{Runner: runner, CacheDir: filepath.Join(p.StateDir, "vulnerability")}, Updater: updater, PollInterval: time.Duration(p.PollSeconds) * time.Second, AssessmentInterval: time.Duration(p.AssessmentMinutes) * time.Minute, FullControl: p.AI.Enabled && p.AI.Mode == "full-control", Report: func(err error) { fmt.Fprintf(stderr, "aegis protection: %v\n", err) }}
	log := &protection.EventLog{Path: filepath.Join(p.StateDir, "history.jsonl"), MaxBytes: 16 * 1024 * 1024}
	r.Post = log.Append
	if p.HubConfig != "" {
		config, err := agent.LoadConfig(p.HubConfig)
		if err != nil {
			return err
		}
		if config.DeviceID != p.DeviceID {
			return fmt.Errorf("hub enrollment deviceId does not match protection policy")
		}
		client, err := agent.NewClient(config)
		if err != nil {
			return err
		}
		r.Post = func(ctx context.Context, e model.SecurityEvent) error {
			if err := client.PostEvent(ctx, e); err != nil {
				return err
			}
			return log.Append(ctx, e)
		}
	}
	q := &remediation.Quarantine{StateDir: p.StateDir, WebRoots: p.WebRoots}
	r.Reconcile = func(ctx context.Context) error {
		return q.Replay(ctx, func(o sensors.Observation) error { return r.RecordResponse(ctx, o) })
	}
	if p.AutoQuarantine {
		r.Contain = q.Apply
	}
	if p.AI.Enabled {
		r.Reasoner = reasoner.NewFX(&codexapp.Client{Config: codexapp.Config{Binary: p.AI.Binary, Home: filepath.Join(p.StateDir, "codex"), Model: p.AI.Model, WorkDir: p.AI.WorkDir, FullControl: p.AI.Mode == "full-control", Activity: r.RecordActivity}})
	}
	r.Verify = func(ctx context.Context) error {
		data, err := runner.Run(ctx, "dpkg", "--audit")
		if err != nil {
			return err
		}
		if len(strings.TrimSpace(string(data))) > 0 {
			return errors.New("dpkg audit reports incomplete package state")
		}
		for _, service := range p.HealthServices {
			if _, err := runner.Run(ctx, "systemctl", "is-active", "--quiet", service); err != nil {
				return fmt.Errorf("service health failed: %s", service)
			}
		}
		return nil
	}
	r.VerifyEvent = func(ctx context.Context, e model.SecurityEvent) error {
		if e.Kind != "webshell.suspicious" {
			return nil
		}
		path := e.Attributes["path"]
		if path == "" {
			return errors.New("webshell verification requires original path")
		}
		if err := ctx.Err(); err != nil {
			return err
		}
		err := monitor.VerifyWebshellAbsent(path)
		if errors.Is(err, monitor.ErrWebshellPresent) {
			return fmt.Errorf("%w: %s", protection.ErrUnresolved, err)
		}
		return err
	}
	fmt.Fprintf(stdout, "Aegis protection starting: device=%s updates=%t AI=%s enabled=%t\n", p.DeviceID, p.SecurityUpdates, p.AI.Mode, p.AI.Enabled)
	return r.Run(ctx, *once)
}

func runAI(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: aegis ai <login|status> --state-dir /var/lib/aegis/protection")
	}
	flags := flag.NewFlagSet("ai", flag.ContinueOnError)
	flags.SetOutput(stderr)
	state := flags.String("state-dir", "/var/lib/aegis/protection", "protection state directory")
	binary := flags.String("binary", "/usr/local/bin/codex", "official Codex CLI path")
	if err := flags.Parse(args[1:]); err != nil {
		return err
	}
	c := &codexapp.Client{Config: codexapp.Config{Binary: *binary, Home: filepath.Join(*state, "codex")}}
	switch args[0] {
	case "login":
		return c.Login(ctx, func(url, code string) { fmt.Fprintf(stdout, "Sign in to ChatGPT: %s\nDevice code: %s\n", url, code) })
	case "status":
		data, err := c.Account(ctx)
		if err != nil {
			return err
		}
		_, err = fmt.Fprintln(stdout, string(data))
		return err
	default:
		return fmt.Errorf("unknown AI command %q", args[0])
	}
}

package sensors

import (
	"context"
	"encoding/json"
	"fmt"
	"os/exec"
	"strings"

	"github.com/ErzenXz/aegis/internal/model"
)

type CommandRunner interface {
	Run(context.Context, string, ...string) ([]byte, error)
}

type Osquery struct{ runner CommandRunner }

func NewOsquery(runner CommandRunner) *Osquery { return &Osquery{runner: runner} }

func (*Osquery) Name() string { return "osquery" }

func (scanner *Osquery) Run(ctx context.Context, emit func(Observation) error) error {
	output, err := scanner.runner.Run(ctx, "osqueryi", "--json", "SELECT name, version, platform, arch FROM os_version;")
	if err != nil {
		return fmt.Errorf("osquery inventory: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var rows []map[string]string
	if err := json.Unmarshal(output, &rows); err != nil {
		return fmt.Errorf("decode osquery inventory: %w", err)
	}
	for _, row := range rows {
		if err := emit(Observation{
			Kind:        "host.os_version",
			Severity:    model.SeverityInfo,
			Confidence:  1,
			DetectorIDs: []string{"osquery:os_version"},
			Attributes:  row,
		}); err != nil {
			return err
		}
	}
	return nil
}

type Trivy struct {
	runner CommandRunner
	target string
}

func NewTrivy(runner CommandRunner, target string) *Trivy {
	return &Trivy{runner: runner, target: target}
}

func (*Trivy) Name() string { return "trivy" }

func (scanner *Trivy) Run(ctx context.Context, emit func(Observation) error) error {
	if scanner.target == "" {
		return fmt.Errorf("Trivy target is required")
	}
	output, err := scanner.runner.Run(ctx, "trivy", "rootfs", "--format", "json", "--scanners", "vuln,misconfig", "--quiet", scanner.target)
	if err != nil {
		return fmt.Errorf("trivy scan: %w: %s", err, strings.TrimSpace(string(output)))
	}
	var report struct {
		Results []struct {
			Target          string `json:"Target"`
			Vulnerabilities []struct {
				ID               string `json:"VulnerabilityID"`
				Package          string `json:"PkgName"`
				InstalledVersion string `json:"InstalledVersion"`
				FixedVersion     string `json:"FixedVersion"`
				Severity         string `json:"Severity"`
				Title            string `json:"Title"`
			} `json:"Vulnerabilities"`
		} `json:"Results"`
	}
	if err := json.Unmarshal(output, &report); err != nil {
		return fmt.Errorf("decode trivy report: %w", err)
	}
	for _, result := range report.Results {
		for _, vulnerability := range result.Vulnerabilities {
			if vulnerability.ID == "" {
				continue
			}
			if err := emit(Observation{
				Kind:        "vulnerability.detected",
				Severity:    severityFromTrivy(vulnerability.Severity),
				Confidence:  1,
				DetectorIDs: []string{"trivy:" + vulnerability.ID},
				Attributes: map[string]string{
					"target":           result.Target,
					"vulnerabilityId":  vulnerability.ID,
					"package":          vulnerability.Package,
					"installedVersion": vulnerability.InstalledVersion,
					"fixedVersion":     vulnerability.FixedVersion,
					"title":            vulnerability.Title,
				},
			}); err != nil {
				return err
			}
		}
	}
	return nil
}

func severityFromTrivy(severity string) model.Severity {
	switch strings.ToUpper(severity) {
	case "CRITICAL":
		return model.SeverityCritical
	case "HIGH":
		return model.SeverityHigh
	case "MEDIUM":
		return model.SeverityMedium
	case "LOW":
		return model.SeverityLow
	default:
		return model.SeverityInfo
	}
}

type ExecRunner struct{}

func (ExecRunner) Run(ctx context.Context, name string, args ...string) ([]byte, error) {
	return exec.CommandContext(ctx, name, args...).CombinedOutput()
}

type YARA struct {
	runner    CommandRunner
	rulesPath string
	targets   []string
}

func NewYARA(runner CommandRunner, rulesPath string, targets []string) *YARA {
	return &YARA{runner: runner, rulesPath: rulesPath, targets: append([]string(nil), targets...)}
}

func (*YARA) Name() string { return "yara" }

func (scanner *YARA) Run(ctx context.Context, emit func(Observation) error) error {
	if scanner.rulesPath == "" || len(scanner.targets) == 0 {
		return fmt.Errorf("YARA rules and at least one target are required")
	}
	args := append([]string{"-r", scanner.rulesPath}, scanner.targets...)
	output, err := scanner.runner.Run(ctx, "yara", args...)
	if err != nil {
		return fmt.Errorf("yara scan: %w: %s", err, strings.TrimSpace(string(output)))
	}
	for _, line := range strings.Split(string(output), "\n") {
		fields := strings.Fields(line)
		if len(fields) < 2 {
			continue
		}
		rule := fields[0]
		path := strings.Join(fields[1:], " ")
		if err := emit(Observation{
			Kind:        "malware.signature_match",
			Severity:    model.SeverityCritical,
			Confidence:  1,
			DetectorIDs: []string{"yara:" + rule},
			Attributes:  map[string]string{"rule": rule, "path": path},
		}); err != nil {
			return err
		}
	}
	return nil
}

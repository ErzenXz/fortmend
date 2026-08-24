package sensors_test

import (
	"context"
	"testing"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

type fixtureRunner struct {
	output []byte
	err    error
}

func (runner fixtureRunner) Run(context.Context, string, ...string) ([]byte, error) {
	return runner.output, runner.err
}

func TestYARAAdapterNormalizesMatches(t *testing.T) {
	adapter := sensors.NewYARA(fixtureRunner{output: []byte("EICAR_Test_File /tmp/eicar.com\n")}, "/rules", []string{"/tmp"})
	var observations []sensors.Observation
	if err := adapter.Run(context.Background(), func(observation sensors.Observation) error {
		observations = append(observations, observation)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Kind != "malware.signature_match" || observations[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected observations: %#v", observations)
	}
	if observations[0].Attributes["path"] != "/tmp/eicar.com" || observations[0].DetectorIDs[0] != "yara:EICAR_Test_File" {
		t.Fatalf("match provenance lost: %#v", observations[0])
	}
}

func TestTrivyAdapterEmitsFixableCriticalVulnerability(t *testing.T) {
	fixture := []byte(`{"Results":[{"Target":"ubuntu","Vulnerabilities":[{"VulnerabilityID":"CVE-2026-0001","PkgName":"openssl","InstalledVersion":"1.0","FixedVersion":"1.1","Severity":"CRITICAL","Title":"fixture"}]}]}`)
	adapter := sensors.NewTrivy(fixtureRunner{output: fixture}, "/")
	var observations []sensors.Observation
	if err := adapter.Run(context.Background(), func(observation sensors.Observation) error {
		observations = append(observations, observation)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Kind != "vulnerability.detected" || observations[0].Severity != model.SeverityCritical {
		t.Fatalf("unexpected observations: %#v", observations)
	}
	if observations[0].Attributes["fixedVersion"] != "1.1" || observations[0].DetectorIDs[0] != "trivy:CVE-2026-0001" {
		t.Fatalf("vulnerability provenance lost: %#v", observations[0])
	}
}

func TestOsqueryAdapterNormalizesOperatingSystemInventory(t *testing.T) {
	fixture := []byte(`[{"name":"macOS","version":"15.6","platform":"darwin","arch":"arm64"}]`)
	adapter := sensors.NewOsquery(fixtureRunner{output: fixture})
	var observations []sensors.Observation
	if err := adapter.Run(context.Background(), func(observation sensors.Observation) error {
		observations = append(observations, observation)
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if len(observations) != 1 || observations[0].Kind != "host.os_version" || observations[0].Attributes["version"] != "15.6" {
		t.Fatalf("unexpected observations: %#v", observations)
	}
}

package sensors

import (
	"context"
	"os"
	"os/exec"
	"runtime"

	"github.com/ErzenXz/fortmend/internal/model"
)

type HostSnapshot struct{}

func (HostSnapshot) Name() string { return "fortmend.host" }

func (HostSnapshot) Run(ctx context.Context, emit func(Observation) error) error {
	hostname, _ := os.Hostname()
	if err := emit(Observation{
		Kind:        "host.inventory",
		Severity:    model.SeverityInfo,
		Confidence:  1,
		DetectorIDs: []string{"fortmend:host-snapshot"},
		Attributes: map[string]string{
			"hostname": hostname,
			"os":       runtime.GOOS,
			"arch":     runtime.GOARCH,
		},
	}); err != nil {
		return err
	}
	for _, tool := range []string{"osqueryi", "trivy", "yara"} {
		if err := ctx.Err(); err != nil {
			return err
		}
		_, err := exec.LookPath(tool)
		status := "available"
		severity := model.SeverityInfo
		if err != nil {
			status = "missing"
			severity = model.SeverityMedium
		}
		if err := emit(Observation{
			Kind:        "sensor.capability",
			Severity:    severity,
			Confidence:  1,
			DetectorIDs: []string{"fortmend:capability-check"},
			Attributes:  map[string]string{"tool": tool, "status": status},
		}); err != nil {
			return err
		}
	}
	return nil
}

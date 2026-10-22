package main

import (
	"context"
	"encoding/json"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"
	"syscall"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/sensors"
)

const (
	aegisVersion = "0.1.0-dev"
	fxVersion    = "v0.0.5"
)

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdout, os.Stderr))
}

func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	if len(args) == 0 {
		fmt.Fprint(stderr, usage)
		return 2
	}
	switch args[0] {
	case "protect":
		if err := runProtect(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis protect: %v\n", err)
			return 1
		}
		return 0
	case "ai":
		if err := runAI(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis ai: %v\n", err)
			return 1
		}
		return 0
	case "version", "--version", "-v":
		fmt.Fprintf(stdout, "aegis %s (fx %s)\n", aegisVersion, fxVersion)
		return 0
	case "scan":
		if err := runScan(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis scan: %v\n", err)
			return 1
		}
		return 0
	case "hub":
		if err := runHub(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis hub: %v\n", err)
			return 1
		}
		return 0
	case "enroll":
		if err := runEnroll(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis enroll: %v\n", err)
			return 1
		}
		return 0
	case "agent":
		if err := runAgent(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis agent: %v\n", err)
			return 1
		}
		return 0
	case "status":
		if err := runStatus(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis status: %v\n", err)
			return 1
		}
		return 0
	case "doctor":
		if err := runDoctor(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis doctor: %v\n", err)
			return 1
		}
		return 0
	case "provider":
		if err := runProvider(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis provider: %v\n", err)
			return 1
		}
		return 0
	case "onboard":
		if err := runOnboard(ctx, args[1:], stdout, stderr); err != nil {
			fmt.Fprintf(stderr, "aegis onboard: %v\n", err)
			return 1
		}
		return 0
	case "help", "--help", "-h":
		fmt.Fprint(stdout, usage)
		return 0
	default:
		fmt.Fprintf(stderr, "aegis: unknown command %q\n\n%s", args[0], usage)
		return 2
	}
}

func runScan(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("scan", flag.ContinueOnError)
	flags.SetOutput(stderr)
	deviceID := flags.String("device-id", "", "stable device identifier")
	useOsquery := flags.Bool("osquery", false, "collect osquery operating-system inventory")
	trivyTarget := flags.String("trivy-target", "", "scan a root filesystem or directory with Trivy")
	yaraRules := flags.String("yara-rules", "", "YARA rules file or directory")
	yaraTargets := flags.String("yara-targets", "", "comma-separated YARA scan targets")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *deviceID == "" {
		hostname, _ := os.Hostname()
		*deviceID = hostname
	}
	encoder := json.NewEncoder(stdout)
	adapters := []sensors.Adapter{sensors.HostSnapshot{}}
	if *useOsquery {
		adapters = append(adapters, sensors.NewOsquery(sensors.ExecRunner{}))
	}
	if *trivyTarget != "" {
		adapters = append(adapters, sensors.NewTrivy(sensors.ExecRunner{}, *trivyTarget))
	}
	if *yaraRules != "" {
		targets := splitNonEmpty(*yaraTargets)
		if len(targets) == 0 {
			return fmt.Errorf("--yara-targets is required with --yara-rules")
		}
		adapters = append(adapters, sensors.NewYARA(sensors.ExecRunner{}, *yaraRules, targets))
	}
	stream := sensors.NewStream(*deviceID, adapters...)
	return stream.Start(ctx, func(event model.SecurityEvent) error { return encoder.Encode(event) })
}

const usage = `Aegis — self-hosted autonomous endpoint defense.

Usage:
  aegis hub       Run the self-hosted hub
  aegis agent     Run the endpoint protection loop
  aegis protect   Run Ubuntu/Debian monitoring, updates and autonomous repair
  aegis ai        Sign in to ChatGPT or inspect Codex account status
  aegis enroll    Enroll this device with a hub
  aegis scan      Run a local developer-preview scan
  aegis status    Show local or hub health
  aegis doctor    Check sensor and planner readiness
  aegis provider  Login, logout, or inspect an fx provider
  aegis onboard   Guided hub or endpoint setup
  aegis version   Print version information
`

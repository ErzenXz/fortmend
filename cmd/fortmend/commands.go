package main

import (
	"bufio"
	"context"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/ErzenXz/fortmend/internal/agent"
	"github.com/ErzenXz/fortmend/internal/detection"
	"github.com/ErzenXz/fortmend/internal/hub"
	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/pki"
	"github.com/ErzenXz/fortmend/internal/sensors"
	"github.com/ErzenXz/fortmend/internal/store"
)

func runHub(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("hub", flag.ContinueOnError)
	flags.SetOutput(stderr)
	address := flags.String("addr", ":7443", "HTTPS listen address")
	dataDir := flags.String("data-dir", defaultDataDir(), "hub data directory")
	tlsHosts := flags.String("tls-hosts", "localhost,127.0.0.1", "comma-separated certificate DNS names or IPs")
	publicURL := flags.String("public-url", "", "HTTPS URL endpoints use to reach this hub")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if err := os.MkdirAll(*dataDir, 0o700); err != nil {
		return err
	}
	authority, err := loadOrCreateAuthority(filepath.Join(*dataDir, "pki"))
	if err != nil {
		return err
	}
	serverCredential, err := authority.IssueServer(splitNonEmpty(*tlsHosts), time.Now().UTC())
	if err != nil {
		return err
	}
	enrollmentToken, err := freshEnrollmentToken(filepath.Join(*dataDir, "enrollment-token"))
	if err != nil {
		return err
	}
	mcpToken, err := freshEnrollmentToken(filepath.Join(*dataDir, "mcp-token"))
	if err != nil {
		return err
	}
	database, err := store.Open(filepath.Join(*dataDir, "fortmend.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		return err
	}
	defer database.Close()
	go func() {
		ticker := time.NewTicker(time.Hour)
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case now := <-ticker.C:
				if err := database.Prune(context.Background(), now.UTC()); err != nil {
					fmt.Fprintf(stderr, "fortmend hub retention: %v\n", err)
				}
			}
		}
	}()
	handler := hub.NewWithOptions(database, detection.New(detection.DefaultPolicy()), hub.Options{
		Authority:               authority,
		EnrollmentToken:         enrollmentToken,
		RequireAgentCertificate: true,
		MCPToken:                mcpToken,
	})
	listener, err := net.Listen("tcp", *address)
	if err != nil {
		return err
	}
	defer listener.Close()
	tlsListener := tls.NewListener(listener, &tls.Config{
		Certificates: []tls.Certificate{serverCredential},
		ClientAuth:   tls.RequestClientCert,
		MinVersion:   tls.VersionTLS13,
	})
	server := &http.Server{Handler: handler, ReadHeaderTimeout: 10 * time.Second, IdleTimeout: 2 * time.Minute}
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	fmt.Fprintf(stdout, "Fortmend hub listening on https://%s\n", listener.Addr())
	fmt.Fprintf(stdout, "Enrollment token (single use for this run): %s\n", enrollmentToken)
	fmt.Fprintf(stdout, "Hub CA: %s\n", filepath.Join(*dataDir, "pki", "ca.pem"))
	fmt.Fprintf(stdout, "Hub CA SHA-256: %s\n", authority.FingerprintSHA256())
	fmt.Fprintf(stdout, "Security MCP credential: %s\n", filepath.Join(*dataDir, "mcp-token"))
	if *publicURL != "" {
		fmt.Fprintf(stdout, "\nInstall an endpoint with one command:\n")
		fmt.Fprintf(stdout, "curl -fsSL https://fortmend.erzen.dev/install.sh | sh -s -- --role agent --hub %s --token %s --ca-sha256 %s\n", shellQuote(*publicURL), shellQuote(enrollmentToken), shellQuote(authority.FingerprintSHA256()))
	}
	err = server.Serve(tlsListener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	return err
}

func runEnroll(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("enroll", flag.ContinueOnError)
	flags.SetOutput(stderr)
	hubURL := flags.String("hub", "", "hub HTTPS URL")
	token := flags.String("token", "", "single-use enrollment token")
	caPath := flags.String("ca", "", "trusted hub CA PEM path")
	caFingerprint := flags.String("ca-sha256", "", "trusted hub CA SHA-256 fingerprint")
	deviceID := flags.String("device-id", "", "stable device identifier")
	configPath := flags.String("config", filepath.Join(defaultDataDir(), "agent.json"), "agent configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	if *deviceID == "" {
		*deviceID, _ = os.Hostname()
	}
	if *hubURL == "" || *token == "" || (*caPath == "" && *caFingerprint == "") || (*caPath != "" && *caFingerprint != "") || *deviceID == "" {
		return fmt.Errorf("--hub, --token, exactly one of --ca or --ca-sha256, and a device id are required")
	}
	var config agent.Config
	var err error
	if *caFingerprint != "" {
		config, err = agent.EnrollPinned(ctx, *hubURL, *token, *caFingerprint, *deviceID)
	} else {
		config, err = agent.Enroll(ctx, *hubURL, *token, *caPath, *deviceID)
	}
	if err != nil {
		return err
	}
	if err := agent.SaveConfig(*configPath, config); err != nil {
		return err
	}
	fmt.Fprintf(stdout, "enrolled %s with %s; config saved to %s\n", config.DeviceID, config.HubURL, *configPath)
	return nil
}

func runOnboard(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("onboard", flag.ContinueOnError)
	flags.SetOutput(stderr)
	role := flags.String("role", "", "hub or agent")
	hubURL := flags.String("hub", "", "hub HTTPS URL")
	token := flags.String("token", "", "single-use enrollment token")
	caFingerprint := flags.String("ca-sha256", "", "hub CA SHA-256 fingerprint")
	publicURL := flags.String("public-url", "", "public hub HTTPS URL")
	address := flags.String("addr", ":7443", "hub HTTPS listen address")
	dataDir := flags.String("data-dir", defaultDataDir(), "Fortmend data directory")
	if err := flags.Parse(args); err != nil {
		return err
	}
	reader := bufio.NewReader(os.Stdin)
	if *role == "" {
		fmt.Fprintln(stdout, "Fortmend onboarding")
		fmt.Fprint(stdout, "Protect this machine as a hub or agent? [hub/agent]: ")
		value, _ := reader.ReadString('\n')
		*role = strings.ToLower(strings.TrimSpace(value))
	}
	switch *role {
	case "hub":
		if *publicURL == "" {
			fmt.Fprint(stdout, "Public HTTPS URL devices will use (optional): ")
			value, _ := reader.ReadString('\n')
			*publicURL = strings.TrimSpace(value)
		}
		hosts := "localhost,127.0.0.1"
		if parsed, err := url.Parse(*publicURL); err == nil && parsed.Hostname() != "" {
			hosts += "," + parsed.Hostname()
		}
		return runHub(ctx, []string{"--addr", *address, "--data-dir", *dataDir, "--tls-hosts", hosts, "--public-url", *publicURL}, stdout, stderr)
	case "agent":
		if *hubURL == "" {
			fmt.Fprint(stdout, "Hub HTTPS URL: ")
			value, _ := reader.ReadString('\n')
			*hubURL = strings.TrimSpace(value)
		}
		if *token == "" {
			fmt.Fprint(stdout, "Enrollment token: ")
			value, _ := reader.ReadString('\n')
			*token = strings.TrimSpace(value)
		}
		if *caFingerprint == "" {
			fmt.Fprint(stdout, "Hub CA SHA-256 fingerprint: ")
			value, _ := reader.ReadString('\n')
			*caFingerprint = strings.TrimSpace(value)
		}
		return runEnroll(ctx, []string{"--hub", *hubURL, "--token", *token, "--ca-sha256", *caFingerprint, "--config", filepath.Join(*dataDir, "agent.json")}, stdout, stderr)
	default:
		return fmt.Errorf("role must be hub or agent")
	}
}

func runAgent(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("agent", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", filepath.Join(defaultDataDir(), "agent.json"), "agent configuration path")
	interval := flags.Duration("interval", time.Minute, "snapshot interval")
	once := flags.Bool("once", false, "run one collection cycle")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	client, err := agent.NewClient(config)
	if err != nil {
		return err
	}
	queue, err := agent.OpenQueue(filepath.Join(filepath.Dir(*configPath), "events.jsonl"), 10*1024*1024)
	if err != nil {
		return err
	}
	cycle := func() error {
		_ = queue.Drain(ctx, client.PostEvent)
		stream := sensors.NewStream(config.DeviceID, sensors.HostSnapshot{})
		if err := stream.Start(ctx, queue.Push); err != nil {
			return err
		}
		if err := queue.Drain(ctx, client.PostEvent); err != nil {
			return fmt.Errorf("hub unavailable; %d events queued: %w", queue.Len(), err)
		}
		fmt.Fprintf(stdout, "snapshot delivered at %s\n", time.Now().UTC().Format(time.RFC3339))
		return nil
	}
	if *once {
		return cycle()
	}
	ticker := time.NewTicker(*interval)
	defer ticker.Stop()
	for {
		if err := cycle(); err != nil {
			fmt.Fprintln(stderr, err)
		}
		select {
		case <-ctx.Done():
			return nil
		case <-ticker.C:
		}
	}
}

func runStatus(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("status", flag.ContinueOnError)
	flags.SetOutput(stderr)
	configPath := flags.String("config", filepath.Join(defaultDataDir(), "agent.json"), "agent configuration path")
	if err := flags.Parse(args); err != nil {
		return err
	}
	config, err := agent.LoadConfig(*configPath)
	if err != nil {
		return err
	}
	client, err := secureHTTPClient(config)
	if err != nil {
		return err
	}
	request, _ := http.NewRequestWithContext(ctx, http.MethodGet, config.HubURL+"/healthz", nil)
	response, err := client.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	_, err = io.Copy(stdout, response.Body)
	return err
}

func runDoctor(_ context.Context, args []string, stdout, stderr io.Writer) error {
	flags := flag.NewFlagSet("doctor", flag.ContinueOnError)
	flags.SetOutput(stderr)
	if err := flags.Parse(args); err != nil {
		return err
	}
	type check struct {
		Name   string `json:"name"`
		Status string `json:"status"`
		Detail string `json:"detail"`
	}
	checks := []check{{Name: "platform", Status: "ok", Detail: "developer-preview user-mode sensors"}}
	for _, name := range []string{"osqueryi", "trivy", "yara", "fortmend-fx"} {
		path, err := exec.LookPath(name)
		if err != nil {
			checks = append(checks, check{Name: name, Status: "warn", Detail: "not installed"})
		} else {
			checks = append(checks, check{Name: name, Status: "ok", Detail: path})
		}
	}
	return json.NewEncoder(stdout).Encode(map[string]any{"schemaVersion": model.SchemaVersion, "checks": checks})
}

func runProvider(ctx context.Context, args []string, stdout, stderr io.Writer) error {
	if len(args) == 0 {
		return fmt.Errorf("usage: fortmend provider <login|logout|status|setup> [vercel|codex|grok]")
	}
	var fxArgs []string
	switch args[0] {
	case "login":
		if len(args) != 2 || !oneOf(args[1], "vercel", "codex", "grok") {
			return fmt.Errorf("usage: fortmend provider login <vercel|codex|grok>")
		}
		fxArgs = []string{"login", args[1]}
	case "logout":
		if len(args) != 2 || !oneOf(args[1], "codex", "grok") {
			return fmt.Errorf("usage: fortmend provider logout <codex|grok>")
		}
		fxArgs = []string{"logout", args[1]}
	case "status":
		fxArgs = []string{"status", "--json"}
	case "setup":
		fxArgs = []string{"setup"}
	default:
		return fmt.Errorf("unknown provider command %q", args[0])
	}
	binary := os.Getenv("FORTMEND_FX_PATH")
	if binary == "" {
		binary = "fortmend-fx"
	}
	command := exec.CommandContext(ctx, binary, fxArgs...)
	command.Stdin, command.Stdout, command.Stderr = os.Stdin, stdout, stderr
	return command.Run()
}

func secureHTTPClient(config agent.Config) (*http.Client, error) {
	credential, err := tls.X509KeyPair([]byte(config.Certificate), []byte(config.PrivateKey))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(config.CA)) {
		return nil, fmt.Errorf("invalid hub CA")
	}
	return &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{credential}, RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 30 * time.Second}, nil
}

func loadOrCreateAuthority(directory string) (*pki.Authority, error) {
	authority, err := pki.LoadAuthority(directory)
	if err == nil {
		return authority, nil
	}
	if !os.IsNotExist(err) {
		return nil, err
	}
	authority, err = pki.NewAuthority("Fortmend Local Hub CA", time.Now().UTC())
	if err != nil {
		return nil, err
	}
	if err := authority.Save(directory); err != nil {
		return nil, err
	}
	return authority, nil
}

func freshEnrollmentToken(path string) (string, error) {
	token := mustRandomToken()
	if err := os.WriteFile(path, []byte(token+"\n"), 0o600); err != nil {
		return "", err
	}
	if err := os.Chmod(path, 0o600); err != nil {
		return "", err
	}
	return token, nil
}

func mustRandomToken() string {
	var random [32]byte
	if _, err := rand.Read(random[:]); err != nil {
		panic(fmt.Sprintf("secure random token: %v", err))
	}
	return hex.EncodeToString(random[:])
}

func defaultDataDir() string {
	home, err := os.UserHomeDir()
	if err != nil {
		return ".fortmend"
	}
	return filepath.Join(home, ".fortmend")
}

func splitNonEmpty(value string) []string {
	var result []string
	for _, part := range strings.Split(value, ",") {
		if part = strings.TrimSpace(part); part != "" {
			result = append(result, part)
		}
	}
	return result
}

func oneOf(value string, allowed ...string) bool {
	for _, candidate := range allowed {
		if value == candidate {
			return true
		}
	}
	return false
}

func shellQuote(value string) string {
	return "'" + strings.ReplaceAll(value, "'", "'\"'\"'") + "'"
}

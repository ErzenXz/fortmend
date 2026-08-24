package agent_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/agent"
	"github.com/ErzenXz/aegis/internal/detection"
	"github.com/ErzenXz/aegis/internal/hub"
	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/pki"
	"github.com/ErzenXz/aegis/internal/store"
	"net/http/httptest"
)

func TestDeviceEnrollsAndPostsOverMutualTLS(t *testing.T) {
	authority, err := pki.NewAuthority("Aegis Test CA", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	serverCredential, err := authority.IssueServer([]string{"127.0.0.1"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "aegis.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := hub.NewWithOptions(db, detection.New(detection.DefaultPolicy()), hub.Options{Authority: authority, EnrollmentToken: "token", RequireAgentCertificate: true})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCredential}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	caPath := filepath.Join(t.TempDir(), "ca.pem")
	if err := os.WriteFile(caPath, authority.CertificatePEM(), 0o600); err != nil {
		t.Fatal(err)
	}
	config, err := agent.Enroll(context.Background(), server.URL, "token", caPath, "device-1")
	if err != nil {
		t.Fatal(err)
	}
	client, err := agent.NewClient(config)
	if err != nil {
		t.Fatal(err)
	}
	event := model.SecurityEvent{SchemaVersion: model.SchemaVersion, ID: "event-1", DeviceID: "device-1", ObservedAt: time.Now().UTC(), Source: "fixture", Kind: "host.inventory", Severity: model.SeverityInfo, Confidence: 1}
	if err := client.PostEvent(context.Background(), event); err != nil {
		t.Fatal(err)
	}
	events, err := db.ListEvents(context.Background(), 10)
	if err != nil || len(events) != 1 || events[0].ID != event.ID {
		t.Fatalf("events=%#v err=%v", events, err)
	}
}

func TestDeviceCanEnrollWithPinnedHubCAFingerprint(t *testing.T) {
	authority, err := pki.NewAuthority("Aegis Test CA", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	serverCredential, err := authority.IssueServer([]string{"127.0.0.1"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	db, err := store.Open(filepath.Join(t.TempDir(), "aegis.db"), store.Retention{})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := hub.NewWithOptions(db, detection.New(detection.DefaultPolicy()), hub.Options{Authority: authority, EnrollmentToken: "token", RequireAgentCertificate: true})
	server := httptest.NewUnstartedServer(handler)
	server.TLS = &tls.Config{Certificates: []tls.Certificate{serverCredential}, ClientAuth: tls.RequestClientCert, MinVersion: tls.VersionTLS13}
	server.StartTLS()
	defer server.Close()

	config, err := agent.EnrollPinned(context.Background(), server.URL, "token", authority.FingerprintSHA256(), "device-pinned")
	if err != nil {
		t.Fatal(err)
	}
	if config.DeviceID != "device-pinned" || config.CA == "" {
		t.Fatalf("unexpected pinned enrollment: %#v", config)
	}
}

func TestAgentConfigRoundTripsThroughPlatformSecretStorage(t *testing.T) {
	path := filepath.Join(t.TempDir(), "agent.json")
	config := agent.Config{
		SchemaVersion: model.SchemaVersion,
		HubURL:        "https://aegis.invalid",
		DeviceID:      "device-1",
		EnrolledAt:    time.Now().UTC(),
		Certificate:   "certificate-fixture",
		PrivateKey:    "private-key-fixture",
		CA:            "ca-fixture",
	}
	if err := agent.SaveConfig(path, config); err != nil {
		t.Fatal(err)
	}
	loaded, err := agent.LoadConfig(path)
	if err != nil {
		t.Fatal(err)
	}
	if loaded.DeviceID != config.DeviceID || loaded.PrivateKey != config.PrivateKey {
		t.Fatalf("config changed: %#v", loaded)
	}
	if runtime.GOOS == "windows" {
		contents, err := os.ReadFile(path)
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(contents, []byte(config.PrivateKey)) {
			t.Fatal("Windows agent key was not sealed with DPAPI")
		}
	}
}

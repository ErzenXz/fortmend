package agent_test

import (
	"context"
	"crypto/tls"
	"os"
	"path/filepath"
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

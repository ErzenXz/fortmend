package hub_test

import (
	"bytes"
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/detection"
	"github.com/ErzenXz/aegis/internal/hub"
	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/pki"
	"github.com/ErzenXz/aegis/internal/store"
)

func TestEventIngestionProducesFindingVisibleThroughHTTP(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "aegis.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	server := httptest.NewServer(hub.New(db, detection.New(detection.DefaultPolicy())))
	defer server.Close()

	event := model.SecurityEvent{
		SchemaVersion: model.SchemaVersion,
		ID:            "event-1",
		DeviceID:      "device-1",
		ObservedAt:    time.Now().UTC(),
		Source:        "yara",
		Kind:          "malware.signature_match",
		Severity:      model.SeverityCritical,
		Confidence:    1,
		DetectorIDs:   []string{"yara:EICAR-Test-File"},
	}
	payload, _ := json.Marshal(event)
	request, _ := http.NewRequestWithContext(context.Background(), http.MethodPost, server.URL+"/api/v1/events", bytes.NewReader(payload))
	request.Header.Set("Content-Type", "application/json")
	response, err := http.DefaultClient.Do(request)
	if err != nil {
		t.Fatal(err)
	}
	response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		t.Fatalf("expected 202, got %d", response.StatusCode)
	}

	response, err = http.Get(server.URL + "/api/v1/findings")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	var findings []model.Finding
	if err := json.NewDecoder(response.Body).Decode(&findings); err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].EventIDs[0] != event.ID {
		t.Fatalf("unexpected findings: %#v", findings)
	}
}

func TestEnrollmentBindsEventIngestionToDeviceCertificate(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "aegis.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	authority, err := pki.NewAuthority("Aegis Test CA", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	handler := hub.NewWithOptions(db, detection.New(detection.DefaultPolicy()), hub.Options{
		Authority:               authority,
		EnrollmentToken:         "single-use-token",
		RequireAgentCertificate: true,
	})
	keyPEM, csrPEM, err := pki.NewDeviceCSR("device-1")
	if err != nil {
		t.Fatal(err)
	}
	enrollPayload, _ := json.Marshal(map[string]string{"token": "single-use-token", "deviceId": "device-1", "csr": string(csrPEM)})
	enrollRequest := httptest.NewRequest(http.MethodPost, "/api/v1/enroll", bytes.NewReader(enrollPayload))
	enrollResponse := httptest.NewRecorder()
	handler.ServeHTTP(enrollResponse, enrollRequest)
	if enrollResponse.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", enrollResponse.Code, enrollResponse.Body.String())
	}
	var enrollment struct {
		Certificate string `json:"certificate"`
		CA          string `json:"ca"`
	}
	if err := json.NewDecoder(enrollResponse.Body).Decode(&enrollment); err != nil {
		t.Fatal(err)
	}
	credential, err := tls.X509KeyPair([]byte(enrollment.Certificate), keyPEM)
	if err != nil {
		t.Fatal(err)
	}
	certificate, _ := x509.ParseCertificate(credential.Certificate[0])

	event := model.SecurityEvent{SchemaVersion: model.SchemaVersion, ID: "event-1", DeviceID: "device-1", ObservedAt: time.Now().UTC(), Source: "fixture", Kind: "host.inventory", Severity: model.SeverityInfo, Confidence: 1}
	eventPayload, _ := json.Marshal(event)
	unauthenticated := httptest.NewRecorder()
	handler.ServeHTTP(unauthenticated, httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(eventPayload)))
	if unauthenticated.Code != http.StatusUnauthorized {
		t.Fatalf("expected missing certificate rejection, got %d", unauthenticated.Code)
	}

	authenticatedRequest := httptest.NewRequest(http.MethodPost, "/api/v1/events", bytes.NewReader(eventPayload))
	authenticatedRequest.TLS = &tls.ConnectionState{PeerCertificates: []*x509.Certificate{certificate}}
	authenticated := httptest.NewRecorder()
	handler.ServeHTTP(authenticated, authenticatedRequest)
	if authenticated.Code != http.StatusAccepted {
		t.Fatalf("authenticated status=%d body=%s", authenticated.Code, authenticated.Body.String())
	}
}

func TestHubServesIncidentTimeline(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "aegis.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	request := httptest.NewRequest(http.MethodGet, "/", nil)
	response := httptest.NewRecorder()
	hub.New(db, detection.New(detection.DefaultPolicy())).ServeHTTP(response, request)
	if response.Code != http.StatusOK || !strings.Contains(response.Body.String(), "Aegis Incident Timeline") {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
}

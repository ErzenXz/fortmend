package hub

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"sync"
	"time"

	"github.com/ErzenXz/aegis/internal/detection"
	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/pki"
	"github.com/ErzenXz/aegis/internal/securitymcp"
	"github.com/ErzenXz/aegis/internal/store"
)

const maxEventBytes = 1024 * 1024

type Server struct {
	store          *store.Store
	detection      *detection.Engine
	mux            *http.ServeMux
	subscribers    map[chan model.SecurityEvent]struct{}
	mu             sync.Mutex
	options        Options
	enrollmentUsed bool
}

type Options struct {
	Authority               *pki.Authority
	EnrollmentToken         string
	RequireAgentCertificate bool
	MCPToken                string
}

func New(store *store.Store, detection *detection.Engine) *Server {
	return NewWithOptions(store, detection, Options{})
}

func NewWithOptions(store *store.Store, detection *detection.Engine, options Options) *Server {
	server := &Server{store: store, detection: detection, mux: http.NewServeMux(), subscribers: make(map[chan model.SecurityEvent]struct{}), options: options}
	server.routes()
	return server
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	s.mux.ServeHTTP(writer, request)
}

func (s *Server) routes() {
	s.mux.HandleFunc("GET /", s.serveUI)
	s.mux.HandleFunc("GET /healthz", s.health)
	s.mux.HandleFunc("POST /api/v1/enroll", s.enroll)
	s.mux.HandleFunc("GET /api/v1/ca.pem", s.caCertificate)
	s.mux.HandleFunc("POST /api/v1/events", s.ingestEvent)
	s.mux.HandleFunc("GET /api/v1/events", s.listEvents)
	s.mux.HandleFunc("GET /api/v1/findings", s.listFindings)
	s.mux.HandleFunc("GET /api/v1/audit", s.listAudit)
	s.mux.HandleFunc("GET /api/v1/stream", s.streamEvents)
	if s.options.MCPToken != "" {
		s.mux.Handle("POST /mcp", securitymcp.New(s.store, s.options.MCPToken))
	}
}

func (s *Server) caCertificate(writer http.ResponseWriter, request *http.Request) {
	if s.options.Authority == nil {
		http.NotFound(writer, request)
		return
	}
	writer.Header().Set("Content-Type", "application/x-pem-file")
	writer.Header().Set("Cache-Control", "public, max-age=3600")
	_, _ = writer.Write(s.options.Authority.CertificatePEM())
}

func (s *Server) health(writer http.ResponseWriter, _ *http.Request) {
	writeJSON(writer, http.StatusOK, map[string]any{"ok": true, "schemaVersion": model.SchemaVersion})
}

func (s *Server) ingestEvent(writer http.ResponseWriter, request *http.Request) {
	certificateDeviceID, err := s.authenticatedDevice(request)
	if err != nil {
		writeError(writer, http.StatusUnauthorized, err.Error())
		return
	}
	body := http.MaxBytesReader(writer, request.Body, maxEventBytes)
	defer body.Close()
	decoder := json.NewDecoder(body)
	decoder.DisallowUnknownFields()
	var event model.SecurityEvent
	if err := decoder.Decode(&event); err != nil {
		writeError(writer, http.StatusBadRequest, fmt.Sprintf("invalid event: %v", err))
		return
	}
	if err := ensureEOF(decoder); err != nil {
		writeError(writer, http.StatusBadRequest, err.Error())
		return
	}
	if err := validateEvent(event); err != nil {
		writeError(writer, http.StatusUnprocessableEntity, err.Error())
		return
	}
	if certificateDeviceID != "" && certificateDeviceID != event.DeviceID {
		writeError(writer, http.StatusForbidden, "event deviceId does not match client certificate")
		return
	}
	findings := s.detection.Evaluate(event)
	if err := s.store.Ingest(request.Context(), event, findings); err != nil {
		writeError(writer, http.StatusConflict, fmt.Sprintf("ingest event: %v", err))
		return
	}
	s.publish(event)
	writeJSON(writer, http.StatusAccepted, map[string]any{"eventId": event.ID, "findingCount": len(findings)})
}

func (s *Server) enroll(writer http.ResponseWriter, request *http.Request) {
	if s.options.Authority == nil || s.options.EnrollmentToken == "" {
		writeError(writer, http.StatusNotFound, "enrollment is not configured")
		return
	}
	var input struct {
		Token    string `json:"token"`
		DeviceID string `json:"deviceId"`
		CSR      string `json:"csr"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 64*1024))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&input); err != nil {
		writeError(writer, http.StatusBadRequest, "invalid enrollment request")
		return
	}
	s.mu.Lock()
	validToken := !s.enrollmentUsed && subtle.ConstantTimeCompare([]byte(input.Token), []byte(s.options.EnrollmentToken)) == 1
	if validToken {
		s.enrollmentUsed = true
	}
	s.mu.Unlock()
	if !validToken {
		writeError(writer, http.StatusUnauthorized, "invalid or already used enrollment token")
		return
	}
	certificate, err := s.options.Authority.SignDeviceCSR(input.DeviceID, []byte(input.CSR), time.Now().UTC())
	if err != nil {
		s.mu.Lock()
		s.enrollmentUsed = false
		s.mu.Unlock()
		writeError(writer, http.StatusUnprocessableEntity, err.Error())
		return
	}
	writeJSON(writer, http.StatusCreated, map[string]string{
		"deviceId":    input.DeviceID,
		"certificate": string(certificate),
		"ca":          string(s.options.Authority.CertificatePEM()),
	})
}

func (s *Server) authenticatedDevice(request *http.Request) (string, error) {
	if !s.options.RequireAgentCertificate {
		return "", nil
	}
	if request.TLS == nil || len(request.TLS.PeerCertificates) == 0 || s.options.Authority == nil {
		return "", fmt.Errorf("valid device certificate required")
	}
	deviceID, err := s.options.Authority.VerifyDeviceCertificate(request.TLS.PeerCertificates[0], time.Now().UTC())
	if err != nil {
		return "", fmt.Errorf("invalid device certificate")
	}
	return deviceID, nil
}

func (s *Server) listEvents(writer http.ResponseWriter, request *http.Request) {
	events, err := s.store.ListEvents(request.Context(), requestLimit(request))
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	if events == nil {
		events = []model.SecurityEvent{}
	}
	writeJSON(writer, http.StatusOK, events)
}

func (s *Server) listFindings(writer http.ResponseWriter, request *http.Request) {
	findings, err := s.store.ListFindings(request.Context(), requestLimit(request))
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	if findings == nil {
		findings = []model.Finding{}
	}
	writeJSON(writer, http.StatusOK, findings)
}

func (s *Server) listAudit(writer http.ResponseWriter, request *http.Request) {
	records, err := s.store.ListAudit(request.Context(), requestLimit(request))
	if err != nil {
		writeError(writer, http.StatusInternalServerError, err.Error())
		return
	}
	if records == nil {
		records = []model.AuditRecord{}
	}
	writeJSON(writer, http.StatusOK, records)
}

func (s *Server) streamEvents(writer http.ResponseWriter, request *http.Request) {
	flusher, ok := writer.(http.Flusher)
	if !ok {
		writeError(writer, http.StatusNotImplemented, "streaming unavailable")
		return
	}
	writer.Header().Set("Content-Type", "text/event-stream")
	writer.Header().Set("Cache-Control", "no-cache")
	channel := make(chan model.SecurityEvent, 16)
	s.mu.Lock()
	s.subscribers[channel] = struct{}{}
	s.mu.Unlock()
	defer func() {
		s.mu.Lock()
		delete(s.subscribers, channel)
		s.mu.Unlock()
	}()
	for {
		select {
		case event := <-channel:
			payload, _ := json.Marshal(event)
			fmt.Fprintf(writer, "event: security_event\ndata: %s\n\n", payload)
			flusher.Flush()
		case <-request.Context().Done():
			return
		}
	}
}

func (s *Server) publish(event model.SecurityEvent) {
	s.mu.Lock()
	defer s.mu.Unlock()
	for subscriber := range s.subscribers {
		select {
		case subscriber <- event:
		default:
		}
	}
}

func validateEvent(event model.SecurityEvent) error {
	if event.SchemaVersion != model.SchemaVersion {
		return fmt.Errorf("unsupported schemaVersion %q", event.SchemaVersion)
	}
	if event.ID == "" || event.DeviceID == "" || event.Source == "" || event.Kind == "" || event.ObservedAt.IsZero() {
		return fmt.Errorf("id, deviceId, observedAt, source, and kind are required")
	}
	if event.Confidence < 0 || event.Confidence > 1 {
		return fmt.Errorf("confidence must be between 0 and 1")
	}
	return nil
}

func ensureEOF(decoder *json.Decoder) error {
	var extra any
	if err := decoder.Decode(&extra); err != io.EOF {
		return fmt.Errorf("request must contain exactly one JSON object")
	}
	return nil
}

func requestLimit(request *http.Request) int {
	limit, _ := strconv.Atoi(request.URL.Query().Get("limit"))
	return limit
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func writeError(writer http.ResponseWriter, status int, message string) {
	writeJSON(writer, status, map[string]string{"error": message})
}

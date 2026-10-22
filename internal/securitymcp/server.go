package securitymcp

import (
	"crypto/subtle"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"

	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/store"
)

type Server struct {
	store *store.Store
	token string
	tools []tool
}

type tool struct {
	Name        string         `json:"name"`
	Description string         `json:"description"`
	InputSchema map[string]any `json:"inputSchema"`
}

func New(store *store.Store, token string) *Server {
	object := func(properties map[string]any) map[string]any {
		return map[string]any{"type": "object", "properties": properties, "additionalProperties": false}
	}
	return &Server{store: store, token: token, tools: []tool{
		{Name: "get_case", Description: "Read one Fortmend incident case or finding by ID.", InputSchema: object(map[string]any{"id": map[string]any{"type": "string"}})},
		{Name: "search_events", Description: "Search bounded normalized endpoint events by device or kind.", InputSchema: object(map[string]any{"deviceId": map[string]any{"type": "string"}, "kind": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 500}})},
		{Name: "collect_evidence", Description: "Collect bounded existing evidence for a device without executing host commands.", InputSchema: object(map[string]any{"deviceId": map[string]any{"type": "string"}, "limit": map[string]any{"type": "integer", "minimum": 1, "maximum": 200}})},
		{Name: "get_host_state", Description: "Read the latest normalized posture and capability events for a device.", InputSchema: object(map[string]any{"deviceId": map[string]any{"type": "string"}})},
		{Name: "simulate_response", Description: "Check whether a typed response would pass deterministic policy without applying it.", InputSchema: actionSchema(object)},
		{Name: "request_response", Description: "Request a typed policy-bound response; the privileged executor independently authorizes it.", InputSchema: actionSchema(object)},
		{Name: "verify_response", Description: "Read the receipt and verification state for an idempotency key.", InputSchema: object(map[string]any{"idempotencyKey": map[string]any{"type": "string"}})},
	}}
}

func actionSchema(object func(map[string]any) map[string]any) map[string]any {
	return object(map[string]any{
		"deviceId":       map[string]any{"type": "string"},
		"findingId":      map[string]any{"type": "string"},
		"kind":           map[string]any{"type": "string"},
		"idempotencyKey": map[string]any{"type": "string"},
		"parameters":     map[string]any{"type": "object"},
	})
}

func (s *Server) ServeHTTP(writer http.ResponseWriter, request *http.Request) {
	if request.Method != http.MethodPost {
		writer.WriteHeader(http.StatusMethodNotAllowed)
		return
	}
	if s.token == "" || subtle.ConstantTimeCompare([]byte(request.Header.Get("Authorization")), []byte("Bearer "+s.token)) != 1 {
		writer.Header().Set("WWW-Authenticate", "Bearer")
		writeJSON(writer, http.StatusUnauthorized, map[string]any{"error": "valid MCP bearer token required"})
		return
	}
	var message struct {
		JSONRPC string `json:"jsonrpc"`
		ID      any    `json:"id"`
		Method  string `json:"method"`
		Params  struct {
			Name      string         `json:"name"`
			Arguments map[string]any `json:"arguments"`
		} `json:"params"`
	}
	decoder := json.NewDecoder(http.MaxBytesReader(writer, request.Body, 256*1024))
	if err := decoder.Decode(&message); err != nil || message.JSONRPC != "2.0" {
		s.rpcError(writer, message.ID, -32600, "invalid JSON-RPC request")
		return
	}
	switch message.Method {
	case "initialize":
		s.rpcResult(writer, message.ID, map[string]any{"protocolVersion": "2025-06-18", "capabilities": map[string]any{"tools": map[string]any{}}, "serverInfo": map[string]string{"name": "fortmend-security", "version": "0.1.0"}})
	case "notifications/initialized":
		writer.WriteHeader(http.StatusAccepted)
	case "tools/list":
		s.rpcResult(writer, message.ID, map[string]any{"tools": s.tools})
	case "tools/call":
		result, err := s.call(request, message.Params.Name, message.Params.Arguments)
		if err != nil {
			s.rpcError(writer, message.ID, -32602, err.Error())
			return
		}
		s.rpcResult(writer, message.ID, result)
	default:
		s.rpcError(writer, message.ID, -32601, "method not found")
	}
}

func (s *Server) call(request *http.Request, name string, arguments map[string]any) (map[string]any, error) {
	limit := intArgument(arguments, "limit", 100)
	if limit > 500 {
		limit = 500
	}
	events, err := s.store.ListEvents(request.Context(), limit)
	if err != nil {
		return nil, err
	}
	findings, err := s.store.ListFindings(request.Context(), limit)
	if err != nil {
		return nil, err
	}
	deviceID := stringArgument(arguments, "deviceId")
	switch name {
	case "search_events":
		kind := stringArgument(arguments, "kind")
		filtered := make([]model.SecurityEvent, 0, len(events))
		for _, event := range events {
			if (deviceID == "" || event.DeviceID == deviceID) && (kind == "" || event.Kind == kind) {
				filtered = append(filtered, event)
			}
		}
		return toolResult(filtered)
	case "get_host_state":
		filtered := make([]model.SecurityEvent, 0)
		for _, event := range events {
			if (deviceID == "" || event.DeviceID == deviceID) && (strings.HasPrefix(event.Kind, "host.") || event.Kind == "sensor.capability") {
				filtered = append(filtered, event)
			}
		}
		return toolResult(filtered)
	case "collect_evidence":
		return toolResult(map[string]any{"events": events, "findings": findings})
	case "get_case":
		id := stringArgument(arguments, "id")
		for _, finding := range findings {
			if finding.ID == id {
				return toolResult(finding)
			}
		}
		return nil, fmt.Errorf("case or finding %q not found", id)
	case "simulate_response", "request_response":
		return toolResult(map[string]any{"status": "rejected", "reason": "developer preview has no recovery-verified privileged adapter"})
	case "verify_response":
		return toolResult(map[string]any{"status": "unknown", "idempotencyKey": stringArgument(arguments, "idempotencyKey")})
	default:
		return nil, fmt.Errorf("unknown security tool %q", name)
	}
}

func toolResult(value any) (map[string]any, error) {
	payload, err := json.Marshal(value)
	if err != nil {
		return nil, err
	}
	return map[string]any{"content": []map[string]string{{"type": "text", "text": string(payload)}}, "structuredContent": value}, nil
}

func (s *Server) rpcResult(writer http.ResponseWriter, id any, result any) {
	writeJSON(writer, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "result": result})
}

func (s *Server) rpcError(writer http.ResponseWriter, id any, code int, message string) {
	writeJSON(writer, http.StatusOK, map[string]any{"jsonrpc": "2.0", "id": id, "error": map[string]any{"code": code, "message": message}})
}

func writeJSON(writer http.ResponseWriter, status int, value any) {
	writer.Header().Set("Content-Type", "application/json")
	writer.WriteHeader(status)
	_ = json.NewEncoder(writer).Encode(value)
}

func stringArgument(arguments map[string]any, name string) string {
	value, _ := arguments[name].(string)
	return value
}

func intArgument(arguments map[string]any, name string, fallback int) int {
	value, ok := arguments[name].(float64)
	if !ok || value < 1 {
		return fallback
	}
	return int(value)
}

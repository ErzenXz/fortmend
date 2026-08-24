package securitymcp_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/securitymcp"
	"github.com/ErzenXz/aegis/internal/store"
)

func TestToolSurfaceContainsOnlyAegisSecurityTools(t *testing.T) {
	db, err := store.Open(filepath.Join(t.TempDir(), "aegis.db"), store.Retention{RawEvents: 30 * 24 * time.Hour, Findings: 180 * 24 * time.Hour})
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	handler := securitymcp.New(db, "secret")
	payload := []byte(`{"jsonrpc":"2.0","id":1,"method":"tools/list","params":{}}`)
	request := httptest.NewRequest(http.MethodPost, "/mcp", bytes.NewReader(payload))
	request.Header.Set("Authorization", "Bearer secret")
	request.Header.Set("Content-Type", "application/json")
	response := httptest.NewRecorder()
	handler.ServeHTTP(response, request)
	if response.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", response.Code, response.Body.String())
	}
	var result struct {
		Result struct {
			Tools []struct {
				Name string `json:"name"`
			} `json:"tools"`
		} `json:"result"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tool := range result.Result.Tools {
		names = append(names, tool.Name)
	}
	sort.Strings(names)
	expected := []string{"collect_evidence", "get_case", "get_host_state", "request_response", "search_events", "simulate_response", "verify_response"}
	if strings.Join(names, ",") != strings.Join(expected, ",") {
		t.Fatalf("unexpected tool surface: %v", names)
	}
}

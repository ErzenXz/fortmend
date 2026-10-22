package fxacp

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os/exec"
	"strings"
	"sync"

	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/reasoner"
)

type Config struct {
	Binary      string
	Model       string
	MCPURL      string
	MCPToken    string
	Environment []string
}

type ProcessClient struct{ config Config }

func New(config Config) *ProcessClient {
	if config.Binary == "" {
		config.Binary = "fortmend-fx"
	}
	return &ProcessClient{config: config}
}

type rpcMessage struct {
	JSONRPC string          `json:"jsonrpc"`
	ID      int             `json:"id,omitempty"`
	Method  string          `json:"method,omitempty"`
	Params  json.RawMessage `json:"params,omitempty"`
	Result  json.RawMessage `json:"result,omitempty"`
	Error   *struct {
		Code    int    `json:"code"`
		Message string `json:"message"`
	} `json:"error,omitempty"`
}

func (client *ProcessClient) Turn(ctx context.Context, request reasoner.TurnRequest) (reasoner.TurnResult, error) {
	args := []string{"acp", "--fortmend"}
	if client.config.Model != "" {
		args = append(args, "--model", client.config.Model)
	}
	command := exec.CommandContext(ctx, client.config.Binary, args...)
	command.Env = append(command.Environ(), client.config.Environment...)
	stdin, err := command.StdinPipe()
	if err != nil {
		return reasoner.TurnResult{}, err
	}
	stdout, err := command.StdoutPipe()
	if err != nil {
		return reasoner.TurnResult{}, err
	}
	stderr, err := command.StderrPipe()
	if err != nil {
		return reasoner.TurnResult{}, err
	}
	if err := command.Start(); err != nil {
		return reasoner.TurnResult{}, err
	}
	var stderrBytes []byte
	var stderrErr error
	var stderrWait sync.WaitGroup
	stderrWait.Add(1)
	go func() {
		defer stderrWait.Done()
		stderrBytes, stderrErr = io.ReadAll(io.LimitReader(stderr, 256*1024))
	}()
	encoder := json.NewEncoder(stdin)
	scanner := bufio.NewScanner(stdout)
	scanner.Buffer(make([]byte, 64*1024), 2*1024*1024)
	fail := func(cause error) (reasoner.TurnResult, error) {
		_ = stdin.Close()
		_ = command.Wait()
		stderrWait.Wait()
		if stderrErr == nil && len(stderrBytes) > 0 {
			return reasoner.TurnResult{}, fmt.Errorf("%w: %s", cause, strings.TrimSpace(string(stderrBytes)))
		}
		return reasoner.TurnResult{}, cause
	}

	if err := sendRequest(encoder, 1, "initialize", map[string]any{"protocolVersion": 1, "clientCapabilities": map[string]any{}}); err != nil {
		return fail(err)
	}
	if _, err := waitResponse(scanner, encoder, 1, nil); err != nil {
		return fail(err)
	}
	mcpServers := []any{}
	if client.config.MCPURL != "" {
		headers := []map[string]string{}
		if client.config.MCPToken != "" {
			headers = append(headers, map[string]string{"name": "Authorization", "value": "Bearer " + client.config.MCPToken})
		}
		mcpServers = append(mcpServers, map[string]any{"type": "http", "name": "fortmend-security", "url": client.config.MCPURL, "headers": headers})
	}
	if err := sendRequest(encoder, 2, "session/new", map[string]any{"mcpServers": mcpServers}); err != nil {
		return fail(err)
	}
	newSession, err := waitResponse(scanner, encoder, 2, nil)
	if err != nil {
		return fail(err)
	}
	var session struct {
		SessionID string `json:"sessionId"`
	}
	if err := json.Unmarshal(newSession, &session); err != nil || session.SessionID == "" {
		return fail(fmt.Errorf("fx ACP returned invalid session"))
	}
	prompt := []map[string]any{
		{"type": "text", "text": request.Instructions + "\nReturn exactly one JSON object with summary, actions, and citations."},
		{"type": "resource", "resource": map[string]any{"uri": "fortmend://incident/evidence.json", "text": request.EvidenceJSON}},
	}
	if err := sendRequest(encoder, 3, "session/prompt", map[string]any{"sessionId": session.SessionID, "prompt": prompt}); err != nil {
		return fail(err)
	}
	var assistant strings.Builder
	if _, err := waitResponse(scanner, encoder, 3, &assistant); err != nil {
		return fail(err)
	}
	_ = stdin.Close()
	if err := command.Wait(); err != nil {
		stderrWait.Wait()
		return reasoner.TurnResult{}, fmt.Errorf("fx ACP exited: %w: %s", err, strings.TrimSpace(string(stderrBytes)))
	}
	stderrWait.Wait()
	var result struct {
		Summary   string             `json:"summary"`
		Actions   []model.ActionSpec `json:"actions"`
		Citations []string           `json:"citations"`
	}
	if err := json.Unmarshal(extractJSONObject(assistant.String()), &result); err != nil {
		return reasoner.TurnResult{}, fmt.Errorf("decode fx response: %w", err)
	}
	return reasoner.TurnResult{Summary: result.Summary, Actions: result.Actions, Citations: result.Citations}, nil
}

func sendRequest(encoder *json.Encoder, id int, method string, params any) error {
	return encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": id, "method": method, "params": params})
}

func waitResponse(scanner *bufio.Scanner, encoder *json.Encoder, id int, assistant *strings.Builder) (json.RawMessage, error) {
	for scanner.Scan() {
		var message rpcMessage
		if err := json.Unmarshal(scanner.Bytes(), &message); err != nil {
			return nil, err
		}
		if message.Method == "session/request_permission" {
			if err := encoder.Encode(map[string]any{"jsonrpc": "2.0", "id": message.ID, "result": map[string]any{"outcome": map[string]string{"outcome": "cancelled"}}}); err != nil {
				return nil, err
			}
			continue
		}
		if message.Method == "session/update" && assistant != nil {
			var update struct {
				Update struct {
					SessionUpdate string `json:"sessionUpdate"`
					Content       struct {
						Text string `json:"text"`
					} `json:"content"`
				} `json:"update"`
			}
			if json.Unmarshal(message.Params, &update) == nil && update.Update.SessionUpdate == "agent_message_chunk" {
				assistant.WriteString(update.Update.Content.Text)
			}
			continue
		}
		if message.ID != id {
			continue
		}
		if message.Error != nil {
			return nil, fmt.Errorf("fx ACP %s: %s", message.Method, message.Error.Message)
		}
		return message.Result, nil
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	return nil, io.ErrUnexpectedEOF
}

func extractJSONObject(value string) []byte {
	start := strings.IndexByte(value, '{')
	end := strings.LastIndexByte(value, '}')
	if start < 0 || end < start {
		return []byte(value)
	}
	return []byte(value[start : end+1])
}

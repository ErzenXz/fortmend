package main

import (
	"bytes"
	"context"
	"encoding/json"
	"testing"

	"github.com/ErzenXz/fortmend/internal/model"
)

func TestVersionCommand(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"version"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	if stdout.String() != "fortmend 0.2.0-preview.1 (fx v0.0.5)\n" {
		t.Fatalf("unexpected version: %q", stdout.String())
	}
}

func TestScanProducesNormalizedHostEvent(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run(context.Background(), []string{"scan", "--device-id", "fixture-device"}, &stdout, &stderr); code != 0 {
		t.Fatalf("code=%d stderr=%s", code, stderr.String())
	}
	decoder := json.NewDecoder(&stdout)
	var event model.SecurityEvent
	if err := decoder.Decode(&event); err != nil {
		t.Fatal(err)
	}
	if event.SchemaVersion != model.SchemaVersion || event.DeviceID != "fixture-device" || event.Kind != "host.inventory" {
		t.Fatalf("unexpected event: %#v", event)
	}
}

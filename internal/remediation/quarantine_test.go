package remediation

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"path/filepath"
	"testing"

	"github.com/ErzenXz/fortmend/internal/model"
	"github.com/ErzenXz/fortmend/internal/monitor"
)

func shellEvent(path string, content []byte) model.SecurityEvent {
	sum := sha256.Sum256(content)
	signature, confidence := monitor.MatchWebshell(content)
	return model.SecurityEvent{ID: "event-test", Kind: "webshell.suspicious", Confidence: confidence, Attributes: map[string]string{"path": path, "sha256": hex.EncodeToString(sum[:]), "signature": signature, "quarantineEligible": "true"}}
}
func TestValidationRefusesUnsafeScopeAndEvidence(t *testing.T) {
	root := t.TempDir()
	q := Quarantine{StateDir: t.TempDir(), WebRoots: []string{root}}
	valid := shellEvent(filepath.Join(root, "hack.php"), []byte("<?php system($_GET['cmd']);"))
	if _, err := q.validate(valid); err != nil {
		t.Fatal(err)
	}
	for _, change := range []func(*model.SecurityEvent){
		func(e *model.SecurityEvent) { e.Kind = "file.modified" },
		func(e *model.SecurityEvent) { e.Confidence = .85 },
		func(e *model.SecurityEvent) { e.Attributes["quarantineEligible"] = "false" },
		func(e *model.SecurityEvent) { e.Attributes["path"] = filepath.Join(filepath.Dir(root), "escape.php") },
		func(e *model.SecurityEvent) { e.Attributes["path"] = "relative.php" },
		func(e *model.SecurityEvent) { e.Attributes["path"] = filepath.Join(root, "hack.txt") },
		func(e *model.SecurityEvent) { e.Attributes["sha256"] = "bad" },
		func(e *model.SecurityEvent) { e.Attributes["signature"] = "php-obfuscated-eval" },
	} {
		e := valid
		e.Attributes = map[string]string{}
		for k, v := range valid.Attributes {
			e.Attributes[k] = v
		}
		change(&e)
		if _, err := q.validate(e); err == nil {
			t.Fatalf("accepted invalid event: %+v", e)
		}
	}
	q.StateDir = filepath.Join(root, "private")
	if _, err := q.validate(valid); err == nil {
		t.Fatal("accepted served quarantine directory")
	}
	q.StateDir = t.TempDir()
	q.WebRoots = []string{"/"}
	if _, err := q.validate(valid); err == nil {
		t.Fatal("accepted filesystem-root scope")
	}
}
func TestCancelledApplyDoesNotWrite(t *testing.T) {
	q := Quarantine{}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, err := q.Apply(ctx, model.SecurityEvent{}); err == nil {
		t.Fatal("cancel ignored")
	}
}

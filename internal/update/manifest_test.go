package update_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/update"
)

func TestSignedManifestRejectsTampering(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := update.Manifest{
		SchemaVersion: "aegis.update/v1alpha1",
		Version:       "0.1.0",
		PublishedAt:   time.Date(2026, time.August, 24, 10, 0, 0, 0, time.UTC),
		Artifacts:     []update.Artifact{{OS: "linux", Arch: "amd64", URL: "https://example.invalid/aegis", SHA256: "abc", Size: 42}},
	}
	signed, err := update.Sign(manifest, privateKey)
	if err != nil {
		t.Fatal(err)
	}
	if err := update.Verify(signed, publicKey); err != nil {
		t.Fatalf("valid manifest failed: %v", err)
	}
	signed.Manifest.Artifacts[0].SHA256 = "tampered"
	if err := update.Verify(signed, publicKey); err == nil {
		t.Fatal("tampered manifest verified")
	}
}

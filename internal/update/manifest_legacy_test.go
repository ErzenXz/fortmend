package update_test

import (
	"crypto/ed25519"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"testing"
	"time"

	"github.com/ErzenXz/fortmend/internal/update"
)

func TestLegacyManifestVerifiesOriginalSignedPayload(t *testing.T) {
	publicKey, privateKey, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	manifest := update.Manifest{
		SchemaVersion: "aegis.update/v1alpha1", Version: "0.1.0",
		PublishedAt: time.Date(2026, time.January, 1, 0, 0, 0, 0, time.UTC),
		Artifacts:   []update.Artifact{{OS: "linux", Arch: "amd64", URL: "https://example.invalid/aegis_linux_amd64", SHA256: "original-hash", Size: 100}},
	}
	// Sign exactly as an old producer did, without using the new Sign helper.
	payload, err := json.Marshal(manifest)
	if err != nil {
		t.Fatal(err)
	}
	signed := update.SignedManifest{Manifest: manifest, Signature: base64.RawStdEncoding.EncodeToString(ed25519.Sign(privateKey, payload))}
	if err := update.Verify(signed, publicKey); err != nil {
		t.Fatalf("legacy signature failed verification: %v", err)
	}
	if signed.Manifest.SchemaVersion != "aegis.update/v1alpha1" {
		t.Fatal("verification rewrote the signed schema")
	}
	canonicalized := signed
	canonicalized.Manifest.SchemaVersion = update.SchemaVersion
	if err := update.Verify(canonicalized, publicKey); err == nil {
		t.Fatal("accepted a schema rewritten after signing")
	}
	signed.Manifest.Version = "tampered"
	if err := update.Verify(signed, publicKey); err == nil {
		t.Fatal("accepted a tampered legacy manifest")
	}
}

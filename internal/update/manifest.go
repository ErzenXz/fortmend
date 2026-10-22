package update

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"time"
)

const SchemaVersion = "fortmend.update/v1alpha1"

type Artifact struct {
	OS     string `json:"os"`
	Arch   string `json:"arch"`
	URL    string `json:"url"`
	SHA256 string `json:"sha256"`
	Size   int64  `json:"size"`
}

type Manifest struct {
	SchemaVersion string     `json:"schemaVersion"`
	Version       string     `json:"version"`
	PublishedAt   time.Time  `json:"publishedAt"`
	Artifacts     []Artifact `json:"artifacts"`
}

type SignedManifest struct {
	Manifest  Manifest `json:"manifest"`
	Signature string   `json:"signature"`
}

func Sign(manifest Manifest, privateKey ed25519.PrivateKey) (SignedManifest, error) {
	if err := validate(manifest); err != nil {
		return SignedManifest{}, err
	}
	if len(privateKey) != ed25519.PrivateKeySize {
		return SignedManifest{}, fmt.Errorf("invalid Ed25519 private key")
	}
	payload, err := canonical(manifest)
	if err != nil {
		return SignedManifest{}, err
	}
	signature := ed25519.Sign(privateKey, payload)
	return SignedManifest{Manifest: manifest, Signature: base64.RawStdEncoding.EncodeToString(signature)}, nil
}

func Verify(signed SignedManifest, publicKey ed25519.PublicKey) error {
	if err := validate(signed.Manifest); err != nil {
		return err
	}
	if len(publicKey) != ed25519.PublicKeySize {
		return fmt.Errorf("invalid Ed25519 public key")
	}
	signature, err := base64.RawStdEncoding.DecodeString(signed.Signature)
	if err != nil {
		return fmt.Errorf("invalid manifest signature encoding: %w", err)
	}
	payload, err := canonical(signed.Manifest)
	if err != nil {
		return err
	}
	if !ed25519.Verify(publicKey, payload, signature) {
		return fmt.Errorf("manifest signature verification failed")
	}
	return nil
}

func canonical(manifest Manifest) ([]byte, error) { return json.Marshal(manifest) }

func validate(manifest Manifest) error {
	if (manifest.SchemaVersion != SchemaVersion && manifest.SchemaVersion != "aegis.update/v1alpha1") || manifest.Version == "" || manifest.PublishedAt.IsZero() || len(manifest.Artifacts) == 0 {
		return fmt.Errorf("invalid update manifest")
	}
	for _, artifact := range manifest.Artifacts {
		if artifact.OS == "" || artifact.Arch == "" || artifact.URL == "" || artifact.SHA256 == "" || artifact.Size <= 0 {
			return fmt.Errorf("invalid update artifact")
		}
	}
	return nil
}

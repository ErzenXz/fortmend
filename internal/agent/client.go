package agent

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/subtle"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/ErzenXz/aegis/internal/model"
	"github.com/ErzenXz/aegis/internal/pki"
	"github.com/ErzenXz/aegis/internal/secret"
)

type Config struct {
	SchemaVersion string    `json:"schemaVersion"`
	HubURL        string    `json:"hubUrl"`
	DeviceID      string    `json:"deviceId"`
	EnrolledAt    time.Time `json:"enrolledAt"`
	Certificate   string    `json:"certificate"`
	PrivateKey    string    `json:"privateKey"`
	CA            string    `json:"ca"`
}

func Enroll(ctx context.Context, hubURL, token, caPath, deviceID string) (Config, error) {
	if _, err := url.ParseRequestURI(hubURL); err != nil || !strings.HasPrefix(hubURL, "https://") {
		return Config{}, fmt.Errorf("hub must be a valid https URL")
	}
	caPEM, err := os.ReadFile(caPath)
	if err != nil {
		return Config{}, fmt.Errorf("read hub CA: %w", err)
	}
	return enrollWithCA(ctx, hubURL, token, deviceID, caPEM)
}

func EnrollPinned(ctx context.Context, hubURL, token, caFingerprint, deviceID string) (Config, error) {
	if _, err := url.ParseRequestURI(hubURL); err != nil || !strings.HasPrefix(hubURL, "https://") {
		return Config{}, fmt.Errorf("hub must be a valid https URL")
	}
	expected, err := hex.DecodeString(strings.ToLower(caFingerprint))
	if err != nil || len(expected) != sha256.Size {
		return Config{}, fmt.Errorf("CA fingerprint must be a 64-character SHA-256 hex value")
	}
	transport := &http.Transport{TLSClientConfig: &tls.Config{
		InsecureSkipVerify: true, // The fetched certificate is authenticated by the required SHA-256 fingerprint below.
		MinVersion:         tls.VersionTLS13,
	}}
	client := &http.Client{Transport: transport, Timeout: 30 * time.Second}
	request, err := http.NewRequestWithContext(ctx, http.MethodGet, strings.TrimRight(hubURL, "/")+"/api/v1/ca.pem", nil)
	if err != nil {
		return Config{}, err
	}
	response, err := client.Do(request)
	if err != nil {
		return Config{}, fmt.Errorf("fetch hub CA: %w", err)
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		return Config{}, fmt.Errorf("fetch hub CA: %s", response.Status)
	}
	caPEM, err := io.ReadAll(io.LimitReader(response.Body, 64*1024))
	if err != nil {
		return Config{}, err
	}
	block, rest := pem.Decode(caPEM)
	if block == nil || block.Type != "CERTIFICATE" || len(rest) != 0 {
		return Config{}, fmt.Errorf("hub returned invalid CA PEM")
	}
	certificate, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return Config{}, fmt.Errorf("parse hub CA: %w", err)
	}
	digest := sha256.Sum256(certificate.Raw)
	if subtle.ConstantTimeCompare(digest[:], expected) != 1 {
		return Config{}, fmt.Errorf("hub CA fingerprint mismatch")
	}
	return enrollWithCA(ctx, hubURL, token, deviceID, caPEM)
}

func enrollWithCA(ctx context.Context, hubURL, token, deviceID string, caPEM []byte) (Config, error) {
	privateKey, csr, err := pki.NewDeviceCSR(deviceID)
	if err != nil {
		return Config{}, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(caPEM) {
		return Config{}, fmt.Errorf("invalid hub CA")
	}
	client := &http.Client{Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: roots, MinVersion: tls.VersionTLS13}}, Timeout: 30 * time.Second}
	payload, _ := json.Marshal(map[string]string{"token": token, "deviceId": deviceID, "csr": string(csr)})
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, strings.TrimRight(hubURL, "/")+"/api/v1/enroll", bytes.NewReader(payload))
	if err != nil {
		return Config{}, err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.Do(request)
	if err != nil {
		return Config{}, err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusCreated {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 16*1024))
		return Config{}, fmt.Errorf("enrollment failed (%s): %s", response.Status, strings.TrimSpace(string(body)))
	}
	var result struct {
		DeviceID    string `json:"deviceId"`
		Certificate string `json:"certificate"`
		CA          string `json:"ca"`
	}
	if err := json.NewDecoder(response.Body).Decode(&result); err != nil {
		return Config{}, err
	}
	if result.DeviceID != deviceID || result.Certificate == "" {
		return Config{}, fmt.Errorf("hub returned invalid enrollment identity")
	}
	if _, err := tls.X509KeyPair([]byte(result.Certificate), privateKey); err != nil {
		return Config{}, fmt.Errorf("hub returned invalid device certificate: %w", err)
	}
	return Config{
		SchemaVersion: model.SchemaVersion,
		HubURL:        strings.TrimRight(hubURL, "/"),
		DeviceID:      deviceID,
		EnrolledAt:    time.Now().UTC(),
		Certificate:   result.Certificate,
		PrivateKey:    string(privateKey),
		CA:            result.CA,
	}, nil
}

func SaveConfig(path string, config Config) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return err
	}
	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	payload = append(payload, '\n')
	sealed, err := secret.Seal(payload)
	if err != nil {
		return err
	}
	if err := os.WriteFile(path, sealed, 0o600); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func LoadConfig(path string) (Config, error) {
	sealed, err := os.ReadFile(path)
	if err != nil {
		return Config{}, err
	}
	payload, err := secret.Open(sealed)
	if err != nil {
		return Config{}, err
	}
	var config Config
	if err := json.Unmarshal(payload, &config); err != nil {
		return Config{}, err
	}
	if config.SchemaVersion != model.SchemaVersion || config.HubURL == "" || config.DeviceID == "" {
		return Config{}, fmt.Errorf("invalid agent configuration")
	}
	return config, nil
}

type Client struct {
	config Config
	http   *http.Client
}

func NewClient(config Config) (*Client, error) {
	credential, err := tls.X509KeyPair([]byte(config.Certificate), []byte(config.PrivateKey))
	if err != nil {
		return nil, err
	}
	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM([]byte(config.CA)) {
		return nil, fmt.Errorf("invalid hub CA")
	}
	return &Client{config: config, http: &http.Client{
		Transport: &http.Transport{TLSClientConfig: &tls.Config{Certificates: []tls.Certificate{credential}, RootCAs: roots, MinVersion: tls.VersionTLS13}},
		Timeout:   30 * time.Second,
	}}, nil
}

func (client *Client) PostEvent(ctx context.Context, event model.SecurityEvent) error {
	payload, err := json.Marshal(event)
	if err != nil {
		return err
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, client.config.HubURL+"/api/v1/events", bytes.NewReader(payload))
	if err != nil {
		return err
	}
	request.Header.Set("Content-Type", "application/json")
	response, err := client.http.Do(request)
	if err != nil {
		return err
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusAccepted {
		body, _ := io.ReadAll(io.LimitReader(response.Body, 16*1024))
		return fmt.Errorf("event rejected (%s): %s", response.Status, strings.TrimSpace(string(body)))
	}
	return nil
}

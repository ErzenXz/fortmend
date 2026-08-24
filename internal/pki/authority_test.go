package pki_test

import (
	"crypto/tls"
	"crypto/x509"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/ErzenXz/aegis/internal/pki"
)

func TestAuthorityIssuesServerAndDeviceCertificates(t *testing.T) {
	authority, err := pki.NewAuthority("Aegis Test CA", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	server, err := authority.IssueServer([]string{"localhost"}, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	device, err := authority.IssueDevice("device-1", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}

	roots := x509.NewCertPool()
	if !roots.AppendCertsFromPEM(authority.CertificatePEM()) {
		t.Fatal("could not parse authority certificate")
	}
	serverCert, _ := x509.ParseCertificate(server.Certificate[0])
	if _, err := serverCert.Verify(x509.VerifyOptions{Roots: roots, DNSName: "localhost", KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}}); err != nil {
		t.Fatalf("server certificate did not verify: %v", err)
	}
	deviceCert, _ := x509.ParseCertificate(device.Certificate[0])
	if _, err := deviceCert.Verify(x509.VerifyOptions{Roots: roots, KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}}); err != nil {
		t.Fatalf("device certificate did not verify: %v", err)
	}
	if deviceCert.Subject.CommonName != "aegis-device:device-1" {
		t.Fatalf("unexpected device identity: %q", deviceCert.Subject.CommonName)
	}
}

func TestAuthorityPersistsWithPrivateKeyPermissions(t *testing.T) {
	directory := filepath.Join(t.TempDir(), "pki")
	authority, err := pki.NewAuthority("Aegis Test CA", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	if err := authority.Save(directory); err != nil {
		t.Fatal(err)
	}
	loaded, err := pki.LoadAuthority(directory)
	if err != nil {
		t.Fatal(err)
	}
	if string(loaded.CertificatePEM()) != string(authority.CertificatePEM()) {
		t.Fatal("loaded authority certificate changed")
	}
	if _, err := loaded.IssueDevice("device-2", time.Now().UTC()); err != nil {
		t.Fatalf("loaded authority cannot issue: %v", err)
	}
	info, err := os.Stat(filepath.Join(directory, "ca-key.pem"))
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o600 {
		t.Fatalf("private key permissions=%o", info.Mode().Perm())
	}
}

func TestAuthoritySignsDeviceOwnedCSR(t *testing.T) {
	authority, err := pki.NewAuthority("Aegis Test CA", time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	keyPEM, csrPEM, err := pki.NewDeviceCSR("device-3")
	if err != nil {
		t.Fatal(err)
	}
	certPEM, err := authority.SignDeviceCSR("device-3", csrPEM, time.Now().UTC())
	if err != nil {
		t.Fatal(err)
	}
	credential, err := tls.X509KeyPair(certPEM, keyPEM)
	if err != nil {
		t.Fatalf("signed certificate does not match device key: %v", err)
	}
	certificate, _ := x509.ParseCertificate(credential.Certificate[0])
	if certificate.Subject.CommonName != "aegis-device:device-3" {
		t.Fatalf("unexpected identity: %q", certificate.Subject.CommonName)
	}
}

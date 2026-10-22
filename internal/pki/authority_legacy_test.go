package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"math/big"
	"testing"
	"time"
)

func TestLegacyDeviceIdentityRetainsCertificateTrustChecks(t *testing.T) {
	now := time.Now().UTC()
	trusted, err := NewAuthority("Legacy trusted CA", now)
	if err != nil {
		t.Fatal(err)
	}
	untrusted, err := NewAuthority("Untrusted CA", now)
	if err != nil {
		t.Fatal(err)
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	issue := func(issuer *Authority, name string) *x509.Certificate {
		t.Helper()
		template := &x509.Certificate{
			SerialNumber: big.NewInt(42),
			Subject:      pkix.Name{CommonName: name},
			NotBefore:    now.Add(-time.Minute), NotAfter: now.Add(time.Hour),
			KeyUsage:    x509.KeyUsageDigitalSignature,
			ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		}
		der, err := x509.CreateCertificate(rand.Reader, template, issuer.certificate, &key.PublicKey, issuer.privateKey)
		if err != nil {
			t.Fatal(err)
		}
		cert, err := x509.ParseCertificate(der)
		if err != nil {
			t.Fatal(err)
		}
		return cert
	}
	for _, prefix := range []string{"aegis-device:", "fortmend-device:"} {
		t.Run(prefix, func(t *testing.T) {
			id, err := trusted.VerifyDeviceCertificate(issue(trusted, prefix+"existing-device"), now)
			if err != nil || id != "existing-device" {
				t.Fatalf("trusted device identity = %q, error = %v", id, err)
			}
			if _, err := trusted.VerifyDeviceCertificate(issue(untrusted, prefix+"existing-device"), now); err == nil {
				t.Fatal("accepted legacy-compatible identity signed by the wrong CA")
			}
		})
	}
	for _, name := range []string{"aegis-device:", "fortmend-device:", "unrelated:existing-device"} {
		if _, err := trusted.VerifyDeviceCertificate(issue(trusted, name), now); err == nil {
			t.Fatalf("accepted malformed device identity %q", name)
		}
	}
}

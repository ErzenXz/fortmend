package pki

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"math/big"
	"net"
	"os"
	"path/filepath"
	"time"
)

type Authority struct {
	certificate *x509.Certificate
	privateKey  *ecdsa.PrivateKey
	certPEM     []byte
}

func NewAuthority(commonName string, now time.Time) (*Authority, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               pkix.Name{CommonName: commonName, Organization: []string{"Aegis"}},
		NotBefore:             now.Add(-5 * time.Minute),
		NotAfter:              now.AddDate(10, 0, 0),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign | x509.KeyUsageDigitalSignature,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &key.PublicKey, key)
	if err != nil {
		return nil, err
	}
	certificate, err := x509.ParseCertificate(der)
	if err != nil {
		return nil, err
	}
	return &Authority{
		certificate: certificate,
		privateKey:  key,
		certPEM:     pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}),
	}, nil
}

func (a *Authority) CertificatePEM() []byte { return append([]byte(nil), a.certPEM...) }

func (a *Authority) VerifyDeviceCertificate(certificate *x509.Certificate, now time.Time) (string, error) {
	roots := x509.NewCertPool()
	roots.AddCert(a.certificate)
	if _, err := certificate.Verify(x509.VerifyOptions{
		Roots:       roots,
		CurrentTime: now,
		KeyUsages:   []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return "", err
	}
	const prefix = "aegis-device:"
	if len(certificate.Subject.CommonName) <= len(prefix) || certificate.Subject.CommonName[:len(prefix)] != prefix {
		return "", fmt.Errorf("invalid device certificate identity")
	}
	return certificate.Subject.CommonName[len(prefix):], nil
}

func (a *Authority) Save(directory string) error {
	if err := os.MkdirAll(directory, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(directory, 0o700); err != nil {
		return err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(a.privateKey)
	if err != nil {
		return err
	}
	certPath := filepath.Join(directory, "ca.pem")
	keyPath := filepath.Join(directory, "ca-key.pem")
	if err := os.WriteFile(certPath, a.certPEM, 0o644); err != nil {
		return err
	}
	if err := os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	return os.Chmod(keyPath, 0o600)
}

func LoadAuthority(directory string) (*Authority, error) {
	certPEM, err := os.ReadFile(filepath.Join(directory, "ca.pem"))
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(filepath.Join(directory, "ca-key.pem"))
	if err != nil {
		return nil, err
	}
	certBlock, _ := pem.Decode(certPEM)
	keyBlock, _ := pem.Decode(keyPEM)
	if certBlock == nil || certBlock.Type != "CERTIFICATE" || keyBlock == nil || keyBlock.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("invalid authority PEM")
	}
	certificate, err := x509.ParseCertificate(certBlock.Bytes)
	if err != nil {
		return nil, err
	}
	parsedKey, err := x509.ParsePKCS8PrivateKey(keyBlock.Bytes)
	if err != nil {
		return nil, err
	}
	privateKey, ok := parsedKey.(*ecdsa.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("authority key is not ECDSA")
	}
	return &Authority{certificate: certificate, privateKey: privateKey, certPEM: certPEM}, nil
}

func (a *Authority) IssueServer(hosts []string, now time.Time) (tls.Certificate, error) {
	return a.issue("aegis-hub", hosts, []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth}, now)
}

func (a *Authority) IssueDevice(deviceID string, now time.Time) (tls.Certificate, error) {
	if deviceID == "" {
		return tls.Certificate{}, fmt.Errorf("device id is required")
	}
	return a.issue("aegis-device:"+deviceID, nil, []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth}, now)
}

func NewDeviceCSR(deviceID string) (keyPEM, csrPEM []byte, err error) {
	if deviceID == "" {
		return nil, nil, fmt.Errorf("device id is required")
	}
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, nil, err
	}
	csrDER, err := x509.CreateCertificateRequest(rand.Reader, &x509.CertificateRequest{
		Subject: pkix.Name{CommonName: "aegis-device:" + deviceID, Organization: []string{"Aegis"}},
	}, key)
	if err != nil {
		return nil, nil, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return nil, nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER}),
		pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE REQUEST", Bytes: csrDER}), nil
}

func (a *Authority) SignDeviceCSR(deviceID string, csrPEM []byte, now time.Time) ([]byte, error) {
	if deviceID == "" {
		return nil, fmt.Errorf("device id is required")
	}
	block, rest := pem.Decode(csrPEM)
	if block == nil || block.Type != "CERTIFICATE REQUEST" || len(rest) != 0 {
		return nil, fmt.Errorf("invalid certificate request PEM")
	}
	request, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, err
	}
	if err := request.CheckSignature(); err != nil {
		return nil, fmt.Errorf("invalid certificate request signature: %w", err)
	}
	serial, err := randomSerial()
	if err != nil {
		return nil, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: "aegis-device:" + deviceID, Organization: []string{"Aegis"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 3, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, request.PublicKey, a.privateKey)
	if err != nil {
		return nil, err
	}
	return pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), nil
}

func (a *Authority) issue(commonName string, hosts []string, usages []x509.ExtKeyUsage, now time.Time) (tls.Certificate, error) {
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return tls.Certificate{}, err
	}
	serial, err := randomSerial()
	if err != nil {
		return tls.Certificate{}, err
	}
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: commonName, Organization: []string{"Aegis"}},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(0, 3, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  usages,
	}
	for _, host := range hosts {
		if address := net.ParseIP(host); address != nil {
			template.IPAddresses = append(template.IPAddresses, address)
		} else {
			template.DNSNames = append(template.DNSNames, host)
		}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, a.certificate, &key.PublicKey, a.privateKey)
	if err != nil {
		return tls.Certificate{}, err
	}
	keyDER, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		return tls.Certificate{}, err
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return tls.X509KeyPair(certPEM, keyPEM)
}

func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	return rand.Int(rand.Reader, limit)
}

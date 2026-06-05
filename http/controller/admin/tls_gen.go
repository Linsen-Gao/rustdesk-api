package admin

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// generateSelfSignedCert creates a self-signed certificate and writes to disk.
func generateSelfSignedCert(certFile, keyFile string) ([]byte, error) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return nil, err
	}

	serial, err := rand.Int(rand.Reader, new(big.Int).Lsh(big.NewInt(1), 128))
	if err != nil {
		return nil, err
	}

	template := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			Organization: []string{"RustDesk API"},
			CommonName:   "rustdesk-api",
		},
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
		BasicConstraintsValid: true,
		IPAddresses:           []net.IP{net.ParseIP("127.0.0.1")},
	}

	derBytes, err := x509.CreateCertificate(rand.Reader, template, template, &priv.PublicKey, priv)
	if err != nil {
		return nil, err
	}

	certPEM := new(bytes.Buffer)
	pem.Encode(certPEM, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes})

	keyPEM := new(bytes.Buffer)
	privBytes, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, err
	}
	pem.Encode(keyPEM, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes})

	if err := os.WriteFile(certFile, certPEM.Bytes(), 0644); err != nil {
		return nil, err
	}
	if err := os.WriteFile(keyFile, keyPEM.Bytes(), 0600); err != nil {
		return nil, err
	}

	return certPEM.Bytes(), nil
}

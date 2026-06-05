package tls

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"math/big"
	"net"
	"os"
	"time"
)

// GenerateSelfSigned creates a self-signed TLS certificate and returns it.
// If certFile and keyFile are provided, the cert is also written to disk.
func GenerateSelfSigned(certFile, keyFile string) (*tls.Config, error) {
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
		NotAfter:              time.Now().Add(365 * 24 * time.Hour), // 1 year
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

	// Write to disk if paths provided
	if certFile != "" {
		if err := os.WriteFile(certFile, certPEM.Bytes(), 0644); err != nil {
			return nil, err
		}
	}
	if keyFile != "" {
		if err := os.WriteFile(keyFile, keyPEM.Bytes(), 0600); err != nil {
			return nil, err
		}
	}

	cert, err := tls.X509KeyPair(certPEM.Bytes(), keyPEM.Bytes())
	if err != nil {
		return nil, err
	}

	return &tls.Config{
		Certificates: []tls.Certificate{cert},
		MinVersion:   tls.VersionTLS12,
	}, nil
}

// LoadOrGenerate returns a TLS config by loading cert files, or generating self-signed if autoCert is true.
func LoadOrGenerate(certFile, keyFile string, autoCert bool) (*tls.Config, error) {
	// Try loading existing certs first
	if certFile != "" && keyFile != "" {
		if _, err := os.Stat(certFile); err == nil {
			if _, err := os.Stat(keyFile); err == nil {
				cert, err := tls.LoadX509KeyPair(certFile, keyFile)
				if err == nil {
					return &tls.Config{
						Certificates: []tls.Certificate{cert},
						MinVersion:   tls.VersionTLS12,
					}, nil
				}
			}
		}
	}

	// Auto-generate self-signed if enabled
	if autoCert {
		return GenerateSelfSigned(certFile, keyFile)
	}

	return nil, nil
}

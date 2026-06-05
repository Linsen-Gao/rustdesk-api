package http

import (
	"crypto/tls"

	tlsutil "github.com/lejianwen/rustdesk-api/v2/lib/tls"
)

// loadOrGenerateTLS loads TLS certs from files or generates self-signed.
func loadOrGenerateTLS(certFile, keyFile string, autoCert bool) (*tls.Config, error) {
	return tlsutil.LoadOrGenerate(certFile, keyFile, autoCert)
}

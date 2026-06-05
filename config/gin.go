package config

type Gin struct {
	ApiAddr       string `mapstructure:"api-addr"`
	AdminAddr     string `mapstructure:"admin-addr"`
	Mode          string
	ResourcesPath string `mapstructure:"resources-path"`
	TrustProxy    string `mapstructure:"trust-proxy"`
	CorsOrigins   string `mapstructure:"cors-origins"`
	// TLS/HTTPS configuration
	TlsEnable bool   `mapstructure:"tls-enable"` // Enable HTTPS
	TlsCertFile string `mapstructure:"tls-cert-file"` // TLS certificate file path (e.g. /etc/ssl/cert.pem)
	TlsKeyFile  string `mapstructure:"tls-key-file"`  // TLS key file path (e.g. /etc/ssl/key.pem)
	TlsAutoCert bool   `mapstructure:"tls-auto-cert"` // Auto-generate self-signed cert if no cert files provided
}
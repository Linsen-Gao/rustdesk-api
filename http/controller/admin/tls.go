package admin

import (
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"os"
	"path/filepath"

	"github.com/gin-gonic/gin"
	"github.com/lejianwen/rustdesk-api/v2/global"
	"github.com/lejianwen/rustdesk-api/v2/http/response"
)

// Default TLS cert storage path
var tlsCertDir = "data/tls"

type Tls struct{}

// TlsStatus returns current TLS configuration status
// @Tags TLS
// @Summary TLS状态
// @Description 获取当前TLS配置状态
// @Success 200 {object} response.Response
// @Router /admin/tls/status [get]
// @Security token
func (ct *Tls) Status(c *gin.Context) {
	certLoaded := false
	certExpiry := ""
	certSubject := ""

	if global.Config.Gin.TlsCertFile != "" {
		if certData, err := os.ReadFile(global.Config.Gin.TlsCertFile); err == nil {
			block, _ := pem.Decode(certData)
			if block != nil {
				cert, err := x509.ParseCertificate(block.Bytes)
				if err == nil {
					certLoaded = true
					certExpiry = cert.NotAfter.Format("2006-01-02 15:04:05")
					certSubject = cert.Subject.CommonName
				}
			}
		}
	}

	response.Success(c, gin.H{
		"enabled":      global.Config.Gin.TlsEnable,
		"auto_cert":    global.Config.Gin.TlsAutoCert,
		"cert_loaded":  certLoaded,
		"cert_subject": certSubject,
		"cert_expiry":  certExpiry,
		"cert_file":    global.Config.Gin.TlsCertFile,
		"key_file":     global.Config.Gin.TlsKeyFile,
	})
}

// Toggle enables or disables TLS
// @Tags TLS
// @Summary 开关TLS
// @Description 启用或禁用TLS
// @Param body body map[string]bool true "{"enabled": true}"
// @Success 200 {object} response.Response
// @Router /admin/tls/toggle [post]
// @Security token
func (ct *Tls) Toggle(c *gin.Context) {
	var req struct {
		Enabled bool `json:"enabled"`
	}
	if err := c.ShouldBindJSON(&req); err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "ParamsError")+err.Error())
		return
	}
	global.Config.Gin.TlsEnable = req.Enabled
	response.Success(c, gin.H{"enabled": req.Enabled, "restart_required": true})
}

// UploadCert accepts PEM certificate and key file uploads
// @Tags TLS
// @Summary 上传证书
// @Description 上传PEM格式的证书和私钥文件
// @Param cert formData file true "证书文件(.pem/.crt)"
// @Param key formData file true "私钥文件(.pem/.key)"
// @Success 200 {object} response.Response
// @Router /admin/tls/upload [post]
// @Security token
func (ct *Tls) UploadCert(c *gin.Context) {
	// Ensure storage directory exists
	if err := os.MkdirAll(tlsCertDir, 0700); err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}

	certFile, err := c.FormFile("cert")
	if err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "ParamsError")+"cert file required")
		return
	}
	keyFile, err := c.FormFile("key")
	if err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "ParamsError")+"key file required")
		return
	}

	// Validate certificate
	certPath := filepath.Join(tlsCertDir, "server.crt")
	if err := c.SaveUploadedFile(certFile, certPath); err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}
	certData, err := os.ReadFile(certPath)
	if err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}

	keyPath := filepath.Join(tlsCertDir, "server.key")
	if err := c.SaveUploadedFile(keyFile, keyPath); err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}
	keyData, err := os.ReadFile(keyPath)
	if err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}

	// Verify the cert/key pair is valid
	_, err = tls.X509KeyPair(certData, keyData)
	if err != nil {
		os.Remove(certPath)
		os.Remove(keyPath)
		response.Fail(c, 101, response.TranslateMsg(c, "ParamsError")+"invalid cert/key pair: "+err.Error())
		return
	}

	// Parse certificate info
	certInfo := "Unknown"
	block, _ := pem.Decode(certData)
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			certInfo = cert.Subject.CommonName + " (expires: " + cert.NotAfter.Format("2006-01-02") + ")"
		}
	}

	// Update config
	absCertPath, _ := filepath.Abs(certPath)
	absKeyPath, _ := filepath.Abs(keyPath)
	global.Config.Gin.TlsCertFile = absCertPath
	global.Config.Gin.TlsKeyFile = absKeyPath
	global.Config.Gin.TlsAutoCert = false

	response.Success(c, gin.H{
		"cert_info":       certInfo,
		"restart_required": true,
	})
}

// GenerateSelfSigned generates a self-signed certificate
// @Tags TLS
// @Summary 生成自签名证书
// @Description 自动生成自签名TLS证书
// @Success 200 {object} response.Response
// @Router /admin/tls/generate [post]
// @Security token
func (ct *Tls) GenerateSelfSigned(c *gin.Context) {
	if err := os.MkdirAll(tlsCertDir, 0700); err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}

	certPath := filepath.Join(tlsCertDir, "server.crt")
	keyPath := filepath.Join(tlsCertDir, "server.key")

	_, err := generateSelfSignedCert(certPath, keyPath)
	if err != nil {
		response.Fail(c, 101, response.TranslateMsg(c, "OperationFailed")+err.Error())
		return
	}

	absCertPath, _ := filepath.Abs(certPath)
	absKeyPath, _ := filepath.Abs(keyPath)
	global.Config.Gin.TlsCertFile = absCertPath
	global.Config.Gin.TlsKeyFile = absKeyPath
	global.Config.Gin.TlsAutoCert = true
	global.Config.Gin.TlsEnable = true

	// Read cert to get expiry
	certData, _ := os.ReadFile(certPath)
	block, _ := pem.Decode(certData)
	expiry := "Unknown"
	if block != nil {
		cert, err := x509.ParseCertificate(block.Bytes)
		if err == nil {
			expiry = cert.NotAfter.Format("2006-01-02 15:04:05")
		}
	}

	response.Success(c, gin.H{
		"cert_path":       absCertPath,
		"key_path":        absKeyPath,
		"expiry":          expiry,
		"restart_required": true,
	})
}

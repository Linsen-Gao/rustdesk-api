#!/bin/bash
# 一键启用 HTTPS
set -e

echo ">>> 生成自签名 TLS 证书..."
mkdir -p data/tls

openssl req -x509 -newkey ec -pkeyopt ec_paramgen_curve:prime256v1 \
  -keyout data/tls/server.key -out data/tls/server.crt \
  -days 365 -nodes \
  -subj "/O=RustDesk API/CN=rustdesk-api" \
  -addext "subjectAltName=IP:$(curl -s ifconfig.me 2>/dev/null || echo '127.0.0.1'),DNS:localhost" 2>/dev/null

echo ">>> 更新配置..."
sed -i 's/tls-enable: false/tls-enable: true/' conf/config.yaml
sed -i "s|tls-cert-file: \"\"|tls-cert-file: \"$PWD/data/tls/server.crt\"|" conf/config.yaml
sed -i "s|tls-key-file: \"\"|tls-key-file: \"$PWD/data/tls/server.key\"|" conf/config.yaml

echo ""
echo "✅ HTTPS 已配置！重启后生效"
echo "   管理页面: https://你的IP:21114/_admin/tls.html"

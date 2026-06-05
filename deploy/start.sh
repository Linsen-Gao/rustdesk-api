#!/bin/bash
# RustDesk API 启动脚本
# 用法: ./start.sh [JWT密钥]

JWT_KEY=${1:-$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | head -c32)}
export RUSTDESK_API_JWT_KEY="$JWT_KEY"

echo "========================================="
echo "  RustDesk API Server"
echo "  JWT Key: $JWT_KEY"
echo "========================================="

mkdir -p runtime data/tls
./apimain

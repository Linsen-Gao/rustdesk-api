#!/bin/bash
# 本地/ECS 编译脚本
go mod tidy
GOOS=linux GOARCH=amd64 CGO_ENABLED=0 go build -o apimain ./cmd/
echo "✅ Build complete: $(ls -lh apimain | awk '{print $5}')"

#!/usr/bin/env sh
# Bigfoot CA 빌드·배포.
#  UI/매뉴얼은 go:embed 로 바이너리에 내장되므로 별도 UI 빌드 단계가 없다(vanilla, npm 불필요).
#  go 1.22+ 필요 → 로컬 go 버전 무관하게 golang:1.22 컨테이너로 cross-compile.
set -e
cd "$(dirname "$0")/.."   # repo 루트(embed 대상 ui/ 포함)

ARCH="${ARCH:-arm64}"     # 호스트/대상 아키텍처. amd64 면 ARCH=amd64.

echo "[1/3] go 빌드 (linux/$ARCH, golang:1.22, ui embed 포함)"
docker run --rm -v "$PWD":/src -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e "GOARCH=$ARCH" -e GOFLAGS=-mod=mod -e GOCACHE=/tmp/gocache \
  golang:1.22 go build -o deploy/bigfoot-linux .

echo "[2/3] 이미지 빌드"
docker build -t chrismarspink/bigfoot-ca:latest deploy

echo "[3/3] 재배포"
( cd deploy && docker compose up -d --force-recreate bigfoot )
echo "done."

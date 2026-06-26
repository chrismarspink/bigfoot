#!/usr/bin/env bash
# Bigfoot CA 이미지 릴리즈 — Docker Hub 로 push.
#  선행: docker login (chrismarspink 계정). step-ca 는 smallstep 공식 이미지라 재배포 안 함.
#  사용: deploy/scripts/release.sh [버전]    (기본 0.1.0)
set -euo pipefail
cd "$(dirname "$0")/.."   # deploy/

IMAGE="chrismarspink/bigfoot-ca"
VERSION="${1:-0.1.0}"
ARCH="${ARCH:-arm64}"

echo "[1/3] 빌드 (linux/$ARCH, ui embed)"
docker run --rm -v "$PWD/..":/src -w /src \
  -e CGO_ENABLED=0 -e GOOS=linux -e "GOARCH=$ARCH" -e GOFLAGS=-mod=mod -e GOCACHE=/tmp/gocache \
  golang:1.22 go build -o deploy/bigfoot-linux .
docker build -t "$IMAGE:$VERSION" -t "$IMAGE:latest" .

echo "[2/3] push $IMAGE:$VERSION + :latest"
docker push "$IMAGE:$VERSION"
docker push "$IMAGE:latest"

echo "[3/3] 완료. 소비측: docker compose pull && docker compose up -d"
echo "  (멀티아키 필요 시: docker buildx build --platform linux/amd64,linux/arm64 ... --push)"

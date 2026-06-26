#!/usr/bin/env bash
# Bigfoot CA 백업 (P0-7) — 신뢰앵커·키·감사·수신자 일괄 백업.
#
# ⚠️ 가장 중요한 자산: step-ca 데이터 볼륨(Root/Intermediate 개인키 + ca.json).
#    이걸 잃으면 신뢰앵커가 바뀌어 모든 수신자 재배포가 필요하다. 오프라인 안전보관 필수.
#
# 백업 대상:
#   - stepca-data 볼륨   : Root/Intermediate 키·인증서·ca.json (신뢰앵커, 최고 기밀)
#   - bigfoot-data 볼륨  : 감사 SoR(해시체인) + 수신자 레지스트리
#   - ./stepca/ 호스트    : root_ca.crt / issuer_ca.crt / ca-password
#
# 사용: deploy/scripts/backup.sh [출력디렉터리]   (기본 ./backups)
# 복구: 동일 이름 볼륨에 tar 를 풀고 ./stepca/ 를 복원 → bootstrap 재실행 불필요.
set -euo pipefail
cd "$(dirname "$0")/.."   # deploy/

TS="$(date +%Y%m%d-%H%M%S)"
OUT="${1:-./backups}/$TS"
mkdir -p "$OUT"

# compose 프로젝트명(볼륨 접두사) 자동 탐지
PROJECT="$(docker compose config --format json 2>/dev/null | jq -r '.name' 2>/dev/null || basename "$PWD")"

dump_volume() { # <volume> <outfile>
  docker run --rm -v "${PROJECT}_$1":/v -v "$PWD/$OUT":/b alpine \
    sh -c "tar czf /b/$2 -C /v ." && echo "  ✓ $1 → $OUT/$2"
}

echo "[1/3] step-ca 볼륨(신뢰앵커·키) 백업"
dump_volume stepca-data stepca-data.tgz

echo "[2/3] bigfoot 볼륨(감사·수신자) 백업"
dump_volume bigfoot-data bigfoot-data.tgz

echo "[3/3] 호스트 신뢰앵커/비밀번호 백업"
tar czf "$OUT/stepca-host.tgz" -C . stepca/root_ca.crt stepca/issuer_ca.crt stepca/ca-password 2>/dev/null || true
echo "  ✓ stepca/ → $OUT/stepca-host.tgz"

# 감사 해시체인 헤드를 함께 기록(복구 후 무결성 대조용)
docker compose exec -T bigfoot wget -qO- http://localhost:9100/api/ca/audit/verify 2>/dev/null > "$OUT/audit-head.json" || true

echo "백업 완료: $OUT"
echo "⚠️ stepca-data.tgz 와 ca-password 는 개인키를 포함 — 오프라인 암호화 매체에 분리 보관하십시오."

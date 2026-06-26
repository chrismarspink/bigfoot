#!/usr/bin/env bash
# Root/Issuing 분리 운영 (P2-1) — Root 개인키를 온라인 시스템에서 분리해 오프라인 보관.
#
# 원리: step-ca 는 일상 리프 발급에 Intermediate 키만 사용한다. Root 개인키는
#   Intermediate 롤오버(수년) 때만 필요하므로, 평시엔 온라인에 둘 이유가 없다.
#   Root 키를 빼두면 침해 시에도 신뢰앵커(Root) 위조가 불가능 → 보안 등급 상승.
#
# 동작:
#   1) Root 개인키를 컨테이너 볼륨에서 호스트로 추출(암호화된 PEM)
#   2) 추출 검증 후 볼륨에서 Root 키 삭제(--remove 지정 시)
#   3) step-ca 재시작 → Intermediate 키로 정상 발급 지속 확인
#
# ⚠️ 추출한 root_ca_key 는 오프라인 암호화 매체(에어갭 USB/HSM)에 분리 보관.
#    분실 시 Intermediate 롤오버가 불가능해진다(신뢰앵커 교체 = 전 수신자 재배포).
#
# 사용: root-offline.sh <출력디렉터리> [--remove]
set -euo pipefail
cd "$(dirname "$0")/.."   # deploy/

OUT="${1:?출력 디렉터리를 지정하세요 (예: /secure/offline)}"
REMOVE="${2:-}"
mkdir -p "$OUT"

echo "[1/3] Root 개인키 추출 → $OUT/root_ca_key"
docker compose exec -T step-ca cat /home/step/secrets/root_ca_key > "$OUT/root_ca_key"
chmod 600 "$OUT/root_ca_key"
# 무결성: 추출본이 비어있지 않은지 확인
test -s "$OUT/root_ca_key" || { echo "추출 실패(빈 파일)"; exit 1; }
echo "  ✓ 추출 완료 ($(wc -c < "$OUT/root_ca_key") bytes, 암호화 PEM)"

if [ "$REMOVE" = "--remove" ]; then
  echo "[2/3] 볼륨에서 Root 키 삭제(오프라인 분리)"
  docker compose exec -T step-ca sh -c 'rm -f /home/step/secrets/root_ca_key && echo removed'
  echo "[3/3] step-ca 재시작 + 발급 동작 확인(Intermediate 키)"
  docker compose restart step-ca
  sleep 3
  if docker compose exec -T step-ca step ca health --ca-url https://localhost:9000 --root /home/step/certs/root_ca.crt 2>/dev/null; then
    echo "  ✓ Root 키 없이 step-ca 정상(리프 발급은 Intermediate 키 사용)"
  else
    echo "  ! health 확인 실패 — 수동 점검 필요"
  fi
  echo "완료. Root 키는 이제 $OUT 에만 존재합니다 — 오프라인 매체로 옮기고 이 사본도 안전 삭제하십시오."
else
  echo "[안내] 실제 분리(볼륨에서 삭제)는 --remove 로 재실행. 먼저 추출본을 오프라인 매체에 안전 보관하세요."
fi

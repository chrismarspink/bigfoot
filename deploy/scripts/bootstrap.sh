#!/usr/bin/env bash
# Bigfoot CA 최초 1회 부트스트랩 — step-ca 초기화 + EKU provisioner 등록 + CRL 활성 + 신뢰앵커 추출.
#
# 동작:
#   1) ca-password 생성(없으면)
#   2) step-ca 기동 → Root/Intermediate 자동 init 대기
#   3) Root/Intermediate 인증서를 ./stepca/ 로 추출(bigfoot 가 마운트)
#   4) ca.json 패치: crl.enabled=true + EKU provisioner 3종(tls/client/codesign) 등록
#      (기본 'bigfoot' JWK provisioner 를 복제해 이름·x509 템플릿만 교체 — 키 재사용, 무프롬프트)
#   5) step-ca 재시작(ca.json 반영)
#
# 의존: docker compose, jq(호스트). 멱등(재실행 안전).
set -euo pipefail
cd "$(dirname "$0")/.."   # deploy/

command -v jq >/dev/null || { echo "jq 가 필요합니다(호스트). 설치 후 재실행."; exit 1; }

PW=stepca/ca-password
if [ ! -f "$PW" ]; then
  echo "[1/5] ca-password 생성"
  ( openssl rand -base64 24 | tr -d '\n' ) > "$PW"
  chmod 600 "$PW"
else
  echo "[1/5] ca-password 존재 — 재사용"
fi

echo "[2/5] step-ca 기동 + init 대기"
docker compose up -d step-ca
for i in $(seq 1 60); do
  if docker compose exec -T step-ca test -f /home/step/certs/root_ca.crt 2>/dev/null; then break; fi
  sleep 1
done
docker compose exec -T step-ca test -f /home/step/certs/root_ca.crt || { echo "step-ca init 실패(타임아웃)"; exit 1; }

echo "[3/5] Root/Intermediate 추출 → ./stepca/"
docker compose exec -T step-ca cat /home/step/certs/root_ca.crt > stepca/root_ca.crt
docker compose exec -T step-ca cat /home/step/certs/intermediate_ca.crt > stepca/issuer_ca.crt

echo "[4/5] ca.json 패치 (CRL 활성 + EKU provisioner 등록)"
docker compose exec -T step-ca cat /home/step/config/ca.json > /tmp/bf-ca.json
CODESIGN=$(cat stepca/templates/codesign.tpl)
TLS=$(cat stepca/templates/tls.tpl)
CLIENT=$(cat stepca/templates/client.tpl)

# CRL 캐시 주기(폐기 반영 지연 상한). 짧게=즉시성↑·부하↑. 폐쇄망 배포 주기와 함께 결정(P2-3).
CRL_CACHE="${CRL_CACHE_DURATION:-10m}"

jq \
  --arg codesign "$CODESIGN" --arg tls "$TLS" --arg client "$CLIENT" --arg crlcache "$CRL_CACHE" '
  # CRL 활성 + 캐시 주기(즉시성 튜닝, P2-3)
  .crl = { "enabled": true, "cacheDuration": $crlcache } |
  # 기본 provisioner(첫 JWK) 복제 → 이름+x509 템플릿만 교체. 키 재사용(무프롬프트).
  (.authority.provisioners[0]) as $base |
  # claims: 리프 수명 상한. 고객 인증서(tls/client) 최대 1년 허용(기본 24h 상한 해제).
  {"maxTLSCertDuration":"8760h","defaultTLSCertDuration":"24h","minTLSCertDuration":"5m"} as $claims |
  ($base | .name="bigfoot-codesign" | .options={x509:{template:$codesign}} | .claims=$claims) as $p1 |
  ($base | .name="bigfoot-tls"      | .options={x509:{template:$tls}}      | .claims=$claims) as $p2 |
  ($base | .name="bigfoot-client"   | .options={x509:{template:$client}}   | .claims=$claims) as $p3 |
  # 중복 등록 방지: 동명 provisioner 제거 후 추가
  .authority.provisioners |= (map(select(.name|test("^bigfoot-(codesign|tls|client)$")|not))) |
  .authority.provisioners += [$p1,$p2,$p3]
  ' /tmp/bf-ca.json > /tmp/bf-ca.patched.json

docker compose cp /tmp/bf-ca.patched.json step-ca:/home/step/config/ca.json
rm -f /tmp/bf-ca.json /tmp/bf-ca.patched.json

echo "[5/5] step-ca 재시작"
docker compose restart step-ca
echo "done. 이제 'docker compose up -d bigfoot' 로 관리 서비스를 올리세요."
echo "신뢰앵커: deploy/stepca/root_ca.crt (수신자 사전 배포 대상)"

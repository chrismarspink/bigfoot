# 🐾 Bigfoot CA

**사설 CA · 파일 전자서명 어플라이언스 (air-gap 우선).**
TLS/디바이스 인증서 발급과 **코드·파일 전자서명**을 한 스택에서 제공합니다.
ZOT/TrustLink SCS 에 내장돼 있던 CA 제어·서명 로직(평면2/3)을 독립 제품으로 분리한 것입니다.

> 검증된 엔진(smallstep **step-ca**, **OpenSSL** CMS)을 **소스 무수정**으로 내장하고,
> 그 위에 발급 제어·파일 서명·수신자 관리·변조탐지 감사·관리 UI 를 얹었습니다.

## 아키텍처 — 3평면 (장애 격리)
```
평면1  step-ca 컨테이너   발급 엔진 + CRL (독립·상시)  ← 검증자/CI 직접 접근(:28443)
                              ▲ step CLI / REST
평면2/3 bigfoot 컨테이너   발급 제어 · 파일 서명(CMS) · 수신자 · 감사 · UI (:9100)
```
**bigfoot 이 죽어도 step-ca 의 검증·CRL·갱신은 독립 생존합니다.** 검증자는 step-ca(또는 배포된 CRL)에 직접 닿습니다.

## 주요 기능 (P0)
- **범용 인증서 발급**: 프로파일별 EKU — `tls`(serverAuth) / `client`(clientAuth) / `codesign`(codeSigning)
- **발급 경로 3종**: 서버키 생성 발급 · 고객 CSR 서명(키 미노출) · 재발급
- **파일 전자서명**: 파일 → 단명 codesign 인증서 → CMS `.p7s`. 검증자는 **루트 하나로** 검증
- **서명+암호화 패키지**: 수신자 공개 인증서로 `.p7m`(EnvelopedData) — 지정 수신자만 복호
- **폐기 / CRL**: 폐기 시 CRL 반영(단명 인증서 + CRL 모델, OCSP 불필요)
- **변조탐지 감사**: append-only 해시체인. `/api/ca/audit/verify` 로 무결성 검증
- **화면 내장 매뉴얼**: 콘솔의 "매뉴얼" 탭
- **FIPS-ready**: OpenSSL FIPS provider 자동 탐지(현 데모 alpine=미적용, 검증 OE 전환은 P1)

## 타 프로젝트에서 받아 쓰기 (Docker Hub)
이미지는 Docker Hub `chrismarspink/bigfoot-ca` 에 공개됩니다. step-ca 는 smallstep 공식 이미지를 그대로 받습니다.
소비 프로젝트는 **이 저장소의 `deploy/` 만** 가져오면 됩니다(compose + stepca/templates + scripts):
```bash
git clone https://github.com/chrismarspink/bigfoot && cd bigfoot/deploy
./scripts/bootstrap.sh          # 최초 1회: step-ca init + EKU provisioner + CRL + 신뢰앵커 추출
docker compose up -d            # bigfoot 이미지를 Docker Hub 에서 pull + 기동
# 콘솔: http://localhost:9100   ·   step-ca 직접: https://localhost:28444
# 특정 버전 고정: BIGFOOT_TAG=0.1.0 docker compose up -d
```

## 소스에서 빌드(개발)
```bash
cd deploy
./scripts/bootstrap.sh          # 최초 1회
./build.sh                      # 로컬 빌드(ui embed) → 동명 태그로 덮어쓰고 기동 (ARCH=amd64 가능)
```

## 릴리즈(메인테이너)
```bash
docker login                          # chrismarspink 계정
deploy/scripts/release.sh 0.1.0       # 빌드 → push 0.1.0 + latest
```

## 검증 (Bigfoot/step-ca 없이 루트만으로)
```bash
# 서명 검증
openssl cms -verify -inform DER -in file.p7s -CAfile deploy/stepca/root_ca.crt -purpose any -out original
# 암호화 패키지 복호 후 검증
openssl cms -decrypt -inform DER -in pkg.p7m -recip me.crt -inkey me.key | \
  openssl cms -verify -inform DER -CAfile deploy/stepca/root_ca.crt -purpose any
```

## 운영
- **백업**: `deploy/scripts/backup.sh` — 신뢰앵커·키·감사·수신자. step-ca 볼륨(개인키)은 오프라인 분리 보관.
- **신뢰앵커 배포**: 개요 탭 → Root PEM 다운로드 → 수신자에 오프라인 사전 배포.
- **API**: [docs/openapi.yaml](docs/openapi.yaml)

## 보안 주의 (현재 단계)
- **인증 미적용** — 신뢰된 망에서만 노출. 도입 플랜: [docs/AUTH-PLAN.md](docs/AUTH-PLAN.md)
- **TLS** — `TLS_CERT`/`TLS_KEY` 미설정 시 평문 HTTP(경고 로그). 운영 전 설정 필수.

## 로드맵
- **P0**(현재): 분리 + 범용 CA + 파일서명 + 감사 해시체인 + 백업 + UI/매뉴얼
- **P1**(보류): FIPS 검증 OE 전환, ACME 자동발급, HSM/PKCS#11, 만료 알림
- **P2**(HA 제외 진행): Root/Issuing 분리 운영, 승인 워크플로(4-eyes), CRL 즉시성 튜닝

# Bigfoot CA — 운영 가이드 (P2)

## 1. Root / Issuing 분리 운영 (P2-1)
2계층 PKI: **Root**(신뢰 앵커) → **Intermediate**(리프 서명) → **Leaf**.
일상 발급은 Intermediate 키만 사용하므로, **Root 개인키는 온라인에 둘 이유가 없다.**

### 절차
```bash
deploy/scripts/root-offline.sh /secure/offline           # 1) Root 키 추출(검증만)
# 추출본을 오프라인 암호화 매체로 이동 후:
deploy/scripts/root-offline.sh /secure/offline --remove  # 2) 볼륨에서 삭제 + 발급 지속 확인
```
- 분리 후: 리프 발급/CSR 서명/폐기/CRL 모두 정상(Intermediate 키). **Root 키는 Intermediate 롤오버 때만** 오프라인에서 일시 사용.
- ⚠️ Root 키 분실 = 신뢰앵커 교체 = 전 수신자 재배포. 반드시 다중 사본·안전 보관.

### Intermediate 롤오버(수년 주기)
1. 오프라인 Root 키 복귀 → 새 Intermediate 재서명(동일 Root) → 볼륨 교체 → Root 키 재분리.
2. 기존 리프는 유효 유지(Root 불변). 새 서명의 임베드 체인만 갱신 — **수신자 영향 없음.**

## 2. 승인 워크플로 (4-eyes, P2-2)
발급/폐기를 **요청 → 승인** 2단계로 분리. 요청자 ≠ 승인자(fail-closed).

- 활성화: `ENFORCE_APPROVAL=true` (compose env) → 직접 `/api/ca/issue`·`/revoke` 차단(403), 승인 경로만 허용.
- 콘솔: **승인** 탭에서 요청 생성 / 대기 목록 / 승인·반려.
- API:
  ```
  POST /api/approvals            {action:"issue"|"revoke", params:{...}}   # 요청
  GET  /api/approvals                                                       # 목록
  POST /api/approvals/{id}/approve                                          # 승인+실행(요청자≠승인자)
  POST /api/approvals/{id}/reject {note}                                    # 반려
  ```
- 모든 요청/승인/반려는 감사 해시체인에 기록.
- ℹ️ 인증 미도입 단계에서는 신원이 `X-User` 헤더 기반이라 분리가 약하다. OIDC 도입 시
  자동으로 "검증된 서로 다른 두 신원" 강제로 승격된다([AUTH-PLAN.md](AUTH-PLAN.md) §5).

## 3. CRL 즉시성 튜닝 (P2-3)
폐기 반영 지연의 상한 = CRL `cacheDuration`. 짧게=즉시성↑·부하↑.

- 설정: bootstrap 시 `CRL_CACHE_DURATION=10m deploy/scripts/bootstrap.sh` (기본 10m).
  - 이미 구동 중이면 step-ca `ca.json` 의 `crl.cacheDuration` 수정 후 `docker compose restart step-ca`.
- 가시화: `GET /api/ca/crl/info` → `lastUpdate`/`nextUpdate`. nextUpdate 까지의 간격이 폐기 반영 상한.
- 폐쇄망 권고: **단명 인증서(릴리스 서명 24h) + 짧은 CRL 주기** 조합으로 OCSP 없이 폐기 통제.
  고객 장수명 인증서(최대 1년)는 CRL 로 폐기 확인.

## 4. 백업 / 복구 (P0-7)
```bash
deploy/scripts/backup.sh                  # 신뢰앵커·키·감사·수신자 일괄 백업(타임스탬프)
```
- `stepca-data.tgz`(개인키 포함) 와 `ca-password` 는 오프라인 암호화 매체에 분리 보관.
- 복구: 동일 이름 볼륨에 tar 풀기 + `./stepca/` 복원 → bootstrap 재실행 불필요.
- 복구 후 `GET /api/ca/audit/verify` 로 감사 해시체인 무결성 대조(백업 시 `audit-head.json` 과 비교).

// Bigfoot CA 화면 내장 매뉴얼.
// ⚠️ 기능이 추가/변경될 때마다 이 파일을 갱신한다(제품 요구사항). 버전·날짜를 함께 올린다.
const MANUAL = `
<div class="card manual">
  <h2>Bigfoot CA 사용 매뉴얼</h2>
  <p class="desc">버전 P0 + P2(HA 제외) · 최종 갱신 2026-06-26</p>
  <p class="note">목록(인증서·감사·수신자·승인)은 20건씩 페이지네이션됩니다. 하단의 ‹이전/다음› 으로 이동하며, 서버에서 해당 페이지만 받아옵니다(전체 건수 표시).</p>
  <p class="note">우측 상단 ☀️/🌙 버튼으로 라이트·다크 테마를 전환할 수 있습니다(브라우저에 저장).</p>

  <h3>1. 개념 — 3평면 구조</h3>
  <ul>
    <li><b>평면1 (step-ca)</b>: 인증서 발급 엔진 + CRL 배포. 독립 컨테이너로 상시 구동되며, 검증자는 여기에 직접 닿습니다. <b>Bigfoot 관리 서비스가 죽어도 검증/CRL/갱신은 살아있습니다.</b></li>
    <li><b>평면2/3 (Bigfoot, 이 콘솔)</b>: 발급 제어 · 파일 서명 · 수신자 관리 · 감사 · 관리 UI.</li>
  </ul>
  <p class="note">신뢰 앵커(Root) 지문이 바뀌면(예: step-ca 데이터 볼륨 재생성) 모든 수신자에게 루트를 재배포해야 합니다 — 운영 시 가장 주의할 점입니다.</p>

  <h3>2. 신뢰 앵커 배포 (수신자 온보딩)</h3>
  <p>개요 탭에서 <b>Root PEM</b>을 내려받아 수신자에게 <u>오프라인으로 사전 배포</u>합니다. 수신자는 루트 하나만 신뢰하면 Bigfoot 의 모든 서명을 검증할 수 있습니다(N×M 키분배 회피).</p>

  <h3>3. 인증서 프로파일 (EKU)</h3>
  <ul>
    <li><code>tls</code> — serverAuth. 서버/디바이스 TLS 인증서 (기본 1년).</li>
    <li><code>client</code> — clientAuth. mTLS 클라이언트 인증서.</li>
    <li><code>codesign</code> — codeSigning. <b>파일/코드 전자서명용</b> (기본 단명 24h).</li>
  </ul>

  <h3>4. 인증서 발급 — 3가지 경로</h3>
  <ul>
    <li><b>서버 키 생성 발급</b> (발급 탭): Bigfoot 이 키쌍 생성 후 서명. 개인키는 서버에만 남고 응답에 포함되지 않습니다.</li>
    <li><b>고객 CSR 서명</b> (발급 탭): 고객이 개인키를 보유하고 CSR 만 제출. 개인키가 서버에 노출되지 않습니다 — 가장 권장되는 방식.</li>
    <li><b>재발급</b> (인증서 탭): 동일 CN 으로 새 인증서. 단명 인증서 갱신 전략에 사용.</li>
  </ul>

  <h3>5. 파일 전자서명 (제품 핵심)</h3>
  <p><b>파일 서명 탭</b>에서:</p>
  <ul>
    <li><b>서명(.p7s)</b>: 파일 업로드 → 단명 codesign 인증서로 CMS SignedData 생성. 매 서명마다 새 24h 인증서가 발급되어 폐기 의존을 줄입니다.</li>
    <li><b>검증</b>: .p7s 업로드 → 신뢰 앵커(루트)로 검증 + 원문 다이제스트 확인.</li>
    <li><b>서명+암호화(.p7m)</b>: 파일을 서명 후 선택한 수신자 공개 인증서로 암호화. 지정 수신자만 복호 가능.</li>
  </ul>
  <p>수신자측 CLI 검증(Bigfoot/step-ca 없이 루트만으로):</p>
  <pre>openssl cms -verify -inform DER -in file.p7s -CAfile bigfoot-root.crt -purpose any -out original
# 암호화 패키지 복호 후 검증:
openssl cms -decrypt -inform DER -in pkg.p7m -recip me.crt -inkey me.key | \\
  openssl cms -verify -inform DER -CAfile bigfoot-root.crt -purpose any</pre>

  <h3>6. 수신자 인증서 (암호화 대상)</h3>
  <p><b>수신자 탭</b>에서 외부 수신자의 공개 인증서(PEM)를 임포트합니다. 개인키는 보관하지 않습니다. 임포트된 수신자는 .p7m 암호화 대상으로 선택됩니다.</p>

  <h3>7. 폐기 / CRL (즉시성 튜닝)</h3>
  <p>인증서 탭에서 폐기하면 step-ca CRL 에 반영됩니다. 검증자는 CRL(개요 탭에서 다운로드)을 받아 폐기 여부를 대조합니다. OCSP 는 미제공 — 단명 인증서 + CRL 조합으로 폐기를 통제합니다.</p>
  <p>폐기 반영 지연의 상한은 CRL <code>cacheDuration</code>(기본 10분)입니다. 짧을수록 즉시성↑·부하↑. <code>GET /api/ca/crl/info</code> 로 lastUpdate/nextUpdate 를 확인할 수 있습니다(운영 가이드 §3).</p>

  <h3>7b. 발급/폐기 승인 워크플로 (4-eyes)</h3>
  <p><b>승인 탭</b>에서 발급/폐기를 <u>요청 → 승인</u> 2단계로 처리합니다. 요청자와 승인자는 동일할 수 없습니다(fail-closed). <code>ENFORCE_APPROVAL=true</code> 설정 시 직접 발급/폐기가 차단되고 이 경로만 허용됩니다. 모든 요청·승인·반려는 감사에 기록됩니다.</p>

  <h3>7c. Root / Issuing 분리 운영</h3>
  <p>일상 발급은 Intermediate 키만 사용하므로, Root 개인키는 오프라인으로 분리 보관할 수 있습니다(<code>deploy/scripts/root-offline.sh</code>). 침해 시에도 신뢰앵커(Root) 위조가 불가능해집니다. 운영 가이드 §1 참조.</p>

  <h3>8. 감사 로그 (변조 탐지)</h3>
  <p>모든 발급·폐기·서명·검증·수신자 변경이 <b>append-only 해시체인</b>으로 기록됩니다. 감사 탭 상단에서 무결성(변조 여부)을 확인할 수 있습니다. <code>GET /api/ca/audit/verify</code> 로도 검증 가능합니다.</p>

  <h3>9. FIPS 상태</h3>
  <p>상단 표시줄의 FIPS 배지는 실행 OpenSSL 의 FIPS provider 활성 여부입니다. 현재 데모(alpine)는 <b>FIPS 미적용</b>입니다. 검증 모듈 OE 전환(RHEL UBI / Ubuntu Pro FIPS)은 P1 과제입니다.</p>

  <h3>10. 인증 (예정)</h3>
  <p class="note">현재 버전은 인증이 적용되지 않았습니다(데모/내부망 전제). OIDC 인증·RBAC·발급 승인 워크플로는 다음 단계에서 도입됩니다(docs/AUTH-PLAN.md). 그때까지 본 콘솔은 신뢰된 망에서만 노출하십시오.</p>

  <h3>11. API 요약</h3>
  <pre>GET  /healthz
GET  /api/ca/info | /certs | /crl | /crl/info | /root | /issuer | /audit | /audit/verify
POST /api/ca/issue | /sign-csr | /revoke | /reissue
GET  /api/approvals   POST /api/approvals   POST /api/approvals/{id}/approve|reject
GET  /api/recipients  POST /api/recipients  DELETE /api/recipients/{id}
POST /api/sign | /verify | /encrypt</pre>
</div>`;

package main

// Bigfoot CA — 독립 사설 CA·파일서명 어플라이언스(평면2·3 제어/관리 서비스).
// 평면1(step-ca)은 별도 컨테이너로 독립 구동되며, 검증자는 step-ca 에 직접 닿는다.
// 본 서비스가 죽어도 step-ca 검증/CRL/갱신은 생존한다(장애 격리 불변 규칙).
//
// 인증(OIDC)은 아직 미적용 — docs/AUTH-PLAN.md 의 플랜대로 guard 미들웨어 자리만 둔다.

import (
	"embed"
	"encoding/json"
	"io/fs"
	"log"
	"net/http"
	"os"
)

//go:embed all:ui
var uiFS embed.FS

type Config struct {
	Addr    string
	TLSCert string // 서버 TLS 인증서 경로 (비어있으면 평문 HTTP + 경고)
	TLSKey  string

	// CA(step-ca) 연동 — 평면2.
	StepCaURL         string
	StepCaRoot        string // 신뢰 앵커(CAfile)
	StepCaIssuer      string // 발급(중간) CA 인증서 (다운로드 제공)
	StepCaProvisioner string // 기본 provisioner
	StepCaPassFile    string // provisioner 비밀번호 파일

	Profiles map[string]CertProfile // 인증서 프로파일(EKU)

	SoRPath        string // 감사 SoR(JSONL, 해시체인)
	RecipientsPath string // 수신자 인증서 레지스트리
	ApprovalsPath  string // 승인 워크플로 저장(P2-2)

	EnforceApproval bool // true 면 직접 발급/폐기 차단, 승인 워크플로만 허용(4-eyes)

	// CMS 암호 알고리즘 — FIPS 승인값 기본. 배포 OE 검증 모듈에 맞게 env 로 교체.
	CMSContentCipher string
	CMSRsaPadding    string
}

func env(k, def string) string {
	if v := os.Getenv(k); v != "" {
		return v
	}
	return def
}

func loadConfig() Config {
	prov := env("STEPCA_PROVISIONER", "bigfoot")
	c := Config{
		Addr:              env("ADDR", ":9100"),
		TLSCert:           env("TLS_CERT", ""),
		TLSKey:            env("TLS_KEY", ""),
		StepCaURL:         env("STEPCA_URL", "https://step-ca:9000"),
		StepCaRoot:        env("STEPCA_ROOT", "/etc/bigfoot/step-root.crt"),
		StepCaIssuer:      env("STEPCA_ISSUER", "/etc/bigfoot/step-issuer.crt"),
		StepCaProvisioner: prov,
		StepCaPassFile:    env("STEPCA_PROVISIONER_PASSWORD_FILE", "/etc/bigfoot/ca-password"),
		SoRPath:           env("SOR_PATH", "/var/lib/bigfoot/sor.jsonl"),
		RecipientsPath:    env("RECIPIENTS_PATH", "/var/lib/bigfoot/recipients.json"),
		ApprovalsPath:     env("APPROVALS_PATH", "/var/lib/bigfoot/approvals.json"),
		EnforceApproval:   env("ENFORCE_APPROVAL", "") == "true",
		CMSContentCipher:  env("CMS_CONTENT_CIPHER", "-aes-256-gcm"),
		CMSRsaPadding:     env("CMS_RSA_PADDING", "oaep"),
	}
	// 프로파일: env 로 provisioner 를 프로파일별로 덮어쓸 수 있다(EKU 템플릿 분리 운영).
	c.Profiles = defaultProfiles(prov)
	overrideProv(c.Profiles, "tls", env("PROVISIONER_TLS", ""))
	overrideProv(c.Profiles, "client", env("PROVISIONER_CLIENT", ""))
	overrideProv(c.Profiles, "codesign", env("PROVISIONER_CODESIGN", ""))
	return c
}

func overrideProv(m map[string]CertProfile, name, prov string) {
	if prov == "" {
		return
	}
	if p, ok := m[name]; ok {
		p.Provisioner = prov
		m[name] = p
	}
}

type Server struct {
	cfg    Config
	ca     CAAdapter
	sor    *SoR
	recips *RecipientStore
	appr   *ApprovalStore
}

func newServer(cfg Config) *Server {
	s := &Server{cfg: cfg}
	s.sor = newSoR(cfg.SoRPath)
	s.recips = newRecipientStore(cfg.RecipientsPath)
	s.appr = newApprovalStore(cfg.ApprovalsPath)
	// CA 활성: 신뢰앵커 파일이 존재하면 step-ca 어댑터 연결.
	if _, err := os.Stat(cfg.StepCaRoot); err == nil {
		s.ca = NewStepCaAdapter(cfg, s.sor)
	} else {
		log.Printf("경고: 신뢰앵커(%s) 없음 — CA 기능 비활성(평면2/3). step-ca init 후 마운트 필요.", cfg.StepCaRoot)
	}
	return s
}

// actorOf — 행위자 식별(감사 actor). 인증 도입 전 placeholder: X-User 헤더 → 없으면 anonymous.
//
//	인증 적용 시 guard 가 검증된 subject 를 X-User 로 주입한다(AUTH-PLAN.md).
func actorOf(r *http.Request) string {
	if u := r.Header.Get("X-User"); u != "" {
		return u
	}
	return "anonymous"
}

// guard — 인증 미들웨어 자리. P0: 인증 미적용(통과). 인증 도입 시 여기에서 OIDC 토큰
//
//	검증 + RBAC 확인 후 거부(fail-closed)하도록 교체한다. AUTH-PLAN.md 참조.
func (s *Server) guard(h http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		h(w, r)
	}
}

func (s *Server) routes() http.Handler {
	mux := http.NewServeMux()

	mux.HandleFunc("GET /healthz", s.apiHealth)

	// CA — 평면2/3
	mux.HandleFunc("GET /api/ca/info", s.guard(s.apiCAInfo))
	mux.HandleFunc("GET /api/ca/certs", s.guard(s.apiCACerts))
	mux.HandleFunc("GET /api/ca/crl", s.guard(s.apiCACRL))
	mux.HandleFunc("GET /api/ca/crl/info", s.guard(s.apiCACRLInfo))
	mux.HandleFunc("GET /api/ca/root", s.guard(s.apiCARoot))
	mux.HandleFunc("GET /api/ca/issuer", s.guard(s.apiCAIssuer))
	mux.HandleFunc("GET /api/ca/audit", s.guard(s.apiCAAudit))
	mux.HandleFunc("GET /api/ca/audit/verify", s.guard(s.apiCAAuditVerify))
	mux.HandleFunc("POST /api/ca/issue", s.guard(s.apiCAIssue))
	mux.HandleFunc("POST /api/ca/sign-csr", s.guard(s.apiCASignCSR))
	mux.HandleFunc("POST /api/ca/revoke", s.guard(s.apiCARevoke))
	mux.HandleFunc("POST /api/ca/reissue", s.guard(s.apiCAReissue))

	// 승인 워크플로(4-eyes, P2-2)
	mux.HandleFunc("GET /api/approvals", s.guard(s.apiApprovalList))
	mux.HandleFunc("POST /api/approvals", s.guard(s.apiApprovalCreate))
	mux.HandleFunc("POST /api/approvals/{id}/approve", s.guard(s.apiApprovalApprove))
	mux.HandleFunc("POST /api/approvals/{id}/reject", s.guard(s.apiApprovalReject))

	// 수신자 레지스트리
	mux.HandleFunc("GET /api/recipients", s.guard(s.apiRecipientsList))
	mux.HandleFunc("POST /api/recipients", s.guard(s.apiRecipientImport))
	mux.HandleFunc("DELETE /api/recipients/{id}", s.guard(s.apiRecipientDelete))

	// 범용 파일 서명
	mux.HandleFunc("POST /api/sign", s.guard(s.apiSign))
	mux.HandleFunc("POST /api/verify", s.guard(s.apiVerify))
	mux.HandleFunc("POST /api/encrypt", s.guard(s.apiEncrypt))

	// 관리 UI(임베디드) + 매뉴얼
	sub, _ := fs.Sub(uiFS, "ui")
	mux.Handle("/", http.FileServer(http.FS(sub)))
	return mux
}

// GET /healthz — 상태 점검(오케스트레이터 헬스체크용).
func (s *Server) apiHealth(w http.ResponseWriter, r *http.Request) {
	fipsActive, fipsDetail := fipsStatus()
	out := map[string]any{
		"status":  "ok",
		"caReady": s.caEnabled(),
		"fips":    map[string]any{"active": fipsActive, "detail": fipsDetail},
	}
	if s.caEnabled() {
		out["caReachable"] = s.ca.Reachable()
	}
	if vr, err := s.sor.verify(); err == nil {
		out["auditIntegrity"] = vr.OK
	}
	writeJSON(w, 200, out)
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

func main() {
	cfg := loadConfig()
	s := newServer(cfg)
	h := s.routes()

	if cfg.TLSCert != "" && cfg.TLSKey != "" {
		log.Printf("Bigfoot CA — HTTPS %s (TLS)", cfg.Addr)
		log.Fatal(http.ListenAndServeTLS(cfg.Addr, cfg.TLSCert, cfg.TLSKey, h))
	}
	log.Printf("경고: TLS 미설정(TLS_CERT/TLS_KEY) — 평문 HTTP 로 기동. 운영 전 TLS 필수.")
	log.Printf("Bigfoot CA — HTTP %s", cfg.Addr)
	log.Fatal(http.ListenAndServe(cfg.Addr, h))
}

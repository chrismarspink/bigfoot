package main

// CA 어댑터 — 평면2(발급/제어). step-ca 를 추상 인터페이스 뒤에 둔다.
// 평면1(검증·CRL 직접 접근)은 이 어댑터를 거치지 않는다(검증자는 step-ca 에 직접 닿음).
// step-ca 소스 무수정: 공식 `step` CLI 호출로만 연동. 개인키는 API/GUI 경로에 노출하지 않는다.

import (
	"bytes"
	"context"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"os"
	"os/exec"
	"sort"
	"strings"
	"time"
)

// CAAdapter — 엔진 추상화. step-ca 의존을 인터페이스 뒤에 두어 차후 엔진 교체 가능(전략 자산).
type CAAdapter interface {
	IssueCert(actor, profile, commonName string, sans []string, notAfter string) (*IssuedCert, error)
	SignCSR(actor, profile string, csrPEM []byte, notAfter string) (*IssuedCert, error)
	GetCRL() ([]byte, error)
	GetCertStatus(serial string) (CertRecord, bool)
	ListCerts() []CertRecord
	RevokeCert(actor, serial, reason string) error
	Reachable() bool // 평면1 도달성(검증자 직접 경로)
}

// IssuedCert — 발급 결과. KeyPEM 은 issue(서버키 생성) 시에만 채워지고 API 응답엔 싣지 않는다.
type IssuedCert struct {
	Serial   string
	Subject  string
	Profile  string
	NotAfter time.Time
	CertPEM  []byte
	KeyPEM   []byte
}

// CertRecord — GUI/SoR 표현용 인증서 레코드(공개 정보만).
type CertRecord struct {
	Serial   string `json:"serial"`
	Subject  string `json:"subject"`
	Profile  string `json:"profile,omitempty"`
	NotAfter string `json:"notAfter"`
	IssuedAt string `json:"issuedAt"`
	Status   string `json:"status"` // valid | revoked
	Actor    string `json:"actor,omitempty"`
}

// StepCaAdapter — step-ca CLI 어댑터. 발급은 `step` CLI, 목록/상태는 SoR 기반.
type StepCaAdapter struct {
	cfg      Config
	url      string
	root     string
	passFile string
	sor      *SoR
}

func NewStepCaAdapter(cfg Config, sor *SoR) *StepCaAdapter {
	return &StepCaAdapter{
		cfg: cfg, url: cfg.StepCaURL, root: cfg.StepCaRoot,
		passFile: cfg.StepCaPassFile, sor: sor,
	}
}

func (a *StepCaAdapter) step(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "step", args...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("step %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// stepStdout: stdout 만 캡처(상태 메시지는 stderr 로 분리). 토큰 등 값 추출용.
func (a *StepCaAdapter) stepStdout(args ...string) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "step", args...)
	var errb bytes.Buffer
	cmd.Stderr = &errb
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("step %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(errb.String()))
	}
	return strings.TrimSpace(string(out)), nil
}

// SignCSR: 고객 CSR 서명(고객이 개인키 보유 → 개인키 미노출). 발급된 인증서만 반환.
func (a *StepCaAdapter) SignCSR(actor, profile string, csrPEM []byte, notAfter string) (*IssuedCert, error) {
	p, err := a.cfg.resolveProfile(profile)
	if err != nil {
		return nil, err
	}
	if notAfter == "" {
		notAfter = p.DefaultDur
	}
	csrPath, err := writeTemp("bf-csr-*.csr", csrPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(csrPath)
	crtPath, err := writeTemp("bf-csrout-*.crt", nil)
	if err != nil {
		return nil, err
	}
	os.Remove(crtPath)
	defer os.Remove(crtPath)
	if _, err := a.step("ca", "sign", csrPath, crtPath, "--ca-url", a.url, "--root", a.root,
		"--provisioner", p.Provisioner, "--provisioner-password-file", a.passFile, "--not-after", notAfter, "--force"); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return nil, err
	}
	serial := strings.ToUpper(leaf.SerialNumber.Text(16))
	ic := &IssuedCert{Serial: serial, Subject: leaf.Subject.String(), Profile: p.Name, NotAfter: leaf.NotAfter, CertPEM: certPEM}
	_ = a.sor.append(SoREvent{Actor: actor, Action: "issue", Serial: serial, Subject: leaf.Subject.String(), Profile: p.Name,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339), Status: "valid", Detail: map[string]any{"mode": "csr-sign"}})
	return ic, nil
}

// IssueCert — 프로파일(EKU) 적용 발급. 서버키 생성형(개인키 함께 반환, 응답엔 미포함).
func (a *StepCaAdapter) IssueCert(actor, profile, cn string, sans []string, notAfter string) (*IssuedCert, error) {
	p, err := a.cfg.resolveProfile(profile)
	if err != nil {
		return nil, err
	}
	if notAfter == "" {
		notAfter = p.DefaultDur
	}
	crtF, err := os.CreateTemp("", "bf-*.crt")
	if err != nil {
		return nil, err
	}
	keyF, err := os.CreateTemp("", "bf-*.key")
	if err != nil {
		return nil, err
	}
	crtPath, keyPath := crtF.Name(), keyF.Name()
	crtF.Close()
	keyF.Close()
	os.Remove(crtPath) // step 이 --force 로 새로 쓴다(기존 빈 파일 제거)
	os.Remove(keyPath)
	defer os.Remove(crtPath)
	defer os.Remove(keyPath)

	args := []string{
		"ca", "certificate", cn, crtPath, keyPath,
		"--ca-url", a.url, "--root", a.root,
		"--provisioner", p.Provisioner, "--provisioner-password-file", a.passFile,
		"--not-after", notAfter, "--kty", p.KeyType, "--force",
	}
	if p.KeyType == "EC" && p.Curve != "" {
		args = append(args, "--curve", p.Curve)
	}
	for _, sn := range sans {
		if sn != "" {
			args = append(args, "--san", sn)
		}
	}
	if _, err := a.step(args...); err != nil {
		return nil, err
	}
	certPEM, err := os.ReadFile(crtPath)
	if err != nil {
		return nil, err
	}
	keyPEM, err := os.ReadFile(keyPath)
	if err != nil {
		return nil, err
	}
	leaf, err := parseLeaf(certPEM)
	if err != nil {
		return nil, err
	}
	serial := strings.ToUpper(leaf.SerialNumber.Text(16))
	subject := leaf.Subject.String()
	ic := &IssuedCert{Serial: serial, Subject: subject, Profile: p.Name, NotAfter: leaf.NotAfter, CertPEM: certPEM, KeyPEM: keyPEM}
	_ = a.sor.append(SoREvent{
		Actor: actor, Action: "issue", Serial: serial, Subject: subject, Profile: p.Name,
		NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339), Status: "valid",
	})
	return ic, nil
}

// GetCRL — step-ca CRL(평면1) HTTP 엔드포인트(/crl) 조회. DER(application/pkix-crl).
func (a *StepCaAdapter) GetCRL() ([]byte, error) {
	pool := x509.NewCertPool()
	if rootPEM, err := os.ReadFile(a.root); err == nil {
		pool.AppendCertsFromPEM(rootPEM)
	}
	cl := &http.Client{Timeout: 15 * time.Second,
		Transport: &http.Transport{TLSClientConfig: &tls.Config{RootCAs: pool, MinVersion: tls.VersionTLS12}}}
	resp, err := cl.Get(a.url + "/crl")
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, fmt.Errorf("crl status %d", resp.StatusCode)
	}
	return io.ReadAll(resp.Body)
}

// RevokeCert — 폐기 + SoR 기록. step-ca 폐기는 OTT(--revoke 토큰) 발급 후 revoke.
func (a *StepCaAdapter) RevokeCert(actor, serial, reason string) error {
	dec := serial
	if n, ok := new(big.Int).SetString(strings.TrimPrefix(strings.ToLower(serial), "0x"), 16); ok {
		dec = n.String()
	}
	tok, err := a.stepStdout("ca", "token", dec, "--revoke", "--ca-url", a.url, "--root", a.root,
		"--provisioner", a.cfg.StepCaProvisioner, "--provisioner-password-file", a.passFile)
	if err != nil {
		return fmt.Errorf("revoke 토큰 발급: %w", err)
	}
	args := []string{"ca", "revoke", dec, "--token", tok, "--ca-url", a.url, "--root", a.root}
	if reason != "" {
		args = append(args, "--reason", reason)
	}
	if _, err := a.step(args...); err != nil {
		return err
	}
	return a.sor.append(SoREvent{Actor: actor, Action: "revoke", Serial: serial, Status: "revoked", Detail: map[string]any{"reason": reason}})
}

// ListCerts — SoR 기반 인증서 목록(발급-폐기 이벤트 접합). step-ca OSS 는 발급목록 API 가 없어
// Bigfoot 이 발급한 것을 SoR 로 기록·표현한다(평면3).
func (a *StepCaAdapter) ListCerts() []CertRecord {
	evs, _ := a.sor.list()
	byMap := map[string]*CertRecord{}
	var order []string
	for _, e := range evs {
		switch e.Action {
		case "issue":
			if _, ok := byMap[e.Serial]; !ok {
				order = append(order, e.Serial)
			}
			byMap[e.Serial] = &CertRecord{Serial: e.Serial, Subject: e.Subject, Profile: e.Profile, NotAfter: e.NotAfter, IssuedAt: e.Time, Status: "valid", Actor: e.Actor}
		case "revoke":
			if r, ok := byMap[e.Serial]; ok {
				r.Status = "revoked"
			}
		}
	}
	out := make([]CertRecord, 0, len(order))
	for _, sn := range order {
		out = append(out, *byMap[sn])
	}
	sort.Slice(out, func(i, j int) bool { return out[i].IssuedAt > out[j].IssuedAt })
	return out
}

// Reachable — step-ca 평면1 도달성(`step ca health`).
func (a *StepCaAdapter) Reachable() bool {
	_, err := a.step("ca", "health", "--ca-url", a.url, "--root", a.root)
	return err == nil
}

func (a *StepCaAdapter) GetCertStatus(serial string) (CertRecord, bool) {
	for _, r := range a.ListCerts() {
		if strings.EqualFold(r.Serial, serial) {
			return r, true
		}
	}
	return CertRecord{}, false
}

func parseLeaf(certPEM []byte) (*x509.Certificate, error) {
	b, _ := pem.Decode(certPEM)
	if b == nil {
		return nil, fmt.Errorf("cert PEM 디코드 실패")
	}
	return x509.ParseCertificate(b.Bytes)
}

// ---------- 핸들러 (평면 2·3) ----------

func (s *Server) caEnabled() bool { return s.ca != nil }

// GET /api/ca/info — CA 신뢰 앵커 요약 + step-ca 도달성 + 프로파일 목록.
func (s *Server) apiCAInfo(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 200, map[string]any{"enabled": false})
		return
	}
	info := map[string]any{"enabled": true, "url": s.cfg.StepCaURL, "provisioner": s.cfg.StepCaProvisioner,
		"profiles": s.cfg.Profiles}
	if root, err := os.ReadFile(s.cfg.StepCaRoot); err == nil {
		if leaf, err := parseLeaf(root); err == nil {
			info["rootSubject"] = leaf.Subject.String()
			info["rootNotAfter"] = leaf.NotAfter.UTC().Format(time.RFC3339)
			sum := sha256.Sum256(leaf.Raw)
			info["rootFingerprint"] = hex.EncodeToString(sum[:])
		}
	}
	info["reachable"] = s.ca.Reachable()
	writeJSON(w, 200, info)
}

// GET /api/ca/certs — 발급 인증서 목록(SoR).
func (s *Server) apiCACerts(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	all := s.ca.ListCerts()
	page, size := pageParams(r, 20)
	writeJSON(w, 200, map[string]any{"certs": pageSlice(all, page, size), "total": len(all), "page": page, "pageSize": size})
}

// GET /api/ca/audit — SoR 감사 이벤트(최신순) + 해시체인 검증 결과.
func (s *Server) apiCAAudit(w http.ResponseWriter, r *http.Request) {
	evs, err := s.sor.list()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	vr, _ := s.sor.verify()
	for i, j := 0, len(evs)-1; i < j; i, j = i+1, j-1 {
		evs[i], evs[j] = evs[j], evs[i]
	}
	page, size := pageParams(r, 20)
	writeJSON(w, 200, map[string]any{"events": pageSlice(evs, page, size), "integrity": vr, "total": len(evs), "page": page, "pageSize": size})
}

// GET /api/ca/audit/verify — 감사 해시체인 무결성 검증(변조 탐지).
func (s *Server) apiCAAuditVerify(w http.ResponseWriter, r *http.Request) {
	vr, err := s.sor.verify()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, vr)
}

// GET /api/ca/crl — CRL(평면1) 패스스루.
func (s *Server) apiCACRL(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	crl, err := s.ca.GetCRL()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/pkix-crl")
	w.Header().Set("Content-Disposition", "attachment; filename=bigfoot.crl")
	w.Write(crl)
}

// GET /api/ca/crl/info — CRL 의 lastUpdate/nextUpdate 파싱(즉시성 가시화, P2-3).
//
//	nextUpdate 까지의 간격이 폐기 반영 지연의 상한 → 운영자가 cacheDuration 정책을 판단.
func (s *Server) apiCACRLInfo(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	crl, err := s.ca.GetCRL()
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	p, err := writeTemp("bf-crl-*.der", crl)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	defer os.Remove(p)
	out, err := opensslRun("crl", "-inform", "DER", "-in", p, "-noout", "-lastupdate", "-nextupdate")
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	info := map[string]any{"sizeBytes": len(crl)}
	for _, line := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		if kv := strings.SplitN(strings.TrimSpace(line), "=", 2); len(kv) == 2 {
			switch kv[0] {
			case "lastUpdate":
				info["lastUpdate"] = kv[1]
			case "nextUpdate":
				info["nextUpdate"] = kv[1]
			}
		}
	}
	writeJSON(w, 200, info)
}

func (s *Server) serveCertFile(w http.ResponseWriter, path, filename string) {
	pemBytes, err := os.ReadFile(path)
	if err != nil {
		writeJSON(w, 404, map[string]string{"error": "인증서 파일 없음: " + err.Error()})
		return
	}
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.Header().Set("Content-Disposition", "attachment; filename="+filename)
	w.Write(pemBytes)
}

// GET /api/ca/root — 최상위(Root) 인증서 PEM 다운로드. 수신자가 사전 신뢰할 신뢰 앵커.
func (s *Server) apiCARoot(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	s.serveCertFile(w, s.cfg.StepCaRoot, "bigfoot-root.crt")
}

// GET /api/ca/issuer — 발급(중간) CA 인증서 PEM 다운로드.
func (s *Server) apiCAIssuer(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	s.serveCertFile(w, s.cfg.StepCaIssuer, "bigfoot-issuer.crt")
}

// POST /api/ca/issue {profile, cn, sans[], notAfter} — 발급(쓰기). 개인키는 응답에 싣지 않는다.
func (s *Server) apiCAIssue(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	if s.cfg.EnforceApproval {
		writeJSON(w, 403, map[string]string{"error": "승인 워크플로 필요(ENFORCE_APPROVAL): POST /api/approvals 사용"})
		return
	}
	var in struct {
		Profile  string   `json:"profile"`
		CN       string   `json:"cn"`
		SANs     []string `json:"sans"`
		NotAfter string   `json:"notAfter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.CN == "" {
		writeJSON(w, 400, map[string]string{"error": "cn 필수"})
		return
	}
	ic, err := s.ca.IssueCert(actorOf(r), in.Profile, in.CN, in.SANs, in.NotAfter)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"serial": ic.Serial, "subject": ic.Subject, "profile": ic.Profile,
		"notAfter": ic.NotAfter.UTC().Format(time.RFC3339),
	})
}

// POST /api/ca/sign-csr {profile, csr, notAfter} — 고객 CSR 서명(고객이 개인키 보유).
func (s *Server) apiCASignCSR(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	var in struct {
		Profile  string `json:"profile"`
		CSR      string `json:"csr"`
		NotAfter string `json:"notAfter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || !strings.Contains(in.CSR, "CERTIFICATE REQUEST") {
		writeJSON(w, 400, map[string]string{"error": "PEM CSR 필수"})
		return
	}
	ic, err := s.ca.SignCSR(actorOf(r), in.Profile, []byte(in.CSR), in.NotAfter)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"serial": ic.Serial, "subject": ic.Subject, "profile": ic.Profile,
		"notAfter": ic.NotAfter.UTC().Format(time.RFC3339),
		"cert":     string(ic.CertPEM),
	})
}

// POST /api/ca/revoke {serial, reason} — 폐기(고가치 쓰기).
func (s *Server) apiCARevoke(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	if s.cfg.EnforceApproval {
		writeJSON(w, 403, map[string]string{"error": "승인 워크플로 필요(ENFORCE_APPROVAL): POST /api/approvals 사용"})
		return
	}
	var in struct{ Serial, Reason string }
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Serial == "" {
		writeJSON(w, 400, map[string]string{"error": "serial 필수"})
		return
	}
	if err := s.ca.RevokeCert(actorOf(r), in.Serial, in.Reason); err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{"status": "revoked", "serial": in.Serial})
}

// POST /api/ca/reissue {serial, notAfter} — 동일 주체(CN)로 신규 발급(짧은수명 재발급 전략).
func (s *Server) apiCAReissue(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	var in struct {
		Serial   string `json:"serial"`
		NotAfter string `json:"notAfter"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Serial == "" {
		writeJSON(w, 400, map[string]string{"error": "serial 필수"})
		return
	}
	rec, ok := s.ca.GetCertStatus(in.Serial)
	if !ok {
		writeJSON(w, 404, map[string]string{"error": "원본 인증서 기록 없음"})
		return
	}
	cn := strings.TrimPrefix(rec.Subject, "CN=")
	if i := strings.Index(cn, ","); i >= 0 {
		cn = cn[:i]
	}
	ic, err := s.ca.IssueCert(actorOf(r), rec.Profile, cn, nil, in.NotAfter)
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": err.Error()})
		return
	}
	writeJSON(w, 200, map[string]any{
		"status": "reissued", "from": in.Serial, "serial": ic.Serial,
		"subject": ic.Subject, "notAfter": ic.NotAfter.UTC().Format(time.RFC3339),
	})
}

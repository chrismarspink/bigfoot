package main

// 범용 파일 전자서명 API (P0-4) — Bigfoot 의 핵심 차별점.
//   POST /api/sign     : 파일 바이트 → codesign 단명 인증서 발급 → CMS SignedData(.p7s)
//   POST /api/verify   : .p7s(DER) → 신뢰 앵커로 검증 + 원문 추출
//   POST /api/encrypt  : 파일 바이트 → (서명) → 수신자 인증서로 암호화(.p7m, EnvelopedData)
//
// 서명 개인키는 매 요청 새로 발급되는 단명 리프의 것으로, 서버 밖으로 나가지 않는다.
// 검증자는 Bigfoot/step-ca 없이 루트 인증서 하나로 .p7s/.p7m 을 검증·복호할 수 있다.

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"io"
	"net/http"
)

const maxSignBytes = 512 << 20 // 512MB 업로드 상한

// readLimited: 요청 본문을 상한까지 읽는다.
func readLimited(w http.ResponseWriter, r *http.Request) ([]byte, error) {
	r.Body = http.MaxBytesReader(w, r.Body, maxSignBytes)
	return io.ReadAll(r.Body)
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// POST /api/sign?cn=&profile=&notAfter=  (body = 서명할 파일 바이트)
// 응답: .p7s (DER, application/pkcs7-signature). 헤더에 서명 인증서 시리얼/FIPS 상태.
func (s *Server) apiSign(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	data, err := readLimited(w, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "본문 읽기 실패: " + err.Error()})
		return
	}
	if len(data) == 0 {
		writeJSON(w, 400, map[string]string{"error": "서명할 본문이 비어있습니다"})
		return
	}
	q := r.URL.Query()
	cn := q.Get("cn")
	if cn == "" {
		cn = "bigfoot-file-signer"
	}
	profile := q.Get("profile")
	if profile == "" {
		profile = "codesign"
	}
	actor := actorOf(r)
	ic, err := s.ca.IssueCert(actor, profile, cn, nil, q.Get("notAfter"))
	if err != nil {
		writeJSON(w, 502, map[string]string{"error": "서명 인증서 발급 실패: " + err.Error()})
		return
	}
	p7s, err := cmsSign(data, ic.CertPEM, ic.KeyPEM)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "CMS 서명 실패: " + err.Error()})
		return
	}
	fips, _ := fipsStatus()
	_ = s.sor.append(SoREvent{Actor: actor, Action: "sign", Serial: ic.Serial, Subject: ic.Subject, Profile: ic.Profile,
		Status: "signed", Detail: map[string]any{"contentSha256": sha256hex(data), "bytes": len(data), "fips": fips}})

	fn := q.Get("filename")
	if fn == "" {
		fn = "signed.p7s"
	}
	w.Header().Set("Content-Type", "application/pkcs7-signature")
	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("X-Bigfoot-Serial", ic.Serial)
	w.Header().Set("X-Bigfoot-Fips", fmt.Sprintf("%t", fips))
	w.Write(p7s)
}

// POST /api/verify  (body = .p7s DER). 신뢰 앵커(루트)로 검증 + 원문 다이제스트 반환.
func (s *Server) apiVerify(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	p7s, err := readLimited(w, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "본문 읽기 실패: " + err.Error()})
		return
	}
	ok, content, detail := cmsVerify(p7s, s.cfg.StepCaRoot)
	_ = s.sor.append(SoREvent{Actor: actorOf(r), Action: "verify",
		Status: map[bool]string{true: "valid", false: "invalid"}[ok], Detail: map[string]any{"detail": detail}})
	resp := map[string]any{"ok": ok, "detail": detail}
	if ok {
		resp["contentSha256"] = sha256hex(content)
		resp["contentBytes"] = len(content)
	}
	code := 200
	if !ok {
		code = 422
	}
	writeJSON(w, code, resp)
}

// POST /api/encrypt?recipient=<id>&recipient=<id>&cn=&sign=true  (body = 파일 바이트)
// 기본: 서명(SignedData) 후 수신자 인증서로 암호화(EnvelopedData) → .p7m.
// sign=false 면 암호화만. 수신자는 레지스트리에 임포트된 공개 인증서로 지정(지문 ID).
func (s *Server) apiEncrypt(w http.ResponseWriter, r *http.Request) {
	if !s.caEnabled() {
		writeJSON(w, 503, map[string]string{"error": "CA 미구성"})
		return
	}
	data, err := readLimited(w, r)
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "본문 읽기 실패: " + err.Error()})
		return
	}
	if len(data) == 0 {
		writeJSON(w, 400, map[string]string{"error": "본문이 비어있습니다"})
		return
	}
	q := r.URL.Query()
	ids := q["recipient"]
	if len(ids) == 0 {
		writeJSON(w, 400, map[string]string{"error": "recipient 지문 1개 이상 필요(수신자 레지스트리 ID)"})
		return
	}
	var recipPEMs [][]byte
	for _, id := range ids {
		rec, ok := s.recips.get(id)
		if !ok {
			writeJSON(w, 404, map[string]string{"error": "수신자 미등록: " + id})
			return
		}
		recipPEMs = append(recipPEMs, []byte(rec.CertPEM))
	}
	actor := actorOf(r)

	payload := data
	var signerSerial string
	if q.Get("sign") != "false" { // 기본 서명 후 암호화
		cn := q.Get("cn")
		if cn == "" {
			cn = "bigfoot-file-signer"
		}
		ic, err := s.ca.IssueCert(actor, "codesign", cn, nil, q.Get("notAfter"))
		if err != nil {
			writeJSON(w, 502, map[string]string{"error": "서명 인증서 발급 실패: " + err.Error()})
			return
		}
		p7s, err := cmsSign(data, ic.CertPEM, ic.KeyPEM)
		if err != nil {
			writeJSON(w, 500, map[string]string{"error": "CMS 서명 실패: " + err.Error()})
			return
		}
		payload = p7s
		signerSerial = ic.Serial
	}
	p7m, err := cmsEncrypt(payload, recipPEMs, s.cfg.CMSContentCipher, s.cfg.CMSRsaPadding)
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": "CMS 암호화 실패: " + err.Error()})
		return
	}
	fips, _ := fipsStatus()
	_ = s.sor.append(SoREvent{Actor: actor, Action: "encrypt", Serial: signerSerial, Status: "encrypted",
		Detail: map[string]any{"recipients": ids, "contentSha256": sha256hex(data), "signed": signerSerial != "", "fips": fips}})

	fn := q.Get("filename")
	if fn == "" {
		fn = "package.p7m"
	}
	w.Header().Set("Content-Type", "application/pkcs7-mime")
	w.Header().Set("Content-Disposition", "attachment; filename="+fn)
	w.Header().Set("X-Bigfoot-Fips", fmt.Sprintf("%t", fips))
	w.Write(p7m)
}

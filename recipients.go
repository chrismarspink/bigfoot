package main

// 수신자 인증서 레지스트리 — 외부 수신자의 공개 인증서를 임포트해 보관(CMS EnvelopedData 수신자).
// 수신자가 자체 PKI 로 발급받은 인증서를 등록 → 파일 암호화(/encrypt, .p7m) 시 수신자로 사용.
// 개인키는 보관하지 않는다(공개 인증서만). 단일 JSON 파일(락).

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	"os"
	"path/filepath"
	"sync"
	"time"
)

type Recipient struct {
	ID         string `json:"id"` // sha256(cert) fingerprint
	Subject    string `json:"subject"`
	NotAfter   string `json:"notAfter"`
	ImportedAt string `json:"importedAt"`
	ImportedBy string `json:"importedBy"`
	CertPEM    string `json:"certPem"`
}

type RecipientStore struct {
	mu   sync.Mutex
	path string
}

func newRecipientStore(path string) *RecipientStore { return &RecipientStore{path: path} }

func (s *RecipientStore) load() ([]Recipient, error) {
	b, err := os.ReadFile(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Recipient{}, nil
		}
		return nil, err
	}
	var rs []Recipient
	if json.Unmarshal(b, &rs) != nil {
		return []Recipient{}, nil
	}
	return rs, nil
}

func (s *RecipientStore) save(rs []Recipient) error {
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	b, _ := json.MarshalIndent(rs, "", "  ")
	return os.WriteFile(s.path, b, 0o640)
}

func (s *RecipientStore) list() ([]Recipient, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

// get: ID(지문)로 단건 조회.
func (s *RecipientStore) get(id string) (Recipient, bool) {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := s.load()
	if err != nil {
		return Recipient{}, false
	}
	for _, r := range rs {
		if r.ID == id {
			return r, true
		}
	}
	return Recipient{}, false
}

// add: ID(지문) 기준 덮어쓰기-또는-추가.
func (s *RecipientStore) add(r Recipient) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := s.load()
	if err != nil {
		return err
	}
	out := rs[:0]
	for _, x := range rs {
		if x.ID != r.ID {
			out = append(out, x)
		}
	}
	out = append(out, r)
	return s.save(out)
}

func (s *RecipientStore) del(id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	rs, err := s.load()
	if err != nil {
		return err
	}
	out := make([]Recipient, 0, len(rs))
	for _, x := range rs {
		if x.ID != id {
			out = append(out, x)
		}
	}
	return s.save(out)
}

// ---------- 핸들러 ----------

// GET /api/recipients — 수신자 인증서 목록.
func (s *Server) apiRecipientsList(w http.ResponseWriter, r *http.Request) {
	rs, err := s.recips.list()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	page, size := pageParams(r, 20)
	writeJSON(w, 200, map[string]any{"recipients": pageSlice(rs, page, size), "total": len(rs), "page": page, "pageSize": size})
}

// POST /api/recipients {cert} — 외부 수신자 공개 인증서 임포트(파싱·검증 후 저장).
func (s *Server) apiRecipientImport(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Cert string `json:"cert"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || in.Cert == "" {
		writeJSON(w, 400, map[string]string{"error": "PEM 인증서 필수"})
		return
	}
	leaf, err := parseLeaf([]byte(in.Cert))
	if err != nil {
		writeJSON(w, 400, map[string]string{"error": "인증서 파싱 실패: " + err.Error()})
		return
	}
	sum := sha256.Sum256(leaf.Raw)
	fp := hex.EncodeToString(sum[:])
	actor := actorOf(r)
	rec := Recipient{
		ID: fp, Subject: leaf.Subject.String(), NotAfter: leaf.NotAfter.UTC().Format(time.RFC3339),
		ImportedAt: time.Now().UTC().Format(time.RFC3339), ImportedBy: actor, CertPEM: in.Cert,
	}
	if err := s.recips.add(rec); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: actor, Action: "recipient-import", Subject: rec.Subject,
		Status: "imported", Detail: map[string]any{"fingerprint": fp}})
	writeJSON(w, 200, map[string]any{"id": fp, "subject": rec.Subject, "notAfter": rec.NotAfter})
}

// DELETE /api/recipients/{id} — 수신자 삭제.
func (s *Server) apiRecipientDelete(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	if id == "" {
		writeJSON(w, 400, map[string]string{"error": "id 필수"})
		return
	}
	if err := s.recips.del(id); err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: actorOf(r), Action: "recipient-delete", Status: "deleted", Detail: map[string]any{"fingerprint": id}})
	writeJSON(w, 200, map[string]any{"status": "deleted", "id": id})
}

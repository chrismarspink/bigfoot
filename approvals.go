package main

// 승인 워크플로 (P2-2) — 4-eyes. 발급/폐기를 요청(request)→승인(approve) 2단계로 분리한다.
//   불변 규칙: 요청자 ≠ 승인자. 승인 시점에 실제 발급/폐기를 실행하고 결과를 기록한다.
//   인증 미도입 단계에서는 actorOf(X-User 헤더)로 신원을 구분한다 → 인증 도입 시
//   자동으로 "검증된 서로 다른 두 신원" 강제로 승격(AUTH-PLAN.md §5).
//
// ENFORCE_APPROVAL=true 이면 직접 /api/ca/issue·/revoke 가 차단되고 이 경로만 허용된다.

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"sync"
	"time"
)

type Approval struct {
	ID          string         `json:"id"`
	Action      string         `json:"action"` // issue | revoke
	Params      map[string]any `json:"params"`
	Requester   string         `json:"requester"`
	RequestedAt string         `json:"requestedAt"`
	Status      string         `json:"status"` // pending | executed | rejected
	Decider     string         `json:"decider,omitempty"`
	DecidedAt   string         `json:"decidedAt,omitempty"`
	Result      map[string]any `json:"result,omitempty"`
	Note        string         `json:"note,omitempty"`
}

type ApprovalStore struct {
	mu   sync.Mutex
	path string
}

func newApprovalStore(path string) *ApprovalStore { return &ApprovalStore{path: path} }

func (s *ApprovalStore) load() ([]Approval, error) {
	b, err := readFileOrEmpty(s.path)
	if err != nil {
		return nil, err
	}
	if len(b) == 0 {
		return []Approval{}, nil
	}
	var as []Approval
	if json.Unmarshal(b, &as) != nil {
		return []Approval{}, nil
	}
	return as, nil
}

func (s *ApprovalStore) list() ([]Approval, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.load()
}

func (s *ApprovalStore) save(as []Approval) error {
	b, _ := json.MarshalIndent(as, "", "  ")
	return writeFileAtomic(s.path, b)
}

func newID() string {
	var b [8]byte
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}

// ---------- 핸들러 ----------

// POST /api/approvals {action, params} — 발급/폐기 요청 생성(요청자=actor).
func (s *Server) apiApprovalCreate(w http.ResponseWriter, r *http.Request) {
	var in struct {
		Action string         `json:"action"`
		Params map[string]any `json:"params"`
	}
	if err := json.NewDecoder(r.Body).Decode(&in); err != nil || (in.Action != "issue" && in.Action != "revoke") {
		writeJSON(w, 400, map[string]string{"error": "action 은 issue|revoke"})
		return
	}
	a := Approval{
		ID: newID(), Action: in.Action, Params: in.Params, Requester: actorOf(r),
		RequestedAt: time.Now().UTC().Format(time.RFC3339), Status: "pending",
	}
	s.appr.mu.Lock()
	as, err := s.appr.load()
	if err == nil {
		as = append(as, a)
		err = s.appr.save(as)
	}
	s.appr.mu.Unlock()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: a.Requester, Action: "request", Status: "pending",
		Detail: map[string]any{"approvalId": a.ID, "request": in.Action, "params": in.Params}})
	writeJSON(w, 200, a)
}

// GET /api/approvals — 요청 목록(최신순).
func (s *Server) apiApprovalList(w http.ResponseWriter, r *http.Request) {
	as, err := s.appr.list()
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	for i, j := 0, len(as)-1; i < j; i, j = i+1, j-1 {
		as[i], as[j] = as[j], as[i]
	}
	writeJSON(w, 200, map[string]any{"approvals": as, "enforce": s.cfg.EnforceApproval})
}

// POST /api/approvals/{id}/approve — 승인+실행. 요청자≠승인자 강제.
func (s *Server) apiApprovalApprove(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	decider := actorOf(r)

	s.appr.mu.Lock()
	as, err := s.appr.load()
	if err != nil {
		s.appr.mu.Unlock()
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	idx := -1
	for i := range as {
		if as[i].ID == id {
			idx = i
			break
		}
	}
	if idx < 0 {
		s.appr.mu.Unlock()
		writeJSON(w, 404, map[string]string{"error": "요청 없음"})
		return
	}
	a := as[idx]
	if a.Status != "pending" {
		s.appr.mu.Unlock()
		writeJSON(w, 409, map[string]string{"error": "이미 처리됨: " + a.Status})
		return
	}
	// 4-eyes: 요청자와 승인자가 같으면 거부(fail-closed).
	if decider == a.Requester {
		s.appr.mu.Unlock()
		writeJSON(w, 403, map[string]string{"error": "요청자와 승인자가 동일할 수 없습니다(4-eyes)"})
		return
	}
	s.appr.mu.Unlock() // 실행(CA 호출)은 락 밖에서

	result, execErr := s.executeApproval(decider, a)
	if execErr != nil {
		writeJSON(w, 502, map[string]string{"error": "실행 실패: " + execErr.Error()})
		return
	}

	s.appr.mu.Lock()
	as, _ = s.appr.load()
	for i := range as {
		if as[i].ID == id {
			as[i].Status = "executed"
			as[i].Decider = decider
			as[i].DecidedAt = time.Now().UTC().Format(time.RFC3339)
			as[i].Result = result
		}
	}
	_ = s.appr.save(as)
	s.appr.mu.Unlock()

	_ = s.sor.append(SoREvent{Actor: decider, Action: "approve", Status: "executed",
		Detail: map[string]any{"approvalId": id, "requester": a.Requester, "request": a.Action, "result": result}})
	writeJSON(w, 200, map[string]any{"status": "executed", "id": id, "result": result})
}

// POST /api/approvals/{id}/reject {note} — 반려.
func (s *Server) apiApprovalReject(w http.ResponseWriter, r *http.Request) {
	id := r.PathValue("id")
	var in struct {
		Note string `json:"note"`
	}
	_ = json.NewDecoder(r.Body).Decode(&in)
	decider := actorOf(r)
	s.appr.mu.Lock()
	as, err := s.appr.load()
	if err != nil {
		s.appr.mu.Unlock()
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	found := false
	for i := range as {
		if as[i].ID == id && as[i].Status == "pending" {
			as[i].Status = "rejected"
			as[i].Decider = decider
			as[i].DecidedAt = time.Now().UTC().Format(time.RFC3339)
			as[i].Note = in.Note
			found = true
		}
	}
	if found {
		err = s.appr.save(as)
	}
	s.appr.mu.Unlock()
	if !found {
		writeJSON(w, 404, map[string]string{"error": "대기중 요청 없음"})
		return
	}
	if err != nil {
		writeJSON(w, 500, map[string]string{"error": err.Error()})
		return
	}
	_ = s.sor.append(SoREvent{Actor: decider, Action: "reject", Status: "rejected",
		Detail: map[string]any{"approvalId": id, "note": in.Note}})
	writeJSON(w, 200, map[string]any{"status": "rejected", "id": id})
}

// executeApproval — 승인된 요청을 실제 CA 동작으로 실행.
func (s *Server) executeApproval(decider string, a Approval) (map[string]any, error) {
	str := func(k string) string {
		if v, ok := a.Params[k].(string); ok {
			return v
		}
		return ""
	}
	switch a.Action {
	case "issue":
		var sans []string
		if raw, ok := a.Params["sans"].([]any); ok {
			for _, x := range raw {
				if sx, ok := x.(string); ok {
					sans = append(sans, sx)
				}
			}
		}
		ic, err := s.ca.IssueCert(decider, str("profile"), str("cn"), sans, str("notAfter"))
		if err != nil {
			return nil, err
		}
		return map[string]any{"serial": ic.Serial, "subject": ic.Subject, "profile": ic.Profile,
			"notAfter": ic.NotAfter.UTC().Format(time.RFC3339)}, nil
	case "revoke":
		if err := s.ca.RevokeCert(decider, str("serial"), str("reason")); err != nil {
			return nil, err
		}
		return map[string]any{"revoked": str("serial")}, nil
	}
	return nil, fmt.Errorf("알 수 없는 action: %s", a.Action)
}

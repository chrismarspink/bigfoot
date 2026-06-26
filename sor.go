package main

// SoR (System of Record) — 발급·폐기·서명·승인 행위의 append-only 감사 기록.
// 변조 탐지(tamper-evident): 각 이벤트는 직전 이벤트 해시를 체인으로 묶는다(P0-6).
//   hash(n) = sha256( prevHash(n) || canonicalJSON(event without hash fields) )
// 외부 의존성 없이 stdlib 만 사용. JSONL 파일에 한 줄씩 추가(파일 락 + fsync).

import (
	"bufio"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sync"
	"time"
)

// SoREvent — 한 건의 감사 이벤트.
// action: issue|revoke|reissue|sign|verify|encrypt|recipient-import|recipient-delete|approve|request
type SoREvent struct {
	Seq      int64          `json:"seq"`
	Time     string         `json:"time"`
	Actor    string         `json:"actor"`
	Action   string         `json:"action"`
	Serial   string         `json:"serial,omitempty"`
	Subject  string         `json:"subject,omitempty"`
	Profile  string         `json:"profile,omitempty"`
	NotAfter string         `json:"notAfter,omitempty"`
	Status   string         `json:"status,omitempty"`
	Detail   map[string]any `json:"detail,omitempty"`
	// 해시체인(변조 탐지). canonical 계산 시 이 두 필드는 제외하고, PrevHash 는 별도로 섞는다.
	PrevHash string `json:"prevHash,omitempty"`
	Hash     string `json:"hash,omitempty"`
}

type SoR struct {
	mu       sync.Mutex
	path     string
	lastHash string
	lastSeq  int64
	loaded   bool
}

func newSoR(path string) *SoR { return &SoR{path: path} }

// canonical: Hash/PrevHash 를 비운 이벤트의 결정적 JSON. 체인 계산 입력.
func (ev SoREvent) canonical() []byte {
	ev.Hash = ""
	ev.PrevHash = ""
	b, _ := json.Marshal(ev)
	return b
}

func chainHash(prevHash string, ev SoREvent) string {
	h := sha256.New()
	h.Write([]byte(prevHash))
	h.Write(ev.canonical())
	return hex.EncodeToString(h.Sum(nil))
}

// loadState: 파일을 한 번 스캔해 마지막 해시/seq 를 복원(append 시 체인 연결용).
func (s *SoR) loadState() error {
	if s.loaded {
		return nil
	}
	evs, err := s.readAll()
	if err != nil {
		return err
	}
	if n := len(evs); n > 0 {
		s.lastHash = evs[n-1].Hash
		s.lastSeq = evs[n-1].Seq
	}
	s.loaded = true
	return nil
}

// append: 이벤트 1건을 체인에 연결해 JSONL 로 추가(생성·append·fsync).
func (s *SoR) append(ev SoREvent) error {
	if ev.Time == "" {
		ev.Time = time.Now().UTC().Format(time.RFC3339)
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.loadState(); err != nil {
		return err
	}
	ev.Seq = s.lastSeq + 1
	ev.PrevHash = s.lastHash
	ev.Hash = chainHash(s.lastHash, ev)

	line, err := json.Marshal(ev)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(s.path), 0o750); err != nil {
		return err
	}
	f, err := os.OpenFile(s.path, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o640)
	if err != nil {
		return err
	}
	defer f.Close()
	if _, err := f.Write(append(line, '\n')); err != nil {
		return err
	}
	if err := f.Sync(); err != nil {
		return err
	}
	s.lastHash = ev.Hash
	s.lastSeq = ev.Seq
	return nil
}

// readAll: 파일에서 전체 이벤트(시간순). 파일 없으면 빈 슬라이스.
func (s *SoR) readAll() ([]SoREvent, error) {
	f, err := os.Open(s.path)
	if err != nil {
		if os.IsNotExist(err) {
			return []SoREvent{}, nil
		}
		return nil, err
	}
	defer f.Close()
	var out []SoREvent
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	for sc.Scan() {
		b := sc.Bytes()
		if len(b) == 0 {
			continue
		}
		var ev SoREvent
		if json.Unmarshal(b, &ev) == nil {
			out = append(out, ev)
		}
	}
	return out, sc.Err()
}

// list: 전체 이벤트(시간순).
func (s *SoR) list() ([]SoREvent, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.readAll()
}

// VerifyResult — 해시체인 검증 결과.
type VerifyResult struct {
	OK       bool   `json:"ok"`
	Count    int    `json:"count"`
	BrokenAt int64  `json:"brokenAt,omitempty"` // 최초 불일치 seq (0=없음)
	Detail   string `json:"detail"`
	HeadHash string `json:"headHash,omitempty"`
}

// verify: 처음부터 해시체인을 재계산해 변조 여부 확인(P0-6 핵심).
func (s *SoR) verify() (VerifyResult, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	evs, err := s.readAll()
	if err != nil {
		return VerifyResult{}, err
	}
	prev := ""
	for _, ev := range evs {
		want := chainHash(prev, ev)
		if ev.PrevHash != prev || ev.Hash != want {
			return VerifyResult{OK: false, Count: len(evs), BrokenAt: ev.Seq,
				Detail: fmt.Sprintf("seq=%d 해시 불일치(변조 의심)", ev.Seq)}, nil
		}
		prev = ev.Hash
	}
	return VerifyResult{OK: true, Count: len(evs), Detail: "감사 해시체인 무결(변조 없음)", HeadHash: prev}, nil
}

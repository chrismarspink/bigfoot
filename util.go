package main

import (
	"net/http"
	"os"
	"path/filepath"
	"strconv"
)

// pageParams: ?page=(1-based)&pageSize= 파싱. 기본 size=def, 상한 200.
func pageParams(r *http.Request, def int) (page, size int) {
	page, _ = strconv.Atoi(r.URL.Query().Get("page"))
	if page < 1 {
		page = 1
	}
	size, _ = strconv.Atoi(r.URL.Query().Get("pageSize"))
	if size < 1 {
		size = def
	}
	if size > 200 {
		size = 200
	}
	return
}

// pageSlice: items 에서 page/size 구간 반환(범위 밖이면 빈 슬라이스, nil 아님).
func pageSlice[T any](items []T, page, size int) []T {
	start := (page - 1) * size
	if start >= len(items) {
		return []T{}
	}
	end := start + size
	if end > len(items) {
		end = len(items)
	}
	return items[start:end]
}

// readFileOrEmpty: 파일을 읽되 없으면 빈 바이트(에러 아님).
func readFileOrEmpty(path string) ([]byte, error) {
	b, err := os.ReadFile(path)
	if os.IsNotExist(err) {
		return nil, nil
	}
	return b, err
}

// writeFileAtomic: 임시파일에 쓴 뒤 rename(원자적 교체). 디렉터리 자동 생성.
func writeFileAtomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0o750); err != nil {
		return err
	}
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, data, 0o640); err != nil {
		return err
	}
	return os.Rename(tmp, path)
}

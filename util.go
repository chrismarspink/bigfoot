package main

import (
	"os"
	"path/filepath"
)

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

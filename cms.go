package main

// CMS (RFC 5652) 서명/검증/암호화 모듈 — OpenSSL `cms` 명령 호출.
//   서명: SignedData(opaque, DER). 임의 파일/바이트 → .p7s.
//   검증: 신뢰 앵커(루트)로 체인 검증 + 원문 추출.
//   암호화: EnvelopedData(.p7m). 수신자 공개 인증서로 키 전송 + 대칭 콘텐츠 암호.
// FIPS: 실행 OpenSSL 의 provider 목록에서 fips 활성 여부를 탐지·기록(P1 에서 검증 OE 전환).
//   ("FIPS 모드 켜짐 ≠ FIPS 검증" — 검증 모듈 OE 는 배포 시점 사안.)
// 비고: codeSigning EKU 리프는 `cms -verify` 기본 smime purpose 를 거부 → `-purpose any` 사용.

import (
	"context"
	"encoding/pem"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"time"
)

func opensslRun(args ...string) ([]byte, error) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	out, err := exec.CommandContext(ctx, "openssl", args...).CombinedOutput()
	if err != nil {
		return out, fmt.Errorf("openssl %s: %v: %s", strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return out, nil
}

// fipsStatus: openssl provider 목록에 fips 가 있으면 활성으로 간주.
func fipsStatus() (active bool, detail string) {
	out, err := opensslRun("list", "-providers")
	if err != nil {
		return false, "provider 조회 실패: " + err.Error()
	}
	if strings.Contains(strings.ToLower(string(out)), "fips") {
		return true, "OpenSSL FIPS provider 활성"
	}
	return false, "default provider (FIPS 검증 모듈 미적용 — 배포 OE 에서 fips provider 구성 필요, P1)"
}

// splitLeafChain: PEM 인증서 묶음에서 첫 블록(서명자) / 나머지(중간 체인) 분리.
func splitLeafChain(certPEM []byte) (leaf, chain []byte) {
	rest := certPEM
	first := true
	for {
		b, r := pem.Decode(rest)
		if b == nil {
			break
		}
		rest = r
		enc := pem.EncodeToMemory(b)
		if first {
			leaf = enc
			first = false
		} else {
			chain = append(chain, enc...)
		}
	}
	if leaf == nil {
		leaf = certPEM
	}
	return leaf, chain
}

func writeTemp(prefix string, data []byte) (string, error) {
	f, err := os.CreateTemp("", prefix)
	if err != nil {
		return "", err
	}
	defer f.Close()
	if data != nil {
		if _, err := f.Write(data); err != nil {
			os.Remove(f.Name())
			return "", err
		}
	}
	return f.Name(), nil
}

// cmsSign: SignedData(opaque, DER). certPEM=leaf(+중간체인), keyPEM=개인키, data=서명 대상.
// 중간 인증서는 -certfile 로 CMS 에 임베드해야 수신자가 루트만으로 체인 검증 가능.
func cmsSign(data, certPEM, keyPEM []byte) ([]byte, error) {
	leaf, chain := splitLeafChain(certPEM)
	inPath, err := writeTemp("bf-cms-in-*", data)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	signerPath, err := writeTemp("bf-cms-signer-*", leaf)
	if err != nil {
		return nil, err
	}
	defer os.Remove(signerPath)
	keyPath, err := writeTemp("bf-cms-key-*", keyPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyPath)
	outPath, err := writeTemp("bf-cms-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)

	args := []string{"cms", "-sign", "-binary", "-nodetach", "-in", inPath,
		"-signer", signerPath, "-inkey", keyPath, "-outform", "DER", "-out", outPath}
	if len(chain) > 0 {
		chainPath, err := writeTemp("bf-cms-chain-*", chain)
		if err != nil {
			return nil, err
		}
		defer os.Remove(chainPath)
		args = append(args, "-certfile", chainPath)
	}
	if _, err := opensslRun(args...); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsEncrypt: EnvelopedData(또는 AEAD 시 AuthEnvelopedData) 로 content 를 수신자 인증서들에게 암호화.
//
//	콘텐츠 암호화 = 대칭(기본 AES-256-GCM), 키 전송 = 수신자 RSA 공개키(기본 OAEP). 둘 다 FIPS 승인.
func cmsEncrypt(content []byte, recipientCertsPEM [][]byte, cipher, rsaPad string) ([]byte, error) {
	if len(recipientCertsPEM) == 0 {
		return nil, fmt.Errorf("수신자 인증서가 없습니다")
	}
	inPath, err := writeTemp("bf-enc-in-*", content)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	outPath, err := writeTemp("bf-enc-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)

	if cipher == "" {
		cipher = "-aes-256-gcm"
	}
	args := []string{"cms", "-encrypt", "-binary", cipher, "-in", inPath, "-outform", "DER", "-out", outPath}
	for i, certPEM := range recipientCertsPEM {
		certPath, err := writeTemp(fmt.Sprintf("bf-enc-recip%d-*", i), certPEM)
		if err != nil {
			return nil, err
		}
		defer os.Remove(certPath)
		args = append(args, "-recip", certPath)
		if rsaPad != "" && rsaPad != "pkcs1" {
			args = append(args, "-keyopt", "rsa_padding_mode:"+rsaPad)
		}
	}
	if _, err := opensslRun(args...); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsDecrypt: EnvelopedData 복호(라운드트립 검증·테스트용). 수신자 개인키 필요.
func cmsDecrypt(p7mDER, recipCertPEM, recipKeyPEM []byte) ([]byte, error) {
	inPath, err := writeTemp("bf-dec-in-*", p7mDER)
	if err != nil {
		return nil, err
	}
	defer os.Remove(inPath)
	certPath, err := writeTemp("bf-dec-cert-*", recipCertPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(certPath)
	keyPath, err := writeTemp("bf-dec-key-*", recipKeyPEM)
	if err != nil {
		return nil, err
	}
	defer os.Remove(keyPath)
	outPath, err := writeTemp("bf-dec-out-*", nil)
	if err != nil {
		return nil, err
	}
	defer os.Remove(outPath)
	if _, err := opensslRun("cms", "-decrypt", "-inform", "DER", "-in", inPath,
		"-recip", certPath, "-inkey", keyPath, "-out", outPath); err != nil {
		return nil, err
	}
	return os.ReadFile(outPath)
}

// cmsVerify: 신뢰 앵커(rootPath)로 SignedData 검증 + 원문 추출. ok=false 면 detail 에 사유.
func cmsVerify(p7sDER []byte, rootPath string) (ok bool, content []byte, detail string) {
	inPath, err := writeTemp("bf-cmsv-in-*", p7sDER)
	if err != nil {
		return false, nil, err.Error()
	}
	defer os.Remove(inPath)
	outPath, err := writeTemp("bf-cmsv-out-*", nil)
	if err != nil {
		return false, nil, err.Error()
	}
	defer os.Remove(outPath)
	out, err := opensslRun("cms", "-verify", "-inform", "DER", "-in", inPath,
		"-CAfile", rootPath, "-purpose", "any", "-out", outPath)
	if err != nil {
		return false, nil, strings.TrimSpace(string(out))
	}
	content, _ = os.ReadFile(outPath)
	return true, content, "CMS 검증 성공"
}

package main

// 인증서 프로파일(EKU) — 범용 CA 포지셔닝의 핵심(P0-3).
//   tls       : serverAuth  — 서버/디바이스 TLS 인증서
//   client    : clientAuth  — mTLS 클라이언트 인증서
//   codesign  : codeSigning — 코드/파일 전자서명용 (파일 배포 서명의 EKU)
//
// step-ca 는 provisioner 에 연결된 certificate template 으로 EKU 를 결정한다.
// 따라서 각 프로파일은 "EKU 템플릿이 설정된 provisioner 이름"에 매핑된다.
//   - 운영(P0-9 deploy): step-ca ca.json 의 provisioner 별 x509 template 으로 EKU 부여.
//   - 미설정 프로파일은 기본 provisioner(serverAuth+clientAuth)로 폴백.
//
// 주의: codeSigning EKU 리프는 `openssl cms -verify` 의 기본 smime purpose 를 통과하지 못해
//   검증 시 `-purpose any` 를 쓴다(cms.go). EKU 자체는 codeSigning 으로 정확히 부여된다.

import "fmt"

// CertProfile — 발급 시 적용할 키/수명/provisioner(=EKU 템플릿) 묶음.
type CertProfile struct {
	Name        string `json:"name"`
	EKU         string `json:"eku"`         // 표시용: serverAuth | clientAuth | codeSigning
	Provisioner string `json:"provisioner"` // step-ca provisioner (EKU 템플릿 연결)
	DefaultDur  string `json:"defaultDur"`  // 기본 수명 (예: 24h, 8760h)
	KeyType     string `json:"keyType"`     // EC | RSA
	Curve       string `json:"curve"`       // EC 일 때 (P-256 등)
	Desc        string `json:"desc"`
}

// defaultProfiles: env 미설정 시 사용할 표준 프로파일 3종.
// Provisioner 는 deploy 에서 step-ca 에 동명 provisioner+EKU 템플릿을 만들어 둔다(P0-9).
// 기본 provisioner 이름은 cfg.StepCaProvisioner 로 폴백(여기선 placeholder).
func defaultProfiles(base string) map[string]CertProfile {
	return map[string]CertProfile{
		"tls": {
			Name: "tls", EKU: "serverAuth", Provisioner: base,
			DefaultDur: "8760h", KeyType: "EC", Curve: "P-256",
			Desc: "서버/디바이스 TLS 인증서 (serverAuth)",
		},
		"client": {
			Name: "client", EKU: "clientAuth", Provisioner: base,
			DefaultDur: "8760h", KeyType: "EC", Curve: "P-256",
			Desc: "mTLS 클라이언트 인증서 (clientAuth)",
		},
		"codesign": {
			Name: "codesign", EKU: "codeSigning", Provisioner: base,
			DefaultDur: "24h", KeyType: "EC", Curve: "P-256",
			Desc: "코드/파일 전자서명 인증서 (codeSigning, 기본 단명 24h)",
		},
	}
}

// resolveProfile: 이름으로 프로파일 조회. 빈 이름은 codesign(서명 제품의 기본 용도).
func (c Config) resolveProfile(name string) (CertProfile, error) {
	if name == "" {
		name = "codesign"
	}
	p, ok := c.Profiles[name]
	if !ok {
		return CertProfile{}, fmt.Errorf("알 수 없는 프로파일 %q (가능: tls, client, codesign)", name)
	}
	if p.Provisioner == "" {
		p.Provisioner = c.StepCaProvisioner
	}
	return p, nil
}

func profileNames(m map[string]CertProfile) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

# Bigfoot CA 이미지 (평면2/3 제어 서비스).
#   openssl: CMS 서명/검증/암호화. step: step-ca 연동(소스 무수정, CLI 호출).
#   UI/매뉴얼은 Go embed 로 바이너리에 내장된다(별도 COPY 불필요).
#   주의: 현재 alpine(musl) = FIPS 미검증 OE. 검증 OE 전환(RHEL UBI/Ubuntu Pro FIPS)은 P1.
FROM smallstep/step-cli:latest AS stepcli
FROM alpine:3.20
RUN apk add --no-cache openssl ca-certificates
COPY --from=stepcli /usr/local/bin/step /usr/local/bin/step
COPY bigfoot-linux /usr/bin/bigfoot
ENTRYPOINT ["/usr/bin/bigfoot"]

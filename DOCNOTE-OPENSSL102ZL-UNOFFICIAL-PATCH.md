# DOCNOTE - OpenSSL 1.0.2zl Unofficial Security Hardening Patch

## Status

This repository is an unofficial OpenSSL 1.0.2zl hardening fork.

OpenSSL 1.0.2 is public-upstream EOL. This patchset is a best-effort source-level defensive hardening set and must not be described as an official OpenSSL 1.0.2zq release.

## Version Label

Expected version string after patch:

    OpenSSL 1.0.2zl-alsyundawy-u20260614

## Covered Areas

- ASN.1 primitive length guard for large attacker-controlled DER content.
- ASN1_mbstring_ncopy integer overflow guards.
- BIO_f_linebuffer short-write bounded copy.
- PKCS12_item_decrypt_d2i NULL OCTET STRING guard.
- PKCS7 digest attribute ASN1_TYPE validation.
- PKCS7_verify caller-owned BIO cleanup hardening.
- CMS PWRI RFC3211 unwrap length check.
- CMS PWRI stream-mode KEK cipher rejection.
- CMS password recipient optional KDF guard.
- Delta CRL missing CRL Number guard.
- CMS KARI malformed parameter guard.
- CMS KTRI malformed algorithm/OAEP parameter guard.
- RSA OAEP/MGF1 NULL digest defensive guards.
- CEK cleanup before KEKRI/PWRI key overwrite.

## Build Validation

Sanitizer build:

    make clean || true
    ./config no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \
      -g -O1 -fno-omit-frame-pointer \
      -fsanitize=address,undefined \
      -DOPENSSL_NO_HEARTBEATS
    make depend
    make -j"$(nproc)"
    make test

Production build:

    make clean || true
    ./config shared no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \
      -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
      -Wformat -Wformat-security \
      -DOPENSSL_NO_HEARTBEATS
    make depend
    make -j"$(nproc)"
    make test

## Manual Verification

    grep -R "ALSYUNDAWY-CVE-" crypto/asn1 crypto/bio crypto/cms crypto/pkcs7 crypto/pkcs12 crypto/x509 crypto/rsa
    grep -R "ALSYUNDAWY-HARDENING" crypto/cms

Verify PKCS7_verify cleanup:

    awk '
    /int PKCS7_verify\(/ {infunc=1}
    infunc {print NR ":" $0}
    /^}/ && infunc {infunc=0}
    ' crypto/pkcs7/pk7_smime.c | grep -E 'BIO_free_all\(p7bio\)|while \(p7bio != NULL && p7bio != indata\)|BIO_free\(p7bio\)'

Expected:

- No BIO_free_all(p7bio) inside PKCS7_verify().
- Safe cleanup loop exists.

## Rollback

    cp -a .openssl102zl-security-backup-YYYYMMDD-HHMMSS/* .

## Important Limitation

This patchset is not a substitute for migration to supported OpenSSL releases such as OpenSSL 3.0 LTS / 3.5 LTS / newer supported branches.

Use this only for legacy compatibility where migration is not immediately possible.

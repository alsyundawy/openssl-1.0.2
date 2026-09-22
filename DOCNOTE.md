# DOCNOTE - OpenSSL 1.0.2zr Unofficial Security Hardening Patch

## Author & Release Metadata

- **Original Authors**: The OpenSSL Project & Eric A. Young, Tim J. Hudson
- **Refactored & Maintained By**: alsyundawy (༺ Initial H ༻) <alsyundawy@gmail.com>
- **Website**: <https://www.alsyundawy.com>
- **GitHub**: <https://github.com/alsyundawy>
- **Location**: DKI Jakarta, Indonesia
- **Base Version**: `1.0.2zr`
- **Release Version**: `1.0.2zr-u20260825-rev3`
- **Release Date**: 2026-09-23
- **Changelog Reference**: [`CHANGELOG.md`](CHANGELOG.md)

---

## Status & Operational Scope

This repository is an **unofficial OpenSSL 1.0.2zr hardening distribution**.

Upstream public OpenSSL 1.0.2 reached End-of-Life (EOL) on December 31, 2019. Subsequent maintenance releases (1.0.2v through 1.0.2zr) are commercially restricted Extended Support versions maintained by the OpenSSL Project for enterprise contracts. This community project provides independent, clean-room source-level security patches backported to open source trees, ensuring legacy systems can mitigate documented vulnerabilities without commercial licensing barriers.

Expected runtime version string after patching:

```text
OpenSSL 1.0.2zr-alsyundawy-u20260825  25 Aug 2026
```

> [!IMPORTANT]
> This distribution is not an official release from the OpenSSL Project. It is an independent security hardening patch engineered for compatibility with legacy systems unable to upgrade immediately to OpenSSL 3.0+ LTS or 3.5+ LTS.

---

## 1. Execution Environment & Behavior

- **Automated Source Engine**: Provided via idempotent shell engine (`patch.sh`) targeting OpenSSL 1.0.2 source trees.
- **Strict Shell Runtime**: Runs under strict execution invariants: `set -Eeuo pipefail` with `IFS=$'\n\t'`.
- **Sanitizer & Dry-Run Modes**: Supports non-destructive dry-run analysis (`DRY_RUN=1`) and automated AddressSanitizer/UndefinedBehaviorSanitizer validation builds (`DO_BUILD=1`).
- **Disaster Recovery Snapshots**: Automatically archives timestamped state into `.openssl102zr-security-backup-YYYYMMDD-HHMMSS/` before modifying any source tree asset.
- **ANSI C Standards Compliance**: Every patch strictly adheres to ANSI C (C89/C90), guaranteeing 100% binary interface (ABI) and API backward compatibility with legacy compiled binaries and shared libraries.

---

## 2. Technical Vulnerability Analysis & Hardening Details

### 2.1. DTLS Record Layer Memory Amplification (CVE-2026-54874)

- **Subsystem**: `ssl/d1_pkt.c` (`dtls1_buffer_record`)
- **Severity**: Low / Moderate DoS
- **Vulnerability Mechanism**: When processing out-of-order DTLS records from future epochs, the original implementation allocated a full `SSL3_BUFFER` (typically ~16 KB) for each buffered record, even if the actual record payload was only a few bytes. An unauthenticated attacker sending thousands of small future epoch records could induce an explosive heap amplification exceeding ~170 MB of unfreeable memory per connection.
- **Defensive Mitigation**:
  Instead of preserving full read buffers, the record buffering routine now calculates and allocates strictly the exact wire length of the record payload:

  ```c
  /* ALSYUNDAWY-CVE-2026-54874: allocate strictly wire-length record buffer */
  pque_wire_len = rrec->length;
  pitem = pitem_new(priority, rdata);
  ```

### 2.2. CMS KEK Unwrapping Buffer Overflow (CVE-2026-63072)

- **Subsystem**: `crypto/cms/cms_kari.c` (`cms_kek_unwrap`)
- **Severity**: Moderate
- **Vulnerability Mechanism**: In AES-WRAP-PAD key unwrapping routines, the output buffer was allocated based on internal expected key lengths without bounding against the input ciphertext length. Malformed ASN.1 structures could trigger heap buffer over-writes during PKCS#7 / CMS decryption.
- **Defensive Mitigation**:
  Allocates destination buffer strictly bounded by input ciphertext length:

  ```c
  /* ALSYUNDAWY-CVE-2026-63072: bounded allocation based on ciphertext length */
  outlen = inlen;
  out = OPENSSL_malloc(outlen);
  ```

### 2.3. PKCS#7 Verification Use-After-Free (CVE-2026-45447)

- **Subsystem**: `crypto/pkcs7/pk7_smime.c` (`PKCS7_verify`)
- **Severity**: High
- **Vulnerability Mechanism**: Calling `BIO_free_all(p7bio)` on error cascades down the entire BIO chain, inadvertently destroying the caller-owned input BIO (`indata`), leading to a heap use-after-free when the caller subsequently attempts to reuse or free its data pointer.
- **Defensive Mitigation**:
  Replaces `BIO_free_all` with a safe iterative traversal that terminates immediately upon reaching `indata`:

  ```c
  /* ALSYUNDAWY-CVE-2026-45447: terminate BIO traversal before caller-owned indata */
  while (p7bio != NULL && p7bio != indata) {
      BIO *next = BIO_pop(p7bio);
      BIO_free(p7bio);
      p7bio = next;
  }
  ```

### 2.4. ASN.1 Primitive Content & Multibyte Boundaries (CVE-2026-34180, CVE-2026-7383)

- **Subsystems**: `crypto/asn1/tasn_dec.c` and `crypto/asn1/a_mbstr.c`
- **Severity**: Low
- **Vulnerability Mechanism**: Integer wrapping and sign-extension when interpreting large primitive length tags, and multi-byte shift overflows when parsing UniversalString / BMPString representations.
- **Defensive Mitigation**:
  Enforces upper bounds against `INT_MAX` on primitive lengths and guards bitwise shift operations against values $\ge 32$.

### 2.5. CMS Password-Based Encryption Bounds Checks (CVE-2026-9076, CVE-2026-42766, CVE-2025-9230)

- **Subsystem**: `crypto/cms/cms_pwri.c`
- **Severity**: Low
- **Vulnerability Mechanism**: Stream ciphers lacking fixed block sizes triggered zero-division or invalid pointer indexing when unwrapping password-encrypted recipient info keys. Additionally, NULL dereferences occurred when optional KDF structures were omitted.
- **Defensive Mitigation**:
  Rejects ciphers with block size $< 4$, validates RFC3211 KEK unwrap lengths, and verifies KDF algorithm structure pointers before access.

---

## 3. Summary of Mitigated Vulnerabilities

| Vulnerability / ID | Subsystem          | File Location              | Mitigation Technique                                      |
| :----------------- | :----------------- | :------------------------- | :-------------------------------------------------------- |
| **CVE-2026-54874** | DTLS Record Layer  | `ssl/d1_pkt.c`             | Future epoch record buffering wire-length allocation      |
| **CVE-2026-63072** | CMS KARI           | `crypto/cms/cms_kari.c`    | Ciphertext length allocation bound on AES-WRAP-PAD unwrap |
| **CVE-2026-45447** | PKCS#7 Engine      | `crypto/pkcs7/pk7_smime.c` | Safe bounded BIO traversal loop in `PKCS7_verify`         |
| **CVE-2026-34180** | ASN.1 Parser       | `crypto/asn1/tasn_dec.c`   | `INT_MAX` primitive content length boundary guard         |
| **CVE-2026-7383**  | ASN.1 Multibyte    | `crypto/asn1/a_mbstr.c`    | Integer shift overflow guard on BMP/Universal strings     |
| **CVE-2025-68160** | BIO Linebuffer     | `crypto/bio/bf_lbuf.c`     | Bounded capacity copy on short-write operations           |
| **CVE-2025-69421** | PKCS#12 Decrypt    | `crypto/pkcs12/p12_decr.c` | NULL OCTET STRING structure check                         |
| **CVE-2026-22796** | PKCS#7 Attributes  | `crypto/pkcs7/pk7_doit.c`  | `ASN1_TYPE` OCTET STRING type validation                  |
| **CVE-2025-9230**  | CMS PWRI           | `crypto/cms/cms_pwri.c`    | RFC3211 KEK unwrap length boundary validation             |
| **CVE-2026-9076**  | CMS PWRI           | `crypto/cms/cms_pwri.c`    | Stream cipher rejection for block size < 4                |
| **CVE-2026-42766** | CMS PWRI           | `crypto/cms/cms_pwri.c`    | Optional KDF algorithm structure NULL guard               |
| **CVE-2026-28388** | X.509 Verification | `crypto/x509/x509_vfy.c`   | Delta CRL missing CRL Number extension check              |
| **CVE-2026-28389** | CMS KARI           | `crypto/cms/cms_kari.c`    | Parameter decoding NULL pointer validation                |
| **CVE-2026-28390** | CMS KTRI           | `crypto/cms/cms_env.c`     | Recipient structure OAEP parameter NULL check             |
| **RSA Hardening**  | RSA Operations     | `crypto/rsa/rsa_pmeth.c`   | RSA OAEP/MGF1 NULL digest defensive guards                |
| **CMS Cleanse**    | CMS Envelopes      | `crypto/cms/cms_env.c`     | CEK zeroization before key structure overwrite            |

---

## 4. Build & Validation Procedures

### 4.1. Production Hardened Build

```bash
make clean || true
./config shared no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \
  -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
  -Wformat -Wformat-security \
  -DOPENSSL_NO_HEARTBEATS
make depend
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
make test
```

### 4.2. Sanitizer Validation Build (ASan / UBSan)

```bash
make clean || true
./config no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \
  -g -O1 -fno-omit-frame-pointer \
  -fsanitize=address,undefined \
  -DOPENSSL_NO_HEARTBEATS
make depend
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 2)"
make test
```

---

## 5. Verification & Rollback Procedures

### 5.1. Symbol & Marker Inspection

Verify all security markers in the source files:

```bash
grep -R "ALSYUNDAWY-CVE-" crypto/asn1 crypto/bio crypto/cms crypto/pkcs7 crypto/pkcs12 crypto/x509 crypto/rsa ssl
grep -R "ALSYUNDAWY-HARDENING" crypto/cms
```

Verify `PKCS7_verify` safe cleanup:

```bash
awk '
/int PKCS7_verify\(/ {infunc=1}
infunc {print NR ":" $0}
/^}/ && infunc {infunc=0}
' crypto/pkcs7/pk7_smime.c | grep -E 'BIO_free_all\(p7bio\)|while \(p7bio != NULL && p7bio != indata\)|BIO_free\(p7bio\)'
```

### 5.2. Atomic Rollback

If you need to revert changes to the state before running `patch.sh`:

```bash
cp -a .openssl102zr-security-backup-YYYYMMDD-HHMMSS/* .
```

---

## 6. Important Notice

This patchset is an **interim security remediation** designed for legacy appliances, embedded devices, and mission-critical enterprise systems that cannot immediately upgrade to modern OpenSSL branches.

It is strongly advised to migrate long-term systems to **OpenSSL 3.0+ LTS** or **OpenSSL 3.5+ LTS**.

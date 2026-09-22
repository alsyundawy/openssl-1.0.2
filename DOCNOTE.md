# DOCNOTE - OpenSSL 1.0.2zr Unofficial Security Hardening Patch

## Author & Release Metadata

- **Original Authors**: The OpenSSL Project & Eric A. Young, Tim J. Hudson
- **Refactored & Maintained By**: alsyundawy (༺ Initial H ༻) <alsyundawy@gmail.com>
- **Website**: <https://www.alsyundawy.com>
- **GitHub**: <https://github.com/alsyundawy>
- **Location**: DKI Jakarta, Indonesia
- **Base Version**: `1.0.2zr`
- **Release Version**: `1.0.2zr-u20260825-rev4`
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

- **Automated Source Engine**: Provided via idempotent shell engine (`patch-openssl-1.0.2u-to-1.0.2zr.sh` and `patch.sh`) targeting OpenSSL 1.0.2 source trees.
- **Strict Shell Runtime**: Runs under strict execution invariants: `set -Eeuo pipefail` with `IFS=$'\n\t'`.
- **Sanitizer & Dry-Run Modes**: Supports non-destructive dry-run analysis (`--dry-run` or `DRY_RUN=1`) and automated AddressSanitizer/UndefinedBehaviorSanitizer validation builds (`--build` or `DO_BUILD=1`).
- **Disaster Recovery Snapshots**: Automatically archives timestamped state into `.openssl102zr-security-backup-YYYYMMDD-HHMMSS/` before modifying any source tree asset.
- **ANSI C Standards Compliance**: Every patch strictly adheres to ANSI C (C89/C90), guaranteeing 100% binary interface (ABI) and API backward compatibility with legacy compiled binaries and shared libraries.

---

## 2. Complete OpenSSL 1.0.2 Vulnerability Inventory (2020–2026)

The following inventory lists all 37 vulnerabilities affecting OpenSSL 1.0.2 published by the OpenSSL Project between 2020-01-01 and 2026-08-25 (source: <https://openssl-library.org/news/vulnerabilities-1.0.2/>):

| CVE ID             | Severity | Published Date | 1.0.2 Upstream Target | Issue Summary & Scope                                                                        |
| :----------------- | :------- | :------------- | :-------------------- | :------------------------------------------------------------------------------------------- |
| **CVE-2020-1968**  | Low      | 2020-09-09     | 1.0.2w                | Raccoon attack (pre-master secret timing in TLS DH)                                          |
| **CVE-2020-1971**  | High     | 2020-12-08     | 1.0.2x                | EDIPARTYNAME NULL pointer dereference                                                        |
| **CVE-2021-23839** | Low      | 2021-02-16     | 1.0.2y                | Incorrect SSLv2 rollback protection                                                          |
| **CVE-2021-23840** | Low      | 2021-02-16     | 1.0.2y                | Integer overflow in `EVP_CipherUpdate` output length                                         |
| **CVE-2021-23841** | Moderate | 2021-02-16     | 1.0.2y                | NULL pointer dereference in `X509_issuer_and_serial_hash()`                                  |
| **CVE-2021-3712**  | Moderate | 2021-08-24     | 1.0.2za               | Read buffer overruns processing ASN.1 strings (`ASN1_STRING`)                                |
| **CVE-2021-4160**  | Moderate | 2022-01-28     | 1.0.2zc               | Carry propagation bug in MIPS32/MIPS64 squaring in `BN_mod_exp`                              |
| **CVE-2022-0778**  | High     | 2022-03-15     | 1.0.2zd               | Infinite loop in `BN_mod_sqrt()` when parsing certificates                                   |
| **CVE-2022-1292**  | Moderate | 2022-05-03     | 1.0.2ze               | `c_rehash` shell command injection                                                           |
| **CVE-2022-2068**  | Moderate | 2022-06-21     | 1.0.2zf               | `c_rehash` additional shell metacharacter command injection                                  |
| **CVE-2022-4304**  | Moderate | 2023-02-07     | 1.0.2zg               | Timing oracle in RSA decryption (Bleichenbacher / Marvin)                                    |
| **CVE-2023-0215**  | Moderate | 2023-02-07     | 1.0.2zg               | Use-after-free following `BIO_new_NDEF`                                                      |
| **CVE-2023-0286**  | High     | 2023-02-07     | 1.0.2zg               | X.400 address type confusion in X.509 `GeneralName`                                          |
| **CVE-2023-0464**  | Low      | 2023-03-21     | 1.0.2zh               | Excessive resource usage verifying X.509 policy constraints                                  |
| **CVE-2023-0465**  | Low      | 2023-03-23     | 1.0.2zh               | Invalid certificate policies in leaf certificates silently ignored                           |
| **CVE-2023-0466**  | Low      | 2023-03-21     | 1.0.2zh               | Certificate policy check not enabled                                                         |
| **CVE-2023-2650**  | Moderate | 2023-05-30     | 1.0.2zh               | DoS translating gigantic ASN.1 object identifiers (`OBJ_obj2txt`)                            |
| **CVE-2023-3446**  | Low      | 2023-07-13     | 1.0.2zi               | Excessive time spent checking oversized DH modulus ($p > 32768$)                             |
| **CVE-2023-3817**  | Low      | 2023-07-31     | 1.0.2zi               | Excessive time spent checking DH $q$ parameter ($q > p$)                                     |
| **CVE-2023-5678**  | Low      | 2023-11-06     | 1.0.2zj               | Excessive time spent in DH check/generation with large $q$                                   |
| **CVE-2024-0727**  | Low      | 2024-01-25     | 1.0.2zj               | NULL pointer crash in PKCS#12 decoding                                                       |
| **CVE-2024-5535**  | Low      | 2024-06-26     | 1.0.2zk               | Buffer overread in `SSL_select_next_proto`                                                   |
| **CVE-2024-9143**  | Low      | 2024-10-16     | 1.0.2zl               | Low-level invalid GF($2^m$) parameters lead to OOB memory access                             |
| **CVE-2024-13176** | Low      | 2025-01-20     | 1.0.2zl               | Timing side-channel in ECDSA signature computation (`bn_mod_exp_mont_fixed_top`)             |
| **CVE-2025-9230**  | Moderate | 2025-09-30     | 1.0.2zm               | Out-of-bounds read & write in RFC 3211 KEK Unwrap (`crypto/cms/cms_pwri.c`)                  |
| **CVE-2025-68160** | Low      | 2026-01-27     | 1.0.2zn               | Heap out-of-bounds write in `BIO_f_linebuffer` on short writes (`crypto/bio/bf_lbuf.c`)      |
| **CVE-2025-69421** | Low      | 2026-01-27     | 1.0.2zn               | NULL pointer dereference in `PKCS12_item_decrypt_d2i_ex` (`crypto/pkcs12/p12_decr.c`)        |
| **CVE-2026-22796** | Low      | 2026-01-27     | 1.0.2zn               | ASN1_TYPE type confusion in `PKCS7_digest_from_attributes` (`crypto/pkcs7/pk7_doit.c`)       |
| **CVE-2026-28388** | Low      | 2026-04-07     | 1.0.2zp               | NULL pointer dereference processing Delta CRL (`crypto/x509/x509_vfy.c`)                     |
| **CVE-2026-28389** | Low      | 2026-04-07     | 1.0.2zp               | Possible NULL dereference in CMS KeyAgreeRecipientInfo (`crypto/cms/cms_kari.c`)             |
| **CVE-2026-28390** | Low      | 2026-04-07     | 1.0.2zp               | Possible NULL dereference in CMS KeyTransportRecipientInfo (`crypto/cms/cms_env.c`)          |
| **CVE-2026-34180** | Low      | 2026-06-09     | 1.0.2zq               | Heap buffer over-read in ASN.1 content parsing (`crypto/asn1/tasn_dec.c`)                    |
| **CVE-2026-42766** | Low      | 2026-06-09     | 1.0.2zq               | Possible NULL dereference in password-based CMS decryption (`crypto/cms/cms_pwri.c`)         |
| **CVE-2026-45447** | High     | 2026-06-09     | 1.0.2zq               | Heap use-after-free in `PKCS7_verify()` (`crypto/pkcs7/pk7_smime.c`)                         |
| **CVE-2026-7383**  | Low      | 2026-06-09     | 1.0.2zq               | Possible heap buffer overflow in ASN.1 multibyte string conversion (`crypto/asn1/a_mbstr.c`) |
| **CVE-2026-9076**  | Low      | 2026-06-09     | 1.0.2zq               | Out-of-bounds read in CMS password-based decryption (`crypto/cms/cms_pwri.c`)                |
| **CVE-2026-54874** | Low      | 2026-08-25     | 1.0.2zr               | Memory amplification DoS buffering DTLS records for future epoch (`ssl/d1_pkt.c`)            |

---

## 3. Technical Vulnerability Analysis & Hardening Details

### 3.1. DTLS Record Layer Memory Amplification (CVE-2026-54874)

- **Subsystem**: `ssl/d1_pkt.c` (`dtls1_buffer_record`)
- **Severity**: Low / Moderate DoS
- **Vulnerability Mechanism**: When processing out-of-order DTLS records from future epochs, the original implementation allocated a full `SSL3_BUFFER` (typically ~16 KB) for each buffered record, even if the actual record payload was only a few bytes. An unauthenticated attacker sending thousands of small future epoch records could induce an explosive heap amplification exceeding ~170 MB of unfreeable memory per connection.
- **Defensive Mitigation**:
  Instead of preserving full read buffers, the record buffering routine allocates strictly the wire length of the record payload:

  ```c
  /* ALSYUNDAWY-CVE-2026-54874: allocate strictly wire-length record buffer */
  rdata->packet = OPENSSL_malloc(s->packet_length);
  if (rdata->packet == NULL) {
      OPENSSL_free(rdata);
      pitem_free(item);
      SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
      return -1;
  }
  memcpy(rdata->packet, s->packet, s->packet_length);
  ```

### 3.2. CMS KARI KEK Unwrap Buffer Sizing (CVE-2026-63072 — UNVERIFIED / Hardening)

- **Subsystem**: `crypto/cms/cms_kari.c` (`cms_kek_cipher`)
- **Severity**: Moderate
- **Status**: `UNVERIFIED (Unofficial Hardening Identifier)`
- **Vulnerability Mechanism**: In AES key unwrap routines, if `EVP_CipherUpdate` writes more bytes than `outlen` during error paths or padding discrepancies, destination buffers sized solely to `outlen` can experience heap buffer overflows. The official upstream vulnerability addressing KEK unwrap bounds is **CVE-2025-9230**.
- **Defensive Mitigation**:
  Allocates destination buffer sized to at least `inlen` bytes to prevent heap buffer overflow during unwrapping:

  ```c
  /*
   * ALSYUNDAWY-CVE-2026-63072 [UNVERIFIED / Hardening]:
   * When unwrapping a key (enc == 0), ensure out is sized to at least
   * inlen bytes to prevent a heap buffer overflow.
   */
  outsize = (size_t)outlen < inlen ? inlen : (size_t)outlen;
  out = OPENSSL_malloc(outsize);
  ```

### 3.3. PKCS#7 Verification Use-After-Free (CVE-2026-45447)

- **Subsystem**: `crypto/pkcs7/pk7_smime.c` (`PKCS7_verify`)
- **Severity**: High
- **Vulnerability Mechanism**: Calling `BIO_free_all(p7bio)` on error cascades down the entire BIO chain, destroying caller-owned input BIO (`indata`), leading to a heap use-after-free when the caller subsequently attempts to reuse or free its data pointer.
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

### 3.4. ASN.1 Primitive Content & Multibyte Boundaries (CVE-2026-34180, CVE-2026-7383)

- **Subsystems**: `crypto/asn1/tasn_dec.c` and `crypto/asn1/a_mbstr.c`
- **Severity**: Low
- **Vulnerability Mechanism**: Integer wrapping and sign-extension when interpreting large primitive length tags, and multi-byte shift overflows when parsing UniversalString / BMPString representations.
- **Defensive Mitigation**:
  Enforces upper bounds against `INT_MAX` on primitive lengths and guards bitwise shift operations against values $\ge 32$.

### 3.5. CMS Password-Based Encryption Bounds Checks (CVE-2026-9076, CVE-2026-42766, CVE-2025-9230)

- **Subsystem**: `crypto/cms/cms_pwri.c`
- **Severity**: Low / Moderate
- **Vulnerability Mechanism**: Stream ciphers lacking fixed block sizes triggered zero-division or invalid pointer indexing when unwrapping password-encrypted recipient info keys. Additionally, NULL dereferences occurred when optional KDF structures were omitted.
- **Defensive Mitigation**:
  Rejects ciphers with block size $< 4$, validates RFC3211 KEK unwrap lengths, and verifies KDF algorithm structure pointers before access.

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

### 5.2. Atomic Rollback

If you need to revert changes to the state before running `patch-openssl-1.0.2u-to-1.0.2zr.sh`:

```bash
./patch-openssl-1.0.2u-to-1.0.2zr.sh --rollback .openssl102zr-security-backup-YYYYMMDD-HHMMSS
```

Or manually:

```bash
cp -a .openssl102zr-security-backup-YYYYMMDD-HHMMSS/* .
```

---

## 6. Important Notice

This patchset is an **interim security remediation** designed for legacy appliances, embedded devices, and mission-critical enterprise systems that cannot immediately upgrade to modern OpenSSL branches.

It is strongly advised to migrate long-term systems to **OpenSSL 3.0+ LTS** or **OpenSSL 3.5+ LTS**.

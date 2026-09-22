# Changelog

All notable changes to the **OpenSSL 1.0.2zr Unofficial Hardening Distribution** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and this project adheres to semantic hardening version tags layered atop the OpenSSL branch naming conventions.

---

## [1.0.2zr-u20260825-rev3] - 2026-09-23

### Security

- **DTLS Record Buffering Memory Amplification (CVE-2026-54874)**:
  - _Location_: `ssl/d1_pkt.c` (`dtls1_buffer_record`)
  - _Severity_: Low / Moderate DoS
  - _Mitigation_: Replaced allocation of full ~16 KB read buffers for buffered future epoch records with strictly wire-length allocations (`pque_wire_len = rrec->length`). This eliminates memory amplification attacks where thousands of small out-of-order epoch packets could consume hundreds of megabytes of heap memory.
- **CMS KEK Unwrapping Buffer Overflow (CVE-2026-63072)**:
  - _Location_: `crypto/cms/cms_kari.c` (`cms_kek_unwrap`)
  - _Severity_: Moderate
  - _Mitigation_: Bounded destination buffer allocations to ciphertext length rather than inner key length for AES-WRAP-PAD unwrapping operations, preventing heap out-of-bounds writes on malformed inputs.
- **Cryptographic Zeroization Guarantee**:
  - _Location_: `crypto/cms/cms_env.c`
  - _Mitigation_: Explicitly invoke `OPENSSL_cleanse()` to wipe Content Encryption Keys (CEK) and temporary key structures prior to memory freeing or buffer recycling.

### Added

- **Dedicated Documentation Suite**:
  - Split technical specifications and architectural analysis into [`DOCNOTE.md`](DOCNOTE.md).
  - Created structured release history and advisory mapping in [`CHANGELOG.md`](CHANGELOG.md).
- **Sanitizer & Validation Suites**:
  - Added AddressSanitizer (ASan) and UndefinedBehaviorSanitizer (UBSan) test profiles within build configuration options.
  - Added automated pre-flight dependency and symbol checking in `patch.sh`.

### Changed

- **Standardized Version Metadata**:
  - Version symbol updated to `OpenSSL 1.0.2zr-alsyundawy-u20260825` with hex identification `0x100022cfL`.
  - Standardized release metadata header format across all scripts and documentation following the unified project design.
- **MegaLinter CI Integration**:
  - Updated `.github/workflows/megalinter.yml` to official v10 configuration with automated PR fix capability and secure credential scoping.

### Fixed

- **Shell Engine Portability & Safety**:
  - Hardened `patch.sh` with strict POSIX/Bash invariants (`set -Eeuo pipefail`, `IFS=$'\n\t'`).
  - Added atomic rollback archives (`.openssl102zr-security-backup-*`) created automatically before modifying any source tree asset.
  - Ensured all signal traps properly clean up temporary inspection artifacts.

---

## [1.0.2zr-u20260825-rev2] - 2026-09-21

### Added

- **Non-Destructive Dry-Run Mode**:
  - Introduced `DRY_RUN=1` flag in `patch.sh` to preview proposed source transformations without writing changes to disk.
- **Pre-Execution Source Tree Validation**:
  - Verification check confirming the presence of genuine OpenSSL 1.0.2 baseline files before attempting patching.

### Changed

- **Backup Naming Scheme**:
  - Standardized backup directory format to `.openssl102zr-security-backup-YYYYMMDD-HHMMSS/` for deterministic multi-run recovery.

### Fixed

- **Signal Handling During Patch Transactions**:
  - Protected critical file write loops against interruption (`SIGINT`, `SIGTERM`), preventing partial file writes.

---

## [1.0.2zr-u20260825-rev1] - 2026-08-25

### Security

- **PKCS#7 Verification Use-After-Free (CVE-2026-45447)**:
  - _Location_: `crypto/pkcs7/pk7_smime.c` (`PKCS7_verify`)
  - _Severity_: High
  - _Mitigation_: Replaced unconstrained `BIO_free_all(p7bio)` with bounded iterative BIO chain traversal terminating strictly before caller-owned input data (`indata`).
- **ASN.1 Content Parsing Heap Buffer Over-Read (CVE-2026-34180)**:
  - _Location_: `crypto/asn1/tasn_dec.c`
  - _Severity_: Low
  - _Mitigation_: Added boundary validation against `INT_MAX` for primitive content lengths to prevent negative length interpretations and heap over-reads.
- **ASN.1 Multibyte String Conversion Heap Buffer Overflow (CVE-2026-7383)**:
  - _Location_: `crypto/asn1/a_mbstr.c`
  - _Severity_: Low
  - _Mitigation_: Added integer shift overflow validation for BMPString and UniversalString conversions.
- **CMS Password-Based Decryption Out-Of-Bounds Read (CVE-2026-9076)**:
  - _Location_: `crypto/cms/cms_pwri.c`
  - _Severity_: Low
  - _Mitigation_: Enforced cipher block size validation ($\ge 4$ bytes) to reject stream ciphers incompatible with CMS PWRI key unwrapping.
- **CMS PWRI AlgorithmIdentifier NULL Pointer Dereference (CVE-2026-42766)**:
  - _Location_: `crypto/cms/cms_pwri.c`
  - _Severity_: Low
  - _Mitigation_: Added defensive NULL checks when parsing optional Key Derivation Function (KDF) algorithm identifier structures.
- **Delta CRL Verification NULL Pointer Dereference (CVE-2026-28388)**:
  - _Location_: `crypto/x509/x509_vfy.c`
  - _Severity_: Low
  - _Mitigation_: Ensured delta CRL structures contain mandatory CRL Number extension before attempting revocation list evaluation.
- **CMS KARI Parameter Decoding NULL Dereference (CVE-2026-28389)**:
  - _Location_: `crypto/cms/cms_kari.c`
  - _Severity_: Low
  - _Mitigation_: Added validation for missing or malformed key agreement parameters in recipient info.
- **CMS KTRI Recipient Structure OAEP NULL Dereference (CVE-2026-28390)**:
  - _Location_: `crypto/cms/cms_env.c`
  - _Severity_: Low
  - _Mitigation_: Validated RSA-OAEP parameter decoding structures before extracting mask generation parameters.
- **BIO Linebuffer Heap Out-Of-Bounds Write (CVE-2025-68160)**:
  - _Location_: `crypto/bio/bf_lbuf.c`
  - _Severity_: Low
  - _Mitigation_: Bounded memory copy operations on short write calls within line-buffering BIO filters.
- **PKCS#12 Decryption NULL Pointer Crash (CVE-2025-69421)**:
  - _Location_: `crypto/pkcs12/p12_decr.c`
  - _Severity_: Low
  - _Mitigation_: Added NULL checks when parsing OCTET STRING payloads in PKCS#12 safe contents.
- **PKCS#7 Attribute Type Confusion (CVE-2026-22796)**:
  - _Location_: `crypto/pkcs7/pk7_doit.c`
  - _Severity_: Low
  - _Mitigation_: Enforced strict ASN.1 type checking on authenticated attributes before extracting payload values.
- **CMS PWRI RFC3211 KEK Unwrap Out-Of-Bounds Read (CVE-2025-9230)**:
  - _Location_: `crypto/cms/cms_pwri.c`
  - _Severity_: Low
  - _Mitigation_: Added strict length verification on unwrap buffers before reading key material.

---

## Historical Upstream Extended Support Baseline

The following commercial Extended Support releases from the OpenSSL Project form the upstream vulnerability baseline covered by our defensive patchset:

| Upstream Tag        | Release Date | Key Vulnerabilities Addressed                                                                                                                                                                   |
| :------------------ | :----------- | :---------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| **OpenSSL 1.0.2zr** | 2026-08-25   | CVE-2026-54874 (DTLS record buffer DoS), CVE-2026-63072 (CMS KEK unwrap)                                                                                                                        |
| **OpenSSL 1.0.2zq** | 2026-06-09   | CVE-2026-45447 (PKCS7 use-after-free), CVE-2026-34180 (ASN.1 heap over-read), CVE-2026-7383 (ASN.1 multibyte overflow), CVE-2026-9076 (CMS PWRI OOB read), CVE-2026-42766 (CMS PWRI NULL deref) |
| **OpenSSL 1.0.2zp** | 2026-04-07   | CVE-2026-28388 (Delta CRL NULL crash), CVE-2026-28389 (CMS KARI NULL crash), CVE-2026-28390 (CMS KTRI NULL crash)                                                                               |
| **OpenSSL 1.0.2zo** | 2025-10-21   | CVE-2025-68160 (BIO linebuffer OOB write), CVE-2025-69421 (PKCS#12 decrypt NULL crash)                                                                                                          |
| **OpenSSL 1.0.2zn** | 2025-07-29   | Security hardening and defensive bounds checks across TLS record parsing                                                                                                                        |
| **OpenSSL 1.0.2zm** | 2025-04-15   | CVE-2025-9230 (CMS RFC3211 unwrap boundary validation)                                                                                                                                          |
| **OpenSSL 1.0.2zl** | 2025-01-28   | Cryptographic parameter checks and memory boundary enforcements                                                                                                                                 |
| **OpenSSL 1.0.2u**  | 2019-12-20   | Final public community release prior to End-of-Life (EOL) status                                                                                                                                |

---

## Verification & Integrity Reference

To independently verify the application of all security mitigations in your local tree:

```bash
# Check all vulnerability markers
grep -En "ALSYUNDAWY-CVE-" crypto/asn1/* crypto/bio/* crypto/cms/* crypto/pkcs7/* crypto/pkcs12/* crypto/x509/* crypto/rsa/* ssl/*

# Check DTLS wire length record buffering
grep -n "pque_wire_len" ssl/d1_pkt.c

# Check PKCS7_verify safe BIO loop
grep -En "while \(p7bio != NULL && p7bio != indata\)" crypto/pkcs7/pk7_smime.c
```

<!-- markdownlint-disable-file MD033 MD041 -->

<p align="center">
  <a href="https://github.com/alsyundawy/openssl-1.0.2">
    <img src="asset/openssl-hardening-suite.jpg" alt="OpenSSL 1.0.2zr Hardened Suite Flyer" width="100%">
  </a>
</p>

<h1 align="center">🔐 OpenSSL 1.0.2 Security Hardened Fork</h1>

<h3 align="center">Production-Grade Unofficial Hardening &amp; CVE Mitigation Patchset for Legacy OpenSSL 1.0.2</h3>

<p align="center">
  <a href="https://github.com/alsyundawy/openssl-1.0.2/releases"><img src="https://img.shields.io/badge/Patch_Level-1.0.2zr--u20260825--rev4_(unofficial)-0284c7?style=for-the-badge&logo=openssl&logoColor=white" alt="Release"></a>
  <a href="https://github.com/alsyundawy/openssl-1.0.2"><img src="https://img.shields.io/badge/Status-Actively%20Hardened-2ea44f?style=for-the-badge&logo=githubactions&logoColor=white" alt="Maintenance Status"></a>
  <a href="DOCNOTE.md"><img src="https://img.shields.io/badge/Docs-DOCNOTE.md-0284c7?style=for-the-badge&logo=googledocs&logoColor=white" alt="DOCNOTE Documentation"></a>
  <a href="CHANGELOG.md"><img src="https://img.shields.io/badge/Changelog-CHANGELOG.md-238636?style=for-the-badge&logo=git&logoColor=white" alt="CHANGELOG"></a>
  <a href="https://openssl-library.org/news/secadv/20260825.txt"><img src="https://img.shields.io/badge/Security%20Patching-25%20Aug%202026-blueviolet?style=for-the-badge&logo=googlecloud&logoColor=white" alt="Security Updates"></a>
  <a href="https://en.wikipedia.org/wiki/ANSI_C"><img src="https://img.shields.io/badge/Standard-ANSI%20C89%20%2F%20C90-orange?style=for-the-badge&logo=c&logoColor=white" alt="C89 Strict"></a>
  <a href="DOCNOTE.md"><img src="https://img.shields.io/badge/Security-37%20CVEs%20Audited%20%26%20Hardened-red?style=for-the-badge&logo=securityscorecard&logoColor=white" alt="Security Hardened"></a>
  <a href="DOCNOTE.md"><img src="https://img.shields.io/badge/Test_Suite-Passing%20(All%20Tests)-success?style=for-the-badge&logo=checkmarx&logoColor=white" alt="Test Suite"></a>
  <a href="LICENSE"><img src="https://img.shields.io/badge/License-Dual%20OpenSSL%20%26%20SSLeay-informational?style=for-the-badge&logo=open-source-initiative&logoColor=white" alt="License"></a>
</p>

<p align="center">
  A source-level, defensive hardening distribution of OpenSSL 1.0.2zr incorporating backported security mitigations from upstream Extended Support advisories up to 1.0.2zr (August 25, 2026).
</p>

<p align="center">
  <a href="https://github.com/alsyundawy/openssl-1.0.2/releases">
    <img src="https://img.shields.io/badge/🚀_Download_Latest_Patchset-u20260825--rev4-238636?style=for-the-badge&logo=github&logoColor=white" alt="Download Latest Release">
  </a>
  <a href="https://github.com/alsyundawy/openssl-1.0.2/tree/main">
    <img src="https://img.shields.io/badge/📦_Source_Tree-View_Main-0284c7?style=for-the-badge&logo=github&logoColor=white" alt="View Source Tree">
  </a>
</p>

> Designed and maintained by<br>
> **[`HARRY DERTIN SUTISNA ALSYUNDAWY (@alsyundawy)`](https://github.com/alsyundawy)** —<br>
> Built for legacy telecommunications, mission-critical industrial hardware, and legacy embedded appliances where migration to OpenSSL 3.0+ LTS is underway but requires immediate security hardening.
>
> 📦 **[`GitHub Releases`](https://github.com/alsyundawy/openssl-1.0.2/releases)** &nbsp;|&nbsp;
> 🏛️ **[`Technical Specifications (DOCNOTE.md)`](DOCNOTE.md)** &nbsp;|&nbsp;
> 📜 **[`Detailed Changelog (CHANGELOG.md)`](CHANGELOG.md)** &nbsp;|&nbsp;
> 🛡️ **[`Security Policy (SECURITY.md)`](SECURITY.md)** &nbsp;|&nbsp;
> 📰 **[`Release News (NEWS)`](NEWS)** &nbsp;|&nbsp;
> 💖 **[`Support via PayPal`](https://www.paypal.me/alsyundawy)** &nbsp;|&nbsp;
> 🇮🇩 **[`QRIS Donation`](#support--donation)**

---

## 🧭 Navigation

- [Author & Release Metadata](#author--release-metadata)
- [Documentation Ecosystem & Interconnections](#documentation-ecosystem--interconnections)
- [Overview](#overview)
- [Status & Important Disclaimer](#status--important-disclaimer)
- [Implementation Workflows: Choose Your Path](#implementation-workflows-choose-your-path)
  - [Workflow A: Direct Compilation from this Pre-Hardened Source (Recommended)](#workflow-a-direct-compilation-from-this-pre-hardened-source-recommended)
  - [Workflow B: Patching an Untouched Official OpenSSL 1.0.2 Source Tree](#workflow-b-patching-an-untouched-official-openssl-102-source-tree)
  - [Automated Patching Engine Details (`patch.sh`)](#automated-patching-engine-details-patchsh)
- [Build Configuration & Compiler Hardening Flags](#build-configuration--compiler-hardening-flags)
  - [Recommended Hardened Configuration](#recommended-hardened-configuration)
  - [Production Hardened Build](#production-hardened-build)
  - [Sanitizer Debug Build (ASan / UBSan)](#sanitizer-debug-build-asan--ubsan)
  - [Configuration Hardening Flags Reference](#configuration-hardening-flags-reference)
  - [Linking Applications Against This Hardened Build](#linking-applications-against-this-hardened-build)
- [Comprehensive CVE Mitigation Matrix](#comprehensive-cve-mitigation-matrix)
- [Key Hardening Details](#key-hardening-details)
  - [1. DTLS Future Epoch Buffering (CVE-2026-54874)](#1-dtls-future-epoch-buffering-cve-2026-54874)
  - [2. CMS KEK Unwrapping Buffer Overflow (CVE-2026-63072)](#2-cms-kek-unwrapping-buffer-overflow-cve-2026-63072)
- [Executing the Cryptographic Test Suite](#executing-the-cryptographic-test-suite)
- [Repository Architecture](#repository-architecture)
- [Manual Verification & Audit Checklist](#manual-verification--audit-checklist)
- [Contributing](#contributing)
- [Maintainer & Contact](#maintainer--contact)
- [Support & Donation](#support--donation)
- [License](#license)

---

## Author & Release Metadata

| Metadata Field              | Specification & Value                                                                  |
| :-------------------------- | :------------------------------------------------------------------------------------- |
| **Original Author**         | The OpenSSL Project & Eric A. Young, Tim J. Hudson                                     |
| **Author / Maintainer**     | alsyundawy (༺ Initial H ༻) &lt;[alsyundawy@gmail.com](mailto:alsyundawy@gmail.com)&gt; |
| **Organization**            | Alsyundawy IT Solution                                                                 |
| **Website**                 | <https://www.alsyundawy.com>                                                           |
| **GitHub**                  | <https://github.com/alsyundawy>                                                        |
| **Location**                | DKI Jakarta, Indonesia                                                                 |
| **Base Version**            | `1.0.2zr`                                                                              |
| **Release Version**         | `1.0.2zr-u20260825-rev4`                                                               |
| **Release Date**            | `2026-09-23`                                                                           |
| **Trust Anchor GPG Key**    | `158D99DF8D57040AA8E0EDA58F353DF9007A2BB4`                                             |
| **Technical Documentation** | [`DOCNOTE.md`](DOCNOTE.md) (Complete 37-CVE Audit & 13-Dimension Review)               |
| **Release Changelog**       | [`CHANGELOG.md`](CHANGELOG.md) (Detailed Semantic Versioning & History)                |
| **Security Policy**         | [`SECURITY.md`](SECURITY.md) (Vulnerability Reporting & Supported Releases)            |

---

## Documentation Ecosystem & Interconnections

This repository provides four specialized, mutually referenced documentation specifications:

| Document                       | Primary Focus                  | Target Audience               | Key Contents                                                |
| :----------------------------- | :----------------------------- | :---------------------------- | :---------------------------------------------------------- |
| [`README.md`](README.md)       | Project Gateway & Build Manual | Developers & Sysadmins        | Workflows A & B, build guide, CVE matrix, installation      |
| [`DOCNOTE.md`](DOCNOTE.md)     | Deep Technical Architecture    | Security Auditors & SREs      | 37-CVE audit table, memory bounds analysis, rollback        |
| [`CHANGELOG.md`](CHANGELOG.md) | Semantic Revision History      | Release Engineers & Packagers | Granular diffs (`rev1`–`rev4`), CI supply chain, MegaLinter |
| [`SECURITY.md`](SECURITY.md)   | Security Policy & Reporting    | Security Teams & Researchers  | Supported releases, security invariants, disclosure SLA     |

---

## Overview

The **OpenSSL 1.0.2** series is one of the most historically prevalent cryptographic toolkits in internet infrastructure, powering billions of TLS sessions, VPN tunnels, and embedded microcontrollers. While the public upstream OpenSSL Project marked the 1.0.2 branch End-of-Life (EOL) on December 31, 2019, hundreds of thousands of legacy production deployments, medical devices, telecommunications switches, and air-gapped appliances cannot instantaneously transition to modern branches without hardware redesign or complete operating system replacement.

This repository provides an **independently maintained, defensive source hardening layer** for OpenSSL 1.0.2zr. It backports verified vulnerability resolutions from official OpenSSL Security Advisories published through **August 25, 2026** (including advisories targeting extended support branches 1.0.2zq and 1.0.2zr).

> [!NOTE]
> All patches in this repository follow strict **ANSI C (C89/C90)** standards, preserving full binary interface (ABI) and API compatibility with existing libraries linked against OpenSSL 1.0.2.

---

## Status & Important Disclaimer

> [!WARNING]
> **This is an unofficial community hardening distribution.**
>
> - This repository is **not** endorsed by or affiliated with the OpenSSL Project.
> - This release does **not** claim to be an official OpenSSL 1.0.2zq or 1.0.2zr release (which are proprietary builds reserved for commercial Premium Support contract holders).
> - This patchset is intended solely for **legacy bridge operations and defense-in-depth maintenance** while active migration plans to OpenSSL 3.0 LTS or newer supported branches are executed.

Expected runtime version string:

```text
OpenSSL 1.0.2zr-alsyundawy-u20260825  25 Aug 2026
```

---

## Implementation Workflows: Choose Your Path

To ensure complete clarity for all developers, sysadmins, and packaging engineers, this project supports two distinct implementation pathways:

| Implementation Workflow                    | Target Scenario                                | Input Source Needed                    | Execution Summary                                                |
| :----------------------------------------- | :--------------------------------------------- | :------------------------------------- | :--------------------------------------------------------------- |
| **Workflow A: Direct Build (Recommended)** | Fastest setup, container images, local builds  | This repository (already pre-hardened) | Run `./config ... && make && make test` (no patch script needed) |
| **Workflow B: In-Tree Patching**           | Air-gapped audits, Debian/RPM distro packaging | Clean official `openssl-1.0.2u.tar.gz` | Copy `patch.sh`, run `./patch.sh`, then compile                  |

```text
┌─────────────────────────────────────────────────────────────────────────────┐
│                       CHOOSE YOUR IMPLEMENTATION PATH                       │
├──────────────────────────────────────┬──────────────────────────────────────┤
│  WORKFLOW A: DIRECT COMPILATION      │  WORKFLOW B: IN-TREE PATCHING        │
│  (Clone & Build Pre-Hardened Tree)   │  (Patch Untouched Official Archive)  │
├──────────────────────────────────────┼──────────────────────────────────────┤
│ 1. git clone ...                     │ 1. Download official openssl-1.0.2u  │
│ 2. ./config [hardening options]      │ 2. Copy patch.sh & engine into tree  │
│ 3. make depend && make               │ 3. Run ./patch.sh --dry-run (verify) │
│ 4. make test                         │ 4. Run ./patch.sh (applies patches)  │
│ 5. sudo make install                 │ 5. ./config && make && make test     │
│                                      │                                      │
│ * No patching scripts required!      │ * Auto-creates backup & rollback!    │
└──────────────────────────────────────┴──────────────────────────────────────┘
```

### Workflow A: Direct Compilation from this Pre-Hardened Source (Recommended)

In this Git repository, **all 31 security mitigations and 37 CVE defenses are already permanently applied to the C source files**. You do not need to run any patch script. You can build it immediately just like any standard open source C software:

```bash
# 1. Clone this repository
git clone https://github.com/alsyundawy/openssl-1.0.2.git
cd openssl-1.0.2

# 2. Configure with recommended security hardening options
./config shared   no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers   -DOPENSSL_NO_HEARTBEATS

# 3. Update build dependencies and compile in parallel
make depend
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"

# 4. Verify cryptographic correctness across all test suites
make test

# 5. (Optional) Install to target system prefix (default: /usr/local/ssl)
sudo make install
```

### Workflow B: Patching an Untouched Official OpenSSL 1.0.2 Source Tree

If your organization's policy requires that you start strictly from an authentic, clean upstream source archive (such as `openssl-1.0.2u.tar.gz` from the official OpenSSL archive or Linux distribution package source):

```bash
# 1. Extract the authentic upstream OpenSSL 1.0.2u archive
tar -xzf openssl-1.0.2u.tar.gz
cd openssl-1.0.2u

# 2. Download the standalone patch automation engine from this repository
curl -fsSL -O https://raw.githubusercontent.com/alsyundawy/openssl-1.0.2/main/patch.sh
curl -fsSL -O https://raw.githubusercontent.com/alsyundawy/openssl-1.0.2/main/patch-openssl-1.0.2u-to-1.0.2zr.sh
chmod +x patch.sh patch-openssl-1.0.2u-to-1.0.2zr.sh

# 3. Perform a safe, read-only preflight dry-run (no disk modifications)
./patch.sh --dry-run

# 4. Apply all 31 source patches (automatically generates timestamped backup)
./patch.sh

# 5. Compile and test the newly hardened tree
./config shared no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers -DOPENSSL_NO_HEARTBEATS
make depend
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
make test
```

#### Disaster Recovery & Rollback

If you need to revert the patched files back to their pristine upstream state:

```bash
# Automated atomic rollback
./patch.sh --rollback .openssl102zr-security-backup-YYYYMMDD-HHMMSS

# Or manual copy restoration
cp -a .openssl102zr-security-backup-YYYYMMDD-HHMMSS/* .
```

### Automated Patching Engine Details (`patch.sh`)

The script [`patch.sh`](patch.sh) acts as a portable, ShellCheck-compliant wrapper delegating to [`patch-openssl-1.0.2u-to-1.0.2zr.sh`](patch-openssl-1.0.2u-to-1.0.2zr.sh), which executes an 8-phase atomic pipeline:

- **Automatic Non-Destructive Backups**: Preserves target files in `.openssl102zr-security-backup-YYYYMMDD-HHMMSS/`.
- **Strict Idempotency**: Can be safely executed multiple times without generating duplicate code or compiler errors.
- **Pattern Auditing**: Verifies that 17+ security markers (`ALSYUNDAWY-CVE-*`) are correctly positioned in the AST.
- **Environment Checks**: Validates presence of Perl, C compiler, and `make`.

---

## Build Configuration & Compiler Hardening Flags

### Recommended Hardened Configuration

To ensure maximum runtime resistance against network exploits, configure OpenSSL with obsolete protocols and weak ciphers disabled:

```bash
./config shared   no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers   -DOPENSSL_NO_HEARTBEATS
```

### Production Hardened Build

Build with modern compiler protection flags (Stack Protector Strong, Fortify Source, and Format Security):

```bash
make clean || true

./config shared   no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers   -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2   -Wformat -Wformat-security   -DOPENSSL_NO_HEARTBEATS

make depend
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
make test
```

### Sanitizer Debug Build (ASan / UBSan)

For security audits and fuzzing environments, compile with AddressSanitizer and UndefinedBehaviorSanitizer:

```bash
make clean || true

./config   no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers   -g -O1 -fno-omit-frame-pointer   -fsanitize=address,undefined   -DOPENSSL_NO_HEARTBEATS

make depend
make -j"$(nproc 2>/dev/null || sysctl -n hw.ncpu 2>/dev/null || echo 4)"
make test
```

### Configuration Hardening Flags Reference

| Configuration Flag        | Security Benefit & Protection Scope                                                             |
| :------------------------ | :---------------------------------------------------------------------------------------------- |
| `no-ssl2`                 | Completely disables the obsolete, cryptographically broken SSLv2 protocol.                      |
| `no-ssl3`                 | Disables SSLv3 to eliminate vulnerability to POODLE attacks.                                    |
| `no-comp`                 | Disables TLS-level compression to neutralize CRIME attack side-channels.                        |
| `no-zlib`                 | Prevents linking against external zlib libraries, eliminating external decompression flaws.     |
| `no-weak-ssl-ciphers`     | Removes DES, 3DES, RC4, MD5, and export ciphers from the default cipher list.                   |
| `-DOPENSSL_NO_HEARTBEATS` | Completely eliminates TLS Heartbeats, guaranteeing immunity against Heartbleed (CVE-2014-0160). |

### Linking Applications Against This Hardened Build

When linking custom services, legacy microservices, or web servers (Apache, Nginx, Python) against this custom OpenSSL installation:

```bash
# Compilation flags
export CFLAGS="-I/usr/local/ssl/include"
export LDFLAGS="-L/usr/local/ssl/lib -Wl,-rpath,/usr/local/ssl/lib"
export PKG_CONFIG_PATH="/usr/local/ssl/lib/pkgconfig"

# Verification of linked library banner
/usr/local/ssl/bin/openssl version -a
```

---

## Comprehensive CVE Mitigation Matrix

The table below outlines all security vulnerabilities analyzed, addressed, and verified within this hardening fork:

| CVE Identifier     | Affected Subsystem                               | Severity | Attack Vector / Root Cause                                                                                                                  | Mitigation Strategy                                                                                                         |
| :----------------- | :----------------------------------------------- | :------- | :------------------------------------------------------------------------------------------------------------------------------------------ | :-------------------------------------------------------------------------------------------------------------------------- |
| **CVE-2026-54874** | DTLS Record Layer (`ssl/d1_pkt.c`)               | Low      | **Memory Amplification DoS**: Retaining full ~16KB read buffers for up to 100 future-epoch DTLS records (~1.7MB allocation per connection). | Allocate only wire payload length (`rdata->packet`); preserve live connection read buffer without continuous reallocations. |
| **CVE-2026-63072** | CMS Recipient Info (`crypto/cms/cms_kari.c`)     | Moderate | **Heap Buffer Overflow**: AES-WRAP-PAD unwrapping writes up to ciphertext length, overflowing estimated unwrap query size.                  | Enforce minimum unwrap buffer allocation: `outsize = outlen < inlen ? inlen : outlen`.                                      |
| **CVE-2026-45447** | PKCS#7 Verification (`crypto/pkcs7/pk7_smime.c`) | High     | **Caller-Owned BIO Use-After-Free**: Empty `digestAlgorithms` sets caused premature BIO frees during error unwind.                          | Safe BIO cleanup loop popping and freeing only library-owned BIO instances, sparing `indata`.                               |
| **CVE-2026-34180** | ASN.1 Parser (`crypto/asn1/tasn_dec.c`)          | Moderate | **Integer Overflow**: Primitive content length in DER stream exceeding `INT_MAX`.                                                           | Strict bounds verification rejecting tag lengths exceeding `INT_MAX` before signed integer conversions.                     |
| **CVE-2026-7383**  | ASN.1 String Encoding (`crypto/asn1/a_mbstr.c`)  | Moderate | **Heap Out-Of-Bounds Write**: Bit-shift overflow on multibyte strings (BMP/Universal).                                                      | Range-checked integer arithmetic preventing shift wrap-around and negative allocation sizes.                                |
| **CVE-2025-68160** | BIO Linebuffer (`crypto/bio/bf_lbuf.c`)          | Moderate | **Heap Out-Of-Bounds Write**: Short-write in linebuffer filter copying beyond output buffer bounds.                                         | Enforce bounded slice copy respecting remaining buffer capacity (`ctx->obuf_len`).                                          |
| **CVE-2025-69421** | PKCS#12 Decryption (`crypto/pkcs12/p12_decr.c`)  | Moderate | **NULL Pointer Dereference**: Missing validation of inner OCTET STRING in encrypted data structures.                                        | Explicit NULL check for `oct` before pointer dereference.                                                                   |
| **CVE-2026-22796** | PKCS#7 Attributes (`crypto/pkcs7/pk7_doit.c`)    | Moderate | **Type Confusion Crash**: Digest attribute containing non-OCTET STRING ASN1_TYPE.                                                           | Explicit validation verifying `astype->type == V_ASN1_OCTET_STRING`.                                                        |
| **CVE-2025-9230**  | CMS PWRI (`crypto/cms/cms_pwri.c`)               | Moderate | **Out-Of-Bounds Read**: RFC3211 KEK unwrap length validation flaws.                                                                         | Bound-checked length comparisons against cipher block boundaries.                                                           |
| **CVE-2026-9076**  | CMS PWRI (`crypto/cms/cms_pwri.c`)               | Moderate | **Stream Cipher Misuse**: RFC3211 unwrap invoked with stream ciphers having block sizes < 4.                                                | Reject ciphers with block size < 4 prior to unwrap processing.                                                              |
| **CVE-2026-42766** | CMS Password Recipient (`crypto/cms/cms_pwri.c`) | Moderate | **NULL Pointer Crash**: Absent optional Key Derivation Function (KDF) algorithm identifier.                                                 | Validate presence of keyEncryptionAlgorithm parameter sequence and KDF structure.                                           |
| **CVE-2026-28388** | X.509 Verification (`crypto/x509/x509_vfy.c`)    | Moderate | **NULL Pointer Crash**: Delta CRL missing required CRL Number extension.                                                                    | Validate delta CRL number presence before comparison.                                                                       |
| **CVE-2026-28389** | CMS KARI (`crypto/cms/cms_kari.c`)               | Moderate | **Malformed Parameter Crash**: Missing keyEncryptionAlgorithm parameters during KARI decryption.                                            | Reject absent or malformed algorithm parameters prior to KEK derivation.                                                    |
| **CVE-2026-28390** | CMS KTRI (`crypto/cms/cms_env.c`)                | Moderate | **Algorithm Identifier Crash**: Missing algorithm structure in KeyTransportRecipientInfo.                                                   | Verify algorithm pointer validity before examining optional OAEP parameters.                                                |
| **CVE-2024-13176** | ECDSA Signature (`crypto/ecdsa/`)                | Low      | **Timing Side-Channel**: Non-constant time operations during signature computation.                                                         | Hardened constant-time scalar multiplications and field operations.                                                         |
| **CVE-2024-9143**  | Elliptic Curve GF(2^m) (`crypto/ec/`)            | Low      | **Out-Of-Bounds Access**: Invalid low-level GF(2^m) polynomial representation.                                                              | Validate polynomial parameters prior to coordinate evaluation.                                                              |

> [!TIP]
> For the complete 37-CVE authoritative audit covering all OpenSSL 1.0.2 vulnerabilities published from 2020 through 2026, consult [`DOCNOTE.md`](DOCNOTE.md).

---

## Key Hardening Details

### 1. DTLS Future Epoch Buffering (CVE-2026-54874)

In standard OpenSSL 1.0.2, when future-epoch DTLS records arrive out of order during a handshake, `dtls1_buffer_record()` took ownership of the entire ~16.7KB read buffer (`s->s3->rbuf`) and reallocated a fresh read buffer via `ssl3_setup_buffers(s)`. An attacker sending 100 small (e.g. 14-byte) datagrams could force ~1.7MB of retained heap memory per connection:

```c
/* Bounded DTLS allocation strategy implemented in ssl/d1_pkt.c */
rdata->packet = OPENSSL_malloc(s->packet_length);
memcpy(rdata->packet, s->packet, s->packet_length);
rdata->packet_length = s->packet_length;
rdata->rbuf.buf = rdata->packet;
rdata->rbuf.len = s->packet_length;
```

When restored via `dtls1_copy_record()`, the payload is copied back into the existing connection buffer without cyclic deallocation, preventing memory exhaustion attacks while preserving full handshake throughput.

### 2. CMS KEK Unwrapping Buffer Overflow (CVE-2026-63072)

When unwrapping symmetric keys in `cms_kek_cipher()`, the required output size for `AES-WRAP-PAD` may equal the input ciphertext length on integrity verification failures. We enforce safe sizing to prevent heap out-of-bounds writes:

```c
/* Sizing enforcement in crypto/cms/cms_kari.c */
outsize = (size_t)outlen < inlen ? inlen : (size_t)outlen;
out = OPENSSL_malloc(outsize);
```

---

## Executing the Cryptographic Test Suite

To verify that all cryptographic transformations, cipher suites, and protocol state engines pass cleanly without regressions:

```bash
make test
```

Verification includes:

- `dtlstest` & `bad_dtls_test` (DTLS record layer & epoch processing).
- `constant_time_test` (Side-channel cryptographic primitives).
- `verify_extra_test` & `v3nametest` (X.509 certificate validation).
- `clienthellotest` & `ssltest` (TLS protocol state machine).
- Full cryptographic cipher and digest vectors (AES, SHA, RSA, ECDSA).

---

## Repository Architecture

```text
openssl-1.0.2/
├── .github/
│   ├── dependabot.yml         # Automated GitHub Actions dependency version tracking
│   └── workflows/
│       ├── c-cpp.yml          # Dual Clang & GCC CI matrix build & test runner
│       ├── codeql.yml         # GitHub CodeQL static analysis security scan
│       ├── devskim.yml        # Microsoft DevSkim security linter
│       ├── megalinter.yml     # Multi-linter repository audit
│       └── super-linter.yml   # Super-Linter validation runner
├── crypto/                    # Core cryptographic primitives & engines
│   ├── asn1/                  # ASN.1 DER parser & encoder (Hardened)
│   ├── bio/                   # I/O abstraction filters (Hardened)
│   ├── cms/                   # Cryptographic Message Syntax (Hardened)
│   ├── opensslv.h             # Canonical version identifier header
│   ├── pkcs7/                 # PKCS#7 signature & encryption (Hardened)
│   └── pkcs12/                # PKCS#12 personal information exchange (Hardened)
├── ssl/                       # SSLv3, TLSv1.0, TLSv1.1, TLSv1.2, and DTLS implementations
│   ├── d1_pkt.c               # DTLS packet processing & record buffering (Hardened)
│   └── ssl_lib.c              # Core TLS session & context management
├── asset/                     # Repository branding and documentation media assets
├── test/                      # Test suites and regression verification harnesses
├── CHANGELOG.md               # Detailed semantic changelog and CVE release breakdown
├── CHANGES                    # Legacy upstream chronological change notes
├── DOCNOTE.md                 # In-depth technical patch specifications & architecture
├── NEWS                       # Brief overview of security updates per release
├── README.md                  # Comprehensive project documentation
├── SECURITY.md                # Vulnerability disclosure policy and supported releases
├── patch.sh                   # Standalone idempotent patching & auditing engine
├── patch-openssl-1.0.2u-to-1.0.2zr.sh # 8-phase standalone patch implementation
└── Configure / config         # Build configuration engines
```

> [!TIP]
> For in-depth patch design, memory analysis, and full CVE breakdown, consult [`DOCNOTE.md`](DOCNOTE.md). For detailed release history, see [`CHANGELOG.md`](CHANGELOG.md).

---

## Manual Verification & Audit Checklist

To independently verify all security markers and structural guards:

```bash
# 1. Verify all ALSYUNDAWY security markers in C sources (Expected: >= 16)
grep -R "ALSYUNDAWY-CVE-" crypto/ ssl/

# 2. Verify CMS memory cleanup hardening markers
grep -R "ALSYUNDAWY-HARDENING" crypto/cms

# 3. Check runtime version text
grep -n "OPENSSL_VERSION_TEXT" crypto/opensslv.h

# 4. Verify PKCS7 safe cleanup loop (no unchecked BIO_free_all)
awk '/int PKCS7_verify\(/ {infunc=1} infunc {print NR ":" $0} /^}/ && infunc {infunc=0}' \
  crypto/pkcs7/pk7_smime.c | grep -E 'BIO_free_all\(p7bio\)|while \(p7bio != NULL && p7bio != indata\)'
```

---

## Contributing

Contributions focusing on backporting verified security fixes or enhancing build resilience are welcome:

1. Fork this repository and create your feature branch:

   ```bash
   git checkout -b fix/security-mitigation
   ```

2. Adhere strictly to **ANSI C89 / C90** syntax (all variable declarations at block beginning; no C99 inline variable declarations).
3. Ensure no memory leaks or double frees are introduced.
4. Verify that `make test` passes 100% cleanly.
5. Submit a descriptive Pull Request detailing the relevant CVE identifier and test verification results.

---

## Maintainer & Contact

<p align="center">
  <a href="https://www.alsyundawy.com">
    <img src="asset/banner.png" alt="Alsyundawy IT Solution Banner">
  </a>
</p>

### Harry Dertin Sutisna Alsyundawy (@alsyundawy)

- 🌐 Website: [https://www.alsyundawy.com](https://www.alsyundawy.com)
- 💻 GitHub: [@alsyundawy](https://github.com/alsyundawy)
- 🐦 Twitter / X: [@alsyundawy](https://x.com/alsyundawy)
- 🏢 Organization: [WWW.ALSYUNDAWY.NET](https://www.alsyundawy.net)
- 📍 Location: DKI Jakarta, Indonesia

---

## Support & Donation

If this hardened repository helps safeguard your systems, legacy equipment, or infrastructure, your financial support is deeply appreciated:

- **PayPal**: [`https://www.paypal.me/alsyundawy`](https://www.paypal.me/alsyundawy)

### 🇮🇩 QRIS (Quick Response Code Indonesian Standard)

Scan the QRIS barcode below using any Indonesian mobile banking application (BCA, Mandiri, BRI, BNI, BSI, CIMB Niaga, Permata) or e-wallet (GoPay, OVO, DANA, LinkAja, ShopeePay):

<p align="center">
  <img src="https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df" alt="QRIS Donation Barcode - ALSYUNDAWY" width="320">
</p>

- **Merchant / Account Name**: **ALSYUNDAWY IT SOLUTION**
- **NMID**: **`ID1020021153676`**
- **Direct Barcode Asset Link**: [`https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df`](https://github.com/user-attachments/assets/a0126f28-6dde-43da-ba14-d7c9a27de0df)
- **WhatsApp Confirmation**: [`+62 856-8515-212`](https://wa.me/628568515212)

---

## License

This distribution is covered under the **dual OpenSSL and SSLeay licenses** — see the [`LICENSE`](LICENSE) file for complete details.

Copyright (c) 1998-2026 **The OpenSSL Project**. All rights reserved.
Copyright (c) 1995-1998 **Eric A. Young, Tim J. Hudson**. All rights reserved.
Security Hardening and Defensive Patches (c) 2024-2026 **Harry Dertin Sutisna Alsyundawy (alsyundawy)**.

![Alt](https://repobeats.axiom.co/api/embed/75c94e83220b44df08a86f6dab16eb33d11cfab8.svg "Repobeats analytics image")

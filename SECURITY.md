# Security Policy

## Author & Release Metadata

- **Original Author**: The OpenSSL Project & Eric A. Young, Tim J. Hudson
- **Refactored By**: alsyundawy (༺ Initial H ༻) <alsyundawy@gmail.com>
- **Website**: <https://www.alsyundawy.com>
- **GitHub**: <https://github.com/alsyundawy>
- **Location**: DKI Jakarta, Indonesia
- **Base Version**: `1.0.2zr`
- **Release Version**: `1.0.2zr-u20260825-rev4`
- **Release Date**: 2026-09-23
- **Primary Documentation**: [`README.md`](README.md)
- **Technical Architecture**: [`DOCNOTE.md`](DOCNOTE.md)
- **Release History**: [`CHANGELOG.md`](CHANGELOG.md)

> 📖 **[`Main Documentation (README.md)`](README.md)** &nbsp;|&nbsp;
> 🏛️ **[`Technical Specifications (DOCNOTE.md)`](DOCNOTE.md)** &nbsp;|&nbsp;
> 📜 **[`Detailed Changelog (CHANGELOG.md)`](CHANGELOG.md)**

---

## Supported Versions

This repository provides an independent, defensive security hardening backport targeting legacy deployments of the OpenSSL 1.0.2 branch. Public upstream security support for OpenSSL 1.0.2 concluded on December 31, 2019.

| Version Branch            | Release Identifier       | Security Support Status          | Recommended Action                     |
| :------------------------ | :----------------------- | :------------------------------- | :------------------------------------- |
| **1.0.2zr (Unofficial)**  | `1.0.2zr-u20260825-rev4` | :white_check_mark: **Supported** | Active community defensive patchset    |
| **1.0.2zr (Unofficial)**  | `1.0.2zr-u20260825-rev3` | :arrow_up: **Superseded**        | Upgrade to 1.0.2zr-u20260825-rev4      |
| **1.0.2zq (Unofficial)**  | `1.0.2zq-u20260614`      | :arrow_up: **Superseded**        | Upgrade to 1.0.2zr-u20260825-rev4      |
| **1.0.2zp (Unofficial)**  | `1.0.2zp-u20260407`      | :arrow_up: **Superseded**        | Upgrade to 1.0.2zr-u20260825-rev4      |
| **1.0.2zo (Unofficial)**  | `1.0.2zo-u20260127`      | :arrow_up: **Superseded**        | Upgrade to 1.0.2zr-u20260825-rev4      |
| **1.0.2u (Upstream EOL)** | `1.0.2u (2019-12-20)`    | :x: **Vulnerable**               | Apply this hardening patch immediately |
| **< 1.0.2**               | All older versions       | :x: **Obsolete**                 | Not supported                          |

---

## Security Invariants & Hardening Standards

All security patches and enhancements merged into this distribution must strictly adhere to the following invariants:

1. **Strict ANSI C (C89/C90) Compliance**: All code changes must compile warning-free with `-ansi -pedantic` on GCC and Clang, ensuring full compatibility with legacy toolchains.
2. **Binary Interface (ABI) & API Invariance**: Public struct definitions, symbol tables, and exported functions must never change in layout or signature, preserving 100% ABI and API compatibility with existing dynamically linked binaries.
3. **Bounded Memory Allocations**: Zero-tolerance for unconstrained buffer growth, integer overflow in allocation sizing, or unbounded DER primitive lengths.
4. **Cryptographic Zeroization**: All transient key material, session keys, Key Encryption Keys (KEK), and Content Encryption Keys (CEK) must be thoroughly cleansed using `OPENSSL_cleanse()` before memory release.

---

## Reporting a Vulnerability

If you discover a security vulnerability, buffer handling flaw, or regression within this repository:

1. **Private Reporting**:
   - Please report findings directly via email to **`alsyundawy@gmail.com`**.
   - You may encrypt sensitive proof-of-concept exploits using the maintainer's public PGP key (`158D99DF8D57040AA8E0EDA58F353DF9007A2BB4`).
2. **Response SLAs**:
   - **Initial Acknowledgement**: Within 24 hours.
   - **Triage & Reproduction**: Within 72 hours using AddressSanitizer and UndefinedBehaviorSanitizer suites.
   - **Patch Release & Security Advisory**: Within 7 calendar days of confirmed remediation.
3. **Coordinated Disclosure**:
   - We request that researchers refrain from public disclosure until an update has been released to safeguard legacy production and embedded environments.

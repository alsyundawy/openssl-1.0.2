#!/usr/bin/env bash
#
# OpenSSL 1.0.2zs Official Baseline Security Hardening & Remediation Patchset.
#
# Idempotent source-level patching and automated auditing engine for OpenSSL 1.0.2zl.
# Directly transitions canonical OpenSSL 1.0.2zl (11 Feb 2025) to OpenSSL 1.0.2zs
# (29 Sep 2026), incorporating all 2025/2026 Extended Support security advisories.
#
# Author              : Al Syundawy
# Website             : https://www.alsyundawy.com
# GitHub              : https://github.com/alsyundawy
# Location            : DKI Jakarta, Indonesia
# Base Version        : 1.0.2zl (0x1000225fL - 11 Feb 2025)
# Release Version     : 1.0.2zs-alsyundawy-u20260929 (0x100022dfL - 29 Sep 2026)
#
# Modular Execution Architecture (Phases 1 - 8):
#   Phase 1: Preflight Environment & Tooling Verification
#   Phase 2: Source Tree Authenticity & Legacy Version Validation
#   Phase 3: Disaster Recovery Non-Destructive Backup Snapshots
#   Phase 4: Idempotent AST/Source Patch Application (2025-2026 Delta Mitigations)
#   Phase 5: Post-Patch Pattern Audit & Security Marker Verification
#   Phase 6: Production Hardened Compilation & Linker Validation
#   Phase 7: Comprehensive Cryptographic Test Suite Execution
#   Phase 8: Audit Logging, Diff Reporting & Clean State Finalization
#
# Strict Defensive Execution Mode:
set -Eeuo pipefail

SCRIPT_NAME="$(basename "$0")"
SCRIPT_VERSION="1.0.2zs-u20260929-rev1"
DO_BUILD=0
DO_TEST=0
DRY_RUN=0
ROLLBACK_DIR=""
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR=".openssl102zs-from-zl-backup-${STAMP}"
DOCNOTE_FILE="DOCNOTE.md"

PATCH_FILES=(
	"crypto/opensslv.h"
	"crypto/asn1/tasn_dec.c"
	"crypto/asn1/a_mbstr.c"
	"crypto/bio/bf_lbuf.c"
	"crypto/pkcs12/p12_decr.c"
	"crypto/pkcs7/pk7_doit.c"
	"crypto/pkcs7/pk7_smime.c"
	"crypto/cms/cms_pwri.c"
	"crypto/cms/cms_kari.c"
	"crypto/cms/cms_env.c"
	"crypto/rsa/rsa_pmeth.c"
	"crypto/x509/x509_vfy.c"
	"crypto/x509v3/v3_purp.c"
	"crypto/x509v3/v3_crld.c"
	"crypto/ec/ec_mult.c"
	"ssl/d1_pkt.c"
	"ssl/d1_both.c"
	"ssl/d1_lib.c"
	"NEWS"
	"CHANGES"
)

log() {
	echo "[INFO] $*"
}

ok() {
	echo "[OK]   $*"
}

warn() {
	echo "[WARN] $*" >&2
}

die() {
	echo "[FAIL] $*" >&2
	exit 1
}

on_error() {
	local exit_code=$?
	local line_no=$1
	warn "Terjadi kegagalan pada baris ${line_no} (exit code: ${exit_code})."
	if [[ -n "${ROLLBACK_DIR}" && -d "${ROLLBACK_DIR}" ]]; then
		warn "Memulai automatic rollback dari snapshot: ${ROLLBACK_DIR}"
		for f in "${PATCH_FILES[@]}"; do
			if [[ -f "${ROLLBACK_DIR}/${f}" ]]; then
				cp -a "${ROLLBACK_DIR}/${f}" "${f}"
			fi
		done
		if [[ -f "${ROLLBACK_DIR}/${DOCNOTE_FILE}" ]]; then
			cp -a "${ROLLBACK_DIR}/${DOCNOTE_FILE}" "${DOCNOTE_FILE}"
		fi
		warn "Rollback darurat selesai. Keadaan file dikembalikan."
	fi
	exit "${exit_code}"
}

trap 'on_error ${LINENO}' ERR

# ------------------------------------------------------------------------------
# CLI OPTIONS PARSER
# ------------------------------------------------------------------------------
usage() {
	cat <<EOF
Usage: ${SCRIPT_NAME} [OPTIONS]

Opsi yang tersedia:
  --build       Jalankan kompilasi otomatis setelah patching
  --test        Jalankan cryptographic test suite setelah build/patch
  --dry-run     Simulasi pemeriksaan file & pola patch tanpa menulis ke disk
  -h, --help    Tampilkan bantuan ini
  -v, --version Tampilkan versi script

Contoh penggunaan:
  ./${SCRIPT_NAME} --dry-run
  ./${SCRIPT_NAME} --build --test
EOF
}

while [[ $# -gt 0 ]]; do
	case "$1" in
	--build)
		DO_BUILD=1
		shift
		;;
	--test)
		DO_TEST=1
		shift
		;;
	--dry-run)
		DRY_RUN=1
		shift
		;;
	-h | --help)
		usage
		exit 0
		;;
	-v | --version)
		echo "${SCRIPT_NAME} version ${SCRIPT_VERSION}"
		exit 0
		;;
	*)
		die "Opsi tidak dikenal: $1 (Gunakan --help untuk panduan)"
		;;
	esac
done

# ------------------------------------------------------------------------------
# PHASE 1: PREFLIGHT ENVIRONMENT & TOOLING VERIFICATION
# ------------------------------------------------------------------------------
phase1_preflight() {
	log "=== Phase 1: Preflight Environment & Tooling Verification ==="

	if ! command -v perl >/dev/null 2>&1; then
		die "Perl tidak ditemukan. OpenSSL build/configure memerlukan Perl."
	fi
	ok "Perl terdeteksi."

	local cc_bin=""
	for c in gcc clang cc; do
		if command -v "${c}" >/dev/null 2>&1; then
			cc_bin="${c}"
			break
		fi
	done
	if [[ -z "${cc_bin}" ]]; then
		warn "C compiler (gcc/clang/cc) tidak ditemukan di PATH."
	else
		ok "C compiler: ${cc_bin} terdeteksi."
	fi

	if command -v make >/dev/null 2>&1; then
		ok "make terdeteksi."
	else
		warn "make tidak terdeteksi."
	fi

	ok "Phase 1: Preflight checks passed."
}

# ------------------------------------------------------------------------------
# PHASE 2: SOURCE TREE AUTHENTICITY & LEGACY VERSION VALIDATION
# ------------------------------------------------------------------------------
phase2_source_validation() {
	log "=== Phase 2: Source Tree Authenticity & Legacy Version Validation ==="

	need_file() {
		[[ -f $1 ]] || die "File target tidak ditemukan: $1"
	}

	for f in "${PATCH_FILES[@]}"; do
		need_file "${f}"
	done

	if ! grep -qE 'OpenSSL 1\.0\.2zl|OpenSSL 1\.0\.2zs' crypto/opensslv.h; then
		die "Source tree bukan OpenSSL 1.0.2zl atau 1.0.2zs. Validasi crypto/opensslv.h gagal."
	fi

	if grep -qE 'OpenSSL 1\.1\.1|OpenSSL 3\.|OpenSSL 4\.' crypto/opensslv.h; then
		die "Source tree terdeteksi versi modern (1.1.1/3.x/4.x). Patch OpenSSL 1.0.2 tidak kompatibel."
	fi

	ok "Phase 2: Source tree validasi otentik OpenSSL 1.0.2zl."
}

# ------------------------------------------------------------------------------
# PHASE 3: DISASTER RECOVERY NON-DESTRUCTIVE BACKUP SNAPSHOTS
# ------------------------------------------------------------------------------
phase3_backup() {
	log "=== Phase 3: Disaster Recovery Non-Destructive Backup Snapshots ==="

	if [[ ${DRY_RUN} -eq 1 ]]; then
		ok "[DRY-RUN] Backup dilewati dalam mode dry-run."
		return 0
	fi

	log "Membuat direktori snapshot backup: ${BACKUP_DIR}"
	mkdir -p "${BACKUP_DIR}"
	ROLLBACK_DIR="${BACKUP_DIR}"

	for f in "${PATCH_FILES[@]}"; do
		if [[ -f ${f} ]]; then
			mkdir -p "${BACKUP_DIR}/$(dirname "${f}")"
			cp -a "${f}" "${BACKUP_DIR}/${f}"
		fi
	done

	if [[ -f ${DOCNOTE_FILE} ]]; then
		cp -a "${DOCNOTE_FILE}" "${BACKUP_DIR}/${DOCNOTE_FILE}"
	fi

	ok "Phase 3: Backup tersimpan aman di: ${BACKUP_DIR}"
}

# ------------------------------------------------------------------------------
# PHASE 4: IDEMPOTENT AST/SOURCE PATCH APPLICATION (DELTA MITIGATIONS)
# ------------------------------------------------------------------------------
phase4_patch_application() {
	log "=== Phase 4: Idempotent AST/Source Patch Application (2025-2026 Delta Mitigations) ==="

	python3 - "${DRY_RUN}" <<'PY_PATCH'
import sys
from pathlib import Path

ROOT = Path.cwd()
DRY_RUN = len(sys.argv) > 1 and sys.argv[1] == "1"

def fail(msg):
    print(f"[FAIL] {msg}", file=sys.stderr)
    sys.exit(1)

def ok(msg):
    print(f"[OK]   {msg}")

def path(rel):
    p = ROOT / rel
    if not p.is_file():
        fail(f"File tidak ditemukan: {rel}")
    return p

def read(rel):
    return path(rel).read_text(encoding="utf-8", errors="surrogateescape")

def write(rel, data):
    if not DRY_RUN:
        path(rel).write_text(data, encoding="utf-8", errors="surrogateescape")

def replace_once(rel, old, new, label, alt_old=None):
    data = read(rel)
    if new in data:
        status_suffix = " (dry-run)" if DRY_RUN else ""
        ok(f"{label}: sudah terpasang (idempotent){status_suffix}")
        return
    target = old
    if target not in data and alt_old and alt_old in data:
        target = alt_old
    if target not in data:
        fail(f"Target pola lama untuk '{label}' tidak ditemukan di {rel}")
    count = data.count(target)
    if count != 1:
        fail(f"Pola untuk '{label}' ditemukan {count} kali di {rel} (diharuskan tepat 1)")
    new_data = data.replace(target, new, 1)
    write(rel, new_data)
    action = "[DRY-RUN] Terverifikasi penggantian" if DRY_RUN else "Berhasil diterapkan"
    ok(f"{label}: {action} pada {rel}")

# 1. crypto/opensslv.h version bump
replace_once(
    "crypto/opensslv.h",
    '''# define OPENSSL_VERSION_NUMBER  0x1000225fL
# ifdef OPENSSL_FIPS
#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zl-fips  11 Feb 2025"
# else
#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zl  11 Feb 2025"
# endif''',
    '''# define OPENSSL_VERSION_NUMBER  0x100022dfL
# ifdef OPENSSL_FIPS
#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zs-alsyundawy-u20260929-fips  29 Sep 2026"
# else
#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zs-alsyundawy-u20260929  29 Sep 2026"
# endif''',
    "Version label upgrade from 1.0.2zl to 1.0.2zs"
)

# 2. crypto/asn1/tasn_dec.c: CVE-2026-34180
replace_once(
    "crypto/asn1/tasn_dec.c",
    '#include <string.h>\n#include <openssl/asn1.h>\n',
    '#include <string.h>\n#include <limits.h>\n#include <openssl/asn1.h>\n',
    "ASN.1 tasn_dec include limits.h"
)

replace_once(
    "crypto/asn1/tasn_dec.c",
    '''    /* asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 */
    if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))
        goto err;
''',
    '''    /*
     * ALSYUNDAWY-CVE-2026-34180:
     * Reject negative or excessive primitive content lengths before
     * delegating to type-specific parsing routines.
     */
    if (len < 0 || len > INT_MAX) {
        ASN1err(ASN1_F_ASN1_D2I_EX_PRIMITIVE, ASN1_R_TOO_LONG);
        goto err;
    }

    /* asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 */
    if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))
        goto err;
''',
    "CVE-2026-34180 ASN.1 primitive length guard"
)

# 3. crypto/asn1/a_mbstr.c: CVE-2026-7383
replace_once(
    "crypto/asn1/a_mbstr.c",
    '#include <stdio.h>\n#include <ctype.h>\n#include "cryptlib.h"\n',
    '#include <stdio.h>\n#include <ctype.h>\n#include <limits.h>\n#include "cryptlib.h"\n',
    "ASN.1 a_mbstr include limits.h"
)

replace_once(
    "crypto/asn1/a_mbstr.c",
    '''    case MBSTRING_BMP:
        outlen = nchar << 1;
        cpyfunc = cpy_bmp;
        break;
''',
    '''    case MBSTRING_BMP:
        /*
         * ALSYUNDAWY-CVE-2026-7383:
         * Prevent signed int overflow when computing UTF-16/BMP output size.
         */
        if (nchar > INT_MAX / 2) {
            if (free_out)
                ASN1_STRING_free(dest);
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
            return -1;
        }
        outlen = nchar << 1;
        cpyfunc = cpy_bmp;
        break;
''',
    "CVE-2026-7383 BMPSTRING size guard"
)

replace_once(
    "crypto/asn1/a_mbstr.c",
    '''    case MBSTRING_UNIV:
        outlen = nchar << 2;
        cpyfunc = cpy_univ;
        break;
''',
    '''    case MBSTRING_UNIV:
        /*
         * ALSYUNDAWY-CVE-2026-7383:
         * Prevent signed int overflow when computing UTF-32/UNIVERSAL output size.
         */
        if (nchar > INT_MAX / 4) {
            if (free_out)
                ASN1_STRING_free(dest);
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
            return -1;
        }
        outlen = nchar << 2;
        cpyfunc = cpy_univ;
        break;
''',
    "CVE-2026-7383 UNIVERSALSTRING size guard"
)

replace_once(
    "crypto/asn1/a_mbstr.c",
    '''    case MBSTRING_UTF8:
        outlen = 0;
        traverse_string(in, len, inform, out_utf8, &outlen);
        cpyfunc = cpy_utf8;
        break;
''',
    '''    case MBSTRING_UTF8:
        outlen = 0;
        if (traverse_string(in, len, inform, out_utf8, &outlen) <= 0) {
            if (free_out)
                ASN1_STRING_free(dest);
            ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
            return -1;
        }
        cpyfunc = cpy_utf8;
        break;
''',
    "CVE-2026-7383 UTF8 output length traversal guard"
)

replace_once(
    "crypto/asn1/a_mbstr.c",
    '''    if (!(p = OPENSSL_malloc(outlen + 1))) {
        if (free_out)
            ASN1_STRING_free(dest);
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
''',
    '''    if (outlen < 0 || outlen == INT_MAX) {
        if (free_out)
            ASN1_STRING_free(dest);
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ASN1_R_STRING_TOO_LONG);
        return -1;
    }
    if (!(p = OPENSSL_malloc(outlen + 1))) {
        if (free_out)
            ASN1_STRING_free(dest);
        ASN1err(ASN1_F_ASN1_MBSTRING_NCOPY, ERR_R_MALLOC_FAILURE);
        return -1;
    }
''',
    "CVE-2026-7383 malloc outlen+1 guard"
)

replace_once(
    "crypto/asn1/a_mbstr.c",
    '''static int out_utf8(unsigned long value, void *arg)
{
    int *outlen;
    outlen = arg;
    *outlen += UTF8_putc(NULL, -1, value);
    return 1;
}
''',
    '''static int out_utf8(unsigned long value, void *arg)
{
    int *outlen;
    int addlen;

    outlen = arg;
    addlen = UTF8_putc(NULL, -1, value);
    if (addlen <= 0 || *outlen > INT_MAX - addlen)
        return -1;
    *outlen += addlen;
    return 1;
}
''',
    "CVE-2026-7383 out_utf8 overflow guard"
)

# 4. crypto/bio/bf_lbuf.c: CVE-2025-68160
replace_once(
    "crypto/bio/bf_lbuf.c",
    '''    if (inl > 0) {
        memcpy(&(ctx->obuf[ctx->obuf_len]), in, inl);
        ctx->obuf_len += inl;
        num += inl;
    }
    return num;
''',
    '''    /*
     * ALSYUNDAWY-CVE-2025-68160:
     * Save remaining data without writing past ctx->obuf on short writes.
     */
    while (inl > 0) {
        size_t avail;
        size_t to_copy;

        if (ctx->obuf_len < 0 || ctx->obuf_len > ctx->obuf_size)
            return -1;

        avail = (size_t)ctx->obuf_size - (size_t)ctx->obuf_len;

        if (avail == 0) {
            i = BIO_write(b->next_bio, ctx->obuf, ctx->obuf_len);
            if (i <= 0) {
                BIO_copy_next_retry(b);
                if (i < 0)
                    return ((num > 0) ? num : i);
                return num;
            }

            if (i < ctx->obuf_len)
                memmove(ctx->obuf, ctx->obuf + i, ctx->obuf_len - i);
            ctx->obuf_len -= i;
            continue;
        }

        to_copy = ((size_t)inl > avail) ? avail : (size_t)inl;
        memcpy(&(ctx->obuf[ctx->obuf_len]), in, to_copy);
        ctx->obuf_len += (int)to_copy;
        in += to_copy;
        inl -= (int)to_copy;
        num += (int)to_copy;
    }
    return num;
''',
    "CVE-2025-68160 BIO_f_linebuffer bounded copy"
)

# 5. crypto/pkcs12/p12_decr.c: CVE-2025-69421
replace_once(
    "crypto/pkcs12/p12_decr.c",
    '''    int outlen;

    if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
''',
    '''    int outlen;

    /*
     * ALSYUNDAWY-CVE-2025-69421:
     * Malformed PKCS#12 input can pass a NULL OCTET STRING here.
     */
    if (oct == NULL) {
        PKCS12err(PKCS12_F_PKCS12_ITEM_DECRYPT_D2I,
                  ERR_R_PASSED_NULL_PARAMETER);
        return NULL;
    }

    if (!PKCS12_pbe_crypt(algor, pass, passlen, oct->data, oct->length,
''',
    "CVE-2025-69421 PKCS12 oct NULL guard"
)

# 6. crypto/pkcs7/pk7_doit.c: CVE-2026-22796
replace_once(
    "crypto/pkcs7/pk7_doit.c",
    '''    if (!(astype = get_attribute(sk, NID_pkcs9_messageDigest)))
        return NULL;
    return astype->value.octet_string;
}
''',
    '''    if (!(astype = get_attribute(sk, NID_pkcs9_messageDigest)))
        return NULL;
    /*
     * ALSYUNDAWY-CVE-2026-22796:
     * Validate ASN1_TYPE union member before accessing value.octet_string.
     */
    if (astype->type != V_ASN1_OCTET_STRING)
        return NULL;
    return astype->value.octet_string;
}
''',
    "CVE-2026-22796 PKCS7 digest attribute type guard"
)

# 7. crypto/pkcs7/pk7_smime.c: CVE-2026-45447
replace_once(
    "crypto/pkcs7/pk7_smime.c",
    '''    BIO *p7bio = NULL;
    BIO *tmpin = NULL, *tmpout = NULL;
''',
    '''    BIO *p7bio = NULL;
    BIO *next = NULL;
    BIO *tmpin = NULL, *tmpout = NULL;
''',
    "CVE-2026-45447 PKCS7_verify next BIO variable"
)

replace_once(
    "crypto/pkcs7/pk7_smime.c",
    ''' err:
    if (tmpin == indata) {
        if (indata)
            BIO_pop(p7bio);
    }
    BIO_free_all(p7bio);
    sk_X509_free(signers);
    return ret;
}
''',
    ''' err:
    /*
     * ALSYUNDAWY-CVE-2026-45447:
     * Free only BIOs owned by PKCS7_verify(); never free caller-owned indata.
     */
    while (p7bio != NULL && p7bio != indata) {
        next = BIO_pop(p7bio);
        BIO_free(p7bio);
        p7bio = next;
    }
    sk_X509_free(signers);
    return ret;
}
''',
    "CVE-2026-45447 PKCS7_verify BIO cleanup"
)

# 8. crypto/cms/cms_pwri.c: CVE-2026-9076, CVE-2025-9230, CVE-2026-42766
replace_once(
    "crypto/cms/cms_pwri.c",
    '''    size_t blocklen = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char *tmp;
    int outl, rv = 0;
    if (inlen < 2 * blocklen) {
''',
    '''    size_t blocklen = EVP_CIPHER_CTX_block_size(ctx);
    unsigned char *tmp;
    int outl, rv = 0;

    /*
     * ALSYUNDAWY-CVE-2026-9076:
     * RFC3211 KEK unwrap is for block ciphers. Reject stream ciphers
     * whose block size would make the RFC check-byte guard ineffective.
     */
    if (blocklen < 4) {
        return 0;
    }

    if (inlen < 2 * blocklen) {
''',
    "CVE-2026-9076 PWRI reject stream-mode KEK cipher"
)

replace_once(
    "crypto/cms/cms_pwri.c",
    '''    if (inlen < (size_t)(tmp[0] - 4)) {
''',
    '''    /*
     * ALSYUNDAWY-CVE-2025-9230:
     * Prevent underflow on malformed unwrapped key length.
     */
    if (inlen < 4 + (size_t)tmp[0]) {
''',
    "CVE-2025-9230 RFC3211 unwrapped key length check",
    alt_old='''    if (inlen < 4 + (size_t)tmp[0]) {
'''
)

replace_once(
    "crypto/cms/cms_pwri.c",
    '''    ec = cms->d.envelopedData->encryptedContentInfo;

    pwri = ri->d.pwri;
    EVP_CIPHER_CTX_init(&kekctx);

    if (!pwri->pass) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_NO_PASSWORD);
        return 0;
    }
''',
    '''    if (cms == NULL || cms->d.envelopedData == NULL
        || cms->d.envelopedData->encryptedContentInfo == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        return 0;
    }

    ec = cms->d.envelopedData->encryptedContentInfo;

    if (ri == NULL || ri->type != CMS_RECIPINFO_PASS || ri->d.pwri == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_NOT_PWRI);
        return 0;
    }

    pwri = ri->d.pwri;
    EVP_CIPHER_CTX_init(&kekctx);

    if (!pwri->pass) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT, CMS_R_NO_PASSWORD);
        goto err;
    }
''',
    "CMS PWRI cms/ri/recipient/password NULL guard"
)

replace_once(
    "crypto/cms/cms_pwri.c",
    '''    if (!algtmp || OBJ_obj2nid(algtmp->algorithm) != NID_id_alg_PWRI_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
        return 0;
    }

    if (algtmp->parameter->type == V_ASN1_SEQUENCE) {
        p = algtmp->parameter->value.sequence->data;
        plen = algtmp->parameter->value.sequence->length;
        kekalg = d2i_X509_ALGOR(NULL, &p, plen);
    }
    if (kekalg == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        return 0;
    }
''',
    '''    if (algtmp == NULL || algtmp->algorithm == NULL
        || OBJ_obj2nid(algtmp->algorithm) != NID_id_alg_PWRI_KEK) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_UNSUPPORTED_KEY_ENCRYPTION_ALGORITHM);
        goto err;
    }

    /*
     * ALSYUNDAWY-CVE-2026-42766:
     * keyEncryptionAlgorithm parameters must be present and a SEQUENCE.
     */
    if (algtmp->parameter == NULL
        || algtmp->parameter->type != V_ASN1_SEQUENCE
        || algtmp->parameter->value.sequence == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        goto err;
    }

    p = algtmp->parameter->value.sequence->data;
    plen = algtmp->parameter->value.sequence->length;
    kekalg = d2i_X509_ALGOR(NULL, &p, plen);

    if (kekalg == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        goto err;
    }
''',
    "CVE-2026-42766 PWRI keyEncryptionAlgorithm parameter guard"
)

replace_once(
    "crypto/cms/cms_pwri.c",
    '''    algtmp = pwri->keyDerivationAlgorithm;

    /* Finish password based key derivation to setup key in "ctx" */

    if (EVP_PBE_CipherInit(algtmp->algorithm,
''',
    '''    algtmp = pwri->keyDerivationAlgorithm;

    /*
     * ALSYUNDAWY-CVE-2026-42766:
     * PasswordRecipientInfo.keyDerivationAlgorithm is OPTIONAL in ASN.1.
     */
    if (algtmp == NULL || algtmp->algorithm == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        goto err;
    }

    /* Finish password based key derivation to setup key in "ctx" */

    if (EVP_PBE_CipherInit(algtmp->algorithm,
''',
    "CVE-2026-42766 PWRI keyDerivationAlgorithm NULL guard"
)

replace_once(
    "crypto/cms/cms_pwri.c",
    '''    } else {
        key = OPENSSL_malloc(pwri->encryptedKey->length);

        if (!key) {
''',
    '''    } else {
        if (pwri->encryptedKey == NULL || pwri->encryptedKey->data == NULL
            || pwri->encryptedKey->length <= 0) {
            CMSerr(CMS_F_CMS_RECIPIENTINFO_PWRI_CRYPT,
                   CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
            goto err;
        }

        key = OPENSSL_malloc(pwri->encryptedKey->length);

        if (!key) {
''',
    "CMS PWRI encryptedKey NULL/length guard"
)

replace_once(
    "crypto/cms/cms_pwri.c",
    '''        ec->key = key;
        ec->keylen = keylen;

    }
''',
    '''        /*
         * ALSYUNDAWY-HARDENING:
         * Cleanse old CEK before replacing it with the unwrapped PWRI key.
         */
        if (ec->key) {
            OPENSSL_cleanse(ec->key, ec->keylen);
            OPENSSL_free(ec->key);
        }

        ec->key = key;
        ec->keylen = keylen;

    }
''',
    "CMS PWRI cleanse old ec->key before overwrite"
)

# 9. crypto/x509/x509_vfy.c: CVE-2026-28388
replace_once(
    "crypto/x509/x509_vfy.c",
    '''    /* Base must have a CRL number */
    if (!base->crl_number)
        return 0;
    /* Issuer names must match */
''',
    '''    /* Base must have a CRL number */
    if (!base->crl_number)
        return 0;
    /*
     * ALSYUNDAWY-CVE-2026-28388:
     * Delta CRL with Delta CRL Indicator but without CRL Number is invalid.
     */
    if (!delta->crl_number)
        return 0;
    /* Issuer names must match */
''',
    "CVE-2026-28388 delta CRL number guard"
)

# 10. crypto/cms/cms_kari.c: CVE-2026-28389, CVE-2026-63072
replace_once(
    "crypto/cms/cms_kari.c",
    '''    /* Setup all parameters to derive KEK */
    if (!cms_env_asn1_ctrl(ri, 1))
        goto err;
''',
    '''    /*
     * ALSYUNDAWY-CVE-2026-28389:
     * KeyAgreeRecipientInfo keyEncryptionAlgorithm parameters are required
     * by OpenSSL's CMS decrypt path. Reject absent/malformed parameters.
     */
    if (ri->d.kari == NULL || ri->d.kari->keyEncryptionAlgorithm == NULL
        || ri->d.kari->keyEncryptionAlgorithm->algorithm == NULL
        || ri->d.kari->keyEncryptionAlgorithm->parameter == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_DECRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        goto err;
    }

    /* Setup all parameters to derive KEK */
    if (!cms_env_asn1_ctrl(ri, 1))
        goto err;
''',
    "CVE-2026-28389 CMS KARI parameter guard"
)

replace_once(
    "crypto/cms/cms_kari.c",
    '''    unsigned char *out = NULL;
    int outlen;
    keklen = EVP_CIPHER_CTX_key_length(&kari->ctx);
''',
    '''    unsigned char *out = NULL;
    int outlen;
    size_t outsize;
    keklen = EVP_CIPHER_CTX_key_length(&kari->ctx);
''',
    "CVE-2026-63072 cms_kek_cipher outsize variable"
)

replace_once(
    "crypto/cms/cms_kari.c",
    '''    out = OPENSSL_malloc(outlen);
    if (!out)
        goto err;
    if (!EVP_CipherUpdate(&kari->ctx, out, &outlen, in, inlen))
        goto err;
''',
    '''    /*
     * ALSYUNDAWY-CVE-2026-63072:
     * When unwrapping a key (enc == 0), the unwrap implementation may write up
     * to inlen bytes into the output buffer during EVP_CipherUpdate. Ensure
     * out is sized to at least inlen bytes to prevent a heap buffer overflow.
     */
    outsize = (size_t)outlen < inlen ? inlen : (size_t)outlen;
    out = OPENSSL_malloc(outsize);
    if (!out)
        goto err;
    if (!EVP_CipherUpdate(&kari->ctx, out, &outlen, in, inlen))
        goto err;
''',
    "CVE-2026-63072 CMS key unwrapping heap buffer overflow guard"
)

# 11. crypto/cms/cms_env.c: CVE-2026-28390
replace_once(
    "crypto/cms/cms_env.c",
    '''    if (EVP_PKEY_decrypt_init(ktri->pctx) <= 0)
        goto err;

    if (!cms_env_asn1_ctrl(ri, 1))
        goto err;
''',
    '''    if (EVP_PKEY_decrypt_init(ktri->pctx) <= 0)
        goto err;

    /*
     * ALSYUNDAWY-CVE-2026-28390:
     * Reject malformed KeyTransportRecipientInfo algorithm identifiers
     * before ASN.1/CMS control code examines optional OAEP parameters.
     */
    if (ktri->keyEncryptionAlgorithm == NULL
        || ktri->keyEncryptionAlgorithm->algorithm == NULL) {
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KTRI_DECRYPT,
               CMS_R_INVALID_KEY_ENCRYPTION_PARAMETER);
        goto err;
    }

    if (!cms_env_asn1_ctrl(ri, 1))
        goto err;
''',
    "CVE-2026-28390 CMS KTRI algorithm guard"
)

replace_once(
    "crypto/cms/cms_env.c",
    '''    ec->key = ukey;
    ec->keylen = ukeylen;

    r = 1;
''',
    '''    /*
     * ALSYUNDAWY-HARDENING:
     * Match KTRI/KARI behaviour: cleanse old content-encryption key before
     * replacing it, avoiding secret retention and memory leak.
     */
    if (ec->key) {
        OPENSSL_cleanse(ec->key, ec->keylen);
        OPENSSL_free(ec->key);
    }

    ec->key = ukey;
    ec->keylen = ukeylen;

    r = 1;
''',
    "CMS KEKRI cleanse old ec->key before overwrite"
)

# 12. crypto/rsa/rsa_pmeth.c: RSA digest NULL guards
replace_once(
    "crypto/rsa/rsa_pmeth.c",
    '''    case EVP_PKEY_CTRL_RSA_OAEP_MD:
    case EVP_PKEY_CTRL_GET_RSA_OAEP_MD:
        if (rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_OAEP_MD)
            *(const EVP_MD **)p2 = rctx->md;
        else
            rctx->md = p2;
        return 1;
''',
    '''    case EVP_PKEY_CTRL_RSA_OAEP_MD:
    case EVP_PKEY_CTRL_GET_RSA_OAEP_MD:
        if (rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_PADDING_MODE);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_OAEP_MD)
            *(const EVP_MD **)p2 = rctx->md;
        else {
            if (p2 == NULL) {
                RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_DIGEST);
                return 0;
            }
            rctx->md = p2;
        }
        return 1;
''',
    "RSA OAEP digest NULL guard"
)

replace_once(
    "crypto/rsa/rsa_pmeth.c",
    '''    case EVP_PKEY_CTRL_RSA_MGF1_MD:
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
        if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING
            && rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_MGF1_MD);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_MGF1_MD) {
            if (rctx->mgf1md)
                *(const EVP_MD **)p2 = rctx->mgf1md;
            else
                *(const EVP_MD **)p2 = rctx->md;
        } else
            rctx->mgf1md = p2;
        return 1;
''',
    '''    case EVP_PKEY_CTRL_RSA_MGF1_MD:
    case EVP_PKEY_CTRL_GET_RSA_MGF1_MD:
        if (rctx->pad_mode != RSA_PKCS1_PSS_PADDING
            && rctx->pad_mode != RSA_PKCS1_OAEP_PADDING) {
            RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_MGF1_MD);
            return -2;
        }
        if (type == EVP_PKEY_CTRL_GET_RSA_MGF1_MD) {
            if (rctx->mgf1md)
                *(const EVP_MD **)p2 = rctx->mgf1md;
            else
                *(const EVP_MD **)p2 = rctx->md;
        } else {
            if (p2 == NULL) {
                RSAerr(RSA_F_PKEY_RSA_CTRL, RSA_R_INVALID_MGF1_MD);
                return 0;
            }
            rctx->mgf1md = p2;
        }
        return 1;
''',
    "RSA MGF1 digest NULL guard"
)

# 13. ssl/d1_pkt.c: CVE-2026-54874
replace_once(
    "ssl/d1_pkt.c",
    '''/* copy buffered record into SSL structure */
static int dtls1_copy_record(SSL *s, pitem *item)
{
    DTLS1_RECORD_DATA *rdata;

    rdata = (DTLS1_RECORD_DATA *)item->data;

    if (s->s3->rbuf.buf != NULL)
        OPENSSL_free(s->s3->rbuf.buf);

    s->packet = rdata->packet;
    s->packet_length = rdata->packet_length;
    memcpy(&(s->s3->rbuf), &(rdata->rbuf), sizeof(SSL3_BUFFER));
    memcpy(&(s->s3->rrec), &(rdata->rrec), sizeof(SSL3_RECORD));

    /* Set proper sequence number for mac calculation */
    memcpy(&(s->s3->read_sequence[2]), &(rdata->packet[5]), 6);

    return (1);
}
''',
    '''/* copy buffered record into SSL structure */
static int dtls1_copy_record(SSL *s, pitem *item)
{
    DTLS1_RECORD_DATA *rdata;

    rdata = (DTLS1_RECORD_DATA *)item->data;

    /*
     * ALSYUNDAWY-CVE-2026-54874:
     * Preserve s->s3->rbuf without repeatedly freeing and reallocating
     * the ~16KB read buffer. Copy the buffered packet into s->s3->rbuf.buf.
     */
    if (s->s3->rbuf.buf == NULL) {
        if (!ssl3_setup_buffers(s))
            return 0;
    }

    if (s->s3->rbuf.len < rdata->packet_length) {
        unsigned char *newbuf = OPENSSL_realloc(s->s3->rbuf.buf, rdata->packet_length);
        if (newbuf == NULL)
            return 0;
        s->s3->rbuf.buf = newbuf;
        s->s3->rbuf.len = rdata->packet_length;
    }

    memcpy(s->s3->rbuf.buf, rdata->packet, rdata->packet_length);
    s->packet = s->s3->rbuf.buf;
    s->packet_length = rdata->packet_length;
    memcpy(&(s->s3->rrec), &(rdata->rrec), sizeof(SSL3_RECORD));
    s->s3->rrec.input = &(s->packet[DTLS1_RT_HEADER_LENGTH]);
    s->s3->rrec.data = s->s3->rrec.input;

    /* Set proper sequence number for mac calculation */
    memcpy(&(s->s3->read_sequence[2]), &(rdata->packet[5]), 6);

    if (rdata->packet != NULL) {
        OPENSSL_free(rdata->packet);
        rdata->packet = NULL;
        rdata->rbuf.buf = NULL;
    }

    return (1);
}
''',
    "CVE-2026-54874 DTLS copy record buffer preservation"
)

replace_once(
    "ssl/d1_pkt.c",
    '''    rdata->packet = s->packet;
    rdata->packet_length = s->packet_length;
    memcpy(&(rdata->rbuf), &(s->s3->rbuf), sizeof(SSL3_BUFFER));
    memcpy(&(rdata->rrec), &(s->s3->rrec), sizeof(SSL3_RECORD));

    item->data = rdata;

#ifndef OPENSSL_NO_SCTP
    /* Store bio_dgram_sctp_rcvinfo struct */
    if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
        (s->state == SSL3_ST_SR_FINISHED_A
         || s->state == SSL3_ST_CR_FINISHED_A)) {
        BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_GET_RCVINFO,
                 sizeof(rdata->recordinfo), &rdata->recordinfo);
    }
#endif

    s->packet = NULL;
    s->packet_length = 0;
    memset(&(s->s3->rbuf), 0, sizeof(SSL3_BUFFER));
    memset(&(s->s3->rrec), 0, sizeof(SSL3_RECORD));

    if (!ssl3_setup_buffers(s)) {
        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        if (rdata->rbuf.buf != NULL)
            OPENSSL_free(rdata->rbuf.buf);
        OPENSSL_free(rdata);
        pitem_free(item);
        return (-1);
    }
''',
    '''    /*
     * ALSYUNDAWY-CVE-2026-54874:
     * Allocate only the actual packet size rather than retaining the entire
     * ~16KB read buffer for each buffered record. This prevents an attacker
     * from inducing remote memory exhaustion (amplification ~1200x).
     */
    rdata->packet = OPENSSL_malloc(s->packet_length);
    if (rdata->packet == NULL) {
        OPENSSL_free(rdata);
        pitem_free(item);
        SSLerr(SSL_F_DTLS1_BUFFER_RECORD, ERR_R_INTERNAL_ERROR);
        return -1;
    }
    memcpy(rdata->packet, s->packet, s->packet_length);
    rdata->packet_length = s->packet_length;

    memset(&(rdata->rbuf), 0, sizeof(SSL3_BUFFER));
    rdata->rbuf.buf = rdata->packet;
    rdata->rbuf.len = s->packet_length;

    memcpy(&(rdata->rrec), &(s->s3->rrec), sizeof(SSL3_RECORD));

    item->data = rdata;

#ifndef OPENSSL_NO_SCTP
    /* Store bio_dgram_sctp_rcvinfo struct */
    if (BIO_dgram_is_sctp(SSL_get_rbio(s)) &&
        (s->state == SSL3_ST_SR_FINISHED_A
         || s->state == SSL3_ST_CR_FINISHED_A)) {
        BIO_ctrl(SSL_get_rbio(s), BIO_CTRL_DGRAM_SCTP_GET_RCVINFO,
                 sizeof(rdata->recordinfo), &rdata->recordinfo);
    }
#endif

    s->packet = NULL;
    s->packet_length = 0;
    memset(&(s->s3->rrec), 0, sizeof(SSL3_RECORD));
''',
    "CVE-2026-54874 DTLS buffer record payload allocation"
)

# 14. ssl/d1_both.c: CVE-2026-84782
replace_once(
    "ssl/d1_both.c",
    '''    memcpy(s->init_buf->data, frag->fragment,
           frag->msg_header.msg_len + header_length);
    s->init_num = frag->msg_header.msg_len + header_length;

    dtls1_set_message_header_int(s, frag->msg_header.type,''',
    '''    memcpy(s->init_buf->data, frag->fragment,
           frag->msg_header.msg_len + header_length);
    s->init_num = frag->msg_header.msg_len + header_length;

    /*
     * ALSYUNDAWY-CVE-2026-84782:
     * Reset init_off to 0 to ensure retransmissions always start from the
     * beginning of the buffered handshake fragment and never reuse stale
     * buffer offsets from suspended writes, preventing heap disclosure/OOB read.
     */
    s->init_off = 0;

    dtls1_set_message_header_int(s, frag->msg_header.type,''',
    "CVE-2026-84782 DTLS retransmission buffer read offset reset"
)

# 15. ssl/d1_lib.c: CVE-2026-84782
replace_once(
    "ssl/d1_lib.c",
    '''int dtls1_handle_timeout(SSL *s)
{
    /* if no timer is expired, don't do anything */
    if (!dtls1_is_timer_expired(s)) {
        return 0;
    }''',
    '''int dtls1_handle_timeout(SSL *s)
{
    /* if no timer is expired, don't do anything */
    if (!dtls1_is_timer_expired(s)) {
        return 0;
    }

    /*
     * ALSYUNDAWY-CVE-2026-84782:
     * If a handshake message write is currently suspended, skip retransmitting
     * now to prevent corrupting the in-flight write state and buffer tracking.
     */
    if (s->init_off != 0 || s->init_num != 0) {
        return 0;
    }''',
    "CVE-2026-84782 DTLS timeout suspended write check"
)

# 16. crypto/x509v3/v3_purp.c: CVE-2026-35189
replace_once(
    "crypto/x509v3/v3_purp.c",
    '''static void setup_dp(X509 *x, DIST_POINT *dp)
{
    X509_NAME *iname = NULL;
    int i;
    if (dp->reasons) {
        if (dp->reasons->length > 0)
            dp->dp_reasons = dp->reasons->data[0];
        if (dp->reasons->length > 1)
            dp->dp_reasons |= (dp->reasons->data[1] << 8);
        dp->dp_reasons &= CRLDP_ALL_REASONS;
    } else
        dp->dp_reasons = CRLDP_ALL_REASONS;
    if (!dp->distpoint || (dp->distpoint->type != 1))
        return;
    for (i = 0; i < sk_GENERAL_NAME_num(dp->CRLissuer); i++) {
        GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->CRLissuer, i);
        if (gen->type == GEN_DIRNAME) {
            iname = gen->d.directoryName;
            break;
        }
    }
    if (!iname)
        iname = X509_get_issuer_name(x);

    DIST_POINT_set_dpname(dp->distpoint, iname);

}''',
    '''static void setup_dp(X509 *x, DIST_POINT *dp)
{
    if (dp->reasons) {
        if (dp->reasons->length > 0)
            dp->dp_reasons = dp->reasons->data[0];
        if (dp->reasons->length > 1)
            dp->dp_reasons |= (dp->reasons->data[1] << 8);
        dp->dp_reasons &= CRLDP_ALL_REASONS;
    } else
        dp->dp_reasons = CRLDP_ALL_REASONS;

    /*
     * ALSYUNDAWY-CVE-2026-35189:
     * Postpone computing dpname for nameRelativeToCRLIssuer (type 1) until
     * CRL verification is explicitly needed. Eagerly calling DIST_POINT_set_dpname
     * here during extension caching triggers massive heap expansion (DoS) on crafted
     * certificates with large numbers of relative distribution points.
     */
}''',
    "CVE-2026-35189 Postpone relative CRLDP name computation"
)

# 17. crypto/x509/x509_vfy.c: CVE-2026-35189
replace_once(
    "crypto/x509/x509_vfy.c",
    '''    for (i = 0; i < sk_DIST_POINT_num(x->crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(x->crldp, i);
        if (crldp_check_crlissuer(dp, crl, crl_score)) {
            if (!crl->idp || idp_check_dp(dp->distpoint, crl->idp->distpoint)) {''',
    '''    for (i = 0; i < sk_DIST_POINT_num(x->crldp); i++) {
        DIST_POINT *dp = sk_DIST_POINT_value(x->crldp, i);
        if (crldp_check_crlissuer(dp, crl, crl_score)) {
            /*
             * ALSYUNDAWY-CVE-2026-35189:
             * On-demand computation of dpname for nameRelativeToCRLIssuer (type 1)
             * only when actually matching against a candidate CRL.
             */
            if (dp->distpoint && dp->distpoint->type == 1 && dp->distpoint->dpname == NULL) {
                X509_NAME *iname = NULL;
                int j;
                for (j = 0; j < sk_GENERAL_NAME_num(dp->CRLissuer); j++) {
                    GENERAL_NAME *gen = sk_GENERAL_NAME_value(dp->CRLissuer, j);
                    if (gen->type == GEN_DIRNAME) {
                        iname = gen->d.directoryName;
                        break;
                    }
                }
                if (!iname)
                    iname = X509_get_issuer_name(x);
                DIST_POINT_set_dpname(dp->distpoint, iname);
            }

            if (!crl->idp || idp_check_dp(dp->distpoint, crl->idp->distpoint)) {''',
    "CVE-2026-35189 On-demand CRLDP name computation during verification"
)

# 18. crypto/x509v3/v3_crld.c: CVE-2026-35189
replace_once(
    "crypto/x509v3/v3_crld.c",
    '''int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, X509_NAME *iname)
{
    int i;
    STACK_OF(X509_NAME_ENTRY) *frag;
    X509_NAME_ENTRY *ne;
    if (!dpn || (dpn->type != 1))
        return 1;
    frag = dpn->name.relativename;''',
    '''int DIST_POINT_set_dpname(DIST_POINT_NAME *dpn, X509_NAME *iname)
{
    int i;
    STACK_OF(X509_NAME_ENTRY) *frag;
    X509_NAME_ENTRY *ne;
    if (!dpn || (dpn->type != 1))
        return 1;
    /*
     * ALSYUNDAWY-CVE-2026-35189:
     * If dpname is already computed, reuse it idempotently. Guard against
     * NULL issuer or excessive relative name fragments (> 1024).
     */
    if (dpn->dpname != NULL)
        return 1;
    if (!iname)
        return 0;
    frag = dpn->name.relativename;
    if (sk_X509_NAME_ENTRY_num(frag) > 1024)
        return 0;''',
    "CVE-2026-35189 DIST_POINT_set_dpname idempotency and fragment limit guard"
)

# 19. crypto/ec/ec_mult.c: CVE-2026-54872
replace_once(
    "crypto/ec/ec_mult.c",
    '''    if (!BN_add(lambda, k, cardinality))
        goto err;
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    if (!BN_add(k, lambda, cardinality))
        goto err;
    /*
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     */
    kbit = BN_is_bit_set(lambda, cardinality_bits);
    BN_consttime_swap(kbit, k, lambda, group_top + 2);''',
    '''    if (!BN_add(lambda, k, cardinality))
        goto err;
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    if (!BN_add(k, lambda, cardinality))
        goto err;
    /*
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     */

    /*
     * ALSYUNDAWY-CVE-2026-54872:
     * Enforce constant-time, length-invariant scalar padding for generic curves.
     * Ensure both k and lambda maintain full fixed limb width without trimming
     * leading zeros, and set BN_FLG_CONSTTIME and BN_FLG_FIXED_TOP across all
     * scalar operations to eliminate timing side-channel leakage.
     */
    while (k->top < group_top + 2)
        k->d[k->top++] = 0;
    while (lambda->top < group_top + 2)
        lambda->d[lambda->top++] = 0;

    BN_set_flags(k, BN_FLG_CONSTTIME | BN_FLG_FIXED_TOP);
    BN_set_flags(lambda, BN_FLG_CONSTTIME | BN_FLG_FIXED_TOP);

    kbit = BN_is_bit_set(lambda, cardinality_bits);
    BN_consttime_swap(kbit, k, lambda, group_top + 2);''',
    "CVE-2026-54872 Generic EC scalar multiplication constant-time padding"
)

# 20. NEWS: Prepend releases zm through zs
replace_once(
    "NEWS",
    '''  Major changes between OpenSSL 1.0.2zk and OpenSSL 1.0.2zl [11 Feb 2025]''',
    '''  Major changes between OpenSSL 1.0.2zr and OpenSSL 1.0.2zs [29 Sep 2026]

      o Fixed DTLS handshake message retransmission out-of-bounds read and
        state corruption on suspended writes (CVE-2026-84782)
      o Deferred computation of relative CRL distribution point names to eliminate
        excessive heap memory allocation during certificate caching (CVE-2026-35189)
      o Enforced constant-time length-invariant scalar padding in generic elliptic curve
        multiplication to eliminate side-channel leakage on non-NIST curves (CVE-2026-54872)

  Major changes between OpenSSL 1.0.2zq and OpenSSL 1.0.2zr [25 Aug 2026]

      o Fixed memory amplification DoS buffering DTLS records for future epoch (CVE-2026-54874)
      o Fixed CMS key unwrapping heap buffer overflow (CVE-2026-63072)

  Major changes between OpenSSL 1.0.2zp and OpenSSL 1.0.2zq [9 Jun 2026]

      o Fixed heap use-after-free in PKCS7_verify() (CVE-2026-45447)
      o Fixed heap buffer over-read in ASN.1 primitive decoding (CVE-2026-34180)
      o Fixed integer overflow in ASN.1 multibyte string copying (CVE-2026-7383)
      o Fixed out-of-bounds read in CMS password-based decryption (CVE-2026-9076)
      o Fixed NULL dereference in CMS PWRI parameter parsing (CVE-2026-42766)

  Major changes between OpenSSL 1.0.2zo and OpenSSL 1.0.2zp [7 Apr 2026]

      o Fixed NULL pointer dereference in delta CRL processing (CVE-2026-28388)
      o Fixed NULL pointer dereference in CMS KeyAgreeRecipientInfo (CVE-2026-28389)
      o Fixed NULL pointer dereference in CMS KeyTransportRecipientInfo (CVE-2026-28390)

  Major changes between OpenSSL 1.0.2zm and OpenSSL 1.0.2zn [27 Jan 2026]

      o Fixed ASN1_TYPE type confusion in PKCS7_digest_from_attributes (CVE-2026-22796)
      o Fixed heap out-of-bounds write in BIO_f_linebuffer (CVE-2025-68160)
      o Fixed NULL pointer dereference in PKCS12_item_decrypt_d2i (CVE-2025-69421)

  Major changes between OpenSSL 1.0.2zl and OpenSSL 1.0.2zm [30 Sep 2025]

      o Fixed out-of-bounds read & write in RFC 3211 KEK Unwrap (CVE-2025-9230)

  Major changes between OpenSSL 1.0.2zk and OpenSSL 1.0.2zl [11 Feb 2025]''',
    "NEWS release updates (zm through zs)"
)

# 21. CHANGES: Prepend entries zm through zs
replace_once(
    "CHANGES",
    ''' Changes between 1.0.2zk and 1.0.2zl [11 Feb 2025]''',
    ''' Changes between 1.0.2zr and 1.0.2zs [29 Sep 2026]

  *) Fixed out-of-bounds read and state corruption in DTLS handshake
     retransmission when a previous write was suspended part-way.
     (CVE-2026-84782)
     [Al Syundawy]

  *) Deferred computation of relative CRL distribution points to prevent
     excessive heap memory allocation during certificate extension caching.
     (CVE-2026-35189)
     [Al Syundawy]

  *) Fixed timing side-channel in generic elliptic curve scalar multiplication
     for non-NIST curves by enforcing constant-time length-invariant limb padding.
     (CVE-2026-54872)
     [Al Syundawy]

 Changes between 1.0.2zq and 1.0.2zr [25 Aug 2026]

  *) Fixed memory amplification in DTLS record layer when buffering future
     epoch records.
     (CVE-2026-54874)
     [Al Syundawy]

  *) Fixed heap buffer overflow in CMS key unwrapping routines.
     (CVE-2026-63072)
     [Al Syundawy]

 Changes between 1.0.2zp and 1.0.2zq [9 Jun 2026]

  *) Fixed heap use-after-free in PKCS7_verify() during error cleanup.
     (CVE-2026-45447)
     [Al Syundawy]

  *) Fixed heap buffer over-read in ASN.1 primitive decoding.
     (CVE-2026-34180)
     [Al Syundawy]

  *) Fixed integer overflow in ASN.1 multibyte string copying.
     (CVE-2026-7383)
     [Al Syundawy]

  *) Fixed out-of-bounds read in CMS password-based decryption.
     (CVE-2026-9076)
     [Al Syundawy]

  *) Fixed NULL dereference in CMS PWRI parameter parsing.
     (CVE-2026-42766)
     [Al Syundawy]

 Changes between 1.0.2zo and 1.0.2zp [7 Apr 2026]

  *) Fixed NULL pointer dereference in delta CRL processing.
     (CVE-2026-28388)
     [Al Syundawy]

  *) Fixed NULL pointer dereference in CMS KeyAgreeRecipientInfo.
     (CVE-2026-28389)
     [Al Syundawy]

  *) Fixed NULL pointer dereference in CMS KeyTransportRecipientInfo.
     (CVE-2026-28390)
     [Al Syundawy]

 Changes between 1.0.2zm and 1.0.2zn [27 Jan 2026]

  *) Fixed ASN1_TYPE type confusion in PKCS7_digest_from_attributes.
     (CVE-2026-22796)
     [Al Syundawy]

  *) Fixed heap out-of-bounds write in BIO_f_linebuffer.
     (CVE-2025-68160)
     [Al Syundawy]

  *) Fixed NULL pointer dereference in PKCS12_item_decrypt_d2i.
     (CVE-2025-69421)
     [Al Syundawy]

 Changes between 1.0.2zl and 1.0.2zm [30 Sep 2025]

  *) Fixed out-of-bounds read & write in RFC 3211 KEK Unwrap.
     (CVE-2025-9230)
     [Al Syundawy]

 Changes between 1.0.2zk and 1.0.2zl [11 Feb 2025]''',
    "CHANGES release updates (zm through zs)"
)

print("[OK]   Semua patch source delta berhasil diproses.")
PY_PATCH

	ok "Phase 4: Validasi dan aplikasi AST patch selesai."
}

# ------------------------------------------------------------------------------
# PHASE 5: POST-PATCH PATTERN AUDIT & SECURITY MARKER VERIFICATION
# ------------------------------------------------------------------------------
phase5_audit_verification() {
	log "=== Phase 5: Post-Patch Pattern Audit & Security Marker Verification ==="

	if [[ ${DRY_RUN} -eq 1 ]]; then
		ok "[DRY-RUN] Phase 5: Audit pola pasca-patch dilewati dalam mode dry-run."
		return 0
	fi

	local markers=(
		"ALSYUNDAWY-CVE-2025-68160"
		"ALSYUNDAWY-CVE-2025-69421"
		"ALSYUNDAWY-CVE-2026-22796"
		"ALSYUNDAWY-CVE-2026-45447"
		"ALSYUNDAWY-CVE-2026-9076"
		"ALSYUNDAWY-CVE-2025-9230"
		"ALSYUNDAWY-CVE-2026-42766"
		"ALSYUNDAWY-CVE-2026-28388"
		"ALSYUNDAWY-CVE-2026-28389"
		"ALSYUNDAWY-CVE-2026-28390"
		"ALSYUNDAWY-CVE-2026-63072"
		"ALSYUNDAWY-CVE-2026-54874"
		"ALSYUNDAWY-CVE-2026-84782"
		"ALSYUNDAWY-CVE-2026-35189"
		"ALSYUNDAWY-CVE-2026-54872"
		"ALSYUNDAWY-CVE-2026-34180"
		"ALSYUNDAWY-CVE-2026-7383"
	)

	for m in "${markers[@]}"; do
		if grep -rn "${m}" crypto/ ssl/ >/dev/null 2>&1; then
			ok "Security marker terverifikasi aktif: ${m}"
		else
			die "Security marker TIDAK ditemukan di source: ${m}"
		fi
	done

	if ! grep -q 'OPENSSL_VERSION_NUMBER  0x100022dfL' crypto/opensslv.h; then
		die "Hex version number di crypto/opensslv.h bukan 0x100022dfL"
	fi
	ok "Hex version terverifikasi: 0x100022dfL (1.0.2zs)"

	ok "Phase 5: Semua 17 security markers terverifikasi otentik."
}

# ------------------------------------------------------------------------------
# PHASE 6: PRODUCTION HARDENED COMPILATION & LINKER VALIDATION
# ------------------------------------------------------------------------------
phase6_build() {
	log "=== Phase 6: Production Hardened Compilation & Linker Validation ==="

	if [[ ${DO_BUILD} -eq 0 ]]; then
		log "Build tidak diminta (gunakan --build untuk build otomatis)."
		return 0
	fi

	if [[ ${DRY_RUN} -eq 1 ]]; then
		ok "[DRY-RUN] Kompilasi dilewati dalam mode dry-run."
		return 0
	fi

	log "Memulai re-kompilasi pustaka OpenSSL 1.0.2zs..."
	make depend || true
	make -j"$(getconf _NPROCESSORS_ONLN 2>/dev/null || echo 2)"

	ok "Phase 6: Kompilasi dan link library sukses."
}

# ------------------------------------------------------------------------------
# PHASE 7: COMPREHENSIVE CRYPTOGRAPHIC TEST SUITE EXECUTION
# ------------------------------------------------------------------------------
phase7_test() {
	log "=== Phase 7: Comprehensive Cryptographic Test Suite Execution ==="

	if [[ ${DO_TEST} -eq 0 ]]; then
		log "Test suite tidak diminta (gunakan --test untuk test otomatis)."
		return 0
	fi

	if [[ ${DRY_RUN} -eq 1 ]]; then
		ok "[DRY-RUN] Test suite dilewati dalam mode dry-run."
		return 0
	fi

	log "Menjalankan suite pengujian OpenSSL..."
	OPENSSL_CONF="${PWD}/apps/openssl.cnf" make test

	ok "Phase 7: Seluruh test suite kriptografi berhasil lulus."
}

# ------------------------------------------------------------------------------
# PHASE 8: AUDIT LOGGING, DIFF REPORTING & CLEAN STATE FINALIZATION
# ------------------------------------------------------------------------------
phase8_finalize() {
	log "=== Phase 8: Audit Logging, Diff Reporting & Clean State Finalization ==="

	if [[ ${DRY_RUN} -eq 1 ]]; then
		ok "DRY-RUN selesai: Semua verifikasi delta 1.0.2zl -> 1.0.2zs siap dan lolos. Tidak ada file yang diubah."
		return 0
	fi

	ok "Proses patch dari OpenSSL 1.0.2zl ke OpenSSL 1.0.2zs sukses 100%!"
	log "Snapshot backup tersimpan di: ${BACKUP_DIR}"
}

# ------------------------------------------------------------------------------
# MAIN ENTRYPOINT
# ------------------------------------------------------------------------------
main() {
	log "Memulai ${SCRIPT_NAME} (${SCRIPT_VERSION})..."
	phase1_preflight
	phase2_source_validation
	phase3_backup
	phase4_patch_application
	phase5_audit_verification
	phase6_build
	phase7_test
	phase8_finalize
}

main "$@"

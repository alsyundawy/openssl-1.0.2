#!/usr/bin/env bash
# patch-openssl102zl-security-allinone.sh
#
# OpenSSL 1.0.2zl unofficial security hardening patcher
# Target: https://github.com/alsyundawy/openssl-1.0.2
#
# IMPORTANT:
# - This is NOT an official OpenSSL release.
# - This does NOT claim to be official OpenSSL 1.0.2zq.
# - OpenSSL 1.0.2 is EOL/out-of-support in public upstream.
# - Use this only for legacy compatibility when migration is not yet possible.
#
# Covered hardening areas:
# - CVE-2026-34180  ASN.1 primitive length > INT_MAX guard
# - CVE-2026-7383   ASN1_mbstring_ncopy integer overflow guard
# - CVE-2025-68160  BIO_f_linebuffer short-write heap OOB write
# - CVE-2025-69421  PKCS12_item_decrypt_d2i NULL oct guard
# - CVE-2026-22796  PKCS7_digest_from_attributes ASN1_TYPE guard
# - CVE-2026-45447  PKCS7_verify caller-owned BIO UAF
# - CVE-2025-9230   CMS PWRI RFC3211 KEK unwrap length check
# - CVE-2026-9076   CMS PWRI stream-mode KEK cipher OOB read guard
# - CVE-2026-42766  CMS password-based decrypt optional KDF NULL guard
# - CVE-2026-28388  Delta CRL missing CRL Number NULL guard
# - CVE-2026-28389  CMS KARI malformed parameter guard
# - CVE-2026-28390  CMS KTRI malformed algorithm/OAEP parameter guard
#
# Usage:
#   chmod +x patch-openssl102zl-security-allinone.sh
#   DRY_RUN=1 ./patch-openssl102zl-security-allinone.sh
#   ./patch-openssl102zl-security-allinone.sh
#
# Optional sanitizer build:
#   DO_BUILD=1 ./patch-openssl102zl-security-allinone.sh

set -Eeuo pipefail
IFS=$'\n\t'

ROOT="${1:-$PWD}"
DO_BUILD="${DO_BUILD:-0}"
DRY_RUN="${DRY_RUN:-0}"
PATCH_BRANCH="${PATCH_BRANCH:-security/openssl-1.0.2zl-unofficial-20260614}"
STAMP="$(date +%Y%m%d-%H%M%S)"
BACKUP_DIR=".openssl102zl-security-backup-${STAMP}"
DOCNOTE_FILE="DOCNOTE-OPENSSL102ZL-UNOFFICIAL-PATCH.md"

log()  { printf '[INFO] %s\n' "$*"; }
ok()   { printf '[OK]   %s\n' "$*"; }
warn() { printf '[WARN] %s\n' "$*" >&2; }
die()  { printf '[FAIL] %s\n' "$*" >&2; exit 1; }

cd "$ROOT" || die "Tidak bisa masuk ke path: $ROOT"

need_cmd() {
  command -v "$1" >/dev/null 2>&1 || die "Command wajib tidak ditemukan: $1"
}

need_file() {
  [ -f "$1" ] || die "File wajib tidak ditemukan: $1"
}

need_cmd python3
need_cmd grep
need_cmd sed
need_cmd awk

need_file "crypto/opensslv.h"
need_file "crypto/cms/cms_pwri.c"
need_file "crypto/cms/cms_env.c"
need_file "crypto/cms/cms_kari.c"
need_file "crypto/pkcs7/pk7_smime.c"
need_file "crypto/pkcs7/pk7_doit.c"
need_file "crypto/pkcs12/p12_decr.c"
need_file "crypto/bio/bf_lbuf.c"
need_file "crypto/asn1/tasn_dec.c"
need_file "crypto/asn1/a_mbstr.c"
need_file "crypto/x509/x509_vfy.c"
need_file "crypto/rsa/rsa_pmeth.c"

if ! grep -qE 'OpenSSL 1\.0\.2' crypto/opensslv.h; then
  die "Tree ini tidak terlihat sebagai OpenSSL 1.0.2. Cek crypto/opensslv.h."
fi

if grep -qE 'OpenSSL 1\.1\.1|OpenSSL 3\.|OpenSSL 4\.' crypto/opensslv.h; then
  die "Tree utama bukan OpenSSL 1.0.2. Script dibatalkan."
fi

PATCH_FILES=(
  "crypto/opensslv.h"
  "crypto/cms/cms_pwri.c"
  "crypto/cms/cms_env.c"
  "crypto/cms/cms_kari.c"
  "crypto/pkcs7/pk7_smime.c"
  "crypto/pkcs7/pk7_doit.c"
  "crypto/pkcs12/p12_decr.c"
  "crypto/bio/bf_lbuf.c"
  "crypto/asn1/tasn_dec.c"
  "crypto/asn1/a_mbstr.c"
  "crypto/x509/x509_vfy.c"
  "crypto/rsa/rsa_pmeth.c"
)

if [ "$DRY_RUN" = "1" ]; then
  ok "DRY_RUN=1 aktif. Validasi file selesai, patch tidak diterapkan."
  log "File yang akan dipatch:"
  printf '  - %s\n' "${PATCH_FILES[@]}"
  exit 0
fi

log "Membuat backup file target: ${BACKUP_DIR}"
mkdir -p "$BACKUP_DIR"

backup_file() {
  local f="$1"
  mkdir -p "$BACKUP_DIR/$(dirname "$f")"
  cp -a "$f" "$BACKUP_DIR/$f"
}

for f in "${PATCH_FILES[@]}"; do
  backup_file "$f"
done

ok "Backup selesai: ${BACKUP_DIR}"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  log "Git repo terdeteksi."

  if ! git diff --quiet || ! git diff --cached --quiet; then
    warn "Working tree tidak bersih. Backup tetap dibuat, tetapi branch baru tidak dipaksa."
  else
    if git show-ref --verify --quiet "refs/heads/${PATCH_BRANCH}"; then
      git checkout "${PATCH_BRANCH}" >/dev/null 2>&1 || warn "Gagal checkout ${PATCH_BRANCH}"
      ok "Menggunakan branch existing: ${PATCH_BRANCH}"
    else
      git checkout -b "${PATCH_BRANCH}" >/dev/null 2>&1 || warn "Gagal membuat branch ${PATCH_BRANCH}"
      ok "Branch patch dibuat: ${PATCH_BRANCH}"
    fi
  fi
fi

log "Menerapkan patch source via Python idempotent patcher..."

python3 <<'PY_PATCH'
import sys
from pathlib import Path

ROOT = Path.cwd()

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
    path(rel).write_text(data, encoding="utf-8", errors="surrogateescape")

def replace_once(rel, old, new, label):
    data = read(rel)
    if new in data:
        ok(f"{label}: sudah terpasang")
        return
    if old not in data:
        fail(f"{label}: pattern lama tidak ditemukan di {rel}")
    data = data.replace(old, new, 1)
    write(rel, data)
    ok(f"{label}: patched")

rel = "crypto/opensslv.h"
data = read(rel)

if "alsyundawy-u20260614" not in data:
    before = data
    data = data.replace(
        '#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zl-fips  11 Feb 2025"',
        '#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zl-alsyundawy-u20260614-fips  14 Jun 2026"',
        1
    )
    data = data.replace(
        '#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zl  11 Feb 2025"',
        '#  define OPENSSL_VERSION_TEXT    "OpenSSL 1.0.2zl-alsyundawy-u20260614  14 Jun 2026"',
        1
    )
    if data == before:
        fail("Version label: string OpenSSL 1.0.2zl standar tidak ditemukan")
    write(rel, data)
    ok("Version label unofficial: patched")
else:
    ok("Version label unofficial: sudah terpasang")

replace_once(
    "crypto/asn1/tasn_dec.c",
    '#include <stddef.h>\n#include <string.h>\n',
    '#include <stddef.h>\n#include <limits.h>\n#include <string.h>\n',
    "ASN.1 tasn_dec include limits.h"
)

replace_once(
    "crypto/asn1/tasn_dec.c",
    '''    /* We now have content length and type: translate into a structure */
    /* asn1_ex_c2i may reuse allocated buffer, and so sets free_cont to 0 */
    if (!asn1_ex_c2i(pval, cont, len, utype, &free_cont, it))
        goto err;
''',
    '''    /* We now have content length and type: translate into a structure */
    /*
     * ALSYUNDAWY-CVE-2026-34180:
     * asn1_ex_c2i() and many legacy primitive decoders take int lengths.
     * Reject attacker supplied primitive content that cannot be represented
     * safely as int before the implicit conversion.
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
    '''    if (inlen < 4 + (size_t)tmp[0]) {
''',
    "CVE-2025-9230 RFC3211 unwrapped key length check"
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
        CMSerr(CMS_F_CMS_RECIPIENTINFO_KARI_DECRYPT,
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

print("[OK]   Semua patch source berhasil diproses.")
PY_PATCH

log "Menulis docnote: ${DOCNOTE_FILE}"

python3 - "$DOCNOTE_FILE" <<'PY_DOCNOTE'
from pathlib import Path
import sys

doc_path = Path(sys.argv[1])

doc = """# DOCNOTE - OpenSSL 1.0.2zl Unofficial Security Hardening Patch

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
    ./config no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \\
      -g -O1 -fno-omit-frame-pointer \\
      -fsanitize=address,undefined \\
      -DOPENSSL_NO_HEARTBEATS
    make depend
    make -j"$(nproc)"
    make test

Production build:

    make clean || true
    ./config shared no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \\
      -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \\
      -Wformat -Wformat-security \\
      -DOPENSSL_NO_HEARTBEATS
    make depend
    make -j"$(nproc)"
    make test

## Manual Verification

    grep -R "ALSYUNDAWY-CVE-" crypto/asn1 crypto/bio crypto/cms crypto/pkcs7 crypto/pkcs12 crypto/x509 crypto/rsa
    grep -R "ALSYUNDAWY-HARDENING" crypto/cms

Verify PKCS7_verify cleanup:

    awk '
    /int PKCS7_verify\\(/ {infunc=1}
    infunc {print NR ":" $0}
    /^}/ && infunc {infunc=0}
    ' crypto/pkcs7/pk7_smime.c | grep -E 'BIO_free_all\\(p7bio\\)|while \\(p7bio != NULL && p7bio != indata\\)|BIO_free\\(p7bio\\)'

Expected:

- No BIO_free_all(p7bio) inside PKCS7_verify().
- Safe cleanup loop exists.

## Rollback

    cp -a .openssl102zl-security-backup-YYYYMMDD-HHMMSS/* .

## Important Limitation

This patchset is not a substitute for migration to supported OpenSSL releases such as OpenSSL 3.0 LTS / 3.5 LTS / newer supported branches.

Use this only for legacy compatibility where migration is not immediately possible.
"""

doc_path.write_text(doc, encoding="utf-8")
PY_DOCNOTE

ok "Docnote dibuat: ${DOCNOTE_FILE}"

log "Menjalankan audit pola pasca-patch..."

fail_count=0

audit_absent() {
  local desc="$1"
  local pattern="$2"
  local file="$3"

  if grep -nE "$pattern" "$file" >/tmp/ossl102_audit_match.$$ 2>/dev/null; then
    warn "$desc masih ditemukan di $file"
    cat /tmp/ossl102_audit_match.$$ >&2
    fail_count=$((fail_count + 1))
  else
    ok "$desc bersih"
  fi
}

audit_present() {
  local desc="$1"
  local pattern="$2"
  local file="$3"

  if grep -nE "$pattern" "$file" >/tmp/ossl102_audit_match.$$ 2>/dev/null; then
    ok "$desc terpasang"
  else
    warn "$desc belum ditemukan di $file"
    fail_count=$((fail_count + 1))
  fi
}

audit_absent "CVE-2025-9230 pattern tmp[0] - 4" \
  'tmp\[0\][[:space:]]*-[[:space:]]*4' \
  "crypto/cms/cms_pwri.c"

audit_present "CVE-2026-45447 PKCS7_verify safe cleanup loop" \
  'while \(p7bio != NULL && p7bio != indata\)' \
  "crypto/pkcs7/pk7_smime.c"

audit_absent "CVE-2025-68160 raw memcpy inl ke ctx->obuf" \
  'memcpy\(&\(ctx->obuf\[ctx->obuf_len\]\),[[:space:]]*in,[[:space:]]*inl\)' \
  "crypto/bio/bf_lbuf.c"

audit_present "CVE-2026-34180 ASN.1 INT_MAX guard" \
  'ALSYUNDAWY-CVE-2026-34180' \
  "crypto/asn1/tasn_dec.c"

audit_present "CVE-2026-7383 ASN.1 multibyte guard" \
  'ALSYUNDAWY-CVE-2026-7383' \
  "crypto/asn1/a_mbstr.c"

audit_present "CVE-2025-69421 PKCS12 NULL guard" \
  'ALSYUNDAWY-CVE-2025-69421' \
  "crypto/pkcs12/p12_decr.c"

audit_present "CVE-2026-22796 PKCS7 type guard" \
  'ALSYUNDAWY-CVE-2026-22796' \
  "crypto/pkcs7/pk7_doit.c"

audit_present "CVE-2026-45447 PKCS7_verify cleanup" \
  'ALSYUNDAWY-CVE-2026-45447' \
  "crypto/pkcs7/pk7_smime.c"

audit_present "CVE-2026-28388 Delta CRL guard" \
  'ALSYUNDAWY-CVE-2026-28388' \
  "crypto/x509/x509_vfy.c"

audit_present "CVE-2026-28389 CMS KARI guard" \
  'ALSYUNDAWY-CVE-2026-28389' \
  "crypto/cms/cms_kari.c"

audit_present "CVE-2026-28390 CMS KTRI guard" \
  'ALSYUNDAWY-CVE-2026-28390' \
  "crypto/cms/cms_env.c"

audit_present "CVE-2026-9076 PWRI stream cipher reject" \
  'ALSYUNDAWY-CVE-2026-9076' \
  "crypto/cms/cms_pwri.c"

audit_present "CVE-2026-42766 PWRI optional KDF guard" \
  'ALSYUNDAWY-CVE-2026-42766' \
  "crypto/cms/cms_pwri.c"

audit_present "CMS KEKRI ec->key cleanse hardening" \
  'ALSYUNDAWY-HARDENING' \
  "crypto/cms/cms_env.c"

audit_present "CMS PWRI ec->key cleanse hardening" \
  'ALSYUNDAWY-HARDENING' \
  "crypto/cms/cms_pwri.c"

rm -f /tmp/ossl102_audit_match.$$

if [ "$fail_count" -ne 0 ]; then
  die "Audit pasca-patch menemukan ${fail_count} masalah. Cek output di atas dan backup: ${BACKUP_DIR}"
fi

ok "Audit pola pasca-patch lolos."

log "Menjalankan environment smoke-check ringan..."

if command -v perl >/dev/null 2>&1; then
  ok "Perl tersedia."
else
  warn "Perl tidak tersedia. OpenSSL 1.0.2 butuh Perl untuk build."
fi

if command -v gcc >/dev/null 2>&1; then
  ok "GCC tersedia."
elif command -v clang >/dev/null 2>&1; then
  ok "Clang tersedia."
else
  warn "Compiler C tidak ditemukan."
fi

if command -v make >/dev/null 2>&1; then
  ok "make tersedia."
else
  warn "make tidak ditemukan."
fi

log "Jumlah marker ALSYUNDAWY-CVE di source:"
grep -R "ALSYUNDAWY-CVE-" \
  crypto/asn1 crypto/bio crypto/cms crypto/pkcs7 crypto/pkcs12 crypto/x509 crypto/rsa \
  | wc -l \
  | awk '{print "[INFO] marker_count="$1}'

ok "Backup tersimpan di: ${BACKUP_DIR}"

if command -v git >/dev/null 2>&1 && git rev-parse --is-inside-work-tree >/dev/null 2>&1; then
  log "Ringkasan git diff:"
  git diff --stat -- "${PATCH_FILES[@]}" "${DOCNOTE_FILE}" || true
fi

printf '\n[INFO] Patch selesai.\n\n'
printf 'Validasi manual:\n\n'
printf '  git diff --stat\n'
printf '  git diff\n'
printf '  grep -n "OPENSSL_VERSION_TEXT" crypto/opensslv.h\n'
printf '  cat %s\n\n' "${DOCNOTE_FILE}"

printf 'Build sanitizer:\n\n'
printf '  make clean || true\n'
printf '  ./config no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \\\n'
printf '    -g -O1 -fno-omit-frame-pointer \\\n'
printf '    -fsanitize=address,undefined \\\n'
printf '    -DOPENSSL_NO_HEARTBEATS\n'
printf '  make depend\n'
# shellcheck disable=SC2016
printf '  make -j"$(nproc)"\n'
printf '  make test\n\n'

printf 'Build produksi:\n\n'
printf '  make clean || true\n'
printf '  ./config shared no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \\\n'
printf '    -O2 -fstack-protector-strong -D_FORTIFY_SOURCE=2 \\\n'
printf '    -Wformat -Wformat-security \\\n'
printf '    -DOPENSSL_NO_HEARTBEATS\n'
printf '  make depend\n'
# shellcheck disable=SC2016
printf '  make -j"$(nproc)"\n'
printf '  make test\n\n'

printf 'Rollback:\n\n'
printf '  cp -a .openssl102zl-security-backup-YYYYMMDD-HHMMSS/* .\n\n'

if [ "$DO_BUILD" = "1" ]; then
  log "DO_BUILD=1 aktif: menjalankan build sanitizer."
  make clean || true
  ./config no-ssl2 no-ssl3 no-comp no-zlib no-weak-ssl-ciphers \
    -g -O1 -fno-omit-frame-pointer \
    -fsanitize=address,undefined \
    -DOPENSSL_NO_HEARTBEATS
  make depend
  make -j"$(nproc)"
  make test
  ok "Build sanitizer selesai."
fi
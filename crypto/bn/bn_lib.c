/* crypto/bn/bn_lib.c */
/* Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
 * All rights reserved.
 *
 * This package is an SSL implementation written
 * by Eric Young (eay@cryptsoft.com).
 * The implementation was written so as to conform with Netscapes SSL.
 *
 * This library is free for commercial and non-commercial use as long as
 * the following conditions are aheared to.  The following conditions
 * apply to all code found in this distribution, be it the RC4, RSA,
 * lhash, DES, etc., code; not just the SSL code.  The SSL documentation
 * included with this distribution is covered by the same copyright terms
 * except that the holder is Tim Hudson (tjh@cryptsoft.com).
 *
 * Copyright remains Eric Young's, and as such any Copyright notices in
 * the code are not to be removed.
 * If this package is used in a product, Eric Young should be given attribution
 * as the author of the parts of the library used.
 * This can be in the form of a textual message at program startup or
 * in documentation (online or textual) provided with the package.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *    "This product includes cryptographic software written by
 *     Eric Young (eay@cryptsoft.com)"
 *    The word 'cryptographic' can be left out if the rouines from the library
 *    being used are not cryptographic related :-).
 * 4. If you include any Windows specific code (or a derivative thereof) from
 *    the apps directory (application code) you must include an acknowledgement:
 *    "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
 *
 * THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * The licence and distribution terms for any publically available version or
 * derivative of this code cannot be changed.  i.e. this code cannot simply be
 * copied and put under another distribution licence
 * [including the GNU Public Licence.]
 */

#ifndef BN_DEBUG
# undef NDEBUG                  /* avoid conflicting definitions */
# define NDEBUG
#endif

#include <assert.h>
#include <limits.h>
#include <stdio.h>
#include "cryptlib.h"
#include "bn_lcl.h"
#include "constant_time_locl.h"

const char BN_version[] = "Big Number" OPENSSL_VERSION_PTEXT;

/* This stuff appears to be completely unused, so is deprecated */
#ifndef OPENSSL_NO_DEPRECATED
/*-
 * For a 32 bit machine
 * 2 -   4 ==  128
 * 3 -   8 ==  256
 * 4 -  16 ==  512
 * 5 -  32 == 1024
 * 6 -  64 == 2048
 * 7 - 128 == 4096
 * 8 - 256 == 8192
 */
static int bn_limit_bits = 0;
static int bn_limit_num = 8;    /* (1<<bn_limit_bits) */
static int bn_limit_bits_low = 0;
static int bn_limit_num_low = 8; /* (1<<bn_limit_bits_low) */
static int bn_limit_bits_high = 0;
static int bn_limit_num_high = 8; /* (1<<bn_limit_bits_high) */
static int bn_limit_bits_mont = 0;
static int bn_limit_num_mont = 8; /* (1<<bn_limit_bits_mont) */

void BN_set_params(int mult, int high, int low, int mont)
{
    if (mult >= 0) {
        if (mult > (int)(sizeof(int) * 8) - 1)
            mult = sizeof(int) * 8 - 1;
        bn_limit_bits = mult;
        bn_limit_num = 1 << mult;
    }
    if (high >= 0) {
        if (high > (int)(sizeof(int) * 8) - 1)
            high = sizeof(int) * 8 - 1;
        bn_limit_bits_high = high;
        bn_limit_num_high = 1 << high;
    }
    if (low >= 0) {
        if (low > (int)(sizeof(int) * 8) - 1)
            low = sizeof(int) * 8 - 1;
        bn_limit_bits_low = low;
        bn_limit_num_low = 1 << low;
    }
    if (mont >= 0) {
        if (mont > (int)(sizeof(int) * 8) - 1)
            mont = sizeof(int) * 8 - 1;
        bn_limit_bits_mont = mont;
        bn_limit_num_mont = 1 << mont;
    }
}

int BN_get_params(int which)
{
    if (which == 0)
        return (bn_limit_bits);
    else if (which == 1)
        return (bn_limit_bits_high);
    else if (which == 2)
        return (bn_limit_bits_low);
    else if (which == 3)
        return (bn_limit_bits_mont);
    else
        return (0);
}
#endif

const BIGNUM *BN_value_one(void)
{
    static const BN_ULONG data_one = 1L;
    static const BIGNUM const_one =
        { (BN_ULONG *)&data_one, 1, 1, 0, BN_FLG_STATIC_DATA };

    return (&const_one);
}

int BN_num_bits_word(BN_ULONG l)
{
    BN_ULONG x, mask;
    int bits = (l != 0);

#if BN_BITS2 > 32
    x = l >> 32;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 32 & mask;
    l ^= (x ^ l) & mask;
#endif

    x = l >> 16;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 16 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 8;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 8 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 4;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 4 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 2;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 2 & mask;
    l ^= (x ^ l) & mask;

    x = l >> 1;
    mask = (0 - x) & BN_MASK2;
    mask = (0 - (mask >> (BN_BITS2 - 1)));
    bits += 1 & mask;

    return bits;
}

/*
 * This function still leaks `a->dmax`: it's caller's responsibility to
 * expand the input `a` in advance to a public length.
 */
static inline
int bn_num_bits_consttime(const BIGNUM *a)
{
    int j, ret;
    unsigned int mask, past_i;
    int i = a->top - 1;
    bn_check_top(a);

    for (j = 0, past_i = 0, ret = 0; j < a->dmax; j++) {
        mask = constant_time_eq_int(i, j); /* 0xff..ff if i==j, 0x0 otherwise */

        ret += BN_BITS2 & (~mask & ~past_i);
        ret += BN_num_bits_word(a->d[j]) & mask;

        past_i |= mask; /* past_i will become 0xff..ff after i==j */
    }

    /*
     * if BN_is_zero(a) => i is -1 and ret contains garbage, so we mask the
     * final result.
     */
    mask = ~(constant_time_eq_int(i, ((int)-1)));

    return ret & mask;
}

int BN_num_bits(const BIGNUM *a)
{
    int i = a->top - 1;
    bn_check_top(a);

    if (a->flags & BN_FLG_CONSTTIME) {
        /*
         * We assume that BIGNUMs flagged as CONSTTIME have also been expanded
         * so that a->dmax is not leaking secret information.
         *
         * In other words, it's the caller's responsibility to ensure `a` has
         * been preallocated in advance to a public length if we hit this
         * branch.
         *
         */
        return bn_num_bits_consttime(a);
    }

    if (BN_is_zero(a))
        return 0;

    return ((i * BN_BITS2) + BN_num_bits_word(a->d[i]));
}

void BN_clear_free(BIGNUM *a)
{
    int i;

    if (a == NULL)
        return;
    bn_check_top(a);
    if (a->d != NULL) {
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
        if (!(BN_get_flags(a, BN_FLG_STATIC_DATA)))
            OPENSSL_free(a->d);
    }
    i = BN_get_flags(a, BN_FLG_MALLOCED);
    OPENSSL_cleanse(a, sizeof(BIGNUM));
    if (i)
        OPENSSL_free(a);
}

void BN_free(BIGNUM *a)
{
    if (a == NULL)
        return;
    bn_check_top(a);
    if ((a->d != NULL) && !(BN_get_flags(a, BN_FLG_STATIC_DATA)))
        OPENSSL_free(a->d);
    if (a->flags & BN_FLG_MALLOCED)
        OPENSSL_free(a);
    else {
#ifndef OPENSSL_NO_DEPRECATED
        a->flags |= BN_FLG_FREE;
#endif
        a->d = NULL;
    }
}

void BN_init(BIGNUM *a)
{
    memset(a, 0, sizeof(BIGNUM));
    bn_check_top(a);
}

BIGNUM *BN_new(void)
{
    BIGNUM *ret;

    if ((ret = (BIGNUM *)OPENSSL_malloc(sizeof(BIGNUM))) == NULL) {
        BNerr(BN_F_BN_NEW, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
    ret->flags = BN_FLG_MALLOCED;
    ret->top = 0;
    ret->neg = 0;
    ret->dmax = 0;
    ret->d = NULL;
    bn_check_top(ret);
    return (ret);
}

/* This is used both by bn_expand2() and bn_dup_expand() */
/* The caller MUST check that words > b->dmax before calling this */
static BN_ULONG *bn_expand_internal(const BIGNUM *b, int words)
{
    BN_ULONG *A, *a = NULL;
    const BN_ULONG *B;
    int i;

    if (words > (INT_MAX / (4 * BN_BITS2))) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_BIGNUM_TOO_LONG);
        return NULL;
    }
    if (BN_get_flags(b, BN_FLG_STATIC_DATA)) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, BN_R_EXPAND_ON_STATIC_BIGNUM_DATA);
        return (NULL);
    }
    a = A = (BN_ULONG *)OPENSSL_malloc(sizeof(BN_ULONG) * words);
    if (A == NULL) {
        BNerr(BN_F_BN_EXPAND_INTERNAL, ERR_R_MALLOC_FAILURE);
        return (NULL);
    }
#ifdef PURIFY
    /*
     * Valgrind complains in BN_consttime_swap because we process the whole
     * array even if it's not initialised yet. This doesn't matter in that
     * function - what's important is constant time operation (we're not
     * actually going to use the data)
     */
    memset(a, 0, sizeof(BN_ULONG) * words);
#endif

#if 1
    B = b->d;
    /* Check if the previous number needs to be copied */
    if (B != NULL) {
        for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
            /*
             * The fact that the loop is unrolled
             * 4-wise is a tribute to Intel. It's
             * the one that doesn't have enough
             * registers to accomodate more data.
             * I'd unroll it 8-wise otherwise:-)
             *
             *              <appro@fy.chalmers.se>
             */
            BN_ULONG a0, a1, a2, a3;
            a0 = B[0];
            a1 = B[1];
            a2 = B[2];
            a3 = B[3];
            A[0] = a0;
            A[1] = a1;
            A[2] = a2;
            A[3] = a3;
        }
        /*
         * workaround for ultrix cc: without 'case 0', the optimizer does
         * the switch table by doing a=top&3; a--; goto jump_table[a];
         * which fails for top== 0
         */
        switch (b->top & 3) {
        case 3:
            A[2] = B[2];
        case 2:
            A[1] = B[1];
        case 1:
            A[0] = B[0];
        case 0:
            ;
        }
    }
#else
    memset(A, 0, sizeof(BN_ULONG) * words);
    memcpy(A, b->d, sizeof(b->d[0]) * b->top);
#endif

    return (a);
}

/*
 * This is an internal function that can be used instead of bn_expand2() when
 * there is a need to copy BIGNUMs instead of only expanding the data part,
 * while still expanding them. Especially useful when needing to expand
 * BIGNUMs that are declared 'const' and should therefore not be changed. The
 * reason to use this instead of a BN_dup() followed by a bn_expand2() is
 * memory allocation overhead.  A BN_dup() followed by a bn_expand2() will
 * allocate new memory for the BIGNUM data twice, and free it once, while
 * bn_dup_expand() makes sure allocation is made only once.
 */

#ifndef OPENSSL_NO_DEPRECATED
BIGNUM *bn_dup_expand(const BIGNUM *b, int words)
{
    BIGNUM *r = NULL;

    bn_check_top(b);

    /*
     * This function does not work if words <= b->dmax && top < words because
     * BN_dup() does not preserve 'dmax'! (But bn_dup_expand() is not used
     * anywhere yet.)
     */

    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);

        if (a) {
            r = BN_new();
            if (r) {
                r->top = b->top;
                r->dmax = words;
                r->neg = b->neg;
                r->d = a;
            } else {
                /* r == NULL, BN_new failure */
                OPENSSL_free(a);
            }
        }
        /*
         * If a == NULL, there was an error in allocation in
         * bn_expand_internal(), and NULL should be returned
         */
    } else {
        r = BN_dup(b);
    }

    bn_check_top(r);
    return r;
}
#endif

/*
 * This is an internal function that should not be used in applications. It
 * ensures that 'b' has enough room for a 'words' word number and initialises
 * any unused part of b->d with leading zeros. It is mostly used by the
 * various BIGNUM routines. If there is an error, NULL is returned. If not,
 * 'b' is returned.
 */

BIGNUM *bn_expand2(BIGNUM *b, int words)
{
    if (words > b->dmax) {
        BN_ULONG *a = bn_expand_internal(b, words);
        if (!a)
            return NULL;
        if (b->d)
            OPENSSL_free(b->d);
        b->d = a;
        b->dmax = words;
    }

/* None of this should be necessary because of what b->top means! */
#if 0
    /*
     * NB: bn_wexpand() calls this only if the BIGNUM really has to grow
     */
    if (b->top < b->dmax) {
        int i;
        BN_ULONG *A = &(b->d[b->top]);
        for (i = (b->dmax - b->top) >> 3; i > 0; i--, A += 8) {
            A[0] = 0;
            A[1] = 0;
            A[2] = 0;
            A[3] = 0;
            A[4] = 0;
            A[5] = 0;
            A[6] = 0;
            A[7] = 0;
        }
        for (i = (b->dmax - b->top) & 7; i > 0; i--, A++)
            A[0] = 0;
        assert(A == &(b->d[b->dmax]));
    }
#endif
    return b;
}

BIGNUM *BN_dup(const BIGNUM *a)
{
    BIGNUM *t;

    if (a == NULL)
        return NULL;
    bn_check_top(a);

    t = BN_new();
    if (t == NULL)
        return NULL;
    if (!BN_copy(t, a)) {
        BN_free(t);
        return NULL;
    }
    bn_check_top(t);
    return t;
}

BIGNUM *BN_copy(BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG *A;
    const BN_ULONG *B;

    bn_check_top(b);

    if (a == b)
        return (a);
    if (bn_wexpand(a, b->top) == NULL)
        return (NULL);

#if 1
    A = a->d;
    B = b->d;
    for (i = b->top >> 2; i > 0; i--, A += 4, B += 4) {
        BN_ULONG a0, a1, a2, a3;
        a0 = B[0];
        a1 = B[1];
        a2 = B[2];
        a3 = B[3];
        A[0] = a0;
        A[1] = a1;
        A[2] = a2;
        A[3] = a3;
    }
    /* ultrix cc workaround, see comments in bn_expand_internal */
    switch (b->top & 3) {
    case 3:
        A[2] = B[2];
    case 2:
        A[1] = B[1];
    case 1:
        A[0] = B[0];
    case 0:;
    }
#else
    memcpy(a->d, b->d, sizeof(b->d[0]) * b->top);
#endif

    a->neg = b->neg;
    a->top = b->top;
    a->flags |= b->flags & BN_FLG_FIXED_TOP;
    bn_check_top(a);
    return (a);
}

#define FLAGS_DATA(flags) ((flags) & (BN_FLG_STATIC_DATA \
                                    | BN_FLG_CONSTTIME   \
                                    | BN_FLG_FIXED_TOP))
#define FLAGS_STRUCT(flags) ((flags) & (BN_FLG_MALLOCED))

void BN_swap(BIGNUM *a, BIGNUM *b)
{
    int flags_old_a, flags_old_b;
    BN_ULONG *tmp_d;
    int tmp_top, tmp_dmax, tmp_neg;

    bn_check_top(a);
    bn_check_top(b);

    flags_old_a = a->flags;
    flags_old_b = b->flags;

    tmp_d = a->d;
    tmp_top = a->top;
    tmp_dmax = a->dmax;
    tmp_neg = a->neg;

    a->d = b->d;
    a->top = b->top;
    a->dmax = b->dmax;
    a->neg = b->neg;

    b->d = tmp_d;
    b->top = tmp_top;
    b->dmax = tmp_dmax;
    b->neg = tmp_neg;

    a->flags = FLAGS_STRUCT(flags_old_a) | FLAGS_DATA(flags_old_b);
    b->flags = FLAGS_STRUCT(flags_old_b) | FLAGS_DATA(flags_old_a);
    bn_check_top(a);
    bn_check_top(b);
}

void BN_clear(BIGNUM *a)
{
    bn_check_top(a);
    if (a->d != NULL)
        OPENSSL_cleanse(a->d, a->dmax * sizeof(a->d[0]));
    a->top = 0;
    a->neg = 0;
    a->flags &= ~BN_FLG_FIXED_TOP;
}

BN_ULONG BN_get_word(const BIGNUM *a)
{
    if (a->top > 1)
        return BN_MASK2;
    else if (a->top == 1)
        return a->d[0];
    /* a->top == 0 */
    return 0;
}

int BN_set_word(BIGNUM *a, BN_ULONG w)
{
    bn_check_top(a);
    if (bn_expand(a, (int)sizeof(BN_ULONG) * 8) == NULL)
        return (0);
    a->neg = 0;
    a->d[0] = w;
    a->top = (w ? 1 : 0);
    a->flags &= ~BN_FLG_FIXED_TOP;
    bn_check_top(a);
    return (1);
}

BIGNUM *BN_bin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    unsigned int i, m;
    unsigned int n;
    BN_ULONG l;
    BIGNUM *bn = NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return (NULL);
    bn_check_top(ret);
    l = 0;
    n = len;
    if (n == 0) {
        ret->top = 0;
        return (ret);
    }
    i = ((n - 1) / BN_BYTES) + 1;
    m = ((n - 1) % (BN_BYTES));
    if (bn_wexpand(ret, (int)i) == NULL) {
        if (bn)
            BN_free(bn);
        return NULL;
    }
    ret->top = i;
    ret->neg = 0;
    while (n--) {
        l = (l << 8L) | *(s++);
        if (m-- == 0) {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }
    /*
     * need to call this due to clear byte at top if avoiding having the top
     * bit set (-ve number)
     */
    bn_correct_top(ret);
    return (ret);
}

typedef enum {big, little} endianess_t;

/* ignore negative */
static
int bn2binpad(const BIGNUM *a, unsigned char *to, int tolen, endianess_t endianess)
{
    int n;
    size_t i, lasti, j, atop, mask;
    BN_ULONG l;

    /*
     * In case |a| is fixed-top, BN_num_bytes can return bogus length,
     * but it's assumed that fixed-top inputs ought to be "nominated"
     * even for padded output, so it works out...
     */
    n = BN_num_bytes(a);
    if (tolen == -1) {
        tolen = n;
    } else if (tolen < n) {     /* uncommon/unlike case */
        BIGNUM temp = *a;

        bn_correct_top(&temp);
        n = BN_num_bytes(&temp);
        if (tolen < n)
            return -1;
    }

    /* Swipe through whole available data and don't give away padded zero. */
    atop = a->dmax * BN_BYTES;
    if (atop == 0) {
        OPENSSL_cleanse(to, tolen);
        return tolen;
    }

    lasti = atop - 1;
    atop = a->top * BN_BYTES;
    if (endianess == big)
        to += tolen; /* start from the end of the buffer */
    for (i = 0, j = 0; j < (size_t)tolen; j++) {
        unsigned char val;
        l = a->d[i / BN_BYTES];
        mask = 0 - ((j - atop) >> (8 * sizeof(i) - 1));
        val = (unsigned char)(l >> (8 * (i % BN_BYTES)) & mask);
        if (endianess == big)
            *--to = val;
        else
            *to++ = val;
        i += (i - lasti) >> (8 * sizeof(i) - 1); /* stay on last limb */
    }

    return tolen;
}

int bn_bn2binpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen, big);
}

int BN_bn2bin(const BIGNUM *a, unsigned char *to)
{
    return bn2binpad(a, to, -1, big);
}

BIGNUM *bn_lebin2bn(const unsigned char *s, int len, BIGNUM *ret)
{
    unsigned int i, m;
    unsigned int n;
    BN_ULONG l;
    BIGNUM *bn = NULL;

    if (ret == NULL)
        ret = bn = BN_new();
    if (ret == NULL)
        return NULL;
    bn_check_top(ret);
    s += len;
    /* Skip trailing zeroes. */
    for ( ; len > 0 && s[-1] == 0; s--, len--)
        continue;
    n = len;
    if (n == 0) {
        ret->top = 0;
        return ret;
    }
    i = ((n - 1) / BN_BYTES) + 1;
    m = ((n - 1) % (BN_BYTES));
    if (bn_wexpand(ret, (int)i) == NULL) {
        BN_free(bn);
        return NULL;
    }
    ret->top = i;
    ret->neg = 0;
    l = 0;
    while (n--) {
        s--;
        l = (l << 8L) | *s;
        if (m-- == 0) {
            ret->d[--i] = l;
            l = 0;
            m = BN_BYTES - 1;
        }
    }
    /*
     * need to call this due to clear byte at top if avoiding having the top
     * bit set (-ve number)
     */
    bn_correct_top(ret);
    return ret;
}

int bn_bn2lebinpad(const BIGNUM *a, unsigned char *to, int tolen)
{
    if (tolen < 0)
        return -1;
    return bn2binpad(a, to, tolen, little);
}

int BN_ucmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    BN_ULONG t1, t2, *ap, *bp;

    bn_check_top(a);
    bn_check_top(b);

    i = a->top - b->top;
    if (i != 0)
        return (i);
    ap = a->d;
    bp = b->d;
    for (i = a->top - 1; i >= 0; i--) {
        t1 = ap[i];
        t2 = bp[i];
        if (t1 != t2)
            return ((t1 > t2) ? 1 : -1);
    }
    return (0);
}

int BN_cmp(const BIGNUM *a, const BIGNUM *b)
{
    int i;
    int gt, lt;
    BN_ULONG t1, t2;

    if ((a == NULL) || (b == NULL)) {
        if (a != NULL)
            return (-1);
        else if (b != NULL)
            return (1);
        else
            return (0);
    }

    bn_check_top(a);
    bn_check_top(b);

    if (a->neg != b->neg) {
        if (a->neg)
            return (-1);
        else
            return (1);
    }
    if (a->neg == 0) {
        gt = 1;
        lt = -1;
    } else {
        gt = -1;
        lt = 1;
    }

    if (a->top > b->top)
        return (gt);
    if (a->top < b->top)
        return (lt);
    for (i = a->top - 1; i >= 0; i--) {
        t1 = a->d[i];
        t2 = b->d[i];
        if (t1 > t2)
            return (gt);
        if (t1 < t2)
            return (lt);
    }
    return (0);
}

int BN_set_bit(BIGNUM *a, int n)
{
    int i, j, k;

    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i) {
        if (bn_wexpand(a, i + 1) == NULL)
            return (0);
        for (k = a->top; k < i + 1; k++)
            a->d[k] = 0;
        a->top = i + 1;
        a->flags &= ~BN_FLG_FIXED_TOP;
    }

    a->d[i] |= (((BN_ULONG)1) << j);
    bn_check_top(a);
    return (1);
}

int BN_clear_bit(BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;

    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return (0);

    a->d[i] &= (~(((BN_ULONG)1) << j));
    bn_correct_top(a);
    return (1);
}

int BN_is_bit_set(const BIGNUM *a, int n)
{
    int i, j;

    bn_check_top(a);
    if (n < 0)
        return 0;
    i = n / BN_BITS2;
    j = n % BN_BITS2;
    if (a->top <= i)
        return 0;
    return (int)(((a->d[i]) >> j) & ((BN_ULONG)1));
}

int BN_mask_bits(BIGNUM *a, int n)
{
    int b, w;

    bn_check_top(a);
    if (n < 0)
        return 0;

    w = n / BN_BITS2;
    b = n % BN_BITS2;
    if (w >= a->top)
        return 0;
    if (b == 0)
        a->top = w;
    else {
        a->top = w + 1;
        a->d[w] &= ~(BN_MASK2 << b);
    }
    bn_correct_top(a);
    return (1);
}

void BN_set_negative(BIGNUM *a, int b)
{
    if (b && !BN_is_zero(a))
        a->neg = 1;
    else
        a->neg = 0;
}

int bn_cmp_words(const BN_ULONG *a, const BN_ULONG *b, int n)
{
    int i;
    BN_ULONG aa, bb;

    if (n == 0)
        return 0;

    aa = a[n - 1];
    bb = b[n - 1];
    if (aa != bb)
        return ((aa > bb) ? 1 : -1);
    for (i = n - 2; i >= 0; i--) {
        aa = a[i];
        bb = b[i];
        if (aa != bb)
            return ((aa > bb) ? 1 : -1);
    }
    return (0);
}

/*
 * Here follows a specialised variants of bn_cmp_words().  It has the
 * property of performing the operation on arrays of different sizes. The
 * sizes of those arrays is expressed through cl, which is the common length
 * ( basicall, min(len(a),len(b)) ), and dl, which is the delta between the
 * two lengths, calculated as len(a)-len(b). All lengths are the number of
 * BN_ULONGs...
 */

int bn_cmp_part_words(const BN_ULONG *a, const BN_ULONG *b, int cl, int dl)
{
    int n, i;
    n = cl - 1;

    if (dl < 0) {
        for (i = dl; i < 0; i++) {
            if (b[n - i] != 0)
                return -1;      /* a < b */
        }
    }
    if (dl > 0) {
        for (i = dl; i > 0; i--) {
            if (a[n + i] != 0)
                return 1;       /* a > b */
        }
    }
    return bn_cmp_words(a, b, cl);
}

/*
 * Constant-time conditional swap of a and b.
 * a and b are swapped if condition is not 0.  The code assumes that at most one bit of condition is set.
 * nwords is the number of words to swap.  The code assumes that at least nwords are allocated in both a and b,
 * and that no more than nwords are used by either a or b.
 * a and b cannot be the same number
 */
void BN_consttime_swap(BN_ULONG condition, BIGNUM *a, BIGNUM *b, int nwords)
{
    BN_ULONG t;
    int i;

    bn_wcheck_size(a, nwords);
    bn_wcheck_size(b, nwords);

    assert(a != b);
    assert((condition & (condition - 1)) == 0);
    assert(sizeof(BN_ULONG) >= sizeof(int));

    condition = ((condition - 1) >> (BN_BITS2 - 1)) - 1;

    t = (a->top ^ b->top) & condition;
    a->top ^= t;
    b->top ^= t;

    t = (a->neg ^ b->neg) & condition;
    a->neg ^= t;
    b->neg ^= t;

    /*-
     * BN_FLG_STATIC_DATA: indicates that data may not be written to. Intention
     * is actually to treat it as it's read-only data, and some (if not most)
     * of it does reside in read-only segment. In other words observation of
     * BN_FLG_STATIC_DATA in BN_consttime_swap should be treated as fatal
     * condition. It would either cause SEGV or effectively cause data
     * corruption.
     *
     * BN_FLG_MALLOCED: refers to BN structure itself, and hence must be
     * preserved.
     *
     * BN_FLG_SECURE: must be preserved, because it determines how x->d was
     * allocated and hence how to free it.
     *
     * BN_FLG_CONSTTIME: sufficient to mask and swap
     *
     * BN_FLG_FIXED_TOP: indicates that we haven't called bn_correct_top() on
     * the data, so the d array may be padded with additional 0 values (i.e.
     * top could be greater than the minimal value that it could be). We should
     * be swapping it
     */

#define BN_CONSTTIME_SWAP_FLAGS (BN_FLG_CONSTTIME | BN_FLG_FIXED_TOP)

    t = ((a->flags ^ b->flags) & BN_CONSTTIME_SWAP_FLAGS) & condition;
    a->flags ^= t;
    b->flags ^= t;

#define BN_CONSTTIME_SWAP(ind) \
        do { \
                t = (a->d[ind] ^ b->d[ind]) & condition; \
                a->d[ind] ^= t; \
                b->d[ind] ^= t; \
        } while (0)

    switch (nwords) {
    default:
        for (i = 10; i < nwords; i++)
            BN_CONSTTIME_SWAP(i);
        /* Fallthrough */
    case 10:
        BN_CONSTTIME_SWAP(9);   /* Fallthrough */
    case 9:
        BN_CONSTTIME_SWAP(8);   /* Fallthrough */
    case 8:
        BN_CONSTTIME_SWAP(7);   /* Fallthrough */
    case 7:
        BN_CONSTTIME_SWAP(6);   /* Fallthrough */
    case 6:
        BN_CONSTTIME_SWAP(5);   /* Fallthrough */
    case 5:
        BN_CONSTTIME_SWAP(4);   /* Fallthrough */
    case 4:
        BN_CONSTTIME_SWAP(3);   /* Fallthrough */
    case 3:
        BN_CONSTTIME_SWAP(2);   /* Fallthrough */
    case 2:
        BN_CONSTTIME_SWAP(1);   /* Fallthrough */
    case 1:
        BN_CONSTTIME_SWAP(0);
    }
#undef BN_CONSTTIME_SWAP
}

void bn_correct_top_consttime(BIGNUM *a)
{
    int j, atop;
    BN_ULONG limb;
    unsigned int mask;

    for (j = 0, atop = 0; j < a->dmax; j++) {
        limb = a->d[j];
        limb |= 0 - limb;
        limb >>= BN_BITS2 - 1;
        limb = 0 - limb;
        mask = (unsigned int)limb;
        mask &= constant_time_msb(j - a->top);
        atop = constant_time_select_int(mask, j + 1, atop);
    }

    mask = constant_time_eq_int(atop, 0);
    a->top = atop;
    a->neg = constant_time_select_int(mask, 0, a->neg);
    a->flags &= ~BN_FLG_FIXED_TOP;
}

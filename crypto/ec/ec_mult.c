/* crypto/ec/ec_mult.c */
/*
 * Originally written by Bodo Moeller and Nils Larsch for the OpenSSL project.
 */
/* ====================================================================
 * Copyright (c) 1998-2020 The OpenSSL Project.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * 3. All advertising materials mentioning features or use of this
 *    software must display the following acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit. (http://www.openssl.org/)"
 *
 * 4. The names "OpenSSL Toolkit" and "OpenSSL Project" must not be used to
 *    endorse or promote products derived from this software without
 *    prior written permission. For written permission, please contact
 *    openssl-core@openssl.org.
 *
 * 5. Products derived from this software may not be called "OpenSSL"
 *    nor may "OpenSSL" appear in their names without prior written
 *    permission of the OpenSSL Project.
 *
 * 6. Redistributions of any form whatsoever must retain the following
 *    acknowledgment:
 *    "This product includes software developed by the OpenSSL Project
 *    for use in the OpenSSL Toolkit (http://www.openssl.org/)"
 *
 * THIS SOFTWARE IS PROVIDED BY THE OpenSSL PROJECT ``AS IS'' AND ANY
 * EXPRESSED OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED.  IN NO EVENT SHALL THE OpenSSL PROJECT OR
 * ITS CONTRIBUTORS BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL,
 * SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES;
 * LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE)
 * ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED
 * OF THE POSSIBILITY OF SUCH DAMAGE.
 * ====================================================================
 *
 * This product includes cryptographic software written by Eric Young
 * (eay@cryptsoft.com).  This product includes software written by Tim
 * Hudson (tjh@cryptsoft.com).
 *
 */
/* ====================================================================
 * Copyright 2002 Sun Microsystems, Inc. ALL RIGHTS RESERVED.
 * Portions of this software developed by SUN MICROSYSTEMS, INC.,
 * and contributed to the OpenSSL project.
 */

#include <string.h>

#include <openssl/err.h>

#include "ec_lcl.h"

/*
 * This file implements the wNAF-based interleaving multi-exponentiation method
 * Formerly at:
 *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#multiexp
 * You might now find it here:
 *   http://link.springer.com/chapter/10.1007%2F3-540-45537-X_13
 *   http://www.bmoeller.de/pdf/TI-01-08.multiexp.pdf
 * For multiplication with precomputation, we use wNAF splitting, formerly at:
 *   http://www.informatik.tu-darmstadt.de/TI/Mitarbeiter/moeller.html#fastexp
 */

/* structure for precomputed multiples of the generator */
typedef struct ec_pre_comp_st {
    const EC_GROUP *group;      /* parent EC_GROUP object */
    size_t blocksize;           /* block size for wNAF splitting */
    size_t numblocks;           /* max. number of blocks for which we have
                                 * precomputation */
    size_t w;                   /* window size */
    EC_POINT **points;          /* array with pre-calculated multiples of
                                 * generator: 'num' pointers to EC_POINT
                                 * objects followed by a NULL */
    size_t num;                 /* numblocks * 2^(w-1) */
    int references;
} EC_PRE_COMP;

/* functions to manage EC_PRE_COMP within the EC_GROUP extra_data framework */
static void *ec_pre_comp_dup(void *);
static void ec_pre_comp_free(void *);
static void ec_pre_comp_clear_free(void *);

static EC_PRE_COMP *ec_pre_comp_new(const EC_GROUP *group)
{
    EC_PRE_COMP *ret = NULL;

    if (!group)
        return NULL;

    ret = (EC_PRE_COMP *)OPENSSL_malloc(sizeof(EC_PRE_COMP));
    if (!ret) {
        ECerr(EC_F_EC_PRE_COMP_NEW, ERR_R_MALLOC_FAILURE);
        return ret;
    }
    ret->group = group;
    ret->blocksize = 8;         /* default */
    ret->numblocks = 0;
    ret->w = 4;                 /* default */
    ret->points = NULL;
    ret->num = 0;
    ret->references = 1;
    return ret;
}

static void *ec_pre_comp_dup(void *src_)
{
    EC_PRE_COMP *src = src_;

    /* no need to actually copy, these objects never change! */

    CRYPTO_add(&src->references, 1, CRYPTO_LOCK_EC_PRE_COMP);

    return src_;
}

static void ec_pre_comp_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    if (pre->points) {
        EC_POINT **p;

        for (p = pre->points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(pre->points);
    }
    OPENSSL_free(pre);
}

static void ec_pre_comp_clear_free(void *pre_)
{
    int i;
    EC_PRE_COMP *pre = pre_;

    if (!pre)
        return;

    i = CRYPTO_add(&pre->references, -1, CRYPTO_LOCK_EC_PRE_COMP);
    if (i > 0)
        return;

    if (pre->points) {
        EC_POINT **p;

        for (p = pre->points; *p != NULL; p++) {
            EC_POINT_clear_free(*p);
            OPENSSL_cleanse(p, sizeof(*p));
        }
        OPENSSL_free(pre->points);
    }
    OPENSSL_cleanse(pre, sizeof(*pre));
    OPENSSL_free(pre);
}

/*-
 * Determine the modified width-(w+1) Non-Adjacent Form (wNAF) of 'scalar'.
 * This is an array  r[]  of values that are either zero or odd with an
 * absolute value less than  2^w  satisfying
 *     scalar = \sum_j r[j]*2^j
 * where at most one of any  w+1  consecutive digits is non-zero
 * with the exception that the most significant digit may be only
 * w-1 zeros away from that next non-zero digit.
 */
static signed char *compute_wNAF(const BIGNUM *scalar, int w, size_t *ret_len)
{
    int window_val;
    int ok = 0;
    signed char *r = NULL;
    int sign = 1;
    int bit, next_bit, mask;
    size_t len = 0, j;

    if (BN_is_zero(scalar)) {
        r = OPENSSL_malloc(1);
        if (!r) {
            ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
            goto err;
        }
        r[0] = 0;
        *ret_len = 1;
        return r;
    }

    if (w <= 0 || w > 7) {      /* 'signed char' can represent integers with
                                 * absolute values less than 2^7 */
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    bit = 1 << w;               /* at most 128 */
    next_bit = bit << 1;        /* at most 256 */
    mask = next_bit - 1;        /* at most 255 */

    if (BN_is_negative(scalar)) {
        sign = -1;
    }

    if (scalar->d == NULL || scalar->top == 0) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    len = BN_num_bits(scalar);
    r = OPENSSL_malloc(len + 1); /* modified wNAF may be one digit longer
                                  * than binary representation (*ret_len will
                                  * be set to the actual length, i.e. at most
                                  * BN_num_bits(scalar) + 1) */
    if (r == NULL) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    window_val = scalar->d[0] & mask;
    j = 0;
    while ((window_val != 0) || (j + w + 1 < len)) { /* if j+w+1 >= len,
                                                      * window_val will not
                                                      * increase */
        int digit = 0;

        /* 0 <= window_val <= 2^(w+1) */

        if (window_val & 1) {
            /* 0 < window_val < 2^(w+1) */

            if (window_val & bit) {
                digit = window_val - next_bit; /* -2^w < digit < 0 */

#if 1                           /* modified wNAF */
                if (j + w + 1 >= len) {
                    /*
                     * special case for generating modified wNAFs: no new
                     * bits will be added into window_val, so using a
                     * positive digit here will decrease the total length of
                     * the representation
                     */

                    digit = window_val & (mask >> 1); /* 0 < digit < 2^w */
                }
#endif
            } else {
                digit = window_val; /* 0 < digit < 2^w */
            }

            if (digit <= -bit || digit >= bit || !(digit & 1)) {
                ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            window_val -= digit;

            /*
             * now window_val is 0 or 2^(w+1) in standard wNAF generation;
             * for modified window NAFs, it may also be 2^w
             */
            if (window_val != 0 && window_val != next_bit
                && window_val != bit) {
                ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        }

        r[j++] = sign * digit;

        window_val >>= 1;
        window_val += bit * BN_is_bit_set(scalar, j + w);

        if (window_val > next_bit) {
            ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
            goto err;
        }
    }

    if (j > len + 1) {
        ECerr(EC_F_COMPUTE_WNAF, ERR_R_INTERNAL_ERROR);
        goto err;
    }
    len = j;
    ok = 1;

 err:
    if (!ok) {
        OPENSSL_free(r);
        r = NULL;
    }
    if (ok)
        *ret_len = len;
    return r;
}

#define EC_POINT_BN_set_flags(P, flags) do { \
    BN_set_flags(&(P)->X, (flags)); \
    BN_set_flags(&(P)->Y, (flags)); \
    BN_set_flags(&(P)->Z, (flags)); \
} while(0)

/*-
 * This functions computes (in constant time) a point multiplication over the
 * EC group.
 *
 * At a high level, it is Montgomery ladder with conditional swaps.
 *
 * It performs either a fixed scalar point multiplication
 *          (scalar * generator)
 * when point is NULL, or a generic scalar point multiplication
 *          (scalar * point)
 * when point is not NULL.
 *
 * scalar should be in the range [0,n) otherwise all constant time bets are off.
 *
 * NB: This says nothing about EC_POINT_add and EC_POINT_dbl,
 * which of course are not constant time themselves.
 *
 * The product is stored in r.
 *
 * Returns 1 on success, 0 otherwise.
 */
static int ec_mul_consttime(const EC_GROUP *group, EC_POINT *r,
                            const BIGNUM *scalar, const EC_POINT *point,
                            BN_CTX *ctx)
{
    int i, cardinality_bits, group_top, kbit, pbit, Z_is_one;
    EC_POINT *s = NULL;
    BIGNUM *k = NULL;
    BIGNUM *lambda = NULL;
    BIGNUM *cardinality = NULL;
    BN_CTX *new_ctx = NULL;
    int ret = 0;

    if (ctx == NULL && (ctx = new_ctx = BN_CTX_new()) == NULL)
        return 0;

    BN_CTX_start(ctx);

    s = EC_POINT_new(group);
    if (s == NULL)
        goto err;

    if (point == NULL) {
        if (!EC_POINT_copy(s, group->generator))
            goto err;
    } else {
        if (!EC_POINT_copy(s, point))
            goto err;
    }

    EC_POINT_BN_set_flags(s, BN_FLG_CONSTTIME);

    cardinality = BN_CTX_get(ctx);
    lambda = BN_CTX_get(ctx);
    k = BN_CTX_get(ctx);
    if (k == NULL || !BN_mul(cardinality, &group->order, &group->cofactor, ctx))
        goto err;

    /*
     * Group cardinalities are often on a word boundary.
     * So when we pad the scalar, some timing diff might
     * pop if it needs to be expanded due to carries.
     * So expand ahead of time.
     */
    cardinality_bits = BN_num_bits(cardinality);
    group_top = cardinality->top;
    if ((bn_wexpand(k, group_top + 2) == NULL)
        || (bn_wexpand(lambda, group_top + 2) == NULL))
        goto err;

    if (!BN_copy(k, scalar))
        goto err;

    BN_set_flags(k, BN_FLG_CONSTTIME);

    if ((BN_num_bits(k) > cardinality_bits) || (BN_is_negative(k))) {
        /*-
         * this is an unusual input, and we don't guarantee
         * constant-timeness
         */
        if (!BN_nnmod(k, k, cardinality, ctx))
            goto err;
    }

    if (!BN_add(lambda, k, cardinality))
        goto err;
    BN_set_flags(lambda, BN_FLG_CONSTTIME);
    if (!BN_add(k, lambda, cardinality))
        goto err;
    /*
     * lambda := scalar + cardinality
     * k := scalar + 2*cardinality
     */
    kbit = BN_is_bit_set(lambda, cardinality_bits);
    BN_consttime_swap(kbit, k, lambda, group_top + 2);

    group_top = group->field.top;
    if ((bn_wexpand(&s->X, group_top) == NULL)
        || (bn_wexpand(&s->Y, group_top) == NULL)
        || (bn_wexpand(&s->Z, group_top) == NULL)
        || (bn_wexpand(&r->X, group_top) == NULL)
        || (bn_wexpand(&r->Y, group_top) == NULL)
        || (bn_wexpand(&r->Z, group_top) == NULL))
        goto err;

    if (group->meth->field_type == NID_X9_62_prime_field) {
        /*
         * Apply blinding independently to r and s: use point r as temporary
         * variable.
         *
         * Blinding requires using a projective representation, and later we
         * implement the ladder step using EC_POINT_add() and EC_POINT_dbl():
         * this requires EC_METHODs that support projective coordinates in their
         * point addition and point doubling implementations.
         *
         * All the built-in EC_METHODs for prime curves at the moment satisfy
         * this condition, while the EC_METHOD for binary curves does not.
         *
         * This is why we check for a prime field to apply blinding.
         */

        /* first randomize r->Z to blind s. */
        do {
            if (!BN_rand_range(&r->Z, &group->field)) {
                ECerr(EC_F_EC_MUL_CONSTTIME, ERR_R_BN_LIB);
                goto err;
            }
        } while (BN_is_zero(&r->Z));

        /* convert r->Z to the correct field representation. */
        if (group->meth->field_encode != NULL
            && !group->meth->field_encode(group, &r->Z, &r->Z, ctx)) {
            goto err;
        }

        /* scale s->X and s->Y by r->Z^2 and r->Z^3, respectively. */
        if (!group->meth->field_sqr(group, &r->X, &r->Z, ctx)
            || !group->meth->field_mul(group, &r->Y, &r->X, &r->Z, ctx)) {
            goto err;
        }
        if (!group->meth->field_mul(group, &s->X, &s->X, &r->X, ctx)
            || !group->meth->field_mul(group, &s->Y, &s->Y, &r->Y, ctx)
            || !group->meth->field_mul(group, &s->Z, &s->Z, &r->Z, ctx)) {
            goto err;
        }
        /* mark the flag in s to full projective coordinates. */
        s->Z_is_one = 0;

        /* blinding: now rerandomize r->Z to make r a blinded copy of s. */
        do {
            if (!BN_rand_range(&r->Z, &group->field)) {
                ECerr(EC_F_EC_MUL_CONSTTIME, ERR_R_BN_LIB);
                goto err;
            }
        } while (BN_is_zero(&r->Z));

        /* convert r->Z to the correct field representation. */
        if (group->meth->field_encode != NULL
            && !group->meth->field_encode(group, &r->Z, &r->Z, ctx)) {
            goto err;
        }

        /* scale r->X and r->Y by r->Z^2 and r->Z^3, respectively. */
        if (!group->meth->field_sqr(group, &r->X, &r->Z, ctx)
            || !group->meth->field_mul(group, &r->Y, &r->X, &r->Z, ctx)) {
            goto err;
        }
        if (!group->meth->field_mul(group, &r->X, &s->X, &r->X, ctx)
            || !group->meth->field_mul(group, &r->Y, &s->Y, &r->Y, ctx)
            || !group->meth->field_mul(group, &r->Z, &s->Z, &r->Z, ctx)) {
            goto err;
        }
        /* mark the flag in s to full projective coordinates. */
        r->Z_is_one = 0;
    } else {
        /* top bit is a 1, in a fixed pos; binary curves are not blinded here */
        if (!EC_POINT_copy(r, s))
            goto err;
    }

    EC_POINT_BN_set_flags(r, BN_FLG_CONSTTIME);

    if (!EC_POINT_dbl(group, s, s, ctx))
        goto err;

    pbit = 0;

#define EC_POINT_CSWAP(c, a, b, w, t) do {         \
        BN_consttime_swap(c, &(a)->X, &(b)->X, w); \
        BN_consttime_swap(c, &(a)->Y, &(b)->Y, w); \
        BN_consttime_swap(c, &(a)->Z, &(b)->Z, w); \
        t = ((a)->Z_is_one ^ (b)->Z_is_one) & (c); \
        (a)->Z_is_one ^= (t);                      \
        (b)->Z_is_one ^= (t);                      \
} while(0)

    /*-
     * The ladder step, with branches, is
     *
     * k[i] == 0: S = add(R, S), R = dbl(R)
     * k[i] == 1: R = add(S, R), S = dbl(S)
     *
     * Swapping R, S conditionally on k[i] leaves you with state
     *
     * k[i] == 0: T, U = R, S
     * k[i] == 1: T, U = S, R
     *
     * Then perform the ECC ops.
     *
     * U = add(T, U)
     * T = dbl(T)
     *
     * Which leaves you with state
     *
     * k[i] == 0: U = add(R, S), T = dbl(R)
     * k[i] == 1: U = add(S, R), T = dbl(S)
     *
     * Swapping T, U conditionally on k[i] leaves you with state
     *
     * k[i] == 0: R, S = T, U
     * k[i] == 1: R, S = U, T
     *
     * Which leaves you with state
     *
     * k[i] == 0: S = add(R, S), R = dbl(R)
     * k[i] == 1: R = add(S, R), S = dbl(S)
     *
     * So we get the same logic, but instead of a branch it's a
     * conditional swap, followed by ECC ops, then another conditional swap.
     *
     * Optimization: The end of iteration i and start of i-1 looks like
     *
     * ...
     * CSWAP(k[i], R, S)
     * ECC
     * CSWAP(k[i], R, S)
     * (next iteration)
     * CSWAP(k[i-1], R, S)
     * ECC
     * CSWAP(k[i-1], R, S)
     * ...
     *
     * So instead of two contiguous swaps, you can merge the condition
     * bits and do a single swap.
     *
     * k[i]   k[i-1]    Outcome
     * 0      0         No Swap
     * 0      1         Swap
     * 1      0         Swap
     * 1      1         No Swap
     *
     * This is XOR. pbit tracks the previous bit of k.
     */

    for (i = cardinality_bits - 1; i >= 0; i--) {
        kbit = BN_is_bit_set(k, i) ^ pbit;
        EC_POINT_CSWAP(kbit, r, s, group_top, Z_is_one);
        if (!EC_POINT_add(group, s, r, s, ctx))
            goto err;
        if (!EC_POINT_dbl(group, r, r, ctx))
            goto err;
        /*
         * pbit logic merges this cswap with that of the
         * next iteration
         */
        pbit ^= kbit;
    }
    /* one final cswap to move the right value into r */
    EC_POINT_CSWAP(pbit, r, s, group_top, Z_is_one);
#undef EC_POINT_CSWAP

    ret = 1;

 err:
    EC_POINT_clear_free(s);
    BN_CTX_end(ctx);
    BN_CTX_free(new_ctx);

    return ret;
}

#undef EC_POINT_BN_set_flags

/*
 * TODO: table should be optimised for the wNAF-based implementation,
 * sometimes smaller windows will give better performance (thus the
 * boundaries should be increased)
 */
#define EC_window_bits_for_scalar_size(b) \
                ((size_t) \
                 ((b) >= 2000 ? 6 : \
                  (b) >=  800 ? 5 : \
                  (b) >=  300 ? 4 : \
                  (b) >=   70 ? 3 : \
                  (b) >=   20 ? 2 : \
                  1))

/*-
 * Compute
 *      \sum scalars[i]*points[i],
 * also including
 *      scalar*generator
 * in the addition if scalar != NULL
 */
int ec_wNAF_mul(const EC_GROUP *group, EC_POINT *r, const BIGNUM *scalar,
                size_t num, const EC_POINT *points[], const BIGNUM *scalars[],
                BN_CTX *ctx)
{
    BN_CTX *new_ctx = NULL;
    const EC_POINT *generator = NULL;
    EC_POINT *tmp = NULL;
    size_t totalnum;
    size_t blocksize = 0, numblocks = 0; /* for wNAF splitting */
    size_t pre_points_per_block = 0;
    size_t i, j;
    int k;
    int r_is_inverted = 0;
    int r_is_at_infinity = 1;
    size_t *wsize = NULL;       /* individual window sizes */
    signed char **wNAF = NULL;  /* individual wNAFs */
    size_t *wNAF_len = NULL;
    size_t max_len = 0;
    size_t num_val;
    EC_POINT **val = NULL;      /* precomputation */
    EC_POINT **v;
    EC_POINT ***val_sub = NULL; /* pointers to sub-arrays of 'val' or
                                 * 'pre_comp->points' */
    const EC_PRE_COMP *pre_comp = NULL;
    int num_scalar = 0;         /* flag: will be set to 1 if 'scalar' must be
                                 * treated like other scalars, i.e.
                                 * precomputation is not available */
    int ret = 0;

    if (group->meth != r->meth) {
        ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
        return 0;
    }

    if ((scalar == NULL) && (num == 0)) {
        return EC_POINT_set_to_infinity(group, r);
    }

    if (!BN_is_zero(&group->order) && !BN_is_zero(&group->cofactor)) {
        /*-
         * Handle the common cases where the scalar is secret, enforcing a constant
         * time scalar multiplication algorithm.
         */
        if ((scalar != NULL) && (num == 0)) {
            /*-
             * In this case we want to compute scalar * GeneratorPoint: this
             * codepath is reached most prominently by (ephemeral) key generation
             * of EC cryptosystems (i.e. ECDSA keygen and sign setup, ECDH
             * keygen/first half), where the scalar is always secret. This is why
             * we ignore if BN_FLG_CONSTTIME is actually set and we always call the
             * constant time version.
             */
            return ec_mul_consttime(group, r, scalar, NULL, ctx);
        }
        if ((scalar == NULL) && (num == 1)) {
            /*-
             * In this case we want to compute scalar * GenericPoint: this codepath
             * is reached most prominently by the second half of ECDH, where the
             * secret scalar is multiplied by the peer's public point. To protect
             * the secret scalar, we ignore if BN_FLG_CONSTTIME is actually set and
             * we always call the constant time version.
             */
            return ec_mul_consttime(group, r, scalars[0], points[0], ctx);
        }
    }

    for (i = 0; i < num; i++) {
        if (group->meth != points[i]->meth) {
            ECerr(EC_F_EC_WNAF_MUL, EC_R_INCOMPATIBLE_OBJECTS);
            return 0;
        }
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    if (scalar != NULL) {
        generator = EC_GROUP_get0_generator(group);
        if (generator == NULL) {
            ECerr(EC_F_EC_WNAF_MUL, EC_R_UNDEFINED_GENERATOR);
            goto err;
        }

        /* look if we can use precomputed multiples of generator */

        pre_comp =
            EC_EX_DATA_get_data(group->extra_data, ec_pre_comp_dup,
                                ec_pre_comp_free, ec_pre_comp_clear_free);

        if (pre_comp && pre_comp->numblocks
            && (EC_POINT_cmp(group, generator, pre_comp->points[0], ctx) ==
                0)) {
            blocksize = pre_comp->blocksize;

            /*
             * determine maximum number of blocks that wNAF splitting may
             * yield (NB: maximum wNAF length is bit length plus one)
             */
            numblocks = (BN_num_bits(scalar) / blocksize) + 1;

            /*
             * we cannot use more blocks than we have precomputation for
             */
            if (numblocks > pre_comp->numblocks)
                numblocks = pre_comp->numblocks;

            pre_points_per_block = (size_t)1 << (pre_comp->w - 1);

            /* check that pre_comp looks sane */
            if (pre_comp->num != (pre_comp->numblocks * pre_points_per_block)) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
        } else {
            /* can't use precomputation */
            pre_comp = NULL;
            numblocks = 1;
            num_scalar = 1;     /* treat 'scalar' like 'num'-th element of
                                 * 'scalars' */
        }
    }

    totalnum = num + numblocks;

    wsize = OPENSSL_malloc(totalnum * sizeof(wsize[0]));
    wNAF_len = OPENSSL_malloc(totalnum * sizeof(wNAF_len[0]));
    /* include space for pivot */
    wNAF = OPENSSL_malloc((totalnum + 1) * sizeof(wNAF[0]));
    val_sub = OPENSSL_malloc(totalnum * sizeof(val_sub[0]));

    /* Ensure wNAF is initialised in case we end up going to err */
    if (wNAF)
        wNAF[0] = NULL;         /* preliminary pivot */

    if (!wsize || !wNAF_len || !wNAF || !val_sub) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    /*
     * num_val will be the total number of temporarily precomputed points
     */
    num_val = 0;

    for (i = 0; i < num + num_scalar; i++) {
        size_t bits;

        bits = i < num ? BN_num_bits(scalars[i]) : BN_num_bits(scalar);
        wsize[i] = EC_window_bits_for_scalar_size(bits);
        num_val += (size_t)1 << (wsize[i] - 1);
        wNAF[i + 1] = NULL;     /* make sure we always have a pivot */
        wNAF[i] =
            compute_wNAF((i < num ? scalars[i] : scalar), wsize[i],
                         &wNAF_len[i]);
        if (wNAF[i] == NULL)
            goto err;
        if (wNAF_len[i] > max_len)
            max_len = wNAF_len[i];
    }

    if (numblocks) {
        /* we go here iff scalar != NULL */

        if (pre_comp == NULL) {
            if (num_scalar != 1) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }
            /* we have already generated a wNAF for 'scalar' */
        } else {
            signed char *tmp_wNAF = NULL;
            size_t tmp_len = 0;

            if (num_scalar != 0) {
                ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            /*
             * use the window size for which we have precomputation
             */
            wsize[num] = pre_comp->w;
            tmp_wNAF = compute_wNAF(scalar, wsize[num], &tmp_len);
            if (!tmp_wNAF)
                goto err;

            if (tmp_len <= max_len) {
                /*
                 * One of the other wNAFs is at least as long as the wNAF
                 * belonging to the generator, so wNAF splitting will not buy
                 * us anything.
                 */

                numblocks = 1;
                totalnum = num + 1; /* don't use wNAF splitting */
                wNAF[num] = tmp_wNAF;
                wNAF[num + 1] = NULL;
                wNAF_len[num] = tmp_len;
                if (tmp_len > max_len)
                    max_len = tmp_len;
                /*
                 * pre_comp->points starts with the points that we need here:
                 */
                val_sub[num] = pre_comp->points;
            } else {
                /*
                 * don't include tmp_wNAF directly into wNAF array - use wNAF
                 * splitting and include the blocks
                 */

                signed char *pp;
                EC_POINT **tmp_points;

                if (tmp_len < numblocks * blocksize) {
                    /*
                     * possibly we can do with fewer blocks than estimated
                     */
                    numblocks = (tmp_len + blocksize - 1) / blocksize;
                    if (numblocks > pre_comp->numblocks) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        goto err;
                    }
                    totalnum = num + numblocks;
                }

                /* split wNAF in 'numblocks' parts */
                pp = tmp_wNAF;
                tmp_points = pre_comp->points;

                for (i = num; i < totalnum; i++) {
                    if (i < totalnum - 1) {
                        wNAF_len[i] = blocksize;
                        if (tmp_len < blocksize) {
                            ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                            goto err;
                        }
                        tmp_len -= blocksize;
                    } else
                        /*
                         * last block gets whatever is left (this could be
                         * more or less than 'blocksize'!)
                         */
                        wNAF_len[i] = tmp_len;

                    wNAF[i + 1] = NULL;
                    wNAF[i] = OPENSSL_malloc(wNAF_len[i]);
                    if (wNAF[i] == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    memcpy(wNAF[i], pp, wNAF_len[i]);
                    if (wNAF_len[i] > max_len)
                        max_len = wNAF_len[i];

                    if (*tmp_points == NULL) {
                        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
                        OPENSSL_free(tmp_wNAF);
                        goto err;
                    }
                    val_sub[i] = tmp_points;
                    tmp_points += pre_points_per_block;
                    pp += blocksize;
                }
                OPENSSL_free(tmp_wNAF);
            }
        }
    }

    /*
     * All points we precompute now go into a single array 'val'.
     * 'val_sub[i]' is a pointer to the subarray for the i-th point, or to a
     * subarray of 'pre_comp->points' if we already have precomputation.
     */
    val = OPENSSL_malloc((num_val + 1) * sizeof(val[0]));
    if (val == NULL) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_MALLOC_FAILURE);
        goto err;
    }
    val[num_val] = NULL;        /* pivot element */

    /* allocate points for precomputation */
    v = val;
    for (i = 0; i < num + num_scalar; i++) {
        val_sub[i] = v;
        for (j = 0; j < ((size_t)1 << (wsize[i] - 1)); j++) {
            *v = EC_POINT_new(group);
            if (*v == NULL)
                goto err;
            v++;
        }
    }
    if (!(v == val + num_val)) {
        ECerr(EC_F_EC_WNAF_MUL, ERR_R_INTERNAL_ERROR);
        goto err;
    }

    if (!(tmp = EC_POINT_new(group)))
        goto err;

    /*-
     * prepare precomputed values:
     *    val_sub[i][0] :=     points[i]
     *    val_sub[i][1] := 3 * points[i]
     *    val_sub[i][2] := 5 * points[i]
     *    ...
     */
    for (i = 0; i < num + num_scalar; i++) {
        if (i < num) {
            if (!EC_POINT_copy(val_sub[i][0], points[i]))
                goto err;
        } else {
            if (!EC_POINT_copy(val_sub[i][0], generator))
                goto err;
        }

        if (wsize[i] > 1) {
            if (!EC_POINT_dbl(group, tmp, val_sub[i][0], ctx))
                goto err;
            for (j = 1; j < ((size_t)1 << (wsize[i] - 1)); j++) {
                if (!EC_POINT_add
                    (group, val_sub[i][j], val_sub[i][j - 1], tmp, ctx))
                    goto err;
            }
        }
    }

#if 1                           /* optional; EC_window_bits_for_scalar_size
                                 * assumes we do this step */
    if (!EC_POINTs_make_affine(group, num_val, val, ctx))
        goto err;
#endif

    r_is_at_infinity = 1;

    for (k = max_len - 1; k >= 0; k--) {
        if (!r_is_at_infinity) {
            if (!EC_POINT_dbl(group, r, r, ctx))
                goto err;
        }

        for (i = 0; i < totalnum; i++) {
            if (wNAF_len[i] > (size_t)k) {
                int digit = wNAF[i][k];
                int is_neg;

                if (digit) {
                    is_neg = digit < 0;

                    if (is_neg)
                        digit = -digit;

                    if (is_neg != r_is_inverted) {
                        if (!r_is_at_infinity) {
                            if (!EC_POINT_invert(group, r, ctx))
                                goto err;
                        }
                        r_is_inverted = !r_is_inverted;
                    }

                    /* digit > 0 */

                    if (r_is_at_infinity) {
                        if (!EC_POINT_copy(r, val_sub[i][digit >> 1]))
                            goto err;
                        r_is_at_infinity = 0;
                    } else {
                        if (!EC_POINT_add
                            (group, r, r, val_sub[i][digit >> 1], ctx))
                            goto err;
                    }
                }
            }
        }
    }

    if (r_is_at_infinity) {
        if (!EC_POINT_set_to_infinity(group, r))
            goto err;
    } else {
        if (r_is_inverted)
            if (!EC_POINT_invert(group, r, ctx))
                goto err;
    }

    ret = 1;

 err:
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
    if (tmp != NULL)
        EC_POINT_free(tmp);
    if (wsize != NULL)
        OPENSSL_free(wsize);
    if (wNAF_len != NULL)
        OPENSSL_free(wNAF_len);
    if (wNAF != NULL) {
        signed char **w;

        for (w = wNAF; *w != NULL; w++)
            OPENSSL_free(*w);

        OPENSSL_free(wNAF);
    }
    if (val != NULL) {
        for (v = val; *v != NULL; v++)
            EC_POINT_clear_free(*v);

        OPENSSL_free(val);
    }
    if (val_sub != NULL) {
        OPENSSL_free(val_sub);
    }
    return ret;
}

/*-
 * ec_wNAF_precompute_mult()
 * creates an EC_PRE_COMP object with preprecomputed multiples of the generator
 * for use with wNAF splitting as implemented in ec_wNAF_mul().
 *
 * 'pre_comp->points' is an array of multiples of the generator
 * of the following form:
 * points[0] =     generator;
 * points[1] = 3 * generator;
 * ...
 * points[2^(w-1)-1] =     (2^(w-1)-1) * generator;
 * points[2^(w-1)]   =     2^blocksize * generator;
 * points[2^(w-1)+1] = 3 * 2^blocksize * generator;
 * ...
 * points[2^(w-1)*(numblocks-1)-1] = (2^(w-1)) *  2^(blocksize*(numblocks-2)) * generator
 * points[2^(w-1)*(numblocks-1)]   =              2^(blocksize*(numblocks-1)) * generator
 * ...
 * points[2^(w-1)*numblocks-1]     = (2^(w-1)) *  2^(blocksize*(numblocks-1)) * generator
 * points[2^(w-1)*numblocks]       = NULL
 */
int ec_wNAF_precompute_mult(EC_GROUP *group, BN_CTX *ctx)
{
    const EC_POINT *generator;
    EC_POINT *tmp_point = NULL, *base = NULL, **var;
    BN_CTX *new_ctx = NULL;
    BIGNUM *order;
    size_t i, bits, w, pre_points_per_block, blocksize, numblocks, num;
    EC_POINT **points = NULL;
    EC_PRE_COMP *pre_comp;
    int ret = 0;

    /* if there is an old EC_PRE_COMP object, throw it away */
    EC_EX_DATA_free_data(&group->extra_data, ec_pre_comp_dup,
                         ec_pre_comp_free, ec_pre_comp_clear_free);

    if ((pre_comp = ec_pre_comp_new(group)) == NULL)
        return 0;

    generator = EC_GROUP_get0_generator(group);
    if (generator == NULL) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNDEFINED_GENERATOR);
        goto err;
    }

    if (ctx == NULL) {
        ctx = new_ctx = BN_CTX_new();
        if (ctx == NULL)
            goto err;
    }

    BN_CTX_start(ctx);
    order = BN_CTX_get(ctx);
    if (order == NULL)
        goto err;

    if (!EC_GROUP_get_order(group, order, ctx))
        goto err;
    if (BN_is_zero(order)) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, EC_R_UNKNOWN_ORDER);
        goto err;
    }

    bits = BN_num_bits(order);
    /*
     * The following parameters mean we precompute (approximately) one point
     * per bit. TBD: The combination 8, 4 is perfect for 160 bits; for other
     * bit lengths, other parameter combinations might provide better
     * efficiency.
     */
    blocksize = 8;
    w = 4;
    if (EC_window_bits_for_scalar_size(bits) > w) {
        /* let's not make the window too small ... */
        w = EC_window_bits_for_scalar_size(bits);
    }

    numblocks = (bits + blocksize - 1) / blocksize; /* max. number of blocks
                                                     * to use for wNAF
                                                     * splitting */

    pre_points_per_block = (size_t)1 << (w - 1);
    num = pre_points_per_block * numblocks; /* number of points to compute
                                             * and store */

    points = OPENSSL_malloc(sizeof(EC_POINT *) * (num + 1));
    if (!points) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    var = points;
    var[num] = NULL;            /* pivot */
    for (i = 0; i < num; i++) {
        if ((var[i] = EC_POINT_new(group)) == NULL) {
            ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
            goto err;
        }
    }

    if (!(tmp_point = EC_POINT_new(group)) || !(base = EC_POINT_new(group))) {
        ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_MALLOC_FAILURE);
        goto err;
    }

    if (!EC_POINT_copy(base, generator))
        goto err;

    /* do the precomputation */
    for (i = 0; i < numblocks; i++) {
        size_t j;

        if (!EC_POINT_dbl(group, tmp_point, base, ctx))
            goto err;

        if (!EC_POINT_copy(*var++, base))
            goto err;

        for (j = 1; j < pre_points_per_block; j++, var++) {
            /*
             * calculate odd multiples of the current base point
             */
            if (!EC_POINT_add(group, *var, tmp_point, *(var - 1), ctx))
                goto err;
        }

        if (i < numblocks - 1) {
            /*
             * get the next base (multiply current one by 2^blocksize)
             */
            size_t k;

            if (blocksize <= 2) {
                ECerr(EC_F_EC_WNAF_PRECOMPUTE_MULT, ERR_R_INTERNAL_ERROR);
                goto err;
            }

            if (!EC_POINT_dbl(group, base, tmp_point, ctx))
                goto err;
            for (k = 2; k < blocksize; k++) {
                if (!EC_POINT_dbl(group, base, base, ctx))
                    goto err;
            }
        }
    }

    if (!EC_POINTs_make_affine(group, num, points, ctx))
        goto err;

    pre_comp->group = group;
    pre_comp->blocksize = blocksize;
    pre_comp->numblocks = numblocks;
    pre_comp->w = w;
    pre_comp->points = points;
    points = NULL;
    pre_comp->num = num;

    if (!EC_EX_DATA_set_data(&group->extra_data, pre_comp,
                             ec_pre_comp_dup, ec_pre_comp_free,
                             ec_pre_comp_clear_free))
        goto err;
    pre_comp = NULL;

    ret = 1;
 err:
    if (ctx != NULL)
        BN_CTX_end(ctx);
    if (new_ctx != NULL)
        BN_CTX_free(new_ctx);
    if (pre_comp)
        ec_pre_comp_free(pre_comp);
    if (points) {
        EC_POINT **p;

        for (p = points; *p != NULL; p++)
            EC_POINT_free(*p);
        OPENSSL_free(points);
    }
    if (tmp_point)
        EC_POINT_free(tmp_point);
    if (base)
        EC_POINT_free(base);
    return ret;
}

int ec_wNAF_have_precompute_mult(const EC_GROUP *group)
{
    if (EC_EX_DATA_get_data
        (group->extra_data, ec_pre_comp_dup, ec_pre_comp_free,
         ec_pre_comp_clear_free) != NULL)
        return 1;
    else
        return 0;
}

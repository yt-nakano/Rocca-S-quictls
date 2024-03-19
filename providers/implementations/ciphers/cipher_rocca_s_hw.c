/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
/* rocca-s cipher implementation */

#include "cipher_rocca_s.h"
#include "include/crypto/rocca.h"

#define enc(m, k) _mm_aesenc_si128(m, k)
#define xor(a, b) _mm_xor_si128(a, b)
#define and(a, b) _mm_and_si128(a, b)
#define setzero() _mm_setzero_si128()

#define S_NUM              ROCCA_S_S_NUM
#define M_NUM              2
#define NUM_LOOP_FOR_INIT  16
#define NUM_LOOP_FOR_TAG   16
#define UPDATE_STATE_VARS  __m128i S[S_NUM], M[M_NUM], tmp1, tmp6;
#define ENCRYPTION_VARS    UPDATE_STATE_VARS __m128i C[M_NUM], strm[M_NUM];

#define STRM_UPDATE(X) \
    do { \
        tmp6 = S[6]; \
        tmp1 = S[1]; \
        strm[0] = enc(xor(S[3], S[5]), S[0]); \
        strm[1] = enc(xor(S[4], S[6]), S[2]); \
        S[6] = enc(S[5], S[4]); \
        S[5] = enc(S[4], S[3]); \
        S[4] = enc(S[3], X[1]); \
        S[3] = enc(S[2], tmp6); \
        S[2] = enc(S[1], S[0]); \
        S[1] = enc(S[0], X[0]); \
        S[0] = xor(tmp6, tmp1); \
    } while (0)

#define UPDATE(X) \
    do { \
        tmp6 = S[6]; \
        tmp1 = S[1]; \
        S[6] = enc(S[5], S[4]); \
        S[5] = enc(S[4], S[3]); \
        S[4] = enc(S[3], X[1]); \
        S[3] = enc(S[2], tmp6); \
        S[2] = enc(S[1], S[0]); \
        S[1] = enc(S[0], X[0]); \
        S[0] = xor(tmp6, tmp1); \
    } while (0)

#define MAKE_STRM() \
    do { \
        strm[0] = enc(xor(S[3], S[5]), S[0]); \
        strm[1] = enc(xor(S[4], S[6]), S[2]); \
    } while (0)

#define LOAD_MSG(src, m) \
    do { \
        m[0] = _mm_loadu_si128((const __m128i*)((src)   )); \
        m[1] = _mm_loadu_si128((const __m128i*)((src)+16)); \
    } while (0)

#define MSG_STORE(dst, m) \
    do { \
        _mm_storeu_si128((__m128i*)((dst)   ), m[0]); \
        _mm_storeu_si128((__m128i*)((dst)+16), m[1]); \
    } while (0)

#define MAKE_C() \
    do { \
        C[0] = xor(M[0], strm[0]); \
        C[1] = xor(M[1], strm[1]); \
    } while (0)

#define STORE_C(dst) \
    do { \
        _mm_storeu_si128((__m128i*)((dst)   ), C[0]); \
        _mm_storeu_si128((__m128i*)((dst)+16), C[1]); \
    } while (0)

#define COPY_STATE_TO_LOCAL(ctx) \
    for (size_t i = 0; i < S_NUM; ++i) { \
        S[i] = _mm_loadu_si128((const __m128i*)&(ctx->S[i*16])); \
    }

#define COPY_STATE_FROM_LOCAL(ctx) \
    for (size_t i = 0; i < S_NUM; ++i) { \
        _mm_storeu_si128((__m128i*)&(ctx->S[i*16]), S[i]); \
    }

#define ENCODE_IN_LITTLE_ENDIAN(bytes, v) \
    do { \
        bytes[ 0] = ((uint64_t)(v) << (    3)); \
        bytes[ 1] = ((uint64_t)(v) >> (1*8-3)); \
        bytes[ 2] = ((uint64_t)(v) >> (2*8-3)); \
        bytes[ 3] = ((uint64_t)(v) >> (3*8-3)); \
        bytes[ 4] = ((uint64_t)(v) >> (4*8-3)); \
        bytes[ 5] = ((uint64_t)(v) >> (5*8-3)); \
        bytes[ 6] = ((uint64_t)(v) >> (6*8-3)); \
        bytes[ 7] = ((uint64_t)(v) >> (7*8-3)); \
        bytes[ 8] = ((uint64_t)(v) >> (8*8-3)); \
        bytes[ 9] = 0; \
        bytes[10] = 0; \
        bytes[11] = 0; \
        bytes[12] = 0; \
        bytes[13] = 0; \
        bytes[14] = 0; \
        bytes[15] = 0; \
    } while (0)

/* macros for buffering */

#define ROCCA_OP_INIT 1
#define ROCCA_OP_AAD  2
#define ROCCA_OP_ENC  3
#define ROCCA_OP_DEC  4
#define ROCCA_OP_TAG  5

#define CACHE_CLEAR(ctx) \
    do { \
        memset(ctx->mblk, 0, sizeof(ctx->mblk)); \
        ctx->size_caching = 0; \
    } while (0)

#define CACHE_PUSH(ctx, src, size) \
    do { \
        memcpy(ctx->mblk + ctx->size_caching, src, size); \
        ctx->size_caching += size; \
    } while (0)

#define XOR_BYTES(dst, src1, src2, size) \
    for (size_t ii = 0; ii < size; ++ii) { \
        (dst)[ii] = (src1)[ii] ^ (src2)[ii]; \
    }

#define MAKE_STRM_AAD(ctx)

#define MAKE_STRM_ENC(ctx) if (ctx->size_caching == 0) { MAKE_STRM(); MSG_STORE(ctx->strm, strm); }

#define MAKE_STRM_DEC(ctx) MAKE_STRM_ENC(ctx)

#define BYTES_LTE_MSGBLK_AAD(ctx, out, in, size) \
    CACHE_PUSH(ctx, in, size);

#define BYTES_LTE_MSGBLK_ENC(ctx, out, in, size) \
    do { \
        size_t offset = ctx->size_caching; \
        CACHE_PUSH(ctx, in, size); \
        XOR_BYTES(out, in, ctx->strm + offset, size); \
    } while (0)

#define BYTES_LTE_MSGBLK_DEC(ctx, out, in, size) \
    do { \
        size_t offset = ctx->size_caching; \
        XOR_BYTES(out, in, ctx->strm + offset, size); \
        CACHE_PUSH(ctx, out, size); \
    } while (0)

#define BYTES_LTE_MSGBLK_OP_AT_FIRST(ctx, op, sizename, out, in, size, size_processed) \
    do { \
        size_processed = 0; \
        if (sizeof(ctx->mblk) <= (ctx->size_caching + size)) { \
            if (ctx->size_caching != 0) { \
                size_processed = sizeof(ctx->mblk) - ctx->size_caching; \
                BYTES_LTE_MSGBLK_##op(ctx, out, in, size_processed); \
                LOAD_MSG(ctx->mblk, M); \
                UPDATE(M); \
                CACHE_CLEAR(ctx); \
                ctx->sizename += size_processed; \
            } \
        } else { \
            if (size != 0) { \
                size_processed = size; \
                MAKE_STRM_##op(ctx); \
                BYTES_LTE_MSGBLK_##op(ctx, out, in, size_processed); \
                ctx->sizename += size_processed; \
            } \
        } \
    } while (0)

#define BYTES_LTE_MSGBLK_AAD_AT_FIRST(ctx, out, in, size, size_processed) BYTES_LTE_MSGBLK_OP_AT_FIRST(ctx, AAD, size_ad, out, in, size, size_processed)
#define BYTES_LTE_MSGBLK_ENC_AT_FIRST(ctx, out, in, size, size_processed) BYTES_LTE_MSGBLK_OP_AT_FIRST(ctx, ENC, size_m , out, in, size, size_processed)
#define BYTES_LTE_MSGBLK_DEC_AT_FIRST(ctx, out, in, size, size_processed) BYTES_LTE_MSGBLK_OP_AT_FIRST(ctx, DEC, size_m , out, in, size, size_processed)

#define FINISH_PREVIOUS_OPERATION(ctx) \
    do { \
        LOAD_MSG(ctx->mblk, M); \
        UPDATE(M); \
        CACHE_CLEAR(ctx); \
    } while (0)

static const unsigned char Z0[] = {0xcd,0x65,0xef,0x23,0x91,0x44,0x37,0x71,0x22,0xae,0x28,0xd7,0x98,0x2f,0x8a,0x42};
static const unsigned char Z1[] = {0xbc,0xdb,0x89,0x81,0xa5,0xdb,0xb5,0xe9,0x2f,0x3b,0x4d,0xec,0xcf,0xfb,0xc0,0xb5};

static void keyiv_setup(PROV_ROCCA_S_CTX *ctx, const unsigned char *key, const unsigned char *iv)
{
    UPDATE_STATE_VARS;
    __m128i K[2];

    K[0] = _mm_loadu_si128((const __m128i*)(key+ 0));
    K[1] = _mm_loadu_si128((const __m128i*)(key+16));
    S[0] = K[1];
    S[1] = _mm_loadu_si128((const __m128i*)(iv));
    S[2] = _mm_loadu_si128((const __m128i*)(Z0));
    S[3] = K[0];
    S[4] = _mm_loadu_si128((const __m128i*)(Z1));
    S[5] = _mm_xor_si128(S[1], S[0]);
    S[6] = _mm_setzero_si128();

    M[0] = S[2];
    M[1] = S[4];

    for (size_t i = 0; i < NUM_LOOP_FOR_INIT; ++i) {
        UPDATE(M);
    }

    S[0] = _mm_xor_si128(S[0], K[0]);
    S[1] = _mm_xor_si128(S[1], K[0]);
    S[2] = _mm_xor_si128(S[2], K[1]);
    S[3] = _mm_xor_si128(S[3], K[0]);
    S[4] = _mm_xor_si128(S[4], K[0]);
    S[5] = _mm_xor_si128(S[5], K[1]);
    S[6] = _mm_xor_si128(S[6], K[1]);

    COPY_STATE_FROM_LOCAL(ctx);
    ctx->size_m = 0;
    ctx->size_ad = 0;
    CACHE_CLEAR(ctx);
    ctx->prev_op = ROCCA_OP_INIT;
}

static void process_enc(PROV_ROCCA_S_CTX *ctx, unsigned char *out, const unsigned char *in, size_t size)
{
    ENCRYPTION_VARS;
    size_t i = 0;

    COPY_STATE_TO_LOCAL(ctx);

    if ((ctx->size_caching != 0) && (ctx->prev_op != ROCCA_OP_ENC)) {
        FINISH_PREVIOUS_OPERATION(ctx);
    }
    BYTES_LTE_MSGBLK_ENC_AT_FIRST(ctx, out, in, size, i);
    if (size <= i) goto L_END;

    in += i;
    out += i;
    size -= i;
    i = 0;
    for (size_t size2 = size / (16*M_NUM*4) * (16*M_NUM*4); i < size2; ) {
        LOAD_MSG(in + i, M); STRM_UPDATE(M); MAKE_C(); STORE_C(out + i); i += 16*M_NUM;
        LOAD_MSG(in + i, M); STRM_UPDATE(M); MAKE_C(); STORE_C(out + i); i += 16*M_NUM;
        LOAD_MSG(in + i, M); STRM_UPDATE(M); MAKE_C(); STORE_C(out + i); i += 16*M_NUM;
        LOAD_MSG(in + i, M); STRM_UPDATE(M); MAKE_C(); STORE_C(out + i); i += 16*M_NUM;
    }
    for (size_t size2 = size / (16*M_NUM) * (16*M_NUM); i < size2; i += 16*M_NUM) {
        LOAD_MSG(in + i, M); STRM_UPDATE(M); MAKE_C(); STORE_C(out + i);
    }
    if (i < size) {
        size_t size2 = size - i;
        MAKE_STRM();
        MSG_STORE(ctx->strm, strm);
        BYTES_LTE_MSGBLK_ENC(ctx, out + i, in + i, size2);
        i += size2;
    }
    ctx->size_m += i;
L_END:
    COPY_STATE_FROM_LOCAL(ctx);
    ctx->prev_op = ROCCA_OP_ENC;
}

static void process_dec(PROV_ROCCA_S_CTX *ctx, unsigned char *out, const unsigned char *in, size_t size)
{
    ENCRYPTION_VARS;
    size_t i = 0;

    COPY_STATE_TO_LOCAL(ctx);

    if ((ctx->size_caching != 0) && (ctx->prev_op != ROCCA_OP_DEC)) {
        FINISH_PREVIOUS_OPERATION(ctx);
    }
    BYTES_LTE_MSGBLK_DEC_AT_FIRST(ctx, out, in, size, i);
    if (size <= i) goto L_END;

    in += i;
    out += i;
    size -= i;
    i = 0;
    for (size_t size2 = size / (16*M_NUM*4) * (16*M_NUM*4); i < size2; ) {
        LOAD_MSG(in + i, M); MAKE_STRM(); MAKE_C(); UPDATE(C); STORE_C(out + i); i += 16*M_NUM;
        LOAD_MSG(in + i, M); MAKE_STRM(); MAKE_C(); UPDATE(C); STORE_C(out + i); i += 16*M_NUM;
        LOAD_MSG(in + i, M); MAKE_STRM(); MAKE_C(); UPDATE(C); STORE_C(out + i); i += 16*M_NUM;
        LOAD_MSG(in + i, M); MAKE_STRM(); MAKE_C(); UPDATE(C); STORE_C(out + i); i += 16*M_NUM;
    }
    for (size_t size2 = size / (16*M_NUM) * (16*M_NUM); i < size2; i += 16*M_NUM) {
        LOAD_MSG(in + i, M); MAKE_STRM(); MAKE_C(); UPDATE(C); STORE_C(out + i);
    }
    if (i < size) {
        size_t size2 = size - i;
        MAKE_STRM();
        MSG_STORE(ctx->strm, strm);
        BYTES_LTE_MSGBLK_DEC(ctx, out + i, in + i, size2);
        i += size2;
    }
    ctx->size_m += i;
L_END:
    COPY_STATE_FROM_LOCAL(ctx);
    ctx->prev_op = ROCCA_OP_DEC;
}

static void add_ad(PROV_ROCCA_S_CTX *ctx, unsigned char *out, const unsigned char *in, size_t size)
{
    UPDATE_STATE_VARS;
    size_t i = 0;

    COPY_STATE_TO_LOCAL(ctx);

    BYTES_LTE_MSGBLK_AAD_AT_FIRST(ctx, out, in, size, i);
    if (size <= i) goto L_END;

    in += i;
    size -= i;
    i = 0;
    for (size_t size2 = size / (16*M_NUM) * (16*M_NUM); i < size2; i += 16*M_NUM) {
        LOAD_MSG(in + i, M);
        UPDATE(M);
    }
    if (i < size) {
        size_t size2 = size - i;
        CACHE_PUSH(ctx, in + i, size2);
        i += size2;
    }
    ctx->size_ad += i;
L_END:
    COPY_STATE_FROM_LOCAL(ctx);
    ctx->prev_op = ROCCA_OP_AAD;
}

static void make_tag(PROV_ROCCA_S_CTX *ctx, unsigned char *tag)
{
    UPDATE_STATE_VARS;
    uint64_t size_ad = ctx->size_ad;
    uint64_t size_m = ctx->size_m;
    unsigned char bytes_bitlen_ad[16];
    unsigned char bytes_bitlen_m [16];
    __m128i tag128a = setzero();
    __m128i tag128b = setzero();

    COPY_STATE_TO_LOCAL(ctx);

    if (ctx->size_caching != 0) {
        FINISH_PREVIOUS_OPERATION(ctx);
    }

    ENCODE_IN_LITTLE_ENDIAN(bytes_bitlen_ad, size_ad);
    ENCODE_IN_LITTLE_ENDIAN(bytes_bitlen_m , size_m );
    M[0] = _mm_loadu_si128((const __m128i*)bytes_bitlen_ad);
    M[1] = _mm_loadu_si128((const __m128i*)bytes_bitlen_m );
    for (size_t i = 0; i < NUM_LOOP_FOR_TAG; ++i) {
        UPDATE(M);
    }

    for (size_t i = 0; i <= 3; ++i) {
        tag128a = xor(tag128a, S[i]);
    }
    for (size_t i = 4; i <= 6; ++i) {
        tag128b = xor(tag128b, S[i]);
    }
    _mm_storeu_si128((__m128i*)(tag   ), tag128a);
    _mm_storeu_si128((__m128i*)(tag+16), tag128b);
    ctx->prev_op = ROCCA_OP_TAG;
}

static int rocca_s_init(PROV_CIPHER_CTX *bctx)
{
    PROV_ROCCA_S_CTX *ctx = (PROV_ROCCA_S_CTX *)bctx;
    keyiv_setup(ctx, ctx->key.key, ctx->iv);
    return 1;
}

static int rocca_s_cipher(PROV_CIPHER_CTX *bctx,
                          unsigned char *out, size_t *outl,
                          const unsigned char *in, size_t inl)
{
    PROV_ROCCA_S_CTX *ctx = (PROV_ROCCA_S_CTX *)bctx;
    int ret = 1;

    if (bctx->enc) {
        if ((out != NULL) && (in != NULL)) {
            process_enc(ctx, out, in, inl);
            if (outl) *outl = inl;
        }
        else if (in != NULL) {
            add_ad(ctx, out, in, inl);
            if (outl != NULL) *outl = inl;
        }
        else if (out != NULL) {
            make_tag(ctx, ctx->tag);
            if (outl != NULL) *outl = 0;
        }
        else {
        }
    }
    else {
        if ((out != NULL) && (in != NULL)) {
            process_dec(ctx, out, in, inl);
            if (outl) *outl = inl;
        }
        else if (in != NULL) {
            add_ad(ctx, out, in, inl);
            if (outl != NULL) *outl = inl;
        }
        else if (out != NULL) {
            unsigned char tag[sizeof(ctx->tag)];
            make_tag(ctx, tag);
            if (memcmp(tag, ctx->tag, ctx->tag_len) != 0) ret = 0;
            if (outl != NULL) *outl = 0;
        }
        else {
        }
    }
    return ret;
}

static int rocca_s_initkey(PROV_CIPHER_CTX *bctx,
                           const unsigned char *key, size_t keylen)
{
    if (key != NULL) {
        PROV_ROCCA_S_CTX *ctx = (PROV_ROCCA_S_CTX *)bctx;
        memcpy(ctx->key.key, key, keylen);
        rocca_s_init(bctx);
    }
    return 1;
}

static int rocca_s_initiv(PROV_CIPHER_CTX *bctx)
{
    if (bctx->iv_set) {
        PROV_ROCCA_S_CTX *ctx = (PROV_ROCCA_S_CTX *)bctx;
        memcpy(ctx->iv, bctx->iv, ROCCA_S_IVLEN);
        rocca_s_init(bctx);
    }
    return 1;
}

static const PROV_CIPHER_HW_ROCCA_S rocca_s_hw =
{
    { rocca_s_initkey, NULL },
    rocca_s_cipher,
    rocca_s_initiv
};

const PROV_CIPHER_HW *ossl_prov_cipher_hw_rocca_s(size_t keybits)
{
    return (PROV_CIPHER_HW *)&rocca_s_hw;
}

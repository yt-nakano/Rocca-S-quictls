/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
#ifndef OSSL_CRYPTO_ROCCA_SIMD_FN_H
#define OSSL_CRYPTO_ROCCA_SIMD_FN_H
#pragma once
 
#if defined(__ARM_FEATURE_CRYPTO) && !defined(__ARM_FEATURE_AES)
 #define __ARM_FEATURE_AES
#endif

#if !defined(__ARM_FEATURE_CRYPTO)
 #error __ARM_FEATURE_CRYPTO is not defined
#endif

#if !defined(__ARM_FEATURE_AES)
 #error __ARM_FEATURE_AES is not defined
#endif

#include <arm_neon.h>

#ifndef __m128i
#define __m128i uint8x16_t
#endif

#ifndef _mm_load_si128
#define _mm_load_si128(p)      vld1q_u8((uint8_t*)p)
#endif

#ifndef _mm_loadu_si128
#define _mm_loadu_si128(p)     vld1q_u8((uint8_t*)p)
#endif

#ifndef _mm_lddq_si128
#define _mm_lddq_si128(p)      vld1q_u8((uint8_t*)p)
#endif

#ifndef _mm_lddqu_si128
#define _mm_lddqu_si128(p)     vld1q_u8((uint8_t*)p)
#endif

#ifndef _mm_store_si128
#define _mm_store_si128(p,v)   vst1q_u8((uint8_t*)p,v)
#endif

#ifndef _mm_storeu_si128
#define _mm_storeu_si128(p,v)  vst1q_u8((uint8_t*)p,v)
#endif

#ifndef _mm_and_si128
#define _mm_and_si128(a,b)     vandq_u8(a,b)
#endif

#ifndef _mm_xor_si128
#define _mm_xor_si128(a,b)     veorq_u8(a,b)
#endif

#ifndef _mm_setzero_si128
#define _mm_setzero_si128()    vdupq_n_u8(0)
#endif

#ifndef _mm_aesenc_si128
#define _mm_aesenc_si128(d,k)  _mm_xor_si128(vaesmcq_u8(vaeseq_u8(_mm_xor_si128(d,k),k)),k) 
#endif
  
#ifndef _mm256_aesenc_epi128
#define _mm256_aesenc_epi128 _MM256_aesenc_epi128
static inline __m256i _MM256_aesenc_epi128(__m256i a, __m256i RoundKey) {
    __m128i a0 = _mm256_castsi256_si128(a);
    __m128i k0 = _mm256_castsi256_si128(RoundKey);
    __m128i a1 = _mm256_extracti128_si256(a, 1);
    __m128i k1 = _mm256_extracti128_si256(RoundKey, 1);
    a0 = _mm_aesenc_si128(a0, k0);
    a1 = _mm_aesenc_si128(a1, k1);
    return _mm256_set_m128i(a1, a0);
}
#endif

#ifndef _mm512_aesenc_epi128
#define _mm512_aesenc_epi128 _MM512_aesenc_epi128
static inline __m512i _MM512_aesenc_epi128(__m512i a, __m512i RoundKey) {
    __m512i c;
    __m128i a0 = _mm512_extracti32x4_epi32(a, 0);
    __m128i a1 = _mm512_extracti32x4_epi32(a, 1);
    __m128i a2 = _mm512_extracti32x4_epi32(a, 2);
    __m128i a3 = _mm512_extracti32x4_epi32(a, 3);
    __m128i k0 = _mm512_extracti32x4_epi32(RoundKey, 0);
    __m128i k1 = _mm512_extracti32x4_epi32(RoundKey, 1);
    __m128i k2 = _mm512_extracti32x4_epi32(RoundKey, 2);
    __m128i k3 = _mm512_extracti32x4_epi32(RoundKey, 3);
    __m128i c0 = _mm_aesenc_si128(a0, k0);
    __m128i c1 = _mm_aesenc_si128(a1, k1);
    __m128i c2 = _mm_aesenc_si128(a2, k2);
    __m128i c3 = _mm_aesenc_si128(a3, k3);
    c = _mm512_inserti32x4(c, c0, 0);
    c = _mm512_inserti32x4(c, c1, 1);
    c = _mm512_inserti32x4(c, c2, 2);
    c = _mm512_inserti32x4(c, c3, 3);
    return c;
}
#endif

#endif

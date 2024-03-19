/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
/* Dispatch functions for rocca-s cipher */

#include "prov/ciphercommon.h"

#define ROCCA_S_KEYLEN          32
#define ROCCA_S_IVLEN           16
#define ROCCA_S_TAGLEN          32
#define ROCCA_S_MSG_BLOCK_SIZE  32
#define ROCCA_S_S_NUM            7

typedef struct {
    PROV_CIPHER_CTX base;     /* must be first */
    union {
        OSSL_UNION_ALIGN;
        unsigned char key[ROCCA_S_KEYLEN];
    } key;
    unsigned char iv[ROCCA_S_IVLEN];
    unsigned char S[16 * ROCCA_S_S_NUM];
    unsigned char tag[ROCCA_S_TAGLEN];
    size_t key_len;
    size_t iv_len;
    size_t tag_len;
    size_t tls_aad_pad_sz;
    size_t size_ad;
    size_t size_m;

    unsigned char strm[ROCCA_S_MSG_BLOCK_SIZE];
    unsigned char mblk[ROCCA_S_MSG_BLOCK_SIZE];
    size_t size_caching;
    size_t prev_op;
} PROV_ROCCA_S_CTX;

typedef struct prov_cipher_hw_rocca_s_st {
    PROV_CIPHER_HW base; /* must be first */
    int (*aead_cipher)(PROV_CIPHER_CTX *dat, unsigned char *out, size_t *outl,
                       const unsigned char *in, size_t len);
    int (*initiv)(PROV_CIPHER_CTX *ctx);
} PROV_CIPHER_HW_ROCCA_S;

const PROV_CIPHER_HW *ossl_prov_cipher_hw_rocca_s(size_t keybits);

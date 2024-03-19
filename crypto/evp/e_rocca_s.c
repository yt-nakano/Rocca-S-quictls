/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
#include <stdio.h>
#include "internal/cryptlib.h"
#include "internal/endian.h"

#ifndef OPENSSL_NO_ROCCA

# include <openssl/evp.h>
# include <openssl/objects.h>
# include "crypto/evp.h"
# include "evp_local.h"


#define ROCCA_KEY_SIZE 32
#define ROCCA_IV_SIZE 16

typedef struct {
    uint8_t key[32];
    uint8_t iv[16];
    uint8_t S[16 * 7];
    size_t sizeAD;
    size_t sizeM;
} EVP_ROCCA_S_KEY;

static int rocca_s_init_key(EVP_CIPHER_CTX *ctx, const unsigned char *key,
    const unsigned char *iv, int enc)
{
    return 1;
}

static int rocca_s_cipher(EVP_CIPHER_CTX *ctx, unsigned char *out, const unsigned char *in, size_t len)
{
    if (in != out)
        memcpy(out, in, len);
    return 1;
}

static const EVP_CIPHER rocca_s = {
    NID_rocca_s,
    1,
    ROCCA_KEY_SIZE,
    ROCCA_IV_SIZE,
    EVP_CIPH_CUSTOM_IV | EVP_CIPH_ALWAYS_CALL_INIT,
    EVP_ORIG_GLOBAL,
    rocca_s_init_key,
    rocca_s_cipher,
    NULL, //rocca_s_cleanup,
    sizeof(EVP_ROCCA_S_KEY), //0,
    NULL,
    NULL,
    NULL, //rocca_s_ctrl,
    NULL
};

const EVP_CIPHER *EVP_rocca_s(void)
{
    return &rocca_s;
}

#endif

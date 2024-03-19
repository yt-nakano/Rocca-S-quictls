/*
 * Copyright 2024 The OpenSSL Project Authors. All Rights Reserved.
 * Copyright (c) 2024 KDDI CORPORATION. All Rights Reserved.
 *
 * Licensed under the Apache License 2.0 (the "License").  You may not use
 * this file except in compliance with the License.  You can obtain a copy
 * in the file LICENSE in the source distribution or at
 * https://www.openssl.org/source/license.html
 */
 
#ifndef OSSL_CRYPTO_ROCCA_H
#define OSSL_CRYPTO_ROCCA_H
# pragma once

#include <stddef.h>
#include <stdint.h>

#if defined(ROCCA_ASM)
 #if defined(__aarch64__)
  #include "rocca_simd_arm.h"
 #else
  #include "rocca_simd_x86.h"
 #endif
#else
 #include "rocca_simd_c.h"
#endif

#endif

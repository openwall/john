/**
 * \file pkcs12.h
 *
 * \brief PKCS#12 Personal Information Exchange Syntax
 *
 *  Copyright (C) 2006-2015, ARM Limited, All Rights Reserved
 *  SPDX-License-Identifier: Apache-2.0
 *
 *  Licensed under the Apache License, Version 2.0 (the "License"); you may
 *  not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *  http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 *  WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 *
 *  This file is part of mbed TLS (https://tls.mbed.org)
 */

/*
 *  Enhanced with SIMD code, JimF, July 2016
 *  JtR changes placed in public domain.
 */

#ifndef MBEDTLS_PKCS12_H
#define MBEDTLS_PKCS12_H

#define MBEDTLS_PKCS12_DERIVE_KEY       1   /**< encryption/decryption key */
#define MBEDTLS_PKCS12_DERIVE_IV        2   /**< initialization vector     */
#define MBEDTLS_PKCS12_DERIVE_MAC_KEY   3   /**< integrity / MAC key       */

#include <string.h>
#include <stdio.h>
#include "sha.h"

// set next line to #if 1 to test non-SIMD logic
#if 0
#undef SIMD_COEF_32
#undef SHA1_ALGORITHM_NAME
#define SHA1_ALGORITHM_NAME		"32/" ARCH_BITS_STR
#endif

#if !defined(SIMD_COEF_32)

int pkcs12_pbe_derive_key( int md_type, int iterations, int id, const unsigned
		char *pwd,  size_t pwdlen, const unsigned char *salt, size_t saltlen,
		unsigned char *key, size_t keylen);

#else
// SIMD method

#define SSE_GROUP_SZ_SHA1 (SIMD_COEF_32*SIMD_PARA_SHA1)

int pkcs12_pbe_derive_key_simd( int md_type, int iterations, int id, const unsigned
		char *pwd[SSE_GROUP_SZ_SHA1],  size_t pwdlen[SSE_GROUP_SZ_SHA1], const unsigned char *salt, size_t saltlen,
		unsigned char *key[SSE_GROUP_SZ_SHA1], size_t keylen);

#endif

#endif /* pkcs12.h */

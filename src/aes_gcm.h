/*
 * Galois/Counter Mode (GCM) and GMAC with AES
 *
 * Copyright (c) 2012, Jouni Malinen <j@w1.fi>
 *
 * This software may be distributed under the terms of the BSD license.
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#if AC_BUILT
#include "autoconfig.h"
#endif

#if HAVE_LIBCRYPTO
#include <openssl/aes.h>
#endif

// #include "aes.h"

/**
 * aes_gcm_ae - GCM-AE_K(IV, P, A)
 */
int aes_gcm_ae(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *plain, size_t plain_len,
	       const uint8_t *aad, size_t aad_len, uint8_t *crypt, uint8_t *tag);


/**
 * aes_gcm_ad - GCM-AD_K(IV, C, A, T)
 */
int aes_gcm_ad(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	       const uint8_t *crypt, size_t crypt_len,
	       const uint8_t *aad, size_t aad_len, const uint8_t *tag, uint8_t *plain,
	       int skip_output);

int aes_gmac(const uint8_t *key, size_t key_len, const uint8_t *iv, size_t iv_len,
	     const uint8_t *aad, size_t aad_len, uint8_t *tag);

/*
 ---------------------------------------------------------------------------
 Copyright (c) 2002, Dr Brian Gladman <                 >, Worcester, UK.
 All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue Date: 24/01/2003

 This is an implementation of HMAC, the FIPS standard keyed hash function
*/

#ifndef _HMAC_H
#define _HMAC_H

//#include <memory.h>

#include "gladman_sha1.h"

#define IN_BLOCK_LENGTH     SHA1_BLOCK_SIZE
#define OUT_BLOCK_LENGTH    SHA1_DIGEST_SIZE
#define HMAC_IN_DATA        0xffffffff

#define HMAC_OK               0
#define HMAC_BAD_MODE        -1

#if defined(__cplusplus)
extern "C"
{
#endif

#include "common.h"

typedef struct
{   ARCH_WORD_32    key[IN_BLOCK_LENGTH / sizeof(ARCH_WORD_32)];
    sha1_ctx        ctx[1];
    unsigned int    klen;
} hmac_ctx;

void hmac_sha1_begin(hmac_ctx cx[1]);

int  hmac_sha1_key(const unsigned char key[], unsigned long key_len, hmac_ctx cx[1]);

void hmac_sha1_data(const unsigned char data[], unsigned long data_len, hmac_ctx cx[1]);

void hmac_sha1_end(unsigned char mac[], unsigned long mac_len, hmac_ctx cx[1]);

void hmac_sha1(const unsigned char key[], unsigned int key_len,
          const unsigned char data[], unsigned int data_len,
          unsigned char mac[], unsigned int mac_len);

#if defined(__cplusplus)
}
#endif

#endif

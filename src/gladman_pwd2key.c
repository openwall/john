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

 This is an implementation of RFC2898, which specifies key derivation from
 a password and a salt value.

 Compile: gcc -DTEST gladman_pwd2key.c gladman_hmac.c -lcrypto */

#include <string.h>
//#include <memory.h>
#include "gladman_hmac.h"

#if defined(__cplusplus)
extern "C"
{
#endif

void derive_key(const unsigned char pwd[],  /* the PASSWORD     */
               unsigned int pwd_len,        /* and its length   */
               const unsigned char salt[],  /* the SALT and its */
               unsigned int salt_len,       /* length           */
               unsigned int iter,   /* the number of iterations */
               unsigned char key[], /* space for the output key */
               unsigned int key_len)/* and its required length  */
{
    unsigned int    i, j, k, n_blk;
    unsigned char uu[OUT_BLOCK_LENGTH], ux[OUT_BLOCK_LENGTH];
    hmac_ctx c1[1], c2[1], c3[1];

    /* set HMAC context (c1) for password               */
    hmac_sha1_begin(c1);
    hmac_sha1_key(pwd, pwd_len, c1);

    /* set HMAC context (c2) for password and salt      */
    memcpy(c2, c1, sizeof(hmac_ctx));
    hmac_sha1_data(salt, salt_len, c2);

    /* find the number of SHA blocks in the key         */
    n_blk = 1 + (key_len - 1) / OUT_BLOCK_LENGTH;

    for(i = 0; i < n_blk; ++i) /* for each block in key */
    {
        /* ux[] holds the running xor value             */
        memset(ux, 0, OUT_BLOCK_LENGTH);

        /* set HMAC context (c3) for password and salt  */
        memcpy(c3, c2, sizeof(hmac_ctx));

        /* enter additional data for 1st block into uu  */
        uu[0] = (unsigned char)((i + 1) >> 24);
        uu[1] = (unsigned char)((i + 1) >> 16);
        uu[2] = (unsigned char)((i + 1) >> 8);
        uu[3] = (unsigned char)(i + 1);

        /* this is the key mixing iteration         */
        for(j = 0, k = 4; j < iter; ++j)
        {
            /* add previous round data to HMAC      */
            hmac_sha1_data(uu, k, c3);

            /* obtain HMAC for uu[]                 */
            hmac_sha1_end(uu, OUT_BLOCK_LENGTH, c3);

            /* xor into the running xor block       */
            for(k = 0; k < OUT_BLOCK_LENGTH; ++k)
                ux[k] ^= uu[k];

            /* set HMAC context (c3) for password   */
            memcpy(c3, c1, sizeof(hmac_ctx));
        }

        /* compile key blocks into the key output   */
        j = 0; k = i * OUT_BLOCK_LENGTH;
        while(j < OUT_BLOCK_LENGTH && k < key_len)
            key[k++] = ux[j++];
    }
}

#ifdef TEST

#include <stdio.h>

struct
{   unsigned int    pwd_len;
    unsigned int    salt_len;
    unsigned int    it_count;
    unsigned char   *pwd;
    unsigned char   salt[32];
    unsigned char   key[32];
} tests[] =
{
    {   8, 4, 5, (unsigned char*)"password",
        {   0x12, 0x34, 0x56, 0x78 },
        {   0x5c, 0x75, 0xce, 0xf0, 0x1a, 0x96, 0x0d, 0xf7,
            0x4c, 0xb6, 0xb4, 0x9b, 0x9e, 0x38, 0xe6, 0xb5 } /* ... */
    },
    {   8, 8, 5, (unsigned char*)"password",
        {   0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12 },
        {   0xd1, 0xda, 0xa7, 0x86, 0x15, 0xf2, 0x87, 0xe6,
            0xa1, 0xc8, 0xb1, 0x20, 0xd7, 0x06, 0x2a, 0x49 } /* ... */
    },
    {   76, 8, 500, (unsigned char*)"All n-entities must communicate with other n-entities via n-1 entiteeheehees",
        {   0x12, 0x34, 0x56, 0x78, 0x78, 0x56, 0x34, 0x12 },
        {   0x6A, 0x89, 0x70, 0xBF, 0x68, 0xC9, 0x2C, 0xAE,
            0xA8, 0x4A, 0x8D, 0xF2, 0x85, 0x10, 0x85, 0x86 } /* ... */
    }

};

int main()
{   unsigned int    i, j, key_len = 256;
    unsigned char   key[256];

    printf("\nTest of RFC2898 Password Based Key Derivation");
    for(i = 0; i < 3; ++i)
    {
        derive_key(tests[i].pwd, tests[i].pwd_len, tests[i].salt,
                    tests[i].salt_len, tests[i].it_count, key, key_len);

        printf("\ntest %i: ", i + 1);
        printf("key %s", memcmp(tests[i].key, key, 16) ? "is bad" : "is good");
        for(j = 0; j < key_len && j < 64; j += 4)
        {
            if(j % 16 == 0)
                printf("\n");
            printf("0x%02x%02x%02x%02x ", key[j], key[j + 1], key[j + 2], key[j + 3]);
        }
        printf(j < key_len ? " ... \n" : "\n");
    }
    printf("\n");
    return 0;
}

#if defined(__cplusplus)
}
#endif

#endif

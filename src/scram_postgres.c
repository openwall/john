/*
 * This file is part of John The Ripper
 * Copyright (c) 2025 Pranjal Prasad <prasadpranjal213@gmail.com>
 *
 * PostgreSQL SCRAM-SHA-256 authentication implementation.
 * Based on SCRAM-SHA-256 as specified in RFC 7677
 *
 * This program is free software: you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation, either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the GNU
 * General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program. If not, see <http://www.gnu.org/licenses/>.
 */

 #if FMT_EXTERNS_H
 extern struct fmt_main fmt_postgresql_scram_sha256;
 #elif FMT_REGISTERS_H
 john_register_one(&fmt_postgresql_scram_sha256);
 #else
 
 #include <string.h>
 
 #ifdef _OPENMP
 #include <omp.h>
 #endif
 
 #include "arch.h"
 #include "misc.h"
 #include "memory.h"
 #include "common.h"
 #include "formats.h"
 #include "johnswap.h"
 #include "sha.h"
 #include "base64_convert.h"
 #include "hmac_sha.h"
 #include "pbkdf2_hmac_sha256.h"
 
 #if defined SIMD_COEF_32
 #define SIMD_KEYS       (SIMD_COEF_32 * SIMD_PARA_SHA256)
 #endif
 
 #define FORMAT_LABEL            "postgresql-scram-sha256"
 #define FORMAT_NAME             ""
 #define ALGORITHM_NAME          "SCRAM-SHA-256 " SHA256_ALGORITHM_NAME
 #define PLAINTEXT_LENGTH        125
 #define HASH_LENGTH             44
 #define SALT_SIZE               sizeof(struct custom_salt)
 #define SALT_ALIGN              sizeof(uint32_t)
 #define BINARY_SIZE             32
 #define BINARY_ALIGN            sizeof(uint32_t)
 #define BENCHMARK_COMMENT       ""
 #define BENCHMARK_LENGTH        0x107
 #define FORMAT_TAG              "$postgresql-scram-sha256$"
 #define FORMAT_TAG_LENGTH       (sizeof(FORMAT_TAG) - 1)
 #define MAX_USERNAME_LENGTH     128
 
 #ifndef OMP_SCALE
 #define OMP_SCALE               1
 #endif
 
 #if !defined(SIMD_COEF_32)
 #define MIN_KEYS_PER_CRYPT      1
 #define MAX_KEYS_PER_CRYPT      64
 #else
 #define MIN_KEYS_PER_CRYPT      SIMD_KEYS
 #define MAX_KEYS_PER_CRYPT      (64 * SIMD_KEYS)
 #endif
 
 static struct fmt_tests tests[] = {
     {"$postgresql-scram-sha256$admin$15000$OxAPvANwV/ZQXqgiW6s6o2+wPM+gfZNthjpUjw==$MenSdE9VmSij4sIKMKfRs+bHy9vkareAopWM8MB+364=", "password1234"},
     {"$postgresql-scram-sha256$user$15000$0sWhCP4Z0gjI7KY6WJ7z/Hs3SEcxC+PUSkv4og==$qnttlssP81IuwtcoZ4TV/M0SMCajePUhPP3mRrnv0aA=", "user@1234"},
     {NULL}
 };
 
 static struct custom_salt {
     int saltlen;
     int iterations;
     char username[MAX_USERNAME_LENGTH + 1];
     unsigned char salt[32];
 } *cur_salt;
 
 static char (*saved_key)[PLAINTEXT_LENGTH + 1];
 static uint32_t (*crypt_out)[BINARY_SIZE / sizeof(uint32_t)];
 
 static void init(struct fmt_main *self)
 {
     omp_autotune(self, OMP_SCALE);
 
     saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
     crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
 }
 
 static void done(void)
 {
     MEM_FREE(crypt_out);
     MEM_FREE(saved_key);
 }
 
 static int valid(char *ciphertext, struct fmt_main *self)
 {
     char *ctcopy, *keeptr, *p;
 
     if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LENGTH) != 0)
         return 0;
 
     ctcopy = xstrdup(ciphertext);
     keeptr = ctcopy;
     ctcopy += FORMAT_TAG_LENGTH;
 
     if (!(p = strtokm(ctcopy, "$")) || strlen(p) >= MAX_USERNAME_LENGTH) goto err;
     if (!(p = strtokm(NULL, "$")) || !isdec(p)) goto err;
     if (!(p = strtokm(NULL, "$")) || strlen(p) > 40) goto err;
     if (!(p = strtokm(NULL, "")) || strlen(p) > HASH_LENGTH) goto err;
 
     MEM_FREE(keeptr);
     return 1;
 
 err:
     MEM_FREE(keeptr);
     return 0;
 }
 
 static void *get_salt(char *ciphertext)
 {
     static struct custom_salt cs;
     char *ctcopy, *keeptr, *p;
 
     memset(&cs, 0, sizeof(cs));
     ctcopy = xstrdup(ciphertext);
     keeptr = ctcopy;
     ctcopy += FORMAT_TAG_LENGTH;
 
     p = strtokm(ctcopy, "$");
     strncpy(cs.username, p, MAX_USERNAME_LENGTH);
     p = strtokm(NULL, "$");
     cs.iterations = atoi(p);
     p = strtokm(NULL, "$");
     base64_convert(p, e_b64_mime, strlen(p), (char*)cs.salt, e_b64_raw, sizeof(cs.salt), flg_Base64_NO_FLAGS, 0);
     cs.salt[28] = cs.salt[29] = cs.salt[30] = 0;
     cs.salt[31] = 1;
 
     MEM_FREE(keeptr);
     return &cs;
 }
 
 static void *get_binary(char *ciphertext)
 {
     static union {
         unsigned char c[BINARY_SIZE];
         ARCH_WORD dummy;
     } buf;
 
     char *p = strrchr(ciphertext, '$') + 1;
     base64_convert(p, e_b64_mime, strlen(p), (char*)buf.c, e_b64_raw, sizeof(buf.c), flg_Base64_DONOT_NULL_TERMINATE, 0);
     return buf.c;
 }
 
 static void set_salt(void *salt)
 {
     cur_salt = (struct custom_salt *)salt;
 }
 
 #define COMMON_GET_HASH_VAR crypt_out
 #include "common-get-hash.h"
 
 static int crypt_all(int *pcount, struct db_salt *salt)
 {
     int count = *pcount;
 
 #ifdef _OPENMP
 #pragma omp parallel for
 #endif
     for (int index = 0; index < count; index += MIN_KEYS_PER_CRYPT) {
 #if !defined(SIMD_COEF_32)
         unsigned char output[BINARY_SIZE];
 
         pbkdf2_sha256((unsigned char *)saved_key[index], strlen(saved_key[index]),
                       cur_salt->salt, 28, cur_salt->iterations, output, BINARY_SIZE, 0);
         hmac_sha256(output, BINARY_SIZE, (unsigned char*)"Server Key", 10,
                     (unsigned char*)crypt_out[index], BINARY_SIZE);
 #else
         int lens[MIN_KEYS_PER_CRYPT];
         unsigned char *pin[MIN_KEYS_PER_CRYPT];
         union {
             uint32_t *pout[MIN_KEYS_PER_CRYPT];
             unsigned char *poutc;
         } x;
 
         for (int i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
             lens[i] = strlen(saved_key[index+i]);
             pin[i] = (unsigned char*)saved_key[index+i];
             x.pout[i] = crypt_out[i + index];
         }
 
         pbkdf2_sha256_sse((const unsigned char**)pin, lens, cur_salt->salt, 28,
                           cur_salt->iterations, &x.poutc, 32, 0);
 
         for (int i = 0; i < MIN_KEYS_PER_CRYPT; ++i) {
             hmac_sha256((unsigned char*)&crypt_out[i + index], BINARY_SIZE,
                         (unsigned char*)"Server Key", 10,
                         (unsigned char *)&crypt_out[index + i], BINARY_SIZE);
         }
 #endif
     }
 
     return count;
 }
 
 static int cmp_all(void *binary, int count)
 {
     for (int i = 0; i < count; i++)
         if (!memcmp(binary, crypt_out[i], ARCH_SIZE))
             return 1;
     return 0;
 }
 
 static int cmp_one(void *binary, int index)
 {
     return !memcmp(binary, crypt_out[index], BINARY_SIZE);
 }
 
 static int cmp_exact(char *source, int index)
 {
     return 1;
 }
 
 static void set_key(char *key, int index)
 {
     strnzcpy(saved_key[index], key, sizeof(*saved_key));
 }
 
 static char *get_key(int index)
 {
     return saved_key[index];
 }
 
 struct fmt_main fmt_postgresql_scram_sha256 = {
     {
         FORMAT_LABEL,
         FORMAT_NAME,
         ALGORITHM_NAME,
         BENCHMARK_COMMENT,
         BENCHMARK_LENGTH,
         0,
         PLAINTEXT_LENGTH,
         BINARY_SIZE,
         BINARY_ALIGN,
         SALT_SIZE,
         SALT_ALIGN,
         MIN_KEYS_PER_CRYPT,
         MAX_KEYS_PER_CRYPT,
         FMT_CASE | FMT_8_BIT | FMT_OMP,
         { NULL },
         { FORMAT_TAG },
         tests
     }, {
         init,
         done,
         fmt_default_reset,
         fmt_default_prepare,
         valid,
         fmt_default_split,
         get_binary,
         get_salt,
         { NULL },
         fmt_default_source,
         {
             fmt_default_binary_hash_0,
             fmt_default_binary_hash_1,
             fmt_default_binary_hash_2,
             fmt_default_binary_hash_3,
             fmt_default_binary_hash_4,
             fmt_default_binary_hash_5,
             fmt_default_binary_hash_6
         },
         fmt_default_salt_hash,
         NULL,
         set_salt,
         set_key,
         get_key,
         fmt_default_clear_keys,
         crypt_all,
         {
             cmp_all,
             cmp_one,
             cmp_exact
         }
     }
 };
 
 #endif
 
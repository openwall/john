/*
 * This patch Copyright (C) 2010 by James Nobis - quel
 * - quel NOSPAM quelrod NOSPAM net, and it is herby released to the general
 * public under the follow terms:
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 * format specification
 * http://www.hmailserver.com/forum/viewtopic.php?p=97515&sid=b2c1c6ba1e10c2f0654ca9421b2059e8#p97515
 * inspiration from the generic sha-1 and md5
 * Copyright (c) 2010 by Solar Designer
 */

#include <openssl/opensslv.h>
#if OPENSSL_VERSION_NUMBER >= 0x00908000

#include <string.h>
#if defined(__APPLE__) && defined(__MACH__)
#ifdef __MAC_OS_X_VERSION_MIN_REQUIRED
#if __MAC_OS_X_VERSION_MIN_REQUIRED >= 1070
#define COMMON_DIGEST_FOR_OPENSSL
#include <CommonCrypto/CommonDigest.h>
#else
#include <openssl/sha.h>
#endif
#else
#include <openssl/sha.h>
#endif
#else
#include <openssl/sha.h>
#endif

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL        "hmailserver"
#define FORMAT_NAME         "hMailServer salted SHA-256"

#define ALGORITHM_NAME      "32/" ARCH_BITS_STR

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0

#define PLAINTEXT_LENGTH    70
#define CIPHERTEXT_LENGTH   64

#define BINARY_SIZE         32
#define SALT_SIZE           6

#define MIN_KEYS_PER_CRYPT  1
#define MAX_KEYS_PER_CRYPT  1

static struct fmt_tests hmailserver_tests[] = {
    {"cc06fa688a64cdeea43d3c0fb761fede7e3ccf00a9daea9c79f7d458e06f88327f16dd", "password"},
    {"fee4fd4446aebcb3332aa5c61845b7bcbe5a3126fedf51a6359663d61b87d4f6ee87df", "12345678"},
    {"2d7b784370c488b6548394ba11513e159220c83e2458ed01d8c7cdadd6bf486b433703", "1234"},
    {"0926aadc8d49682c3f091af2dbf7f16f1cc7130b8e6dc86978d3f1bef914ce0096d4b3", "0123456789ABCDE"},
    {NULL}
};

static char saved_salt[SALT_SIZE];
static int saved_key_length;
static char saved_key[PLAINTEXT_LENGTH + 1];
static SHA256_CTX ctx;
static ARCH_WORD_32 crypt_out[8] = {0}; // 8 * 32 = 256

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
    int i;

    if ( ciphertext == NULL )
        return 0;

    if ( strlen( ciphertext ) != PLAINTEXT_LENGTH )
        return 0;

    for ( i = 0; i < PLAINTEXT_LENGTH - 1; i++ )
        if (!( (('0' <= ciphertext[i] ) && ( ciphertext[i] <= '9' ))
                || (('a' <= ciphertext[i] ) && ( ciphertext[i] <= 'f' )) ))
            return 0;

    return 1;
}

static void *get_binary(char *ciphertext)
{
    static unsigned char *out;
    char *p;
    int i;

    if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

    p = ciphertext + SALT_SIZE;
    for (i = 0; i < BINARY_SIZE; i++) {
        out[i] =
            (atoi16[ARCH_INDEX(*p)] << 4) |
            atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }

    return out;
}

static void *salt(char *ciphertext)
{
    static unsigned *out;
    if (!out) out = mem_alloc_tiny(SALT_SIZE, MEM_ALIGN_WORD);

    memcpy(out, ciphertext, SALT_SIZE);

    return out;
}

static int binary_hash_0(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xF;
}

static int binary_hash_1(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFF;
}

static int binary_hash_2(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFF;
}

static int binary_hash_3(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFFFF;
}

static int binary_hash_5(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0xFFFFFF;
}

static int binary_hash_6(void *binary)
{
    return *(ARCH_WORD_32 *)binary & 0x7FFFFFF;
}

static int get_hash_0(int index)
{
    return crypt_out[0] & 0xF;
}

static int get_hash_1(int index)
{
    return crypt_out[0] & 0xFF;
}

static int get_hash_2(int index)
{
    return crypt_out[0] & 0xFFF;
}

static int get_hash_3(int index)
{
    return crypt_out[0] & 0xFFFF;
}

static int get_hash_4(int index)
{
    return crypt_out[0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
    return crypt_out[0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
    return crypt_out[0] & 0x7FFFFFF;
}

static int salt_hash(void *salt)
{
	return (((ARCH_WORD_32)(ARCH_INDEX(((unsigned char *)salt)[0])-' ')) +
	    ((ARCH_WORD_32)(ARCH_INDEX(((unsigned char *)salt)[1])-' ')<<4) +
	    ((ARCH_WORD_32)(ARCH_INDEX(((unsigned char *)salt)[2])-' ')<<8))
	    & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
    memcpy(saved_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
    saved_key_length = strlen(key);
    if (saved_key_length > PLAINTEXT_LENGTH)
        saved_key_length = PLAINTEXT_LENGTH;
    memcpy(saved_key, key, saved_key_length);
}

static char *get_key(int index)
{
    saved_key[saved_key_length] = 0;
    return saved_key;
}

static void crypt_all(int count)
{
    SHA256_Init(&ctx);
    SHA256_Update(&ctx, saved_salt, SALT_SIZE);
    SHA256_Update(&ctx, saved_key, saved_key_length);
    SHA256_Final((unsigned char *)crypt_out, &ctx);
}

static int cmp_all(void *binary, int count)
{
    return !memcmp(binary, crypt_out, BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

struct fmt_main fmt_hmailserver = {
    {
        FORMAT_LABEL,
        FORMAT_NAME,
        ALGORITHM_NAME,
        BENCHMARK_COMMENT,
        BENCHMARK_LENGTH,
        PLAINTEXT_LENGTH,
        BINARY_SIZE,
        SALT_SIZE,
        MIN_KEYS_PER_CRYPT,
        MAX_KEYS_PER_CRYPT,
        FMT_CASE | FMT_8_BIT,
        hmailserver_tests
    }, {
        fmt_default_init,
	fmt_default_prepare,
        valid,
        fmt_default_split,
        get_binary,
        salt,
        {
            binary_hash_0,
            binary_hash_1,
            binary_hash_2,
            binary_hash_3,
            binary_hash_4,
            binary_hash_5,
            binary_hash_6
        },
        salt_hash,
        set_salt,
        set_key,
        get_key,
        fmt_default_clear_keys,
        crypt_all,
        {
            get_hash_0,
            get_hash_1,
            get_hash_2,
            get_hash_3,
            get_hash_4,
            get_hash_5,
            get_hash_6
        },
        cmp_all,
        cmp_all,
        cmp_exact
    }
};

#else
#ifdef __GNUC__
#warning Note: hmailserver format disabled - it needs OpenSSL 0.9.8 or above
#endif
#endif

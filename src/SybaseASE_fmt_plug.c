/*
 * Unicode conversion enhancements by magnum, 2011. Licensed as below.
 *
 * Sybase ASE hash support for version 15.0.2 and above, based on hmailserver
 * patch by James Nobis.
 * Hash format description : http://marcellmajor.com/sybase_sha256.html
 * Hacked together by Dhiru Kholia in February, 2011.
 *
 * This patch Copyright (C) 2010 by James Nobis - quel
 * quel NOSPAM quelrod NOSPAM net, and it is herby released to the general
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

 * Inspiration from the generic sha-1 and md5 (Copyright (c) 2010 by Solar Designer)
 */

#include "sha2.h"

#include "arch.h"
#include "params.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"

#define FORMAT_LABEL        "sybasease"
#define FORMAT_NAME         "Sybase ASE salted SHA-256"

#define ALGORITHM_NAME      "32/" ARCH_BITS_STR " " SHA2_LIB

#define BENCHMARK_COMMENT   ""
#define BENCHMARK_LENGTH    0

#define PLAINTEXT_LENGTH    64
#define CIPHERTEXT_LENGTH   (6 + 16 + 64)
#define PREFIX_LENGTH       6

#define BINARY_SIZE         32
#define SALT_SIZE           8

#define MIN_KEYS_PER_CRYPT  96
#define MAX_KEYS_PER_CRYPT  96

static struct fmt_tests SybaseASE_tests[] = {
    {"0xc0074f9cc8c0d55d9803b0c0816e127f2a56ee080230af5b4ce3da1f3d9fcc5449fcfcf3fb9595eb8ea6", "test12"},
    {"0xc0074BE393C06BE420AD541671aa5e6f1a19a4a73bb51c59f45790f0887cfb70e0599747c6844d4556b3", "a"},
    {NULL}
};

static char *saved_salt;
static UTF16 prep_key[MAX_KEYS_PER_CRYPT][518 / sizeof(UTF16)];
static ARCH_WORD_32 crypt_out[MAX_KEYS_PER_CRYPT][8];

extern struct fmt_main fmt_SybaseASE;
static void init(struct fmt_main *pFmt)
{
    if (options.utf8)
        fmt_SybaseASE.params.plaintext_length = 125;
}

// TODO: strengthen checks
static int valid(char *ciphertext, struct fmt_main *pFmt)
{
    if(strncmp(ciphertext, "0xc007", 6)!=0)
        return 0;
    if(strlen(ciphertext) != CIPHERTEXT_LENGTH)
        return 0;

    return 1;
}

static void *get_binary(char *ciphertext)
{
    static unsigned char *out;
    int i;
    char *p = ciphertext + PREFIX_LENGTH + SALT_SIZE * 2;

    if (!out) out = mem_alloc_tiny(BINARY_SIZE, MEM_ALIGN_WORD);

    for (i = 0; i < BINARY_SIZE; i++) {
        out[i] = (atoi16[ARCH_INDEX(*p)] << 4) | atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }
    return out;
}

static void *salt(char *ciphertext)
{
    static unsigned char out[SALT_SIZE];
    int i;
    char *p = ciphertext + PREFIX_LENGTH;
    for (i = 0; i < sizeof(out); i++) {
        out[i] = (atoi16[ARCH_INDEX(*p)] << 4) |atoi16[ARCH_INDEX(p[1])];
        p += 2;
    }
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
    return crypt_out[index][0] & 0xF;
}

static int get_hash_1(int index)
{
    return crypt_out[index][0] & 0xFF;
}

static int get_hash_2(int index)
{
    return crypt_out[index][0] & 0xFFF;
}

static int get_hash_3(int index)
{
    return crypt_out[index][0] & 0xFFFF;
}

static int get_hash_4(int index)
{
    return crypt_out[index][0] & 0xFFFFF;
}

static int get_hash_5(int index)
{
    return crypt_out[index][0] & 0xFFFFFF;
}

static int get_hash_6(int index)
{
    return crypt_out[index][0] & 0x7FFFFFF;
}

static void set_salt(void *salt)
{
    saved_salt = salt;
}

static void set_key(char *key, int index)
{
    /* Clean slate */
    memset(prep_key[index], 0, 2 * PLAINTEXT_LENGTH);

    /* convert key to UTF-16BE, --encoding aware */
    enc_to_utf16_be(prep_key[index], PLAINTEXT_LENGTH, (UTF8*)key,
                    strlen(key));
}

static char *get_key(int index)
{
#if ARCH_LITTLE_ENDIAN
    UTF16 key_le[PLAINTEXT_LENGTH + 1];
    UTF16 *s = prep_key[index];
    UTF16 *d = key_le;

    // Byte-swap back to UTF-16LE
    while ((*d++ = *s >> 8 | *s << 8))
        s++;

    return (char*)utf16_to_enc(key_le);
#else
    return (char*)utf16_to_enc(prep_key[index]);
#endif
}

static void crypt_all(int count)
{
    int index;

#ifdef _OPENMP
#pragma omp parallel for default(none) private(index) shared(count, crypt_out, prep_key, saved_salt)
#endif
    for(index = 0; index < count; index++) {
        SHA256_CTX ctx;

        /* append salt at offset 510 */
        memcpy((unsigned char *)prep_key[index] + 510, saved_salt, 8);

        SHA256_Init(&ctx);
        SHA256_Update(&ctx, prep_key[index], 518);
        SHA256_Final((unsigned char *)crypt_out[index], &ctx);
    }
}

static int cmp_all(void *binary, int count)
{
    int index;
    for (index = 0; index < count; index++)
        if (*(ARCH_WORD_32 *)binary == *(ARCH_WORD_32 *)crypt_out[index])
            return 1;
    return 0;
}

static int cmp_one(void *binary, int index)
{
    return !memcmp((char *)binary, (const char*)crypt_out[index], BINARY_SIZE);
}

static int cmp_exact(char *source, int index)
{
    return 1;
}

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_SybaseASE = {
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
        FMT_CASE | FMT_8_BIT | FMT_OMP | FMT_UNICODE | FMT_UTF8,
        SybaseASE_tests
    }, {
        init,
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
        cmp_one,
        cmp_exact
    }
};

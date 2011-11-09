// vim: set ts=8 sw=4 et :
/*
 * Copyright (c) 2007 Marti Raudsepp <marti AT juffo org>
 *
 * Simple MySQL 4.1+ PASSWORD() hash cracker, rev 1.
 * Adapted from the original rawSHA1_fmt.c cracker.
 *
 * Note that many version 4.1 and 5.0 installations still use the old
 * homebrewn pre-4.1 hash for compatibility with older clients, notably all
 * Red Hat-based distributions.
 *
 * The new PASSWORD() function is unsalted and equivalent to
 * SHA1(SHA1(password)) where the inner is a binary digest (not hex!) This
 * means that with the SSE2-boosted SHA-1 implementation, it will be several
 * times faster than John's cracker for the old hash format. (though the old
 * hash had significant weaknesses, John's code does not take advantage of
 * that)
 *
 * It's a slight improvement over the old hash, but still not something a
 * reasonable DBMS would use for password storage.
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"

//#define X_DEBUG
#ifdef X_DEBUG
# include <assert.h>
#endif

#define FORMAT_LABEL			"mysql-sha1"
#define FORMAT_NAME			"MySQL 4.1 double-SHA-1"
#ifdef MMX_COEF
# if (MMX_COEF == 2)
#  define ALGORITHM_NAME		"mysql-sha1 MMX"
# else
#  define ALGORITHM_NAME		"mysql-sha1 SSE2"
# endif
#else
# define ALGORITHM_NAME			"mysql-sha1"
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		41

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
# define MIN_KEYS_PER_CRYPT		MMX_COEF
# define MAX_KEYS_PER_CRYPT		MMX_COEF
//#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) ) //std getpos
# define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
# define BYTESWAP(n) ( \
        (((n)&0x000000ff) << 24) | \
        (((n)&0x0000ff00) << 8 ) | \
        (((n)&0x00ff0000) >> 8 ) | \
        (((n)&0xff000000) >> 24) )
#else
# define MIN_KEYS_PER_CRYPT		1
# define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests mysqlsha1_tests[] = {
    {"*5AD8F88516BD021DD43F171E2C785C69F8E54ADB", "tere"},
    {"*2C905879F74F28F8570989947D06A8429FB943E6", "verysecretpassword"},
    {"*A8A397146B1A5F8C8CF26404668EFD762A1B7B82", "________________________________"},
    {"*F9F1470004E888963FB466A5452C9CBD9DF6239C", "12345678123456781234567812345678"},
    {"*97CF7A3ACBE0CA58D5391AC8377B5D9AC11D46D9", "' OR 1 /*'"},
    {"*2470C0C06DEE42FD1618BB99005ADCA2EC9D1E19", "password"},
    {"*7534F9EAEE5B69A586D1E9C1ACE3E3F9F6FCC446", "5"},
    {NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key mysqlSHA1_saved_key
#define crypt_key mysqlSHA1_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) char saved_key[80*4*MMX_COEF];
__declspec(align(16)) char crypt_key[BINARY_SIZE*MMX_COEF];
#define interm_key mysqlSHA1_interm_key
__declspec(align(16)) char interm_key[80*4*MMX_COEF];
#else
char saved_key[80*4*MMX_COEF] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
/* Intermediate key which stores the hashes between two SHA-1 operations. Don't
 * ask me why it has to be so long ;) */
#define interm_key mysqlSHA1_interm_key
char interm_key[80*4*MMX_COEF] __attribute__ ((aligned(16)));
#endif

static unsigned long total_len;

# if MMX_COEF > 2
/* argument to shammx(); all intermediary plaintexts are 20 bytes long */
#  define TMPKEY_LENGTHS 0x14141414
# else
#  define TMPKEY_LENGTHS 0x00140014
# endif

#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
    int i;

    if (strlen(ciphertext) != CIPHERTEXT_LENGTH) return 0;
    if (ciphertext[0] != '*')
        return 0;
    for (i = 1; i < CIPHERTEXT_LENGTH; i++){
        if (!( (('0' <= ciphertext[i])&&(ciphertext[i] <= '9'))
           || (('a' <= ciphertext[i])&&(ciphertext[i] <= 'f'))
           || (('A' <= ciphertext[i])&&(ciphertext[i] <= 'F'))))
        {
            return 0;
        }
    }
    return 1;
}

static void mysqlsha1_init(struct fmt_main *pFmt)
{
#ifdef MMX_COEF
	const int offset = (MMX_COEF*BINARY_SIZE)/4;

    memset(saved_key, 0, sizeof saved_key);
    memset(interm_key, 0, sizeof interm_key);
    /* input strings have to be terminated by 0x80. The input strings in
     * interm_key have a static length (20 bytes) so we can set them just once.
     */
    ((unsigned*)interm_key)[offset+0] = BYTESWAP(0x80);
    ((unsigned*)interm_key)[offset+1] = BYTESWAP(0x80);
# if MMX_COEF > 2
    ((unsigned*)interm_key)[offset+2] = BYTESWAP(0x80);
    ((unsigned*)interm_key)[offset+3] = BYTESWAP(0x80);
# endif
#endif
}

static void mysqlsha1_set_key(char *key, int index) {
#ifdef MMX_COEF
    int len;
    int i;
    /* FIXME: we're wasting 22% time in set_key with SSE2 (rawSHA1 is wasting
     * nearly 50%!). The huge memset() is probably a culprit, but also the
     * bytewise byte-order swapping code (see GETPOS macro above). */

    if(index==0)
    {
        total_len = 0;
        //memset(saved_key, 0, sizeof(saved_key));
		memset(saved_key, 0, 56*MMX_COEF);
    }
    len = strlen(key);
    if(len>PLAINTEXT_LENGTH)
        len = PLAINTEXT_LENGTH;

    total_len += len << ( ( (32/MMX_COEF) * index ) );
    for(i=0;i<len;i++)
        saved_key[GETPOS(i, index)] = key[i];

    saved_key[GETPOS(i, index)] = 0x80;
#else
    strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static char *mysqlsha1_get_key(int index) {
#ifdef MMX_COEF
    static char out[PLAINTEXT_LENGTH+1];
    unsigned int i,s;

    s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
    for(i=0;i<s;i++)
        out[i] = saved_key[ GETPOS(i, index) ];
    out[i] = 0;
    return out;
#else
    return saved_key;
#endif
}

static int mysqlsha1_cmp_all(void *binary, int index) {
#ifdef MMX_COEF
    int i=0;
    while(i< (BINARY_SIZE/4) )
    {
        if (
                ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF])
                && ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
                && ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+2])
                && ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+3])
#endif
           )
            return 0;
        i++;
    }
    return 1;
#else
    return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int mysqlsha1_cmp_exact(char *source, int count){
  return (1);
}

static int mysqlsha1_cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
    int i = 0;
    for(i=0;i<(BINARY_SIZE/4);i++)
        if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
            return 0;
    return 1;
#else
    return mysqlsha1_cmp_all(binary, index);
#endif
}

static void mysqlsha1_crypt_all(int count) {
#ifdef MMX_COEF
    unsigned int i;

//    shammx((unsigned char *) crypt_key, (unsigned char *) saved_key, total_len);

//    for(i = 0; i < MMX_COEF*BINARY_SIZE/sizeof(unsigned); i++)
//    {
//        ((unsigned*)interm_key)[i] = BYTESWAP(((unsigned*)crypt_key)[i]);
//    }

    shammx_nofinalbyteswap((unsigned char *) crypt_key, (unsigned char *) saved_key, total_len);
    for(i = 0; i < MMX_COEF*BINARY_SIZE/sizeof(unsigned); i++)
    {
        ((unsigned*)interm_key)[i] = ((unsigned*)crypt_key)[i];
    }


    /* Verify that the 0x80 padding hasn't been overwritten. */
# ifdef X_DEBUG
    assert(((unsigned*)interm_key)[i+0] == BYTESWAP(0x80));
    assert(((unsigned*)interm_key)[i+1] == BYTESWAP(0x80));
#  if MMX_COEF > 2
    assert(((unsigned*)interm_key)[i+2] == BYTESWAP(0x80));
    assert(((unsigned*)interm_key)[i+3] == BYTESWAP(0x80));
#  endif
# endif /* X_DEBUG */

    shammx((unsigned char *) crypt_key, (unsigned char *) interm_key, TMPKEY_LENGTHS);

#else
    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char *) saved_key, strlen(saved_key));
    SHA1_Final((unsigned char *) crypt_key, &ctx);

    SHA1_Init(&ctx);
    SHA1_Update(&ctx, (unsigned char *) crypt_key, BINARY_SIZE);
    SHA1_Final((unsigned char *) crypt_key, &ctx);
#endif
}

static void *mysqlsha1_binary(char *ciphertext)
{
    static char realcipher[BINARY_SIZE];
    int i;

    // ignore first character '*'
    ciphertext += 1;
    for(i=0;i<BINARY_SIZE;i++)
    {
        realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
    }
    return (void *)realcipher;
}

static int binary_hash_0(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xF;
}

static int binary_hash_1(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFF;
}

static int binary_hash_2(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFF;
}

static int binary_hash_3(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFF;
}

static int binary_hash_4(void *binary)
{
	return ((ARCH_WORD_32 *)binary)[0] & 0xFFFFF;
}

static int get_hash_0(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xF;
}

static int get_hash_1(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFF;
}

static int get_hash_2(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFF;
}

static int get_hash_3(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFF;
}

static int get_hash_4(int index)
{
	return ((ARCH_WORD_32 *)crypt_key)[index] & 0xFFFFF;
}

struct fmt_main fmt_mysqlSHA1 = {
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
        mysqlsha1_tests
    }, {
        mysqlsha1_init,
		fmt_default_prepare,
        valid,
        fmt_default_split,
        mysqlsha1_binary,
        fmt_default_salt,
        {
            binary_hash_0,
            binary_hash_1,
            binary_hash_2,
            binary_hash_3,
            binary_hash_4
        },
        fmt_default_salt_hash,
        fmt_default_set_salt,
        mysqlsha1_set_key,
        mysqlsha1_get_key,
        fmt_default_clear_keys,
        mysqlsha1_crypt_all,
        {
            get_hash_0,
            get_hash_1,
            get_hash_2,
            get_hash_3,
            get_hash_4
        },
        mysqlsha1_cmp_all,
        mysqlsha1_cmp_one,
        mysqlsha1_cmp_exact
    }
};

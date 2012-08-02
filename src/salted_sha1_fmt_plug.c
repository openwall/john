/*
 * generic salted-sha1 support for LDAP style password storage
 *
 * Copyright (c) 2003 Simon Marechal, salt length fixes (c) 2012 magnum
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted.
 */

#define MAX_SALT_LEN	16	// bytes, the base64 representation is longer

#include <string.h>

#include "misc.h"
#include "formats.h"
#include "arch.h"
#include "options.h"
#include "johnswap.h"
#ifdef HAVE_MPI
#include "john-mpi.h"
#endif

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "common.h"

#include "sha.h"
#include "base64.h"

#define FORMAT_LABEL			"salted-sha1"
#define FORMAT_NAME			"Salted SHA-1"

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		(55-MAX_SALT_LEN)

#define BINARY_SIZE			20 // this is 28 chars of base64
#define SALT_SIZE			(MAX_SALT_LEN + sizeof(unsigned int))

#define CIPHERTEXT_LENGTH		((BINARY_SIZE + MAX_SALT_LEN + 2) / 3 * 4)

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6

struct s_salt
{
	unsigned int len;
	union {
		unsigned char c[MAX_SALT_LEN];
		ARCH_WORD_32 w32;
	} data;
};

static struct s_salt *saved_salt;

static struct fmt_tests tests[] = {
// Test hashes originally(?) in OPENLDAPS_fmt (openssha) (salt length 4)
	{"{SSHA}bPXG4M1KkwZh2Hbgnuoszvpat0T/OS86", "thales"},
	{"{SSHA}hHSEPW3qeiOo5Pl2MpHQCXh0vgfyVR/X", "test1"},
	{"{SSHA}pXp4yIiRmppvKYn7cKCT+lngG4qELq4h", "test2"},
	{"{SSHA}Bv8tu3wB8WTMJj3tcOsl1usm5HzGwEmv", "test3"},
	{"{SSHA}kXyh8wLCKbN+QRbL2F2aUbkP62BJ/bRg", "lapin"},
	{"{SSHA}rnMVxsf1YJPg0L5CBhbVLIsJF+o/vkoE", "canard"},
	{"{SSHA}Uf2x9YxSWZZNAi2t1QXbG2PmT07AtURl", "chien"},
	{"{SSHA}XXGLZ7iKpYSBpF6EwoeTl27U0L/kYYsY", "hibou"},
	{"{SSHA}HYRPmcQIIzIIg/c1L8cZKlYdNpyeZeml", "genou"},
	{"{SSHA}Zm/0Wll7rLNpBU4HFUKhbASpXr94eSTc", "caillou"},
	{"{SSHA}Qc9OB+aEFA/mJ5MNy0AB4hRIkNiAbqDb", "doudou"},

// Test vectors originally in NSLDAPS_fmt (ssha) (salt length 8)
	{"{SSHA}WTT3B9Jjr8gOt0Q7WMs9/XvukyhTQj0Ns0jMKQ==", "Password9"},
	{"{SSHA}ypkVeJKLzbXakEpuPYbn+YBnQvFmNmB+kQhmWQ==", "qVv3uQ45"},
	{"{SSHA}cKFVqtf358j0FGpPsEIK1xh3T0mtDNV1kAaBNg==", "salles"},
	{"{SSHA}W3ipFGmzS3+j6/FhT7ZC39MIfqFcct9Ep0KEGA==", "asddsa123"},
	{"{SSHA}YbB2R1D2AlzYc9wk/YPtslG7NoiOWaoMOztLHA==", "ripthispassword"},

/*
 * These two were found in john-1.6-nsldaps4.diff.gz
 */
	{"{SSHA}/EExmSfmhQSPHDJaTxwQSdb/uPpzYWx0ZXI=", "secret"},
	{"{SSHA}gVK8WC9YyFT1gMsQHTGCgT3sSv5zYWx0", "secret"},

	{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define saved_key SALT_SHA_saved_key
#define crypt_key SALT_SHA_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS];
__declspec(align(16)) unsigned char crypt_key[BINARY_SIZE*NBKEYS];
#else
unsigned char saved_key[SHA_BUF_SIZ*4*NBKEYS] __attribute__ ((aligned(16)));
unsigned char crypt_key[BINARY_SIZE*NBKEYS] __attribute__ ((aligned(16)));
#endif
static unsigned int saved_len[NBKEYS];
static unsigned char out[PLAINTEXT_LENGTH + 1];
static int last_salt_size;
#else
static char saved_key[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static SHA_CTX ctx;
#endif

static void * binary(char *ciphertext) {
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + SALT_SIZE, MEM_ALIGN_WORD);

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, BINARY_SIZE);
	base64_decode(ciphertext, strlen(ciphertext), realcipher);
#ifdef MMX_COEF
	alter_endianity((unsigned char *)realcipher, BINARY_SIZE);
#endif
	return (void *)realcipher;
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int len;

	len = strlen(ciphertext);

	if (len < NSLDAP_MAGIC_LENGTH + (BINARY_SIZE+1+2)/3*4)
		return 0;

	len -= NSLDAP_MAGIC_LENGTH;
	if (len & 3 || len > CIPHERTEXT_LENGTH)
		return 0;

	return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)key;
	ARCH_WORD_32 *keybuf_word = (ARCH_WORD_32*)&saved_key[GETPOS(3, index)];
	unsigned int len;
	ARCH_WORD_32 temp;

	len = 0;
	while((temp = *wkey++) & 0xff) {
		if (!(temp & 0xff00))
		{
			*keybuf_word = JOHNSWAP((temp & 0xff) | (0x80 << 8));
			len++;
			goto key_cleaning;
		}
		if (!(temp & 0xff0000))
		{
			*keybuf_word = JOHNSWAP((temp & 0xffff) | (0x80 << 16));
			len+=2;
			goto key_cleaning;
		}
		if (!(temp & 0xff000000))
		{
			*keybuf_word = JOHNSWAP(temp | (0x80 << 24));
			len+=3;
			goto key_cleaning;
		}
		*keybuf_word = JOHNSWAP(temp);
		len += 4;
		keybuf_word += MMX_COEF;
	}
	*keybuf_word = 0x80000000;

key_cleaning:
	keybuf_word += MMX_COEF;
	while(*keybuf_word) {
		*keybuf_word = 0;
		keybuf_word += MMX_COEF;
	}

	saved_len[index] = len;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH + 1);
#endif
}

static void * get_salt(char * ciphertext)
{
	static struct s_salt cursalt;
	char *p;
	char realcipher[CIPHERTEXT_LENGTH];
	int len;

	ciphertext += NSLDAP_MAGIC_LENGTH;
	memset(realcipher, 0, sizeof(realcipher));
	memset(&cursalt, 0, sizeof(struct s_salt));
	len = strlen(ciphertext);
	base64_decode(ciphertext, len, realcipher);

	// We now support any salt length up to SALT_SIZE
	cursalt.len = (len + 3) / 4 * 3 - BINARY_SIZE;
	p = &ciphertext[len];
	while (*--p == '=')
		cursalt.len--;

	memcpy(cursalt.data.c, realcipher+BINARY_SIZE, cursalt.len);
	return &cursalt;
}

static char *get_key(int index) {
#ifdef MMX_COEF
	unsigned int i,s;

//	s = ((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] >> 3;
	s = saved_len[index];
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
	return saved_key;
#endif
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
	for(;y<SHA1_SSE_PARA;y++)
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((ARCH_WORD_32*)binary)[0] ==
		    ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	return !memcmp(binary, crypt_key, BINARY_SIZE);
#endif
}

static int cmp_exact(char *source, int count){
	return (1);
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&3;
	y = index/4;

	if( ((ARCH_WORD_32*)binary)[0] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[1] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*1] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[2] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*2] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[3] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*3] )
		return 0;
	if( ((ARCH_WORD_32*)binary)[4] != ((ARCH_WORD_32*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF*4] )
		return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}

static void set_salt(void *salt) {
	saved_salt = salt;
}

#ifdef MMX_COEF
static inline void set_onesalt(int index)
{
	unsigned int i;

	for(i=0;i<saved_salt->len;i++)
		saved_key[GETPOS(i + saved_len[index], index)] = saved_salt->data.c[i];
	saved_key[GETPOS(i + saved_len[index], index)] = 0x80;

	while (++i <= last_salt_size)
		saved_key[GETPOS(i + saved_len[index], index)] = 0;

	((unsigned int *)saved_key)[15*MMX_COEF + (index&3) + (index>>2)*SHA_BUF_SIZ*MMX_COEF] = (saved_salt->len + saved_len[index])<<3;
}
#endif

static void crypt_all(int count) {
#ifdef MMX_COEF
	unsigned int i;

	for(i=0;i<NBKEYS;i++)
		set_onesalt(i);
	last_salt_size = saved_salt->len;

# if SHA1_SSE_PARA
	SSESHA1body(saved_key, (unsigned int *)crypt_key, NULL, 0);
# else
	shammx_nosizeupdate_nofinalbyteswap((unsigned char *) crypt_key, (unsigned char *) saved_key, 1);

# endif

#else
	SHA1_Init( &ctx );
	SHA1_Update( &ctx, (unsigned char *) saved_key, strlen( saved_key ) );
	SHA1_Update( &ctx, (unsigned char *) saved_salt->data.c, saved_salt->len);
	SHA1_Final( (unsigned char *) crypt_key, &ctx);
//	dump_stuff((unsigned char *)crypt_key, 20);
//	exit(1);
#endif

}

static int binary_hash_0(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff; }

#ifdef MMX_COEF
#define HASH_IDX ((index&3)+(index/4)*MMX_COEF*5)
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[HASH_IDX] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[0] & 0x7ffffff; }
#endif

static int salt_hash(void *salt)
{
	struct s_salt * mysalt = salt;
	return mysalt->data.w32 & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_saltedsha = {
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
		tests
	}, {
		fmt_default_init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		get_salt,
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

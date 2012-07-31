// Fix for john the ripper 1.6.37 by Sun-Zero, 2004. 07. 26.
/*
 * Minor performance enhancement by bartavelle at bandecon.com
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "params.h"
#include "formats.h"
#include "common.h"

#include "sha.h"
#include "base64.h"

// This format has some MMX/SSE sha things in there but it's not completed.
// We should re-work it to use sse-intrinsics
#undef MMX_COEF
#undef MMX_TYPE

#define FORMAT_LABEL			"openssha"
#define FORMAT_NAME			"OpenLDAP SSHA"

#if defined(MMX_COEF) && MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif defined(MMX_COEF) && MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		32

#define BINARY_SIZE			20
#define SALT_SIZE			4

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{ssha}"
#define NSLDAP_MAGIC_LENGTH 6

static struct fmt_tests tests[] = {
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
	{NULL}
};

#ifdef MMX_COEF
static char crypt_key[BINARY_SIZE*MMX_COEF];
/* Cygwin would not guarantee the alignment for this static declaration, but
 * this source file is not MMX-ready anyway (MMX_COEF is #undef'ed above). */
static char saved_key[80*MMX_COEF*4] __attribute__ ((aligned(8*MMX_COEF)));
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static char saved_key[PLAINTEXT_LENGTH + 1];
#endif

#ifdef MMX_COEF
static unsigned long length[MAX_KEYS_PER_CRYPT];
#endif

static char saved_salt[SALT_SIZE];

static void * binary(char *ciphertext) {
  static char *realcipher;

  if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + SALT_SIZE + 9, MEM_ALIGN_WORD);

  /* stupid overflows */
  memset(realcipher, 0, BINARY_SIZE + SALT_SIZE + 9);
  base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
#ifdef MMX_COEF
  alter_endianity((unsigned char*)realcipher, BINARY_SIZE);
#endif
  return (void *)realcipher;
}

static void * get_salt(char * ciphertext)
{
	static char *realcipher;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE + SALT_SIZE + 9, MEM_ALIGN_WORD);

	memset(realcipher, 0, BINARY_SIZE + SALT_SIZE + 9);
	base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
	return (void*)&realcipher[BINARY_SIZE];
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if(ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH + NSLDAP_MAGIC_LENGTH)
		return !strncasecmp(ciphertext, NSLDAP_MAGIC, NSLDAP_MAGIC_LENGTH);
	return 0;
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

static int salt_hash(void *salt)
{
	return *((ARCH_WORD_32 *)salt) & (SALT_HASH_SIZE - 1);
}

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	int len;
	int i;

	if(index==0)
	{
		memset(saved_key, 0, sizeof(saved_key));
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	length[index] = len;

	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS( (i+SALT_SIZE) , index)] = 0x80;
	((unsigned int *)saved_key)[15*MMX_COEF+index] = (len+SALT_SIZE)<<3;
#else
	strnzcpy(saved_key, key, PLAINTEXT_LENGTH+1);
#endif
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, SALT_SIZE);
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int i,s;

	s = length[index];
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char*)out;
#else
  return saved_key;
#endif
}

static int
cmp_all(void *binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
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

static int
cmp_exact(char *source, int index)
{
  return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef MMX_COEF
	int i = 0;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((unsigned long *)binary)[i] != ((unsigned long *)crypt_key)[i*MMX_COEF+index] )
			return 0;
	return 1;
#else
	return cmp_all(binary, index);
#endif
}


static void crypt_all(int count)
{
#ifdef MMX_COEF
	int i,idx;

	for(idx=0;idx<MAX_KEYS_PER_CRYPT;idx++)
	{
		for(i=0;i<SALT_SIZE;i++)
			saved_key[GETPOS((i+length[idx]),idx)] = ((unsigned char *)saved_salt)[i];
	}
	shammx((unsigned char*)crypt_key, (unsigned char*)saved_key);
#else
	static SHA_CTX ctx;
	SHA1_Init(&ctx);
	SHA1_Update(&ctx, (unsigned char*)saved_key, strlen(saved_key));
	SHA1_Update(&ctx, (unsigned char*)saved_salt, SALT_SIZE);
	SHA1_Final((unsigned char*)crypt_key, &ctx);
#endif
}

struct fmt_main fmt_OPENLDAPS = {
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
			binary_hash_4
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
			get_hash_4
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

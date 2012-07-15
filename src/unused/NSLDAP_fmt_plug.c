// Fix for john the ripper 1.6.37 by Sun-Zero, 2004. 07. 26.
/*
 * Minor performance enhancement by bartavelle at bandecon.com
 */

#include <string.h>

#include "misc.h"
#include "formats.h"
#include "common.h"

#include "sha.h"
#include "base64.h"

#define FORMAT_LABEL			"nsldap"
#define FORMAT_NAME			"Netscape LDAP SHA"

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
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		33

#define BINARY_SIZE			20
#define SALT_SIZE			0

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		MMX_COEF
#define MAX_KEYS_PER_CRYPT		MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + (3-((i)&3)) )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define NSLDAP_MAGIC "{sha}"
#define NSLDAP_MAGIC_LENGTH 5

static struct fmt_tests tests[] = {
  {"{SHA}cMiB1KJphN3OeV9vcYF8nPRIDnk=", "aaaa"},
  {"{SHA}iu0TIuVFC62weOH7YKgXod8loso=", "bbbb"},
  {"{SHA}0ijZPTcJXMa+t2XnEbEwSOkvQu0=", "ccccccccc"},
  {"{SHA}vNR9eUfJfcKmdkLDqNoKagho+qU=", "dddddddddd"},
  {NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define buffer NSLDAP_buffer
#define crypt_key NSLDAP_crypt_key
#ifdef _MSC_VER
__declspec(align(16)) unsigned char buffer[80*4*MMX_COEF];
__declspec(align(16)) char crypt_key[BINARY_SIZE*MMX_COEF];
#else
unsigned char buffer[80*4*MMX_COEF] __attribute__ ((aligned(16)));
char crypt_key[BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
#endif
static char saved_key[(PLAINTEXT_LENGTH+4+1)*MMX_COEF]; // we add an extra DWORD to hold the 0x80 if the password is exactly PLAINTEXT_LENGTH bytes long)
static unsigned long total_len;
static unsigned char out[PLAINTEXT_LENGTH + 1];
#else
static ARCH_WORD_32 crypt_key[BINARY_SIZE / 4];
static char saved_key[PLAINTEXT_LENGTH + 1];
#endif

static void *
binary(char *ciphertext) {
  static char realcipher[BINARY_SIZE + 9];

  /* stupid overflows */
  memset(realcipher, 0, sizeof(realcipher));
  base64_decode(NSLDAP_MAGIC_LENGTH+ciphertext, CIPHERTEXT_LENGTH, realcipher);
  return (void *)realcipher;
}

static int
valid(char *ciphertext, struct fmt_main *self)
{
  if(ciphertext && strlen(ciphertext) == CIPHERTEXT_LENGTH)
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

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	int len;
	int i;

	if(index==0)
	{
		total_len = 0;
		memset(saved_key, 0, sizeof(saved_key));
	}
	len = strlen(key);
	if(len>PLAINTEXT_LENGTH)
		len = PLAINTEXT_LENGTH;

	total_len += len << ( ( (32/MMX_COEF) * index ) );
	for(i=0;i<len;i++)
		saved_key[GETPOS(i, index)] = key[i];

	saved_key[GETPOS(i, index)] = 0x80;
#else
  strnzcpy(saved_key, key, sizeof(saved_key));
#endif
}

static char *get_key(int index)
{
#ifdef MMX_COEF
	unsigned int i,s;

	s = (total_len >> (((32/MMX_COEF)*(index)))) & 0xff;
	for(i=0;i<s;i++)
		out[i] = saved_key[ GETPOS(i, index) ];
	out[i] = 0;
	return (char *) out;
#else
  return saved_key;
#endif
}

static int
cmp_all(void *binary, int count)
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

static void
crypt_all(int count) {
#ifdef MMX_COEF
	memcpy(buffer, saved_key, (PLAINTEXT_LENGTH+4)*MMX_COEF);
	shammx((unsigned char *) crypt_key, buffer, total_len);
#else
  static SHA_CTX ctx;
  SHA1_Init(&ctx);
  SHA1_Update(&ctx, (unsigned char *) saved_key, strlen(saved_key));
  SHA1_Final((unsigned char *) crypt_key, &ctx);
#endif
}

struct fmt_main fmt_NSLDAP = {
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

/*
 * EPiServer module for john 1.7.2 (and possibly later)
 * Uses hashes/salts found in the tblSID of an EPiServer database installation
 *
 * Created by Johannes Gumbel (johannes [at] iforge.cc)
 *
 * If you have any questions as to how a function incorporates with john, please refer to formats.h of john
 *
 * version 0.1 released on 10 jan 2007
 *
 * See doc/README.format-epi for information on the input file format.
 *
 * Updated Dec, 2014, JimF.  Added OMP, and allowed more than one hash to be
 * processed at once (OMP_SCALE stuff).
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_EPI;
#elif FMT_REGISTERS_H
john_register_one(&fmt_EPI);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"

#include "sha.h"
#ifdef _OPENMP
#include <omp.h>
#ifdef __MIC__
#ifndef OMP_SCALE
#define OMP_SCALE              8192
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE              32768   // Tuned, K8-dual HT
#endif
#endif // __MIC__
#endif
#include "memdbg.h"

#define PLAINTEXT_LENGTH   125
#define BINARY_LENGTH      20
#define BINARY_ALIGN       sizeof(ARCH_WORD_32)
#define SALT_LENGTH        30
#define SALT_ALIGN         4
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1

static int (*key_len);
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_out)[BINARY_LENGTH / 4];
static char global_salt[SALT_LENGTH+1];

static struct fmt_tests global_tests[] =
{
  {"0x5F1D84A6DE97E2BEFB637A3CB5318AFEF0750B856CF1836BD1D4470175BE 0x4D5EFDFA143EDF74193076F174AC47CEBF2F417F", "Abc.!23"},
// new tests from pass_gen.pl
  {"0x4F5233704337716F63526A7066344B52784F7A6363316750516A72335668 0x7346DA02479E55973E052FC9A173A3FEA4644FF8","test1"},
  {"0x76706335715834565A55784662304F3367756350684F634447777A313642 0xDBD3D2764A376673164962E3EE2AE95AB6ED2759","thatsworking"},
  {"0x6F724166466172354A7431316A4842746878434B6632744945574A37524A 0xE1ADE625160BB27C16184795715F1C9EF30C45B0","test3"},
  {NULL}
};

static void init(struct fmt_main *self)
{
#if defined (_OPENMP)
	int omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt *= omp_t;
#endif
	key_len   = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*key_len));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_out = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_out));
}

static void done(void)
{
	MEM_FREE(crypt_out);
	MEM_FREE(saved_key);
	MEM_FREE(key_len);
}

/*
 * Expects ciphertext of format: 0xHEX*60 0xHEX*40
 */
static int valid(char *ciphertext, struct fmt_main *self)
{
  unsigned int len, n;

  if(!ciphertext) return 0;
  len = strlen(ciphertext);

  if(len != 105)
    return 0;

  // check fixed positions
  if(ciphertext[0]  != '0' || ciphertext[1]  != 'x' ||
     ciphertext[62] != ' ' ||
     ciphertext[63] != '0' || ciphertext[64] != 'x')
    return 0;

  for(n = 2; n < 62 && atoi16[ARCH_INDEX(ciphertext[n])] != 0x7F; ++n);
  for(n = 65; n < 105 && atoi16[ARCH_INDEX(ciphertext[n])] != 0x7F; ++n);

  return n == len;
}

static void _tobin(char* dst, char *src, unsigned int len)
{
  unsigned int n;

  if(src[0] == '0' && src[1] == 'x')
    src += sizeof(char)*2;

  for(n = 0; n < len; ++n)
    dst[n] = atoi16[ARCH_INDEX(src[n*2])]<<4 |
             atoi16[ARCH_INDEX(src[n*2+1])];
}

static void* get_binary(char *ciphertext)
{
  static ARCH_WORD bin[(BINARY_LENGTH + sizeof(ARCH_WORD) - 1) / sizeof(ARCH_WORD)];

  _tobin((char*)bin, (char*)(ciphertext+65), BINARY_LENGTH);

  return bin;
}

static void* get_salt(char *ciphertext)
{
  static ARCH_WORD salt[(SALT_LENGTH + sizeof(ARCH_WORD) - 1) / sizeof(ARCH_WORD)];

  _tobin((char*)salt, (char*)(ciphertext+2), sizeof(salt));

  return salt;
}

static void set_salt(void *salt)
{
  memcpy(global_salt, salt, SALT_LENGTH);
}

static void set_key(char *key, int index)
{
  if(!key) return;
  key_len[index] = strlen(key) + 1;
  strcpy(saved_key[index], key);
}

static char* get_key(int index)
{
  return saved_key[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int i=0;
#ifdef _OPENMP
#pragma omp parallel for private(i) shared(global_salt, saved_key, key_len, crypt_out)
#endif
#if defined (_OPENMP) || MAX_KEYS_PER_CRYPT>1
	for (i = 0; i < count; ++i)
#endif
	{
		SHA_CTX ctx;
		SHA1_Init(&ctx);
		SHA1_Update(&ctx, (unsigned char*)global_salt, SALT_LENGTH-1);
		SHA1_Update(&ctx, saved_key[i], key_len[i]);
		SHA1_Final((unsigned char*)crypt_out[i], &ctx);
	}

	return count;
}

static int cmp_all(void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if ( ((ARCH_WORD_32*)binary)[0] == crypt_out[index][0] )
			return 1;
	return 0;
}

static int cmp_one(void *binary, int index)
{
  return !memcmp(binary, crypt_out[index], BINARY_LENGTH);
}

static int cmp_exact(char *source, int index)
{
  return 1;
}

static int get_hash_0(int index) { return crypt_out[index][0] & 0xF; }
static int get_hash_1(int index) { return crypt_out[index][0] & 0xFF; }
static int get_hash_2(int index) { return crypt_out[index][0] & 0xFFF; }
static int get_hash_3(int index) { return crypt_out[index][0] & 0xFFFF; }
static int get_hash_4(int index) { return crypt_out[index][0] & 0xFFFFF; }
static int get_hash_5(int index) { return crypt_out[index][0] & 0xFFFFFF; }
static int get_hash_6(int index) { return crypt_out[index][0] & 0x7FFFFFF; }

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

// Define john integration
struct fmt_main fmt_EPI =
{
	{ // fmt_params
		"EPI",
		"EPiServer SID",
		"SHA1 32/" ARCH_BITS_STR,
		"", // benchmark comment
		0, // benchmark length
		0,
		PLAINTEXT_LENGTH,
		BINARY_LENGTH,
		BINARY_ALIGN,
		SALT_LENGTH,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
		global_tests
	},
	{ // fmt_methods
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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
		salt_hash,
		NULL,
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

#endif /* plugin stanza */

//original work by Jeff Fay
//some optimisations by bartavelle at bandecon.com
/* OpenMP support and further optimizations (including some code rewrites)
 * by Solar Designer */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_lotus5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_lotus5);
#else

#include <stdio.h>
#include <string.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "misc.h"
#include "formats.h"
#include "common.h"

#ifdef __x86_64__
#define LOTUS_N 3
#define LOTUS_N_STR " X3"
#else
#define LOTUS_N 2
#define LOTUS_N_STR " X2"
#endif

/*preprocessor constants that John The Ripper likes*/
#define FORMAT_LABEL                   "lotus5"
#define FORMAT_NAME                    "Lotus Notes/Domino 5"
#define ALGORITHM_NAME                 "8/" ARCH_BITS_STR LOTUS_N_STR
#define BENCHMARK_COMMENT              ""
#define BENCHMARK_LENGTH               0x107
#define PLAINTEXT_LENGTH               16
#define CIPHERTEXT_LENGTH              32
#define BINARY_SIZE                    16
#define SALT_SIZE                      0
#define BINARY_ALIGN			sizeof(uint32_t)
#define SALT_ALIGN				1
#define MIN_KEYS_PER_CRYPT             LOTUS_N
/* Must be divisible by any LOTUS_N (thus, by 2 and 3) */
#define MAX_KEYS_PER_CRYPT             (64 * LOTUS_N)

#ifndef OMP_SCALE
#define OMP_SCALE               16 // MKPC and scale tuned for i7
#endif

/*A struct used for JTR's benchmarks*/
static struct fmt_tests tests[] = {
  {"06E0A50B579AD2CD5FFDC48564627EE7", "secret"},
  {"355E98E7C7B59BD810ED845AD0FD2FC4", "password"},
  {"CD2D90E8E00D8A2A63A81F531EA8A9A3", "lotus"},
  {"69D90B46B1AC0912E5CCF858094BBBFC", "dirtydog"},
  {NULL}
};

static const unsigned char lotus_magic_table[] = {
  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36,
  0x3e, 0xee, 0xfb, 0x95, 0x1a, 0xfe, 0xce, 0xa8,
  0x34, 0xa9, 0x13, 0xf0, 0xa6, 0x3f, 0xd8, 0x0c,
  0x78, 0x24, 0xaf, 0x23, 0x52, 0xc1, 0x67, 0x17,
  0xf5, 0x66, 0x90, 0xe7, 0xe8, 0x07, 0xb8, 0x60,
  0x48, 0xe6, 0x1e, 0x53, 0xf3, 0x92, 0xa4, 0x72,
  0x8c, 0x08, 0x15, 0x6e, 0x86, 0x00, 0x84, 0xfa,
  0xf4, 0x7f, 0x8a, 0x42, 0x19, 0xf6, 0xdb, 0xcd,
  0x14, 0x8d, 0x50, 0x12, 0xba, 0x3c, 0x06, 0x4e,
  0xec, 0xb3, 0x35, 0x11, 0xa1, 0x88, 0x8e, 0x2b,
  0x94, 0x99, 0xb7, 0x71, 0x74, 0xd3, 0xe4, 0xbf,
  0x3a, 0xde, 0x96, 0x0e, 0xbc, 0x0a, 0xed, 0x77,
  0xfc, 0x37, 0x6b, 0x03, 0x79, 0x89, 0x62, 0xc6,
  0xd7, 0xc0, 0xd2, 0x7c, 0x6a, 0x8b, 0x22, 0xa3,
  0x5b, 0x05, 0x5d, 0x02, 0x75, 0xd5, 0x61, 0xe3,
  0x18, 0x8f, 0x55, 0x51, 0xad, 0x1f, 0x0b, 0x5e,
  0x85, 0xe5, 0xc2, 0x57, 0x63, 0xca, 0x3d, 0x6c,
  0xb4, 0xc5, 0xcc, 0x70, 0xb2, 0x91, 0x59, 0x0d,
  0x47, 0x20, 0xc8, 0x4f, 0x58, 0xe0, 0x01, 0xe2,
  0x16, 0x38, 0xc4, 0x6f, 0x3b, 0x0f, 0x65, 0x46,
  0xbe, 0x7e, 0x2d, 0x7b, 0x82, 0xf9, 0x40, 0xb5,
  0x1d, 0x73, 0xf8, 0xeb, 0x26, 0xc7, 0x87, 0x97,
  0x25, 0x54, 0xb1, 0x28, 0xaa, 0x98, 0x9d, 0xa5,
  0x64, 0x6d, 0x7a, 0xd4, 0x10, 0x81, 0x44, 0xef,
  0x49, 0xd6, 0xae, 0x2e, 0xdd, 0x76, 0x5c, 0x2f,
  0xa7, 0x1c, 0xc9, 0x09, 0x69, 0x9a, 0x83, 0xcf,
  0x29, 0x39, 0xb9, 0xe9, 0x4c, 0xff, 0x43, 0xab,

  0xbd, 0x56, 0xea, 0xf2, 0xa2, 0xf1, 0xac, 0x2a,
  0xb0, 0x93, 0xd1, 0x9c, 0x1b, 0x33, 0xfd, 0xd0,
  0x30, 0x04, 0xb6, 0xdc, 0x7d, 0xdf, 0x32, 0x4b,
  0xf7, 0xcb, 0x45, 0x9b, 0x31, 0xbb, 0x21, 0x5a,
  0x41, 0x9f, 0xe1, 0xd9, 0x4a, 0x4d, 0x9e, 0xda,
  0xa0, 0x68, 0x2c, 0xc3, 0x27, 0x5f, 0x80, 0x36
};

/*Some more JTR variables*/
static uint32_t (*crypt_key)[BINARY_SIZE / 4];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];

static void init(struct fmt_main *self)
{
	omp_autotune(self, OMP_SCALE);

	crypt_key = mem_calloc_align(sizeof(*crypt_key),
	    self->params.max_keys_per_crypt, MEM_ALIGN_CACHE);
	saved_key = mem_calloc_align(sizeof(*saved_key),
	    self->params.max_keys_per_crypt, MEM_ALIGN_CACHE);
}

static void done(void)
{
	MEM_FREE(crypt_key);
	MEM_FREE(saved_key);
}

/*Utility function to convert hex to bin */
static void * get_binary(char *ciphertext)
{
  static uint32_t out[BINARY_SIZE/4];
  char *realcipher = (char*)out;
  int i;

  for (i = 0; i < BINARY_SIZE; i++)
      realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
  return (void*)out;
}

/*Another function required by JTR: decides whether we have a valid
 * ciphertext */
static int
valid (char *ciphertext, struct fmt_main *self)
{
  int i;

  for (i = 0; i < CIPHERTEXT_LENGTH; i++)
	  if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9'))
				  //|| ((ciphertext[i] >= 'a') && (ciphertext[i] <= 'f'))
				  || ((ciphertext[i] >= 'A') && (ciphertext[i] <= 'F'))))
	  {
		  return 0;
	  }
  return !ciphertext[i];
}

/*sets the value of saved_key so we can play with it*/
static void set_key (char *key, int index)
{
  strnzcpy (saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

/*retrieves the saved key; used by JTR*/
static char * get_key (int index)
{
	return saved_key[index];
}

static int cmp_all (void *binary, int count)
{
	int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
}

static int cmp_one (void *binary, int index)
{
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
}

static int cmp_exact (char *source, int index)
{
	return 1;
}

/*Beginning of private functions*/
/* Takes the plaintext password and generates the second row of our
 * working matrix for the final call to the mixing function*/
MAYBE_INLINE static void
#if LOTUS_N == 3
lotus_transform_password (unsigned char *i0, unsigned char *o0,
    unsigned char *i1, unsigned char *o1,
    unsigned char *i2, unsigned char *o2)
#else
lotus_transform_password (unsigned char *i0, unsigned char *o0,
    unsigned char *i1, unsigned char *o1)
#endif
{
  unsigned char t0, t1;
#if LOTUS_N == 3
  unsigned char t2;
#endif
  int i;

#if LOTUS_N == 3
  t0 = t1 = t2 = 0;
#else
  t0 = t1 = 0;
#endif
  for (i = 0; i < 8; i++)
    {
      t0 = *o0++ = lotus_magic_table[ARCH_INDEX(*i0++ ^ t0)];
      t1 = *o1++ = lotus_magic_table[ARCH_INDEX(*i1++ ^ t1)];
#if LOTUS_N == 3
      t2 = *o2++ = lotus_magic_table[ARCH_INDEX(*i2++ ^ t2)];
#endif
      t0 = *o0++ = lotus_magic_table[ARCH_INDEX(*i0++ ^ t0)];
      t1 = *o1++ = lotus_magic_table[ARCH_INDEX(*i1++ ^ t1)];
#if LOTUS_N == 3
      t2 = *o2++ = lotus_magic_table[ARCH_INDEX(*i2++ ^ t2)];
#endif
    }
}

/* The mixing function: perturbs the first three rows of the matrix*/
#if LOTUS_N == 3
static void lotus_mix (unsigned char *m0, unsigned char *m1,
    unsigned char *m2)
#else
static void lotus_mix (unsigned char *m0, unsigned char *m1)
#endif
{
  unsigned char t0, t1;
  unsigned char *p0, *p1;
#if LOTUS_N == 3
  unsigned char t2;
  unsigned char *p2;
#endif
  int i, j;

#if LOTUS_N == 3
  t0 = t1 = t2 = 0;
#else
  t0 = t1 = 0;
#endif

  for (i = 18; i > 0; i--)
    {
      p0 = m0;
      p1 = m1;
#if LOTUS_N == 3
      p2 = m2;
#endif
      for (j = 48; j > 0; j--)
	{
	  t0 = p0[0] ^= lotus_magic_table[ARCH_INDEX(j + t0)];
	  t1 = p1[0] ^= lotus_magic_table[ARCH_INDEX(j + t1)];
#if LOTUS_N == 3
	  t2 = p2[0] ^= lotus_magic_table[ARCH_INDEX(j + t2)];
#endif
	  j--;
	  t0 = p0[1] ^= lotus_magic_table[ARCH_INDEX(j + t0)];
	  p0 += 2;
	  t1 = p1[1] ^= lotus_magic_table[ARCH_INDEX(j + t1)];
	  p1 += 2;
#if LOTUS_N == 3
	  t2 = p2[1] ^= lotus_magic_table[ARCH_INDEX(j + t2)];
	  p2 += 2;
#endif
	}
    }
}

/*the last public function; generates ciphertext*/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index += LOTUS_N) {
		struct {
			union {
				unsigned char m[64];
				unsigned char m4[4][16];
				ARCH_WORD m4w[4][16 / ARCH_SIZE];
			} u;
		} ctx[LOTUS_N];
		int password_length;

		memset(ctx[0].u.m4[0], 0, 16);
		password_length = strlen(saved_key[index]);
		memset(ctx[0].u.m4[1], (PLAINTEXT_LENGTH - password_length), PLAINTEXT_LENGTH);
		memcpy(ctx[0].u.m4[1], saved_key[index], password_length);
		memcpy(ctx[0].u.m4[2], ctx[0].u.m4[1], 16);

		memset(ctx[1].u.m4[0], 0, 16);
		password_length = strlen(saved_key[index + 1]);
		memset(ctx[1].u.m4[1], (PLAINTEXT_LENGTH - password_length), PLAINTEXT_LENGTH);
		memcpy(ctx[1].u.m4[1], saved_key[index + 1], password_length);
		memcpy(ctx[1].u.m4[2], ctx[1].u.m4[1], 16);

#if LOTUS_N == 3
		memset(ctx[2].u.m4[0], 0, 16);
		password_length = strlen(saved_key[index + 2]);
		memset(ctx[2].u.m4[1], (PLAINTEXT_LENGTH - password_length), PLAINTEXT_LENGTH);
		memcpy(ctx[2].u.m4[1], saved_key[index + 2], password_length);
		memcpy(ctx[2].u.m4[2], ctx[2].u.m4[1], 16);

		lotus_transform_password(ctx[0].u.m4[1], ctx[0].u.m4[3],
		                         ctx[1].u.m4[1], ctx[1].u.m4[3],
		                         ctx[2].u.m4[1], ctx[2].u.m4[3]);
		lotus_mix(ctx[0].u.m, ctx[1].u.m, ctx[2].u.m);
#else
		lotus_transform_password(ctx[0].u.m4[1], ctx[0].u.m4[3],
		                         ctx[1].u.m4[1], ctx[1].u.m4[3]);
		lotus_mix(ctx[0].u.m, ctx[1].u.m);
#endif

		memcpy(ctx[0].u.m4[1], ctx[0].u.m4[3], 16);
		memcpy(ctx[1].u.m4[1], ctx[1].u.m4[3], 16);
#if LOTUS_N == 3
		memcpy(ctx[2].u.m4[1], ctx[2].u.m4[3], 16);
#endif
		{
			int i;
			for (i = 0; i < 16 / ARCH_SIZE; i++) {
				ctx[0].u.m4w[2][i] = ctx[0].u.m4w[0][i] ^ ctx[0].u.m4w[1][i];
				ctx[1].u.m4w[2][i] = ctx[1].u.m4w[0][i] ^ ctx[1].u.m4w[1][i];
#if LOTUS_N == 3
				ctx[2].u.m4w[2][i] = ctx[2].u.m4w[0][i] ^ ctx[2].u.m4w[1][i];
#endif
			}
		}
#if LOTUS_N == 3
		lotus_mix(ctx[0].u.m, ctx[1].u.m, ctx[2].u.m);
#else
		lotus_mix(ctx[0].u.m, ctx[1].u.m);
#endif
		memcpy(crypt_key[index], ctx[0].u.m4[0], BINARY_SIZE);
		memcpy(crypt_key[index + 1], ctx[1].u.m4[0], BINARY_SIZE);
#if LOTUS_N == 3
		memcpy(crypt_key[index + 2], ctx[2].u.m4[0], BINARY_SIZE);
#endif
	}

	return count;
}

#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

/* C's version of a class specifier */
struct fmt_main fmt_lotus5 = {
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
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		fmt_default_salt,
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
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
#define COMMON_GET_HASH_LINK
#include "common-get-hash.h"
		},
		cmp_all,
		cmp_one,
		cmp_exact
	}
};

#endif /* plugin stanza */

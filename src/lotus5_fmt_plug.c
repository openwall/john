//original work by Jeff Fay
//some optimisations by bartavelle at bandecon.com
/* OpenMP support and further optimizations (including some code rewrites)
 * by Solar Designer */

#include <stdio.h>
#include <string.h>
#include "misc.h"
#include "formats.h"
#include "common.h"

/*preprocessor constants that John The Ripper likes*/
#define FORMAT_LABEL                   "lotus5"
#define FORMAT_NAME                    "Lotus5"
#define ALGORITHM_NAME			"Lotus v5 Proprietary"
#define BENCHMARK_COMMENT              ""
#define BENCHMARK_LENGTH               -1
#define PLAINTEXT_LENGTH               16
#define CIPHERTEXT_LENGTH              32
#define BINARY_SIZE                    16
#define SALT_SIZE                      0
#define MIN_KEYS_PER_CRYPT             2
#define MAX_KEYS_PER_CRYPT             0x900 /* must be even */

/*A struct used for JTR's benchmarks*/
static struct fmt_tests tests[] = {
  {"06E0A50B579AD2CD5FFDC48564627EE7", "secret"},
  {"355E98E7C7B59BD810ED845AD0FD2FC4", "password"},
  {"CD2D90E8E00D8A2A63A81F531EA8A9A3", "lotus"},
  {"69D90B46B1AC0912E5CCF858094BBBFC", "dirtydog"},
  {NULL}
};

static const unsigned char lotus_magic_table[256] = {
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
};

/*Some more JTR variables*/
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / 4];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];

#ifdef _OPENMP
#include <omp.h>
#endif

static void init(struct fmt_main *pFmt)
{
#ifdef _OPENMP
	int n = omp_get_max_threads();
	if (n < 1)
		n = 1;
	n *= 2;
	if (n > pFmt->params.max_keys_per_crypt)
		n = pFmt->params.max_keys_per_crypt;
	pFmt->params.min_keys_per_crypt = n;
#endif

	crypt_key = mem_calloc_tiny(
	    (sizeof(*crypt_key) + sizeof(*saved_key)) *
	    pFmt->params.max_keys_per_crypt,
	    MEM_ALIGN_CACHE);
	saved_key = (void *)((char *)crypt_key +
	    sizeof(*crypt_key) * pFmt->params.max_keys_per_crypt);
}

/*Utility function to convert hex to bin */
static void * binary (char *ciphertext)
{
  static char realcipher[BINARY_SIZE];
  int i;
  for (i = 0; i < BINARY_SIZE; i++)
      realcipher[i] = atoi16[ARCH_INDEX(ciphertext[i*2])]*16 + atoi16[ARCH_INDEX(ciphertext[i*2+1])];
  return ((void *) realcipher);
}

/*Another function required by JTR: decides whether we have a valid
 * ciphertext */
static int
valid (char *ciphertext, struct fmt_main *pFmt)
{
  int i;

  for (i = 0; i < CIPHERTEXT_LENGTH; i++)
	  if (!(((ciphertext[i] >= '0') && (ciphertext[i] <= '9'))
				  || ((ciphertext[i] >= 'a') && (ciphertext[i] <= 'f'))
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
void MAYBE_INLINE
lotus_transform_password (unsigned char *i1, unsigned char *o1,
    unsigned char *i2, unsigned char *o2)
{
  unsigned char p1, p2;
  int i;

  p1 = p2 = 0x00;
  for (i = 0; i < 8; i++)
    {
      p1 = *o1++ = lotus_magic_table[ARCH_INDEX(*i1++ ^ p1)];
      p2 = *o2++ = lotus_magic_table[ARCH_INDEX(*i2++ ^ p2)];
      p1 = *o1++ = lotus_magic_table[ARCH_INDEX(*i1++ ^ p1)];
      p2 = *o2++ = lotus_magic_table[ARCH_INDEX(*i2++ ^ p2)];
    }
}

/* The mixing function: perturbs the first three rows of the matrix*/
void MAYBE_INLINE lotus_mix (unsigned char *m1, unsigned char *m2)
{
  int i, j;
  unsigned char p1, p2;
  unsigned char *t1, *t2;

  p1 = p2 = 0x00;

  for (i = 18; i > 0; i--)
    {
      t1 = m1;
      t2 = m2;
      for (j = 48; j > 0; )
	{
	  p1 = t1[0] ^= lotus_magic_table[ARCH_INDEX((j + p1) & 0xff)];
	  p2 = t2[0] ^= lotus_magic_table[ARCH_INDEX((j-- + p2) & 0xff)];
	  p1 = t1[1] ^= lotus_magic_table[ARCH_INDEX((j + p1) & 0xff)];
	  p2 = t2[1] ^= lotus_magic_table[ARCH_INDEX((j-- + p2) & 0xff)];
	  t1 += 2;
	  t2 += 2;
	}
    }
}


/*the last public function; generates ciphertext*/
static void crypt_all (int count)
{
 int index;

#ifdef _OPENMP
#pragma omp parallel for
#endif
 for (index = 0; index < count; index += 2) {
  struct {
   union {
    unsigned char m[64];
    unsigned char m4[4][16];
    ARCH_WORD m4w[4][16 / ARCH_SIZE];
   } u;
  } ctx[2];
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
  lotus_transform_password(ctx[0].u.m4[1], ctx[0].u.m4[3],
      ctx[1].u.m4[1], ctx[1].u.m4[3]);
  lotus_mix(ctx[0].u.m, ctx[1].u.m);
  memcpy(ctx[0].u.m4[1], ctx[0].u.m4[3], 16);
  memcpy(ctx[1].u.m4[1], ctx[1].u.m4[3], 16);
  {
   int i;
   for (i = 0; i < 16 / ARCH_SIZE; i++) {
    ctx[0].u.m4w[2][i] = ctx[0].u.m4w[0][i] ^ ctx[0].u.m4w[1][i];
    ctx[1].u.m4w[2][i] = ctx[1].u.m4w[0][i] ^ ctx[1].u.m4w[1][i];
   }
  }
  lotus_mix(ctx[0].u.m, ctx[1].u.m);
  memcpy(crypt_key[index], ctx[0].u.m4[0], BINARY_SIZE);
  memcpy(crypt_key[index + 1], ctx[1].u.m4[0], BINARY_SIZE);
 }
}

static int get_hash1(int index) { return crypt_key[index][0] & 0xf; }
static int get_hash2(int index) { return crypt_key[index][0] & 0xff; }
static int get_hash3(int index) { return crypt_key[index][0] & 0xfff; }
static int get_hash4(int index) { return crypt_key[index][0] & 0xffff; }
static int get_hash5(int index) { return crypt_key[index][0] & 0xfffff; }
static int get_hash6(int index) { return crypt_key[index][0] & 0xffffff; }
static int get_hash7(int index) { return crypt_key[index][0] & 0x7ffffff; }
static int binary_hash1(void * binary) { return *(ARCH_WORD_32 *)binary & 0xf; }
static int binary_hash2(void * binary) { return *(ARCH_WORD_32 *)binary & 0xff; }
static int binary_hash3(void * binary) { return *(ARCH_WORD_32 *)binary & 0xfff; }
static int binary_hash4(void * binary) { return *(ARCH_WORD_32 *)binary & 0xffff; }
static int binary_hash5(void * binary) { return *(ARCH_WORD_32 *)binary & 0xfffff; }
static int binary_hash6(void * binary) { return *(ARCH_WORD_32 *)binary & 0xffffff; }
static int binary_hash7(void * binary) { return *(ARCH_WORD_32 *)binary & 0x7ffffff; }

/* C's version of a class specifier */
struct fmt_main fmt_lotus5 = {
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
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		fmt_default_salt,
		{
			binary_hash1,
			binary_hash2,
			binary_hash3,
			binary_hash4,
			binary_hash5,
			binary_hash6,
			binary_hash7
		},
		fmt_default_salt_hash,
		fmt_default_set_salt,
		set_key,
		get_key,
		fmt_default_clear_keys,
		crypt_all,
		{
			get_hash1,
			get_hash2,
			get_hash3,
			get_hash4,
			get_hash5,
			get_hash6,
			get_hash7
		},
		cmp_all,
		cmp_one,
		cmp_exact,
		fmt_default_get_source
	}
};

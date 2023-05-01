/*
 * IPB2_fmt.c (version 4)
 *
 * Invision Power Board 2.x salted MD5 module for Solar Designer's JtR
 * Uses Solar Designer's MD5 implementation.
 * regenrecht at o2.pl, Jan 2006
 *
 * Hashes list should have form of username:$IPB2$salt$hash
 * Values to be taken from IPB database, where:
 * salt = bin2hex(ibf_members_converge.converge_pass_salt)
 * hash = ibf_members_converge.converge_pass_hash
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_IPB2;
#elif FMT_REGISTERS_H
john_register_one(&fmt_IPB2);
#else

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "johnswap.h"
#include "common.h"
#include "formats.h"
#include "simd-intrinsics.h"

#if defined(_OPENMP)
#include <omp.h>
static unsigned int threads = 1;
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE			512  // Tuned K8-dual HT
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE			256
#endif
#endif
#else
#define threads				1
#endif


#define FORMAT_LABEL			"ipb2"
#define FORMAT_NAME			"Invision Power Board 2.x"
#define FORMAT_TAG			"$IPB2$"
#define FORMAT_TAG_LEN		(sizeof(FORMAT_TAG)-1)

#define ALGORITHM_NAME			"MD5 " MD5_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

#define BINARY_ALIGN			4
#define BINARY_SIZE			16
#define MD5_HEX_SIZE			(BINARY_SIZE * 2)
#define SALT_SIZE			MD5_HEX_SIZE
#define SALT_ALIGN			4

#define SALT_LENGTH			5

#define PLAINTEXT_LENGTH		31
#define CIPHERTEXT_LENGTH		(1 + 4 + 1 + SALT_LENGTH * 2 + 1 + MD5_HEX_SIZE)

#ifdef SIMD_COEF_32
#define NBKEYS					(SIMD_COEF_32 * SIMD_PARA_MD5)
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#if ARCH_LITTLE_ENDIAN==1
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#define GETOUTPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32 )
#else
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#define GETOUTPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32 )
#endif
#else
#define NBKEYS                  1
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

static struct fmt_tests tests[] = {
	{"$IPB2$2e75504633$d891f03a7327639bc632d62a7f302604", "welcome"},
	{"$IPB2$735a213a4e$4f23de7bb115139660db5e953153f28a", "enter"},
	{"$IPB2$5d75343455$de98ba8ca7bb16f43af05e9e4fb8afee", "matrix"},
	{"$IPB2$556c576c39$16d4f29c71b05bd75e61d0254800bfa3", "123456"},
	{NULL}
};

static const char itoa16_shr_04[] =
	"0000000000000000"
	"1111111111111111"
	"2222222222222222"
	"3333333333333333"
	"4444444444444444"
	"5555555555555555"
	"6666666666666666"
	"7777777777777777"
	"8888888888888888"
	"9999999999999999"
	"aaaaaaaaaaaaaaaa"
	"bbbbbbbbbbbbbbbb"
	"cccccccccccccccc"
	"dddddddddddddddd"
	"eeeeeeeeeeeeeeee"
	"ffffffffffffffff";

static const char itoa16_and_0f[] =
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef"
	"0123456789abcdef";

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];

#if SIMD_COEF_32

static unsigned char *saved_key;
static unsigned char *key_buf;
static unsigned char *empty_key;
static unsigned char *crypt_key;
static uint32_t *cur_salt;
static int new_salt;
static int new_key;

#else

static char (*saved_key)[2*MD5_HEX_SIZE];
static uint32_t (*crypt_key)[BINARY_SIZE / sizeof(uint32_t)];

#endif

static void init(struct fmt_main *self)
{
#if SIMD_COEF_32
	unsigned int i;
#endif
#if defined (_OPENMP)
	threads = omp_get_max_threads();
	self->params.min_keys_per_crypt *= threads;
	threads *= OMP_SCALE;
	// these 2 lines of change, allows the format to work with
	// [Options] FormatBlockScaleTuneMultiplier= without other format change
	threads *= self->params.max_keys_per_crypt;
	threads /= NBKEYS;
	self->params.max_keys_per_crypt = (threads*NBKEYS);
#endif
#if SIMD_COEF_32
	key_buf   = mem_calloc_align(self->params.max_keys_per_crypt,
	                             64, MEM_ALIGN_SIMD);
	empty_key = mem_calloc_align(64 * NBKEYS,
	                             sizeof(empty_key), MEM_ALIGN_SIMD);
	for (i = 0; i < NBKEYS; ++i) {
		empty_key[GETPOS(0, i)] = 0x80;
		((unsigned int*)empty_key)[14*SIMD_COEF_32 + (i&(SIMD_COEF_32-1)) + i/SIMD_COEF_32*16*SIMD_COEF_32] = (2 * MD5_HEX_SIZE)<<3;
	}
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             BINARY_SIZE, MEM_ALIGN_SIMD);
	saved_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             64, MEM_ALIGN_SIMD);
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
}

static void done(void)
{
	MEM_FREE(saved_plain);
	MEM_FREE(saved_key);
	MEM_FREE(crypt_key);
#if SIMD_COEF_32
	MEM_FREE(empty_key);
	MEM_FREE(key_buf);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) != 0)
		return 0;

	if (strnlen(ciphertext, CIPHERTEXT_LENGTH + 1) != CIPHERTEXT_LENGTH)
		return 0;

	if (ciphertext[16] != '$')
		return 0;

	if (strspn(ciphertext+6, HEXCHARS_lc) != SALT_LENGTH*2)
		return 0;

	if (strspn(ciphertext+17, HEXCHARS_lc) != MD5_HEX_SIZE)
		return 0;

	return 1;
}

static void *get_binary(char *ciphertext)
{
	static uint32_t out[BINARY_SIZE/4];
	unsigned char *binary_cipher = (unsigned char*)out;
	int i;

	ciphertext += 17;
	for (i = 0; i < BINARY_SIZE; ++i)
		binary_cipher[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

#if !ARCH_LITTLE_ENDIAN && defined (SIMD_COEF_32)
	alter_endianity(out, BINARY_SIZE);
#endif
	return (void*)out;
}

static void *get_salt(char *ciphertext)
{
	static uint32_t hex_salt[MD5_HEX_SIZE/4];
	unsigned char binary_salt[SALT_LENGTH];
	unsigned char salt_hash[BINARY_SIZE];
	static MD5_CTX ctx;
	int i;

	ciphertext += FORMAT_TAG_LEN;
	for (i = 0; i < SALT_LENGTH; ++i)
		binary_salt[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	MD5_Init(&ctx);
	MD5_Update(&ctx, binary_salt, SALT_LENGTH);
	MD5_Final(salt_hash, &ctx);

	for (i = 0; i < BINARY_SIZE; ++i) {
		((char*)hex_salt)[i*2] = itoa16[ARCH_INDEX(salt_hash[i] >> 4)];
		((char*)hex_salt)[i*2+1] = itoa16[ARCH_INDEX(salt_hash[i] & 0x0f)];
	}

	return (void*)hex_salt;
}

static void set_salt(void *salt)
{
#ifdef SIMD_COEF_32
	cur_salt = salt;
	new_salt = 1;
#else
	int index;

	for (index = 0; index < threads * MAX_KEYS_PER_CRYPT; index++)
		memcpy(saved_key[index], salt, MD5_HEX_SIZE);
#endif
}

static void set_key(char *key, int index)
{
#ifdef SIMD_COEF_32
	strnzcpy(saved_plain[index], key, sizeof(*saved_plain));
	new_key = 1;
#else
	unsigned char key_hash[BINARY_SIZE];
	unsigned char *kh = key_hash;
	unsigned char *key_ptr = (unsigned char*)saved_key[index] + MD5_HEX_SIZE;
	unsigned char v;
	int i, len;
	MD5_CTX ctx;

	len = strnzcpyn(saved_plain[index], key, sizeof(*saved_plain));

	MD5_Init(&ctx);
	MD5_Update(&ctx, key, len);
	MD5_Final(key_hash, &ctx);

	for (i = 0; i < BINARY_SIZE; ++i) {
		v = *kh++;
		*key_ptr++ = itoa16_shr_04[ARCH_INDEX(v)];
		*key_ptr++ = itoa16_and_0f[ARCH_INDEX(v)];
	}
#endif
}

static char *get_key(int index)
{
	return saved_plain[index];
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#ifdef SIMD_COEF_32
#if defined(_OPENMP)
	int t;
#pragma omp parallel for
	for (t = 0; t < threads; t++)
#define ti (t*NBKEYS+index)
#else
#define t  0
#define ti index
#endif
	{
		unsigned int index, i;

		if (new_salt)
		for (index = 0; index < NBKEYS; index++) {
			const uint32_t *sp = cur_salt;
#if ARCH_LITTLE_ENDIAN
			uint32_t *kb = (uint32_t*)&saved_key[GETPOS(0, ti)];
			for (i = 0; i < MD5_HEX_SIZE / 4; i++, kb += SIMD_COEF_32)
				*kb = *sp++;
#else
			uint32_t *kb = (uint32_t*)&saved_key[GETPOS(3, ti)];
			for (i = 0; i < MD5_HEX_SIZE / 4; i++, kb += SIMD_COEF_32)
				*kb = JOHNSWAP(*sp++);
#endif
		}

		if (new_key)
		for (index = 0; index < NBKEYS; index++) {
			const uint32_t *key = (uint32_t*)saved_plain[ti];
			int len = 0, temp;
#if ARCH_LITTLE_ENDIAN
			uint32_t *kb = (uint32_t*)&key_buf[GETPOS(0, ti)];
			uint32_t *keybuffer = kb;

			while((unsigned char)(temp = *key++)) {
				if (!(temp & 0xff00)) {
					*kb = (unsigned char)temp | (0x80 << 8);
					len++;
					goto key_cleaning;
				}
				if (!(temp & 0xff0000)) {
					*kb = (unsigned short)temp | (0x80 << 16);
					len+=2;
					goto key_cleaning;
				}
				if (!(temp & 0xff000000)) {
					*kb = temp | (0x80U << 24);
					len+=3;
					goto key_cleaning;
				}
				*kb = temp;
#else
			uint32_t *kb = (uint32_t*)&key_buf[GETPOS(3, ti)];
			uint32_t *keybuffer = kb;

			while((temp = *key++) & 0xff000000) {
				if (!(temp & 0xff0000))
				{
					*kb = JOHNSWAP((temp & 0xff000000) | (0x80 << 16));
					len++;
					goto key_cleaning;
				}
				if (!(temp & 0xff00))
				{
					*kb = JOHNSWAP((temp & 0xffff0000) | (0x80 << 8));
					len+=2;
					goto key_cleaning;
				}
				if (!(temp & 0xff))
				{
					*kb = JOHNSWAP(temp | 0x80U);
					len+=3;
					goto key_cleaning;
				}
				*kb = JOHNSWAP(temp);
#endif

				len += 4;
				kb += SIMD_COEF_32;
			}
			*kb = 0x00000080;

key_cleaning:
			kb += SIMD_COEF_32;
			while(*kb) {
				*kb = 0;
				kb += SIMD_COEF_32;
			}
			keybuffer[14*SIMD_COEF_32] = len << 3;
		}

		SIMDmd5body(&key_buf[t*NBKEYS*64], (unsigned int*)&crypt_key[t*NBKEYS*16], NULL, SSEi_MIXED_IN);
		for (index = 0; index < NBKEYS; index++) {
			// Somehow when I optimised this it got faster in Valgrind but slower IRL
			for (i = 0; i < BINARY_SIZE; i++) {
				unsigned char v = crypt_key[GETOUTPOS(i, ti)];
				saved_key[GETPOS(MD5_HEX_SIZE + 2 * i, ti)] = itoa16_shr_04[ARCH_INDEX(v)];
				saved_key[GETPOS(MD5_HEX_SIZE + 2 * i + 1, ti)] = itoa16_and_0f[ARCH_INDEX(v)];
			}
		}

		SIMDmd5body(&saved_key[t*NBKEYS*64], (unsigned int*)&crypt_key[t*NBKEYS*16], NULL, SSEi_MIXED_IN);
		SIMDmd5body(empty_key, (unsigned int*)&crypt_key[t*NBKEYS*16], (unsigned int*)&crypt_key[t*NBKEYS*16], SSEi_RELOAD|SSEi_MIXED_IN);
	}
	//dump_stuff_mmx_msg("\nfinal ", saved_key, 64, count-1);
	//dump_out_mmx_msg("result", crypt_key, 16, count-1);
	new_salt = new_key = 0;

#else

#ifdef _OPENMP
	int index;
#pragma omp parallel for
	for (index = 0; index < count; index++)
#else
#define index	0
#endif
	{
		MD5_CTX ctx;

		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[index], MD5_HEX_SIZE * 2);
		MD5_Final((unsigned char*)crypt_key[index], &ctx);
	}
#undef index
#endif
	return count;
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;
#ifdef _OPENMP
	for (y = 0; y < SIMD_PARA_MD5*threads; y++)
#else
	for (y = 0; y < SIMD_PARA_MD5; y++)
#endif
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((uint32_t*)binary)[0] == ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+x] )
				return 1;
		}
	return 0;
#else
	int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

static int cmp_one(void * binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int i,x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;
	for (i=0;i<(BINARY_SIZE/4);i++)
		if ( ((uint32_t*)binary)[i] != ((uint32_t*)crypt_key)[y*SIMD_COEF_32*4+i*SIMD_COEF_32+x] )
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

#define COMMON_GET_HASH_SIMD32 4
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	return *(uint32_t*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_IPB2 = {
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
	},
	{
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
		salt_hash,
		NULL,
		set_salt,
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

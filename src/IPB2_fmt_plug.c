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

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "md5.h"
#include "common.h"
#include "formats.h"

#define FORMAT_LABEL			"ipb2"
#define FORMAT_NAME			"Invision Power Board 2.x salted MD5"

#ifdef MD5_SSE_PARA
#define MMX_COEF			4
#include "sse-intrinsics.h"
#define NBKEYS				(MMX_COEF * MD5_SSE_PARA)
#define ALGORITHM_NAME			"SSE2i " MD5_N_STR
#elif defined(MMX_COEF)
#define NBKEYS				MMX_COEF
#if MMX_COEF == 4
#define ALGORITHM_NAME			"SSE2 4x"
#elif MMX_COEF == 2
#define ALGORITHM_NAME			"MMX 2x"
#elif defined(MMX_COEF)
#define ALGORITHM_NAME			"?"
#endif
#else
#define ALGORITHM_NAME			"32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define BINARY_SIZE			16
#define MD5_HEX_SIZE			(BINARY_SIZE * 2)

#define SALT_SIZE			5

#define PLAINTEXT_LENGTH		32
#define CIPHERTEXT_LENGTH		(1 + 4 + 1 + SALT_SIZE * 2 + 1 + MD5_HEX_SIZE)

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&60)*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*64*MMX_COEF )
#define GETOUTPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&12)*MMX_COEF + ((i)&3) + (index>>(MMX_COEF>>1))*16*MMX_COEF )
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#if defined(_OPENMP) && (defined (MD5_SSE_PARA) || !defined(MMX_COEF))
#include <omp.h>
static unsigned int omp_t = 1;
#ifdef MD5_SSE_PARA
#define OMP_SCALE			256
#else
#define OMP_SCALE			256
#endif
#else
#define omp_t				1
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

#if MMX_COEF

static unsigned char *saved_key;
static unsigned char *key_buf;
static unsigned char *empty_key;
static unsigned char *crypt_key;
static ARCH_WORD_32 *cur_salt;
static int new_salt;
static int new_key;

#else

static char (*saved_key)[2*MD5_HEX_SIZE];
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

#endif

static void init(struct fmt_main *pFmt)
{
#if MMX_COEF
	int i;
#endif
#if defined (_OPENMP) && (defined(MD5_SSE_PARA) || !defined(MMX_COEF))
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt *= omp_t;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt *= omp_t;
#endif
#if MMX_COEF
	key_buf = mem_calloc_tiny(64 * pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_tiny(BINARY_SIZE * pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	saved_key = mem_calloc_tiny(64 * pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	empty_key = mem_calloc_tiny(64 * NBKEYS, MEM_ALIGN_SIMD);
	for (i = 0; i < NBKEYS; ++i) {
		empty_key[GETPOS(0, i)] = 0x80;
		((unsigned int*)empty_key)[14*MMX_COEF + (i&3) + (i>>2)*16*MMX_COEF] = (2 * MD5_HEX_SIZE)<<3;
	}
#else
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
#endif
	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	if (strlen(ciphertext) != CIPHERTEXT_LENGTH)
		return 0;

	if (strncmp(ciphertext, "$IPB2$", 6) != 0)
		return 0;

	if (ciphertext[16] != '$')
		return 0;

	if (strspn(ciphertext+6, itoa16) != SALT_SIZE*2)
		return 0;

	if (strspn(ciphertext+17, itoa16) != MD5_HEX_SIZE)
		return 0;

	return 1;
}

static void *binary(char *ciphertext)
{
	static unsigned char binary_cipher[BINARY_SIZE];
	int i;

	ciphertext += 17;
	for (i = 0; i < BINARY_SIZE; ++i)
		binary_cipher[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	return (void *)binary_cipher;
}

static void *salt(char *ciphertext)
{
	static unsigned char hex_salt[MD5_HEX_SIZE];
	unsigned char binary_salt[SALT_SIZE];
	unsigned char salt_hash[BINARY_SIZE];
	static MD5_CTX ctx;
	int i;

	ciphertext += 6;
	for (i = 0; i < SALT_SIZE; ++i)
		binary_salt[i] =
			(atoi16[ARCH_INDEX(ciphertext[i*2])] << 4)
			+ atoi16[ARCH_INDEX(ciphertext[i*2+1])];

	MD5_Init(&ctx);
	MD5_Update(&ctx, binary_salt, SALT_SIZE);
	MD5_Final(salt_hash, &ctx);

	for (i = 0; i < BINARY_SIZE; ++i) {
		hex_salt[i*2] = itoa16[ARCH_INDEX(salt_hash[i] >> 4)];
		hex_salt[i*2+1] = itoa16[ARCH_INDEX(salt_hash[i] & 0x0f)];
	}

	return (void*)hex_salt;
}

static void set_salt(void *salt)
{
#ifdef MMX_COEF
	cur_salt = salt;
	new_salt = 1;
#else
	int index;

	for (index = 0; index < omp_t * MAX_KEYS_PER_CRYPT; index++)
		memcpy(saved_key[index], salt, MD5_HEX_SIZE);
#endif
}

#ifndef MMX_COEF
static inline int strnfcpy_count(char *dst, char *src, int size)
{
	char *dptr = dst, *sptr = src;
	int count = size;

	while (count--)
		if (!(*dptr++ = *sptr++)) break;

	return size-count-1;
}
#endif

static void set_key(char *key, int index)
{
#ifdef MMX_COEF
	memcpy(saved_plain[index], key, PLAINTEXT_LENGTH);
	new_key = 1;
#else
	unsigned char key_hash[BINARY_SIZE];
	unsigned char *kh = key_hash;
	unsigned char *key_ptr = (unsigned char*)saved_key[index] + MD5_HEX_SIZE;
	unsigned char v;
	int i, len;
	MD5_CTX ctx;

	len = strnfcpy_count(saved_plain[index], key, PLAINTEXT_LENGTH);

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

static void crypt_all(int count)
{
#ifdef MMX_COEF
#if defined(_OPENMP) && defined(MD5_SSE_PARA)
	int t;
#pragma omp parallel for
	for (t = 0; t < omp_t; t++)
#define ti (t*NBKEYS+index)
#else
#define t  0
#define ti index
#endif
	{
		unsigned int index, i;

		if (new_salt)
		for (index = 0; index < NBKEYS; index++) {
			const ARCH_WORD_32 *sp = cur_salt;
			ARCH_WORD_32 *kb = (ARCH_WORD_32*)&saved_key[GETPOS(0, ti)];

			for (i = 0; i < MD5_HEX_SIZE / 4; i++, kb += MMX_COEF)
				*kb = *sp++;
		}

		if (new_key)
		for (index = 0; index < NBKEYS; index++) {
			const ARCH_WORD_32 *key = (ARCH_WORD_32*)saved_plain[ti];
			ARCH_WORD_32 *kb = (ARCH_WORD_32*)&key_buf[GETPOS(0, ti)];
			ARCH_WORD_32 *keybuffer = kb;
			int len, temp;

			len = 0;
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
					*kb = temp | (0x80 << 24);
					len+=3;
					goto key_cleaning;
				}
				*kb = temp;
				len += 4;
				kb += MMX_COEF;
			}
			*kb = 0x00000080;

key_cleaning:
			kb += MMX_COEF;
			while(*kb) {
				*kb = 0;
				kb += MMX_COEF;
			}
			keybuffer[14*MMX_COEF] = len << 3;
		}

#ifdef MD5_SSE_PARA
		SSEmd5body(&key_buf[t*NBKEYS*64], (unsigned int*)&crypt_key[t*NBKEYS*16], 1);
#else
		mdfivemmx_nosizeupdate(crypt_key, key_buf, 0);
#endif
		for (index = 0; index < NBKEYS; index++) {
			// Somehow when I optimised this it got faster in Valgrind but slower IRL
			for (i = 0; i < BINARY_SIZE; i++) {
				unsigned char v = crypt_key[GETOUTPOS(i, ti)];
				saved_key[GETPOS(MD5_HEX_SIZE + 2 * i, ti)] = itoa16_shr_04[ARCH_INDEX(v)];
				saved_key[GETPOS(MD5_HEX_SIZE + 2 * i + 1, ti)] = itoa16_and_0f[ARCH_INDEX(v)];
			}
		}

#ifdef MD5_SSE_PARA
		SSEmd5body(&saved_key[t*NBKEYS*64], (unsigned int*)&crypt_key[t*NBKEYS*16], 1);
		SSEmd5body(empty_key, (unsigned int*)&crypt_key[t*NBKEYS*16], 0);
#else
		mdfivemmx_nosizeupdate(crypt_key, saved_key, 0);
		mdfivemmx_noinit_nosizeupdate(crypt_key, empty_key, 0);
#endif
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
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;
#ifdef MD5_SSE_PARA
#ifdef _OPENMP
	for(;y<MD5_SSE_PARA*omp_t;y++)
#else
	for(;y<MD5_SSE_PARA;y++)
#endif
#endif
		for(x = 0; x < MMX_COEF; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+x] )
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
#ifdef MMX_COEF
	unsigned int i,x,y;
	x = index&(MMX_COEF-1);
	y = index/MMX_COEF;
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[y*MMX_COEF*4+i*MMX_COEF+x] )
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static int binary_hash_0(void *binary) { return *(ARCH_WORD_32*)binary & 0xF; }
static int binary_hash_1(void *binary) { return *(ARCH_WORD_32*)binary & 0xFF; }
static int binary_hash_2(void *binary) { return *(ARCH_WORD_32*)binary & 0xFFF; }
static int binary_hash_3(void *binary) { return *(ARCH_WORD_32*)binary & 0xFFFF; }
static int binary_hash_4(void *binary) { return *(ARCH_WORD_32*)binary & 0xFFFFF; }
static int binary_hash_5(void *binary) { return *(ARCH_WORD_32*)binary & 0xFFFFFF; }
static int binary_hash_6(void *binary) { return *(ARCH_WORD_32*)binary & 0x7FFFFFF; }

#ifdef MMX_COEF
#define HASH_OFFSET (index&(MMX_COEF-1))+(index/MMX_COEF)*MMX_COEF*4
static int get_hash_0(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32 *)crypt_key)[HASH_OFFSET] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xF; }
static int get_hash_1(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFF; }
static int get_hash_2(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFF; }
static int get_hash_3(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFFF; }
static int get_hash_4(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFFFF; }
static int get_hash_5(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xFFFFFF; }
static int get_hash_6(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0x7FFFFFF; }
#endif

static int salt_hash(void *salt)
{
	return *(ARCH_WORD_32*)salt & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_IPB2 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		MD5_HEX_SIZE,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT | FMT_OMP,
		tests
	},
	{
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
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
		cmp_exact,
		fmt_default_get_source
	}
};

/* MSCASH2 patch for John the Ripper written by S3nf in 2010, 2011
 * a slow but working version
 *
 * Cracking Domain Cached Credentials for modern Windows operating systems, supporting:
 *     - Windows Vista
 *     - Windows 7
 *     - Windows Server 2008
 *
 * This software was written by S3nf in 2010, 2011. No copyright is claimed, and the software is hereby placed in
 * the public domain. In case this attempt to disclaim copyright and place the software in the public domain
 * is deemed null and void, then the software is Copyright (c) 2010, 2011 S3nf and it is hereby released to the
 * general public under the following terms:
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted.
 *
 * Modified for optional utf-8 support by magnum 2011, same terms as above
 *
 * Code redone/optimized by JimF June 2011.  (2x to 10x improvement in speed)
 *	- Code converted to oSSL (for non-sse builds).  The inline MD4/SHA1 replaced.  This reduced
 *	  about 900 lines down to 60 or so, which were much easier to follow.  This was a preliminary
 *	  step to getting SSE2 added.  Once done, this ended up faster than the original, so the new
 *	  simplified code was kept.
 *	- Setup of ipad/opad only done once per PW/Salt  about 10-15% speedup
 *	- 1/2 of the encryption performed within inner loop was moved outside of inner loop (nearly doubles speed)
 *	- changed signature from M$salt#hash to $DCC2$iterations#salt#hash
 *	- variable iterations now 'possible'.  Default is 10240
 *	- increased salt (user name) upto 22 UC2 characters. Bug in original code only allowed up to 8 chars.
 *	- Added SSE2(/MMX) and SSE2i to the deep inner loop.  2x to 4x speedup.
 *	- total about 2x to 10x improvment in speed (depending upon CPU and compiler).  Some compilers
 *	  were more efficient with orinal code, and thus received less of a performance boost.  Others
 *	  got a signicant improvment.
 *	- The utf8 code was greatly simplified.  There was no reason to try to optimized the UTF code as
 *	  the format is so slow that utf8 conversion is a non-issue. Thus the we always call the enc_to_utf16()
 *	  at the proper locations, and let that function deal with being in --encoding=utf8 switch mode or not.
 *	- Fixed code to properly work with BE systems, and alignment required systems.
 *	- Made some 'interface' changes to the SSE2i for SHA1, and to the sha-mmx.S code, to make it work
 *	  properly, and to make it more efficient.  We deal with 2 SHA1 states, and alternate back and forth
 *	  between them. The changes to the SSE2i code, were to optimize this dual state, and the changes
 *	  to the .S code were simply to make it work at all and the same optimizations were place there.
 *	- the OMP code was removed during initial re-write, and was properly re-incorporated by magnum.
 *
 * This module is based on:
 *     - the MSCASH patch for john written by Alain Espinosa <alainesp at gmail.com> in 2007
 *     - RFC 1320 - The MD4 Message-Digest Algorithm
 *     - RFC 2104 - HMAC: Keyed-Hashing for Message Authentication
 *     - RFC 3174 - US Secure Hash Algorithm 1 (SHA1)
 *     - the HMAC-SHA1 implementation of the PolarSSL open source cryptagraphic library (http://polarssl.org/)
 */

#include <string.h>
#include "arch.h"
#include "misc.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "unicode.h"
#include "options.h"
#ifndef HAVE_OPENSSL
#include "sha.h"
#include "md4.h"
#else
#include <openssl/sha.h>
#include <openssl/md4.h>
#endif
#include "unicode.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF			4
#endif
#include "sse-intrinsics.h"

#if (!defined(SHA1_SSE_PARA) && defined(MMX_COEF))
#undef _OPENMP
#undef FMT_OMP
#define FMT_OMP				0
#elif defined (_OPENMP)
#include <omp.h>
#define OMP_LOOPS			1
#endif

#define ITERATIONS			10240
static unsigned iteration_cnt =	(ITERATIONS); /* this will get changed at runtime, salt loading */

/* Note: some tests will be replaced in init() if running UTF-8 */
static struct fmt_tests tests[] = {
	{"$DCC2$10240#test1#607bbe89611e37446e736f7856515bf8", "test1" },
	{"$DCC2$10240#Joe#e09b38f84ab0be586b730baf61781e30", "qerwt" },
	{"$DCC2$10240#Joe#6432f517a900b3fc34ffe57f0f346e16", "12345" },
	{"c0cbe0313a861062e29f92ede58f9b36", "", {"bin"} },           // nullstring password
	{"87136ae0a18b2dafe4a41d555425b2ed", "w00t", {"nineteen_characters"} }, // max salt length
	{"fc5df74eca97afd7cd5abb0032496223", "w00t", {"eighteencharacters"} },
	{"cfc6a1e33eb36c3d4f84e4c2606623d2", "longpassword", {"twentyXXX_characters"} },
	{"99ff74cea552799da8769d30b2684bee", "longpassword", {"twentyoneX_characters"} },
	{"0a721bdc92f27d7fb23b87a445ec562f", "longpassword", {"twentytwoXX_characters"} },
	{"$DCC2$10240#TEST2#c6758e5be7fc943d00b97972a8a97620", "test2" },    // salt is lowercased before hashing
	{"$DCC2$10240#test3#360e51304a2d383ea33467ab0b639cc4", "test3" },
	{"$DCC2$10240#test4#6f79ee93518306f071c47185998566ae", "test4" },

	{NULL}
};

#define FORMAT_LABEL			"mscash2"
#define FORMAT_NAME			"M$ Cache Hash 2 (DCC2) PBKDF2-HMAC-SHA-1"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		27
#define MAX_CIPHERTEXT_LENGTH		(6 + 5 + 22*3 + 2 + 32) // x3 because salt may be UTF-8 in input  // changed to $DCC2$num#salt#hash  WARNING, only handles num of 5 digits!!

#define BINARY_SIZE			16
#define SALT_SIZE			(11*4+4)

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#ifdef MMX_COEF
# ifdef SHA1_SSE_PARA
#  define MS_NUM_KEYS			(MMX_COEF*SHA1_SSE_PARA)
# else
#  define MS_NUM_KEYS			MMX_COEF
# endif
// Ok, now we have our MMX/SSE2/intr buffer.
// this version works properly for MMX, SSE2 (.S) and SSE2 intrinsic.
#define GETPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
static unsigned char (*sse_hash1);
static unsigned char (*sse_crypt1);
static unsigned char (*sse_crypt2);
static unsigned char (*sse_crypt);

#else
# define MS_NUM_KEYS			1
#endif

#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		MS_NUM_KEYS

#define PLAIN_KEY_LEN			(3*PLAINTEXT_LENGTH+1)
#define U16_KEY_LEN			(2*PLAINTEXT_LENGTH)
#define HASH_LEN			(16+48)

static unsigned char *salt_buffer;
static unsigned int   salt_len;
static unsigned char(*key);
static unsigned int   new_key = 1;
static unsigned char(*md4hash); // allows the md4 of user, and salt to be appended to it.  the md4 is ntlm, with the salt is DCC1
static unsigned int (*crypt);
static int omp_t = 1;

static void init(struct fmt_main *self)
{
#ifdef _OPENMP
	omp_t = OMP_LOOPS * omp_get_max_threads();
	if (omp_t < 1)
		omp_t = 1;
	self->params.max_keys_per_crypt = omp_t * MS_NUM_KEYS;
#endif

	key = mem_calloc_tiny(sizeof(*key)*PLAIN_KEY_LEN*self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	md4hash = mem_calloc_tiny(sizeof(*md4hash)*HASH_LEN*self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	crypt = mem_calloc_tiny(sizeof(*crypt)*4*self->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#if defined (MMX_COEF)
	sse_hash1 = mem_calloc_tiny(sizeof(*sse_hash1)*SHA_BUF_SIZ*4*self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	sse_crypt1 = mem_calloc_tiny(sizeof(*sse_crypt1)*20*self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	sse_crypt2 = mem_calloc_tiny(sizeof(*sse_crypt2)*20*self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	sse_crypt = mem_calloc_tiny(sizeof(*sse_crypt)*20*self->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	{
		int index;
		for (index = 0; index < self->params.max_keys_per_crypt; ++index) {
			// set the length of all hash1 SSE buffer to 64+20 * 8 bits
			// The 64 is for the ipad/opad, the 20 is for the length of the SHA1 buffer that also gets into each crypt
			// this works for SSEi
			((unsigned int *)sse_hash1)[15*MMX_COEF + (index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF] = (84<<3); // all encrypts are 64+20 bytes.
			sse_hash1[GETPOS(20,index)] = 0x80;
		}
	}
	// From this point on, we ONLY touch the first 20 bytes (* MMX_COEF) of each buffer 'block'.  If !SHA_PARA', then only the first
	// block is written to after this, if there are more that one SHA_PARA, then the start of each para block will be updated inside the inner loop.
#endif

	if (options.utf8) {
		// UTF8 may be up to three bytes per character
		self->params.plaintext_length = PLAIN_KEY_LEN - 1;
		tests[1].plaintext = "\xc3\xbc";         // German u-umlaut in UTF-8
		tests[1].ciphertext = "$DCC2$10240#joe#bdb80f2c4656a8b8591bd27d39064a54";
		tests[2].plaintext = "\xe2\x82\xac\xe2\x82\xac"; // 2 x Euro signs
		tests[2].ciphertext = "$DCC2$10240#joe#1e1e20f482ff748038e47d801d0d1bda";
	}
	if (options.iso8859_1) {
		tests[1].plaintext = "\xfc";
		tests[1].ciphertext = "$DCC2$10240#joe#bdb80f2c4656a8b8591bd27d39064a54";
		tests[2].plaintext = "\xfc\xfc";
		tests[2].ciphertext = "$DCC2$10240#admin#0839e4a07c00f18a8c65cf5b985b9e73";
	}
}

static char * ms_split(char *ciphertext, int index)
{
	static char out[MAX_CIPHERTEXT_LENGTH + 1];
	int i = 0;

	for(; ciphertext[i] && i < MAX_CIPHERTEXT_LENGTH; i++)
		out[i] = ciphertext[i];

	out[i] = 0;

	// lowercase salt as well as hash, encoding-aware
	enc_strlwr(&out[6]);

	return out;
}


static int valid(char *ciphertext, struct fmt_main *self)
{
	unsigned int i;
	unsigned int l;
	char insalt[3*22+1];
	UTF16 realsalt[23];
	int saltlen;

	if (strncmp(ciphertext, "$DCC2$", 6))
		return 0;

	l = strlen(ciphertext);
	if (l <= 32 || l > MAX_CIPHERTEXT_LENGTH)
		return 0;

	l -= 32;
	if(ciphertext[l-1]!='#')
		return 0;

	for (i = l; i < l + 32; i++)
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7F)
			return 0;

	// This is tricky: Max supported salt length is 22 characters of Unicode
	i = 6;
	while (ciphertext[i] && ciphertext[i] != '#') ++i;
	++i;
	saltlen = enc_to_utf16(realsalt, 22, (UTF8*)strnzcpy(insalt, &ciphertext[i], l-i), l-(i+1));
	if (saltlen < 0 || saltlen > 22)
		return 0;

	// iteration count must be less than 2^16. It must fit in a UTF16 (salt[1]);
	sscanf(&ciphertext[6], "%d", &i);
	if (i >= 1<<16)
		return 0;

	return 1;
}

static char *prepare(char *split_fields[10], struct fmt_main *self)
{
	char *cp;
	int i;
	if (!strncmp(split_fields[1], "$DCC2$", 6)) {
		if (valid(split_fields[1], self))
			return split_fields[1];
		// see if this is a form $DCC2$salt#hash.  If so, make it $DCC2$10240#salt#hash and retest (insert 10240# into the line).
		cp = mem_alloc(strlen(split_fields[1]) + 7);
		sprintf(cp, "$DCC2$10240#%s", &(split_fields[1][6]));
		if (valid(cp, self)) {
			char *cipher = str_alloc_copy(cp);
			MEM_FREE(cp);
			return cipher;
		}
		return split_fields[1];
	}
	if (!split_fields[0])
		return split_fields[1];
	// ONLY check, if this string split_fields[1], is ONLY a 32 byte hex string.
	for (i = 0; i < 32; i++)
		if (atoi16[ARCH_INDEX(split_fields[1][i])] == 0x7F)
			return split_fields[1];
	cp = mem_alloc(strlen(split_fields[0]) + strlen(split_fields[1]) + 14);
	sprintf (cp, "$DCC2$10240#%s#%s", split_fields[0], split_fields[1]);
	if (valid(cp, self))
	{
		char *cipher = str_alloc_copy(cp);
		MEM_FREE(cp);
		return cipher;
	}
	MEM_FREE(cp);
	return split_fields[1];
}

static void set_salt(void *salt) {
	UTF16 *p = (UTF16*)salt;
	salt_len = *p++;
	iteration_cnt = *p++;
	salt_buffer = (unsigned char*)p;
}

static void *get_salt(char *_ciphertext)
{
	unsigned char *ciphertext = (unsigned char *)_ciphertext;
	static UTF16 out[24+1];
	unsigned char input[22*3+1];
	int utf16len, md4_size;

	memset(out, 0, sizeof(out));

	ciphertext += 6;

	while (*ciphertext && *ciphertext != '#') ++ciphertext;
	++ciphertext;
	for (md4_size=0;md4_size<sizeof(input)-1;md4_size++) {
		if (ciphertext[md4_size] == '#')
			break;
		input[md4_size] = ciphertext[md4_size];
	}
	input[md4_size] = 0;

	utf16len = enc_to_utf16(&out[2], 22, input, md4_size);
	if (utf16len <= 0)
		utf16len = strlen16(&out[2]);
	out[0] = utf16len << 1;
	sscanf(&_ciphertext[6], "%d", &utf16len);
	out[1] = utf16len;
	return out;
}


static void *get_binary(char *ciphertext)
{
	static unsigned long out_[BINARY_SIZE/sizeof(unsigned long)];
	unsigned int *out = (unsigned int*)out_;
	unsigned int i = 0;
	unsigned int temp;

	for (; ciphertext[0] != '#'; ciphertext++);
	ciphertext++;
	for (; ciphertext[0] != '#'; ciphertext++);
	ciphertext++;

	for (; i < 4 ;i++)
	{
#if ARCH_LITTLE_ENDIAN
		temp  = (atoi16[ARCH_INDEX(ciphertext[i * 8 + 0])]) << 4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 1])]);
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 2])]) << 12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 3])]) << 8;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 4])]) << 20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 5])]) << 16;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 6])]) << 28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 7])]) << 24;
#else
		temp  = (atoi16[ARCH_INDEX(ciphertext[i * 8 + 6])]) << 4;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 7])]);
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 4])]) << 12;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 5])]) << 8;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 2])]) << 20;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 3])]) << 16;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 0])]) << 28;
		temp |= (atoi16[ARCH_INDEX(ciphertext[i * 8 + 1])]) << 24;
#endif
		out[i] = temp;
	}
#ifdef MMX_COEF
	alter_endianity(out, BINARY_SIZE);
#endif
	return out;
}


static int binary_hash_0(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0F;
}


static int binary_hash_1(void *binary)
{
	return ((unsigned int*)binary)[3] & 0xFF;
}


static int binary_hash_2(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFF;
}


static int binary_hash_3(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFFF;
}


static int binary_hash_4(void *binary)
{
	return ((unsigned int*)binary)[3] & 0x0FFFFF;
}


static int get_hash_0(int index)
{
	return crypt[4 * index + 3] & 0x0F;
}


static int get_hash_1(int index)
{
	return crypt[4 * index + 3] & 0xFF;
}


static int get_hash_2(int index)
{
	return crypt[4 * index + 3] & 0x0FFF;
}


static int get_hash_3(int index)
{
	return crypt[4 * index + 3] & 0x0FFFF;
}


static int get_hash_4(int index)
{
	return crypt[4 * index + 3] & 0x0FFFFF;
}

static int cmp_all(void *binary, int count)
{
	unsigned int i = 0;
	unsigned int d = ((unsigned int *)binary)[3];

	for (; i < count; i++)
		if (d == crypt[i * 4 + 3])
			return 1;

	return 0;
}


static int cmp_one(void * binary, int index)
{
	unsigned int *t = (unsigned int *)binary;
	unsigned int a = crypt[4 * index + 0];
	unsigned int b = crypt[4 * index + 1];
	unsigned int c = crypt[4 * index + 2];
	unsigned int d = crypt[4 * index + 3];

	if (d != t[3])
		return 0;

	if (c != t[2])
		return 0;

	if (b != t[1])
		return 0;

	return (a == t[0]);
}


static int cmp_exact(char *source, int index)
{
	return 1;
}


static void set_key(char *_key, int index)
{
	strnzcpy ((char*)&key[index*PLAIN_KEY_LEN], _key, PLAIN_KEY_LEN);
	new_key = 1;
}


static char *get_key(int index)
{
	return (char*)&key[index*PLAIN_KEY_LEN];
}


// Public domain hash function by DJ Bernstein (salt is a username)
static int salt_hash(void *salt)
{
	UTF16 *n = salt, i;
	unsigned char *s  = (unsigned char*)n;
	unsigned int hash = 5381;
	for (i = 0; i < (*n+2); ++i)
		hash = ((hash<<5)+hash) ^ s[i];
	return hash & (SALT_HASH_SIZE - 1);
}


#ifdef MMX_COEF
// NOTE, in the end, this block will move above the pbkdf2() function, and the #else and #endif wrapping that function will be
// uncommented. Thus, if built for SSE2 (mmx, or intrisic), we get this function. Otherwise we get teh pbkdf2() function which
// uses OpenSSL.  However to get the 'layout' right, The code here will walk through the array buffer, calling the pbkdf2
// function.
static void pbkdf2_sse2(int t)
{
	// Thread safe, t is our thread number.
	// All indexes into buffers are offset by (t * MS_NUM_KEYS * (size))
	SHA_CTX ctx1, ctx2;
	unsigned int ipad[SHA_LBLOCK], opad[SHA_LBLOCK];
	unsigned int tmp_hash[SHA_DIGEST_LENGTH/4];
	unsigned int i, j, k, *i1, *i2, *o1, *t_crypt;
	unsigned char *t_sse_crypt1, *t_sse_crypt2, *t_sse_hash1;

	memset(&ipad[4], 0x36, SHA_CBLOCK-16);
	memset(&opad[4], 0x5C, SHA_CBLOCK-16);


	// All pointers get their offset for this thread here. No further offsetting below.
	t_crypt = &crypt[t * MS_NUM_KEYS * 4];
	t_sse_crypt1 = &sse_crypt1[t * MS_NUM_KEYS * 20];
	t_sse_crypt2 = &sse_crypt2[t * MS_NUM_KEYS * 20];
	t_sse_hash1 = &sse_hash1[t * MS_NUM_KEYS * SHA_BUF_SIZ * 4];
	i1 = (unsigned int*)t_sse_crypt1;
	i2 = (unsigned int*)t_sse_crypt2;
	o1 = (unsigned int*)t_sse_hash1;

	for(k = 0; k < MS_NUM_KEYS; ++k)
	{
		for(i = 0;i < 4;i++) {
			ipad[i] = t_crypt[k*4+i]^0x36363636;
			opad[i] = t_crypt[k*4+i]^0x5C5C5C5C;
		}

		SHA1_Init(&ctx1);
		SHA1_Init(&ctx2);

		SHA1_Update(&ctx1,ipad,SHA_CBLOCK);
		SHA1_Update(&ctx2,opad,SHA_CBLOCK);

		// we memcopy from flat into MMX_COEF output buffer's (our 'temp' ctx buffer).
		// This data will NOT need to be BE swapped (it already IS BE swapped).
		i1[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))]               = ctx1.h0;
		i1[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+MMX_COEF]      = ctx1.h1;
		i1[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+(MMX_COEF<<1)] = ctx1.h2;
		i1[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+MMX_COEF*3]    = ctx1.h3;
		i1[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+(MMX_COEF<<2)] = ctx1.h4;

		i2[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))]               = ctx2.h0;
		i2[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+MMX_COEF]      = ctx2.h1;
		i2[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+(MMX_COEF<<1)] = ctx2.h2;
		i2[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+MMX_COEF*3]    = ctx2.h3;
		i2[(k/MMX_COEF)*MMX_COEF*5+(k&(MMX_COEF-1))+(MMX_COEF<<2)] = ctx2.h4;

		SHA1_Update(&ctx1,salt_buffer,salt_len);
		SHA1_Update(&ctx1,"\x0\x0\x0\x1",4);
		SHA1_Final((unsigned char*)tmp_hash,&ctx1);

		SHA1_Update(&ctx2,(unsigned char*)tmp_hash,SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)tmp_hash,&ctx2);

		// now convert this from flat into MMX_COEF buffers.
		// Also, perform the 'first' ^= into the crypt buffer.  NOTE, we are doing that in BE format
		// so we will need to 'undo' that in the end.
		o1[(k/MMX_COEF)*MMX_COEF*SHA_BUF_SIZ+(k&(MMX_COEF-1))]                = t_crypt[k*4+0] = ctx2.h0;
		o1[(k/MMX_COEF)*MMX_COEF*SHA_BUF_SIZ+(k&(MMX_COEF-1))+MMX_COEF]       = t_crypt[k*4+1] = ctx2.h1;
		o1[(k/MMX_COEF)*MMX_COEF*SHA_BUF_SIZ+(k&(MMX_COEF-1))+(MMX_COEF<<1)]  = t_crypt[k*4+2] = ctx2.h2;
		o1[(k/MMX_COEF)*MMX_COEF*SHA_BUF_SIZ+(k&(MMX_COEF-1))+MMX_COEF*3]     = t_crypt[k*4+3] = ctx2.h3;
		o1[(k/MMX_COEF)*MMX_COEF*SHA_BUF_SIZ+(k&(MMX_COEF-1))+(MMX_COEF<<2)]                   = ctx2.h4;
	}

	for(i = 1; i < iteration_cnt; i++)
	{
#if SHA1_SSE_PARA
		SSESHA1body((unsigned int*)t_sse_hash1, (unsigned int*)t_sse_hash1, (unsigned int*)t_sse_crypt1, 1);
		SSESHA1body((unsigned int*)t_sse_hash1, (unsigned int*)t_sse_hash1, (unsigned int*)t_sse_crypt2, 1);
		// only xor first 16 bytes, since that is ALL this format uses
		for (k = 0; k < MS_NUM_KEYS; k++) {
			unsigned *p = &((unsigned int*)t_sse_hash1)[(((k>>2)*SHA_BUF_SIZ)<<2) + (k&(MMX_COEF-1))];
			for(j = 0; j < 4; j++)
				t_crypt[(k<<2)+j] ^= p[(j<<(MMX_COEF>>1))];
		}
#else
		shammx_reloadinit_nosizeupdate_nofinalbyteswap(t_sse_hash1, t_sse_hash1, t_sse_crypt1);
		shammx_reloadinit_nosizeupdate_nofinalbyteswap(t_sse_hash1, t_sse_hash1, t_sse_crypt2);
		// only xor first 16 bytes, since that is ALL this format uses
		for (k = 0; k < MMX_COEF; k++) {
			for(j = 0; j < 4; j++)
				t_crypt[(k<<2)+j] ^= ((unsigned int*)t_sse_hash1)[(j<<(MMX_COEF>>1))+k];
		}
#endif
	}
}

#else
/*
 * This function is derived from IEEE Std 802.11-2004, Clause H.4.
 * The main construction is from PKCS#5 v2.0.  It is tweaked a little
 * to remove some code not needed for our SHA1-128 output.
 */
static void pbkdf2(unsigned int _key[]) // key is also 'final' digest.
{
	SHA_CTX ctx1, ctx2, tmp_ctx1, tmp_ctx2;
	unsigned char ipad[SHA_CBLOCK], opad[SHA_CBLOCK];
	unsigned int tmp_hash[SHA_DIGEST_LENGTH/4];
	unsigned i, j;
	unsigned char *key = (unsigned char*)_key;

	for(i = 0; i < 16; i++) {
		ipad[i] = key[i]^0x36;
		opad[i] = key[i]^0x5C;
	}
	memset(&ipad[16], 0x36, sizeof(ipad)-16);
	memset(&opad[16], 0x5C, sizeof(opad)-16);

	SHA1_Init(&ctx1);
	SHA1_Init(&ctx2);

	SHA1_Update(&ctx1, ipad, SHA_CBLOCK);
	SHA1_Update(&ctx2, opad, SHA_CBLOCK);

	memcpy(&tmp_ctx1, &ctx1, sizeof(SHA_CTX));
	memcpy(&tmp_ctx2, &ctx2, sizeof(SHA_CTX));

	SHA1_Update(&ctx1, salt_buffer, salt_len);
	SHA1_Update(&ctx1, "\x0\x0\x0\x1", 4);
	SHA1_Final((unsigned char*)tmp_hash,&ctx1);

	SHA1_Update(&ctx2, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
	// we have to sha1 final to a 'temp' buffer, since we can only overwrite first 16 bytes
	// of the _key buffer.  If we overwrote 20 bytes, then we would lose the first 4 bytes
	// of the next element (and overwrite end of buffer on last element).
	SHA1_Final((unsigned char*)tmp_hash, &ctx2);

	// only copy first 16 bytes, since that is ALL this format uses
	memcpy(_key, tmp_hash, 16);

	for(i = 1; i < iteration_cnt; i++)
	{
		// we only need to copy the accumulator data from the CTX, since
		// the original encryption was a full block of 64 bytes.
		memcpy(&ctx1, &tmp_ctx1, sizeof(SHA_CTX)-(64+sizeof(unsigned int)));
		SHA1_Update(&ctx1, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)tmp_hash, &ctx1);

		memcpy(&ctx2, &tmp_ctx2, sizeof(SHA_CTX)-(64+sizeof(unsigned int)));
		SHA1_Update(&ctx2, (unsigned char*)tmp_hash, SHA_DIGEST_LENGTH);
		SHA1_Final((unsigned char*)tmp_hash, &ctx2);

		// only xor first 16 bytes, since that is ALL this format uses
		for(j = 0; j < 4; j++)
			_key[j] ^= tmp_hash[j];
	}
}
#endif


static void crypt_all(int count)
{
	int i, t;
	// Note, for a format like DCC2, there is little reason to optimize anything other
	// than the pbkdf2 inner loop.  The one exception to that, is the NTLM can be done
	// and known when to be done, only when the

	// now get NTLM of the password (MD4 of unicode)
	if (new_key) {
#if MS_NUM_KEYS > 1 && defined(_OPENMP)
#pragma omp parallel for default(none) private(i) shared(count, key, md4hash)
#endif
		for (i = 0; i < count; ++i) {
			int utf16len;
			UTF16 pass_unicode[PLAINTEXT_LENGTH+1];
			MD4_CTX ctx;
			utf16len = enc_to_utf16(pass_unicode, PLAINTEXT_LENGTH, &key[PLAIN_KEY_LEN*i], strlen((char*)&key[PLAIN_KEY_LEN*i]));
			if (utf16len <= 0) {
				key[PLAIN_KEY_LEN*i-utf16len] = 0;
				if (utf16len != 0)
					utf16len = strlen16(pass_unicode);
			}
			MD4_Init(&ctx);
			MD4_Update(&ctx, pass_unicode, utf16len<<1);
			MD4_Final(&md4hash[HASH_LEN*i], &ctx);
		}
		new_key = 0;
	}

#ifdef _OPENMP
#pragma omp parallel for default(none) private(t, i) shared(omp_t, salt_buffer, salt_len, crypt, md4hash)
#endif
	for (t = 0; t < omp_t; t++)	{
		MD4_CTX ctx;
		for (i = 0; i < MS_NUM_KEYS; ++i) {
			// Get DCC1.  That is MD4( NTLM . unicode(lc username) )
			MD4_Init(&ctx);
			MD4_Update(&ctx, &md4hash[(t * MS_NUM_KEYS + i) * HASH_LEN], 16);
			MD4_Update(&ctx, salt_buffer, salt_len);
			MD4_Final((unsigned char*)&crypt[(t * MS_NUM_KEYS + i) * 4], &ctx);
			// now we have DCC1 (mscash) which is MD4 (MD4(unicode(pass)) . unicode(lc username))

#ifndef MMX_COEF
			// Non-SSE: Compute DCC2 one at a time
			pbkdf2(&crypt[(t * MS_NUM_KEYS + i) * 4]);
#endif
		}
#ifdef MMX_COEF
		// SSE: Compute DCC2 in parallel, once per thread
		pbkdf2_sse2(t);
#endif
	}
}

struct fmt_main fmt_mscash2 = {
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
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE | FMT_OMP | FMT_UNICODE | FMT_UTF8,
		tests
	}, {
		init,
		prepare,
		valid,
		ms_split,
		get_binary,
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

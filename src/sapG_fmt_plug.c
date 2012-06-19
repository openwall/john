/*
 * this is a SAP PASSCODE (CODEVN G) plugin for john the ripper.
 * tested on linux/x86 only, rest is up to you.. at least, someone did the reversing :-)
 *
 * please note: this code is in a "works for me"-state, feel free to modify/speed up/clean/whatever it...
 *
 * (c) x7d8 sap loverz, public domain, btw
 * cheers: see test-cases.
 *
 * Heavily modified by magnum 2011-2012 for performance and for SIMD, OMP and
 * encodings support. Copyright © 2011, 2012 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#include <string.h>
#include <ctype.h>

#include "arch.h"

#ifdef SHA1_SSE_PARA
#define MMX_COEF	4
#define NBKEYS	(MMX_COEF * SHA1_SSE_PARA)
#elif MMX_COEF
#define NBKEYS	MMX_COEF
#endif
#include "sse-intrinsics.h"

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"

#define FORMAT_LABEL			"sapg"
#define FORMAT_NAME			"SAP CODVN F/G (PASSCODE)"

#define ALGORITHM_NAME			SHA1_ALGORITHM_NAME

#if defined(_OPENMP) && (defined (SHA1_SSE_PARA) || !defined(MMX_COEF))
#include <omp.h>
static unsigned int omp_t = 1;
#ifdef SHA1_SSE_PARA
#define OMP_SCALE			128
#else
#define OMP_SCALE			2048
#endif
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define SALT_LENGTH			(12*3)	/* 12 characters of UTF-8 */
#define PLAINTEXT_LENGTH		(64+55-SALT_LENGTH) /* Max 2 limbs */

#define BINARY_SIZE			20
#define CIPHERTEXT_LENGTH		(SALT_LENGTH + 1 + 2*BINARY_SIZE)	/* SALT + $ + 2x20 bytes for SHA1-representation */

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&60)*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 ) //for endianity conversion
#define GETWORDPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&60)*MMX_COEF + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 )
#define GETSTARTPOS(index)		( (index&(MMX_COEF-1))*4 + (index>>(MMX_COEF>>1))*SHA_BUF_SIZ*MMX_COEF*4 )
#define GETOUTPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + (3-((i)&3)) + (index>>(MMX_COEF>>1))*20*MMX_COEF ) //for endianity conversion

#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

//this array is from disp+work (sap's worker process)
#define MAGIC_ARRAY_SIZE 160
static const unsigned char theMagicArray[MAGIC_ARRAY_SIZE]=
{0x91, 0xAC, 0x51, 0x14, 0x9F, 0x67, 0x54, 0x43, 0x24, 0xE7, 0x3B, 0xE0, 0x28, 0x74, 0x7B, 0xC2,
 0x86, 0x33, 0x13, 0xEB, 0x5A, 0x4F, 0xCB, 0x5C, 0x08, 0x0A, 0x73, 0x37, 0x0E, 0x5D, 0x1C, 0x2F,
 0x33, 0x8F, 0xE6, 0xE5, 0xF8, 0x9B, 0xAE, 0xDD, 0x16, 0xF2, 0x4B, 0x8D, 0x2C, 0xE1, 0xD4, 0xDC,
 0xB0, 0xCB, 0xDF, 0x9D, 0xD4, 0x70, 0x6D, 0x17, 0xF9, 0x4D, 0x42, 0x3F, 0x9B, 0x1B, 0x11, 0x94,
 0x9F, 0x5B, 0xC1, 0x9B, 0x06, 0x05, 0x9D, 0x03, 0x9D, 0x5E, 0x13, 0x8A, 0x1E, 0x9A, 0x6A, 0xE8,
 0xD9, 0x7C, 0x14, 0x17, 0x58, 0xC7, 0x2A, 0xF6, 0xA1, 0x99, 0x63, 0x0A, 0xD7, 0xFD, 0x70, 0xC3,
 0xF6, 0x5E, 0x74, 0x13, 0x03, 0xC9, 0x0B, 0x04, 0x26, 0x98, 0xF7, 0x26, 0x8A, 0x92, 0x93, 0x25,
 0xB0, 0xA2, 0x0D, 0x23, 0xED, 0x63, 0x79, 0x6D, 0x13, 0x32, 0xFA, 0x3C, 0x35, 0x02, 0x9A, 0xA3,
 0xB3, 0xDD, 0x8E, 0x0A, 0x24, 0xBF, 0x51, 0xC3, 0x7C, 0xCD, 0x55, 0x9F, 0x37, 0xAF, 0x94, 0x4C,
 0x29, 0x08, 0x52, 0x82, 0xB2, 0x3B, 0x4E, 0x37, 0x9F, 0x17, 0x07, 0x91, 0x11, 0x3B, 0xFD, 0xCD };

// For backwards compatibility, we must support salts padded with spaces to a field width of 40
static struct fmt_tests tests[] = {
	{"F           $646A0AD270DF651065669A45D171EDD62DFE39A1", "X"},
	{"JOHNNY                                  $7D79B478E70CAAE63C41E0824EAB644B9070D10A", "CYBERPUNK"},
	{"VAN$D15597367F24090F0A501962788E9F19B3604E73", "hauser"},
	{"ROOT$1194E38F14B9F3F8DA1B181F14DEB70E7BDCC239", "KID"},
	{"MAN$22886450D0AB90FDA7F91C4F3DD5619175B372EA", "u"},
	{"------------------------------------$463BDDCF2D2D6E07FC64C075A0802BD87A39BBA6", "-------"},
	{"SAP*                                $60A0F7E06D95BC9FB45F605BDF1F7B660E5D5D4E", "MaStEr"},
	{"DDIC$6066CD3147915331EC4C602847D27A75EB3E8F0A", "DDIC"},
	{"DoLlAR$$$---$E0180FD4542D8B6715E7D0D9EDE7E2D2E40C3D4D", "Dollar$$$---"},
	{NULL}
};

static UTF8 (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int *keyLen;

#ifdef MMX_COEF

// max intermediate crypt size is 192 bytes
// multiple key buffers for lengths > 55
#define LIMB				3
static unsigned char *saved_key[LIMB];
static unsigned char *crypt_key;
static unsigned char *interm_crypt;
static unsigned int *clean_pos;

#else

static UTF8 (*saved_key)[PLAINTEXT_LENGTH + 1];
static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE / sizeof(ARCH_WORD_32)];

#endif

static struct saltstruct {
	unsigned int l;
	unsigned char s[SALT_LENGTH];
} *cur_salt;
#define SALT_SIZE			sizeof(struct saltstruct)

static void init(struct fmt_main *pFmt)
{
	static int warned = 0;
#ifdef MMX_COEF
	int i;
#endif
	// This is needed in order NOT to upper-case german double-s
	// in UTF-8 mode.
	initUnicode(UNICODE_MS_NEW);

	if (!options.utf8 && !(options.flags & FLG_TEST_CHK) && warned++ == 0)
		fprintf(stderr, "Warning: SAP-F/G format should always be UTF-8.\nConvert your input files to UTF-8 and use --encoding=utf8\n");

#if defined (_OPENMP) && (defined(SHA1_SSE_PARA) || !defined(MMX_COEF))
	omp_t = omp_get_max_threads();
	pFmt->params.min_keys_per_crypt = omp_t * MIN_KEYS_PER_CRYPT;
	omp_t *= OMP_SCALE;
	pFmt->params.max_keys_per_crypt = omp_t * MAX_KEYS_PER_CRYPT;
#endif

	saved_plain = mem_calloc_tiny(sizeof(*saved_plain) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	keyLen = mem_calloc_tiny(sizeof(*keyLen) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
#ifdef MMX_COEF
	clean_pos = mem_calloc_tiny(sizeof(*clean_pos) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	for(i = 0; i < LIMB; i++)
		saved_key[i] = mem_calloc_tiny(SHA_BUF_SIZ*4 * pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	interm_crypt = mem_calloc_tiny(20 * pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_tiny(20 * pFmt->params.max_keys_per_crypt, MEM_ALIGN_SIMD);
#else
	crypt_key = mem_calloc_tiny(sizeof(*crypt_key) * pFmt->params.max_keys_per_crypt, MEM_ALIGN_WORD);
	saved_key = saved_plain;
#endif
}

static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i;
	char *p;

	if (!ciphertext) return 0;

	p = strrchr(ciphertext, '$');
	if (!p) return 0;

	if (strlen(&p[1]) != BINARY_SIZE * 2) return 0;

	p++;
	for (i = 0; i < BINARY_SIZE * 2; i++)
		if (!(((p[i]>='A' && p[i]<='F')) ||
			((p[i]>='a' && p[i]<='f')) ||
			((p[i]>='0' && p[i]<='9')) ))
			return 0;
	return 1;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

// Salt is already trimmed and uppercased in split()
static void *get_salt(char *ciphertext)
{
	char *p;
	static struct saltstruct out;

	p = strrchr(ciphertext, '$');
	out.l = (int)(p - ciphertext);

	memset(out.s, 0, sizeof(out.s));
	memcpy(out.s, ciphertext, out.l);

	return &out;
}

static void set_key(char *key, int index)
{
	memcpy((char*)saved_plain[index], key, PLAINTEXT_LENGTH);
	keyLen[index] = -1;
}

static char *get_key(int index) {
	return (char*)saved_plain[index];
}

static int cmp_all(void *binary, int count) {
#ifdef MMX_COEF
	unsigned int x,y=0;

#ifdef SHA1_SSE_PARA
#ifdef _OPENMP
	for(;y<SHA1_SSE_PARA*omp_t;y++)
#else
	for(;y<SHA1_SSE_PARA;y++)
#endif
#endif
	for(x=0;x<MMX_COEF;x++)
	{
		if( ((unsigned int*)binary)[0] == ((unsigned int*)crypt_key)[x+y*MMX_COEF*5] )
			return 1;
	}
	return 0;
#else
	unsigned int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE))
			return 1;
	return 0;
#endif
}

static int cmp_exact(char *source, int index){
	return 1;
}

static int cmp_one(void *binary, int index)
{
#ifdef MMX_COEF
	unsigned int x,y;
	x = index&(MMX_COEF-1);
	y = index>>(MMX_COEF>>1);

	if( (((unsigned int*)binary)[0] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5])   |
	    (((unsigned int*)binary)[1] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+MMX_COEF]) |
	    (((unsigned int*)binary)[2] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+2*MMX_COEF]) |
	    (((unsigned int*)binary)[3] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+3*MMX_COEF])|
	    (((unsigned int*)binary)[4] != ((unsigned int*)crypt_key)[x+y*MMX_COEF*5+4*MMX_COEF]) )
		return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

/*
 * calculate the length of data that has to be hashed from the magic array. pass the first hash result in here.
 * this is part of the walld0rf-magic
 * The return value will always be between 32 and 82, inclusive
 */
#if MMX_COEF
static inline unsigned int extractLengthOfMagicArray(unsigned const char *pbHashArray, unsigned int index)
#else
static inline unsigned int extractLengthOfMagicArray(unsigned const char *pbHashArray)
#endif
{
	unsigned int modSum = 0;

#if MMX_COEF
	unsigned const char *p = &pbHashArray[GETOUTPOS(3, index)];
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	p += 4*(MMX_COEF - 1);
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	p += 4*(MMX_COEF - 1) + 2;
	modSum += *p++ % 6;
	modSum += *p % 6;
#else
	unsigned int i;

	for (i=0; i<=9; i++)
		modSum += pbHashArray[i] % 6;
#endif
	return modSum + 0x20; //0x20 is hardcoded...
}

/*
 * Calculate the offset into the magic array. pass the first hash result in here
 * part of the walld0rf-magic
 * The return value will always be between 0 and 70, inclusive
 */
#if MMX_COEF
static inline unsigned int extractOffsetToMagicArray(unsigned const char *pbHashArray, unsigned int index)
#else
static inline unsigned int extractOffsetToMagicArray(unsigned const char *pbHashArray)
#endif
{
	unsigned int modSum = 0;

#if MMX_COEF
	unsigned const int *p = (unsigned int*)&pbHashArray[GETOUTPOS(11, index)];
	unsigned int temp;

	temp = *p & 0x0707;
	modSum += (temp >> 8) + (unsigned char)temp;
	p += MMX_COEF;
	temp = *p & 0x07070707;
	modSum += (temp >> 24) + (unsigned char)(temp >> 16) +
		(unsigned char)(temp >> 8) + (unsigned char)temp;
	p += MMX_COEF;
	temp = *p & 0x07070707;
	modSum += (temp >> 24) + (unsigned char)(temp >> 16) +
		(unsigned char)(temp >> 8) + (unsigned char)temp;
#else
	unsigned int i;

	for (i = 19; i >= 10; i--)
		modSum += pbHashArray[i] % 8;
#endif
	return modSum;
}

#if MMX_COEF
static inline void crypt_done(unsigned const int *source, unsigned int *dest, int index)
{
	unsigned int i;
	unsigned const int *s = &source[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*5*MMX_COEF];
	unsigned int *d = &dest[(index&(MMX_COEF-1)) + (index>>(MMX_COEF>>1))*5*MMX_COEF];

	for (i = 0; i < 5; i++) {
		*d = *s;
		s += MMX_COEF;
		d += MMX_COEF;
	}
}
#endif

static void crypt_all(int count)
{
#if MMX_COEF

#if defined(_OPENMP) && defined(SHA1_SSE_PARA)
	int t;
#pragma omp parallel for
	for (t = 0; t < omp_t; t++)
#define ti (t*NBKEYS+index)
#else
#define t  0
#define ti index
#endif
	{
		unsigned int index, i, longest;
		int len;
		unsigned int crypt_len[NBKEYS];

		longest = 0;

		for (index = 0; index < NBKEYS; index++) {

			// Store key into vector key buffer
			if ((len = keyLen[ti]) < 0) {
				ARCH_WORD_32 *keybuf_word = (ARCH_WORD_32*)&saved_key[0][GETSTARTPOS(ti)];
				const ARCH_WORD_32 *wkey = (ARCH_WORD_32*)saved_plain[ti];
				ARCH_WORD_32 temp;

				len = 0;
				while(((unsigned char)(temp = *wkey++))) {
					if (!(temp & 0xff00))
					{
						*keybuf_word = JOHNSWAP(temp & 0xff);
						keybuf_word += MMX_COEF;
						len++;
						break;
					}
					if (!(temp & 0xff0000))
					{
						*keybuf_word = JOHNSWAP(temp & 0xffff);
						keybuf_word += MMX_COEF;
						len+=2;
						break;
					}
					*keybuf_word = JOHNSWAP(temp);
					if (!(temp & 0xff000000))
					{
						keybuf_word += MMX_COEF;
						len+=3;
						break;
					}
					len += 4;
					if (len & 63)
						keybuf_word += MMX_COEF;
					else
						keybuf_word = (ARCH_WORD_32*)&saved_key[len>>8][GETSTARTPOS(ti)];
				}

				// Back-out of trailing spaces
				while( saved_plain[ti][len - 1] == ' ' )
				{
					saved_plain[ti][--len] = 0;
					if (len == 0) break;
				}
				keyLen[ti] = len;
			}

			// 1.	we need to SHA1 the password and username
			for (i = 0; i < cur_salt->l; i++)
				saved_key[(len+i)>>6][GETPOS((len + i), ti)] = cur_salt->s[i];
			len += i;

			saved_key[len>>6][GETPOS(len, ti)] = 0x80;

			// Clean rest of this buffer
			i = len;
			while (++i & 3)
				saved_key[i>>6][GETPOS(i, ti)] = 0;
			for (; i < (((len+8)>>6)+1)*64; i += 4)
				*(ARCH_WORD_32*)&saved_key[i>>6][GETWORDPOS(i, ti)] = 0;

			// This should do good but Valgrind insists it's a waste
			//if (clean_pos[ti] < i)
			//	clean_pos[ti] = len + 1;

			if (len > longest)
				longest = len;
			((unsigned int*)saved_key[(len+8)>>6])[15*MMX_COEF + (ti&3) + (ti>>2)*SHA_BUF_SIZ*MMX_COEF] = len << 3;
			crypt_len[index] = len;
		}

#if SHA1_SSE_PARA
		SSESHA1body(&saved_key[0][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&crypt_key[t*20*NBKEYS], NULL, 0);
#else
		shammx_nosizeupdate_nofinalbyteswap(crypt_key, saved_key[0], 1);
#endif

		// Do another limb if needed
		if (longest > 55) {
			memcpy(&interm_crypt[t*20*NBKEYS], &crypt_key[t*20*NBKEYS], 20*NBKEYS);
#if SHA1_SSE_PARA
			SSESHA1body(&saved_key[1][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], 0);
#else
			shammx_reloadinit_nosizeupdate_nofinalbyteswap(interm_crypt, saved_key[1], interm_crypt);
#endif
			// Copy the new output
			for (index = 0; index < NBKEYS; index++)
				if (crypt_len[index] > 55)
					crypt_done((unsigned int*)interm_crypt, (unsigned int*)crypt_key, ti);
		}

		longest = 0;

		for (index = 0; index < NBKEYS; index++) {
			unsigned int offsetMagicArray;
			unsigned int lengthIntoMagicArray;
			const unsigned char *p;

			// If final crypt ends up to be 56-61 bytes (or so), this must be clean
			((unsigned int*)saved_key[0])[15*MMX_COEF + (ti&3) + (ti>>2)*SHA_BUF_SIZ*MMX_COEF] = 0;
			((unsigned int*)saved_key[1])[15*MMX_COEF + (ti&3) + (ti>>2)*SHA_BUF_SIZ*MMX_COEF] = 0;

			len = keyLen[ti];
			lengthIntoMagicArray = extractLengthOfMagicArray(crypt_key, ti);
			offsetMagicArray = extractOffsetToMagicArray(crypt_key, ti);

			// 2.	now, hash again --> sha1($password+$partOfMagicArray+$username) --> this is CODVNG passcode...
			i = len - 1;
			p = &theMagicArray[offsetMagicArray];
			// Copy a char at a time until aligned (at destination)...
			while (++i & 3)
				saved_key[i>>6][GETPOS(i, ti)] = *p++;
			// ...then a word at a time. This is a good boost, we are copying between 32 and 82 bytes here.
			for (;i < lengthIntoMagicArray + len; i += 4, p += 4)
				*(ARCH_WORD_32*)&saved_key[i>>6][GETWORDPOS(i, ti)] = JOHNSWAP(*(ARCH_WORD_32*)p);

			// Now, the salt. This is typically too short for the stunt above.
			for (i = 0; i < cur_salt->l; i++)
				saved_key[(len+lengthIntoMagicArray+i)>>6][GETPOS((len + lengthIntoMagicArray + i), ti)] = cur_salt->s[i];
			len += lengthIntoMagicArray + cur_salt->l;
			saved_key[len>>6][GETPOS(len, ti)] = 0x80;
			crypt_len[index] = len;

			// Clean the rest of this buffer as needed
			i = len;
			while (++i & 3)
				saved_key[i>>6][GETPOS(i, ti)] = 0;
			for (; i < clean_pos[ti]; i += 4)
				*(ARCH_WORD_32*)&saved_key[i>>6][GETWORDPOS(i, ti)] = 0;

			clean_pos[ti] = len + 1;
			if (len > longest)
				longest = len;

			((unsigned int*)saved_key[(len+8)>>6])[15*MMX_COEF + (ti&3) + (ti>>2)*SHA_BUF_SIZ*MMX_COEF] = len << 3;
		}

#if SHA1_SSE_PARA
		SSESHA1body(&saved_key[0][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], NULL, 0);
#else
		shammx_nosizeupdate_nofinalbyteswap(interm_crypt, saved_key[0], 1);
#endif

		// Typically, no or very few crypts are done at this point so this is faster than to memcpy the lot
		for (index = 0; index < NBKEYS; index++)
			if (crypt_len[index] < 56)
				crypt_done((unsigned int*)interm_crypt, (unsigned int*)crypt_key, ti);

		// Do another and possibly a third limb
		for (i = 1; i < (((longest + 8) >> 6) + 1); i++) {
#if SHA1_SSE_PARA
			SSESHA1body(&saved_key[i][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], 0);
#else
			shammx_reloadinit_nosizeupdate_nofinalbyteswap(interm_crypt, saved_key[i], interm_crypt);
#endif
			// Copy any output that is done now
			for (index = 0; index < NBKEYS; index++)
				if (((crypt_len[index] + 8) >> 6) == i)
					crypt_done((unsigned int*)interm_crypt, (unsigned int*)crypt_key, ti);
		}
	}
#undef t
#undef ti

#else

#ifdef _OPENMP
	int index;
#pragma omp parallel for
	for (index = 0; index < count; index++)
#else
#define index 0
#endif
	{
		unsigned int offsetMagicArray, lengthIntoMagicArray;
		unsigned char temp_key[BINARY_SIZE];
		unsigned char tempVar[PLAINTEXT_LENGTH + MAGIC_ARRAY_SIZE + SALT_LENGTH]; //max size...
		SHA_CTX ctx;

		if (keyLen[index] < 0) {
			keyLen[index] = strlen((char*)saved_key[index]);

			// Back-out of trailing spaces
			while (saved_key[index][keyLen[index] - 1] == ' ') {
				saved_key[index][--keyLen[index]] = 0;
				if (keyLen[index] == 0) break;
			}
		}

		//1.	we need to SHA1 the password and username
		memcpy(tempVar, saved_key[index], keyLen[index]);  //first: the password
		memcpy(tempVar + keyLen[index], cur_salt->s, cur_salt->l); //second: the salt(username)

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, tempVar, keyLen[index] + cur_salt->l);
		SHA1_Final((unsigned char*)temp_key, &ctx);

		lengthIntoMagicArray = extractLengthOfMagicArray(temp_key);
		offsetMagicArray = extractOffsetToMagicArray(temp_key);

		//2.     now, hash again --> sha1($password+$partOfMagicArray+$username) --> this is CODVNG passcode...
		memcpy(tempVar + keyLen[index], &theMagicArray[offsetMagicArray], lengthIntoMagicArray);
		memcpy(tempVar + keyLen[index] + lengthIntoMagicArray, cur_salt->s, cur_salt->l);

		SHA1_Init(&ctx);
		SHA1_Update(&ctx, tempVar, keyLen[index] + lengthIntoMagicArray + cur_salt->l);
		SHA1_Final((unsigned char*)crypt_key[index], &ctx);
	}
#undef index

#endif
}

static void *binary(char *ciphertext)
{
	static int outbuf[BINARY_SIZE / sizeof(int)];
	char *realcipher = (char*)outbuf;
	int i;
	char* newCiphertextPointer;

	newCiphertextPointer = strrchr(ciphertext, '$') + 1;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(newCiphertextPointer[i*2])]*16 + atoi16[ARCH_INDEX(newCiphertextPointer[i*2+1])];
	}
#ifdef MMX_COEF
	alter_endianity((unsigned char*)realcipher, BINARY_SIZE);
#endif
	return (void*)realcipher;
}

static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffffff; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff; }

#ifdef MMX_COEF
#define KEY_OFF ((index/MMX_COEF)*MMX_COEF*5+(index&(MMX_COEF-1)))
static int get_hash_0(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0xf; }
static int get_hash_1(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0xff; }
static int get_hash_2(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0xfff; }
static int get_hash_3(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0xffff; }
static int get_hash_4(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0xfffff; }
static int get_hash_5(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0xffffff; }
static int get_hash_6(int index) { return ((ARCH_WORD_32*)crypt_key)[KEY_OFF] & 0x7ffffff; }
#else
static int get_hash_0(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xf; }
static int get_hash_1(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xff; }
static int get_hash_2(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xfff; }
static int get_hash_3(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xffff; }
static int get_hash_4(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xfffff; }
static int get_hash_5(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0xffffff; }
static int get_hash_6(int index) { return *(ARCH_WORD_32*)crypt_key[index] & 0x7ffffff; }
#endif

// Here, we remove any salt padding, trim it to 36 bytes and upper-case it
static char *split(char *ciphertext, int index)
{
	static char out[CIPHERTEXT_LENGTH + 1];
	char *p;
	int i;

	p = strrchr(ciphertext, '$');

	i = (int)(p - ciphertext) - 1;
	while (ciphertext[i] == ' ' || i >= SALT_LENGTH)
		i--;
	i++;

	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, i);
	strnzcpy(&out[i], p, CIPHERTEXT_LENGTH + 1 - i);

	enc_strupper(out); // upper-case salt (username) + hash

	return out;
}

// Public domain hash function by DJ Bernstein
static int salt_hash(void *salt)
{
	struct saltstruct *s = (struct saltstruct*)salt;
	unsigned int hash = 5381;
	unsigned int i;

	for (i = 0; i < s->l; i++)
		hash = ((hash << 5) + hash) ^ s->s[i];

	return hash & (SALT_HASH_SIZE - 1);
}

struct fmt_main fmt_sapG = {
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
#if !defined(MMX_COEF) || defined(SHA1_SSE_PARA)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_SPLIT_UNIFIES_CASE,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		split,
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

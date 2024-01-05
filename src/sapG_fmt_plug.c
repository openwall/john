/*
 * This is a SAP PASSCODE (CODEVN G) plugin for JtR.
 *
 * Tested on linux/x86 only, rest is up to you... at least, someone did the reversing :-)
 *
 * Please note: this code is in a "works for me"-state, feel free to modify/speed up/clean/whatever it...
 *
 * (c) x7d8 sap loverz, public domain, btw
 * cheers: see test-cases.
 *
 * Heavily modified by magnum 2011-2012 for performance and for SIMD, OMP and
 * encodings support. Copyright (c) 2011, 2012 magnum, and it is hereby released
 * to the general public under the following terms:  Redistribution and use in
 * source and binary forms, with or without modification, are permitted.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sapG;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sapG);
#else

#include <string.h>
#include <ctype.h>

#if defined(_OPENMP)
#include <omp.h>
#endif

#include "arch.h"
#include "simd-intrinsics.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "sha.h"
#include "options.h"
#include "unicode.h"
#include "johnswap.h"
#include "config.h"

#define FORMAT_LABEL            "sapg"
#define FORMAT_NAME             "SAP CODVN F/G (PASSCODE)"
#define ALGORITHM_NAME          "SHA1 " SHA1_ALGORITHM_NAME
#define BENCHMARK_COMMENT        ""
#define BENCHMARK_LENGTH        7
#define SALT_FIELD_LENGTH       40
#define USER_NAME_LENGTH        12 /* max. length of user name in characters */
#define SALT_LENGTH             (USER_NAME_LENGTH * 4)    /* bytes of UTF-8 */
#define PLAINTEXT_LENGTH        40 /* Characters */
#define UTF8_PLAINTEXT_LENGTH   MIN(125, PLAINTEXT_LENGTH * 3) /* bytes */
#define BINARY_SIZE             20
#define BINARY_ALIGN            4
#define SALT_SIZE               sizeof(struct saltstruct)
#define SALT_ALIGN              4
#define CIPHERTEXT_LENGTH       (SALT_LENGTH + 1 + 2*BINARY_SIZE)    /* SALT + $ + 2x20 bytes for SHA1-representation */

#ifdef SIMD_COEF_32
#define NBKEYS                  (SIMD_COEF_32 * SIMD_PARA_SHA1)
#define GETWORDPOS(i, index)    ( (index&(SIMD_COEF_32-1))*4 + ((i)&60)*SIMD_COEF_32 + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#define GETSTARTPOS(index)      ( (index&(SIMD_COEF_32-1))*4 +                         (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 )
#define GETOUTSTARTPOS(index)   ( (index&(SIMD_COEF_32-1))*4 +                         (unsigned int)index/SIMD_COEF_32*20*SIMD_COEF_32 )
#if ARCH_LITTLE_ENDIAN
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&60)*SIMD_COEF_32 +             (3-((i)&3)) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 ) //for endianity conversion
#else
#define GETPOS(i, index)        ( (index&(SIMD_COEF_32-1))*4 + ((i)&60)*SIMD_COEF_32 +             ((i)&3) + (unsigned int)index/SIMD_COEF_32*64*SIMD_COEF_32 ) //for endianity conversion
#endif
#define MIN_KEYS_PER_CRYPT      NBKEYS
// max keys increased to allow sorting based on limb counts
#define MAX_KEYS_PER_CRYPT      (NBKEYS * 64)
#else
#define MIN_KEYS_PER_CRYPT      1
#define MAX_KEYS_PER_CRYPT      32
#endif

#ifndef OMP_SCALE
#if defined (SIMD_COEF_32)
#define OMP_SCALE               4 // Tuned w/ MKPC for core i7
#else
#define OMP_SCALE               16
#endif
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
	{"DDIC$6066CD3147915331EC4C602847D27A75EB3E8F0A", "DDIC"},
	/*
	 * invalid IRL because password is too short (would work during login,
	 * but not during password change). We use these tests anyway because
	 * they help verifying key buffer cleaning:
	 */
	{"F           $646A0AD270DF651065669A45D171EDD62DFE39A1", "X"},
	{"JOHNNY                                  $7D79B478E70CAAE63C41E0824EAB644B9070D10A", "CYBERPUNK"},
	{"VAN$D15597367F24090F0A501962788E9F19B3604E73", "hauser"},
	{"ROOT$1194E38F14B9F3F8DA1B181F14DEB70E7BDCC239", "KID"},
	// invalid, because password is too short (would work during login, but not during password change):
	{"MAN$22886450D0AB90FDA7F91C4F3DD5619175B372EA", "u"},
	// SAP user name consisting of 12 consecutive EURO characters:
	{"\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac"
	 "\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac\xe2\x82\xac"
	 "$B20D15C088481780CD44FCF2003AAAFBD9710C7C", "--+----"},
	{"SAP*                                $60A0F7E06D95BC9FB45F605BDF1F7B660E5D5D4E", "MaStEr"},
	{"DOLLAR$$$---$E0180FD4542D8B6715E7D0D9EDE7E2D2E40C3D4D", "Dollar$$$---"},
	{NULL}
};

static UTF8 (*saved_plain)[UTF8_PLAINTEXT_LENGTH + 1];
static int *keyLen;
static int max_keys;

/*
 * If john.conf option 'SAPhalfHash' is true, we support 'half hashes' from
 * the RFC_READ table. This means second half of the hash are zeros.
 */
static int half_hashes;

#ifdef SIMD_COEF_32

// max intermediate crypt size is 256 bytes
// multiple key buffers for lengths > 55
#define LIMB	5
static unsigned char *saved_key[LIMB];
static unsigned char *crypt_key;
static unsigned char *interm_crypt;
static unsigned int *clean_pos;

#else

static UTF8 (*saved_key)[UTF8_PLAINTEXT_LENGTH + 1];
static uint32_t (*crypt_key)[BINARY_SIZE / sizeof(uint32_t)];

#endif

static struct saltstruct {
	unsigned int l;
	unsigned char s[SALT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
#ifdef SIMD_COEF_32
	int i;
#endif

	half_hashes = cfg_get_bool(SECTION_OPTIONS, NULL, "SAPhalfHashes", 0);

	// This is needed in order NOT to upper-case german double-s
	// in UTF-8 mode.
	initUnicode(UNICODE_MS_NEW);

	// Max 40 characters or 125 bytes of UTF-8, We actually do not truncate
	// multibyte input at 40 characters later because it's too expensive.
	if (options.target_enc == UTF_8)
		self->params.plaintext_length = UTF8_PLAINTEXT_LENGTH;

	omp_autotune(self, OMP_SCALE);

	max_keys = self->params.max_keys_per_crypt;
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain));
	keyLen = mem_calloc(self->params.max_keys_per_crypt, sizeof(*keyLen));
#ifdef SIMD_COEF_32
	clean_pos = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*clean_pos));
	for (i = 0; i < LIMB; i++)
		saved_key[i] = mem_calloc_align(self->params.max_keys_per_crypt,
		                                SHA_BUF_SIZ * 4,
		                                MEM_ALIGN_SIMD);
	interm_crypt = mem_calloc_align(self->params.max_keys_per_crypt,
	                                20, MEM_ALIGN_SIMD);
	crypt_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                             20, MEM_ALIGN_SIMD);
#else
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
	saved_key = saved_plain;
#endif
}

static void done(void)
{
#ifdef SIMD_COEF_32
	int i;
#endif
	MEM_FREE(crypt_key);
#ifdef SIMD_COEF_32
	MEM_FREE(interm_crypt);
	for (i = 0; i < LIMB; i++)
		MEM_FREE(saved_key[i]);
	MEM_FREE(clean_pos);
#endif
	MEM_FREE(keyLen);
	MEM_FREE(saved_plain);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i, j;
	char *p;

	if (!ciphertext) return 0;
	p = strrchr(ciphertext, '$');
	if (!p) return 0;

	if (p - ciphertext > SALT_FIELD_LENGTH) return 0;
	if (strlen(&p[1]) != BINARY_SIZE * 2) return 0;

	j = 0;
	for (i = 0; i < p - ciphertext; i++) {
		// even those lower case non-ascii characters with a
		// corresponding upper case character could be rejected
		if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z')
			return 0;
		else if (ciphertext[i] & 0x80)
			j++;

		// Reject if user name is longer than 12 characters.
		// This is not accurate, but close enough.
		// To be exact, I'd need to keep j unchanged for
		// the first byte of each character, instead of
		// incrementing j for every byte >= 0x80.
		if (i >= USER_NAME_LENGTH + j && ciphertext[i] != ' ')
			return 0;
	}
	// SAP user name cannot start with ! or ?
	if (ciphertext[0] == '!' || ciphertext[0] == '?') return 0;
	// the user name must not simply be spaces, or empty
	for (i = 0; i < p - ciphertext; ++i) {
		if (ciphertext[i] == ' ')
			continue;
		break;
	}
	if (ciphertext[i] == '$') return 0;

	p++;

	// SAP and sap2john.pl always use upper case A-F for hashes,
	// so don't allow a-f
	for (i = 0; i < BINARY_SIZE * 2; i++)
		if (!(((p[i]>='0' && p[i]<='9')) ||
		      ((p[i]>='A' && p[i]<='F')) ))
			return 0;

	return 1;
}

static void set_salt(void *salt)
{
	cur_salt = salt;
}

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

static void clear_keys(void)
{
	memset(keyLen, 0, sizeof(*keyLen) * max_keys);
}

static void set_key(char *key, int index)
{
	strnzcpy((char*)saved_plain[index], key, sizeof(*saved_plain));
	keyLen[index] = -1;
}

static char *get_key(int index) {
	return (char*)saved_plain[index];
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x, y;

	for (y = 0; y < max_keys; y += SIMD_COEF_32) {
		for (x = 0; x < SIMD_COEF_32; x++) {
			if ( ((unsigned int*)binary)[0] == ((unsigned int*)crypt_key)[x+y*5] )
				return 1;
		}
	}
	return 0;
#else
	unsigned int index;
	for (index = 0; index < count; index++)
		if (!memcmp(binary, crypt_key[index], BINARY_SIZE / 2))
			return 1;
	return 0;
#endif
}

/*
 * We support 'half hashes' from the RFC_READ table. This means second half
 * of the hash are zeros.
 */
static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	unsigned int x,y;
	x = index&(SIMD_COEF_32-1);
	y = (unsigned int)index/SIMD_COEF_32;

	if ( (((unsigned int*)binary)[0] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5])   |
	     (((unsigned int*)binary)[1] != ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+SIMD_COEF_32]))
		return 0;
	if ((((unsigned int*)binary)[2] == ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+2*SIMD_COEF_32]) &&
	    (((unsigned int*)binary)[3] == ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+3*SIMD_COEF_32]) &&
		 (((unsigned int*)binary)[4] == ((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+4*SIMD_COEF_32]) )
		return 1;
	if (half_hashes &&
	    ((((unsigned int*)binary)[2] >> 16) == (((unsigned int*)crypt_key)[x+y*SIMD_COEF_32*5+2*SIMD_COEF_32] >> 16)) &&
	    ((((unsigned int*)binary)[2] & 0xffff) == 0) &&
	    (((unsigned int*)binary)[3] == 0) && (((unsigned int*)binary)[4] == 0))
		return 1;
	return 0;
#else
	const char zeros[BINARY_SIZE / 2] = { 0 };

	if (half_hashes)
		return (!memcmp(binary, crypt_key[index], BINARY_SIZE) ||
		        (!memcmp(binary, crypt_key[index], BINARY_SIZE / 2) &&
		         !memcmp(((unsigned char*)binary) + BINARY_SIZE / 2, zeros, BINARY_SIZE / 2)));
	else
		return (!memcmp(binary, crypt_key[index], BINARY_SIZE));
#endif
}

static int cmp_exact(char *source, int index)
{
	return 1;
}

/*
 * calculate the length of data that has to be hashed from the magic array. pass the first hash result in here.
 * this is part of the walld0rf-magic
 * The return value will always be between 32 and 82, inclusive
 */
#if SIMD_COEF_32
inline static unsigned int extractLengthOfMagicArray(unsigned const char *pbHashArray, unsigned int index)
#else
inline static unsigned int extractLengthOfMagicArray(unsigned const char *pbHashArray)
#endif
{
	unsigned int modSum = 0;

#if SIMD_COEF_32
	unsigned const char *p = &pbHashArray[GETOUTSTARTPOS(index)]; // [(index/SIMD_COEF_32)*20*SIMD_COEF_32+(index%SIMD_COEF_32)*4]
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	p += 4*(SIMD_COEF_32 - 1);
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	modSum += *p++ % 6;
	p += 4*(SIMD_COEF_32 - 1);
#if ARCH_LITTLE_ENDIAN
	p += 2;
#endif
	modSum += *p++ % 6;
	modSum += *p % 6;
#else
	unsigned int i;

	for (i = 0; i < 10; i++)
		modSum += pbHashArray[i] % 6;
#endif
	return modSum + 0x20; //0x20 is hardcoded...
}

/*
 * Calculate the offset into the magic array. pass the first hash result in here
 * part of the walld0rf-magic
 * The return value will always be between 0 and 70, inclusive
 */
#if SIMD_COEF_32
inline static unsigned int extractOffsetToMagicArray(unsigned const char *pbHashArray, unsigned int index)
#else
inline static unsigned int extractOffsetToMagicArray(unsigned const char *pbHashArray)
#endif
{
	unsigned int modSum = 0;

#if SIMD_COEF_32
	unsigned const char *p = &pbHashArray[GETOUTSTARTPOS(index)]; // [(index/SIMD_COEF_32)*20*SIMD_COEF_32+(index%SIMD_COEF_32)*4]
	p += 4*(SIMD_COEF_32)*2;
#if !ARCH_LITTLE_ENDIAN
	p += 2;
#endif
	modSum += *p++ % 8;
	modSum += *p++ % 8;
#if ARCH_LITTLE_ENDIAN
	p += 2;
#endif
	p += 4*(SIMD_COEF_32 - 1);
	modSum += *p++ % 8;
	modSum += *p++ % 8;
	modSum += *p++ % 8;
	modSum += *p++ % 8;
	p += 4*(SIMD_COEF_32 - 1);
	modSum += *p++ % 8;
	modSum += *p++ % 8;
	modSum += *p++ % 8;
	modSum += *p % 8;
#else
	unsigned int i;

	for (i = 10; i < 20; i++)
		modSum += pbHashArray[i] % 8;
#endif
	return modSum;
}

#if SIMD_COEF_32
inline static void crypt_done(unsigned const int *source, unsigned int *dest, int index)
{
	unsigned int i;
	unsigned const int *s = &source[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32];
	unsigned int *d = &dest[(index&(SIMD_COEF_32-1)) + (unsigned int)index/SIMD_COEF_32*5*SIMD_COEF_32];

	for (i = 0; i < 5; i++) {
		*d = *s;
		s += SIMD_COEF_32;
		d += SIMD_COEF_32;
	}
}
#endif

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#if SIMD_COEF_32
#define ti (t*NBKEYS+index)

	int t;
#if defined(_OPENMP)
#pragma omp parallel for
#endif
	for (t = 0; t < (count-1)/(NBKEYS)+1; t++) {
		unsigned int index, i, longest;
		int len;
		unsigned int crypt_len[NBKEYS];

		longest = 0;

		for (index = 0; index < NBKEYS; index++) {

			// Store key into vector key buffer
			if ((len = keyLen[ti]) < 0) {
				uint32_t *keybuf_word = (uint32_t*)&saved_key[0][GETSTARTPOS(ti)];
#if ARCH_ALLOWS_UNALIGNED
				const uint32_t *wkey = (uint32_t*)saved_plain[ti];
#else
				char buf_aligned[UTF8_PLAINTEXT_LENGTH + 1] JTR_ALIGN(4);
				char *key = (char*)saved_plain[ti];
				const uint32_t *wkey = is_aligned(key, 4) ?
						(uint32_t*)key : (uint32_t*)strcpy(buf_aligned, key);
#endif
				uint32_t temp;

				len = 0;
#if ARCH_LITTLE_ENDIAN
				while(((unsigned char)(temp = *wkey++))) {
					if (!(temp & 0xff00))
					{
						*keybuf_word = JOHNSWAP(temp & 0xff);
						len++;
						break;
					}
					if (!(temp & 0xff0000))
					{
						*keybuf_word = JOHNSWAP(temp & 0xffff);
						len+=2;
						break;
					}
					*keybuf_word = JOHNSWAP(temp);
					if (!(temp & 0xff000000))
					{
						len+=3;
						break;
					}
#else
				while((temp = *wkey++) & 0xff000000) {
					if (!(temp & 0xff0000))
					{
						*keybuf_word = (temp & 0xff000000) | (0x80 << 16);
						len++;
						break;
					}
					if (!(temp & 0xff00))
					{
						*keybuf_word = (temp & 0xffff0000) | (0x80 << 8);
						len+=2;
						break;
					}
					*keybuf_word = temp;
					if (!(temp & 0xff))
					{
						*keybuf_word = temp | 0x80U;
						len+=3;
						break;
					}
#endif
					len += 4;
					if (len & 63)
						keybuf_word += SIMD_COEF_32;
					else
						keybuf_word = (uint32_t*)&saved_key[len>>6][GETSTARTPOS(ti)];
				}

				// Back-out of trailing spaces
				while(len && saved_plain[ti][len - 1] == ' ')
					saved_plain[ti][--len] = 0;
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
				*(uint32_t*)&saved_key[i>>6][GETWORDPOS(i, ti)] = 0;

			// This should do good but Valgrind insists it's a waste
			//if (clean_pos[ti] < i)
			//	clean_pos[ti] = len + 1;

			if (len > longest)
				longest = len;
			((unsigned int*)saved_key[(len+8)>>6])[15*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + ti/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = len << 3;
			crypt_len[index] = len;
		}

		SIMDSHA1body(&saved_key[0][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&crypt_key[t*20*NBKEYS], NULL, SSEi_MIXED_IN);

		// Do another and possibly a third limb
		memcpy(&interm_crypt[t*20*NBKEYS], &crypt_key[t*20*NBKEYS], 20*NBKEYS);
		for (i = 1; i < (((longest + 8) >> 6) + 1); i++) {
			SIMDSHA1body(&saved_key[i][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], SSEi_MIXED_IN|SSEi_RELOAD);
			// Copy any output that is done now
			for (index = 0; index < NBKEYS; index++)
				if (((crypt_len[index] + 8) >> 6) == i)
					crypt_done((unsigned int*)interm_crypt, (unsigned int*)crypt_key, ti);
		}

		longest = 0;

		for (index = 0; index < NBKEYS; index++) {
			unsigned int offsetMagicArray;
			unsigned int lengthIntoMagicArray;
			const unsigned char *p;
			int i;

			// If final crypt ends up to be 56-61 bytes (or so), this must be clean
			for (i = 0; i < LIMB; i++)
				if (keyLen[ti] < i * 64 + 55)
					((unsigned int*)saved_key[i])[15*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + ti/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = 0;

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
#if ARCH_ALLOWS_UNALIGNED
			for (;i < lengthIntoMagicArray + len; i += 4, p += 4)
#if ARCH_LITTLE_ENDIAN
				*(uint32_t*)&saved_key[i>>6][GETWORDPOS(i, ti)] = JOHNSWAP(*(uint32_t*)p);
#else
				*(uint32_t*)&saved_key[i>>6][GETWORDPOS(i, ti)] = *(uint32_t*)p;
#endif
#else
			for (;i < lengthIntoMagicArray + len; ++i, ++p) {
				saved_key[i>>6][GETPOS(i, ti)] = *p;
			}
#endif

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
				*(uint32_t*)&saved_key[i>>6][GETWORDPOS(i, ti)] = 0;

			clean_pos[ti] = len + 1;
			if (len > longest)
				longest = len;

			((unsigned int*)saved_key[(len+8)>>6])[15*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + ti/SIMD_COEF_32*SHA_BUF_SIZ*SIMD_COEF_32] = len << 3;
		}

		SIMDSHA1body(&saved_key[0][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], NULL, SSEi_MIXED_IN);

		// Typically, no or very few crypts are done at this point so this is faster than to memcpy the lot
		for (index = 0; index < NBKEYS; index++)
			if (crypt_len[index] < 56)
				crypt_done((unsigned int*)interm_crypt, (unsigned int*)crypt_key, ti);

		// Do another and possibly a third, fourth and fifth limb
		for (i = 1; i < (((longest + 8) >> 6) + 1); i++) {
			SIMDSHA1body(&saved_key[i][t*SHA_BUF_SIZ*4*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], (unsigned int*)&interm_crypt[t*20*NBKEYS], SSEi_MIXED_IN|SSEi_RELOAD);
			// Copy any output that is done now
			for (index = 0; index < NBKEYS; index++)
				if (((crypt_len[index] + 8) >> 6) == i)
					crypt_done((unsigned int*)interm_crypt, (unsigned int*)crypt_key, ti);
		}
	}
#undef t
#undef ti

#else

	int index;
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (index = 0; index < count; index++) {
		unsigned int offsetMagicArray, lengthIntoMagicArray;
		unsigned char temp_key[BINARY_SIZE];
		unsigned char tempVar[UTF8_PLAINTEXT_LENGTH + MAGIC_ARRAY_SIZE + SALT_LENGTH]; //max size...
		SHA_CTX ctx;

		if (keyLen[index] < 0) {
			keyLen[index] = strlen((char*)saved_key[index]);

			// Back-out of trailing spaces
			while (keyLen[index] && saved_key[index][keyLen[index] - 1] == ' ') {
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
	return count;
}

static void *get_binary(char *ciphertext)
{
	static int outbuf[BINARY_SIZE / sizeof(int)];
	char *realcipher = (char*)outbuf;
	int i;
	char* newCiphertextPointer;

	newCiphertextPointer = strrchr(ciphertext, '$') + 1;

	for (i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(newCiphertextPointer[i*2])]*16 + atoi16[ARCH_INDEX(newCiphertextPointer[i*2+1])];
	}
#if defined(SIMD_COEF_32) && ARCH_LITTLE_ENDIAN
	alter_endianity((unsigned char*)realcipher, BINARY_SIZE);
#endif
	return (void*)realcipher;
}

#if 0 // Not possible with current interface
static char *source(struct db_password *pw, char Buf[LINE_BUFFER_SIZE] )
{
	struct saltstruct *salt_s = (struct saltstruct*)(pw->source);
	unsigned char realcipher[BINARY_SIZE];
	unsigned char *cpi;
	char *cpo;
	int i;

	memcpy(realcipher, pw->binary, BINARY_SIZE);
#ifdef SIMD_COEF_32
	alter_endianity(realcipher, BINARY_SIZE);
#endif
	memcpy(Buf, salt_s->s, salt_s->l);
	cpo = &Buf[salt_s->l];
	*cpo++ = '$';

	cpi = realcipher;

	for (i = 0; i < BINARY_SIZE; ++i) {
		*cpo++ = itoa16u[(*cpi)>>4];
		*cpo++ = itoa16u[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
#endif

#define COMMON_GET_HASH_SIMD32 5
#define COMMON_GET_HASH_VAR crypt_key
#include "common-get-hash.h"

// Here, we remove any salt padding and trim it to 44 bytes
static char *split(char *ciphertext, int index, struct fmt_main *self)
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
		0,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#if !defined(SIMD_COEF_32) || defined(SIMD_PARA_SHA1)
		FMT_OMP |
#endif
		FMT_CASE | FMT_8_BIT | FMT_UTF8,
		{ NULL },
		{ NULL },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		split,
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
		clear_keys,
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

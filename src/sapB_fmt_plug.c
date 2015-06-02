/*
 * this is a SAP-BCODE plugin for john the ripper.
 * tested on linux/x86 only, rest is up to you.. at least, someone did the reversing :-)
 *
 * please note: this code is in a "works for me"-state, feel free to modify/speed up/clean/whatever it...
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
extern struct fmt_main fmt_sapB;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sapB);
#else

#include <string.h>
#include <ctype.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "options.h"
#include "unicode.h"
#include "md5.h"

#define FORMAT_LABEL			"sapb"
#define FORMAT_NAME			"SAP CODVN B (BCODE)"

#ifdef SIMD_COEF_32
#define NBKEYS				(SIMD_COEF_32 * SIMD_PARA_MD5)
#endif
#include "sse-intrinsics.h"
#define ALGORITHM_NAME			"MD5 " MD5_ALGORITHM_NAME

#if defined(_OPENMP)
#include <omp.h>
static unsigned int omp_t = 1;
#ifdef SIMD_COEF_32
#ifndef OMP_SCALE
#define OMP_SCALE			512	// tuned on K8-dual HT.
#endif
#else
#ifndef OMP_SCALE
#define OMP_SCALE			2048
#endif
#endif
#endif

#include "memdbg.h"

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		0

#define SALT_FIELD_LENGTH		40	/* the max listed username length */
#define SALT_LENGTH			12	/* the max used username length */
#define PLAINTEXT_LENGTH		8	/* passwordlength max 8 chars */
#define CIPHERTEXT_LENGTH		SALT_FIELD_LENGTH + 1 + 16	/* SALT + $ + 2x8 bytes for BCODE-representation */

#define BINARY_SIZE			8	/* half of md5 */
#define BINARY_ALIGN			4
#define SALT_SIZE			sizeof(struct saltstruct)
#define SALT_ALIGN			4

#ifdef SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT		NBKEYS
#define MAX_KEYS_PER_CRYPT		NBKEYS
#define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32*4 )
#define GETOUTPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + (unsigned int)index/SIMD_COEF_32*16*SIMD_COEF_32)
#else
#define MIN_KEYS_PER_CRYPT		1
#define MAX_KEYS_PER_CRYPT		1
#endif

#define BCODE_ARRAY_LENGTH 3*16
static const unsigned char bcodeArr[BCODE_ARRAY_LENGTH] =
{ 0x14, 0x77, 0xf3, 0xd4, 0xbb, 0x71, 0x23, 0xd0, 0x03, 0xff, 0x47, 0x93, 0x55, 0xaa, 0x66, 0x91,
  0xf2, 0x88, 0x6b, 0x99, 0xbf, 0xcb, 0x32, 0x1a, 0x19, 0xd9, 0xa7, 0x82, 0x22, 0x49, 0xa2, 0x51,
  0xe2, 0xb7, 0x33, 0x71, 0x8b, 0x9f, 0x5d, 0x01, 0x44, 0x70, 0xae, 0x11, 0xef, 0x28, 0xf0, 0x0d };

/* char transition table for BCODE (from disp+work) */
static const unsigned char transtable[] =
{ 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0x3f, 0x40, 0x41, 0x50, 0x43, 0x44, 0x45, 0x4b, 0x47, 0x48, 0x4d, 0x4e, 0x54, 0x51, 0x53, 0x46,
  0x35, 0x36, 0x37, 0x38, 0x39, 0x3a, 0x3b, 0x3c, 0x3d, 0x3e, 0x56, 0x55, 0x5c, 0x49, 0x5d, 0x4a,
  0x42, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x58, 0x5b, 0x59, 0xff, 0x52,
//0x4c, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f, 0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27, 0x28, 0x29,
  0x4c, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
//0x2a, 0x2b, 0x2c, 0x2d, 0x2e, 0x2f, 0x30, 0x31, 0x32, 0x33, 0x34, 0x57, 0x5e, 0x5a, 0x4f, 0xff
  0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x57, 0x5e, 0x5a, 0x4f, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff,
  0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0xff };

// For backwards compatibility, we must support salts padded with spaces to a field width of 40
static struct fmt_tests tests[] = {
	{"DDIC$C94E2F7DD0178374", "DDIC"},
	// While "X" and "U" are not valid SAP passwords, they might still occur
	// if passwords longer than 8 characters are allowed, and if the CODVN B
	// password is calculated and stored in addition to the CODVN F or
	// CODVN H password.
	// Although a user picking "X       Y" as a password is probably
	// not very likely.
	{"F           $E3A65AAA9676060F", "X"},
	// the 9 character password CYBERPUNK will be truncated to CYBERPUN
	{"JOHNNY                                  $7F7207932E4DE471", "CYBERPUNK"},
	{"VAN         $487A2A40A7BA2258", "HAUSER"},
	{"ROOT        $8366A4E9E6B72CB0", "KID"},
	{"MAN         $9F48E7CE5B184D2E", "U"},
	// "-------" is not a valid SAP password (first 3 characters are
	// identical)
	// ("^^^^^^^" would be allowed, since "^" also replaces arbitrary
	// non-ascii characters, as far as the CODVN B hash algorithm is
	// concerned)
	// {"------------$2CF190AF13E858A2", "-------"},
	{"------------$058DE95926E00F32", "--+----"},
	{"SAP*$7016BFF7C5472F1B", "MASTER"},
	// password DOLLAR$$$--- will be truncated to DOLLAR$$
	{"DOLLAR$$$---$C3413C498C48EB67", "DOLLAR$$$---"},
	// Trigger suspected over-run of sum20. We do behave like SAP so it's
	// not a problem.
	{"12850413$1470EF2F683C956D", "46813230"},
	{NULL}
};

#define TEMP_ARRAY_SIZE 4*16
#define DEFAULT_OFFSET 15

static char (*saved_plain)[PLAINTEXT_LENGTH + 1];
static int (*keyLen);

#ifdef SIMD_COEF_32

static unsigned char (*saved_key);
static unsigned char (*interm_key);
static unsigned char (*crypt_key);
static unsigned int (*clean_pos);

#else

static ARCH_WORD_32 (*crypt_key)[BINARY_SIZE/sizeof(ARCH_WORD_32)];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];

#endif

static struct saltstruct {
	unsigned int l;
	unsigned char s[SALT_LENGTH];
} *cur_salt;

static void init(struct fmt_main *self)
{
	static int warned = 0;

	if (pers_opts.target_enc == UTF_8 && warned++ == 0)
		fprintf(stderr, "Warning: SAP-B format should never be UTF-8.\nUse --target-encoding=iso-8859-1 or whatever is applicable.\n");

#if defined (_OPENMP)
	omp_t = omp_get_max_threads();
	self->params.min_keys_per_crypt = (omp_t * MIN_KEYS_PER_CRYPT);
	omp_t *= OMP_SCALE;
	self->params.max_keys_per_crypt = (omp_t * MAX_KEYS_PER_CRYPT);
#endif
#ifdef SIMD_COEF_32
	saved_key  = mem_calloc_align(self->params.max_keys_per_crypt,
	                              64, MEM_ALIGN_SIMD);
	interm_key = mem_calloc_align(self->params.max_keys_per_crypt,
	                              64, MEM_ALIGN_SIMD);
	clean_pos  = mem_calloc(self->params.max_keys_per_crypt,
	                        sizeof(*clean_pos));
	crypt_key  = mem_calloc_align(self->params.max_keys_per_crypt,
	                              16, MEM_ALIGN_SIMD);
#else
	saved_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*saved_key));
	crypt_key = mem_calloc(self->params.max_keys_per_crypt,
	                       sizeof(*crypt_key));
#endif
	saved_plain = mem_calloc(self->params.max_keys_per_crypt,
	                         sizeof(*saved_plain) );
	keyLen = mem_calloc(self->params.max_keys_per_crypt,
	                    sizeof(*keyLen));
}

static void done(void)
{
	MEM_FREE(keyLen);
	MEM_FREE(saved_plain);
	MEM_FREE(crypt_key);
#ifdef SIMD_COEF_32
	MEM_FREE(clean_pos);
	MEM_FREE(interm_key);
#endif
	MEM_FREE(saved_key);
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	int i;
	char *p;

	if (!ciphertext) return 0;

	p = strrchr(ciphertext, '$');
	if (!p) return 0;

	if (p - ciphertext > SALT_FIELD_LENGTH) return 0;
	if (strlen(&p[1]) != BINARY_SIZE * 2) return 0;

	for (i = 0; i < p - ciphertext; i++) {
		// even those lower case non-ascii characters with a
		// corresponding upper case character could be rejected
		if (ciphertext[i] >= 'a' && ciphertext[i] <= 'z') return 0;
		// SAP user names cannot be longer than 12 characters
		if (i >= SALT_LENGTH && ciphertext[i] != ' ') return 0;
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

static void set_key(char *key, int index)
{
	memcpy(saved_plain[index], key, PLAINTEXT_LENGTH);
	keyLen[index] = -1;
}

static char *get_key(int index)
{
	int i;

	// Work-around for new self-test.
	if (keyLen[index] == -1)
		keyLen[index] = strlen(saved_plain[index]);

	for (i = 0; i < keyLen[index]; i++) {
		if (saved_plain[index][i] >= 'a' && saved_plain[index][i] <= 'z')
			saved_plain[index][i] ^= 0x20;
		else if (saved_plain[index][i] & 0x80)
			saved_plain[index][i] = '^';
	}
	saved_plain[index][i] = 0;

	return saved_plain[index];
}

static int cmp_all(void *binary, int count) {
#ifdef SIMD_COEF_32
	unsigned int x,y=0;

#ifdef _OPENMP
	for(;y<SIMD_PARA_MD5*omp_t;y++)
#else
	for(;y<SIMD_PARA_MD5;y++)
#endif
		for(x = 0; x < SIMD_COEF_32; x++)
		{
			if( ((ARCH_WORD_32*)binary)[0] == ((ARCH_WORD_32*)crypt_key)[y*SIMD_COEF_32*4+x] )
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
	for(i=0;i<(BINARY_SIZE/4);i++)
		if ( ((ARCH_WORD_32*)binary)[i] != ((ARCH_WORD_32*)crypt_key)[y*SIMD_COEF_32*4+i*SIMD_COEF_32+x] )
			return 0;
	return 1;
#else
	return !memcmp(binary, crypt_key[index], BINARY_SIZE);
#endif
}

static unsigned int walld0rf_magic(const int index, const unsigned char *temp_key, unsigned char *destArray)
{
	unsigned int sum20, I1, I2, I3;
	const int len = keyLen[index];

#ifdef SIMD_COEF_32
#define key(i)	saved_key[GETPOS(i, index)]
#else
#define key(i)	saved_key[index][i]
#endif
	// some magic in between....yes, byte 4 is ignored...
	// sum20 will be between 0x20 and 0x2F
	//sum20 = temp_key[5]%4 + temp_key[3]%4 + temp_key[2]%4 + temp_key[1]%4 + temp_key[0]%4 + 0x20;
	sum20 = *(unsigned int*)temp_key & 0x03030303;
	sum20 = (unsigned char)((sum20 >> 24) + (sum20 >> 16) +
	                        (sum20 >> 8) + sum20);
	sum20 += (temp_key[5] & 3) | 0x20;

	// Some unrolling
	if (temp_key[15] & 0x01) {
		destArray[0] = bcodeArr[47];
		I2 = 1;
	}
	else {
		I2 = 0;
	}
	destArray[I2++] = key(0);
	destArray[I2++] = cur_salt->s[0];
	destArray[I2] = bcodeArr[I2-2];
	destArray[++I2] = 0; I2++;

	if( len >= 6) {
		I1 = 6;
		if( cur_salt->l >= 4 ) {
			// key >= 6 bytes, salt >= 4 bytes
			if (temp_key[14] & 0x01)
				destArray[I2++] = bcodeArr[46];
			destArray[I2++] = key(1);
			destArray[I2++] = cur_salt->s[1];
			destArray[I2] = bcodeArr[I2-4];
			destArray[++I2] = 0; I2++;
			if (temp_key[13] & 0x01)
				destArray[I2++] = bcodeArr[45];
			destArray[I2++] = key(2);
			destArray[I2++] = cur_salt->s[2];
			destArray[I2] = bcodeArr[I2-6];
			destArray[++I2] = 0; I2++;
			if (temp_key[12] & 0x01)
				destArray[I2++] = bcodeArr[44];
			destArray[I2++] = key(3);
			destArray[I2++] = cur_salt->s[3];
			destArray[I2] = bcodeArr[I2-8];
			destArray[++I2] = 0; I2++;
			I3 = 4;
			if (temp_key[DEFAULT_OFFSET - 4] & 0x01)
				destArray[I2++] = bcodeArr[43];
			destArray[I2++] = key(4);
			if (4 < cur_salt->l)
				destArray[I2++] = cur_salt->s[I3++];
			destArray[I2] = bcodeArr[I2 - 5 - I3];
			destArray[++I2] = 0; I2++;
			if (temp_key[DEFAULT_OFFSET - 5] & 0x01)
				destArray[I2++] = bcodeArr[42];
			destArray[I2++] = key(5);
			if (5 < cur_salt->l)
				destArray[I2++] = cur_salt->s[I3++];
			destArray[I2] = bcodeArr[I2 - 6 - I3];
			destArray[++I2] = 0; I2++;
			if (6 < len) {
				if (temp_key[DEFAULT_OFFSET - 6] & 0x01)
					destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 7];
				destArray[I2++] = key(6); I1++;
			}
			if (6 < cur_salt->l)
				destArray[I2++] = cur_salt->s[I3++];
		} else {
			// Key >= 6 bytes, salt < 4 Bytes
			I3 = 1;
			if (temp_key[DEFAULT_OFFSET - 1] & 0x01)
				destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 2];
			destArray[I2++] = key(1);
			if (1 < cur_salt->l)
				destArray[I2++] = cur_salt->s[I3++];
			destArray[I2] = bcodeArr[I2 - 2 - I3];
			destArray[++I2] = 0; I2++;
			if (temp_key[DEFAULT_OFFSET - 2] & 0x01)
				destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 3];
			destArray[I2++] = key(2);
			if (2 < cur_salt->l)
				destArray[I2++] = cur_salt->s[I3++];
			destArray[I2] = bcodeArr[I2 - 3 - I3];
			destArray[++I2] = 0; I2++;
			if (temp_key[DEFAULT_OFFSET - 3] & 0x01)
				destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 4];
			destArray[I2++] = key(3);
			destArray[I2] = bcodeArr[I2 - 4 - I3];
			destArray[++I2] = 0; I2++;
			if (temp_key[DEFAULT_OFFSET - 4] & 0x01)
				destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 5];
			destArray[I2++] = key(4);
			destArray[I2] = bcodeArr[I2 - 5 - I3];
			destArray[++I2] = 0; I2++;
			if (temp_key[DEFAULT_OFFSET - 5] & 0x01)
				destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 6];
			destArray[I2++] = key(5);
			destArray[I2] = bcodeArr[I2 - 6 - I3];
			destArray[++I2] = 0; I2++;
			if (6 < len) {
				if (temp_key[DEFAULT_OFFSET - 6] & 0x01)
					destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - 7];
				destArray[I2++] = key(6); I1++;
			}
		}
		destArray[I2] = bcodeArr[I2 - I1 - I3];
		destArray[++I2] = 0; I2++;
	} else {
		I1 = I3 = 1;
	}
	// End of unrolling. Now the remaining bytes
	while(I2 < sum20) {
		if (I1 < len) {
			if (temp_key[DEFAULT_OFFSET - I1] & 0x01)
				destArray[I2++] = bcodeArr[BCODE_ARRAY_LENGTH - I1 - 1];
			destArray[I2++] = key(I1); I1++;
		}
		if (I3 < cur_salt->l)
			destArray[I2++] = cur_salt->s[I3++];
		destArray[I2] = bcodeArr[I2 - I1 - I3];
		destArray[++I2] = 0; I2++;
	}
#if SIMD_COEF_32
	// This may be unaligned here, but after the aligned vector buffer
	// transfer, we will have no junk left from loop overrun
	*(unsigned int*)&destArray[sum20] = 0x00000080;
#endif
	return sum20;
}

static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
#if SIMD_COEF_32
#if defined(_OPENMP)
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

		for (index = 0; index < NBKEYS; index++) {
			int len;

			if ((len = keyLen[ti]) < 0) {
				unsigned char *key;

				// Load key into vector buffer
				len = 0;
				key = (unsigned char*)saved_plain[ti];
				while (*key)
				{
					saved_key[GETPOS(len, ti)] =
						transtable[*key++];
					len++;
				}

				// Back-out of trailing spaces
				while(len && *--key == ' ')
				{
					len--;
					saved_key[GETPOS(len, ti)] = 0;
				}

				keyLen[ti] = len;
			}

			// Prepend the salt
			for (i = 0; i < cur_salt->l; i++)
				saved_key[GETPOS((len + i), ti)] =
					cur_salt->s[i];

			saved_key[GETPOS((len + i), ti)] = 0x80;
			((unsigned int *)saved_key)[14*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + (unsigned int)ti/SIMD_COEF_32*16*SIMD_COEF_32] = (len + i) << 3;

			// Clean rest of buffer
			for (i = i + len + 1; i <= clean_pos[ti]; i++)
				saved_key[GETPOS(i, ti)] = 0;
			clean_pos[ti] = len + cur_salt->l;
		}

		SSEmd5body(&saved_key[t*NBKEYS*64],
		           (unsigned int*)&crypt_key[t*NBKEYS*16], NULL, SSEi_MIXED_IN);

		for (i = 0; i < SIMD_PARA_MD5; i++)
			memset(&interm_key[t*64*NBKEYS+i*64*SIMD_COEF_32+32*SIMD_COEF_32], 0, 32*SIMD_COEF_32);

		for (index = 0; index < NBKEYS; index++) {
			unsigned int sum20;
			unsigned char temp_key[BINARY_SIZE*2];
			ARCH_WORD_32 destArray[TEMP_ARRAY_SIZE / 4];
			const unsigned int *sw;
			unsigned int *dw;

			// Temporary flat copy of crypt
			sw = (unsigned int*)&crypt_key[GETOUTPOS(0, ti)];
			dw = (unsigned int*)temp_key;
			for (i = 0; i < 4; i++, sw += SIMD_COEF_32)
				*dw++ = *sw;

			//now: walld0rf-magic [tm], (c), <g>
			sum20 = walld0rf_magic(ti, temp_key, (unsigned char*)destArray);

			// Vectorize a word at a time
			dw = (unsigned int*)&interm_key[GETPOS(0, ti)];
			for (i = 0;i <= sum20; i += 4, dw += SIMD_COEF_32)
				*dw = destArray[i >> 2];

			((unsigned int *)interm_key)[14*SIMD_COEF_32 + (ti&(SIMD_COEF_32-1)) + (unsigned int)ti/SIMD_COEF_32*16*SIMD_COEF_32] = sum20 << 3;
		}

		SSEmd5body(&interm_key[t*NBKEYS*64],
		           (unsigned int*)&crypt_key[t*NBKEYS*16], NULL, SSEi_MIXED_IN);

		for (index = 0; index < NBKEYS; index++) {
			*(ARCH_WORD_32*)&crypt_key[GETOUTPOS(0, ti)] ^= *(ARCH_WORD_32*)&crypt_key[GETOUTPOS(8, ti)];
			*(ARCH_WORD_32*)&crypt_key[GETOUTPOS(4, ti)] ^= *(ARCH_WORD_32*)&crypt_key[GETOUTPOS(12, ti)];
		}
	}

#else

#ifdef _OPENMP
	int t;
#pragma omp parallel for
	for (t = 0; t < count; t++)
#else
#define t 0
#endif
	{
		unsigned char temp_key[BINARY_SIZE*2];
		unsigned char final_key[BINARY_SIZE*2];
		unsigned int i;
		unsigned int sum20;
		unsigned char destArray[TEMP_ARRAY_SIZE];
		MD5_CTX ctx;

		if (keyLen[t] < 0) {
			keyLen[t] = strlen(saved_plain[t]);

			// Back-out of trailing spaces
			while ( saved_plain[t][keyLen[t] - 1] == ' ' )
			{
				if (keyLen[t] == 0) break;
				saved_plain[t][--keyLen[t]] = 0;
			}

			for (i = 0; i < keyLen[t]; i++)
				saved_key[t][i] = transtable[ARCH_INDEX(saved_plain[t][i])];
		}

		MD5_Init(&ctx);
		MD5_Update(&ctx, saved_key[t], keyLen[t]);
		MD5_Update(&ctx, cur_salt->s, cur_salt->l);
		MD5_Final(temp_key,&ctx);

		//now: walld0rf-magic [tm], (c), <g>
		sum20 = walld0rf_magic(t, temp_key, destArray);

		MD5_Init(&ctx);
		MD5_Update(&ctx, destArray, sum20);
		MD5_Final(final_key, &ctx);

		for (i = 0; i < 8; i++)
			((char*)crypt_key[t])[i] = final_key[i + 8] ^ final_key[i];
	}
#endif
	return count;
#undef t
#undef ti
}

static void *get_binary(char *ciphertext)
{
	static ARCH_WORD_32 binary[BINARY_SIZE / sizeof(ARCH_WORD_32)];
	char *realcipher = (char*)binary;
	int i;
	char* newCiphertextPointer;

	newCiphertextPointer = strrchr(ciphertext, '$') + 1;

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] = atoi16[ARCH_INDEX(newCiphertextPointer[i*2])]*16 + atoi16[ARCH_INDEX(newCiphertextPointer[i*2+1])];
	}
	return (void *)realcipher;
}

// Salt is already trimmed and 8-bit converted in split()
static void *get_salt(char *ciphertext)
{
	int i;
	static struct saltstruct out;

	/* We don't care about trailing garbage, but loader does */
	memset(out.s, 0, sizeof(out.s));

	out.l = (int)(strrchr(ciphertext, '$') - ciphertext);

	for (i = 0; i < out.l; ++i)
		out.s[i] = transtable[ARCH_INDEX(ciphertext[i])];

	return &out;
}

// Here, we remove any salt padding, trim it to 12 bytes
// and finally replace any 8-bit character with '^'
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

	p = &out[i];
	while(--p >= out)
		if (*p & 0x80)
			*p = '^';

	return out;
}

#ifdef SIMD_COEF_32
#define HASH_OFFSET (index&(SIMD_COEF_32-1))+((unsigned int)index/SIMD_COEF_32)*SIMD_COEF_32*4
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

struct fmt_main fmt_sapB = {
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
		FMT_OMP | FMT_8_BIT,
#if FMT_MAIN_VERSION > 11
		{ NULL },
#endif
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

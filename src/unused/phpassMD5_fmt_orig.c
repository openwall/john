/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright © 2009 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Cracks phpass 'portable' hashes, and phpBBv3 hashes, which
 * are simply phpass portable, with a slightly different signature.
 * These are 8 byte salted hashes, with a 1 byte 'salt' that
 * defines the number of loops to compute.  Internally we work
 * with 8 byte salt (the 'real' salt), but let john track it as
 * 9 byte salts (the loop count byte is appended to the 'real'
 * 8 byte salt value.
 *
 * code should be pretty fast, and pretty well debugged.  Works
 * even if there are multiple loop count values in the set of
 * hashes. PHPv5 kicked up the default loop number, but it is
 * programatically allowed to have different looping counts.
 * This format should handle all valid loop values.
 *
 * uses openSSL's MD5 and SSE2/MMX MD5 found in md5-mmx.S
 *
 */

#include <string.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"

#define FORMAT_LABEL			"phpass-md5"
#define FORMAT_NAME				"PHPass MD5"
#ifdef MMX_COEF
#if (MMX_COEF == 2)
#define ALGORITHM_NAME			"phpass-MD5 MMX"
#else
#define ALGORITHM_NAME			"phpass-MD5 SSE2"
#endif
#else
#define ALGORITHM_NAME			"phpass-md5"
#endif

#ifdef MMX_TYPE
#define BENCHMARK_COMMENT		MMX_TYPE
#else
#define BENCHMARK_COMMENT		""
#endif
#define BENCHMARK_LENGTH		-1

#define PLAINTEXT_LENGTH		64
#define CIPHERTEXT_LENGTH		34

#define BINARY_SIZE					16
#define SALT_SIZE						8
// NOTE salts are only 8 bytes, but we tell john they are 9.
// We then take the 8 bytes of salt, and append the 1 byte of
// loop count data, making it 9.  However, internal to this
// code, we only use the 8 bytes of salt. We do 'use' the loop
// count data to set our counters, whenever we set the salt, but
// it is NOT part of the rest of the salt 'usage'.
// So, $H$9PE8jEklg.... would have a salt of PE8jEklg9 but only
// the PE8jEklg is the 'actual' salt, and we use the '9' to figure
// out the looping.

#ifdef MMX_COEF
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	MMX_COEF
#define GETPOS(i, index)		( (index)*4 + ((i)& (0xffffffff-3) )*MMX_COEF + ((i)&3) )
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	1
#endif

static struct fmt_tests phpassmd5_tests[] = {
		{"$H$9aaaaaSXBjgypwqm.JsMssPLiS8YQ00","test1"},
		{"$H$9PE8jEklgZhgLmZl5.HYJAzfGCQtzi1", "123456"},
		{"$H$9pdx7dbOW3Nnt32sikrjAxYFjX8XoK1", "123456"},
		{"$P$912345678LIjjb6PhecupozNBmDndU0", "thisisalongertestPW"},
		{"$H$9A5she.OeEiU583vYsRXZ5m2XIpI68/", "123456"},
		{"$P$917UOZtDi6ksoFt.y2wUYvgUI6ZXIK/", "test1"},
		{"$P$91234567AQwVI09JXzrV1hEC6MSQ8I0", "thisisalongertest"},
		{"$P$9234560A8hN6sXs5ir0NfozijdqT6f0", "test2"},
		{"$P$9234560A86ySwM77n2VA/Ey35fwkfP0", "test3"},
		{"$P$9234560A8RZBZDBzO5ygETHXeUZX5b1", "test4"},
		{"$P$91234567xogA.H64Lkk8Cx8vlWBVzH0", "thisisalongertst"},
		{"$P$612345678si5M0DDyPpmRCmcltU/YW/", "JohnRipper"}, // note smaller loop count
		{"$H$712345678WhEyvy1YWzT4647jzeOmo0", "JohnRipper"}, // note smaller loop count (phpbb w/older PHP version)
		{"$P$B12345678L6Lpt4BxNotVIMILOa9u81", "JohnRipper"}, // note larber loop count  (Wordpress)
		{NULL}
};

#ifdef MMX_COEF
/* Cygwin would not guarantee the alignment if these were declared static */
#define crypt_key phpassmd5_crypt_key
#define cursalt phpassmd5_cursalt
#define dump phpassmd5_dump
char crypt_key[PLAINTEXT_LENGTH*MMX_COEF+1] __attribute__ ((aligned(16)));
unsigned char cursalt[PLAINTEXT_LENGTH*MMX_COEF+1] __attribute__ ((aligned(16)));
unsigned char dump[BINARY_SIZE*MMX_COEF] __attribute__((aligned(16)));
static unsigned keylen[MMX_COEF];
static unsigned maxkeylen, bNewKeys;
static ARCH_WORD_32 total_len;
static unsigned tot_keys;
static unsigned char EncKey[MMX_COEF][PLAINTEXT_LENGTH + 1];
#else
static MD5_CTX ctx;
static unsigned char cursalt[SALT_SIZE];
static char crypt_key[PLAINTEXT_LENGTH+1+BINARY_SIZE];
static unsigned char EncKey[PLAINTEXT_LENGTH + 1];
static unsigned EncKeyLen;
#endif
static unsigned loopCnt;
static char out[PLAINTEXT_LENGTH+1];

static int valid(char *ciphertext, struct fmt_main *self)
{
		int i;
		unsigned count_log2;

		if (strlen(ciphertext) != 34)
				return 0;
		// Handle both the phpass signature, and the phpBB v3 signature (same formula)
		// NOTE we are only dealing with the 'portable' encryption method
		if (strncmp(ciphertext, "$P$", 3) != 0 && strncmp(ciphertext, "$H$", 3) != 0)
				return 0;
		for (i = 3; i < 34; ++i)
				if (atoi64[ARCH_INDEX(ciphertext[i])] == 0x7F)
						return 0;

		count_log2 = atoi64[ARCH_INDEX(ciphertext[3])];
		if (count_log2 < 7 || count_log2 > 31)
				return 0;

		return 1;
}

static void phpassmd5_init(struct fmt_main *self) {
#ifdef MMX_COEF
		memset(cursalt, 0, sizeof(cursalt));
		memset(crypt_key, 0, sizeof(crypt_key));
#endif
}
static void phpassmd5_set_salt(void *salt)
{
		// compute the loop count for this salt
		loopCnt = (1 << (atoi64[ARCH_INDEX(((char*)salt)[8])]));

		// Now, deal with the 8 byte salt 'value'
#ifdef MMX_COEF
#if (MMX_COEF == 4)
		// since salt is 8 bytes long, we can use 2 32 bit assignments to
		// handle the setting (replicated 4 times), vs 32 8 bit character
		// assignments.  Same end result, but faster.
		((ARCH_WORD_32 *)cursalt)[0] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[1] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[2] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[3] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[4] = ((ARCH_WORD_32 *)salt)[1];
		((ARCH_WORD_32 *)cursalt)[5] = ((ARCH_WORD_32 *)salt)[1];
		((ARCH_WORD_32 *)cursalt)[6] = ((ARCH_WORD_32 *)salt)[1];
		((ARCH_WORD_32 *)cursalt)[7] = ((ARCH_WORD_32 *)salt)[1];
#else
		((ARCH_WORD_32 *)cursalt)[0] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[1] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[2] = ((ARCH_WORD_32 *)salt)[1];
		((ARCH_WORD_32 *)cursalt)[3] = ((ARCH_WORD_32 *)salt)[1];
#endif  // MMX_COEF != 4
#else	// !MMX_COEF
		((ARCH_WORD_32 *)cursalt)[0] = ((ARCH_WORD_32 *)salt)[0];
		((ARCH_WORD_32 *)cursalt)[1] = ((ARCH_WORD_32 *)salt)[1];
#endif
}

static void phpassmd5_set_key(char *key, int index) {
		int len;
		len = strlen(key);
#ifdef MMX_COEF
		int i;

		// the SSE code works up to 55 chars, but we have append PW to 16 byte prior
		// md5 hashes, so 39 is max PW size we can do with this SSE phpass code.
		if(len > (55-16) )
				len = (55-16);
		if (index == 0)
		{
				tot_keys = total_len = 0;
				memset(&cursalt[SALT_SIZE*MMX_COEF], 0, (maxkeylen+4)*MMX_COEF);
				memset(&crypt_key[BINARY_SIZE*MMX_COEF], 0, (maxkeylen+4)*MMX_COEF);
				maxkeylen = len;
		}
		else if (len > maxkeylen)
			maxkeylen = len;
		bNewKeys = 1;
		keylen[index] = len;
		strncpy(((char*)(EncKey[index])), key, len);
		EncKey[index][len] = 0;
		i = SALT_SIZE;
		int j, wordcnt = (len >> 2);
		if (wordcnt)
		{
				i += (wordcnt << 2);
				for (j = 0; j < wordcnt; ++j)
						((ARCH_WORD_32 *)cursalt)[((SALT_SIZE>>2)+j)*MMX_COEF+index] = ((ARCH_WORD_32 *)key)[j];
		}
		for(; i < len+SALT_SIZE; ++i)
				cursalt[GETPOS(i, index)] = ((unsigned char *)key)[i-SALT_SIZE];
		cursalt[GETPOS(i, index)] = 0x80;
		total_len += ( len << ( ( (32/MMX_COEF) * index ) ));
		++tot_keys;
#else
		if(len>PLAINTEXT_LENGTH)
				len = PLAINTEXT_LENGTH;
		EncKeyLen=len;
		strcpy(((char*)EncKey), key);
#endif
}

static char *phpassmd5_get_key(int index) {
#ifdef MMX_COEF
		strcpy(out, ((char*)(EncKey[index])));
#else
		strcpy(out, ((char*)EncKey));
#endif
		return (char *) out;
}

static int phpassmd5_cmp_all(void *binary, int index) {

#ifdef MMX_COEF
#if (MMX_COEF > 3)
		unsigned int i=0;
		while(i< (BINARY_SIZE/4) )
		{
				if((((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF]) &&
					 (((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+1])
#if (MMX_COEF > 3)
					 &&
					 (((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+2]) &&
					 (((ARCH_WORD_32 *)binary)[i] != ((ARCH_WORD_32 *)crypt_key)[i*MMX_COEF+3])
#endif
						)
						return 0;
				i++;
		}
		return 1;
#endif
#else
		int i=0;
		while(i<BINARY_SIZE/4)
		{
				if(((ARCH_WORD_32 *)binary)[i]!=((ARCH_WORD_32 *)crypt_key)[i])
						return 0;
				i++;
		}
#endif
		return 1;
}

static int phpassmd5_cmp_exact(char *source, int count)
{
		return (1);
}

#ifdef MMX_COEF
static int phpassmd5_cmp_one(void * binary, int index)
{
		return((((ARCH_WORD_32 *)binary)[0] == ((ARCH_WORD_32 *)crypt_key)[0*MMX_COEF+index]) &&
				   (((ARCH_WORD_32 *)binary)[1] == ((ARCH_WORD_32 *)crypt_key)[1*MMX_COEF+index])
#if (MMX_COEF > 3)
				   &&
				   (((ARCH_WORD_32 *)binary)[2] == ((ARCH_WORD_32 *)crypt_key)[2*MMX_COEF+index]) &&
				   (((ARCH_WORD_32 *)binary)[3] == ((ARCH_WORD_32 *)crypt_key)[3*MMX_COEF+index])
#endif
				);
}
#else
#define phpassmd5_cmp_one phpassmd5_cmp_all
#endif

#ifdef MMX_COEF
static void appendOneKey(int index) {
		int i=0;

		int j, wordcnt = (keylen[index] >> 2);
		if (wordcnt)
		{
				ARCH_WORD_32 *dwKey = ((ARCH_WORD_32*)EncKey[index]);
				i += (wordcnt << 2);
				for (j = 0; j < wordcnt; ++j)
						((ARCH_WORD_32 *)crypt_key)[((BINARY_SIZE>>2)+j)*MMX_COEF+index] = dwKey[j];
		}
		for (; i < keylen[index]; ++i)
				crypt_key[GETPOS(i+BINARY_SIZE, index)] = EncKey[index][i];
		crypt_key[GETPOS(keylen[index]+BINARY_SIZE, index)] = 0x80;
}
#endif

static void phpassmd5_crypt_all(int count) {
		unsigned Lcount;

#ifdef MMX_COEF
		int i, cur_working_lengths;

		// The first call, is to encrypt the seeds (8 bytes long) with the password
		// appened.  Thus, we need total_len + 0x08080808  (for sse2), since the
		// 8 byte fixed length of the seeds (0x00080008 for MMX, for the 2 seeds)
#if (MMX_COEF > 2)
		cur_working_lengths = 0x08080808 + total_len;
#else
		cur_working_lengths = 0x80008 + total_len;
#endif

		// Now, encrypt the seed+pw data
		mdfivemmx(crypt_key, cursalt, cur_working_lengths);

		// Now setup length for md5hash+password.  The md5hash will be overwrittnen
		// again and again, within our loop, but the password (and length info) will
		// stay static.  Huge improvement over doing 2 MD5 calls.  Again, add 0x10
		// to the length of the passwords (0x10101010 for SSE2, 0x00100010 for MMX)
#if (MMX_COEF > 2)
		cur_working_lengths = 0x10101010 + total_len;
#else
		cur_working_lengths = 0x100010 + total_len;
#endif
		if (bNewKeys)
		{
				bNewKeys = 0;
				for (i = 0; i < tot_keys; ++i)
						appendOneKey(i);
		}

		Lcount = loopCnt;
		// Now, encrypt the hash+pw data (again and again)  NOTE crypt_key is both input
		// and output. the md5 hashes will be at the 'base' of this, followed by the
		// already stored passwords.

		mdfivemmx( crypt_key, crypt_key, cur_working_lengths);
		--Lcount;
		do
		{
				//mdfivemmx( crypt_key, crypt_key, cur_working_lengths);
				mdfivemmx_nosizeupdate( crypt_key, crypt_key, cur_working_lengths);
		} while (--Lcount);

#else
		MD5_Init( &ctx );
		MD5_Update( &ctx, cursalt, 8 );
		MD5_Update( &ctx, EncKey, EncKeyLen );
		MD5_Final( (unsigned char *) crypt_key, &ctx);

		strcpy(&crypt_key[BINARY_SIZE], ((char*)EncKey));
		Lcount = loopCnt;

		do {
				MD5_Init( &ctx );
				MD5_Update( &ctx, crypt_key,  BINARY_SIZE+EncKeyLen);
				MD5_Final( (unsigned char *) crypt_key, &ctx);
		} while (--Lcount);

#endif
}

static void * phpassmd5_binary(char *ciphertext)
{
		int i;
		unsigned sixbits;
		static unsigned char b[16];
		int bidx=0;
		char *pos;

		// ugly code, but only called one time (at program load,
		// once for each candidate pass hash).

		pos = &ciphertext[3+1+8];
		for (i = 0; i < 5; ++i)
		{
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx] = sixbits;
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx++] |= (sixbits<<6);
				sixbits >>= 2;
				b[bidx] = sixbits;
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx++] |= (sixbits<<4);
				sixbits >>= 4;
				b[bidx] = sixbits;
				sixbits = atoi64[ARCH_INDEX(*pos++)];
				b[bidx++] |= (sixbits<<2);
		}
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] = sixbits;
		sixbits = atoi64[ARCH_INDEX(*pos++)];
		b[bidx] |= (sixbits<<6);
		return b;
}

static void * phpassmd5_salt(char *ciphertext)
{
		static unsigned char salt[SALT_SIZE+2];
		// store off the 'real' 8 bytes of salt
		memcpy(salt, &ciphertext[4], 8);
		// append the 1 byte of loop count information.
		salt[8] = ciphertext[3];
		salt[9]=0;
		return salt;
}

static int phpassmd5_binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int phpassmd5_binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int phpassmd5_binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int phpassmd5_binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int phpassmd5_binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }

/* Note, even though in non MMX/SSE code, there is only 1 crypt_key, using   */
/* the typecast and dereference of element [index] works fine, since indes   */
/* will always be 0 (the program knows only 1 element at most is used. Thus  */
/* the same 'simple' function(s) work for SSE and non-SSE get_hash_x() funcs */
static int phpassmd5_get_hash_0(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xf; }
static int phpassmd5_get_hash_1(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xff; }
static int phpassmd5_get_hash_2(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xfff; }
static int phpassmd5_get_hash_3(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xffff; }
static int phpassmd5_get_hash_4(int index) { return ((ARCH_WORD_32 *)crypt_key)[index] & 0xfffff; }

static int phpassmd5_salt_hash(void *salt)
{
	return *((ARCH_WORD *)salt) & 0x3FF;
}

struct fmt_main fmt_phpassmd5 = {
		{
				FORMAT_LABEL,
				FORMAT_NAME,
				ALGORITHM_NAME,
				BENCHMARK_COMMENT,
				BENCHMARK_LENGTH,
				PLAINTEXT_LENGTH,
				BINARY_SIZE,
				// only true salt of SALT_SIZE (8), but we store on 'extra' byte
				// as a salt, since we need it AND it does act as a different salt
				// byte.  However, when we use the salt in our crypting, we only
				// use the SALT_SIZE bytes.
				SALT_SIZE+1,
				MIN_KEYS_PER_CRYPT,
				MAX_KEYS_PER_CRYPT,
				FMT_CASE | FMT_8_BIT,
				phpassmd5_tests
		}, {
				phpassmd5_init,
				fmt_default_prepare,
				valid,
				fmt_default_split,
				phpassmd5_binary,
				phpassmd5_salt,
				{
					phpassmd5_binary_hash_0,
					phpassmd5_binary_hash_1,
					phpassmd5_binary_hash_2,
					phpassmd5_binary_hash_3,
					phpassmd5_binary_hash_4
				},
				phpassmd5_salt_hash,
				phpassmd5_set_salt,
				phpassmd5_set_key,
				phpassmd5_get_key,
				fmt_default_clear_keys,
				phpassmd5_crypt_all,
				{
					phpassmd5_get_hash_0,
					phpassmd5_get_hash_1,
					phpassmd5_get_hash_2,
					phpassmd5_get_hash_3,
					phpassmd5_get_hash_4
				},
				phpassmd5_cmp_all,
				phpassmd5_cmp_one,
				phpassmd5_cmp_exact
		}
};

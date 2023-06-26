/*
 * This file is
 * Copyright (c) 2023 magnum,
 * Copyright (c) 2012 Bartavelle and JimF and it is hereby released to
 * the general public under the following terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 */

#if FMT_EXTERNS_H
extern struct fmt_main fmt_sunmd5;
#elif FMT_REGISTERS_H
john_register_one(&fmt_sunmd5);
#else

#include <string.h>
#include "os.h"
#if (!AC_BUILT || HAVE_UNISTD_H) && !_MSC_VER
#include <unistd.h>
#endif
#include <stdio.h>
#include <stdlib.h>

#ifdef _OPENMP
#include <omp.h>
#endif

#include "arch.h"

#if !ARCH_LITTLE_ENDIAN
// For now, neuter this format from SIMD building.
// Someone else can port to BE at a later date.
#undef SIMD_COEF_32
#undef SIMD_PARA_MD5
#endif

#include "misc.h"
#include "options.h"
#include "params.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "md5.h"
#include "simd-intrinsics.h"

#ifndef OMP_SCALE
#if SIMD_COEF_32
#define OMP_SCALE 2 // Tuned for core i7 w/ MKPC
#else
#define OMP_SCALE 8 // Tuned for core i7 w/ SIMD disabled
#endif
#endif

#ifndef MD5_CBLOCK
#define MD5_CBLOCK 64
#endif
#ifndef MD5_DIGEST_LENGTH
#define MD5_DIGEST_LENGTH 16
#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

#define PLAINTEXT_LENGTH		120

/* JtR actually only 'uses' 4 byte binaries from this format, but for cmp_exact we need full binary */
#define FULL_BINARY_SIZE		16
#define BINARY_SIZE			4
#define BINARY_ALIGN			4
/* salt==48 allows $md5$ (5) rounds=999999$ (14) salt (16) null(1) (40 allows for 19 byte salt) */
#define SALT_SIZE			40
#define SALT_ALIGN			1

#if SIMD_COEF_32
#define MIN_KEYS_PER_CRYPT  (SIMD_COEF_32 * SIMD_PARA_MD5)
#define MAX_KEYS_PER_CRYPT  (SIMD_COEF_32 * SIMD_PARA_MD5 * 4)
#else
#define MIN_KEYS_PER_CRYPT	1
#define MAX_KEYS_PER_CRYPT	2
#endif

#define FORMAT_LABEL			"SunMD5"
#define FORMAT_NAME			""
#define FORMAT_TAG           "$md5$"
#define FORMAT_TAG2          "$md5,"
#define FORMAT_TAG_LEN       (sizeof(FORMAT_TAG)-1)
#define ALGORITHM_NAME			"MD5 " MD5_ALGORITHM_NAME

#define BENCHMARK_COMMENT		""
// it is salted, but very slow, AND there is no difference between 1 and multi salts, so simply turn off salt benchmarks
#define BENCHMARK_LENGTH		0x107

/* THIS one IS a deprecated sun string, but for real:  $md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0: Sun MD5 "password"  */
/* $md5,rounds=5000$GUBv0xjJ$$mSwgIswdjlTY0YxV7HBVm0   passwd  This one was the python code from http://packages.python.org/passlib/lib/passlib.hash.sun_md5_crypt.html, but the rounds are busted. */

static struct fmt_tests tests[] = {
	{"$md5$rounds=904$Vc3VgyFx44iS8.Yu$Scf90iLWN6O6mT9TA06NK/", "test"},
	/* from CMIYC-12 */
	{"$md5$rounds=904$ZZZig8GS.S0pRNhc$dw5NMYJoxLlnFq4E.phLy.", "Don41dL33"},
	{"$md5$rounds=904$zSuVTn567UJLv14u$q2n2ZBFwKg2tElFBIzUq/0", "J4ck!3Wood"},
	{"$md5$rounds=904$zuZVga3IOSfOshxU$gkUlHjR6apc6cr.7Bu5tt/", "K!m!M4rt!n"},
	{"$md5$rounds=904$/KP7bVaKYTOcplkx$i74NBQdysLaDTUSEu5FtQ.", "people"},
	{"$md5$rounds=904$/p4qqfWbTQcUqjNc$leW.8/vzyDpFQxSZrV0x.0", "me"},
	{"$md5$rounds=904$wOyGLc0NMRiXJTvI$v69lVSnLif78hZbZWhuEG1", "private"},
	// from pass_gen.pl 120 bytes long.
	{"$md5$rounds=904$Vc3VgyFx44iS8.Yu$mEyEet31IlEkO4HTeobmq0", "012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789012345678901234567890123456789"},

	{NULL}
};

#ifdef SIMD_PARA_MD5
#define PARA SIMD_PARA_MD5
#else
#define PARA 1
#endif

#ifdef SIMD_COEF_32
#define COEF SIMD_COEF_32
#define BLK_CNT (PARA*COEF)
#if PARA > 1
/*
 * for para-3 32 bit at MAX_KEYS=1k,  0==281 1==292 2==284 3==284 4==283 5==282
 * for para-3 32 bit at MAX_KEYS=512, 0==286 1==287 2==279 3==279 4==278 5==278
 * for para-3 32 bit at MAX_KEYS=256, 0==278 1==282 2==276 3==274 4==274 5==274 Above these, the same speed
 * for para-3 32 bit at MAX_KEYS=128, 0==272 1==277 2==271 3==270 4==271 5==270
 * for para-3 32 bit at MAX_KEYS=64,  0==259 1==264 2==264 3==263 4==259 5==270
 */
#define MIN_DROP_BACK 1
#else
#define MIN_DROP_BACK 1
#endif
//#define GETPOS(i, index)		    ( ((index)&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) )
//#define PARAGETPOS(i, index)		( ((index)&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3))*SIMD_COEF_32 + ((i)&3) + ((index)/SIMD_COEF_32)*SIMD_COEF_32*64 )
// these next 2 defines are same as above, but faster (on my gcc). Speed went fro 282 to 292, about 3.5% improvement.  Shifts vs mults.
#define GETPOS(i, index)		    ( (((index)&(SIMD_COEF_32-1))<<2) + (((i)&(0xffffffff-3))*SIMD_COEF_32) + ((i)&3) )
#define PARAGETPOS(i, index)		( (((index)&(SIMD_COEF_32-1))<<2) + (((i)&(0xffffffff-3))*SIMD_COEF_32) + ((i)&3) + (((unsigned int)index/SIMD_COEF_32*SIMD_COEF_32)<<6) )
/* GETPOS0 can be 'faster' if we already have a pointer to the first DWORD in this block.  Thus we can do a GETPOS(0,idx), and then multiple GETPOS0(x) and sometimes be faster */
#define GETPOS0(i)					(                               (((i)&(0xffffffff-3))*SIMD_COEF_32) + ((i)&3) )
/* output buffer for para is only 16 bytes per COEF, vs 64, so it's fewer bytes to jumbo to the next PARA start */
#define PARAGETOUTPOS(i, index)		( (((index)&(SIMD_COEF_32-1))<<2) + (((i)&(0xffffffff-3))*SIMD_COEF_32) + ((i)&3) + (((unsigned int)index/SIMD_COEF_32*SIMD_COEF_32)<<4) )

static uint32_t (*input_buf)[BLK_CNT * MD5_CBLOCK / sizeof(uint32_t)];
static uint32_t (*out_buf)[BLK_CNT * MD5_DIGEST_LENGTH / sizeof(uint32_t)];
static uint32_t (*input_buf_big)[25][BLK_CNT * MD5_CBLOCK / sizeof(uint32_t)];

#else
#define COEF 1
#endif

/* allocated in init() */
static uint32_t (*crypt_out)[FULL_BINARY_SIZE / sizeof(uint32_t)];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char *saved_salt;

/* minimum number of rounds we do, not including the per-user ones */

#define	BASIC_ROUND_COUNT 4096 /* enough to make things interesting */
#define	DIGEST_LEN	16
#define	ROUND_BUFFER_LEN	64

/* ------------------------------------------------------------------ */

typedef struct {
	MD5_CTX context;	/* working buffer for MD5 algorithm */
	uint32_t digest[DIGEST_LEN / sizeof(uint32_t)]; /* where the MD5 digest is stored */
} JTR_ALIGN(MEM_ALIGN_CACHE) Contx, *pConx;
static Contx *data;

/*
 * Public domain quotation courtesy of Project Gutenberg.
 * ftp://metalab.unc.edu/pub/docs/books/gutenberg/etext98/2ws2610.txt
 * Hamlet III.ii - 1517 bytes, including trailing NUL
 * ANSI-C string constant concatenation is a requirement here.
 */

#define constant_phrase_size 1517
static const char constant_phrase[] =
	"To be, or not to be,--that is the question:--\n"
	"Whether 'tis nobler in the mind to suffer\n"
	"The slings and arrows of outrageous fortune\n"
	"Or to take arms against a sea of troubles,\n"
	"And by opposing end them?--To die,--to sleep,--\n"
	"No more; and by a sleep to say we end\n"
	"The heartache, and the thousand natural shocks\n"
	"That flesh is heir to,--'tis a consummation\n"
	"Devoutly to be wish'd. To die,--to sleep;--\n"
	"To sleep! perchance to dream:--ay, there's the rub;\n"
	"For in that sleep of death what dreams may come,\n"
	"When we have shuffled off this mortal coil,\n"
	"Must give us pause: there's the respect\n"
	"That makes calamity of so long life;\n"
	"For who would bear the whips and scorns of time,\n"
	"The oppressor's wrong, the proud man's contumely,\n"
	"The pangs of despis'd love, the law's delay,\n"
	"The insolence of office, and the spurns\n"
	"That patient merit of the unworthy takes,\n"
	"When he himself might his quietus make\n"
	"With a bare bodkin? who would these fardels bear,\n"
	"To grunt and sweat under a weary life,\n"
	"But that the dread of something after death,--\n"
	"The undiscover'd country, from whose bourn\n"
	"No traveller returns,--puzzles the will,\n"
	"And makes us rather bear those ills we have\n"
	"Than fly to others that we know not of?\n"
	"Thus conscience does make cowards of us all;\n"
	"And thus the native hue of resolution\n"
	"Is sicklied o'er with the pale cast of thought;\n"
	"And enterprises of great pith and moment,\n"
	"With this regard, their currents turn awry,\n"
	"And lose the name of action.--Soft you now!\n"
	"The fair Ophelia!--Nymph, in thy orisons\n"
	"Be all my sins remember'd.\n";

static unsigned char mod5[0x100];
static int ngroups = 1;

static void init(struct fmt_main *self)
{
	int i;
#ifdef SIMD_COEF_32
	int j, k;
#endif

	ngroups = omp_autotune(self, OMP_SCALE);

#ifdef SIMD_COEF_32
	/*
	 * allocate SSE2 input and output buffer space.  For input's we have
	 * 2 buffers.  One does the 'short' 1 block crypts. The other does the
	 * long 25 block crypts.  All MUST be aligned to SIMD.
	 */
	input_buf     = mem_calloc_align(ngroups, sizeof(*input_buf), MEM_ALIGN_CACHE);
	input_buf_big = mem_calloc_align(ngroups, sizeof(*input_buf_big), MEM_ALIGN_CACHE);
	out_buf       = mem_calloc_align(ngroups, sizeof(*out_buf), MEM_ALIGN_CACHE);

	/* not super optimal, but only done one time, at program startup, so speed is not important */
	for (k = 0; k < ngroups; ++k) {
		for (i = 0; i < constant_phrase_size; ++i) {
			for (j = 0; j < BLK_CNT; ++j)
				((unsigned char*)input_buf_big[k][(i+16)/64])[PARAGETPOS((16+i)%64,j)] = constant_phrase[i];
		}
	}
#endif

	saved_key = mem_calloc(self->params.max_keys_per_crypt, sizeof(*saved_key));
	saved_salt = mem_calloc(1, SALT_SIZE + 1);
	crypt_out = mem_calloc(self->params.max_keys_per_crypt, sizeof(*crypt_out));
	data = mem_calloc_align(self->params.max_keys_per_crypt, sizeof(*data), MEM_ALIGN_CACHE);

	for (i = 0; i < 0x100; i++)
		mod5[i] = i % 5;
}

static void done(void)
{
	MEM_FREE(data);
	MEM_FREE(crypt_out);
	MEM_FREE(saved_salt);
	MEM_FREE(saved_key);
#ifdef SIMD_COEF_32
	MEM_FREE(input_buf);
	MEM_FREE(input_buf_big);
	MEM_FREE(out_buf);
#endif
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *pos;

	/* Common prefix. */
	if (strncmp(ciphertext, FORMAT_TAG, FORMAT_TAG_LEN) &&
		strncmp(ciphertext, FORMAT_TAG2, FORMAT_TAG_LEN))
		return 0;
	ciphertext += FORMAT_TAG_LEN-1;

	/* Optional rounds. */
	if (!strncmp(ciphertext, ",rounds=", 8) ||
	    !strncmp(ciphertext, "$rounds=", 8)) {
		pos = ciphertext += 8;
		while (*ciphertext >= '0' && *ciphertext <= '9')
			ciphertext++;
		/* Accept only numbers from 0 to 999999? */
		/* Zero-padding is ok */
		if (ciphertext - pos < 1 || ciphertext - pos > 6)
			return 0;
	}
	if (*ciphertext++ != '$')
		return 0;

	/* Salt per se. */
	pos = ciphertext;
	while (atoi64[ARCH_INDEX(*ciphertext)] != 0x7F)
		ciphertext++;
	/* Upto 16 salt chars? */
	if (ciphertext - pos > 16)
		return 0;

	/* One or two $ */
	if (*ciphertext++ != '$')
		return 0;
	if (*ciphertext == '$')
		ciphertext++;

	/* Hash per se. */
	pos = ciphertext;
	while (atoi64[ARCH_INDEX(*ciphertext)] != 0x7F)
		ciphertext++;
	/* Samples from CMIYC-12 have garbage in padding bits.
	   Hence the check is disabled for now. */
	if (ciphertext - pos != 22
	    /* || atoi64[ARCH_INDEX(*(ciphertext - 1))] & 0x0F */)
		return 0;

	/* No garbage at the end */
	if (*ciphertext)
		return 0;

	return 1;
}

static long from64 (unsigned char *s, int n) {
	long l = 0;
	while (--n >= 0) {
		l <<= 6;
		l += atoi64[s[n]];
	}
	return l;
}

static void *get_binary(char *ciphertext)
{
	static union {
		char c[FULL_BINARY_SIZE];
		uint32_t w[FULL_BINARY_SIZE / sizeof(uint32_t)];
	} out;
	unsigned l;
	unsigned char *cp;
	cp = (unsigned char*)strrchr(ciphertext, '$');
	++cp;
	l = from64(cp, 4);
	out.c[0] = l>>16;  out.c[6] = (l>>8)&0xFF;  out.c[12] = l&0xFF;
	l = from64(&cp[4], 4);
	out.c[1] = l>>16;  out.c[7] = (l>>8)&0xFF;  out.c[13] = l&0xFF;
	l = from64(&cp[8], 4);
	out.c[2] = l>>16;  out.c[8] = (l>>8)&0xFF;  out.c[14] = l&0xFF;
	l = from64(&cp[12], 4);
	out.c[3] = l>>16;  out.c[9] = (l>>8)&0xFF;  out.c[15] = l&0xFF;
	l = from64(&cp[16], 4);
	out.c[4] = l>>16;  out.c[10] = (l>>8)&0xFF;  out.c[5] = l&0xFF;
	l = from64(&cp[20], 2);
	out.c[11] = l;
	return out.c;
}

static void *get_salt(char *ciphertext)
{
	static char out[SALT_SIZE];

	char *p = strrchr(ciphertext, '$');
	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, p - ciphertext);
	return out;
}

#define COMMON_GET_HASH_VAR crypt_out
#include "common-get-hash.h"

static int salt_hash(void *salt)
{
	int h;
	char *sp = (char*)salt;
	char *cp = strrchr(sp, '$');
	if (cp) --cp;
	else cp = &sp[strlen(sp)-1];

	h = atoi64[ARCH_INDEX(*cp--)];
	h ^= (unsigned char)*cp--;
	h <<= 5;
	h ^= atoi64[ARCH_INDEX(*cp--)];
	h ^= (unsigned char)*cp++;
	return h & (SALT_HASH_SIZE - 1);
}

static void set_salt(void *salt)
{
	memcpy(saved_salt, salt, SALT_SIZE);
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, sizeof(*saved_key));
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (((uint32_t*)binary)[0] == crypt_out[index][0])
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return ((uint32_t*)binary)[0] == crypt_out[index][0];
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(get_binary(source), crypt_out[index], FULL_BINARY_SIZE);
}


// inline function, as a macro.
#define md5bit_1(d,b) ((d[((b)>>3)&0xF]&(1<<((b)&7))) ? 1 : 0)
// md5bit with no conditional logic.
#define md5bit_2(d,b) (((d[((b)>>3)&0xF]>>((b)&7)))&1)

inline static int
md5bit(unsigned char *digest, int bit_num)
{
	return (((digest[((bit_num)>>3)&0xF]>>((bit_num)&7)))&1);
#if 0
	/* original function from sun code */
	int byte_off;
	int bit_off;

	bit_num %= 128; /* keep this bounded for convenience */
	byte_off = bit_num / 8;
	bit_off = bit_num % 8;
	/* return the value of bit N from the digest */
	return ((digest[byte_off] & (0x01 << bit_off)) ? 1 : 0);
#endif
}

inline static int
coin_step(unsigned char *digest, int i, int j, int shift)
{
	return md5bit(digest, digest[(digest[i] >> mod5[digest[j]]) & 0x0F] >> ((digest[j] >> (digest[i] & 0x07)) & 0x01)) << shift;
}

#define	ROUNDS		"rounds="
#define	ROUNDSLEN	7

/*
 * get the integer value after rounds= where ever it occurs in the string.
 * if the last char after the int is a , or $ that is fine anything else is an
 * error.
 */
static unsigned int
getrounds(const char *s)
{
	char *r, *p, *e;
	long val;

	if (s == NULL)
		return (0);

	if ((r = strstr(s, ROUNDS)) == NULL) {
		return (0);
	}

	if (strncmp(r, ROUNDS, ROUNDSLEN) != 0) {
		return (0);
	}

	p = r + ROUNDSLEN;
	val = strtol(p, &e, 10);
	/*
	 * An error occurred or there is non-numeric stuff at the end
	 * which isn't one of the crypt(3c) special chars ',' or '$'
	 */
	if (val < 0 ||
	    !(*e == '\0' || *e == ',' || *e == '$')) {
		fprintf(stderr, "crypt_sunmd5: invalid rounds specification \"%s\"", s);
		return (0);
	}

	return ((unsigned int)val);
}


static int crypt_all(int *pcount, struct db_salt *salt)
{
	const int count = *pcount;
	unsigned int k, group_idx;
	int group_sz = (count + ngroups - 1) / ngroups;

	for (k = 0; k < count; ++k) {
		/* initialise the context */

		MD5_Init(&data[k].context);

		/* update with the (hopefully entropic) plaintext */

		MD5_Update(&data[k].context, (unsigned char*)saved_key[k], strlen(saved_key[k]));

		/* update with the (publicly known) salt */

		MD5_Update(&data[k].context, (unsigned char*)saved_salt, strlen(saved_salt));

		/* compute the digest */

		MD5_Final((unsigned char*)data[k].digest, &data[k].context);
	}

/*
 * We don't use default(none) here because some compilers export
 * constant_phrase into the parallel region automatically and don't allow
 * listing it in shared(), whereas some others require listing it in shared(),
 * and we don't want to drop const from constant_phrase nor are we confident
 * in getting all per-compiler-version #if's right (especially not for future
 * versions).  (The same issue with "const int count" we'd work around by
 * simply dropping the const from there.)
 */
#ifdef _OPENMP
#pragma omp parallel for
#endif
	for (group_idx = 0; group_idx < ngroups; ++group_idx) {
		int roundasciilen;
		int round, maxrounds = BASIC_ROUND_COUNT + getrounds(saved_salt);
		char roundascii[8];

		int idx_begin = group_idx * group_sz;
		int idx_end = idx_begin + group_sz > count ?
			count : idx_begin + group_sz;

#ifdef SIMD_COEF_32
		int i, j, zs, zb, zs0, zb0;
		int bigs[MAX_KEYS_PER_CRYPT], smalls[MAX_KEYS_PER_CRYPT];
		int nbig, nsmall;
		// int zb2;  // used in debugging
		memset(input_buf[group_idx], 0, BLK_CNT*MD5_CBLOCK);
#endif

		/*
		 * now to delay high-speed md5 implementations that have stuff
		 * like code inlining, loops unrolled and table lookup
		 */

		/* this is the 'first' sprintf(roundascii,"%d",round);  The rest are at the bottom of the loop */
		/* some compilers dont allow strcpy inside OMP block with default(none) used */
		//strcpy(roundascii, "0");
		roundascii[0] = '0';
		roundascii[1] = 0;

		roundasciilen=1;

		for (round = 0; round < maxrounds; round++) {
#ifdef SIMD_COEF_32
			nbig = nsmall = 0;
#endif

			/*
			 *  now this is computed at bottom of loop (we start properly set at "0", len==1)
			 *    ** code replaced**
			 *  roundasciilen = sprintf(roundascii, "%d", round);
			 */
			unsigned int idx;
			for (idx = idx_begin; idx < idx_end; ++idx) {
				pConx px = &data[idx];

				int indirect_a =
					md5bit((unsigned char*)px->digest, round) ?
					coin_step((unsigned char*)px->digest, 1,  4,  0) |
					coin_step((unsigned char*)px->digest, 2,  5,  1) |
					coin_step((unsigned char*)px->digest, 3,  6,  2) |
					coin_step((unsigned char*)px->digest, 4,  7,  3) |
					coin_step((unsigned char*)px->digest, 5,  8,  4) |
					coin_step((unsigned char*)px->digest, 6,  9,  5) |
					coin_step((unsigned char*)px->digest, 7, 10,  6)
					:
					coin_step((unsigned char*)px->digest, 0,  3,  0) |
					coin_step((unsigned char*)px->digest, 1,  4,  1) |
					coin_step((unsigned char*)px->digest, 2,  5,  2) |
					coin_step((unsigned char*)px->digest, 3,  6,  3) |
					coin_step((unsigned char*)px->digest, 4,  7,  4) |
					coin_step((unsigned char*)px->digest, 5,  8,  5) |
					coin_step((unsigned char*)px->digest, 6,  9,  6);

				int indirect_b =
					md5bit((unsigned char*)px->digest, round + 64) ?
					coin_step((unsigned char*)px->digest,  9, 12,  0) |
					coin_step((unsigned char*)px->digest, 10, 13,  1) |
					coin_step((unsigned char*)px->digest, 11, 14,  2) |
					coin_step((unsigned char*)px->digest, 12, 15,  3) |
					coin_step((unsigned char*)px->digest, 13,  0,  4) |
					coin_step((unsigned char*)px->digest, 14,  1,  5) |
					coin_step((unsigned char*)px->digest, 15,  2,  6)
					:
					coin_step((unsigned char*)px->digest,  8, 11,  0) |
					coin_step((unsigned char*)px->digest,  9, 12,  1) |
					coin_step((unsigned char*)px->digest, 10, 13,  2) |
					coin_step((unsigned char*)px->digest, 11, 14,  3) |
					coin_step((unsigned char*)px->digest, 12, 15,  4) |
					coin_step((unsigned char*)px->digest, 13,  0,  5) |
					coin_step((unsigned char*)px->digest, 14,  1,  6);

				int bit = md5bit((unsigned char*)px->digest, indirect_a) ^ md5bit((unsigned char*)px->digest, indirect_b);

				/* xor a coin-toss; if true, mix-in the constant phrase */

#ifndef SIMD_COEF_32
				/*
				 * This is the real 'crypt'. Pretty trival, but there are 2 possible sizes
				 * there is a 1 block crypte, and a 25 block crypt.  They are chosen based
				 * upon the 'long' coin flip algorithm above.
				 */

				/* re-initialise the context */
				MD5_Init(&px->context);

				/* update with the previous digest */
				MD5_Update(&px->context, (unsigned char*)px->digest, sizeof(px->digest));

				/* optional, add a constant string. This is what makes the 'long' crypt loops */
				if (bit)
					MD5_Update(&px->context, (unsigned char*)constant_phrase, constant_phrase_size);
				/* Add a decimal current roundcount */
				MD5_Update(&px->context, (unsigned char*)roundascii, roundasciilen);
				MD5_Final((unsigned char*)px->digest, &px->context);
#else
				/*
				 * we do not actually perform the work here. We run through all of the
				 * keys we are working on, and figure out which ones need 'small' buffers
				 * and which ones need large buffers. Then we can group them SIMD_COEF_32*SIMD_PARA_MD5
				 * at a time, later in the process.
				 */
				if (bit)
					bigs[nbig++] = idx;
				else
					smalls[nsmall++] = idx;
#endif

			}
#ifdef SIMD_COEF_32
			/*
			 * ok, at this time we know what group each element is in.  Either a large
			 * crypt, or small one. Now group our crypts up based upon the crypt size
			 * doing COEF*PARA at a time, until we have 2 'partial' buffers left. We
			 * 'waste' some CPU in them, but that is what happens. If there is only 1 or
			 * or 2, we may even drop back and use oSSL, it may be faster than an entire
			 * SSE crypt.  We will have to time test, and find where the cut over point is
			 * but likely it will NOT be 0. The cuttover appears to be 1, meaning that 0,
			 * only a 1 limb PARA buffer will not be done (and will fall back to oSSL). This
			 * was for PARA==3 on 32 bit.   A much BIGGER difference was in the MAX_KEYS_PER_CRYPT
			 * increasing this does make for more speed, HOWEVER, it also makes for more lost time
			 * if the run is stopped, since ALL of the words in the keys buffer would have to be
			 * redone again (hopefully only redone over the candidates left to test in the input file).
			 * The choice to use 512 MAX_KEYS seems about right.
			 */

			/********************************************/
			/* get the little ones out of the way first */
			/********************************************/

			/* first, put the length text, 0x80, and buffer length into the buffer 1 time, not in the loop */
			for (j = 0; j < BLK_CNT; ++j) {
				unsigned char *cpo = &((unsigned char*)input_buf[group_idx])[PARAGETPOS(0, j)];
				int k;
				for (k = 0; k < roundasciilen; ++k) {
					cpo[GETPOS0(k+16)] = roundascii[k];
				}
				cpo[GETPOS0(k+16)] = 0x80;
				((uint32_t*)cpo)[14 * SIMD_COEF_32]=((16+roundasciilen)<<3);
			}
			/* now do the 'loop' for the small 1-limb blocks. */
			zs = zs0 = zb = zb0 = 0;
			// zb2 = 0; /* for debugging */
			for (i = 0; i < nsmall-MIN_DROP_BACK; i += BLK_CNT) {
				for (j = 0; j < BLK_CNT && zs < nsmall; ++j) {
					pConx px = &data[smalls[zs++]];
					uint32_t *pi = px->digest;
					uint32_t *po = (uint32_t*)&((unsigned char*)input_buf[group_idx])[PARAGETPOS(0, j)];
					/*
					 * digest is flat, input buf is SSE_COEF.
					 * input_buf is po (output) here, we are writing to it.
					 */
					po[0] = pi[0];
					po[COEF] = pi[1];
					po[COEF+COEF] = pi[2];
					po[COEF+COEF+COEF] = pi[3];
				}
				SIMDmd5body(input_buf[group_idx], out_buf[group_idx], NULL, SSEi_MIXED_IN);
				/*
				 * we convert from COEF back to flat. since this data will later be used
				 * in non linear order, there is no gain trying to keep it in COEF order
				 */
				for (j = 0; j < BLK_CNT && zs0 < nsmall; ++j) {
					uint32_t *pi, *po;
					pConx px = &data[smalls[zs0++]];
					pi = (uint32_t*)&((unsigned char*)out_buf[group_idx])[PARAGETOUTPOS(0, j)];
					po = px->digest;
					po[0] = pi[0];
					po[1] = pi[COEF];
					po[2] = pi[COEF+COEF];
					po[3] = pi[COEF+COEF+COEF];
				}
			}
			/* this catches any left over small's, and simply uses oSSL */
			while (zs < nsmall) {
				pConx px = &data[smalls[zs++]];
				MD5_Init(&px->context);
				MD5_Update(&px->context, (unsigned char*)px->digest, sizeof(px->digest));
				MD5_Update(&px->context, (unsigned char*)roundascii, roundasciilen);
				MD5_Final((unsigned char*)px->digest, &px->context);
			}
			/*****************************************************************************
			 * Now do the big ones.  These are more complex that the little ones
			 * (much more complex actually).  Here, we have to insert the prior crypt
			 * into the first 16 bytes (just like in the little ones, but then we have
			 * our buffer 'pre-loaded' with a 1517 byte string.  we append the text number
			 * after the null byte of that 1517 byte string, then put on the 0x80, and
			 * then put the bit length.  NOTE, that this actually is an array of 25
			 * SSE_PARA buffer blocks, so there is quite a bit more manipluation of where
			 * in the buffer to write this.  This is most noted in the text number, where
			 * it spills over from buffer 24 to 25.
			 *****************************************************************************/

			/* first, put the length text, 0x80, and buffer length into the buffer 1 time, not in the loop */
			for (j = 0; j < BLK_CNT; ++j) {
				unsigned char *cpo23 = &((unsigned char*)input_buf_big[group_idx][23])[PARAGETPOS(0, j)];
				unsigned char *cpo24 = &((unsigned char*)input_buf_big[group_idx][24])[PARAGETPOS(0, j)];
				uint32_t *po24 = (uint32_t*)cpo24;
				*po24 = 0; /* key clean */
				cpo23[GETPOS0(61)] = roundascii[0];
				switch(roundasciilen) {
					case 1:
						cpo23[GETPOS0(62)] = 0x80;
						cpo23[GETPOS0(63)] = 0; /* key clean. */
						break;
					case 2:
						cpo23[GETPOS0(62)] = roundascii[1];
						cpo23[GETPOS0(63)] = 0x80;
						break;
					case 3:
						cpo23[GETPOS0(62)] = roundascii[1];
						cpo23[GETPOS0(63)] = roundascii[2];
						cpo24[0] = 0x80;
						break;
					case 4:
						cpo23[GETPOS0(62)] = roundascii[1];
						cpo23[GETPOS0(63)] = roundascii[2];
						cpo24[0] = roundascii[3];
						cpo24[1] = 0x80;
						break;
					case 5:
						cpo23[GETPOS0(62)] = roundascii[1];
						cpo23[GETPOS0(63)] = roundascii[2];
						cpo24[0] = roundascii[3];
						cpo24[1] = roundascii[4];
						cpo24[2] = 0x80;
						break;
					case 6:
						cpo23[GETPOS0(62)] = roundascii[1];
						cpo23[GETPOS0(63)] = roundascii[2];
						cpo24[0] = roundascii[3];
						cpo24[1] = roundascii[4];
						cpo24[2] = roundascii[5];
						cpo24[3] = 0x80;
						break;
				}
				po24[14*SIMD_COEF_32]=((16+constant_phrase_size+roundasciilen)<<3);
			}
			for (i = 0; i < nbig-MIN_DROP_BACK; i += BLK_CNT) {
				for (j = 0; j < BLK_CNT && zb < nbig; ++j) {
					pConx px = &data[bigs[zb++]];
					uint32_t *pi = px->digest;
					uint32_t *po = (uint32_t*)&((unsigned char*)input_buf_big[group_idx][0])[PARAGETPOS(0, j)];
					/*
					 * digest is flat, input buf is SSE_COEF.
					 * input_buf is po (output) here, we are writing to it.
					 */
					po[0] = pi[0];
					po[COEF] = pi[1];
					po[COEF+COEF] = pi[2];
					po[COEF+COEF+COEF] = pi[3];
				}
				SIMDmd5body(input_buf_big[group_idx][0], out_buf[group_idx], NULL, SSEi_MIXED_IN);
				for (j = 1; j < 25; ++j)
					SIMDmd5body(input_buf_big[group_idx][j], out_buf[group_idx], out_buf[group_idx], SSEi_RELOAD|SSEi_MIXED_IN);

				for (j = 0; j < BLK_CNT && zb0 < nbig; ++j) {
					uint32_t *pi, *po;
					pConx px = &data[bigs[zb0++]];
					pi = (uint32_t*)&((unsigned char*)out_buf[group_idx])[PARAGETOUTPOS(0, j)];
					po = px->digest;
					po[0] = pi[0];
					po[1] = pi[COEF];
					po[2] = pi[COEF+COEF];
					po[3] = pi[COEF+COEF+COEF];
				}
			}
			/* this catches any left overs, and simply uses oSSL */
			while (zb < nbig) {
				pConx px = &data[bigs[zb++]];
				MD5_Init(&px->context);
				MD5_Update(&px->context, (unsigned char*)px->digest, sizeof(px->digest));
				MD5_Update(&px->context, (unsigned char*)constant_phrase, constant_phrase_size);
				MD5_Update(&px->context, (unsigned char*)roundascii, roundasciilen);
				MD5_Final((unsigned char*)px->digest, &px->context);
			}
#endif
			/*
			 * this is the equivalent of the original code:
			 *    roundasciilen = sprintf(roundascii, "%d", round);
			 * that was at the top of this rounds loop.  We have moved
			 * it to the bottom. It does compute one 'extra' value that
			 * is never used (5001), but it is faster, and that one
			 * extra value causes no harm.
			 * we do call the sprintf a few times (at 10, 100, 1000, etc)
			 * but we only call it there.
			 */

			if (++roundascii[roundasciilen-1] == '9'+1) {
				int j = roundasciilen-1;
				if (j > 0) {
					do {
						roundascii[j] = '0';
						++roundascii[--j];
					} while (j > 0 && roundascii[j] == '9'+1);
				}
				if (!j && roundascii[0] == '9'+1) {
					/* some compilers dont allow sprintf inside OMP block */
					//roundasciilen = sprintf(roundascii, "%d", round+1);
					roundascii[0] = '1';
					roundascii[roundasciilen++] = '0';
					roundascii[roundasciilen] = 0;
				}
			}
		}
	}

	for (k = 0; k < count; ++k) {
		pConx px = &data[k];
		memcpy(crypt_out[k], px->digest, FULL_BINARY_SIZE);
	}
	return count;
}
/*
 * the number of iterations is the sum of a "basic round count" (4096) and
 * a configurable "per-user round count"; we report the sum as cost
 */
unsigned int sunmd5_cost(void *salt)
{
	return (unsigned int) (BASIC_ROUND_COUNT + getrounds(salt));
}

struct fmt_main fmt_sunmd5 = {
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
		{
			/*
			 * sum of a "basic round count" (4096) and
			 * a configurable "per-user round count"
			 */
			"iteration count",
		},
		{ FORMAT_TAG, FORMAT_TAG2 },
		tests
	}, {
		init,
		done,
		fmt_default_reset,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		get_binary,
		get_salt,
		{
			sunmd5_cost,
		},
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

/*
 * First cut, which was oSSL only, and done in 2 source files, by
 * Bartavelle  (please change to proper cite).
 * Corrections, and re-write into SSE2, JimF.
 *
 * This software was written by Bartavelle <cite> and JimF
 * jfoug AT cox dot net, in 2012 for CMIYC-12. No copyright is claimed,
 * and the software is hereby placed in the public domain. In case this
 * attempt to disclaim copyright and place the software in the public
 * domain is deemed null and void, then the software is:
 * Copyright © 2012 Bartavelle and JimF and it is hereby released to
 * the general public under the following terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 */

#include <string.h>
#ifdef _MSC_VER
#include <stdio.h>
#else
#include <unistd.h>
#endif

#include "arch.h"
#include "misc.h"
#include "options.h"
#include "misc.h"
#include "params.h"
#include "memory.h"
#include "common.h"
#include "formats.h"
#include "loader.h"
#include "memory.h"
#include "md5.h"
#include "sse-intrinsics.h"

// 'bug' in arch.h for 64 bit builds.  WE NEED TO FIX that in the arch file.
#ifdef MD5_SSE_PARA
#define MMX_COEF	4
#endif

/*
 * these 2 are for testing non-MMX mode. if we
 * undefine these 2, then we force build oSSL model.
 */
//#undef MD5_SSE_PARA
//#undef MMX_COEF

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

#define MIN_KEYS_PER_CRYPT		1
#if defined (MMX_COEF)
#define MAX_KEYS_PER_CRYPT		1024
#else
#define MAX_KEYS_PER_CRYPT		1
#endif

#define FORMAT_LABEL			"sunmd5"
#define FORMAT_NAME			"SunMD5"
#ifdef MMX_COEF
#define ALGORITHM_NAME			MD5_ALGORITHM_NAME " x" STRINGIZE(MAX_KEYS_PER_CRYPT)
#else
#define ALGORITHM_NAME			MD5_ALGORITHM_NAME
#endif

#define BENCHMARK_COMMENT		""
// it is salted, but very slow, AND there is no differnce between 1 and multi salts, so simply turn off salt benchmarks
#define BENCHMARK_LENGTH		-1

// There 'ARE' more types, but we only handle these 2, at this time.
#define MAGIC  "$md5,rounds=904$"
#define MAGIC2 "$md5$rounds=904$"

/* THIS one IS a depricated sun string, but for real:  $md5$3UqYqndY$$6P.aaWOoucxxq.l00SS9k0: Sun MD5 "password"  */
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

#ifdef MD5_SSE_PARA
#define PARA MD5_SSE_PARA
#else
#define PARA 1
#endif

#ifdef MMX_COEF
#define COEF MMX_COEF
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
//#define GETPOS(i, index)		    ( ((index)&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) )
//#define PARAGETPOS(i, index)		( ((index)&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3))*MMX_COEF + ((i)&3) + ((index)>>(MMX_COEF>>1))*MMX_COEF*64 )
// these next 2 defines are same as above, but faster (on my gcc). Speed went fro 282 to 292, abotu 3.5% improvement.  Shifts vs mults.
#define GETPOS(i, index)		    ( (((index)&(MMX_COEF-1))<<2) + (((i)&(0xffffffff-3))<<(MMX_COEF>>1)) + ((i)&3) )
#define PARAGETPOS(i, index)		( (((index)&(MMX_COEF-1))<<2) + (((i)&(0xffffffff-3))<<(MMX_COEF>>1)) + ((i)&3) + ((((index)>>(MMX_COEF>>1))<<(MMX_COEF>>1))<<6) )
/* GETPOS0 can be 'faster' if we already have a pointer to the first DWORD in this block.  Thus we can do a GETPOS(0,idx), and then multiple GETPOS0(x) and sometimes be faster */
#define GETPOS0(i)					(                               (((i)&(0xffffffff-3))<<(MMX_COEF>>1)) + ((i)&3) )
/* output buffer for para is only 16 bytes per COEF, vs 64, so it's fewer bytes to jumbo to the next PARA start */
#define PARAGETOUTPOS(i, index)		( (((index)&(MMX_COEF-1))<<2) + (((i)&(0xffffffff-3))<<(MMX_COEF>>1)) + ((i)&3) + ((((index)>>(MMX_COEF>>1))<<(MMX_COEF>>1))<<4) )

unsigned char *input_buf;
unsigned char *out_buf;
unsigned char (*input_buf_big)[BLK_CNT*MD5_CBLOCK];
/*  Now these are allocated in init()
unsigned char input_buf[BLK_CNT*MD5_CBLOCK]         __attribute__ ((aligned(16)));
unsigned char input_buf_big[25][BLK_CNT*MD5_CBLOCK] __attribute__ ((aligned(16)));
unsigned char out_buf[BLK_CNT*MD5_DIGEST_LENGTH]    __attribute__ ((aligned(16)));
*/

#else
#define COEF 1
#endif

/* allocated in init() */
static char (*crypt_out)[FULL_BINARY_SIZE];
static char (*saved_key)[PLAINTEXT_LENGTH + 1];
static char *saved_salt;

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

static void init(struct fmt_main *self)
{
#ifdef MMX_COEF
	int i, j;
	/*
	 * allocate SSE2 input and output buffer space.  For input's we have
	 * 2 buffers.  One does the 'short' 1 block crypts. The other does the
	 * long 25 block crypts.  All MUST be aligned to 16 bytes
	 */
	input_buf     = mem_calloc_tiny(BLK_CNT*MD5_CBLOCK, MEM_ALIGN_SIMD);
	input_buf_big = mem_calloc_tiny(sizeof(*input_buf_big) * 25, MEM_ALIGN_SIMD);
	out_buf       = mem_calloc_tiny(BLK_CNT*MD5_DIGEST_LENGTH, MEM_ALIGN_SIMD);

	/* not super optimal, but only done one time, at program startup, so speed is not important */
	for (i = 0; i < constant_phrase_size; ++i) {
		for (j = 0; j < BLK_CNT; ++j)
			input_buf_big[(i+16)/64][PARAGETPOS((16+i)%64,j)] = constant_phrase[i];
	}
#endif
	saved_key = mem_calloc_tiny(sizeof(*saved_key) * self->params.max_keys_per_crypt, MEM_ALIGN_NONE);
	saved_salt = mem_calloc_tiny(SALT_SIZE+1, MEM_ALIGN_NONE);
	crypt_out = mem_calloc_tiny(sizeof(*crypt_out) * self->params.max_keys_per_crypt, MEM_ALIGN_WORD);

	{
		int i;
		for (i = 0; i < 0x100; i++)
			mod5[i] = i % 5;
	}
}

static int valid(char *ciphertext, struct fmt_main *self)
{
	char *cp;
	if (strncmp(ciphertext, MAGIC, strlen(MAGIC)) && strncmp(ciphertext, MAGIC2, strlen(MAGIC2)))
		return 0;
	cp = strrchr(ciphertext, '$');
	if (!cp) return 0;
	if (strlen(cp) != 23) return 0;
	while (*++cp)
		if (atoi64[ARCH_INDEX(*cp)] == 0x7F)
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

static void *binary(char *ciphertext)
{
	static union {
		char c[FULL_BINARY_SIZE];
		ARCH_WORD_32 w[FULL_BINARY_SIZE / sizeof(ARCH_WORD_32)];
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

static void *salt(char *ciphertext)
{
	static char out[SALT_SIZE];

	char *p = strrchr(ciphertext, '$');
	memset(out, 0, sizeof(out));
	memcpy(out, ciphertext, p - ciphertext);
	return out;
}

static int get_hash_0(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0xf; }
static int get_hash_1(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0xff; }
static int get_hash_2(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0xfff; }
static int get_hash_3(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0xffff; }
static int get_hash_4(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0xfffff; }
static int get_hash_5(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0xffffff; }
static int get_hash_6(int index) { return *((ARCH_WORD_32*)(crypt_out[index])) & 0x7ffffff; }
static int binary_hash_0(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xf; }
static int binary_hash_1(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xff; }
static int binary_hash_2(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfff; }
static int binary_hash_3(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffff; }
static int binary_hash_4(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xfffff; }
static int binary_hash_5(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0xffffff; }
static int binary_hash_6(void *binary) { return ((ARCH_WORD_32*)binary)[0] & 0x7ffffff; }

static int salt_hash(void *salt)
{
	int h;
	char *sp = (char *)salt;
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
	memset(saved_salt, 0, sizeof(saved_salt));
	strcpy(saved_salt, salt);
}

static void set_key(char *key, int index)
{
	strnzcpy(saved_key[index], key, PLAINTEXT_LENGTH + 1);
}

static char *get_key(int index)
{
	return saved_key[index];
}

static int cmp_all(void *binary, int count)
{
	int index;

	for (index = 0; index < count; index++)
		if (*((ARCH_WORD_32*)binary) == *((ARCH_WORD_32*)crypt_out[index]))
			return 1;

	return 0;
}

static int cmp_one(void *binary, int index)
{
	return *((ARCH_WORD_32*)binary) == *((ARCH_WORD_32*)crypt_out[index]);
}

static int cmp_exact(char *source, int index)
{
	return !memcmp(binary(source), crypt_out[index], FULL_BINARY_SIZE);
}


/* minimum number of rounds we do, not including the per-user ones */

#define	BASIC_ROUND_COUNT 4096 /* enough to make things interesting */
#define	DIGEST_LEN	16
#define	ROUND_BUFFER_LEN	64


/* ------------------------------------------------------------------ */

static inline int
md5bit(unsigned char *digest, int bit_num)
{
	int byte_off;
	int bit_off;

	bit_num %= 128; /* keep this bounded for convenience */
	byte_off = bit_num / 8;
	bit_off = bit_num % 8;

	/* return the value of bit N from the digest */
	return ((digest[byte_off] & (0x01 << bit_off)) ? 1 : 0);
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
	// NOTE, this logic should be in valid. If not valid, then do not use the hash.
//	errno = 0;
	val = strtol(p, &e, 10);
	/*
	 * An error occurred or there is non-numeric stuff at the end
	 * which isn't one of the crypt(3c) special chars ',' or '$'
	 */
//	if (errno != 0 || val < 0 ||
	if (val < 0 ||
	    !(*e == '\0' || *e == ',' || *e == '$')) {
		fprintf(stderr, "crypt_sunmd5: invalid rounds specification \"%s\"", s);
		return (0);
	}

	return ((unsigned int)val);
}

/* put all the sensitive data in a struct */
typedef struct {
	MD5_CTX context;	/* working buffer for MD5 algorithm */
	unsigned char digest[DIGEST_LEN]; /* where the MD5 digest is stored */

	int indirect_4[16]; /* extracted array of 4bit values */
	int shift_4[16];	/* shift schedule, vals 0..4 */

	int indirect_7[16]; /* extracted array of 7bit values */
	int shift_7[16];	/* shift schedule, vals 0..1 */

	int indirect_a;	 /* 7bit index into digest */
	int shift_a;		/* shift schedule, vals 0..1 */

	int indirect_b;	 /* 7bit index into digest */
	int shift_b;		/* shift schedule, vals 0..1 */

	int bit_a;		  /* single bit for cointoss */
	int bit_b;		  /* single bit for cointoss */

} Contx, *pConx;
static Contx data[MAX_KEYS_PER_CRYPT];

#ifdef MMX_COEF
static int bigs[MAX_KEYS_PER_CRYPT], smalls[MAX_KEYS_PER_CRYPT];
#endif
// it is easiest to just leave these to be set even in non. mmx builds.
static int nbig, nsmall;

static void crypt_all(int count)
{
	int i, idx, zs, zb, zs0, zb0;
	// int zb2;  // used in debugging
	int round;
	int maxrounds = BASIC_ROUND_COUNT;

#ifdef MMX_COEF
	int j;
	memset(input_buf, 0, BLK_CNT*MD5_CBLOCK);
	// input_buf_big is NOT cleaned here.  It is set during init, and the
	// middle stuff is NEVER touched after that.
#endif

	maxrounds += getrounds(saved_salt);

	for (idx = 0; idx < count; ++idx) {
		/* initialise the context */

		MD5_Init(&data[idx].context);

		/* update with the (hopefully entropic) plaintext */

		MD5_Update(&data[idx].context, (unsigned char *)saved_key[idx], strlen(saved_key[idx]));

		/* update with the (publically known) salt */

		MD5_Update(&data[idx].context, (unsigned char *)saved_salt, strlen(saved_salt));

		/* compute the digest */

		MD5_Final(data[idx].digest, &data[idx].context);

		/*
		 * now to delay high-speed md5 implementations that have stuff
		 * like code inlining, loops unrolled and table lookup
		 */
	}

	for (round = 0; round < maxrounds; round++) {
		char roundascii[8];
		int roundasciilen;

		nbig = nsmall = 0;
		zs = zs0 = zb = zb0 = 0;
		// zb2 = 0; /* for debugging */

		roundasciilen = sprintf(roundascii, "%d", round);

		for (idx = 0; idx < count; ++idx) {
			pConx px = &data[idx];

			/* populate the shift schedules for use later */
			for (i = 0; i < 16; i++) {
				int j;
			/* offset 3 -> occasionally span more than 1 int32 fetch */
				j = (i + 3) & 0xF;
				px->shift_4[i] = mod5[px->digest[j]];
				px->shift_7[i] = (px->digest[j] >> (px->digest[i] & 7)) & 0x01;
			}

			px->shift_a = md5bit(px->digest, round);
			px->shift_b = md5bit(px->digest, round + 64);

			/* populate indirect_4 with 4bit values extracted from digest */
			for (i = 0; i < 16; i++)
				/* shift the digest byte and extract four bits */
				px->indirect_4[i] = (px->digest[i] >> px->shift_4[i]) & 0x0f;

			/*
			 * populate indirect_7 with 7bit values from digest
			 * indexed via indirect_4
			 */
			for (i = 0; i < 16; i++)
				/* shift the digest byte and extract seven bits */
				px->indirect_7[i] = (px->digest[px->indirect_4[i]] >> px->shift_7[i]) & 0x7f;

			/*
			 * use the 7bit values to indirect into digest,
			 * and create two 8bit values from the results.
			 */
			px->indirect_a = px->indirect_b = 0;

			for (i = 0; i < 8; i++) {
				px->indirect_a |= (md5bit(px->digest, px->indirect_7[i]) << i);
				px->indirect_b |= (md5bit(px->digest, px->indirect_7[i + 8]) << i);
			}

			/* shall we utilise the top or bottom 7 bits? */
			px->indirect_a = (px->indirect_a >> px->shift_a) & 0x7f;
			px->indirect_b = (px->indirect_b >> px->shift_b) & 0x7f;

			/* extract two px->digest bits */
			px->bit_a = md5bit(px->digest, px->indirect_a);
			px->bit_b = md5bit(px->digest, px->indirect_b);

			/* xor a coin-toss; if true, mix-in the constant phrase */

#ifndef MMX_COEF
			/*
			 * This is the real 'crypt'. Pretty trival, but there are 2 possible sizes
			 * there is a 1 block crypte, and a 25 block crypt.  They are chosen based
			 * upon the 'long' coin flip algorithm above.
			 */

			/* re-initialise the context */
			MD5_Init(&px->context);

			/* update with the previous digest */
			MD5_Update(&px->context, px->digest, sizeof (px->digest));

			/* optional, add a constant string. This is what makes the 'long' crypt loops */
			if (px->bit_a ^ px->bit_b)
				MD5_Update(&px->context, (unsigned char *) constant_phrase, constant_phrase_size);
			/* Add a decimal current roundcount */
			MD5_Update(&px->context, (unsigned char *) roundascii, roundasciilen);
			MD5_Final(px->digest, &px->context);
			px=px;
#else
			/*
			 * we do not actually perform the work here. We run through all of the
			 * keys we are working on, and figure out which ones need 'small' buffers
			 * and which ones need large buffers. Then we can group them MMX_COEF*MD5_SSE_PARA
			 * at a time, later in the process.
			 */
			if (px->bit_a ^ px->bit_b)
				bigs[nbig++] = idx;
			else
				smalls[nsmall++] = idx;
#endif

		}
#ifdef MMX_COEF
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
			unsigned char *cpo = &input_buf[PARAGETPOS(0, j)];
			int k;
			for (k = 0; k < roundasciilen; ++k) {
				cpo[GETPOS0(k+16)] = roundascii[k];
			}
			cpo[GETPOS0(k+16)] = 0x80;
#if COEF==4
			((ARCH_WORD_32*)cpo)[56]=((16+roundasciilen)<<3);
#else
			((ARCH_WORD_32*)cpo)[28]=((16+roundasciilen)<<3);
#endif
		}
		/* now do the 'loop' for the small 1-limb blocks. */
		i = 0;
		if (nsmall > MIN_DROP_BACK) {
		for (; i < nsmall-MIN_DROP_BACK; i += BLK_CNT) {
			for (j = 0; j < BLK_CNT && zs < nsmall; ++j) {
				pConx px = &data[smalls[zs++]];
				ARCH_WORD_32 *pi = (ARCH_WORD_32*)px->digest;
				ARCH_WORD_32 *po = (ARCH_WORD_32*)&input_buf[PARAGETPOS(0, j)];
				/*
				 * digest is flat, input buf is SSE_COEF.
				 * input_buf is po (output) here, we are writing to it.
				 */
				po[0] = pi[0];
				po[COEF] = pi[1];
				po[COEF+COEF] = pi[2];
				po[COEF+COEF+COEF] = pi[3];
			}
#ifdef MD5_SSE_PARA
			SSEmd5body(input_buf, (unsigned int *)out_buf, 1);
#else
			mdfivemmx_nosizeupdate(out_buf, input_buf, 1);
#endif
			/*
			 * we convert from COEF back to flat. since this data will later be used
			 * in non linear order, there is no gain trying to keep it in COEF order
			 */
			for (j = 0; j < BLK_CNT && zs0 < nsmall; ++j) {
				ARCH_WORD_32 *pi, *po;
				pConx px = &data[smalls[zs0++]];
				pi = (ARCH_WORD_32*)&out_buf[PARAGETOUTPOS(0, j)];
				po = (ARCH_WORD_32*)px->digest;
				po[0] = pi[0];
				po[1] = pi[COEF];
				po[2] = pi[COEF+COEF];
				po[3] = pi[COEF+COEF+COEF];
			}
		}
		}
		/* this catches any left over small's, and simply uses oSSL */
		while (zs < nsmall) {
			pConx px = &data[smalls[zs++]];
			MD5_Init(&px->context);
			MD5_Update(&px->context, px->digest, sizeof (px->digest));
			MD5_Update(&px->context, (unsigned char *) roundascii, roundasciilen);
			MD5_Final(px->digest, &px->context);
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
			unsigned char *cpo23 = &(input_buf_big[23][PARAGETPOS(0, j)]);
			unsigned char *cpo24 = &(input_buf_big[24][PARAGETPOS(0, j)]);
			*((ARCH_WORD_32*)cpo24) = 0; /* key clean */
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
					cpo24[GETPOS0(0)] = 0x80;
					break;
				case 4:
					cpo23[GETPOS0(62)] = roundascii[1];
					cpo23[GETPOS0(63)] = roundascii[2];
					cpo24[GETPOS0(0)] = roundascii[3];
					cpo24[GETPOS0(1)] = 0x80;
					break;
				case 5:
					cpo23[GETPOS0(62)] = roundascii[1];
					cpo23[GETPOS0(63)] = roundascii[2];
					cpo24[GETPOS0(0)] = roundascii[3];
					cpo24[GETPOS0(1)] = roundascii[4];
					cpo24[GETPOS0(2)] = 0x80;
					break;
				case 6:
					cpo23[GETPOS0(62)] = roundascii[1];
					cpo23[GETPOS0(63)] = roundascii[2];
					cpo24[GETPOS0(0)] = roundascii[3];
					cpo24[GETPOS0(1)] = roundascii[4];
					cpo24[GETPOS0(2)] = roundascii[5];
					cpo24[GETPOS0(3)] = 0x80;
					break;
			}
#if COEF==4
			((ARCH_WORD_32*)cpo24)[56]=((16+constant_phrase_size+roundasciilen)<<3);
#else
			((ARCH_WORD_32*)cpo24)[28]=((16+constant_phrase_size+roundasciilen)<<3);
#endif
		}
		i = 0;
		if (nbig > MIN_DROP_BACK) {
		for (; i < nbig-MIN_DROP_BACK; i += BLK_CNT) {
			for (j = 0; j < BLK_CNT && zb < nbig; ++j) {
				pConx px = &data[bigs[zb++]];
				ARCH_WORD_32 *pi = (ARCH_WORD_32 *)px->digest;
				ARCH_WORD_32 *po = (ARCH_WORD_32*)&input_buf_big[0][PARAGETPOS(0, j)];
				/*
				 * digest is flat, input buf is SSE_COEF.
				 * input_buf is po (output) here, we are writing to it.
				 */
				po[0] = pi[0];
				po[COEF] = pi[1];
				po[COEF+COEF] = pi[2];
				po[COEF+COEF+COEF] = pi[3];
			}
#ifdef MD5_SSE_PARA
			SSEmd5body(input_buf_big[0], (unsigned int *)out_buf, 1);
			for (j = 1; j < 25; ++j)
				SSEmd5body(input_buf_big[j], (unsigned int *)out_buf, 0);
#else
			mdfivemmx_nosizeupdate(out_buf, input_buf_big[0], 1);
			for (j = 1; j < 25; ++j)
				mdfivemmx_noinit_nosizeupdate(out_buf, input_buf_big[j], 1);
#endif
/*
			{
				int x,y,z;
				unsigned char tmp[1600], sse_to_flat[1600];
				for (z = 0; zb2 < nbig && z < BLK_CNT; ++z) {
					pConx px = &data[bigs[zb2++]];
					memcpy(tmp, px->digest, 16);
					memcpy(&tmp[16], constant_phrase, 1517);
					memcpy(&tmp[16+1517], roundascii, roundasciilen);
					tmp[16+1517+roundasciilen] = 0x80;
					memset(&tmp[16+1517+roundasciilen+1], 0, 1600-(16+1517+roundasciilen+1));
					*(unsigned*)&tmp[1592] = (16+1517+roundasciilen)<<3;
					getbuf_stuff_mpara_mmx(sse_to_flat, input_buf_big, 1600, z);

					if (memcmp(tmp, sse_to_flat, 1600)) {
						printf("Error, z=%d  count=%d, round = %d\n", z, count, round);
						printf("FLAT:\n");
						dump_stuff(tmp, 1600);
						printf("\nSSE2:\n");
						dump_stuff(sse_to_flat, 1600);
						exit(0);
					}
				}
			}
*/
			for (j = 0; j < BLK_CNT && zb0 < nbig; ++j) {
				ARCH_WORD_32 *pi, *po;
				pConx px = &data[bigs[zb0++]];
				pi = (ARCH_WORD_32*)&out_buf[PARAGETOUTPOS(0, j)];
				po = (ARCH_WORD_32*)px->digest;
				po[0] = pi[0];
				po[1] = pi[COEF];
				po[2] = pi[COEF+COEF];
				po[3] = pi[COEF+COEF+COEF];
			}
		}
		}
		/* this catches any left overs, and simply uses oSSL */
		while (zb < nbig) {
			pConx px = &data[bigs[zb++]];
			MD5_Init(&px->context);
			MD5_Update(&px->context, px->digest, sizeof (px->digest));
			MD5_Update(&px->context, (unsigned char *) constant_phrase, constant_phrase_size);
			MD5_Update(&px->context, (unsigned char *) roundascii, roundasciilen);
			MD5_Final(px->digest, &px->context);
		}
#endif
	}

#ifndef MMX_COEF
#else
#endif
	for (idx = 0; idx < count; ++idx) {
		pConx px = &data[idx];
		memcpy(crypt_out[idx], px->digest, FULL_BINARY_SIZE);
	}
}

struct fmt_main fmt_sunmd5 = {
	{
		FORMAT_LABEL,
		FORMAT_NAME,
		ALGORITHM_NAME,
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		PLAINTEXT_LENGTH,
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		BINARY_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		SALT_ALIGN,
#endif
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
		FMT_CASE | FMT_8_BIT,
		tests
	}, {
		init,
		fmt_default_prepare,
		valid,
		fmt_default_split,
		binary,
		salt,
#if FMT_MAIN_VERSION > 9
		fmt_default_source,
#endif
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

/*
 *  NS_fmt.c
 *  Written by Samuel Monux <smonux at gmail.com> in 2008, and placed
 *  in the public domain.  There's absolutely no warranty.
 *
 *  Netscreen OS password module. Passwords must be in this format
 *  <username>:<username>$<cryptedpass>
 *
 *  which appear in Netscreen config file
 *
 *  set admin name "<username>"
 *  set admin password "<cryptedpass>"
 *
 *  username is needed because is used as part of the salt.
 *
 *  Cryptedpass is generated this way (pseudocode):
 *
 *  b64 = array([A-Za-z0-9+/])
 *  md5_binary = MD5("<username>:Administration Tools:<password>")
 *
 *  md5_ascii = ""
 *  for every 16bits word "w" in md5_binary:
 *  	append(md5_ascii, b64[ w >> 12 & 0xf ])
 *  	append(md5_ascii, b64[ w >> 6  & 0x3f ])
 *  	append(md5_ascii, b64[ w       & 0x3f ])
 *
 *  ciphertext = md5_ascii
 *  for every c,p  ("nrcstn", [0, 6, 12, 17, 23, 29]):
 *  	interpolate  character "c" in position "p" in ciphertext
 *
 * Changed to thin format dynamic_2004, Dec 2014, JimF
 */

#if AC_BUILT
#include "../autoconfig.h"
#endif
#ifndef DYNAMIC_DISABLED

#if FMT_EXTERNS_H
extern struct fmt_main fmt_NS;
#elif FMT_REGISTERS_H
john_register_one(&fmt_NS);
#else

#include <string.h>

#include "../misc.h"
#include "../md5.h"
#include "../common.h"
#include "../formats.h"
#include "../dynamic.h"
#include "../base64_convert.h"
#include "../johnswap.h"

#define FORMAT_LABEL			"md5ns"
#define FORMAT_NAME			"Netscreen"
#ifdef SIMD_COEF_32
#define ALGORITHM_NAME			"dynamic_2004 MD5 " MD5_N_STR " " SIMD_TYPE
#else
#define ALGORITHM_NAME			"dynamic_2004 MD5 32/" ARCH_BITS_STR
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7

// set PLAINTEXT_LENGTH to 0, so dyna will set this
#define PLAINTEXT_LENGTH		0

#define BINARY_SIZE			16
#define SALT_SIZE			32
#define DYNA_SALT_SIZE		(sizeof(char*))
#define BINARY_ALIGN		sizeof(uint32_t)
#define SALT_ALIGN			4

static struct fmt_tests tests[] = {
	{"admin$nMjFM0rdC9iOc+xIFsGEm3LtAeGZhn", "password"},
	{"a$nMf9FkrCIgHGccRAxsBAwxBtDtPHfn", "netscreen"},
	{"admin$nDa2MErEKCsMcuQOTsLNpGCtKJAq5n", "QUESTIONDEFENSE"},
	{NULL}
};

static unsigned short e64toshort[256];

#define ADM_LEN 22
static const char *adm = ":Administration Tools:";
static const char *b64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

static char Conv_Buf[256];
static struct fmt_main *pDynamic;
static void our_init(struct fmt_main *self);
static void get_ptr();

static uint32_t *get_binary(char *ciphertext);
static int NS_valid(char *ciphertext, struct fmt_main *self);

/* this function converts a 'native' phps signature string into a $dynamic_6$ syntax string */
static char *Convert(char *Buf, char *ciphertext)
{
	char *cp, *cpo;
	unsigned char *bin, hash[32+1], salt_hex[(ADM_LEN+SALT_SIZE)*2+1], salt_raw[(ADM_LEN+SALT_SIZE)+1];

	if (text_in_dynamic_format_already(pDynamic, ciphertext))
		return ciphertext;
	cp = strchr(ciphertext, '$');
	if (!cp)
		return "*";

	bin = (unsigned char*)get_binary(ciphertext);
	base64_convert(bin, e_b64_raw, 16, hash, e_b64_hex, sizeof(hash), 0, 0);
	cp = ciphertext; cpo = (char*)salt_raw;
	while (*cp != '$')
		*cpo++ = *cp++;
	strcpy(cpo, adm);
	base64_convert(salt_raw, e_b64_raw, strlen((char*)salt_raw), salt_hex, e_b64_hex, sizeof(salt_hex), 0, 0);
	snprintf(Buf, sizeof(Conv_Buf) - SALT_SIZE, "$dynamic_2004$%s$HEX$%s", hash, salt_hex);
	return Buf;
}


static int our_valid(char *ciphertext, struct fmt_main *self)
{
	if (!ciphertext )
		return 0;

	get_ptr();

	if (text_in_dynamic_format_already(pDynamic, ciphertext)) {
		return pDynamic->methods.valid(ciphertext, pDynamic);
	}
	if (NS_valid(ciphertext, self))
		return pDynamic->methods.valid(Convert(Conv_Buf, ciphertext), pDynamic);
	return 0;
}


static void * our_salt(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.salt(Convert(Conv_Buf, ciphertext));
}
static void * our_binary(char *ciphertext)
{
	get_ptr();
	return pDynamic->methods.binary(Convert(Conv_Buf, ciphertext));
}

struct fmt_main fmt_NS =
{
	{
		// setup the labeling and stuff. NOTE the max and min crypts are set to 1
		// here, but will be reset within our init() function.
		FORMAT_LABEL, FORMAT_NAME, ALGORITHM_NAME, BENCHMARK_COMMENT, BENCHMARK_LENGTH,
		0, PLAINTEXT_LENGTH, BINARY_SIZE, BINARY_ALIGN, DYNA_SALT_SIZE, SALT_ALIGN, 1, 1, FMT_CASE | FMT_8_BIT | FMT_DYNAMIC,
		{ NULL },
		{ NULL },
		tests
	},
	{
		/*  All we setup here, is the pointer to valid, and the pointer to init */
		/*  within the call to init, we will properly set this full object      */
		our_init,
		fmt_default_done,
		fmt_default_reset,
		fmt_default_prepare,
		our_valid,
		fmt_default_split
	}
};

static void link_funcs() {
	fmt_NS.methods.salt   = our_salt;
	fmt_NS.methods.binary = our_binary;
	fmt_NS.methods.split = fmt_default_split;
	fmt_NS.methods.prepare = fmt_default_prepare;
	fmt_NS.params.flags &= ~(FMT_SPLIT_UNIFIES_CASE);
}

static void our_init(struct fmt_main *self)
{
	if (self->private.initialized == 0) {
		get_ptr();
		pDynamic->methods.init(pDynamic);
		self->private.initialized = 1;
	}
}

static void get_ptr() {
	if (!pDynamic) {
		int i;
		const char *pos;
		for (pos = b64, i = 0 ; *pos != 0 ; pos++, i++)
			e64toshort[(int)*pos] = i;
		pDynamic = dynamic_THIN_FORMAT_LINK(&fmt_NS, Convert(Conv_Buf, tests[0].ciphertext), "md5ns", 0);
		link_funcs();
	}
}

/* old format valid.  We use this in our new valid also */
static int NS_valid(char *ciphertext, struct fmt_main *self)
{
	char *password;
	static char *netscreen = "nrcstn" ;
	static int  p[] = { 0, 6, 12, 17, 23, 29 };
	int i;

	password = strchr(ciphertext, '$');

	if (!password)
		return 0;

	if ((int)(password - ciphertext) > SALT_SIZE)
		return 0;

	password++;

	if (strnlen(password, 31) != 30)
		return 0;
	if (strspn(password, b64) != 30)
		return 0;
	for (i = 0; i < 6 ; i++)
		if (netscreen[i] != password[p[i]])
			return 0;

	for (i = 0; i < 30 ; i++) {
		char c = password[i];
		if (((c >= 'A') && ( c <= 'Z')) ||
		     ((c >= 'a') && ( c <= 'z')) ||
		     ((c >= '0') && ( c <= '9')) ||
		     (c == '+')  || ( c == '/'))
		continue;
		return 0;
	}
	return 1;
}

/* original binary for the original hash. We use this also in convert() */
static uint32_t *get_binary(char *ciphertext)
{
	static union {
		unsigned long dummy;
		uint32_t i[BINARY_SIZE/sizeof(uint32_t)];
	} _out;
	uint32_t *out = _out.i;
	char unscrambled[24];
	int i;
	MD5_u32plus a, b, c;
	MD5_u32plus d, e, f;
	char *pos;

	pos = ciphertext;
	while (*pos++ != '$');

	memcpy(unscrambled, pos + 1, 6 );
	memcpy(unscrambled + 5, pos + 7, 6 );
	memcpy(unscrambled + 10, pos + 13, 5 );
	memcpy(unscrambled + 14, pos + 18, 6 );
	memcpy(unscrambled + 19, pos + 24, 5 );

	for ( i = 0 ; i < 4 ; i++ ) {
		a = e64toshort[ARCH_INDEX(unscrambled[6*i])];
		b = e64toshort[ARCH_INDEX(unscrambled[6*i + 1 ])];
		c = e64toshort[ARCH_INDEX(unscrambled[6*i + 2 ])];
		d = e64toshort[ARCH_INDEX(unscrambled[6*i + 3 ])];
		e = e64toshort[ARCH_INDEX(unscrambled[6*i + 4 ])];
		f = e64toshort[ARCH_INDEX(unscrambled[6*i + 5 ])];
		out[i] = (((a << 12) | (b << 6) | (c)) << 16) |
		          ((d << 12) | (e << 6) | (f));
#if ARCH_LITTLE_ENDIAN
		out[i] = JOHNSWAP(out[i]);
#endif
	}
	return out;
}
#if 0
// code kept for historical reason
static int crypt_all(int *pcount, struct db_salt *salt)
{
	MD5_CTX ctx;

	MD5_Init(&ctx);
	memcpy(tocipher, cipher_salt, salt_len);
	memcpy(tocipher + salt_len, adm, ADM_LEN);
	memcpy(tocipher + salt_len + ADM_LEN, cipher_key, key_len);
	MD5_Update(&ctx , tocipher, salt_len + ADM_LEN + key_len);
	MD5_Final((void*)crypted, &ctx);

	return *pcount;
}
#endif

#endif /* plugin stanza */

#endif /* DYNAMIC_DISABLED */

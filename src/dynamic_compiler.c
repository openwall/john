/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2015. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2015 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Expression to Generic 'scriptable' compiler/builder for the
 * existing dynamic format.
 *
 *  Here is an 'expression'
 *    dynamic=EXPR[,param,param....]
 *    This expression language will be very similar to the expression language in pass_gen.pl
 *
 *  Valid items in EXPR
 *     md5(EXPR)   Perform MD5.   Results in lowcase hex (unless it's the outter EXPR)
 *     sha1(EXPR)  Perform SHA1.  Results in lowcase hex (unless it's the outter EXPR)
 *     md4(EXPR), sha256(EXPR), sha224(EXPR), sha384(EXPR), sha512(EXPR), gost(EXPR),
 *     whirlpool(EXPR) tiger(EXPR), ripemd128(EXPR), ripemd160(EXPR), ripemd256(EXPR),
 *     ripemd320(EXPR) all act like md5() and sha1, but use the hash listed.
 *
 *     MD5(EXPR) (and other hashes with upper case string), is the same as the lower
 *     case variant, except the hex result will be upper cased.
 *
 *     From here on ONLY md5() will be used to explain the expression language, BUT
 *     the md5 can be replaced with any of the other hash types.
 *
 *     md5_raw(EXPR) this one returns the raw buffer from the md5 (the 16 byte buffer)
 *     Other hashes will return their raw buffer (all valid bytes which depend upon hash)
 *
 *     md5_64(EXPR) This one returns mime base-64,
 *
 *     md5_64c(EXPR)  This one returns crypt base-64
 *
 *     $p   The input password
 *
 *     .    The . char means concatination.  So $p.$p will be the password concatenated
 *          to itself.  $p.md5($p.$s).$s.$p is the password concated with the md5 of the
 *          password concatentated to the salt. This result is then concated with the salt
 *          and password again.  Dots are required.  md5(md5($p)md5($p)) is not valid, but
 *          md5(md5($p).md5($p)) is the proper syntax.
 *
 *  params:
 *   (Note, to have a comma IN a param value, use \, )
 *   (Note all params a comma separated. The last param can have the comma omitted)
 *
 *     c1=const_value    Up to 9 const values. they must be 'packed', i.e. if you have
 *     ...               2 of the, then you MUST use c1=something,c2=somethingelse
 *     c9=const_value.
 *     pass=uni          Unicode the passwords
 *     passcase=[L|U]    This will up case or low case the password
 *     salt=             (true), ashex or tohex
 *     usrname=          (true), lc, uc, uni
 *     saltlen=#         This sets the length of the salt
 *     debug             If this is set, then JtR will output the script and other data and exit.
 *     optimize          If set, performs optimizations
 *     optimize2         If set, performs 2nd level of optimizations.
 *
 *****************************************************************
 *     TODO:
 *****************************************************************
 *   Handle #define MGF_KEYS_INPUT                   0x00000001
#define MGF_KEYS_CRYPT_IN2               0x00000002
// for salt_as_hex for other formats, we do this:  (flag>>56)
// Then 00 is md5, 01 is md4, 02 is SHA1, etc
// NOTE, all top 8 bits of the flags are reserved, and should NOT be used for flags.
#define MGF_KEYS_BASE16_IN1              0x00000004   // deprecated (use the _MD5 version)
#define MGF_KEYS_BASE16_IN1_MD5          0x0000000000000004ULL
#define MGF_KEYS_BASE16_IN1_MD4	         0x0100000000000004ULL
#define MGF_KEYS_BASE16_IN1_SHA1         0x0200000000000004ULL
#define MGF_KEYS_BASE16_IN1_SHA224       0x0300000000000004ULL
#define MGF_KEYS_BASE16_IN1_SHA256       0x0400000000000004ULL
#define MGF_KEYS_BASE16_IN1_SHA384       0x0500000000000004ULL
#define MGF_KEYS_BASE16_IN1_SHA512       0x0600000000000004ULL
#define MGF_KEYS_BASE16_IN1_GOST         0x0700000000000004ULL
#define MGF_KEYS_BASE16_IN1_WHIRLPOOL    0x0800000000000004ULL
#define MGF_KEYS_BASE16_IN1_TIGER        0x0900000000000004ULL
#define MGF_KEYS_BASE16_IN1_RIPEMD128    0x0A00000000000004ULL
#define MGF_KEYS_BASE16_IN1_RIPEMD160    0x0B00000000000004ULL
#define MGF_KEYS_BASE16_IN1_RIPEMD256    0x0C00000000000004ULL
#define MGF_KEYS_BASE16_IN1_RIPEMD320    0x0D00000000000004ULL

#define MGF_KEYS_BASE16_IN1_Offset32         0x00000008   // deprecated (use the _MD5 version)
#define MGF_KEYS_BASE16_IN1_Offset_MD5       0x0000000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_MD4       0x0100000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA1      0x0200000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA224    0x0300000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA256    0x0400000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA384    0x0500000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA512    0x0600000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_GOST      0x0700000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_WHIRLPOOL 0x0800000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_TIGER     0x0900000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD128 0x0A00000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD160 0x0B00000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD256 0x0C00000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD320 0x0D00000000000008ULL

// MGF_INPBASE64 uses e_b64_cryptBS from base64_convert.h chang b64e to b64c
#define MGF_INPBASE64		         0x00000080
if any utf16 used, set this flag??

#define MGF_PASSWORD_UPCASE          0x08000000
#define MGF_PASSWORD_LOCASE          0x10000000

if outter hash is upcase
#define MGF_BASE_16_OUTPUT_UPCASE    0x00002000

Figure out how to better hook in dynamic= so that we can use this in other
situations than ONLY working if -format=dynamic=expr is used.

Right now, all handles are allocated 'tiny'.  Change that so that we
do normal alloc/calloc, keep a list of all handles ever allocated, and
then upon void dynamic_compile_done() free up all memory from that list.

DONE // MGF_INPBASE64b uses e_b64_crypt from base64_convert.h
DONE #define MGF_INPBASE64b		         0x00004000
DONE if outter hash is md5_b64 (or b64e) then use this flag
DONE #define MGF_INPBASE64m               0x02000000
DONE #define MGF_UTF8                     0x04000000
DONE Remove all md5u() types.  Replace with a utf16() function.
DONE #define MGF_USERNAME_UPCASE         (0x00000020|MGF_USERNAME)
DONE #define MGF_USERNAME_LOCASE         (0x00000040|MGF_USERNAME)

 */

#include "arch.h"
#include <ctype.h>
#include <stdarg.h>
#include "common.h"
#include "stdint.h"
#include "formats.h"
#include "list.h"
#include "crc32.h"
#include "johnswap.h"
#include "dynamic_compiler.h"
#include "base64_convert.h"
#include "md5.h"
#include "md4.h"
#include "sha2.h"
#include "gost.h"
#include "unicode.h"
// this one is going to be harder.  only haval_256_5 is implemented in CPAN perl, making genation of test cases harder.
// Also, there are 15 different hashes in this 'family'.
//#include "sph_haval.h"

#include "sph_ripemd.h"
#include "sph_tiger.h"
#include "sph_whirlpool.h"

#if (AC_BUILT && HAVE_WHIRLPOOL) ||	  \
   (!AC_BUILT && OPENSSL_VERSION_NUMBER >= 0x10000000 && !HAVE_NO_SSL_WHIRLPOOL)
#include <openssl/whrlpool.h>
#else
// on my 32 bit cygwin builds, this code is about 4x slower than the oSSL code.
#define WHIRLPOOL_CTX             sph_whirlpool_context
#define WHIRLPOOL_Init(a)         sph_whirlpool_init(a)
#define WHIRLPOOL_Update(a,b,c)   sph_whirlpool(a,b,c)
#define WHIRLPOOL_Final(a,b)      sph_whirlpool_close(b,a)
#endif

#include "memdbg.h"

static int gost_init = 0;

typedef struct DC_list {
	struct DC_list *next;
	DC_struct *value;
} DC_list;

const char *dyna_script = "Expression=dynamic=md5($p)\nFlag=MGF_KEYS_INPUT\nFunc=DynamicFunc__crypt_md5\nTest=@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72:abc";
const char *dyna_signature = "@dynamic=md5($p)@";
const char *dyna_line1 = "@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72";
const char *dyna_line2 = "@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785";
const char *dyna_line3 = "@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb";
int dyna_sig_len = 17;

static DC_list *pList;
static DC_struct *pLastFind;

static uint32_t compute_checksum(const char *expr);
static DC_HANDLE find_checksum(uint32_t crc32);
static DC_HANDLE do_compile(const char *expr, uint32_t crc32);
static void add_checksum_list(DC_HANDLE pHand);

// TODO
static char *dynamic_expr_normalize(char *ct) {
//	if (!strncmp(ct, "@dynamic=", 9)) {
//		static char Buf[512];
//		char *cp = Buf;
//		strcpy(Buf, ct);
//		ct = Buf;
//	}
	return ct;
}

int dynamic_compile(const char *expr, DC_HANDLE *p) {
	uint32_t crc32 = compute_checksum(expr);
	DC_HANDLE pHand;
	if (pLastFind && pLastFind->crc32 == crc32) {
		*p = (DC_HANDLE)pLastFind;
		return 0;
	}

	pHand = find_checksum(crc32);
	if (pHand) {
		*p = pHand;
		pLastFind = (DC_struct*)pHand;
		return 0;
	}
	/* this is the real 'workhorse' function */
	pHand = do_compile(expr, crc32);
	if (!pHand)
		return 1;
	add_checksum_list(pHand);
	*p = pHand;
	return 0;
}

int dynamic_load(DC_HANDLE p) {
	return 0;
}

int dynamic_print_script(DC_HANDLE p) {
	return 0;
}

static char *find_the_expression(const char *expr) {
	static char buf[512];
	char *cp;
	if (strncmp(expr, "dynamic=", 8))
		return "";
	strnzcpy(buf, &expr[8], sizeof(buf));
	cp = strrchr(buf, ')');
	if (!cp) return "";
	cp[1] = 0;
	return buf;
}
static char *find_the_extra_params(const char *expr) {
	static char buf[512];
	char *cp;
	if (strncmp(expr, "dynamic=", 8))
		return "";
	cp = strrchr(expr, ')');
	if (!cp) return "";
	if (cp[1] == ',') ++cp;
	strnzcpy(buf, &cp[1], sizeof(buf));
	// NOTE, we should normalize this string!!
	// we should probably call handle_extra_params, and then make a function
	// regen_extra_params() so that we always normalize this string.
	return buf;
}

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(a[0]))
typedef void (*fpSYM)();
static int nConst;
static const char *Const[10];
static int compile_debug;
static char *SymTab[1024];
static fpSYM fpSymTab[1024];
static char *pCode[1024];
static fpSYM fpCode[1024];
static int nCode;
static char *pScriptLines[1024];
static int nScriptLines;
static int nSyms;
static int LastTokIsFunc;
static int bNeedS, bNeedS2, bNeedU, bNeedUlc, bNeedUuc;
static char *salt_as_hex_type;
static int keys_as_input;
static char *gen_Stack[1024];
static int gen_Stack_len[1024];
static int ngen_Stack, ngen_Stack_max;
static char *h;
static int h_len;
static int nSaltLen = -32;
static char gen_s[260], gen_s2[16], gen_u[16], gen_uuc[16], gen_ulc[16], gen_pw[16], gen_conv[260];
// static char gen_pwlc[16], gen_pwuc[16];

/*
 * These are the 'low level' primative functions ported from pass_gen.pl.
 * These do the md5($p) stuff (hex, HEX, unicode, base64, etc), for all hash
 * types, and for other functions.
 */
static void md5_hex()          { MD5_CTX c; MD5_Init(&c); MD5_Update(&c, h, h_len); MD5_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void md4_hex()          { MD4_CTX c; MD4_Init(&c); MD4_Update(&c, h, h_len); MD4_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void sha1_hex()         { SHA_CTX c; SHA1_Init(&c); SHA1_Update(&c, h, h_len); SHA1_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void md5_base64()       { MD5_CTX c; MD5_Init(&c); MD5_Update(&c, h, h_len); MD5_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void md4_base64()       { MD4_CTX c; MD4_Init(&c); MD4_Update(&c, h, h_len); MD4_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void sha1_base64()      { SHA_CTX c; SHA1_Init(&c); SHA1_Update(&c, h, h_len); SHA1_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void md5_base64c()      { MD5_CTX c; MD5_Init(&c); MD5_Update(&c, h, h_len); MD5_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void md4_base64c()      { MD4_CTX c; MD4_Init(&c); MD4_Update(&c, h, h_len); MD4_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void sha1_base64c()     { SHA_CTX c; SHA1_Init(&c); SHA1_Update(&c, h, h_len); SHA1_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void md5_raw()          { MD5_CTX c; MD5_Init(&c); MD5_Update(&c, h, h_len); MD5_Final((unsigned char*)h, &c);    }
static void sha1_raw()         { MD4_CTX c; MD4_Init(&c); MD4_Update(&c, h, h_len); MD4_Final((unsigned char*)h, &c);    }
static void md4_raw()          { SHA_CTX c; SHA1_Init(&c); SHA1_Update(&c, h, h_len); SHA1_Final((unsigned char*)h, &c); }
static void sha224_hex()       { SHA256_CTX c; SHA224_Init(&c); SHA224_Update(&c, h, h_len); SHA224_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,28,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void sha224_base64()    { SHA256_CTX c; SHA224_Init(&c); SHA224_Update(&c, h, h_len); SHA224_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,28,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void sha224_base64c()   { SHA256_CTX c; SHA224_Init(&c); SHA224_Update(&c, h, h_len); SHA224_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,28,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void sha256_hex()       { SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, h, h_len); SHA256_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void sha256_base64()    { SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, h, h_len); SHA256_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void sha256_base64c()   { SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, h, h_len); SHA256_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void sha384_hex()       { SHA512_CTX c; SHA384_Init(&c); SHA384_Update(&c, h, h_len); SHA384_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,48,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void sha384_base64()    { SHA512_CTX c; SHA384_Init(&c); SHA384_Update(&c, h, h_len); SHA384_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,48,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void sha384_base64c()   { SHA512_CTX c; SHA384_Init(&c); SHA384_Update(&c, h, h_len); SHA384_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,48,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void sha512_hex()       { SHA512_CTX c; SHA512_Init(&c); SHA512_Update(&c, h, h_len); SHA512_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void sha512_base64()    { SHA512_CTX c; SHA512_Init(&c); SHA512_Update(&c, h, h_len); SHA512_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void sha512_base64c()   { SHA512_CTX c; SHA512_Init(&c); SHA512_Update(&c, h, h_len); SHA512_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void sha224_raw()       { SHA256_CTX c; SHA224_Init(&c); SHA224_Update(&c, h, h_len); SHA224_Final((unsigned char*)h, &c); }
static void sha256_raw()       { SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, h, h_len); SHA256_Final((unsigned char*)h, &c); }
static void sha384_raw()       { SHA512_CTX c; SHA384_Init(&c); SHA384_Update(&c, h, h_len); SHA384_Final((unsigned char*)h, &c); }
static void sha512_raw()       { SHA512_CTX c; SHA512_Init(&c); SHA512_Update(&c, h, h_len); SHA512_Final((unsigned char*)h, &c); }
static void whirlpool_hex()    { WHIRLPOOL_CTX c; WHIRLPOOL_Init(&c); WHIRLPOOL_Update(&c, h, h_len); WHIRLPOOL_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void whirlpool_base64() { WHIRLPOOL_CTX c; WHIRLPOOL_Init(&c); WHIRLPOOL_Update(&c, h, h_len); WHIRLPOOL_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void whirlpool_base64c(){ WHIRLPOOL_CTX c; WHIRLPOOL_Init(&c); WHIRLPOOL_Update(&c, h, h_len); WHIRLPOOL_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void whirlpool_raw()    { WHIRLPOOL_CTX c; WHIRLPOOL_Init(&c); WHIRLPOOL_Update(&c, h, h_len); WHIRLPOOL_Final((unsigned char*)h, &c); }
static void tiger_hex()        { sph_tiger_context c; sph_tiger_init(&c); sph_tiger(&c, h, h_len); sph_tiger_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,24,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void tiger_base64()     { sph_tiger_context c; sph_tiger_init(&c); sph_tiger(&c, h, h_len); sph_tiger_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,24,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void tiger_base64c()    { sph_tiger_context c; sph_tiger_init(&c); sph_tiger(&c, h, h_len); sph_tiger_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,24,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void tiger_raw()        { sph_tiger_context c; sph_tiger_init(&c); sph_tiger(&c, h, h_len); sph_tiger_close(&c, (unsigned char*)h); }
static void gost_hex()         { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void gost_base64()      { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void gost_base64c()     { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void gost_raw()         { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); }
static void ripemd128_hex()    { sph_ripemd128_context c; sph_ripemd128_init(&c); sph_ripemd128(&c, (unsigned char*)h, h_len); sph_ripemd128_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void ripemd128_base64() { sph_ripemd128_context c; sph_ripemd128_init(&c); sph_ripemd128(&c, (unsigned char*)h, h_len); sph_ripemd128_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void ripemd128_base64c(){ sph_ripemd128_context c; sph_ripemd128_init(&c); sph_ripemd128(&c, (unsigned char*)h, h_len); sph_ripemd128_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void ripemd128_raw()    { sph_ripemd128_context c; sph_ripemd128_init(&c); sph_ripemd128(&c, (unsigned char*)h, h_len); sph_ripemd128_close(&c, (unsigned char*)h); }
static void ripemd160_hex()    { sph_ripemd160_context c; sph_ripemd160_init(&c); sph_ripemd160(&c, (unsigned char*)h, h_len); sph_ripemd160_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void ripemd160_base64() { sph_ripemd160_context c; sph_ripemd160_init(&c); sph_ripemd160(&c, (unsigned char*)h, h_len); sph_ripemd160_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void ripemd160_base64c(){ sph_ripemd160_context c; sph_ripemd160_init(&c); sph_ripemd160(&c, (unsigned char*)h, h_len); sph_ripemd160_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void ripemd160_raw()    { sph_ripemd160_context c; sph_ripemd160_init(&c); sph_ripemd160(&c, (unsigned char*)h, h_len); sph_ripemd160_close(&c, (unsigned char*)h); }
static void ripemd256_hex()    { sph_ripemd256_context c; sph_ripemd256_init(&c); sph_ripemd256(&c, (unsigned char*)h, h_len); sph_ripemd256_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void ripemd256_base64() { sph_ripemd256_context c; sph_ripemd256_init(&c); sph_ripemd256(&c, (unsigned char*)h, h_len); sph_ripemd256_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void ripemd256_base64c(){ sph_ripemd256_context c; sph_ripemd256_init(&c); sph_ripemd256(&c, (unsigned char*)h, h_len); sph_ripemd256_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void ripemd256_raw()    { sph_ripemd256_context c; sph_ripemd256_init(&c); sph_ripemd256(&c, (unsigned char*)h, h_len); sph_ripemd256_close(&c, (unsigned char*)h); }
static void ripemd320_hex()    { sph_ripemd320_context c; sph_ripemd320_init(&c); sph_ripemd320(&c, (unsigned char*)h, h_len); sph_ripemd320_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,40,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv); }
static void ripemd320_base64() { sph_ripemd320_context c; sph_ripemd320_init(&c); sph_ripemd320(&c, (unsigned char*)h, h_len); sph_ripemd320_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,40,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv); }
static void ripemd320_base64c(){ sph_ripemd320_context c; sph_ripemd320_init(&c); sph_ripemd320(&c, (unsigned char*)h, h_len); sph_ripemd320_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,40,gen_conv,e_b64_crypt,260,0); strcpy(h, gen_conv); }
static void ripemd320_raw()    { sph_ripemd320_context c; sph_ripemd320_init(&c); sph_ripemd320(&c, (unsigned char*)h, h_len); sph_ripemd320_close(&c, (unsigned char*)h); }
static int encode_le()         { int len = enc_to_utf16((UTF16*)gen_conv, 260, (UTF8*)h, h_len); memcpy(h, gen_conv, len*2); return len*2; }
static char *pad16()           { memset(gen_conv, 0, 16); strncpy(gen_conv, gen_pw, 16); return gen_conv; }
static char *pad20()           { memset(gen_conv, 0, 20); strncpy(gen_conv, gen_pw, 20); return gen_conv; }
static char *pad100()          { memset(gen_conv, 0, 100); strncpy(gen_conv, gen_pw, 100); return gen_conv; }
// TODO:
//int encode_be() { int len = enc_to_utf16_be((UTF16*)gen_conv, 260, (UTF8*)h, h_len); memcpy(h, gen_conv, len); return len; }

/*
 * helper functions, to reduce the size of our dynamic_*() functions
 */
static void dyna_helper_append(const char *v) {
	memcpy(&gen_Stack[ngen_Stack-1][gen_Stack_len[ngen_Stack-1]], v, strlen(v));
	gen_Stack_len[ngen_Stack-1] += strlen(v);
}
static void dyna_helper_appendn(const char *v, int len) {
	memcpy(&gen_Stack[ngen_Stack-1][gen_Stack_len[ngen_Stack-1]], v, len);
	gen_Stack_len[ngen_Stack-1] += len;
}
static void dyna_helper_pre() {
	h = gen_Stack[--ngen_Stack];
	h_len = gen_Stack_len[ngen_Stack];
}
static void dyna_helper_post(int len) {
	// like dyna_helper_append but always works with the h variable.
	// this one is for binary data, so we have to pass the length in.
	memcpy(&gen_Stack[ngen_Stack-1][gen_Stack_len[ngen_Stack-1]], h, len);
	gen_Stack_len[ngen_Stack-1] += len;
}
static void dyna_helper_poststr() {
	// like dyna_helper_append but always works with the h variable.
	int len = strlen(h);
	memcpy(&gen_Stack[ngen_Stack-1][gen_Stack_len[ngen_Stack-1]], h, len);
	gen_Stack_len[ngen_Stack-1] += len;
}

/*
 * these are the functions called by the script. They may do all the work
 * themselves, or may also use the low level primatives for hashing.
 */
static void fpNull(){}
static void dynamic_push()   { char *p = mem_calloc(260, 1); MEM_FREE(gen_Stack[ngen_Stack]); gen_Stack_len[ngen_Stack] = 0; gen_Stack[ngen_Stack++] = p; ngen_Stack_max++; }
//static void dynamic_pop    { return pop @gen_Stack; }  # not really needed.
//static void dynamic_app_s()  { dyna_helper_append(gen_s);    }
static void dynamic_app_sh() { dyna_helper_append(gen_s);    } //md5_hex($gen_s); }
static void dynamic_app_S()  { dyna_helper_append(gen_s2);   }
static void dynamic_app_u()  { dyna_helper_append(gen_u);    }
static void dynamic_app_u_lc()  { dyna_helper_append(gen_ulc);    }
static void dynamic_app_u_uc()  { dyna_helper_append(gen_uuc);    }
static void dynamic_app_p()  { dyna_helper_append(gen_pw);   }
static void dynamic_pad16()  { dyna_helper_appendn(pad16(), 16);  }
static void dynamic_pad20()  { dyna_helper_appendn(pad20(), 20);  }
static void dynamic_pad100() { dyna_helper_appendn(pad100(), 100); }

//static void dynamic_app_pU() { dyna_helper_append(gen_pwuc); }
//static void dynamic_app_pL() { dyna_helper_append(gen_pwlc); }
static void dynamic_app_1()  { dyna_helper_append(Const[1]); }
static void dynamic_app_2()  { dyna_helper_append(Const[2]); }
static void dynamic_app_3()  { dyna_helper_append(Const[3]); }
static void dynamic_app_4()  { dyna_helper_append(Const[4]); }
static void dynamic_app_5()  { dyna_helper_append(Const[5]); }
static void dynamic_app_6()  { dyna_helper_append(Const[6]); }
static void dynamic_app_7()  { dyna_helper_append(Const[7]); }
static void dynamic_app_8()  { dyna_helper_append(Const[8]); }
static void dynamic_app_9()  { dyna_helper_append(Const[9]); }
//static void dynamic_ftr32  { $h = gen_Stack[--ngen_Stack]; substr($h,0,32);  strcat(gen_Stack[ngen_Stack-1], h);  }
//static void dynamic_f54    { $h = gen_Stack[--ngen_Stack]; md5_hex(h)."00000000";	 strcat(gen_Stack[ngen_Stack-1], h);  }

static void dynamic_f5h()    { dyna_helper_pre(); md5_hex();               dyna_helper_poststr(); }
static void dynamic_f1h()    { dyna_helper_pre(); sha1_hex();              dyna_helper_poststr(); }
static void dynamic_f4h()    { dyna_helper_pre(); md4_hex();               dyna_helper_poststr(); }
static void dynamic_f5H()    { dyna_helper_pre(); md5_hex(); strupr(h);    dyna_helper_poststr(); }
static void dynamic_f1H()    { dyna_helper_pre(); sha1_hex(); strupr(h);   dyna_helper_poststr(); }
static void dynamic_f4H()    { dyna_helper_pre(); md4_hex();  strupr(h);   dyna_helper_poststr(); }
static void dynamic_f56()    { dyna_helper_pre(); md5_base64();	        dyna_helper_poststr(); }
static void dynamic_f16()    { dyna_helper_pre(); sha1_base64();           dyna_helper_poststr(); }
static void dynamic_f46()    { dyna_helper_pre(); md4_base64();            dyna_helper_poststr(); }
static void dynamic_f5c()    { dyna_helper_pre(); md5_base64c();           dyna_helper_poststr(); }
static void dynamic_f1c()    { dyna_helper_pre(); sha1_base64c();          dyna_helper_poststr(); }
static void dynamic_f4c()    { dyna_helper_pre(); md4_base64c();           dyna_helper_poststr(); }
static void dynamic_f5r()    { dyna_helper_pre(); md5_raw();               dyna_helper_post(16); }
static void dynamic_f1r()    { dyna_helper_pre(); sha1_raw();              dyna_helper_post(20); }
static void dynamic_f4r()    { dyna_helper_pre(); md4_raw();               dyna_helper_post(16); }
static void dynamic_f224h()  { dyna_helper_pre(); sha224_hex();            dyna_helper_poststr(); }
static void dynamic_f224H()  { dyna_helper_pre(); sha224_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_f2246()  { dyna_helper_pre(); sha224_base64();         dyna_helper_poststr(); }
static void dynamic_f224c()  { dyna_helper_pre(); sha224_base64c();        dyna_helper_poststr(); }
static void dynamic_f224r()  { dyna_helper_pre(); sha224_raw();            dyna_helper_post(28); }
static void dynamic_f256h()  { dyna_helper_pre(); sha256_hex();            dyna_helper_poststr(); }
static void dynamic_f256H()  { dyna_helper_pre(); sha256_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_f2566()  { dyna_helper_pre(); sha256_base64();         dyna_helper_poststr(); }
static void dynamic_f256c()  { dyna_helper_pre(); sha256_base64c();        dyna_helper_poststr(); }
static void dynamic_f256r()  { dyna_helper_pre(); sha256_raw();            dyna_helper_post(32); }
static void dynamic_f384h()  { dyna_helper_pre(); sha384_hex();            dyna_helper_poststr(); }
static void dynamic_f384H()  { dyna_helper_pre(); sha384_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_f3846()  { dyna_helper_pre(); sha384_base64();         dyna_helper_poststr(); }
static void dynamic_f384c()  { dyna_helper_pre(); sha384_base64c();        dyna_helper_poststr(); }
static void dynamic_f384r()  { dyna_helper_pre(); sha384_raw();            dyna_helper_post(48); }
static void dynamic_f512h()  { dyna_helper_pre(); sha512_hex();            dyna_helper_poststr(); }
static void dynamic_f512H()  { dyna_helper_pre(); sha512_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_f5126()  { dyna_helper_pre(); sha512_base64();         dyna_helper_poststr(); }
static void dynamic_f512c()  { dyna_helper_pre(); sha512_base64c();        dyna_helper_poststr(); }
static void dynamic_f512r()  { dyna_helper_pre(); sha512_raw();            dyna_helper_post(64); }
static void dynamic_fgosth() { dyna_helper_pre(); gost_hex();              dyna_helper_poststr(); }
static void dynamic_fgostH() { dyna_helper_pre(); gost_hex(); strupr(h);   dyna_helper_poststr(); }
static void dynamic_fgost6() { dyna_helper_pre(); gost_base64();           dyna_helper_poststr(); }
static void dynamic_fgostc() { dyna_helper_pre(); gost_base64c();          dyna_helper_poststr(); }
static void dynamic_fgostr() { dyna_helper_pre(); gost_raw();              dyna_helper_post(32); }
static void dynamic_fwrlph() { dyna_helper_pre(); whirlpool_hex();            dyna_helper_poststr(); }
static void dynamic_fwrlpH() { dyna_helper_pre(); whirlpool_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_fwrlp6() { dyna_helper_pre(); whirlpool_base64();         dyna_helper_poststr(); }
static void dynamic_fwrlpc() { dyna_helper_pre(); whirlpool_base64c();        dyna_helper_poststr(); }
static void dynamic_fwrlpr() { dyna_helper_pre(); whirlpool_raw();            dyna_helper_post(64); }
static void dynamic_ftigh()  { dyna_helper_pre(); tiger_hex();             dyna_helper_poststr(); }
static void dynamic_ftigH()  { dyna_helper_pre(); tiger_hex(); strupr(h);  dyna_helper_poststr(); }
static void dynamic_ftig6()  { dyna_helper_pre(); tiger_base64();          dyna_helper_poststr(); }
static void dynamic_ftigc()  { dyna_helper_pre(); tiger_base64c();         dyna_helper_poststr(); }
static void dynamic_ftigr()  { dyna_helper_pre(); tiger_raw();             dyna_helper_post(24); }
static void dynamic_frip128h()  { dyna_helper_pre(); ripemd128_hex();            dyna_helper_poststr(); }
static void dynamic_frip128H()  { dyna_helper_pre(); ripemd128_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_frip1286()  { dyna_helper_pre(); ripemd128_base64();         dyna_helper_poststr(); }
static void dynamic_frip128c()  { dyna_helper_pre(); ripemd128_base64c();        dyna_helper_poststr(); }
static void dynamic_frip128r()  { dyna_helper_pre(); ripemd128_raw();            dyna_helper_post(16); }
static void dynamic_frip160h()  { dyna_helper_pre(); ripemd160_hex();            dyna_helper_poststr(); }
static void dynamic_frip160H()  { dyna_helper_pre(); ripemd160_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_frip1606()  { dyna_helper_pre(); ripemd160_base64();         dyna_helper_poststr(); }
static void dynamic_frip160c()  { dyna_helper_pre(); ripemd160_base64c();        dyna_helper_poststr(); }
static void dynamic_frip160r()  { dyna_helper_pre(); ripemd160_raw();            dyna_helper_post(20); }
static void dynamic_frip256h()  { dyna_helper_pre(); ripemd256_hex();            dyna_helper_poststr(); }
static void dynamic_frip256H()  { dyna_helper_pre(); ripemd256_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_frip2566()  { dyna_helper_pre(); ripemd256_base64();         dyna_helper_poststr(); }
static void dynamic_frip256c()  { dyna_helper_pre(); ripemd256_base64c();        dyna_helper_poststr(); }
static void dynamic_frip256r()  { dyna_helper_pre(); ripemd256_raw();            dyna_helper_post(32); }
static void dynamic_frip320h()  { dyna_helper_pre(); ripemd320_hex();            dyna_helper_poststr(); }
static void dynamic_frip320H()  { dyna_helper_pre(); ripemd320_hex(); strupr(h); dyna_helper_poststr(); }
static void dynamic_frip3206()  { dyna_helper_pre(); ripemd320_base64();         dyna_helper_poststr(); }
static void dynamic_frip320c()  { dyna_helper_pre(); ripemd320_base64c();        dyna_helper_poststr(); }
static void dynamic_frip320r()  { dyna_helper_pre(); ripemd320_raw();            dyna_helper_post(40); }
static void dynamic_futf16()    { dyna_helper_pre();                             dyna_helper_post(encode_le()); }
//static void dynamic_futf16be()  { dyna_helper_pre();                             dyna_helper_post(encode_be()); }


static void init_static_data() {
	int i;
	nConst = 0;
	for (i = 0; i < nSyms; ++i) {
		MEM_FREE(SymTab[i]);
		fpSymTab[i] = NULL;
	}
	for (i = 0; i < 10; ++i) {
		if (Const[i]) {
			char *p = (char*)Const[i];
			MEM_FREE(p);
		}
		Const[i] = NULL;
	}
	for (i = 0; i < nCode; ++i) {
		MEM_FREE(pCode[i]);
		fpCode[i] = NULL;
	}
	for (i = 0; i < nScriptLines; ++i)
		MEM_FREE(pScriptLines[i]);
	for (i = 0; i < ngen_Stack; ++i) {
		MEM_FREE(gen_Stack[i]);
		gen_Stack_len[i] = 0;
	}
	ngen_Stack = ngen_Stack_max = 0;
	nCode = 0;
	nSyms = 0;
	nScriptLines = 0;
	LastTokIsFunc = 0;
	keys_as_input = 0;
	bNeedS = bNeedS2 = bNeedU = bNeedUlc = bNeedUuc = compile_debug = 0;
	MEM_FREE(salt_as_hex_type);
	h = NULL;
	h_len = 0;
	nSaltLen = -32;
	memset(gen_s, 0, sizeof(gen_s));
	memset(gen_s2, 0, sizeof(gen_s2));
	memset(gen_u, 0, sizeof(gen_u));
	memset(gen_uuc, 0, sizeof(gen_uuc));
	memset(gen_ulc, 0, sizeof(gen_ulc));
	memset(gen_pw, 0, sizeof(gen_pw));
	memset(gen_conv, 0, sizeof(gen_conv));
}
static const char *get_param(const char *p, const char *what) {
	const char *cp;
	char *cpRet;
	p = strstr(p, what);
	if (!p)
		return NULL;
	p += strlen(what);
	cp = strchr(p, ',');
	while (cp && cp[-1] == '\\')
		cp = strchr(&cp[1], ',');
	if (cp) {
		cpRet = mem_alloc_tiny((cp-p)+1, 1);
		memcpy(cpRet, p, cp-p);
		cpRet[cp-p] = 0;
	} else {
		cpRet = mem_alloc_tiny(strlen(p)+1, 1);
		strcpy(cpRet, p);
	}
	return cpRet;
}
static int handle_extra_params(DC_struct *ptr) {
	// c1=boobies,c2=bootie
	int i;
	char cx[4];
	const char *cp;

	nConst = 0;
	if (!ptr->pExtraParams || !ptr->pExtraParams[0])
		return 0;

	// Find any 'const' values that have been provided.
	for (i = 1; i < 10; ++i) {
		sprintf(cx, "c%d=", i);
		cp = get_param(ptr->pExtraParams, cx);
		if (!cp)
			break;
		Const[++nConst] = cp;
	}

	// Find any other values here.
	if (strstr(ptr->pExtraParams, "debug,") || strstr(ptr->pExtraParams, ",debug") || !strcmp(ptr->pExtraParams, "debug"))
		compile_debug = 1;

	if ( (cp = get_param(ptr->pExtraParams, "saltlen")) != NULL) {
		nSaltLen = atoi(&cp[1]);
		if (nSaltLen > 200)
			error("Max salt len allowed is 200 bytes\n");
	}
	return 0;
}

static const char *comp_push_sym(const char *p, fpSYM fpsym, const char *pRet) {
	if (nSyms < ARRAY_COUNT(SymTab)) {
		SymTab[nSyms] = mem_alloc(strlen(p)+1);
		fpSymTab[nSyms] = fpsym;
		strcpy(SymTab[nSyms++], p);
	}
	return pRet;
}
static const char *comp_get_symbol(const char *pInput) {
	// This function will grab the next valid symbol, and returns
	// the location just past this symbol.
	char TmpBuf[64];
	LastTokIsFunc = 0;
	if (!pInput || *pInput == 0) return comp_push_sym("X", fpNull, pInput);
	if (*pInput == '.') return comp_push_sym(".", fpNull, pInput+1);
	if (*pInput == '(') return comp_push_sym("(", fpNull, pInput+1);
	if (*pInput == ')') return comp_push_sym(")", fpNull, pInput+1);
	if (*pInput == '$') {
		switch(pInput[1]) {
			case 'p': return comp_push_sym("p", fpNull, pInput+2);
			case 'u': return comp_push_sym("u", fpNull, pInput+2);
			case 's': if (pInput[2] == '2') return comp_push_sym("S", fpNull, pInput+3);
					  return comp_push_sym("s", fpNull, pInput+2);
			case 'c': if (pInput[2] > '9' || pInput[2] < '1')
						  return comp_push_sym("X", fpNull, pInput);
					  if (Const[pInput[2]-'0'] == NULL) {
						  fprintf(stderr, "Error, a c%c found in expression, but the data for this const was not provided\n", pInput[2]);
						  return comp_push_sym("X", fpNull, pInput);
					  }
					  TmpBuf[0] = pInput[2];
					  TmpBuf[1] = 0;
					  return comp_push_sym(TmpBuf, fpNull, pInput+3);
		}
	}
	// these are functions, BUT can not be used for 'outter' function (i.e. not the final hash)
	LastTokIsFunc = 1;
	if (!strncasecmp(pInput, "md5", 3)) {
		if (!strncmp(pInput, "md5_raw", 7)) { LastTokIsFunc = 2; return comp_push_sym("f5r", dynamic_f5r, pInput+7); }
		if (!strncmp(pInput, "md5_64c", 7)) { return comp_push_sym("f5c", dynamic_f5c, pInput+7); }
		if (!strncmp(pInput, "md5_64", 6)) { return comp_push_sym("f56", dynamic_f56, pInput+6); }
		if (!strncmp(pInput, "md5", 3)) { return comp_push_sym("f5h", dynamic_f5h, pInput+3); }
		if (!strncmp(pInput, "MD5", 3)) { return comp_push_sym("f5H", dynamic_f5H, pInput+3); }
	}
	if (!strncasecmp(pInput, "md4", 3)) {
		if (!strncmp(pInput, "md4_raw", 7)) { LastTokIsFunc = 2; return comp_push_sym("f4r", dynamic_f4r, pInput+7); }
		if (!strncmp(pInput, "md4_64c", 7)) { return comp_push_sym("f4c", dynamic_f4c, pInput+7); }
		if (!strncmp(pInput, "md4_64", 6)) { return comp_push_sym("f46", dynamic_f46, pInput+6); }
		if (!strncmp(pInput, "md4", 3)) { return comp_push_sym("f4h", dynamic_f4h, pInput+3); }
		if (!strncmp(pInput, "MD4", 3)) { return comp_push_sym("f4H", dynamic_f4H, pInput+3); }
	}
	if (!strncasecmp(pInput, "sha1", 4)) {
		if (!strncmp(pInput, "sha1_raw", 8)) { LastTokIsFunc = 2; return comp_push_sym("f1r", dynamic_f1r, pInput+8); }
		if (!strncmp(pInput, "sha1_64c", 8)) { return comp_push_sym("f1c", dynamic_f1c, pInput+8); }
		if (!strncmp(pInput, "sha1_64", 7)) { return comp_push_sym("f16", dynamic_f16, pInput+7); }
		if (!strncmp(pInput, "sha1", 4)) { return comp_push_sym("f1h", dynamic_f1h, pInput+4); }
		if (!strncmp(pInput, "SHA1", 4)) { return comp_push_sym("f1H", dynamic_f1H, pInput+4); }
	}
	if (!strncasecmp(pInput, "sha224", 6)) {
		if (!strncmp(pInput, "sha224_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f224r", dynamic_f224r, pInput+10); }
		if (!strncmp(pInput, "sha224_64c", 10)) { return comp_push_sym("f224c", dynamic_f224c, pInput+10); }
		if (!strncmp(pInput, "sha224_64", 9)) { return comp_push_sym("f2246", dynamic_f2246, pInput+9); }
		if (!strncmp(pInput, "sha224", 6)) { return comp_push_sym("f224h", dynamic_f224h, pInput+6); }
		if (!strncmp(pInput, "SHA224", 6)) { return comp_push_sym("f224H", dynamic_f224H, pInput+6); }
	}
	if (!strncasecmp(pInput, "sha256", 6)) {
		if (!strncmp(pInput, "sha256_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f256r", dynamic_f256r, pInput+10); }
		if (!strncmp(pInput, "sha256_64c", 10)) { return comp_push_sym("f256c", dynamic_f256c, pInput+10); }
		if (!strncmp(pInput, "sha256_64", 9)) { return comp_push_sym("f2566", dynamic_f2566, pInput+9); }
		if (!strncmp(pInput, "sha256", 6)) { return comp_push_sym("f256h", dynamic_f256h, pInput+6); }
		if (!strncmp(pInput, "SHA256", 6)) { return comp_push_sym("f256H", dynamic_f256H, pInput+6); }
	}
	if (!strncasecmp(pInput, "sha384", 6)) {
		if (!strncmp(pInput, "sha384_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f384r", dynamic_f384r, pInput+10); }
		if (!strncmp(pInput, "sha384_64c", 10)) { return comp_push_sym("f384c", dynamic_f384c, pInput+10); }
		if (!strncmp(pInput, "sha384_64", 9)) { return comp_push_sym("f3846", dynamic_f3846, pInput+9); }
		if (!strncmp(pInput, "sha384", 6)) { return comp_push_sym("f384h", dynamic_f384h, pInput+6); }
		if (!strncmp(pInput, "SHA384", 6)) { return comp_push_sym("f384H", dynamic_f384H, pInput+6); }
	}
	if (!strncasecmp(pInput, "sha512", 6)) {
		if (!strncmp(pInput, "sha512_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f512r", dynamic_f512r, pInput+10); }
		if (!strncmp(pInput, "sha512_64c", 10)) { return comp_push_sym("f512c", dynamic_f512c, pInput+10); }
		if (!strncmp(pInput, "sha512_64", 9)) { return comp_push_sym("f5126", dynamic_f5126, pInput+9); }
		if (!strncmp(pInput, "sha512", 6)) { return comp_push_sym("f512h", dynamic_f512h, pInput+6); }
		if (!strncmp(pInput, "SHA512", 6)) { return comp_push_sym("f512H", dynamic_f512H, pInput+6); }
	}
	if (!strncasecmp(pInput, "gost", 4)) {
		if (!strncmp(pInput, "gost_raw", 8)) { LastTokIsFunc = 2; return comp_push_sym("fgostr", dynamic_fgostr, pInput+8); }
		if (!strncmp(pInput, "gost_64c", 8)) { return comp_push_sym("fgostc", dynamic_fgostc, pInput+8); }
		if (!strncmp(pInput, "gost_64", 7)) { return comp_push_sym("fgost6", dynamic_fgost6, pInput+7); }
		if (!strncmp(pInput, "gost", 4)) { return comp_push_sym("fgosth", dynamic_fgosth, pInput+4); }
		if (!strncmp(pInput, "GOST", 4)) { return comp_push_sym("fgostH", dynamic_fgostH, pInput+4); }
	}
	if (!strncasecmp(pInput, "tiger", 5)) {
		if (!strncmp(pInput, "tiger_raw", 9)) { LastTokIsFunc = 2; return comp_push_sym("ftigr", dynamic_ftigr, pInput+9); }
		if (!strncmp(pInput, "tiger_64c", 9)) { return comp_push_sym("ftigc", dynamic_ftigc, pInput+9); }
		if (!strncmp(pInput, "tiger_64", 8)) { return comp_push_sym("ftig6", dynamic_ftig6, pInput+8); }
		if (!strncmp(pInput, "tiger", 5)) { return comp_push_sym("ftigh", dynamic_ftigh, pInput+5); }
		if (!strncmp(pInput, "TIGER", 5)) { return comp_push_sym("ftigH", dynamic_ftigH, pInput+5); }
	}
	if (!strncasecmp(pInput, "whirlpool", 9)) {
		if (!strncmp(pInput, "whirlpool_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("fwrlpr", dynamic_fwrlpr, pInput+13); }
		if (!strncmp(pInput, "whirlpool_64c", 13)) { return comp_push_sym("fwrlpc", dynamic_fwrlpc, pInput+13); }
		if (!strncmp(pInput, "whirlpool_64", 12)) { return comp_push_sym("fwrlp6", dynamic_fwrlp6, pInput+12); }
		if (!strncmp(pInput, "whirlpool", 9)) { return comp_push_sym("fwrlph", dynamic_fwrlph, pInput+9); }
		if (!strncmp(pInput, "WHIRLPOOL", 9)) { return comp_push_sym("fwrlpH", dynamic_fwrlpH, pInput+9); }
	}
	if (!strncasecmp(pInput, "ripemd128", 9)) {
		if (!strncmp(pInput, "ripemd128_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip128r", dynamic_frip128r, pInput+13); }
		if (!strncmp(pInput, "ripemd128_64c", 13)) { return comp_push_sym("frip128c", dynamic_frip128c, pInput+13); }
		if (!strncmp(pInput, "ripemd128_64", 12)) { return comp_push_sym("frip1286", dynamic_frip1286, pInput+12); }
		if (!strncmp(pInput, "ripemd128", 9)) { return comp_push_sym("frip128h", dynamic_frip128h, pInput+9); }
		if (!strncmp(pInput, "RIPEMD128", 9)) { return comp_push_sym("frip128H", dynamic_frip128H, pInput+9); }
	}
	if (!strncasecmp(pInput, "ripemd160", 9)) {
		if (!strncmp(pInput, "ripemd160_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip160r", dynamic_frip160r, pInput+13); }
		if (!strncmp(pInput, "ripemd160_64c", 13)) { return comp_push_sym("frip160c", dynamic_frip160c, pInput+13); }
		if (!strncmp(pInput, "ripemd160_64", 12)) { return comp_push_sym("frip1606", dynamic_frip1606, pInput+12); }
		if (!strncmp(pInput, "ripemd160", 9)) { return comp_push_sym("frip160h", dynamic_frip160h, pInput+9); }
		if (!strncmp(pInput, "RIPEMD160", 9)) { return comp_push_sym("frip160H", dynamic_frip160H, pInput+9); }
	}
	if (!strncasecmp(pInput, "ripemd256", 9)) {
		if (!strncmp(pInput, "ripemd256_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip256r", dynamic_frip256r, pInput+13); }
		if (!strncmp(pInput, "ripemd256_64c", 13)) { return comp_push_sym("frip256c", dynamic_frip256c, pInput+13); }
		if (!strncmp(pInput, "ripemd256_64", 12)) { return comp_push_sym("frip2566", dynamic_frip2566, pInput+12); }
		if (!strncmp(pInput, "ripemd256", 9)) { return comp_push_sym("frip256h", dynamic_frip256h, pInput+9); }
		if (!strncmp(pInput, "RIPEMD256", 9)) { return comp_push_sym("frip256H", dynamic_frip256H, pInput+9); }
	}
	if (!strncasecmp(pInput, "ripemd320", 9)) {
		if (!strncmp(pInput, "ripemd320_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip320r", dynamic_frip320r, pInput+13); }
		if (!strncmp(pInput, "ripemd320_64c", 13)) { return comp_push_sym("frip320c", dynamic_frip320c, pInput+13); }
		if (!strncmp(pInput, "ripemd320_64", 12)) { return comp_push_sym("frip3206", dynamic_frip3206, pInput+12); }
		if (!strncmp(pInput, "ripemd320", 9)) { return comp_push_sym("frip320h", dynamic_frip320h, pInput+9); }
		if (!strncmp(pInput, "RIPEMD320", 9)) { return comp_push_sym("frip320H", dynamic_frip320H, pInput+9); }
	}
	LastTokIsFunc = 0;
	if (!strncmp(pInput, "pad16($p)", 9))   return comp_push_sym("pad16", dynamic_pad16, pInput+9);
	if (!strncmp(pInput, "pad20($p)", 9))   return comp_push_sym("pad20", dynamic_pad20, pInput+9);
	if (!strncmp(pInput, "pad100($p)", 10))  return comp_push_sym("pad100", dynamic_pad100, pInput+10);
	if (!strncmp(pInput, "lc($u)", 6)) return comp_push_sym("u_lc", fpNull, pInput+6);
	if (!strncmp(pInput, "uc($u)", 6)) return comp_push_sym("u_uc", fpNull, pInput+6);
	LastTokIsFunc = 2;
	//if (!strncmp(pInput, "utf16be", 7)) return comp_push_sym("futf16be", dynamic_futf16be, pInput+7);
	if (!strncmp(pInput, "utf16", 5))   return comp_push_sym("futf16", dynamic_futf16, pInput+5);
	LastTokIsFunc = 0;
	return comp_push_sym("X", fpNull, pInput);
}

static void comp_lexi_error(DC_struct *p, const char *pInput, char *msg) {
	int n;
	fprintf(stderr, "Dyna expression syntax error around this part of expression\n");
	fprintf(stderr, "%s\n", p->pExpr);
	n = strlen(p->pExpr)-strlen(pInput);
	if (SymTab[nSyms-1][0] != 'X') n--;
	while (n--) fprintf(stderr, " ");
	fprintf(stderr, "^\n");
	if (SymTab[nSyms-1][0] != 'X') fprintf(stderr, "Invalid token found\n");
	else fprintf(stderr, "%s\n", msg);
	error("exiting now");
}
static char *comp_optimize_expression(const char *pExpr) {
	char *pBuf = (char*)mem_alloc(strlen(pExpr)+1), *p, *p2;
	int n1, n2;
	strcpy(pBuf, pExpr);

	/*
	 * Look for crypt($s) optimziation. At this time, we do not look for SALT_AS_HEX_TO_SALT2 variant.
	 */
	p = strstr(pBuf, "($s)");
	n1 = 0;
	while (p) {
		++n1;
		p = strstr(&p[1], "($s)");
	}
	if (n1) {
		// make sure they are all the same crypt type
		char cpType[48];
		p = strstr(pBuf, "($s)");
		--p;
		while (isalnum(ARCH_INDEX(*p))) --p;
		p2 = cpType;
		++p;
		while (p[-1] != ')' && p2-cpType < sizeof(cpType)-1)
			*p2++ = *p++;
		*p2 = 0;
		p = strstr(pBuf, cpType);
		n2 = 0;
		while (p) {
			++n2;
			p = strstr(&p[1], cpType);
		}
		if (n1 == n2) {
			// ok, all were same hash type.  Now make sure all $s are in crypt($s)
			n2 = 0;
			p = strstr(pBuf, "$s");
			while (p) {
				++n2;
				p = strstr(&p[1], cpType);
			}
			if (n1 == n2) {
				// we can use SALT_AS_HEX
				salt_as_hex_type = mem_alloc(strlen(cpType)+1);
				strcpy(salt_as_hex_type, cpType);
				p = strstr(pBuf, cpType);
				while (p) {
					memcpy(p, "$s", 2);
					memmove(&p[2], &p[strlen(cpType)], strlen(&p[strlen(cpType)])+1);
					p = strstr(p, cpType);
				}

			} else {
				// we could use MGF_SALT_AS_HEX_TO_SALT2
			}
		}
	}
	/*
	 * End of SALT_AS_HEX optimization
	 */

	/*
	 * Look for common sub-expressions  we handle crypt($p), crypt($s.$p) crypt($p.$s)
	 */
	return pBuf;
}
static int comp_do_lexi(DC_struct *p, const char *pInput) {
	int paren = 0;
	pInput = comp_get_symbol(pInput);
	if (LastTokIsFunc != 1)
		error("Error: dynamic hash must start with md4/md5/sha1 and NOT a *_raw version. This expression one does not\n");
	while (SymTab[nSyms-1][0] != 'X') {
		if (LastTokIsFunc) {
			pInput = comp_get_symbol(pInput);
			if (SymTab[nSyms-1][0] != '(')
				comp_lexi_error(p, pInput, "A ( MUST follow one of the hash function names");
			continue;
		}
		if (SymTab[nSyms-1][0] == '(') {
			pInput = comp_get_symbol(pInput);
			if (SymTab[nSyms-1][0] == 'X' || SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == '(' || SymTab[nSyms-1][0] == ')')
				comp_lexi_error(p, pInput, "Invalid token following a ( character");
			++paren;
			continue;
		}
		if (SymTab[nSyms-1][0] == ')') {
			--paren;
			if (*pInput == 0) {
				if (!paren) {
					// expression is VALID and syntax check successful
#ifdef WITH_MAIN
					printf ("The expression checks out as valid\n");
#endif
					return nSyms;
				}
				comp_lexi_error(p, pInput, "Not enough ) characters at end of expression");
			}
			if (paren == 0)
				comp_lexi_error(p, pInput, "Reached the matching ) to the initial ( and there is still more expression left");
			pInput = comp_get_symbol(pInput);
			if (!(SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == ')'))
				comp_lexi_error(p, pInput, "The only things valid to follow a ) char are a . or a )");
			continue;
		}
		if (SymTab[nSyms-1][0] == '.') {
			pInput = comp_get_symbol(pInput);
			if (SymTab[nSyms-1][0] == 'X' || SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == '(' || SymTab[nSyms-1][0] == ')')
				comp_lexi_error(p, pInput, "Invalid token following the . character");
			continue;
		}
		// some string op
		pInput = comp_get_symbol(pInput);
		if (!(SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == ')'))
			comp_lexi_error(p, pInput, "The only things valid to follow a string type are a . or a )");
	}
	return 0;
}
static void push_pcode(const char *v, fpSYM _fpSym) {
	pCode[nCode] = mem_alloc(strlen(v)+1);
	fpCode[nCode] = _fpSym;
	strcpy(pCode[nCode++], v);
}

static void comp_do_parse(int cur, int curend) {
	char *curTok;
	fpSYM fpcurTok;
	if (SymTab[cur][0] == '(' && SymTab[curend][0] == ')') {++cur; --curend; }
	while (cur <= curend) {
		curTok = SymTab[cur];
		fpcurTok = fpSymTab[cur];
		if (*curTok == '.') {
			++cur;
			continue;
		}
		if (strlen(curTok)>1 && (*curTok == 'f' || *curTok == 'F')) {
			int tail, count = 1;
			// find the closing ')' for this function.
			++cur; // skip the function name.  Now cur should point to the ( symbol
			tail = cur;
			while(count) {
				++tail;
				if (SymTab[tail][0] == '(') ++count;
				if (SymTab[tail][0] == ')') --count;
			}
			// output code
			push_pcode("push", dynamic_push);
			//. recursion
			comp_do_parse(cur, tail);
			cur = tail+1;
			// now output right code to do the crypt;
			push_pcode(curTok, fpcurTok);
			continue;
		}
		++cur;
		switch(*curTok) {
			case 's':
				//if (!strcmp(gen_stype, "tohex")) push_pcode("app_sh");
				//else
					push_pcode("app_sh", dynamic_app_sh);
				bNeedS = 1;
				continue;
			case 'p':
			{
				if (!strcmp(curTok, "p"))
					push_pcode("app_p", dynamic_app_p);
				else if (!strcmp(curTok, "pad16"))
					push_pcode("pad16", dynamic_pad16);
				else if (!strcmp(curTok, "pad20"))
					push_pcode("pad20", dynamic_pad20);
				else if (!strcmp(curTok, "pad100"))
					push_pcode("pad100", dynamic_pad100);
				continue;
			}
			case 'S': push_pcode("app_s2", dynamic_app_S); bNeedS2 = 1; continue;
			case 'u':
			{
				bNeedU = 1;
				if (!strcmp(curTok, "u"))
					push_pcode("app_u", dynamic_app_u);
				else if (!strcmp(curTok, "u_lc")) {
					bNeedUlc = 1;
					push_pcode("app_u_lc", dynamic_app_u_lc);
				} else if (!strcmp(curTok, "u_uc")) {
					bNeedUuc = 1;
					push_pcode("app_u_uc", dynamic_app_u_uc);
				}
				continue;
			}
			case '1': push_pcode("app_1", dynamic_app_1); continue;
			case '2': push_pcode("app_2", dynamic_app_2); continue;
			case '3': push_pcode("app_3", dynamic_app_3); continue;
			case '4': push_pcode("app_4", dynamic_app_4); continue;
			case '5': push_pcode("app_5", dynamic_app_5); continue;
			case '6': push_pcode("app_6", dynamic_app_6); continue;
			case '7': push_pcode("app_7", dynamic_app_7); continue;
			case '8': push_pcode("app_8", dynamic_app_8); continue;
			case '9': push_pcode("app_9", dynamic_app_9); continue;
		}
	}
}

static void comp_add_script_line(const char *fmt, ...) {
	//static char *pScriptLines[1024];
	//static int nScriptLines;
	va_list va;
	int len, len2;

	len = strlen(fmt)*2;
	pScriptLines[nScriptLines] = mem_alloc(len+1);
	va_start(va, fmt);
	len2 = vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
#ifdef _MSC_VER  // we should find out about MinGW here!!
	pScriptLines[nScriptLines][len] = 0;
	while (len2 == -1) {
		MEM_FREE(pScriptLines[nScriptLines]);
		len *= 2;
		pScriptLines[nScriptLines] = mem_alloc(len+1);
		va_end(va);
		va_start(va, fmt);
		len2 = vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
		pScriptLines[nScriptLines][len] = 0;
	}
#else
	if (len2 > len) {
		MEM_FREE(pScriptLines[nScriptLines]);
		len = len2+1;
		pScriptLines[nScriptLines] = mem_alloc(len+1);
		va_end(va);
		va_start(va, fmt);
		vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
	}
#endif
	va_end(va);
	++nScriptLines;
}

static char *rand_str(int len) {
	static char tmp[256];
	const char *alpha = "0123456789abcdef";
	char *cp = tmp;
	int i;
	if (len > 255)
		len = 255;
	for (i = 0; i < len; ++i) {
		int j = rand() % 16;
		*cp++ = alpha[j];
	}
	*cp = 0;
	return tmp;
}
// Ported from pass_gen.pl dynamic_run_compiled_pcode() function.
static void build_test_string(DC_struct *p, char **pLine) {
	int i;
	char salt[260];
	dynamic_push();
	*gen_s = 0;
	if (bNeedS) {
		if (nSaltLen > 0)
			strcpy(gen_s, rand_str(nSaltLen));
		else
			strcpy(gen_s, rand_str(8));
	}
	if (bNeedU) {
		strcpy(gen_u, rand_str(8));
		strcpy(gen_ulc, gen_u);
		strlwr(gen_ulc);
		strcpy(gen_uuc, gen_u);
		strupr(gen_uuc);
	}
	if (bNeedS2) {
		strcpy(gen_s2, rand_str(8));
	}
	strcpy(salt, gen_s);
	if (salt_as_hex_type) {
		char tmp[64], *cp;
		strcpy(tmp, salt_as_hex_type);
		cp = strchr(tmp, '(');
		*cp = 0;
		strupr(tmp);
		h = gen_s;
		h_len = strlen(h);
		if (!strcmp(tmp, "MD5")) md5_hex();
		else if (!strcmp(tmp, "MD4")) md4_hex();
		else if (!strcmp(tmp, "SHA1")) sha1_hex();
		else if (!strcmp(tmp, "SHA224")) sha224_hex();
		else if (!strcmp(tmp, "SHA256")) sha256_hex();
		else if (!strcmp(tmp, "SHA384")) sha384_hex();
		else if (!strcmp(tmp, "SHA512")) sha512_hex();
		else if (!strcmp(tmp, "WHIRLPOOL")) whirlpool_hex();
		else if (!strcmp(tmp, "TIGER")) tiger_hex();
		else if (!strcmp(tmp, "RIPEMD128")) ripemd128_hex();
		else if (!strcmp(tmp, "RIPEMD160")) ripemd160_hex();
		else if (!strcmp(tmp, "RIPEMD256")) ripemd256_hex();
		else if (!strcmp(tmp, "RIPEMD320")) ripemd320_hex();
	}
	for (i = 0; i < nCode; ++i)
		fpCode[i]();
	//my $ret = "";
	//if ($gen_needu == 1) { $ret .= "\$dynamic_$gen_num\$$h"; }
	//else { $ret .= "\$dynamic_$gen_num\$$h"; }
	//if ($gen_needs > 0) { $ret .= "\$$gen_soutput"; }
	//if ($gen_needs2 > 0) { if (!defined($gen_stype) || $gen_stype ne "toS2hex") {$ret .= "\$\$2$gen_s2";} }
	//return $ret;
	MEM_FREE(*pLine);
	*pLine = mem_alloc_tiny(strlen(p->pExpr)+strlen(salt)+strlen(gen_Stack[0])+24, 1);
	sprintf(*pLine, "@dynamic=%s@%s", p->pExpr,  gen_Stack[0]);
	if (bNeedS) {
		strcat(*pLine, "$");
		strcat(*pLine, salt);
	}
	if (bNeedU) {
		strcat(*pLine, "$$U");
		strcat(*pLine, gen_u);
	}
	if (bNeedS2) {
		strcat(*pLine, "$$2");
		strcat(*pLine, gen_s2);
	}
	comp_add_script_line("Test=%s:%s\n", *pLine, gen_pw);
	for (i = 0; i < ngen_Stack_max; ++i)
		MEM_FREE(gen_Stack[i]);
	ngen_Stack = ngen_Stack_max = 0;
}

static int parse_expression(DC_struct *p) {
	int i, len;
	char *pExpr, *pScr;
	int salt_hex_len = 0;
	init_static_data();
	// first handle the extra strings
	if (handle_extra_params(p))
		return 1;
	pExpr = comp_optimize_expression(p->pExpr);
	if (!comp_do_lexi(p, pExpr))
		return 1;
	comp_do_parse(0, nSyms-1);
	MEM_FREE(pExpr);

	// Ok, now 'build' the script
	comp_add_script_line("Expression=dynamic=%s\nFlag=MGF_FLAT_BUFFERS\n", p->pExpr);
	if (salt_as_hex_type) {
		char tmp[64], *cp;
		strcpy(tmp, salt_as_hex_type);
		cp = strchr(tmp, '(');
		*cp = 0;
		strupr(tmp);
		comp_add_script_line("Flag=MGF_SALT_AS_HEX_%s\n", tmp);
		if (!strcmp(tmp,"MD5")||!strcmp(tmp,"MD4")||strcmp(tmp,"RIPEMD128")) salt_hex_len = 32;
		if (!strcmp(tmp,"SHA1")||!strcmp(tmp,"RIPEMD160")) salt_hex_len = 40;
		if (!strcmp(tmp,"TIGER")) salt_hex_len = 48;
		if (!strcmp(tmp,"SHA224")) salt_hex_len = 56;
		if (!strcmp(tmp,"SHA256")||!strcmp(tmp,"RIPEMD256")||!strcmp(tmp,"GOST")) salt_hex_len = 64;
		if (!strcmp(tmp,"RIPEMD320")) salt_hex_len = 80;
		if (!strcmp(tmp,"SHA384")) salt_hex_len = 96;
		if (!strcmp(tmp,"SHA512")||!strcmp(tmp,"WHIRLPOOL")) salt_hex_len = 128;
	}
	if (bNeedS) comp_add_script_line("Flag=MGF_SALTED\n");
	if (bNeedS2) comp_add_script_line("Flag=MGF_SALTED2\n");
	if (bNeedU) {
		if (bNeedUuc)
			comp_add_script_line("Flag=MGF_USERNAME_UPCASE\n");
		else if (bNeedUlc)
			comp_add_script_line("Flag=MGF_USERNAME_LOCASE\n");
		else
			comp_add_script_line("Flag=MGF_USERNAME\n");
	}
	for (i = 1; i < 10; ++i) {
		if (Const[i]) {
			comp_add_script_line("Const%d=%s\n", i, Const[i]);
		} else
			break;
	}

	if (compile_debug) {
		for (i = 0; i <nCode; ++i)
			printf ("%s\n", pCode[i]);
	}

	// Build test strings.
	strcpy(gen_pw, "abc");
	build_test_string(p, &p->pLine1);
	strcpy(gen_pw, "john");
	build_test_string(p, &p->pLine2);
	strcpy(gen_pw, "passweird");
	build_test_string(p, &p->pLine3);

	// Ok now run the script
	{
		int x, j, last_push;
		//int inp2_used = 0;
		int salt_len = nSaltLen ? nSaltLen : -32;
		int in_unicode = 0;
		int append_mode = 0;
		int max_inp_len = 110, len_comp = 0;
		int inp1_clean = 0;
		int use_inp1 = 1, use_inp1_again = 0;
		int inp_cnt = 0, ex_cnt = 0, salt_cnt = 0, hash_cnt = 0, flag_utf16 = 0;

		if (bNeedS) {
			comp_add_script_line("SaltLen=%d\n", salt_len);
			if (salt_hex_len)
				salt_len = salt_hex_len;
		} else
			salt_len = 0;
		if (salt_len < 0)
			salt_len *= -1;
		if (!keys_as_input) {
			comp_add_script_line("Func=DynamicFunc__clean_input_kwik\n");
			inp1_clean = 1;
		}
		for (i = 0; i < nCode; ++i) {
			if (pCode[i][0] == 'f' || pCode[i][0] == 'F') {

				if (!inp1_clean && !keys_as_input) {
					comp_add_script_line("Func=DynamicFunc__clean_input_kwik\n");
					inp1_clean = 1;
				}
				//if (!strcasecmp(pCode[i], "futf16be") || !strcasecmp(pCode[i], "futf16")) {
				if (!strcasecmp(pCode[i], "futf16")) {
					if (!in_unicode) {
						in_unicode = 1;
						comp_add_script_line("Func=DynamicFunc__setmode_unicode\n");
					}
					if (!flag_utf16) {
						comp_add_script_line("Flag=MGF_UTF8\n");
						flag_utf16 = 1;
					}
				} else {
					// if final hash, then dont clear the mode to normal
					if (in_unicode && !(!pCode[i+1] || !pCode[i+1][0]))
						comp_add_script_line("Func=DynamicFunc__setmode_normal\n");
					in_unicode = 0;
				}

				// Found next function.  Now back up and load the data
				for (j = i - 1; j >= 0; --j) {
					if (!strcmp(pCode[j], "push")) { // push
						last_push = j;
						use_inp1_again = 0;
						inp_cnt = 0, ex_cnt = 0, salt_cnt = 0, hash_cnt = 0;
						for (x = j+1; x < i; ++x) {
							if (!strcmp(pCode[x], "app_p")) {
								comp_add_script_line("Func=DynamicFunc__append_keys%s\n", use_inp1?"":"2"); ++inp_cnt; }
							else if (!strcmp(pCode[x], "app_s")) {
								comp_add_script_line("Func=DynamicFunc__append_salt%s\n", use_inp1?"":"2"); ++salt_cnt; }
							else if (!strncmp(pCode[x], "app_u", 5)) {
								comp_add_script_line("Func=DynamicFunc__append_userid%s\n", use_inp1?"":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_s2")) {
								comp_add_script_line("Func=DynamicFunc__append_2nd_salt%s\n", use_inp1?"":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_sh")) {
								comp_add_script_line("Func=DynamicFunc__append_salt%s\n", use_inp1?"":"2"); ++salt_cnt; }
							else if (!strcmp(pCode[x], "app_1")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST1\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_2")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST2\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_3")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST3\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_4")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST4\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_5")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST5\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_6")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST6\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_7")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST7\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_8")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST8\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_9")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST9\n", use_inp1?"1":"2"); ++ex_cnt; }
							else if (!strncmp(pCode[x], "IN2", 3)) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_input2\n", use_inp1?"":"2"); ++hash_cnt; }
							else if (!strncmp(pCode[x], "IN1", 3)) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_input\n", use_inp1?"":"2"); ++hash_cnt; }
							else if (!strcmp(pCode[x], "pad16")) {
								comp_add_script_line("Func=DynamicFunc__append_keys_pad16\n"); ++hash_cnt; }
							else if (!strcmp(pCode[x], "pad20")) {
								comp_add_script_line("Func=DynamicFunc__append_keys_pad20\n"); ++hash_cnt; }
							else if (!strcmp(pCode[x], "pad100")) {
								comp_add_script_line("Func=DynamicFunc__set_input_len_100\n"); len_comp += 100; }

							*pCode[x] = 'X';
						}
						if (!last_push || pCode[last_push-1][0] == 'p')
							pCode[last_push][0] = 'X';
						else {
							strcpy(pCode[last_push], "IN2");
							inp1_clean = 0;
							use_inp1_again = 1;
						}

						// Ok, the only thing we can control is salt_len (if not in hex_as_salt), and inp_len
						// all we worry about is inp_len.  256 bytes is MAX.
						len_comp += ex_cnt*24;
						len_comp += inp_cnt*max_inp_len;
						len_comp += salt_cnt*salt_len;
						// add in hash_cnt*whatever_size_hash is.
						if (len_comp > 256) {
							max_inp_len -= (len_comp-256+(inp_cnt-1))/inp_cnt;
						}
						len_comp = 0;
						if (!pCode[i+1] || !pCode[i+1][0]) {
							// final hash
							char endch = pCode[i][strlen(pCode[i])-1];
							if (endch == 'c') {
								comp_add_script_line("Flag=MGF_INPBASE64b\n");
							} else if (endch == '6') {
								comp_add_script_line("Flag=MGF_INPBASE64m\n");
							}
							// check for sha512 has to happen before md5, since both start with f5
							if (!strncasecmp(pCode[i], "f512", 4)) {
								comp_add_script_line("Func=DynamicFunc__SHA512_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_64_BYTE\n");
							} else if (!strncasecmp(pCode[i], "f5", 2))
								comp_add_script_line("Func=DynamicFunc__MD5_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
							else if (!strncasecmp(pCode[i], "f4", 2))
								comp_add_script_line("Func=DynamicFunc__MD4_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
							else if (!strncasecmp(pCode[i], "f1", 2)) {
								comp_add_script_line("Func=DynamicFunc__SHA1_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_20_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "f224", 4)) {
								comp_add_script_line("Func=DynamicFunc__SHA224_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_28_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "f256", 4)) {
								comp_add_script_line("Func=DynamicFunc__SHA256_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_32_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "f384", 4)) {
								comp_add_script_line("Func=DynamicFunc__SHA384_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_48_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "fgost", 5)) {
								comp_add_script_line("Func=DynamicFunc__GOST_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_32_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "ftig", 4)) {
								comp_add_script_line("Func=DynamicFunc__Tiger_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_24_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "fwrl", 4)) {
								comp_add_script_line("Func=DynamicFunc__WHIRLPOOL_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_64_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "frip128", 7))
								comp_add_script_line("Func=DynamicFunc__RIPEMD128_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
							else if (!strncasecmp(pCode[i], "frip160", 7)) {
								comp_add_script_line("Func=DynamicFunc__RIPEMD160_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_20_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "frip256", 7)) {
								comp_add_script_line("Func=DynamicFunc__RIPEMD256_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_32_BYTE\n");
							}
							else if (!strncasecmp(pCode[i], "frip320", 7)) {
								comp_add_script_line("Func=DynamicFunc__RIPEMD320_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2");
								comp_add_script_line("Flag=MGF_INPUT_40_BYTE\n");
							}
						} else {
							if (append_mode) {
								// check for sha512 has to happen before md5, since both start with f5
								if (!strncasecmp(pCode[i], "f512", 4))
									comp_add_script_line("Func=DynamicFunc__SHA512_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f5", 2))
									comp_add_script_line("Func=DynamicFunc__MD5_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f4", 2))
									comp_add_script_line("Func=DynamicFunc__MD4_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f1", 2))
									comp_add_script_line("Func=DynamicFunc__SHA1_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f224", 4))
									comp_add_script_line("Func=DynamicFunc__SHA224_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f256", 4))
									comp_add_script_line("Func=DynamicFunc__SHA256_crypt_input%s_append_input2n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f384", 4))
									comp_add_script_line("Func=DynamicFunc__SHA384_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "fgost", 5))
									comp_add_script_line("Func=DynamicFunc__GOST_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "ftig", 4))
									comp_add_script_line("Func=DynamicFunc__Tiger_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "fwrl", 4))
									comp_add_script_line("Func=DynamicFunc__WHIRLPOOL_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip128", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD128_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip160", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD160_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip256", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD256_crypt_input%s_append_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip320", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD320_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else {
									if (use_inp1 && !use_inp1_again)
										use_inp1_again = 1;
								}
						} else {
								// check for sha512 has to happen before md5, since both start with f5
								if (!strncasecmp(pCode[i], "f512", 4))
									comp_add_script_line("Func=DynamicFunc__SHA512_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f5", 2))
									comp_add_script_line("Func=DynamicFunc__MD5_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f4", 2))
									comp_add_script_line("Func=DynamicFunc__MD4_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f1", 2))
									comp_add_script_line("Func=DynamicFunc__SHA1_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f224", 4))
									comp_add_script_line("Func=DynamicFunc__SHA224_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f256", 4))
									comp_add_script_line("Func=DynamicFunc__SHA256_crypt_input%s_overwrite_input2n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "f384", 4))
									comp_add_script_line("Func=DynamicFunc__SHA384_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "fgost", 5))
									comp_add_script_line("Func=DynamicFunc__GOST_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "ftig", 4))
									comp_add_script_line("Func=DynamicFunc__Tiger_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "fwrl", 4))
									comp_add_script_line("Func=DynamicFunc__WHIRLPOOL_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip128", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD128_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip160", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD160_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip256", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD256_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else if (!strncasecmp(pCode[i], "frip320", 7))
									comp_add_script_line("Func=DynamicFunc__RIPEMD320_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2");
								else {
									if (use_inp1 && !use_inp1_again)
										use_inp1_again = 1;
								}
							}
							use_inp1 = append_mode = 0;
							if (use_inp1_again)
								use_inp1 = 1;
							if (pCode[i+1] && pCode[i+1][0] == 'p') {
								inp1_clean = 0;
								append_mode = 1;
								use_inp1 = 1;
							}
						}
						break;
					}
				}
				pCode[i][0] = 'X';
			}
		}
		if (max_inp_len < 110) {
			comp_add_script_line("MaxInputLenX86=%d\n",max_inp_len);
			comp_add_script_line("MaxInputLen=%d\n",max_inp_len);
		}
	}

	len = i = 0;
	for (i = 0; i < nScriptLines; ++i)
		len += strlen(pScriptLines[i]);
	pScr = mem_alloc_tiny(len+1,1);
	*pScr = 0;
	for (i = 0; i < nScriptLines; ++i)
		strcat(pScr, pScriptLines[i]);
	p->pScript = pScr;

	if (compile_debug) {
		printf("%s\n", p->pScript);
		exit(0);
	}

	return 0;
}

static DC_HANDLE do_compile(const char *expr, uint32_t crc32) {
	DC_struct *p;
	char *cp;
	int len;

	if (!gost_init) {
		gost_init_table();
		gost_init = 1;
	}

	p = mem_calloc_tiny(sizeof(DC_struct), sizeof(void*));
	p->magic = ~DC_MAGIC;
	if (strncmp(expr, "dynamic=", 8))
		return p;
	p->crc32 = crc32;
	p->pFmt = NULL; // not setup yet
	p->pExpr = str_alloc_copy(find_the_expression(expr));
	p->pExtraParams = str_alloc_copy(find_the_extra_params(expr));
	len = strlen(expr)+3;
	cp = mem_calloc_tiny(len, 1);
	snprintf(cp, len, "@%s@", expr);
	p->pSignature = cp;
	if (parse_expression(p)) {
		return p;
	}
	p->magic = DC_MAGIC;

	return p;
}

static uint32_t compute_checksum(const char *expr) {
	uint32_t crc32 = 0xffffffff;
	/* we should 'normalize' the expression 'first' */
	while (*expr) {
		crc32 = jtr_crc32(crc32,*expr);
		++expr;
	}
	return crc32;
}

static DC_HANDLE find_checksum(uint32_t crc32) {
	DC_list *p;
	if (!pList)
		pList = mem_calloc_tiny(sizeof(DC_list), sizeof(void*));
	p = pList->next;
	while (p) {
		if (p->value->crc32 == crc32)
			return p->value;
		p = p->next;
	}
	return 0;
}

static void add_checksum_list(DC_HANDLE pHand) {
	DC_list *p;
	p = mem_calloc_tiny(sizeof(DC_list), sizeof(void*));
	p->next = pList->next;
	pList->next = p;
}

static char *convert_old_dyna_to_new(char *in, char *out, char *expr) {
	char *cp = strchr(&in[1], '$');
	if (!cp)
		return in;
	++cp;
	sprintf(out, "@dynamic=%s@%s", expr, cp);
	return out;
}

char *dynamic_compile_prepare(char *fld1) {
	if (!strncmp(fld1, "$dynamic_", 9)) {
		int num;
		static char Buf[512], tmp1[64];
		if (sscanf(fld1, "$dynamic_%d$", &num) == 1) {
			char *cpExpr=0;
			if (num >= 50 && num < 160) {
				char *type = 0;
				switch (num/10) {
					case 5: type="sha224"; break; // 50-59
					case 6: type="sha256"; break; // 60-69, etc
					case 7: type="sha384"; break;
					case 8: type="sha512"; break;
					case 9: type="gost"; break;
					case 10: type="whirlpool"; break;
					case 11: type="tiger"; break;
					case 12: type="ripemd128"; break;
					case 13: type="ripemd160"; break;
					case 14: type="ripemd256"; break;
					case 15: type="ripemd320"; break;
				}
				switch(num%10) {
					case 0: sprintf(tmp1, "%s($p)", type); break;
					case 1: sprintf(tmp1, "%s($s.$p)", type); break;
					case 2: sprintf(tmp1, "%s($p.$s)", type); break;
					case 3: sprintf(tmp1, "%s(%s($p))", type, type); break;
					case 4: sprintf(tmp1, "%s(%s_raw($p))", type, type); break;
					case 5: sprintf(tmp1, "%s(%s($p).$s)", type, type); break;
					case 6: sprintf(tmp1, "%s($s.%s($p))", type, type); break;
					case 7: sprintf(tmp1, "%s(%s($s).%s($p))", type, type, type); break;
					case 8: sprintf(tmp1, "%s(%s($p).%s($p))", type, type, type); break;
				}
				cpExpr = tmp1;
			} else
			switch(num) {
				case 0: cpExpr = "md5($p)"; break;
				case 1: cpExpr = "md5($p.$s)"; break;
				case 2: cpExpr = "md5(md5($p))"; break;
				case 3: cpExpr = "md5(md5(md5($p)))"; break;
				case 4: cpExpr = "md5($s.$p)"; break;
				case 5: cpExpr = "md5($s.$p.$s)"; break;
				case 6: cpExpr = "md5(md5($p).$s)"; break;
				case 8: cpExpr = "md5(md5($s).$p)"; break;
				case 9: cpExpr = "md5($s.md5($p))"; break;
				case 10: cpExpr = "md5($s.md5($s.$p))"; break;
				case 11: cpExpr = "md5($s.md5($p.$s))"; break;
				case 12: cpExpr = "md5(md5($s).md5($p))"; break;
				case 13: cpExpr = "md5(md5($p).md5($s))"; break;
				case 14: cpExpr = "md5($s.md5($p).$s)"; break;
				case 15: cpExpr = "md5($u.md5($p).$s)"; break;
				case 16: cpExpr = "md5(md5(md5($p).$s).$s2)"; break;
				case 22: cpExpr = "md5(sha1($p))"; break;
				case 23: cpExpr = "sha1(md5($p))"; break;
				case 24: cpExpr = "sha1($p.$s)"; break;
				case 25: cpExpr = "sha1($s.$p)"; break;
				case 26: cpExpr = "sha1($p)"; break;
				case 29: cpExpr = "md5(utf16($p))"; break;
				case 30: cpExpr = "md4($p)"; break;
				case 31: cpExpr = "md4($s.$p)"; break;
				case 32: cpExpr = "md4($p.$s)"; break;
				case 33: cpExpr = "md4(utf16($p))"; break;
				case 34: cpExpr = "md5(md4($p))"; break;
				case 35: cpExpr = "sha1(uc($u).$c1.$p),c1=:"; break;
				case 36: cpExpr = "sha1($u.$c1.$p),c1=:"; break;
				case 37: cpExpr = "sha1(lc($u).$p)"; break;
				case 38: cpExpr = "sha1($s.sha1($s.sha1($p)))"; break;
				case 39: cpExpr = "md5($s.pad16($p)),saltlen=-120"; break;
				case 40: cpExpr = "sha1($s.pad20($p)),saltlen=-120"; break;
				//case 30: cpExpr = ""; break;
				//case 30: cpExpr = ""; break;
				//case 30: cpExpr = ""; break;
			}
			if (cpExpr)
				fld1 = convert_old_dyna_to_new(fld1, Buf, cpExpr);
		}
	}
	return fld1;
}
char *dynamic_compile_split(char *ct) {
	extern int ldr_in_pot;
	if (strncmp(ct, "dynamic_", 8)) {
		return dynamic_compile_prepare(ct);
	} else if (strncmp(ct, "@dynamic=", 9) && strncmp(ct, dyna_signature, dyna_sig_len)) {
		// convert back into dynamic= format
		static char Buf[512];
		sprintf(Buf, "%s%s", dyna_signature, ct);
		ct = Buf;
	} else {
		if (ldr_in_pot == 1 && !strncmp(ct, "@dynamic=", 9)) {
			static char Buf[512], Buf2[512];
			char *cp = strchr(&ct[1], '@');
			if (cp) {
				strcpy(Buf, &cp[1]);
				sprintf(Buf2, "%s%s", dyna_signature, Buf);
				ct = Buf2;
			}
		}
	}
	// ok, now 'normalize' the hash if it is dynamic= hash.
	ct = dynamic_expr_normalize(ct);
	return ct;
}

int dynamic_assign_script_to_format(DC_HANDLE H, struct fmt_main *pFmt) {
	if (!((DC_struct*)H) || ((DC_struct*)H)->magic != DC_MAGIC)
		return -1;
	dyna_script = ((DC_struct*)H)->pScript;
	dyna_signature = ((DC_struct*)H)->pSignature;
	dyna_line1 = ((DC_struct*)H)->pLine1;
	dyna_line2 = ((DC_struct*)H)->pLine2;
	dyna_line3 = ((DC_struct*)H)->pLine3;
	dyna_sig_len = strlen(dyna_signature);
	((DC_struct*)H)->pFmt = pFmt;
	return 0;
}
void dynamic_compile_done() {
	init_static_data(); /* this will free all allocated crap */
}
#ifdef WITH_MAIN
int ldr_in_pot = 0;
int main(int argc, char **argv) {
		DC_HANDLE p;
		DC_struct *p2;
		int ret;

		CRC32_Init_tab();
		compile_debug = 1;
		printf("processing this expression: %s\n\n", argv[1]);
		ret = dynamic_compile(argv[1], &p);
		p2 = (DC_struct *)p;
		if (ret || !p2->pScript) return !!printf ("Error, null script variable\n");

		printf("Script:\n-------------\n%s\n\n", p2->pScript);
		printf("Expression:  %s\n", p2->pExpr);
		printf("ExtraParams: %s\n", p2->pExtraParams);
		printf("Signature:   %s\n", p2->pSignature);
		printf("Test Line:   %s\n", p2->pLine1);
		printf("Test Line:   %s\n", p2->pLine2);
		printf("Test Line:   %s\n", p2->pLine3);
		printf("crc32:       %08x\n", p2->crc32);
		if (nConst) {
			int i;
			for (i = 1; i <= nConst; ++i)
				printf("Const%d:      %s\n", i, Const[i]);
		}
}
#endif

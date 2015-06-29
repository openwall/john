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
 *     md5_64(EXPR) This one returns mime base-64, BUT does not pad the last group
 *     with '=' characters
 *
 *     md5_64e(EXPR)  This one returns mime base-64, and pads final group with '='
 *     if needed, to get to an even 4 byte length.
 *
 *     md5u This one encodes input in UTF-16LE and returns results in lower case hex.
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
 */

#include "arch.h"
#include <ctype.h>
#include <stdarg.h>
#include "common.h"
#include "stdint.h"
#include "formats.h"
#include "list.h"
#include "crc32.h"
#include "dynamic_compiler.h"
#include "base64_convert.h"
#include "memdbg.h"
#include "md5.h"
#include "md4.h"
#include "sha2.h"

typedef struct DC_list {
	struct DC_list *next;
	DC_struct *value;
} DC_list;

const char *dyna_script="Expression=dynamic=md5($p)\nFlag=MGF_KEYS_INPUT\nFunc=DynamicFunc__crypt_md5\nTest=@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72:abc";
const char *dyna_signature="@dynamic=md5($p)@";
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
static int bNeedS, bNeedS2, bNeedU;
static char *salt_as_hex_type;
static int keys_as_input;
static char *gen_Stack[1024];
static int ngen_Stack, ngen_Stack_max;
static char *h;
static char gen_s[260], gen_s2[16], gen_u[16], gen_pw[16], gen_pwlc[16], gen_pwuc[16], gen_conv[260];

void md5_hex() { MD5_CTX c; MD5_Init(&c); MD5_Update(&c, h, strlen(h)); MD5_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void md4_hex() { MD4_CTX c; MD4_Init(&c); MD4_Update(&c, h, strlen(h)); MD4_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void sha1_hex(){ SHA_CTX c; SHA1_Init(&c); SHA1_Update(&c, h, strlen(h)); SHA1_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void md5_base64() { MD5_CTX c; MD5_Init(&c); MD5_Update(&c, h, strlen(h)); MD5_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}
void md4_base64() { MD4_CTX c; MD4_Init(&c); MD4_Update(&c, h, strlen(h)); MD4_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,16,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}
void sha1_base64(){ SHA_CTX c; SHA1_Init(&c); SHA1_Update(&c, h, strlen(h)); SHA1_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,20,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}
void sha224_hex()   { SHA256_CTX c; SHA224_Init(&c); SHA224_Update(&c, h, strlen(h)); SHA224_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,28,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void sha224_base64(){ SHA256_CTX c; SHA224_Init(&c); SHA224_Update(&c, h, strlen(h)); SHA224_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,28,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}
void sha256_hex()   { SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, h, strlen(h)); SHA256_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void sha256_base64(){ SHA256_CTX c; SHA256_Init(&c); SHA256_Update(&c, h, strlen(h)); SHA256_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}
void sha384_hex()   { SHA512_CTX c; SHA384_Init(&c); SHA384_Update(&c, h, strlen(h)); SHA384_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,48,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void sha384_base64(){ SHA512_CTX c; SHA384_Init(&c); SHA384_Update(&c, h, strlen(h)); SHA384_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,48,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}
void sha512_hex()   { SHA512_CTX c; SHA512_Init(&c); SHA512_Update(&c, h, strlen(h)); SHA512_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_hex,260,0); strcpy(h, gen_conv);}
void sha512_base64(){ SHA512_CTX c; SHA512_Init(&c); SHA512_Update(&c, h, strlen(h)); SHA512_Final((unsigned char*)h, &c); base64_convert(h,e_b64_raw,64,gen_conv,e_b64_mime,260,0); strcpy(h, gen_conv);}

void fpNull(){}
void dynamic_push()   { char *p = mem_calloc(260, 1); MEM_FREE(gen_Stack[ngen_Stack]); gen_Stack[ngen_Stack++] = p; ngen_Stack_max++; }
//void dynamic_pop    { return pop @gen_Stack; }  # not really needed.
void dynamic_app_s()  { strcat(gen_Stack[ngen_Stack-1], gen_s); }
void dynamic_app_sh() { strcat(gen_Stack[ngen_Stack-1], gen_s); } //md5_hex($gen_s); }
void dynamic_app_S()  { strcat(gen_Stack[ngen_Stack-1], gen_s2); }
void dynamic_app_u()  { strcat(gen_Stack[ngen_Stack-1], gen_u); }
void dynamic_app_p()  { strcat(gen_Stack[ngen_Stack-1], gen_pw); }
void dynamic_app_pU() { strcat(gen_Stack[ngen_Stack-1], gen_pwuc); }
void dynamic_app_pL() { strcat(gen_Stack[ngen_Stack-1], gen_pwlc); }
void dynamic_app_1()  { strcat(gen_Stack[ngen_Stack-1], Const[1]); }
void dynamic_app_2()  { strcat(gen_Stack[ngen_Stack-1], Const[2]); }
void dynamic_app_3()  { strcat(gen_Stack[ngen_Stack-1], Const[3]); }
void dynamic_app_4()  { strcat(gen_Stack[ngen_Stack-1], Const[4]); }
void dynamic_app_5()  { strcat(gen_Stack[ngen_Stack-1], Const[5]); }
void dynamic_app_6()  { strcat(gen_Stack[ngen_Stack-1], Const[6]); }
void dynamic_app_7()  { strcat(gen_Stack[ngen_Stack-1], Const[7]); }
void dynamic_app_8()  { strcat(gen_Stack[ngen_Stack-1], Const[8]); }
void dynamic_app_9()  { strcat(gen_Stack[ngen_Stack-1], Const[9]); }
//void dynamic_ftr32  { $h = pop @gen_Stack; $h = substr($h,0,32);  strcat(gen_Stack[ngen_Stack-1], h);  }
/////void dynamic_f54    { $h = pop @gen_Stack; $h = md5_hex(h)."00000000";	 strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f5h()    { h = gen_Stack[--ngen_Stack]; md5_hex();  strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f1h()    { h = gen_Stack[--ngen_Stack]; sha1_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f4h()    { h = gen_Stack[--ngen_Stack]; md4_hex();  strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f5H()    { h = gen_Stack[--ngen_Stack]; md5_hex();	strupr(h); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f1H()    { h = gen_Stack[--ngen_Stack]; sha1_hex(); strupr(h); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f4H()    { h = gen_Stack[--ngen_Stack]; md4_hex();  strupr(h); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f56()    { h = gen_Stack[--ngen_Stack]; md5_base64();	 strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f16()    { h = gen_Stack[--ngen_Stack]; sha1_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f46()    { h = gen_Stack[--ngen_Stack]; md4_base64();  strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f5e()    { h = gen_Stack[--ngen_Stack]; md5_base64();  while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f1e()    { h = gen_Stack[--ngen_Stack]; sha1_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f4e()    { h = gen_Stack[--ngen_Stack]; md4_base64();  while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f5u()    { h = gen_Stack[--ngen_Stack]; md5_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f1u()    { h = gen_Stack[--ngen_Stack]; sha1_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f4u()    { h = gen_Stack[--ngen_Stack]; md4_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f5r()    { h = gen_Stack[--ngen_Stack]; md5();  strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f1r()    { h = gen_Stack[--ngen_Stack]; sha1(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f4r()    { h = gen_Stack[--ngen_Stack]; md4();  strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f224h()  { h = gen_Stack[--ngen_Stack]; sha224_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f224H()  { h = gen_Stack[--ngen_Stack]; sha224_hex(); strupr(h);strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f2246()  { h = gen_Stack[--ngen_Stack]; sha224_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f224e()  { h = gen_Stack[--ngen_Stack]; sha224_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f224u()  { h = gen_Stack[--ngen_Stack]; sha224_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f224r()  { h = gen_Stack[--ngen_Stack]; sha224(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f256h()  { h = gen_Stack[--ngen_Stack]; sha256_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f256H()  { h = gen_Stack[--ngen_Stack]; sha256_hex(); strupr(h);strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f2566()  { h = gen_Stack[--ngen_Stack]; sha256_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f256e()  { h = gen_Stack[--ngen_Stack]; sha256_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f256u()  { h = gen_Stack[--ngen_Stack]; sha256_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f256r()  { h = gen_Stack[--ngen_Stack]; sha256(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f384h()  { h = gen_Stack[--ngen_Stack]; sha384_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f384H()  { h = gen_Stack[--ngen_Stack]; sha384_hex(); strupr(h);strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f3846()  { h = gen_Stack[--ngen_Stack]; sha384_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f384e()  { h = gen_Stack[--ngen_Stack]; sha384_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f384u()  { h = gen_Stack[--ngen_Stack]; sha384_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f384r()  { h = gen_Stack[--ngen_Stack]; sha384(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f512h()  { h = gen_Stack[--ngen_Stack]; sha512_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f512H()  { h = gen_Stack[--ngen_Stack]; sha512_hex(); strupr(h);strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f5126()  { h = gen_Stack[--ngen_Stack]; sha512_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
void dynamic_f512e()  { h = gen_Stack[--ngen_Stack]; sha512_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f512u()  { h = gen_Stack[--ngen_Stack]; sha512_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_f512r()  { h = gen_Stack[--ngen_Stack]; sha512(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fgosth() { h = gen_Stack[--ngen_Stack]; gost_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fgostH() { h = gen_Stack[--ngen_Stack]; uc gost_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fgost6() { h = gen_Stack[--ngen_Stack]; gost_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fgoste() { h = gen_Stack[--ngen_Stack]; gost_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fgostu() { h = gen_Stack[--ngen_Stack]; gost_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fgostr() { h = gen_Stack[--ngen_Stack]; gost(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fwrlph() { h = gen_Stack[--ngen_Stack]; whirlpool_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fwrlpH() { h = gen_Stack[--ngen_Stack]; uc whirlpool_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fwrlp6() { h = gen_Stack[--ngen_Stack]; whirlpool_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fwrlpe() { h = gen_Stack[--ngen_Stack]; whirlpool_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fwrlpu() { h = gen_Stack[--ngen_Stack]; whirlpool_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fwrlpr() { h = gen_Stack[--ngen_Stack]; whirlpool(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_ftigh()  { h = gen_Stack[--ngen_Stack]; tiger_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_ftigH()  { h = gen_Stack[--ngen_Stack]; uc tiger_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_ftig6()  { h = gen_Stack[--ngen_Stack]; tiger_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_ftige()  { h = gen_Stack[--ngen_Stack]; tiger_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_ftigu()  { h = gen_Stack[--ngen_Stack]; tiger_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_ftigr()  { h = gen_Stack[--ngen_Stack]; tiger(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip128h()  { h = pop @gen_Stack; $h = ripemd128_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip128H()  { h = pop @gen_Stack; $h = uc ripemd128_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip1286()  { h = pop @gen_Stack; $h = ripemd128_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip128e()  { h = pop @gen_Stack; $h = ripemd128_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip128u()  { h = pop @gen_Stack; $h = ripemd128_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip128r()  { h = pop @gen_Stack; $h = ripemd128(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip160h()  { h = pop @gen_Stack; $h = ripemd160_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip160H()  { h = pop @gen_Stack; $h = uc ripemd160_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip1606()  { h = pop @gen_Stack; $h = ripemd160_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip160e()  { h = pop @gen_Stack; $h = ripemd160_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip160u()  { h = pop @gen_Stack; $h = ripemd160_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip160r()  { h = pop @gen_Stack; $h = ripemd160(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip256h()  { h = pop @gen_Stack; $h = ripemd256_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip256H()  { h = pop @gen_Stack; $h = uc ripemd256_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip2566()  { h = pop @gen_Stack; $h = ripemd256_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip256e()  { h = pop @gen_Stack; $h = ripemd256_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip256u()  { h = pop @gen_Stack; $h = ripemd256_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip256r()  { h = pop @gen_Stack; $h = ripemd256(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip320h()  { h = pop @gen_Stack; $h = ripemd320_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip320H()  { h = pop @gen_Stack; $h = uc ripemd320_hex(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip3206()  { h = pop @gen_Stack; $h = ripemd320_base64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip320e()  { h = pop @gen_Stack; $h = ripemd320_base64(); while (strlen(h)%4) { strcat(h,"="); } strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip320u()  { h = pop @gen_Stack; $h = ripemd320_hex(encode("UTF-16LE",$h)); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_frip320r()  { h = pop @gen_Stack; $h = ripemd320(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fpad16() { h = gen_Stack[--ngen_Stack]; $h = pad16(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fpad20() { h = gen_Stack[--ngen_Stack]; $h = pad20(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fpad100(){ h = gen_Stack[--ngen_Stack]; $h = pad100(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_fpadmd64() { h = gen_Stack[--ngen_Stack]; $h = pad_md64(); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_futf16()  { h = gen_Stack[--ngen_Stack]; $h = encode("UTF-16LE",$h); strcat(gen_Stack[ngen_Stack-1], h);  }
//void dynamic_futf16be(){ h = gen_Stack[--ngen_Stack]; $h = encode("UTF-16BE",$h); strcat(gen_Stack[ngen_Stack-1], h);  }

static void init_static_data() {
	int i;
	nConst = 0;
	for (i = 0; i < nSyms; ++i)
		MEM_FREE(SymTab[i]);
	for (i = 1; i < 10; ++i) {
		if (Const[i]);
		free((char*)(Const[i]));
		Const[i] = NULL;
	}
	for (i = 0; i < nCode; ++i)
		MEM_FREE(pCode[i]);
	for (i = 0; i < nScriptLines; ++i)
		MEM_FREE(pScriptLines[1]);
	for (i = 0; i < ngen_Stack; ++i)
		MEM_FREE(gen_Stack[i]);
	ngen_Stack = ngen_Stack_max = 0;
	nCode = 0;
	nSyms = 0;
	nScriptLines = 0;
	LastTokIsFunc = 0;
	keys_as_input = 0;
	bNeedS = bNeedS2 = bNeedU = 0;
	MEM_FREE(salt_as_hex_type);
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
		//if (!strncmp(pInput, "md5u", 4)) { return comp_push_sym("f5u", dynamic_f5u, pInput+4); }
		//if (!strncmp(pInput, "md5_raw", 7)) { LastTokIsFunc = 2; return comp_push_sym("f5r", dynamic_f5r, pInput+7); }
		if (!strncmp(pInput, "md5_64e", 7)) { return comp_push_sym("f5e", dynamic_f5e, pInput+7); }
		if (!strncmp(pInput, "md5_64", 6)) { return comp_push_sym("f56", dynamic_f56, pInput+6); }
		if (!strncmp(pInput, "md5", 3)) { return comp_push_sym("f5h", dynamic_f5h, pInput+3); }
		if (!strncmp(pInput, "MD5", 3)) { return comp_push_sym("f5H", dynamic_f5H, pInput+3); }
	}
	if (!strncasecmp(pInput, "md4", 3)) {
		//if (!strncmp(pInput, "md4u", 4)) { return comp_push_sym("f4u", dynamic_f4u, pInput+4); }
		//if (!strncmp(pInput, "md4_raw", 7)) { LastTokIsFunc = 2; return comp_push_sym("f4r", dynamic_f4r, pInput+7); }
		if (!strncmp(pInput, "md4_64e", 7)) { return comp_push_sym("f4e", dynamic_f4e, pInput+7); }
		if (!strncmp(pInput, "md4_64", 6)) { return comp_push_sym("f46", dynamic_f46, pInput+6); }
		if (!strncmp(pInput, "md4", 3)) { return comp_push_sym("f4h", dynamic_f4h, pInput+3); }
		if (!strncmp(pInput, "MD4", 3)) { return comp_push_sym("f4H", dynamic_f4H, pInput+3); }
	}
	if (!strncasecmp(pInput, "sha1", 4)) {
		//if (!strncmp(pInput, "sha1u", 5)) { return comp_push_sym("f1u", dynamic_, pInput+5); }
		//if (!strncmp(pInput, "sha1_raw", 8)) { LastTokIsFunc = 2; return comp_push_sym("f1r", dynamic_, pInput+8); }
		if (!strncmp(pInput, "sha1_64e", 8)) { return comp_push_sym("f1e", dynamic_f1e, pInput+8); }
		if (!strncmp(pInput, "sha1_64", 7)) { return comp_push_sym("f16", dynamic_f16, pInput+7); }
		if (!strncmp(pInput, "sha1", 4)) { return comp_push_sym("f1h", dynamic_f1h, pInput+4); }
		if (!strncmp(pInput, "SHA1", 4)) { return comp_push_sym("f1H", dynamic_f1H, pInput+4); }
	}
	if (!strncasecmp(pInput, "sha224", 6)) {
		//if (!strncmp(pInput, "sha224u", 7)) { return comp_push_sym("f224u", dynamic_f224u, pInput+7); }
		//if (!strncmp(pInput, "sha224_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f224r", dynamic_f224r, pInput+10); }
		if (!strncmp(pInput, "sha224_64e", 10)) { return comp_push_sym("f224e", dynamic_f224e, pInput+10); }
		if (!strncmp(pInput, "sha224_64", 9)) { return comp_push_sym("f2246", dynamic_f2246, pInput+9); }
		if (!strncmp(pInput, "sha224", 6)) { return comp_push_sym("f224h", dynamic_f224h, pInput+6); }
		if (!strncmp(pInput, "SHA224", 6)) { return comp_push_sym("f224H", dynamic_f224H, pInput+6); }
	}
	if (!strncasecmp(pInput, "sha256", 6)) {
		//if (!strncmp(pInput, "sha256u", 7)) { return comp_push_sym("f256u", dynamic_f256u, pInput+7); }
		//if (!strncmp(pInput, "sha256_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f256r", dynamic_f256r, pInput+10); }
		if (!strncmp(pInput, "sha256_64e", 10)) { return comp_push_sym("f256e", dynamic_f256e, pInput+10); }
		if (!strncmp(pInput, "sha256_64", 9)) { return comp_push_sym("f2566", dynamic_f2566, pInput+9); }
		if (!strncmp(pInput, "sha256", 6)) { return comp_push_sym("f256h", dynamic_f256h, pInput+6); }
		if (!strncmp(pInput, "SHA256", 6)) { return comp_push_sym("f256H", dynamic_f256H, pInput+6); }
	}
	if (!strncasecmp(pInput, "sha384", 6)) {
		//if (!strncmp(pInput, "sha384u", 7)) { return comp_push_sym("f384u", dynamic_f384u, pInput+7); }
		//if (!strncmp(pInput, "sha384_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f384r", dynamic_f384r, pInput+10); }
		if (!strncmp(pInput, "sha384_64e", 10)) { return comp_push_sym("f384e", dynamic_f384e, pInput+10); }
		if (!strncmp(pInput, "sha384_64", 9)) { return comp_push_sym("f3846", dynamic_f3846, pInput+9); }
		if (!strncmp(pInput, "sha384", 6)) { return comp_push_sym("f384h", dynamic_f384h, pInput+6); }
		if (!strncmp(pInput, "SHA384", 6)) { return comp_push_sym("f384H", dynamic_f384H, pInput+6); }
	}
	if (!strncasecmp(pInput, "sha512", 6)) {
		//if (!strncmp(pInput, "sha512u", 7)) { return comp_push_sym("f512u", dynamic_f512u, pInput+7); }
		//if (!strncmp(pInput, "sha512_raw", 10)) { LastTokIsFunc = 2; return comp_push_sym("f512r", dynamic_f512r, pInput+10); }
		if (!strncmp(pInput, "sha512_64e", 10)) { return comp_push_sym("f512e", dynamic_f512e, pInput+10); }
		if (!strncmp(pInput, "sha512_64", 9)) { return comp_push_sym("f5126", dynamic_f5126, pInput+9); }
		if (!strncmp(pInput, "sha512", 6)) { return comp_push_sym("f512h", dynamic_f512h, pInput+6); }
		if (!strncmp(pInput, "SHA512", 6)) { return comp_push_sym("f512H", dynamic_f512H, pInput+6); }
	}
	//if (!strncasecmp(pInput, "gost", 4)) {
	//	if (!strncmp(pInput, "gostu", 5)) { return comp_push_sym("fgostu", pInput+5); }
	//	if (!strncmp(pInput, "gost_raw", 8)) { LastTokIsFunc = 2; return comp_push_sym("fgostr", pInput+8); }
	//	if (!strncmp(pInput, "gost_64e", 8)) { return comp_push_sym("fgoste", pInput+8); }
	//	if (!strncmp(pInput, "gost_64", 7)) { return comp_push_sym("fgost6", pInput+7); }
	//	if (!strncmp(pInput, "gost", 4)) { return comp_push_sym("fgosth", pInput+4); }
	//	if (!strncmp(pInput, "GOST", 4)) { return comp_push_sym("fgostH", pInput+4); }
	//}
	//if (!strncasecmp(pInput, "tiger", 5)) {
	//	if (!strncmp(pInput, "tigeru", 6)) { return comp_push_sym("ftigu", pInput+6); }
	//	if (!strncmp(pInput, "tiger_raw", 9)) { LastTokIsFunc = 2; return comp_push_sym("ftigr", pInput+9); }
	//	if (!strncmp(pInput, "tiger_64e", 9)) { return comp_push_sym("ftige", pInput+9); }
	//	if (!strncmp(pInput, "tiger_64", 8)) { return comp_push_sym("ftig6", pInput+8); }
	//	if (!strncmp(pInput, "tiger", 5)) { return comp_push_sym("ftigh", pInput+5); }
	//	if (!strncmp(pInput, "TIGER", 5)) { return comp_push_sym("ftigH", pInput+5); }
	//}
	//if (!strncasecmp(pInput, "whirlpool", 9)) {
	//	if (!strncmp(pInput, "whirlpoolu", 10)) { return comp_push_sym("fwrlpu", pInput+10); }
	//	if (!strncmp(pInput, "whirlpool_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("fwrlpr", pInput+13); }
	//	if (!strncmp(pInput, "whirlpool_64e", 13)) { return comp_push_sym("fwrlpe", pInput+13); }
	//	if (!strncmp(pInput, "whirlpool_64", 12)) { return comp_push_sym("fwrlp6", pInput+12); }
	//	if (!strncmp(pInput, "whirlpool", 9)) { return comp_push_sym("fwrlph", pInput+9); }
	//	if (!strncmp(pInput, "WHIRLPOOL", 9)) { return comp_push_sym("fwrlpH", pInput+9); }
	//}
	//if (!strncasecmp(pInput, "ripemd128", 9)) {
	//	if (!strncmp(pInput, "ripemd128u", 10)) { return comp_push_sym("frip128u", pInput+10); }
	//	if (!strncmp(pInput, "ripemd128_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip128r", pInput+13); }
	//	if (!strncmp(pInput, "ripemd128_64e", 13)) { return comp_push_sym("frip128e", pInput+13); }
	//	if (!strncmp(pInput, "ripemd128_64", 12)) { return comp_push_sym("frip1286", pInput+12); }
	//	if (!strncmp(pInput, "ripemd128", 9)) { return comp_push_sym("frip128h", pInput+9); }
	//	if (!strncmp(pInput, "RIPEMD128", 9)) { return comp_push_sym("frip128H", pInput+9); }
	//}
	//if (!strncasecmp(pInput, "ripemd160", 9)) {
	//	if (!strncmp(pInput, "ripemd160u", 10)) { return comp_push_sym("frip160u", pInput+10); }
	//	if (!strncmp(pInput, "ripemd160_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip160r", pInput+13); }
	//	if (!strncmp(pInput, "ripemd160_64e", 13)) { return comp_push_sym("frip160e", pInput+13); }
	//	if (!strncmp(pInput, "ripemd160_64", 12)) { return comp_push_sym("frip1606", pInput+12); }
	//	if (!strncmp(pInput, "ripemd160", 9)) { return comp_push_sym("frip160h", pInput+9); }
	//	if (!strncmp(pInput, "RIPEMD160", 9)) { return comp_push_sym("frip160H", pInput+9); }
	//}
	//if (!strncasecmp(pInput, "ripemd256", 9)) {
	//	if (!strncmp(pInput, "ripemd256u", 10)) { return comp_push_sym("frip256u", pInput+10); }
	//	if (!strncmp(pInput, "ripemd256_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip256r", pInput+13); }
	//	if (!strncmp(pInput, "ripemd256_64e", 13)) { return comp_push_sym("frip256e", pInput+13); }
	//	if (!strncmp(pInput, "ripemd256_64", 12)) { return comp_push_sym("frip2566", pInput+12); }
	//	if (!strncmp(pInput, "ripemd256", 9)) { return comp_push_sym("frip256h", pInput+9); }
	//	if (!strncmp(pInput, "RIPEMD256", 9)) { return comp_push_sym("frip256H", pInput+9); }
	//}
	//if (!strncasecmp(pInput, "ripemd320", 9)) {
	//	if (!strncmp(pInput, "ripemd320u", 10)) { return comp_push_sym("frip320u", pInput+10); }
	//	if (!strncmp(pInput, "ripemd320_raw", 13)) { LastTokIsFunc = 2; return comp_push_sym("frip320r", pInput+13); }
	//	if (!strncmp(pInput, "ripemd320_64e", 13)) { return comp_push_sym("frip320e", pInput+13); }
	//	if (!strncmp(pInput, "ripemd320_64", 12)) { return comp_push_sym("frip3206", pInput+12); }
	//	if (!strncmp(pInput, "ripemd320", 9)) { return comp_push_sym("frip320h", pInput+9); }
	//	if (!strncmp(pInput, "RIPEMD320", 9)) { return comp_push_sym("frip320H", pInput+9); }
	//}
	LastTokIsFunc=2;
	//if (!strncmp(pInput, "pad16", 5)) return comp_push_sym("Fpad16", dynamic_fpad16, pInput+5);
	//if (!strncmp(pInput, "pad20", 5)) return comp_push_sym("Fpad20", dynamic_fpad20, pInput+5);
	//if (!strncmp(pInput, "pad100", 6)) return comp_push_sym("Fpad100", dynamic_fpad100, pInput+6);
	//if (!strncmp(pInput, "padm64", 6)) return comp_push_sym("Fpadm64", dynamic_fpadmd64, pInput+6);
	//if (!strncmp(pInput, "utf16be", 7)) return comp_push_sym("Futf16be", dynamic_futf16, pInput+7);
	//if (!strncmp(pInput, "utf16", 5)) return comp_push_sym("Futf16", dynamic_futf16be, pInput+5);
	LastTokIsFunc=0;
	return comp_push_sym("X", fpNull, pInput);
}

void comp_lexi_error(DC_struct *p, const char *pInput, char *msg) {
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
char *comp_optimize_expression(const char *pExpr) {
	char *pBuf = (char*)mem_alloc(strlen(pExpr)+1), *p, *p2;
	int n1, n2;
	strcpy(pBuf, pExpr);

	/*
	 * Look for crypt($s) optimziation. At this time, we do not look for SALT_AS_HEX_TO_SALT2 variant.
	 */
	p = strstr(pBuf, "($s)");
	n1=0;
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
		error("Error: dynamic hash must start with md4/md5/sha1, etc, this one does not\n");
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
			int tail, count=1;
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
			case 'p': push_pcode("app_p", dynamic_app_p); continue;
			case 'S': push_pcode("app_s2", dynamic_app_S); bNeedS2 = 1; continue;
			case 'u': push_pcode("app_u", dynamic_app_u); bNeedU = 1; continue;
			default:
			{
				char tmp[8];
				sprintf(tmp, "app_%c", *curTok);
				push_pcode(tmp, fpcurTok);
				continue;
			}
		}
	}
}

void comp_add_script_line(const char *fmt, ...) {
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
		len2 = vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
		pScriptLines[nScriptLines][len] = 0;
	}
#else
	if (len2 > len) {
		MEM_FREE(pScriptLines[nScriptLines]);
		len = len2+1;
		pScriptLines[nScriptLines] = mem_alloc(len+1);
		vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
	}
#endif
	va_end(va);
	++nScriptLines;
}

char *rand_str(int len) {
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
	char salt[48];
	dynamic_push();
	*gen_s = 0;
	if (bNeedS)
		strcpy(gen_s, rand_str(8));
	strcpy(salt, gen_s);
	if (salt_as_hex_type) {
		char tmp[64], *cp;
		strcpy(tmp, salt_as_hex_type);
		cp = strchr(tmp, '(');
		*cp = 0;
		strupr(tmp);
		h = gen_s;
		if (!strcmp(tmp, "MD5")) md5_hex();
		else if (!strcmp(tmp, "MD4")) md4_hex();
		else if (!strcmp(tmp, "SHA1")) sha1_hex();
		else if (!strcmp(tmp, "SHA224")) sha224_hex();
		else if (!strcmp(tmp, "SHA256")) sha256_hex();
		else if (!strcmp(tmp, "SHA384")) sha384_hex();
		else if (!strcmp(tmp, "SHA512")) sha512_hex();
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
	*pLine = mem_alloc(strlen(p->pExpr)+strlen(salt)+strlen(gen_Stack[0])+24);
	sprintf(*pLine, "@dynamic=%s@%s", p->pExpr,  gen_Stack[0]);
	if (bNeedS) {
		strcat(*pLine, "$");
		strcat(*pLine, salt);
	}
	comp_add_script_line("Test=%s:%s\n", *pLine, gen_pw);
	for (i = 0; i < ngen_Stack_max; ++i)
		MEM_FREE(gen_Stack[i]);
	ngen_Stack = ngen_Stack_max = 0;
}

static int parse_expression(DC_struct *p) {
	int i, len;
	char *pExpr, *pScr;
	int salt_hex_len=0;
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
		if (!strcmp(tmp,"MD5")||!strcmp(tmp,"MD4")||strcmp(tmp,"RIPEMD128")) salt_hex_len=32;
		if (!strcmp(tmp,"SHA1")||!strcmp(tmp,"RIPEMD160")) salt_hex_len=40;
		if (!strcmp(tmp,"TIGER")) salt_hex_len=48;
		if (!strcmp(tmp,"SHA224")) salt_hex_len=56;
		if (!strcmp(tmp,"SHA256")||!strcmp(tmp,"RIPEMD256")||!strcmp(tmp,"GOST")) salt_hex_len=64;
		if (!strcmp(tmp,"RIPEMD320")) salt_hex_len=80;
		if (!strcmp(tmp,"SHA384")) salt_hex_len=96;
		if (!strcmp(tmp,"SHA512")||!strcmp(tmp,"WHIRLPOOL")) salt_hex_len=128;
	}
	if (bNeedS) comp_add_script_line("Flag=MGF_SALTED\n");
	if (bNeedS2) comp_add_script_line("Flag=MGF_SALTED2\n");
	if (bNeedU) comp_add_script_line("Flag=MGF_USERNAME\n");
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
		//int inp2_used=0;
		int salt_len=32;
		int max_inp_len=110, len_comp;
		int inp1_clean = 0; //, inp2_clean = 0;
		int inp_cnt=0, ex_cnt=0, salt_cnt=0, hash_cnt=0;

		if (salt_hex_len)
			salt_len=salt_hex_len;
		else {
			// if salt_len from command line, add it:
			comp_add_script_line("SaltLen=%d\n", salt_len);
		}
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
				if (!strcasecmp(pCode[i], "utf16be") || !strcasecmp(pCode[i], "utf16"))
					// NOTE, utf16be not handled.
					comp_add_script_line("Func=DynamicFunc__setmode_unicode\n");

				// Found next function.  Now back up and load the data
				for (j = i-1; j>=0; --j) {
					if (pCode[j][0] == 'p') { // push
						last_push = j;
						inp_cnt=0, ex_cnt=0, salt_cnt=0, hash_cnt=0;
						for (x = j+1; x < i; ++x) {
							if (!strcmp(pCode[x], "app_p")) {
								comp_add_script_line("Func=DynamicFunc__append_keys\n"); ++inp_cnt; }
							else if (!strcmp(pCode[x], "app_s")) {
								comp_add_script_line("Func=DynamicFunc__append_salt\n"); ++salt_cnt; }
							else if (!strcmp(pCode[x], "app_u")) {
								comp_add_script_line("Func=DynamicFunc__append_userid\n"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_s2")) {
								comp_add_script_line("Func=DynamicFunc__append_2nd_salt\n"); ++ex_cnt; }
							else if (!strcmp(pCode[x], "app_sh")) {
								comp_add_script_line("Func=DynamicFunc__append_salt\n"); ++salt_cnt; }
							else if (!strncmp(pCode[x], "IN2", 3)) {
								comp_add_script_line("Func=DynamicFunc__append_input_from_input2\n"); ++hash_cnt; }
							else if (!strncmp(pCode[x], "IN1", 3)) {
								comp_add_script_line("Func=DynamicFunc__append_input_from_input\n"); ++hash_cnt; }
							*pCode[x] = 'X';
						}
						strcpy(pCode[last_push], "IN2");
						// Ok, the only thing we can control is salt_len (if not in hex_as_salt), and inp_len
						// all we worry about is inp_len.  256 bytes is MAX.
						len_comp = ex_cnt*24;
						len_comp += inp_cnt*max_inp_len;
						len_comp += salt_cnt*salt_len;
						// add in hash_cnt*whatever_size_hash is.
						if (len_comp > 256) {
							max_inp_len -= (len_comp-256+(inp_cnt-1))/inp_cnt;
						}
					}
				}
				if (!pCode[i+1] || !pCode[i+1][0]) {
					// final hash
					if (!strncasecmp(pCode[i], "f5", 2))
						comp_add_script_line("Func=DynamicFunc__MD5_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "f4", 2))
						comp_add_script_line("Func=DynamicFunc__MD4_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "f1", 2))
						comp_add_script_line("Func=DynamicFunc__SHA1_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "f224", 4))
						comp_add_script_line("Func=DynamicFunc__SHA224_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "f256", 4))
						comp_add_script_line("Func=DynamicFunc__SHA256_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "f384", 4))
						comp_add_script_line("Func=DynamicFunc__SHA384_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "f512", 4))
						comp_add_script_line("Func=DynamicFunc__SHA512_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "fgost", 5))
						comp_add_script_line("Func=DynamicFunc__GOST_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "ftig", 4))
						comp_add_script_line("Func=DynamicFunc__Tiger_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "fwrl", 4))
						comp_add_script_line("Func=DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "frip128", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD128_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "frip160", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD160_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "frip256", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD256_crypt_input1_to_output1_FINAL\n");
					else if (!strncasecmp(pCode[i], "frip320", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD320_crypt_input1_to_output1_FINAL\n");
				} else {
					if (!strncasecmp(pCode[i], "f5", 2))
						comp_add_script_line("Func=DynamicFunc__MD5_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "f4", 2))
						comp_add_script_line("Func=DynamicFunc__MD4_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "f1", 2))
						comp_add_script_line("Func=DynamicFunc__SHA1_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "f224", 4))
						comp_add_script_line("Func=DynamicFunc__SHA224_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "f256", 4))
						comp_add_script_line("Func=DynamicFunc__SHA256_crypt_input1_overwrite_input2n");
					else if (!strncasecmp(pCode[i], "f384", 4))
						comp_add_script_line("Func=DynamicFunc__SHA384_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "f512", 4))
						comp_add_script_line("Func=DynamicFunc__SHA512_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "fgost", 5))
						comp_add_script_line("Func=DynamicFunc__GOST_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "ftig", 4))
						comp_add_script_line("Func=DynamicFunc__Tiger_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "fwrl", 4))
						comp_add_script_line("Func=DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "frip128", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD128_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "frip160", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD160_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "frip256", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD256_crypt_input1_overwrite_input2\n");
					else if (!strncasecmp(pCode[i], "frip320", 7))
						comp_add_script_line("Func=DynamicFunc__RIPEMD320_crypt_input1_overwrite_input2\n");
					else if (!strcasecmp(pCode[i], "pad16"))
						comp_add_script_line("Func=DynamicFunc__append_keys_pad16\n");
					else if (!strcasecmp(pCode[i], "pad20"))
						comp_add_script_line("Func=DynamicFunc__append_keys_pad20\n");
					else if (!strcasecmp(pCode[i], "pad100"))
						comp_add_script_line("Func=DynamicFunc__set_input_len_100\n");
					//else if (!strcasecmp(pCode[i], "padm64"))  // in pass_gen.pl, but not in dynamic_fmt.c yet.  HSRP uses this, but that is a thick format.
					//	comp_add_script_line("Func=DynamicFunc__append_keys_pad16\n");

					else if (!strcasecmp(pCode[i], "utf16be") || !strcasecmp(pCode[i], "utf16"))
						comp_add_script_line("Func=DynamicFunc__setmode_normal\n");
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
	pScr = mem_alloc(len+1);
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

	p = mem_calloc(sizeof(DC_struct), sizeof(void*));
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

#ifdef WITH_MAIN
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

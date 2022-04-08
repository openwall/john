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
 *     md5(EXPR)   Perform MD5.   Results in lowcase hex (unless it's the outer EXPR)
 *     sha1(EXPR)  Perform SHA1.  Results in lowcase hex (unless it's the outer EXPR)
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
 *     saltlen=#         This sets the length of the salt, negative value used for variable sized
 *                       salt, with the max var size allowed being the positive of the number.
 *                       so saltlen=-23 is variable sized salt from 0 to 23 bytes, while
 *                       saltlen=23 is a fixed sized 23 byte salt.
 *     maxinplen=#       If run in -O=3, this must be provided currently. It is the max plaintext
 *                       len that this expression can handle that will not blow past the 55 byte
 *                       SIMD max string length. So md5(md5($p).$s), the maxinplen=55 is used.
 *                       but for md5($s.$p) the maxinplen would need to be 55-maxsaltlen so if
 *                       we have this exression: md5(md5($s).$p) then the salt in this case is
 *                       'really' 32 bytes, no matter what length the salt is, so we know the
 *                       max to be 55-32 or only maxinplen=23 is the right value.
 *     debug             If this is set, then JtR will output the script and other data and exit.
 *     rdp               Force the RDP format to be used, even if the compiler can generate
 *                       a valid dynamic script for this expression.
 *     O=n               Optimize. Can be levels are 0, 1, 2 and 3
 *
 *****************************************************************
 *     TODO:
 *****************************************************************
 *
 *  The big_hash speed tests done with 100's (whirlpool).  All others
 *  should be similar, EXCEPT hashes using SIMD.  They should each be
 *  looked at.
 *
 *  Optimal big_hash speeds:   *00, *01, *02, *03, *04, *05, *06, *07, *08 (all big hashes!)
 *****************************************************************

 add new logic for ^  (exponentiation)

 Handle:
#define MGF_KEYS_INPUT                   0x00000001
#define MGF_KEYS_CRYPT_IN2               0x00000002

// for salt_as_hex for other formats, we do this:  (flag>>56)
// Then 00 is md5, 01 is md4, 02 is SHA1, etc
// NOTE, all top 8 bits of the flags are reserved, and should NOT be used for flags.
#define MGF_KEYS_BASE16_IN1_Offset_MD5       0x0000000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_MD4       0x0100000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA1      0x0200000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA224    0x0300000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA256    0x0400000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA384    0x0500000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_SHA512    0x0600000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_GOST      0x0700000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_WHIRLPOOL 0x0800000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_Tiger     0x0900000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD128 0x0A00000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD160 0x0B00000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD256 0x0C00000000000008ULL
#define MGF_KEYS_BASE16_IN1_Offset_RIPEMD320 0x0D00000000000008ULL

BENCHMARK_FLAG  (for raw hashes, etc).

// MGF_INPBASE64 uses e_b64_cryptBS from base64_convert.h chang b64e to b64c
#define MGF_INPBASE64		         0x00000080
if any utf16 used, set this flag??

Figure out how to better hook in dynamic= so that we can use this in other
situations than ONLY working if -format=dynamic=expr is used.

Right now, all handles are allocated 'tiny'.  Change that so that we
do normal alloc/calloc, keep a list of all handles ever allocated, and
then upon void dynamic_compile_done() free up all memory from that list.

$p and or uc($p) or lc($p) MUST be the only way $p is shown. If uc($p) then ALL must be uc, etc.
Same goes for $u.  NOTE, the lexi works this way. I just need to document it.

DONE // MGF_INPBASE64b uses e_b64_crypt from base64_convert.h
DONE #define MGF_INPBASE64b		         0x00004000
DONE if outer hash is md5_64 (or 64c) then use this flag
DONE #define MGF_INPBASE64m               0x02000000
DONE #define MGF_UTF8                     0x04000000
DONE Remove all md5u() types.  Replace with a utf16() function.
DONE #define MGF_USERNAME_UPCASE         (0x00000020|MGF_USERNAME)
DONE #define MGF_USERNAME_LOCASE         (0x00000040|MGF_USERNAME)
DONE #define MGF_PASSWORD_UPCASE          0x08000000
DONE #define MGF_PASSWORD_LOCASE          0x10000000
DONE #define MGF_BASE_16_OUTPUT_UPCASE    0x00002000

DONE: #define MGF_KEYS_BASE16_IN1              0x00000004   // deprecated (use the _MD5 version)
DONE: #define MGF_KEYS_BASE16_IN1_MD5          0x0000000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_MD4	       0x0100000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_SHA1         0x0200000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_SHA224       0x0300000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_SHA256       0x0400000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_SHA384       0x0500000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_SHA512       0x0600000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_GOST         0x0700000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_WHIRLPOOL    0x0800000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_Tiger        0x0900000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_RIPEMD128    0x0A00000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_RIPEMD160    0x0B00000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_RIPEMD256    0x0C00000000000004ULL
DONE: #define MGF_KEYS_BASE16_IN1_RIPEMD320    0x0D00000000000004ULL

 */

#include "arch.h"

#if defined(SIMD_COEF_32) && !ARCH_LITTLE_ENDIAN
	#undef SIMD_COEF_32
	#undef SIMD_COEF_64
	#undef SIMD_PARA_MD5
	#undef SIMD_PARA_MD4
	#undef SIMD_PARA_SHA1
	#undef SIMD_PARA_SHA256
	#undef SIMD_PARA_SHA512
	#define BITS ARCH_BITS_STR
#endif

#ifndef DYNAMIC_DISABLED
#include <stdint.h>
#include <ctype.h>
#include <stdarg.h>

#include "misc.h"	// error()
#include "common.h"
#include "formats.h"
#include "list.h"
#include "crc32.h"
#include "johnswap.h"
#include "dynamic.h"
#include "dynamic_compiler.h"
#include "base64_convert.h"
#include "md5.h"
#include "md4.h"
#include "sha.h"
#include "sha2.h"
#include "gost.h"
#include "unicode.h"
// this one is going to be harder.  only haval_256_5 is implemented in CPAN perl, making generation of test cases harder.
// Also, there are 15 different hashes in this 'family'.
//#include "sph_haval.h"

#include "sph_ripemd.h"
#include "sph_tiger.h"
#include "sph_whirlpool.h"
#include "sph_haval.h"
#include "sph_md2.h"
#include "sph_panama.h"
#include "sph_skein.h"

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

#include "KeccakHash.h"
#define KECCAK_CTX                  Keccak_HashInstance
#define KECCAK_Update(a,b,c)        Keccak_HashUpdate(a,b,(c)*8)
#define KECCAK_Final(a,b)           Keccak_HashFinal(b,a)
#define KECCAK_224_Init(hash)       Keccak_HashInitialize(hash, 1152,  448, 224, 0x01)
#define KECCAK_256_Init(hash)       Keccak_HashInitialize(hash, 1088,  512, 256, 0x01)
#define KECCAK_384_Init(hash)       Keccak_HashInitialize(hash,  832,  768, 384, 0x01)
#define KECCAK_512_Init(hash)       Keccak_HashInitialize(hash,  576, 1024, 512, 0x01)
// FIPS202 complient
#define SHA3_224_Init(hash)         Keccak_HashInitialize(hash, 1152,  448, 224, 0x06)
#define SHA3_256_Init(hash)         Keccak_HashInitialize(hash, 1088,  512, 256, 0x06)
#define SHA3_384_Init(hash)         Keccak_HashInitialize(hash,  832,  768, 384, 0x06)
#define SHA3_512_Init(hash)         Keccak_HashInitialize(hash,  576, 1024, 512, 0x06)

int dynamic_compiler_failed = 0;

static char *find_the_extra_params(const char *expr);

/*
 * use this size for all buffers inside of the format. This is WAY too large
 * for dynamic, but since we now have the RDP format to handle any expresions
 * which do not function in dynamic. Thus, we can have a much larger workspace
 * and the RDP format will be able to handle this.  NOTE, we still do use
 * static sized buffers, so overly complex expressions will still overflow
 */
#define INTERNAL_TMP_BUFSIZE		4096


typedef struct DC_list {
	struct DC_list *next;
	DC_struct *value;
} DC_list;

const char *dyna_script = "Expression=dynamic=md5($p)\nFlag=MGF_KEYS_INPUT\nFunc=DynamicFunc__crypt_md5\nTest=@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72:abc";
const char *dyna_signature = "@dynamic=md5($p)@";
int dyna_sig_len = 17;
const char *dyna_line[DC_NUM_VECTORS] = {
	"@dynamic=md5($p)@900150983cd24fb0d6963f7d28e17f72",
	"@dynamic=md5($p)@527bd5b5d689e2c32ae974c6229ff785",
	"@dynamic=md5($p)@9dc1dc3f8499ab3bbc744557acf0a7fb",
#if SIMD_COEF_32 < 4
	"@dynamic=md5($p)@fc58a609d0358176385b00970bfb2b49", // Len 110
#else
	"@dynamic=md5($p)@142a42ffcb282cf8087dd4dfebacdec2", // Len 55
#endif
	"@dynamic=md5($p)@d41d8cd98f00b204e9800998ecf8427e",
};
const char *options_format="";

static int OLvL = 2;
static int gost_init = 0;

extern char *dynamic_Demangle(char*,int *);

#ifdef WITH_MAIN
int GEN_BIG=0;
#endif

static DC_list *pList;
static DC_struct *pLastFind;

#define ARRAY_COUNT(a) (sizeof(a)/sizeof(a[0]))
typedef void(*fpSYM)();
static int nConst;
static const char *Const[9];
static int compile_debug;
static int force_rdp;
static char *SymTab[INTERNAL_TMP_BUFSIZE];
static fpSYM fpSymTab[INTERNAL_TMP_BUFSIZE];
static int nSymTabLen[INTERNAL_TMP_BUFSIZE];
static char *pCode[INTERNAL_TMP_BUFSIZE];
static fpSYM fpCode[INTERNAL_TMP_BUFSIZE];
static int nLenCode[INTERNAL_TMP_BUFSIZE];
static int nCode, nCurCode;
static char *pScriptLines[INTERNAL_TMP_BUFSIZE];
static int nScriptLines;
static int outer_hash_len;
static int nSyms;
static int LastTokIsFunc;
static int bNeedS, bNeedS2, bNeedU, bNeedUlc, bNeedUuc, bNeedPlc, bNeedPuc, bNeedUC, bNeedPC;
static char *salt_as_hex_type, *keys_base16_in1_type;
static int bOffsetHashIn1; // for hash(hash(p).....) type hashes.
static int keys_as_input;
static char *gen_Stack[INTERNAL_TMP_BUFSIZE];
static int gen_Stack_len[INTERNAL_TMP_BUFSIZE];
static int ngen_Stack, ngen_Stack_max;
static char *h;
static int h_len;
static int nSaltLen = -32;
static char gen_s[INTERNAL_TMP_BUFSIZE], gen_conv[INTERNAL_TMP_BUFSIZE];
static char gen_s2[PLAINTEXT_BUFFER_SIZE], gen_u[PLAINTEXT_BUFFER_SIZE], gen_uuc[PLAINTEXT_BUFFER_SIZE], gen_ulc[PLAINTEXT_BUFFER_SIZE], gen_pw[PLAINTEXT_BUFFER_SIZE], gen_puc[PLAINTEXT_BUFFER_SIZE], gen_plc[PLAINTEXT_BUFFER_SIZE];

static uint32_t compute_checksum(const char *expr);
static DC_HANDLE find_checksum(uint32_t crc32);
static DC_HANDLE do_compile(const char *expr, uint32_t crc32);
static void add_checksum_list(DC_HANDLE pHand);

// TODO
static char *dynamic_expr_normalize(const char *ct) {
	// normalize $pass -> $p
	//           $password -> $p
	//           $salt -> $s
	//           $user -> $u
	//           $username -> $u
	//           unicode( -> utf16(
	//           -c=: into c1=\x3a  (colon ANYWHERE in the constant)
	if (/*!strncmp(ct, "@dynamic=", 9) &&*/ (strstr(ct, "$pass") || strstr(ct, "$salt") || strstr(ct, "$user"))) {
		static char Buf[INTERNAL_TMP_BUFSIZE];
		char *cp = Buf;

		strnzcpy(Buf, ct, sizeof(Buf));
		ct = Buf;
		cp = Buf;
		while (*cp) {
			int cnt=0;

			while (*cp && *cp != '$' && *cp != 'u')
				++cp;
			if (*cp) {
				if (!strncmp(cp, "$password", 9))
					cnt = 7;
				else if (!strncmp(cp, "$pass", 5))
					cnt = 3;
				else if (!strncmp(cp, "$salt", 5))
					cnt = 3;
				else if (!strncmp(cp, "$username", 9))
					cnt = 7;
				else if (!strncmp(cp, "$user", 5))
					cnt = 3;
				else if (!strncmp(cp, "unicode(", 8)) {
					memcpy(cp, "utf16", 5);
					cp += 3;
					cnt = 2;
				}
			}
			cp += 2;;
			if (cnt) {
				char *cp2 = cp;
				while (cp2[cnt]) {
					*cp2 = cp2[cnt];
					++cp2;
				}
				*cp2 = 0;
			}
		}
	}
	if (strstr(ct, ",c")) {
		// this need greatly improved. Only handling ':' char right now.
		static char Buf[INTERNAL_TMP_BUFSIZE];
		char *cp = Buf;

		strnzcpy(Buf, ct, sizeof(Buf));
		ct = Buf;
		cp = strstr(ct, ",c");
		while (cp) {
			char *ctp = strchr(&cp[1], ',');

			if (ctp) *ctp = 0;
			if (strchr(cp, ':')) {
				char *cp2 = &cp[strlen(cp)-1];
				if (ctp) *ctp = ',';
				while (cp2 > cp) {
					if (*cp2 == ':') {
						memmove(&cp2[4], &cp2[1], strlen(cp2));
						memcpy(cp2, "\\x3a", 4);
					}
					--cp2;
				}
			} else
				if (ctp) *ctp = ',';
			cp = strstr(&cp[1], ",c");
		}
	}
	//
	// TODO:  put in this order:  expression,c1=,c2=,...,cn=,passcase=,saltlen=,pass=uni,salt=,usrname=,-O=,debug
	// NOTE,  we only crc up to the 'passcase=' part.  Everything after that should not be used to 'distinguish' the format hash
	//        between hashes.  NOTE, it may still cause valid to not 'load' for testing some hashes, but these still should
	//        be loaded from the .pot file to cross off items.
	//
	/* normalize when it comes to constants:  md5($c1.$p.$c2),c1=x,c2=x  and  md5($c1.$p.$c1),c1=x  are the same.
	   Also md5($c2.$p.$c1),c1=x,c2=y  and  md5($c1.$p.$c2),c1=y,c2=x are the same.
	   The normalizer will have to address these, and put them into cannonical layout
	*/
	return (char*)ct;
}

static void DumpParts(char *part, char *cp) {
	int len = strlen(part);

	cp = strtok(cp, "\n");
	while (cp) {
		if (!strncmp(cp, part, len))
			printf("%s\n", cp);
		cp = strtok(NULL, "\n");
	}
}

static void DumpParts2(char *part, char *cp, char *comment) {
	int len = strlen(part), first = 1;

	cp = strtok(cp, "\n");
	while (cp) {
		if (!strncmp(cp, part, len)) {
			if (first)
				printf("%s\n", comment);
			printf("%s\n", cp);
			first = 0;
		}
		cp = strtok(NULL, "\n");
	}
}

static void dump_HANDLE(void *_p) {
	DC_struct *p = (DC_struct*)_p;
	char *cp;
	int i;

	printf("\ncrc32 = %08X\n", p->crc32);
	printf("pExpr=%s\n", p->pExpr);
	printf("extraParams=%s\n", p->pExtraParams);
	printf("signature=%s\n", p->pSignature);
	for (i = 0; i < DC_NUM_VECTORS; i++)
		if (p->pLine[i])
			printf("line%d=%s\n", i, p->pLine[i]);

	// Now print out a nicely commented script, and put it back into order.
	// order does not matter for the dyna-parser, BUT putting in good form
	// will help anyone wanting to learn how to properly code in the dyna
	// script language.
	printf("##############################################################\n");
	printf("#  Dynamic script for expression %s%s\n", p->pExpr, p->pExtraParams);
	printf("##############################################################\n");
	cp = str_alloc_copy(p->pScript);
	DumpParts("Expression", cp);
	cp = str_alloc_copy(p->pScript);
	printf("#  Flags for this format\n");
	DumpParts("Flag=", cp);
	cp = str_alloc_copy(p->pScript);
	printf("#  Lengths used in this format\n");
	DumpParts("SaltLen=", cp);
	cp = str_alloc_copy(p->pScript);
	DumpParts("MaxInput", cp);
	cp = str_alloc_copy(p->pScript);
	printf("#  The functions in the script\n");
	DumpParts("Func=", cp);
	cp = str_alloc_copy(p->pScript);
	DumpParts2("Const", cp, "#  Constants used by this format");
	cp = str_alloc_copy(p->pScript);
	printf("#  The test hashes that validate this script\n");
	DumpParts("Test", cp);

	exit(0);
}

int dynamic_compile(const char *expr, DC_HANDLE *p) {
	uint32_t crc32 = compute_checksum(dynamic_expr_normalize(expr));
	DC_HANDLE pHand=0;

	// This work, moved from do_compile, AND from dynamic_assign_script_to_format
	if (!gost_init) {
		extern void Dynamic_Load_itoa16_w2();
		gost_init_table();
		gost_init = 1;
		common_init();
		Dynamic_Load_itoa16_w2();
	}

	if (pLastFind && pLastFind->crc32 == crc32) {
		*p = (DC_HANDLE)pLastFind;
		return 0;
	}
	if (!strstr(expr, ",nolib") && !strstr(expr, ",rdp") && (OLvL || strstr(expr, ",O"))) {
		pHand = dynamic_compile_library(expr, crc32, &outer_hash_len);
		// Note, we are returned a constant data. If we want to assign
		// the extra params into the pExtraParams field, we will have
		// to create a non-const object, copy all needed data, and
		// then add the extra params to that field.
		if (pHand) {
			DC_struct *p;
			const DC_struct *cp = (const DC_struct *)pHand;
			int n;

			p = mem_calloc_tiny(sizeof(DC_struct), sizeof(void*));
			p->magic = DC_MAGIC;
			p->crc32 = cp->crc32;
			p->pFmt = cp->pFmt;
			p->pExpr = cp->pExpr;
			p->pExtraParams = str_alloc_copy(find_the_extra_params(expr));
			p->pScript = cp->pScript;
			p->pSignature = cp->pSignature;
			for (n = 0; n < DC_NUM_VECTORS; ++n)
				p->pLine[n] = cp->pLine[n];
			pHand = p;
		}
		if (pHand && strstr(expr, ",debug")) {
			printf("Code from dynamic_compiler_lib.c\n");
			dump_HANDLE(pHand);
		}
	}
	if (!pHand)
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

static char *find_the_expression(const char *expr) {
	static char buf[512];
	char *cp;

	if (strncmp(expr, "dynamic=", 8))
		return "";
	strnzcpy(buf, &expr[8], sizeof(buf));
	cp = strchr(buf, ',');
	if (cp) {
		*cp = 0;
		cp = dynamic_expr_normalize(buf);
		return cp;
	}
	cp = strrchr(buf, ')');
	if (!cp) return "";
	while (cp[1] && cp[1] != ',')
		++cp;
	cp[1] = 0;
	cp = dynamic_expr_normalize(buf);
	return cp;
}

static char *find_the_extra_params(const char *expr) {
	static char buf[512];
	char *cp;

	if (strncmp(expr, "dynamic=", 8))
		return "";
	cp = strchr(expr, ',');
	if (!cp) return "";
	strnzcpy(buf, cp, sizeof(buf));
	// NOTE, we should normalize this string!!
	// we should probably call handle_extra_params, and then make a function
	// regen_extra_params() so that we always normalize this string.
	return buf;
}


/*
 * These are the 'low level' primative functions ported from pass_gen.pl.
 * These do the md5($p) stuff (hex, HEX, unicode, base64, etc), for all hash
 * types, and for other functions.
 * now done using macros (makes source smaller and easier to maintain). NOTE
 * it is not very debuggable, but that really should not matter.' I would rather
 * have working prototypes like this, then simply add 1 line to get a NEW full
 * set of properly working functions.
 */
#define OSSL_FUNC(N,TT,T,L) \
static void N##_hex()    {TT##_CTX c; T##_Init(&c); T##_Update(&c,h,h_len); T##_Final((unsigned char*)h,&c); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_hex,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void N##_base64() {TT##_CTX c; T##_Init(&c); T##_Update(&c,h,h_len); T##_Final((unsigned char*)h,&c); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_mime,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void N##_base64c(){TT##_CTX c; T##_Init(&c); T##_Update(&c,h,h_len); T##_Final((unsigned char*)h,&c); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_crypt,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void N##_raw()    {TT##_CTX c; T##_Init(&c); T##_Update(&c,h,h_len); T##_Final((unsigned char*)h,&c); }
OSSL_FUNC(md5,MD5,MD5,16)
OSSL_FUNC(md4,MD4,MD4,16)
OSSL_FUNC(sha1,SHA,SHA1,20)
OSSL_FUNC(sha224,SHA256,SHA224,28)
OSSL_FUNC(sha256,SHA256,SHA256,32)
OSSL_FUNC(sha384,SHA512,SHA384,48)
OSSL_FUNC(sha512,SHA512,SHA512,64)
OSSL_FUNC(whirlpool,WHIRLPOOL,WHIRLPOOL,64)
// LARGE_HASH_EDIT_POINT


#define KECCAK_FUNC(N,T,L) \
static void N##_hex()    {KECCAK_CTX c; T##_Init(&c); KECCAK_Update(&c,(BitSequence*)h,h_len); KECCAK_Final((BitSequence*)h,&c); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_hex,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void N##_base64() {KECCAK_CTX c; T##_Init(&c); KECCAK_Update(&c,(BitSequence*)h,h_len); KECCAK_Final((BitSequence*)h,&c); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_mime,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void N##_base64c(){KECCAK_CTX c; T##_Init(&c); KECCAK_Update(&c,(BitSequence*)h,h_len); KECCAK_Final((BitSequence*)h,&c); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_crypt,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void N##_raw()    {KECCAK_CTX c; T##_Init(&c); KECCAK_Update(&c,(BitSequence*)h,h_len); KECCAK_Final((BitSequence*)h,&c); }
KECCAK_FUNC(sha3_224,SHA3_224,28)
KECCAK_FUNC(sha3_256,SHA3_256,32)
KECCAK_FUNC(sha3_384,SHA3_384,48)
KECCAK_FUNC(sha3_512,SHA3_512,64)
KECCAK_FUNC(keccak_224,KECCAK_256,28)
KECCAK_FUNC(keccak_256,KECCAK_256,32)
KECCAK_FUNC(keccak_384,KECCAK_512,48)
KECCAK_FUNC(keccak_512,KECCAK_512,64)
// LARGE_HASH_EDIT_POINT

static void gost_hex()         { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_hex,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); }
static void gost_base64()      { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_mime,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); }
static void gost_base64c()     { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,32,gen_conv,e_b64_crypt,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); }
static void gost_raw()         { gost_ctx c; john_gost_init(&c); john_gost_update(&c, (unsigned char*)h, h_len); john_gost_final(&c, (unsigned char*)h); }
#define SPH_FUNC(T,L) \
static void T##_hex()    { sph_##T##_context c; sph_##T##_init(&c); sph_##T(&c, (unsigned char*)h, h_len); sph_##T##_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_hex,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void T##_base64() { sph_##T##_context c; sph_##T##_init(&c); sph_##T(&c, (unsigned char*)h, h_len); sph_##T##_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_mime,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void T##_base64c(){ sph_##T##_context c; sph_##T##_init(&c); sph_##T(&c, (unsigned char*)h, h_len); sph_##T##_close(&c, (unsigned char*)h); base64_convert(h,e_b64_raw,L,gen_conv,e_b64_crypt,INTERNAL_TMP_BUFSIZE,0, 0); strcpy(h, gen_conv); } \
static void T##_raw()    { sph_##T##_context c; sph_##T##_init(&c); sph_##T(&c, (unsigned char*)h, h_len); sph_##T##_close(&c, (unsigned char*)h); }
SPH_FUNC(tiger,24)
SPH_FUNC(ripemd128,16)  SPH_FUNC(ripemd160,20)  SPH_FUNC(ripemd256,32) SPH_FUNC(ripemd320,40)
SPH_FUNC(haval128_3,16) SPH_FUNC(haval128_4,16) SPH_FUNC(haval128_5,16)
SPH_FUNC(haval160_3,20) SPH_FUNC(haval160_4,20) SPH_FUNC(haval160_5,20)
SPH_FUNC(haval192_3,24) SPH_FUNC(haval192_4,24) SPH_FUNC(haval192_5,24)
SPH_FUNC(haval224_3,28) SPH_FUNC(haval224_4,28) SPH_FUNC(haval224_5,28)
SPH_FUNC(haval256_3,32) SPH_FUNC(haval256_4,32) SPH_FUNC(haval256_5,32)
SPH_FUNC(md2,16) SPH_FUNC(panama,32)
SPH_FUNC(skein224,28) SPH_FUNC(skein256,32) SPH_FUNC(skein384,48) SPH_FUNC(skein512,64)
// LARGE_HASH_EDIT_POINT

static int encode_le()         { int len = enc_to_utf16((UTF16*)gen_conv, INTERNAL_TMP_BUFSIZE, (UTF8*)h, h_len); memcpy(h, gen_conv, len*2); return len*2; }
static int encode_be()         { int len = enc_to_utf16_be((UTF16*)gen_conv, INTERNAL_TMP_BUFSIZE, (UTF8*)h, h_len); memcpy(h, gen_conv, len*2); return len*2; }
static char *pad16()           { strncpy_pad(gen_conv, gen_pw, 16, 0); return gen_conv; }
static char *pad20()           { strncpy_pad(gen_conv, gen_pw, 20, 0); return gen_conv; }
static char *pad100()          { strncpy_pad(gen_conv, gen_pw, 100, 0); return gen_conv; }

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
static void dynamic_push()   { char *p = mem_calloc(INTERNAL_TMP_BUFSIZE, 1); MEM_FREE(gen_Stack[ngen_Stack]); gen_Stack_len[ngen_Stack] = 0; gen_Stack[ngen_Stack++] = p; ngen_Stack_max++; }
static void dynamic_pad16()  { dyna_helper_appendn(pad16(), 16);  }
static void dynamic_pad20()  { dyna_helper_appendn(pad20(), 20);  }
static void dynamic_pad100() { dyna_helper_appendn(pad100(), 100); }
//static void dynamic_pop    { return pop @gen_Stack; }  # not really needed.

#define APP_FUNC(TY,VAL) static void dynamic_app_##TY (){dyna_helper_append(VAL);}
APP_FUNC(sh,gen_s) /*APP_FUNC(s,gen_s)*/ APP_FUNC(S,gen_s2) APP_FUNC(u,gen_u) APP_FUNC(u_lc,gen_ulc)
APP_FUNC(u_uc,gen_uuc) APP_FUNC(p,gen_pw) APP_FUNC(p_uc,gen_puc) APP_FUNC(p_lc,gen_plc)
#define APP_CFUNC(N) static void dynamic_app_##N (){int len; char * cp = dynamic_Demangle((char*)Const[N],&len); dyna_helper_appendn(cp, len);}
APP_CFUNC(1) APP_CFUNC(2) APP_CFUNC(3) APP_CFUNC(4) APP_CFUNC(5) APP_CFUNC(6) APP_CFUNC(7) APP_CFUNC(8)
//static void dynamic_ftr32  { $h = gen_Stack[--ngen_Stack]; substr($h,0,32);  strcat(gen_Stack[ngen_Stack-1], h);  }
//static void dynamic_f54    { $h = gen_Stack[--ngen_Stack]; md5_hex(h)."00000000";	 strcat(gen_Stack[ngen_Stack-1], h);  }

#define LEXI_FUNC(N,T,L) \
	static void dynamic_f##N##h()    { dyna_helper_pre(); T##_hex();               dyna_helper_poststr(); } \
	static void dynamic_f##N##H()    { dyna_helper_pre(); T##_hex(); strupr(h);    dyna_helper_poststr(); } \
	static void dynamic_f##N##6()    { dyna_helper_pre(); T##_base64();	           dyna_helper_poststr(); } \
	static void dynamic_f##N##c()    { dyna_helper_pre(); T##_base64c();           dyna_helper_poststr(); } \
	static void dynamic_f##N##r()    { dyna_helper_pre(); T##_raw();               dyna_helper_post(L); }
LEXI_FUNC(5,md5,16)       LEXI_FUNC(4,md4,16)          LEXI_FUNC(1,sha1,20)
LEXI_FUNC(224,sha224,28)  LEXI_FUNC(256,sha256,32)     LEXI_FUNC(384,sha384,48)  LEXI_FUNC(512,sha512,64)
LEXI_FUNC(gost,gost,32)   LEXI_FUNC(tig,tiger,24)      LEXI_FUNC(wrlp,whirlpool,64)
LEXI_FUNC(rip128,ripemd128,16) LEXI_FUNC(rip160,ripemd160,20) LEXI_FUNC(rip256,ripemd256,32) LEXI_FUNC(rip320,ripemd320,40)
LEXI_FUNC(hav128_3,haval128_3,16) LEXI_FUNC(hav128_4,haval128_4,16) LEXI_FUNC(hav128_5,haval128_5,16)
LEXI_FUNC(hav160_3,haval160_3,20) LEXI_FUNC(hav160_4,haval160_4,20) LEXI_FUNC(hav160_5,haval160_5,20)
LEXI_FUNC(hav192_3,haval192_3,24) LEXI_FUNC(hav192_4,haval192_4,24) LEXI_FUNC(hav192_5,haval192_5,24)
LEXI_FUNC(hav224_3,haval224_3,28) LEXI_FUNC(hav224_4,haval224_4,28) LEXI_FUNC(hav224_5,haval224_5,28)
LEXI_FUNC(hav256_3,haval256_3,32) LEXI_FUNC(hav256_4,haval256_4,32) LEXI_FUNC(hav256_5,haval256_5,32)
LEXI_FUNC(md2,md2,16) LEXI_FUNC(pan,panama,32)
LEXI_FUNC(skn224,skein224,28)    LEXI_FUNC(skn256,skein256,32)   LEXI_FUNC(skn384,skein384,48)   LEXI_FUNC(skn512,skein512,64)
LEXI_FUNC(sha3_224,sha3_224,28)  LEXI_FUNC(sha3_256,sha3_256,32) LEXI_FUNC(sha3_384,sha3_384,48) LEXI_FUNC(sha3_512,sha3_512,64)
LEXI_FUNC(keccak_224,keccak_224,28) LEXI_FUNC(keccak_256,keccak_256,32) LEXI_FUNC(keccak_384,keccak_384,48) LEXI_FUNC(keccak_512,keccak_512,64)
// LARGE_HASH_EDIT_POINT

static void dynamic_futf16()    { dyna_helper_pre();                             dyna_helper_post(encode_le()); }
static void dynamic_futf16be()  { dyna_helper_pre();                             dyna_helper_post(encode_be()); }
static void dynamic_exp() {
	int i, j;

	j = atoi(&pCode[nCurCode][1]);
	for (i = 1; i < j; ++i) {
		gen_Stack_len[ngen_Stack] = gen_Stack_len[ngen_Stack-1];
		gen_Stack_len[ngen_Stack-1] = 0;
		++ngen_Stack;
		fpCode[nCurCode-1]();
	}
}

static void init_static_data() {
	int i;

	nConst = 0;
	for (i = 0; i < nSyms; ++i) {
		MEM_FREE(SymTab[i]);
		fpSymTab[i] = NULL;
		nSymTabLen[i] = 0;
	}
	for (i = 0; i < 9; ++i) {
		if (Const[i]) {
			char *p = (char*)Const[i];
			MEM_FREE(p);
		}
		Const[i] = NULL;
	}
	for (i = 0; i < nCode; ++i) {
		MEM_FREE(pCode[i]);
		fpCode[i] = NULL;
		nLenCode[i] = 0;
	}
	for (i = 0; i < nScriptLines; ++i)
		MEM_FREE(pScriptLines[i]);
	for (i = 0; i < ngen_Stack; ++i) {
		MEM_FREE(gen_Stack[i]);
		gen_Stack_len[i] = 0;
	}
	ngen_Stack = ngen_Stack_max = 0;
	nCode = nCurCode = 0;
	nSyms = 0;
	nScriptLines = 0;
	LastTokIsFunc = 0;
	keys_as_input = 0;
	outer_hash_len = 0;
	bNeedS = bNeedS2 = bNeedU = bNeedUlc = bNeedUuc = bNeedPlc = bNeedPuc = bNeedUC = bNeedPC = 0;
	compile_debug = 0;
	force_rdp = 0;
	MEM_FREE(salt_as_hex_type);
	MEM_FREE(keys_base16_in1_type);
	bOffsetHashIn1=0;
	h = NULL;
	h_len = 0;
	nSaltLen = -32;
	memset(gen_s, 0, sizeof(gen_s));
	memset(gen_s2, 0, sizeof(gen_s2));
	memset(gen_u, 0, sizeof(gen_u));
	memset(gen_uuc, 0, sizeof(gen_uuc));
	memset(gen_ulc, 0, sizeof(gen_ulc));
	memset(gen_pw, 0, sizeof(gen_pw));
	memset(gen_puc, 0, sizeof(gen_puc));
	memset(gen_plc, 0, sizeof(gen_plc));
	memset(gen_conv, 0, sizeof(gen_conv));
}
static const char *get_param(const char *p, const char *what) {
	const char *cp;
	char *cpRet;

	p = strstr(p, what);
	if (!p)
		return NULL;
	p += strlen(what)+1;	// the +1 is to skip the = character.
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
	for (i = 1; i < 9; ++i) {
		char *cp2;
#if __GNUC__ == 8
/* suppress false positive GCC 8 warning */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow="
#endif
		sprintf(cx, "c%d", i);
#if __GNUC__ == 8
#pragma GCC diagnostic pop
#endif
		cp = get_param(ptr->pExtraParams, cx);
		if (!cp || !cp[0])
			break;

		cp2 = mem_alloc(strlen(cp)+1);
		strcpy(cp2, cp);
		Const[++nConst] = cp2;
	}
	if ( (cp = get_param(ptr->pExtraParams, "O")) != NULL)
		OLvL = atoi(cp);
	// Find any other values here.
	if (strstr(ptr->pExtraParams, ",debug"))
		compile_debug = 1;
	if (strstr(ptr->pExtraParams, ",rdp"))
		force_rdp = 1;

	if ( (cp = get_param(ptr->pExtraParams, "saltlen")) != NULL) {
		nSaltLen = atoi(cp);
		if (nSaltLen > 200)
			error("Max salt len allowed is 200 bytes\n");
	}
	return 0;
}

static const char *comp_push_sym(const char *p, fpSYM fpsym, const char *pRet, int len) {
	if (nSyms < ARRAY_COUNT(SymTab)) {
		SymTab[nSyms] = mem_alloc(strlen(p)+1);
		fpSymTab[nSyms] = fpsym;
		nSymTabLen[nSyms] = len;
		strcpy(SymTab[nSyms++], p);
	}
	return pRet;
}

#define LOOKUP_IF_BLK(T,U,S,F,L,LL) \
	if (!strncasecmp(pInput, #T, L)) { \
		if (!strncmp(pInput, #T "_raw(", L+5)) { LastTokIsFunc = 2; return comp_push_sym("f" #S "r", dynamic_f##F##r, pInput+(L+4), LL); } \
		if (!strncmp(pInput, #T "_64c(", L+5)) { return comp_push_sym("f" #S "c", dynamic_f##F##c, pInput+(L+4), LL); } \
		if (!strncmp(pInput, #T "_64(", L+4)) { return comp_push_sym("f" #S "6", dynamic_f##F##6, pInput+(L+3), LL); } \
		if (!strncmp(pInput, #T "(", L+1)) { return comp_push_sym("f" #S "h", dynamic_f##F##h, pInput+L, LL); } \
		if (!strncmp(pInput, #U "(", L+1)) { return comp_push_sym("f" #S "H", dynamic_f##F##H, pInput+L, LL); } }

static const char *comp_get_symbol(const char *pInput) {
	// This function will grab the next valid symbol, and returns
	// the location just past this symbol.
	char TmpBuf[64];

	LastTokIsFunc = 0;
	if (!pInput || *pInput == 0) return comp_push_sym("X", fpNull, pInput, 0);
	if (*pInput == '.') return comp_push_sym(".", fpNull, pInput+1, 0);
	if (*pInput == '(') return comp_push_sym("(", fpNull, pInput+1, 0);
	if (*pInput == ')') return comp_push_sym(")", fpNull, pInput+1, 0);
	if (*pInput == '^') {
		int i=1;
		// number. Can follow a ^, like    md5_raw($p)^5   ==  md5(md5(md5(md5(md5($p)))))
		*TmpBuf = '^';
		if (!isdigit(ARCH_INDEX(pInput[1])))
			return comp_push_sym("X", fpNull, pInput+1, 0);
		while (i < 10 && isdigit(ARCH_INDEX(pInput[i])))
			++i;
		memcpy(&TmpBuf[1], &pInput[1], i-1);
		TmpBuf[i]=0;
		return comp_push_sym(TmpBuf, fpNull, pInput+i, 0);
	}
	if (*pInput == '$') {
		switch(pInput[1]) {
			case 'p': { if (bNeedPC>1) return comp_push_sym("X", fpNull, pInput, 0); bNeedPC=-1; return comp_push_sym("p", fpNull, pInput+2, 0); }
			case 'u': { bNeedU=1; if (bNeedUC>0) return comp_push_sym("X", fpNull, pInput, 0); bNeedUC=-1; return comp_push_sym("u", fpNull, pInput+2, 0); }
			case 's': if (pInput[2] == '2') return comp_push_sym("S", fpNull, pInput+3, 0);
					  return comp_push_sym("s", fpNull, pInput+2, 0);
			case 'c': if (pInput[2] > '8' || pInput[2] < '1')
						  return comp_push_sym("X", fpNull, pInput, 0);
					  if (Const[pInput[2]-'0'] == NULL) {
						  fprintf(stderr, "Error, a c%c found in expression, but the data for this const was not provided\n", pInput[2]);
						  return comp_push_sym("X", fpNull, pInput, 0);
					  }
					  TmpBuf[0] = pInput[2];
					  TmpBuf[1] = 0;
					  return comp_push_sym(TmpBuf, fpNull, pInput+3, 0);
		}
	}
	// these are functions, BUT can not be used for 'outer' function (i.e. not the final hash)
	// Note this may 'look' small, but it is a large IF block, once the macro's expand
	LastTokIsFunc = 1;
	LOOKUP_IF_BLK(md5,MD5,5,5,3,16)
	LOOKUP_IF_BLK(md4,MD4,4,4,3,16)
	LOOKUP_IF_BLK(sha1,SHA1,1,1,4,20)
	LOOKUP_IF_BLK(sha224,SHA224,224,224,6,28)
	LOOKUP_IF_BLK(sha256,SHA256,256,256,6,32)
	LOOKUP_IF_BLK(sha384,SHA384,384,384,6,48)
	LOOKUP_IF_BLK(sha512,SHA512,512,512,6,64)
	LOOKUP_IF_BLK(gost,GOST,gost,gost,4,32)
	LOOKUP_IF_BLK(tiger,TIGER,tig,tig,5,24)
	LOOKUP_IF_BLK(whirlpool,WHIRLPOOL,wrlp,wrlp,9,64)
	LOOKUP_IF_BLK(ripemd128,RIPEMD128,rip128,rip128,9,16) 	LOOKUP_IF_BLK(ripemd160,RIPEMD160,rip160,rip160,9,20)
	LOOKUP_IF_BLK(ripemd256,RIPEMD256,rip256,rip256,9,32)	LOOKUP_IF_BLK(ripemd320,RIPEMD320,rip320,rip320,9,40)
	LOOKUP_IF_BLK(haval128_3,HAVAL128_3,hav128_3,hav128_3,10,16) LOOKUP_IF_BLK(haval128_4,HAVAL128_4,hav128_4,hav128_4,10,16) LOOKUP_IF_BLK(haval128_5,HAVAL128_5,hav128_5,hav128_5,10,16)
	LOOKUP_IF_BLK(haval160_3,HAVAL160_3,hav160_3,hav160_3,10,20) LOOKUP_IF_BLK(haval160_4,HAVAL160_4,hav160_4,hav160_4,10,20) LOOKUP_IF_BLK(haval160_5,HAVAL160_5,hav160_5,hav160_5,10,20)
	LOOKUP_IF_BLK(haval192_3,HAVAL192_3,hav192_3,hav192_3,10,24) LOOKUP_IF_BLK(haval192_4,HAVAL192_4,hav192_4,hav192_4,10,24) LOOKUP_IF_BLK(haval192_5,HAVAL192_5,hav192_5,hav192_5,10,24)
	LOOKUP_IF_BLK(haval224_3,HAVAL224_3,hav224_3,hav224_3,10,28) LOOKUP_IF_BLK(haval224_4,HAVAL224_4,hav224_4,hav224_4,10,28) LOOKUP_IF_BLK(haval224_5,HAVAL224_5,hav224_5,hav224_5,10,28)
	LOOKUP_IF_BLK(haval256_3,HAVAL256_3,hav256_3,hav256_3,10,32) LOOKUP_IF_BLK(haval256_4,HAVAL256_4,hav256_4,hav256_4,10,32) LOOKUP_IF_BLK(haval256_5,HAVAL256_5,hav256_5,hav256_5,10,32)
	LOOKUP_IF_BLK(md2,MD2,md2,md2,3,16) LOOKUP_IF_BLK(panama,PANAMA,pan,pan,6,32)
	LOOKUP_IF_BLK(skein224,SKEIN224,skn224,skn224,8,28) LOOKUP_IF_BLK(skein256,SKEIN256,skn256,skn256,8,32)
	LOOKUP_IF_BLK(skein384,SKEIN384,skn384,skn384,8,48) LOOKUP_IF_BLK(skein512,SKEIN512,skn512,skn512,8,64)
	LOOKUP_IF_BLK(sha3_224,SHA3_224,sha3_224,sha3_224,8,28)
	LOOKUP_IF_BLK(sha3_256,SHA3_256,sha3_256,sha3_256,8,32)
	LOOKUP_IF_BLK(sha3_384,SHA3_384,sha3_384,sha3_384,8,48)
	LOOKUP_IF_BLK(sha3_512,SHA3_512,sha3_512,sha3_512,8,64)
	LOOKUP_IF_BLK(keccak_224,KECCAK_224,keccak_224,keccak_224,10,28)
	LOOKUP_IF_BLK(keccak_256,KECCAK_256,keccak_256,keccak_256,10,32)
	LOOKUP_IF_BLK(keccak_384,KECCAK_384,keccak_384,keccak_384,10,48)
	LOOKUP_IF_BLK(keccak_512,KECCAK_512,keccak_512,keccak_512,10,64)
	// LARGE_HASH_EDIT_POINT

	LastTokIsFunc = 0;
	if (!strncmp(pInput, "pad16($p)", 9))   return comp_push_sym("pad16", dynamic_pad16, pInput+9, 0);
	if (!strncmp(pInput, "pad20($p)", 9))   return comp_push_sym("pad20", dynamic_pad20, pInput+9, 0);
	if (!strncmp(pInput, "pad100($p)", 10))  return comp_push_sym("pad100", dynamic_pad100, pInput+10, 0);
	if (!strncmp(pInput, "lc($u)", 6)) { if (bNeedUC&&bNeedUC!=1) return comp_push_sym("X", fpNull, pInput, 0); bNeedU=bNeedUC=1; return comp_push_sym("u_lc", fpNull, pInput+6, 0); }
	if (!strncmp(pInput, "uc($u)", 6)) { if (bNeedUC&&bNeedUC!=2) return comp_push_sym("X", fpNull, pInput, 0); bNeedU=bNeedUC=2; return comp_push_sym("u_uc", fpNull, pInput+6, 0); }
	if (!strncmp(pInput, "lc($p)", 6)) { if (bNeedPC&&bNeedPC!=1) return comp_push_sym("X", fpNull, pInput, 0); bNeedPC=1; return comp_push_sym("p_lc", fpNull, pInput+6, 0); }
	if (!strncmp(pInput, "uc($p)", 6)) { if (bNeedPC&&bNeedPC!=2) return comp_push_sym("X", fpNull, pInput, 0); bNeedPC=2; return comp_push_sym("p_uc", fpNull, pInput+6, 0); }
	LastTokIsFunc = 2;
	if (!strncmp(pInput, "utf16be", 7)) return comp_push_sym("futf16be", dynamic_futf16be, pInput+7, 0);
	if (!strncmp(pInput, "utf16(", 6))   return comp_push_sym("futf16", dynamic_futf16, pInput+5, 0);
	LastTokIsFunc = 0;
	return comp_push_sym("X", fpNull, pInput, 0);
}

static void comp_lexi_error(DC_struct *p, const char *pInput, char *msg) {
	int n;

	fprintf(stderr, "Dyna expression syntax error around this part of expression\n");
	fprintf(stderr, "%s\n", p->pExpr);
	n = strlen(p->pExpr)-strlen(pInput);
	if (SymTab[nSyms-1][0] != 'X')
		n--;
	while (n--)
		fprintf(stderr, " ");
	fprintf(stderr, "^\n");
	if (SymTab[nSyms-1][0] != 'X')
		fprintf(stderr, "Invalid token found\n");
	else
		fprintf(stderr, "%s\n", msg);
	error_msg("exiting now");
}

static char *comp_optimize_script(char *pScr) {
	/*
	 * in this function, we optimize out certain key issues.  We add the MGF_KEYS_IN1 if we can, and remove
	 * the clean/key_load.   Also, if there is a trailing copy of input2 to input just to crypt_final from 1,
	 * then we fix that.
	 */
	char *cp = strstr(pScr, "Func=");

	if (!cp)
		return pScr;

	if (!strncmp(cp, "Func=DynamicFunc__clean_input_kwik\nFunc=DynamicFunc__append_keys\n", 64)) {
		char *cp2 = mem_alloc_tiny(strlen(pScr), 1);
		snprintf(cp2, strlen(pScr), "%*.*sFlag=MGF_KEYS_INPUT%s", (int)(cp-pScr), (int)(cp-pScr), pScr, &cp[64]);
		// now make sure there are no other append_keys, or cleans.
		// I think this is all that we need to know, but there may be other things to look for.
		// we may not want to set this flag if we 'use'
		if (!strstr(cp2, "DynamicFunc__clean_input\n") && !strstr(cp2, "DynamicFunc__clean_input_kwik\n") &&
		    !strstr(cp2, "DynamicFunc__append_keys\n") && !strstr(cp2, "DynamicFunc__clean_input_full\n") &&
		    !strstr(cp2, "DynamicFunc__append_salt\n") && !strstr(cp2, "DynamicFunc__append_salt\n") &&
		    !strstr(cp2, "DynamicFunc__append_input1") && !strstr(cp2, "DynamicFunc__append_2nd_salt\n") &&
		    !strstr(cp2, "DynamicFunc__append_userid\n") && !strstr(cp2, "DynamicFunc__append_keys_pad") &&
		    !strstr(cp2, "DynamicFunc__overwrite_keys\n") &&
		    !strstr(cp2, "DynamicFunc__overwrite_salt\n") &&   !strstr(cp2, "DynamicFunc__overwrite_salt\n") &&
		    !strstr(cp2, "DynamicFunc__overwrite_input1") &&   !strstr(cp2, "DynamicFunc__overwrite_2nd_salt\n") &&
		    !strstr(cp2, "DynamicFunc__overwrite_userid\n") && !strstr(cp2, "DynamicFunc__overwrite_keys_pad")
			)
			pScr = cp2;
	}
	return pScr;
}

static char *comp_optimize_script_mixed(char *pScr, char *pParams) {
	/*
	 * in this function, we optimize out certain key issues.  We add the MGF_KEYS_IN1 if we can, and remove
	 * the clean/key_load.   Also, if there is a trailing copy of input2 to input just to crypt_final from 1,
	 * then we fix that.
	 */
	char *cp = strstr(pScr, "Func="), *cp2, *pNewScr;
	const char *param;
	int sha1=0, md45=0, inplen=55, saltlen=0;

	if (!cp)
		return pScr;

	param = get_param(pParams, "maxinplen");
	if (!param) {
		// ok for unsalted, just use 55
		if (strstr(pScr, "$s"))
			return pScr;
		inplen = 55;
	} else
		inplen = atoi(param);
	if (inplen < 6 || inplen > 55)
		return pScr;
	param = get_param(pParams, "saltlen");
	if (param) {
		saltlen = atoi(param);
		if (abs(saltlen) < 6 || saltlen > 55)
			return pScr;
	}

	// ok, see if we can convert this into a mixed SIMD hash.

	// First, the hash must be fully MD4/MD5 or fully SHA1 (MD4/MD5 can have a mix of both)
	cp2 = strstr(pScr, "_crypt_");
	if (strstr(pScr, "$u")) goto SkipFlat; // skip any hash with user name
	if (strstr(pScr, "$s2")) goto SkipFlat; // skip any hash with 2nd salt
	if (strstr(pScr, "pad")) goto SkipFlat; // skip pad16/pad20's
	if (strstr(pScr, "$c")) goto SkipFlat; // skip any hash with constants (we 'could' deal with this if we want later)
	if (!strstr(pScr, "MaxInputLen=110")) goto SkipFlat;  // if so complex that it would not fit a 110 byte PLAIN in 247 byte flat, then do not even try.
	while (cp2) {
		if (!strncmp(&cp2[-3], "MD5_", 4) || !strncmp(&cp2[-4], "MD4_", 4))
			++md45;
		else if (!strncmp(&cp2[-4], "SHA1_", 5))
			goto SkipFlat;//++sha1;
		else
			goto SkipFlat;
		cp2 = strstr(&cp2[1], "_crypt_");
	}
	if ((md45 && !sha1) || (sha1 && !md45)) {
		// possible.
		int len = strlen(pScr)+150*(md45+sha1);
		char *cpI, *cpO;
		pNewScr = mem_alloc_tiny(len, 1);
		cpI = pScr, cpO = pNewScr;
		while (*cpI) {
			if (*cpI == 'F' && cpI[1] == 'l') {
				// might be 'flag='
				if (!strncmp(cpI, "Flag=MGF_FLAT_BUFFERS\n", 22)) {
					cpI += 22;
					continue;
				}
			}
			if (*cpI == 'F' && cpI[1] == 'u') {
				// might be 'Func=crypt'
				if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt", 27)) {
					if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt_input1_to_output1_FINAL\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt_md5\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt_input2_to_output1_FINAL\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt_md5_in2_to_out1\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt_input1_append_input2\n", 49)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt_md5_in1_to_out2\nFunc=DynamicFunc__append_from_last_output2_as_base16\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt_input2_append_input2\n", 49)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt2_md5\nFunc=DynamicFunc__append_from_last_output2_as_base16\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt_input1_overwrite_input2\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__clean_input2\nFunc=DynamicFunc__crypt_md5_in1_to_out2\nFunc=DynamicFunc__append_from_last_output2_as_base16\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD5_crypt_input2_overwrite_input2\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt2_md5\nFunc=DynamicFunc__overwrite_from_last_output2_to_input2_as_base16_no_size_fix\n");
					}
					cpI = strchr(cpI, '\n');
					++cpI;
					continue;
				}
				if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt", 27)) {
					if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt_input1_to_output1_FINAL\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt_md4\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt_input2_to_output1_FINAL\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt_md4_in2_to_out1\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt_input1_append_input2\n", 49)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt_md4_in1_to_out2\nFunc=DynamicFunc__append_from_last_output2_as_base16\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt_input2_append_input2\n", 49)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt2_md4\nFunc=DynamicFunc__append_from_last_output2_as_base16\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt_input1_overwrite_input2\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__clean_input2\nFunc=DynamicFunc__crypt_md4_in1_to_out2\nFunc=DynamicFunc__append_from_last_output2_as_base16\n");
					} else if (!strncmp(cpI, "Func=DynamicFunc__MD4_crypt_input2_overwrite_input2\n", 52)) {
						cpO += sprintf(cpO, "Func=DynamicFunc__crypt2_md4\nFunc=DynamicFunc__overwrite_from_last_output2_to_input2_as_base16_no_size_fix\n");
					}
					cpI = strchr(cpI, '\n');
					++cpI;
					continue;
				}
			}
			*cpO++ = *cpI++;
		}
		*cpO++ = 0;
		// ok, recompute (and fix) MaxInLen and SaltLen
		pScr = pNewScr;
//		inplen = 55;
//		cp2 = strstr(pScr, "SaltLen=");
//		if (cp2) {
//			int salt_cnt=0;
//			if (!salt_as_hex_type && !strncmp(cp2, "SaltLen=-32", 11)) {
//				memcpy(cp2, "SaltLen=-16", 11);
//				saltlen=16;
//			} else
//				sscanf(cp2, "SaltLen=%d", &saltlen);
//			if (saltlen < 0) saltlen *= -1;
//			cp2 = strstr(pScr, "$s");
//			while (cp2) {
//				salt_cnt++;
//				cp2 = strstr(&cp2[1], "$s");
//			}
//			// ok, salt_cnt will be count of salts in the expression, and all 3 of the test strings, so divide by 4
//			salt_cnt /= 4;
//			len -= salt_cnt*saltlen;
//		}
//		if (inplen < 8) goto SkipFlat;
		cp2 = strstr(pScr, "MaxInputLen=110");
		cp2 += 12;
		memcpy(cp2, "   ", 3);
		len = sprintf(cp2, "%d", inplen);
		cp2[len] = ' ';
		// change all _clean_input_kwik to _clean_input
		cp2 = strstr(pScr, "_clean_input_kwik");
		while (cp2) {
			memcpy(cp2, "_clean_input     ", 17);
			cp2 = strstr(cp2, "_clean_input_kwik");
		}
		cp2 = strstr(pScr, "_clean_input2_kwik");
		while (cp2) {
			memcpy(cp2, "_clean_input2     ", 18);
			cp2 = strstr(cp2, "_clean_input2_kwik");
		}
	}
SkipFlat:;
	return pScr;
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
		while (p > pBuf && *p != '.' && *p != '(')
			--p;
		if (p==pBuf)
			goto SkipSaltCheck;
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
			// Ignore lc() and uc() */
			n2 = 0;
			p = strstr(pBuf, "$s");
			while (p && (p[-1] != '(' || p[-2] != 'c' ||
			             (p[-3] != 'l' && p[-3] != 'u'))) {
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
SkipSaltCheck:;
	/*
	 * End of SALT_AS_HEX optimization
	 */

	/*
	 * Look for MGF_KEYS_BASE16_IN1 optimization  1 level deep, except any hash($p), and have hash($p)
	 * also eliminate things from this optimization such as  md5(md5($p)) or md5(sha1($p))  Those are
	 * faster done in other methods.
	 */
	p = strstr(pBuf, "($p)");
	n1 = 0;
	while (p) {
		++n1;
		p = strstr(&p[1], "($p)");
	}
	if (n1) {
		// make sure they are all the same crypt type
		char cpType[48];
		p = strstr(pBuf, "($p)");
		--p;
		while (p > pBuf && *p != '.' && *p != '(')
			--p;
		if (p==pBuf)
			goto SkipPassCheck;
		p2 = cpType;
		++p;
		while (p[-1] != ')' && p2-cpType < sizeof(cpType)-1)
			*p2++ = *p++;
		*p2 = 0;
		if (islower(ARCH_INDEX(*cpType)) && !strstr(cpType, "_raw") && !strstr(cpType, "_64") && strncmp(cpType, "utf", 3) && strncmp(cpType, "pad", 3) && strncmp(cpType, "lc(", 3) && strncmp(cpType, "uc(", 3)) {
			p = strstr(pBuf, cpType);
			n2 = 0;
			while (p) {
				++n2;
				p = strstr(&p[1], cpType);
			}
			if (n1 == n2) {
				// ok, make sure no other expressions (we do not have input buffers to handle them.
				// NOTE, we 'could' handle salt as hex, but they should have been cleared already,
				// and only $s are left. We 'also' could handle an expression (even semi complex)
				// if it is the FIRST thing. SO md5(md5($p.$s.$u).md5($p).$s) we can still use this
				// optimization, because we can build our md5($p.$s.$u) in buffer2, then crypt over
				// writing buffer 2, then do the appends.  We may not add this on the very first
				// iteration of this optimization.

				// simple check, count '('.  It should be 1 more than n1.
				n2 = 0;
				p = strchr(pBuf, '(');
				while (p) {
					++n2;
					p = strchr(&p[1], '(');
				}
				// if the ONLY thing is hash($p), then do not use this optimzation.
				if (n1 == n2-1) {
					// Make SURE there is something 'more' than just hash($p).  If not, we
					// have code that is FASTER than using this optimization, so let this
					// one NOT be optimized in this way.
					n1 = 0;
					p = strchr(pBuf, '$');
					while (p) {
						++n1;
						p = strchr(&p[1], '$');
					}
					if (n1 > 1) {
						// we can MGF_KEYS_BASE16_IN1
						keys_base16_in1_type = mem_alloc(strlen(cpType)+1);
						strcpy(keys_base16_in1_type, cpType);
						// see if this is a bOffsetHashIn1 type.
						if (n1 == 1) {
							p = strchr(pExpr, '(');
							++p;
							if (!strncmp(p, cpType, strlen(cpType)))
								bOffsetHashIn1=1;
						}
					}
				}
			}
		}
	}
SkipPassCheck:;
	/*
	 * Look for common sub-expressions  we handle crypt($p), crypt($s.$p) crypt($p.$s)
	 */
	return pBuf;
}

static int comp_do_lexi(DC_struct *p, const char *pInput) {
	int paren = 0;

	pInput = comp_get_symbol(pInput);
	if (LastTokIsFunc != 1)
		error_msg("Error: dynamic hash must start with md4/md5/sha1 and NOT a *_raw version. This expression one does not\n");
	while (SymTab[nSyms-1][0] != 'X') {
		if (LastTokIsFunc) {
			pInput = comp_get_symbol(pInput);
			if (SymTab[nSyms-1][0] != '(')
				comp_lexi_error(p, pInput, "A ( MUST follow one of the hash function names");
			continue;
		}
		if (SymTab[nSyms-1][0] == '(') {
			pInput = comp_get_symbol(pInput);
			if (SymTab[nSyms-1][0] == 'X' || SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == '(' || SymTab[nSyms-1][0] == ')' || SymTab[nSyms-1][0] == '^')
				comp_lexi_error(p, pInput, "Invalid token following a ( character");
			++paren;
			continue;
		}
		if (SymTab[nSyms-1][0] == ')') {
			--paren;
			if (*pInput == 0 && *pInput != '^') {
				if (!paren) {
					// expression is VALID and syntax check successful
#ifdef WITH_MAIN
					if (!GEN_BIG)
					printf("The expression checks out as valid\n");
#endif
					return nSyms;
				}
				comp_lexi_error(p, pInput, "Not enough ) characters at end of expression");
			}
			if (paren == 0 && *pInput != '^')
				comp_lexi_error(p, pInput, "Reached the matching ) to the initial ( and there is still more expression left");
			pInput = comp_get_symbol(pInput);
			// only . ) or ^ are valid to follow a )
			if (!(SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == ')' || SymTab[nSyms-1][0] == '^'))
				comp_lexi_error(p, pInput, "The only things valid to follow a ) char are a . or a )");
			continue;
		}
		if (SymTab[nSyms-1][0] == '^') {
			if (*pInput == 0) {
				if (!paren) {
					// expression is VALID and syntax check successful
#ifdef WITH_MAIN
					if (!GEN_BIG)
						printf("The expression checks out as valid\n");
#endif
					return nSyms;
				}
				comp_lexi_error(p, pInput, "Not enough ) characters at end of expression");
			}
			pInput = comp_get_symbol(pInput);
			// only a . or ) are valid
			if (SymTab[nSyms-1][0] != '.' && SymTab[nSyms-1][0] != ')')
				comp_lexi_error(p, pInput, "The only things valid to follow a ^# is a . )");
			continue;
		}
		if (SymTab[nSyms-1][0] == '.') {
			pInput = comp_get_symbol(pInput);
			// any unknown, or a: . ( ) ^  are not valid to follow a .
			if (SymTab[nSyms-1][0] == 'X' || SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == '(' || SymTab[nSyms-1][0] == ')' || SymTab[nSyms-1][0] == '^')
				comp_lexi_error(p, pInput, "Invalid token following the . character");
			continue;
		}
		// some string op
		pInput = comp_get_symbol(pInput);
		// The only thing that can follow a string op is a . or a )
		if (!(SymTab[nSyms-1][0] == '.' || SymTab[nSyms-1][0] == ')'))
			comp_lexi_error(p, pInput, "The only things valid to follow a string type are a . or a )");
	}
	return 0;
}

static void push_pcode(const char *v, fpSYM _fpSym, int len) {
	pCode[nCode] = mem_alloc(strlen(v)+1);
	fpCode[nCode] = _fpSym;
	nLenCode[nCode] = len;
	strcpy(pCode[nCode++], v);
}

static void comp_do_parse(int cur, int curend) {
	char *curTok;
	fpSYM fpcurTok;
	int curTokLen;

	if (SymTab[cur][0] == '(' && SymTab[curend][0] == ')') {++cur; --curend; }
	while (cur <= curend) {
		curTok = SymTab[cur];
		fpcurTok = fpSymTab[cur];
		curTokLen = nSymTabLen[cur];
		if (*curTok == '.') {
			push_pcode(curTok, dynamic_exp, 0);
			curTok = SymTab[++cur];
			//++cur;
			continue;
		}
		if (*curTok == '^') {
			push_pcode(curTok, dynamic_exp, 0);
			curTok = SymTab[++cur];
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
			push_pcode("push", dynamic_push, 0);
			//. recursion
			comp_do_parse(cur, tail);
			cur = tail+1;
			// now output right code to do the crypt;
			push_pcode(curTok, fpcurTok, curTokLen);
			continue;
		}
		++cur;
		switch(*curTok) {
			case 's':
				//if (!strcmp(gen_stype, "tohex")) push_pcode("app_sh");
				//else
					push_pcode("app_sh", dynamic_app_sh, 0);
				bNeedS = 1;
				continue;
			case 'p':
			{
				if (!strcmp(curTok, "p"))
					push_pcode("app_p", dynamic_app_p, 0);
				else if (!strcmp(curTok, "pad16"))
					push_pcode("pad16", dynamic_pad16, 0);
				else if (!strcmp(curTok, "pad20"))
					push_pcode("pad20", dynamic_pad20, 0);
				else if (!strcmp(curTok, "pad100"))
					push_pcode("pad100", dynamic_pad100, 0);
				else if (!strcmp(curTok, "p_lc")) {
					bNeedPlc = 1;
					push_pcode("app_p_lc", dynamic_app_p_lc, 0);
				} else if (!strcmp(curTok, "p_uc")) {
					bNeedPuc = 1;
					push_pcode("app_p_uc", dynamic_app_p_uc, 0);
				}
				continue;
			}
			case 'S': push_pcode("app_s2", dynamic_app_S, 0); bNeedS2 = 1; continue;
			case 'u':
			{
				bNeedU = 1;
				if (!strcmp(curTok, "u"))
					push_pcode("app_u", dynamic_app_u, 0);
				else if (!strcmp(curTok, "u_lc")) {
					bNeedUlc = 1;
					push_pcode("app_u_lc", dynamic_app_u_lc, 0);
				} else if (!strcmp(curTok, "u_uc")) {
					bNeedUuc = 1;
					push_pcode("app_u_uc", dynamic_app_u_uc, 0);
				}
				continue;
			}
			case '1': push_pcode("app_1", dynamic_app_1, 0); continue;
			case '2': push_pcode("app_2", dynamic_app_2, 0); continue;
			case '3': push_pcode("app_3", dynamic_app_3, 0); continue;
			case '4': push_pcode("app_4", dynamic_app_4, 0); continue;
			case '5': push_pcode("app_5", dynamic_app_5, 0); continue;
			case '6': push_pcode("app_6", dynamic_app_6, 0); continue;
			case '7': push_pcode("app_7", dynamic_app_7, 0); continue;
			case '8': push_pcode("app_8", dynamic_app_8, 0); continue;
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

	// NOTE, VC (2015 under Win10), vsnprintf() if fully C99
	// compliant.  _vsnprintf() is kept the broken MSVC for
	// backward compliance
//#ifdef _MSC_VER  // we should find out about MinGW here!!
//	pScriptLines[nScriptLines][len] = 0;
//	while (len2 == -1) {
//		MEM_FREE(pScriptLines[nScriptLines]);
//		len *= 2;
//		pScriptLines[nScriptLines] = mem_alloc(len+1);
//		va_end(va);
//		va_start(va, fmt);
//		len2 = vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
//		pScriptLines[nScriptLines][len] = 0;
//	}
//#else
	if (len2 >= len) {
		MEM_FREE(pScriptLines[nScriptLines]);
		len = len2+1;
		pScriptLines[nScriptLines] = mem_alloc(len+1);
		va_end(va);
		va_start(va, fmt);
		vsnprintf(pScriptLines[nScriptLines], len, fmt, va);
	}
//#endif
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

// This is the 'crypt-all' for the RecursiveDecentParser code
// This will be called from within dynamic_fmt crypt_all, IF
// the compiler does not generate a valid script. john will
// still process the data properly, but it does so much slower.
void run_one_RDP_test(DC_ProcData *p) {
	int n;
	unsigned char *in;

	strnzcpy(gen_pw, p->iPw, p->nPw+1);
	ngen_Stack = 0;
	dynamic_push();
	if (bNeedPuc) {
		strcpy(gen_puc, gen_pw);
		strupr(gen_puc);
	}
	else if (bNeedPlc) {
		strcpy(gen_plc, gen_pw);
		strlwr(gen_plc);
	}
	if (bNeedU) {
		strnzcpy(gen_u, (char*)(p->iUsr), p->nUsr+1);
		if (bNeedUuc) {
			strcpy(gen_uuc, gen_u);
			strupr(gen_uuc);
		}
		else if (bNeedUlc) {
			strcpy(gen_ulc, gen_u);
			strlwr(gen_ulc);
		}
	}
	*gen_s = 0;
	if (bNeedS) {
		nSaltLen = p->nSlt;
		strnzcpy(gen_s, (char*)(p->iSlt), p->nSlt+1);
	}
	if (bNeedS2) {
		strnzcpy(gen_s2, (char*)(p->iSlt2), p->nSlt2+1);
	}
	for (nCurCode = 0; nCurCode < nCode; ++nCurCode)
		fpCode[nCurCode]();
	in = (unsigned char*)(gen_Stack[0]);
	for (n = 0; n < 16; ++n) {
		p->oBin[n] = (atoi16[in[0]] << 4) + atoi16[in[1]];
		in += 2;
	}
}

// Ported from pass_gen.pl dynamic_run_compiled_pcode() function.
static void build_test_string(DC_struct *p, char **pLine) {
	int i;
	char salt[INTERNAL_TMP_BUFSIZE];
	dynamic_push();
	*gen_s = 0;
	strcpy(gen_plc, gen_pw);
	strcpy(gen_puc, gen_pw);
	strlwr(gen_plc);
	strupr(gen_puc);
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
#undef IF
#define IF(T,F) if (!strcmp(tmp, #T)) F##_hex()
#undef ELSEIF
#define ELSEIF(T,F) else if (!strcmp(tmp, #T)) F##_hex()

		IF(MD5,md5); ELSEIF(MD4,md4); ELSEIF(SHA1,sha1); ELSEIF(SHA224,sha224); ELSEIF(SHA256,sha256); ELSEIF(SHA384,sha384); ELSEIF(SHA512,sha512);
		ELSEIF(WHIRLPOOL,whirlpool); ELSEIF(TIGER,tiger); ELSEIF(GOST,gost);
		ELSEIF(RIPEMD128,ripemd128); ELSEIF(RIPEMD160,ripemd160); ELSEIF(RIPEMD256,ripemd256); ELSEIF(RIPEMD320,ripemd320);
		ELSEIF(HAVAL128_3,haval128_3); ELSEIF(HAVAL128_4,haval128_4); ELSEIF(HAVAL128_5,haval128_5);
		ELSEIF(HAVAL160_3,haval160_3); ELSEIF(HAVAL160_4,haval160_4); ELSEIF(HAVAL160_5,haval160_5);
		ELSEIF(HAVAL192_3,haval192_3); ELSEIF(HAVAL192_4,haval192_4); ELSEIF(HAVAL192_5,haval192_5);
		ELSEIF(HAVAL224_3,haval224_3); ELSEIF(HAVAL224_4,haval224_4); ELSEIF(HAVAL224_5,haval224_5);
		ELSEIF(HAVAL256_3,haval256_3); ELSEIF(HAVAL256_4,haval256_4); ELSEIF(HAVAL256_5,haval256_5);
		ELSEIF(MD2,md2); ELSEIF(PANAMA,panama);
		ELSEIF(SKEIN224,skein224); ELSEIF(SKEIN256,skein256);
		ELSEIF(SKEIN384,skein384); ELSEIF(SKEIN512,skein512);
		ELSEIF(SHA3_224,sha3_224); ELSEIF(SHA3_256,sha3_256); ELSEIF(SHA3_384,sha3_384); ELSEIF(SHA3_512,sha3_512);
		ELSEIF(KECCAK_224,keccak_224); ELSEIF(KECCAK_256,keccak_256); ELSEIF(KECCAK_384,keccak_384); ELSEIF(KECCAK_512,keccak_512);
		// LARGE_HASH_EDIT_POINT

		else { error_msg("ERROR in dyna-parser. Have salt_as_hex_type set, but do not KNOW this type of hash\n"); }
	}
	for (nCurCode = 0; nCurCode < nCode; ++nCurCode)
		fpCode[nCurCode]();
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
	if (bNeedPuc) strupr(gen_pw);
	else if (bNeedPlc) strlwr(gen_pw);
	comp_add_script_line("Test=%s:%s\n", *pLine, gen_pw);
	for (i = 0; i < ngen_Stack_max; ++i)
		MEM_FREE(gen_Stack[i]);
	ngen_Stack = ngen_Stack_max = 0;
}

static int compile_keys_base16_in1_type(char *pExpr, DC_struct *_p, int salt_hex_len, int keys_hex_len) {
	// ok, for this type, we simply walk the expression, parsing it again. We 'know' this
	// is a simple expression.
	int len = strlen(keys_base16_in1_type), i, side=2;
	char *p = strchr(pExpr, '('), *pScr;

	*p++ = 0;
	if (bOffsetHashIn1) {
		side = 1;
		comp_add_script_line("Func=DynamicFunc__set_input_len_%d\n", keys_hex_len);
	} else {
		comp_add_script_line("Func=DynamicFunc__clean_input2_kwik\n");
	}
	while (*p) {
		if (*p == '$') {
			++p;
			if (*p == 's') {
				++p;
				if (*p == '2'){ ++p; comp_add_script_line("Func=DynamicFunc__append_2nd_salt%s\n", side==2?"2":""); }
				else                 comp_add_script_line("Func=DynamicFunc__append_salt%s\n", side==2?"2":"");
			} else if (*p == 'p') { ++p; comp_add_script_line("Func=DynamicFunc__append_keys%s\n", side==2?"2":"");
			} else if (*p == 'u') { ++p; comp_add_script_line("Func=DynamicFunc__append_userid%s\n", side==2?"2":"");
			} else if (*p == 'c') { ++p; comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST%c\n", side==2?"2":"1", *p++);
			}
		} else if (!strncmp(p, keys_base16_in1_type, len)) {
			p += len;
			if (!bOffsetHashIn1)
				comp_add_script_line("Func=DynamicFunc__append_input2_from_input\n");
		} else if (*p == '.')
			++p;
		else if (*p == ')' && p[1] == 0) {
			++p;
		} else {
			error_msg("compile_keys_base16_in1_type() : Error parsing %s, we got to %s\n", _p->pExpr, p);
		}
	}
#undef IF
#undef ELSEIF
#define IF(C,L,F) if (!strncasecmp(pExpr, #C, L)) { \
	comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%d_to_output1_FINAL\n",side); \
	if (F) { comp_add_script_line("Flag=MGF_INPUT_" #F "_BYTE\n"); } }
#define ELSEIF(C,L,F) else if (!strncasecmp(pExpr, #C, L)) { \
	comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%d_to_output1_FINAL\n",side); \
	if (F) { comp_add_script_line("Flag=MGF_INPUT_" #F "_BYTE\n"); } }

	// now compute just what hash function was used.
	IF(MD5,3,0) ELSEIF(MD4,3,0) ELSEIF(SHA1,4,20)
	ELSEIF(SHA224,6,28) ELSEIF(SHA256,6,32) ELSEIF(SHA384,6,48) ELSEIF(SHA512,6,64)
	ELSEIF(GOST,4,32) ELSEIF(Tiger,5,24) ELSEIF(WHIRLPOOL,9,64)
	ELSEIF(RIPEMD128,9,0) ELSEIF(RIPEMD160,9,20) ELSEIF(RIPEMD256,9,32) ELSEIF(RIPEMD320,9,40)
	ELSEIF(HAVAL128_3,10, 0) ELSEIF(HAVAL128_4,10, 0) ELSEIF(HAVAL128_5,10, 0)
	ELSEIF(HAVAL160_3,10,20) ELSEIF(HAVAL160_4,10,20) ELSEIF(HAVAL160_5,10,20)
	ELSEIF(HAVAL192_3,10,24) ELSEIF(HAVAL192_4,10,24) ELSEIF(HAVAL192_5,10,24)
	ELSEIF(HAVAL224_3,10,28) ELSEIF(HAVAL224_4,10,28) ELSEIF(HAVAL224_5,10,28)
	ELSEIF(HAVAL256_3,10,32) ELSEIF(HAVAL256_4,10,32) ELSEIF(HAVAL256_5,10,32)
	ELSEIF(MD2,3,0) ELSEIF(PANAMA,6,32)
	ELSEIF(SKEIN224,8,28) ELSEIF(SKEIN256,8,32)
	ELSEIF(SKEIN384,8,48) ELSEIF(SKEIN512,8,64)
	ELSEIF(SHA3_224,8,28) ELSEIF(SHA3_256,8,32)  ELSEIF(SHA3_384,8,48) ELSEIF(SHA3_512,8,64)
	ELSEIF(KECCAK_224,10,28) ELSEIF(KECCAK_256,10,32) ELSEIF(KECCAK_384,10,48) ELSEIF(KECCAK_512,10,64)
	// LARGE_HASH_EDIT_POINT

	comp_add_script_line("MaxInputLenX86=110\n");
	comp_add_script_line("MaxInputLen=110\n");

	// Build test strings.
	strcpy(gen_pw, "abc");
	build_test_string(_p, &_p->pLine[0]);
	strcpy(gen_pw, "john");
	build_test_string(_p, &_p->pLine[1]);
	strcpy(gen_pw, "passweird");
	build_test_string(_p, &_p->pLine[2]);
	for (i = 0; i < 110; i++)
		gen_pw[i] = 'A' + (i % 26) + ((i % 52) > 25 ? 0x20 : 0);
	gen_pw[i] = 0;
	build_test_string(_p, &_p->pLine[3]);
	strcpy(gen_pw, "");
	build_test_string(_p, &_p->pLine[4]);

	len = i = 0;
	for (i = 0; i < nScriptLines; ++i)
		len += strlen(pScriptLines[i]);
	pScr = mem_alloc_tiny(len+1,1);
	*pScr = 0;
	_p->pScript = pScr;
	for (i = 0; i < nScriptLines; ++i) {
		strcpy(pScr, pScriptLines[i]);
		pScr += strlen(pScr);
	}

	if (OLvL < 3 && compile_debug)
		dump_HANDLE(_p);
	MEM_FREE(pExpr);
	return 0;
}

static int b64_len (int rawlen) {
	// this is the formula for mime with trailing = values. It always jumps up
	// an even 4 bytes, when we cross a base64 block threashold. Even though
	// this may return a slightly larger string size than the actual string
	// we put into the buffer, this function is safe. It may simply make
	// MAX_PLAINTEXT_LENGTH a byte or 2 shorter than it possibly could be.
	return (((((rawlen+2)/3)*4)+3)/4)*4;
}
static int parse_expression(DC_struct *p) {
	int i, len;
	char *pExpr, *pScr;
	int salt_hex_len = 0;
	int keys_hex_len = 0;
	int max_inp_len = 110;

	init_static_data();
	// first handle the extra strings
	if (handle_extra_params(p))
		return 1;
	pExpr = p->pExpr;
	if (OLvL>0)
		pExpr = comp_optimize_expression(pExpr);
	else {
		pExpr = mem_alloc(strlen(p->pExpr)+1);
		strcpy(pExpr,p->pExpr);
	}
	if (!comp_do_lexi(p, pExpr))
		return 1;
	comp_do_parse(0, nSyms-1);

	// Ok, now 'build' the script
	comp_add_script_line("Expression=dynamic=%s\n", p->pExpr);
	comp_add_script_line("Flag=MGF_FLAT_BUFFERS\n");
	if (salt_as_hex_type) {
		char tmp[64], *cp;
		strcpy(tmp, salt_as_hex_type);
		cp = strchr(tmp, '(');
		*cp = 0;
		strupr(tmp);
		comp_add_script_line("Flag=MGF_SALT_AS_HEX_%s\n", tmp);
		if (!strcmp(tmp,"MD5")||!strcmp(tmp,"MD4")||!strcmp(tmp,"RIPEMD128")||!strncmp(tmp,"HAVAL128", 8)||!strcmp(tmp,"MD2")) salt_hex_len = 32;
		if (!strcmp(tmp,"SHA1")||!strcmp(tmp,"RIPEMD160")||!strncmp(tmp,"HAVAL160", 8)) salt_hex_len = 40;
		if (!strcmp(tmp,"TIGER")||!strncmp(tmp,"HAVAL192", 8)) salt_hex_len = 48;
		if (!strcmp(tmp,"SHA224")||!strncmp(tmp,"HAVAL224", 8)||!strcmp(tmp,"SKEIN224")||!strcmp(tmp,"SHA3_224")||!strcmp(tmp,"KECCAK_224")) salt_hex_len = 56;
		if (!strcmp(tmp,"SHA256")||!strcmp(tmp,"RIPEMD256")||!strcmp(tmp,"GOST")||!strncmp(tmp,"HAVAL256",8)||
			!strcmp(tmp,"PANAMA")||!strcmp(tmp,"SKEIN256")||!strcmp(tmp,"SHA3_256")||!strcmp(tmp,"KECCAK_256")) salt_hex_len = 64;
		if (!strcmp(tmp,"RIPEMD320")) salt_hex_len = 80;
		if (!strcmp(tmp,"SHA384")||!strcmp(tmp,"SKEIN384")||!strcmp(tmp,"SHA3_384")||!strcmp(tmp,"KECCAK_384")) salt_hex_len = 96;
		if (!strcmp(tmp,"SHA512")||!strcmp(tmp,"WHIRLPOOL")||!strcmp(tmp,"SKEIN512")||!strcmp(tmp,"SHA3_512")||!strcmp(tmp,"KECCAK_512")) salt_hex_len = 128;
		// LARGE_HASH_EDIT_POINT
	}
	if (keys_base16_in1_type) {
		char tmp[64], *cp;
		strcpy(tmp, keys_base16_in1_type);
		cp = strchr(tmp, '(');
		*cp = 0;
		strupr(tmp);
		comp_add_script_line("Flag=MGF_KEYS_BASE16_IN1_%s\n", tmp);
		if (!strcmp(tmp,"MD5")||!strcmp(tmp,"MD4")||!strcmp(tmp,"RIPEMD128")||!strncmp(tmp,"HAVAL128", 8)||!strcmp(tmp,"MD2")) keys_hex_len = 32;
		if (!strcmp(tmp,"SHA1")||!strcmp(tmp,"RIPEMD160")||!strncmp(tmp,"HAVAL160", 8)) keys_hex_len = 40;
		if (!strcmp(tmp,"TIGER")||!strncmp(tmp,"HAVAL192", 8)) keys_hex_len = 48;
		if (!strcmp(tmp,"SHA224")||!strncmp(tmp,"HAVAL224", 8)||!strcmp(tmp,"SKEIN224")||!strcmp(tmp,"SHA3_224")||!strcmp(tmp,"KECCAK_224")) keys_hex_len = 56;
		if (!strcmp(tmp,"SHA256")||!strcmp(tmp,"RIPEMD256")||!strcmp(tmp,"GOST")||!strncmp(tmp,"HAVAL256",8)||
			!strcmp(tmp,"PANAMA")||!strcmp(tmp,"SKEIN256")||!strcmp(tmp,"SHA3_256")||!strcmp(tmp,"KECCAK_256")) keys_hex_len = 64;
		if (!strcmp(tmp,"RIPEMD320")) keys_hex_len = 80;
		if (!strcmp(tmp,"SHA384")||!strcmp(tmp,"SKEIN384")||!strcmp(tmp,"SHA3_384")||!strcmp(tmp,"KECCAK_384")) keys_hex_len = 96;
		if (!strcmp(tmp,"SHA512")||!strcmp(tmp,"WHIRLPOOL")||!strcmp(tmp,"SKEIN512")||!strcmp(tmp,"SHA3_512")||!strcmp(tmp,"KECCAK_512")) keys_hex_len = 128;
		// LARGE_HASH_EDIT_POINT
	}
	if (bNeedS) comp_add_script_line("Flag=MGF_SALTED\n");
	if (bNeedS2) comp_add_script_line("Flag=MGF_SALTED2\n");
	if (bNeedPuc)
		comp_add_script_line("Flag=MGF_PASSWORD_UPCASE\n");
	if (bNeedPlc)
		comp_add_script_line("Flag=MGF_PASSWORD_LOCASE\n");
	if (bNeedU) {
		if (bNeedUuc)
			comp_add_script_line("Flag=MGF_USERNAME_UPCASE\n");
		else if (bNeedUlc)
			comp_add_script_line("Flag=MGF_USERNAME_LOCASE\n");
		else
			comp_add_script_line("Flag=MGF_USERNAME\n");
	}
	for (i = 1; i < 9; ++i) {
		if (Const[i]) {
			comp_add_script_line("Const%d=%s\n", i, Const[i]);
		} else
			break;
	}

	// we have to dump these items here.  The current code generator smashes them.
	if (compile_debug)
		for (i = 0; i <nCode; ++i)
			printf("%s\n", pCode[i]);

	if (bNeedS || bNeedU || Const[1])
		comp_add_script_line("SaltLen=%d\n", nSaltLen ? nSaltLen : -32);

	if (keys_base16_in1_type) {
		if (OLvL>2) {
			compile_keys_base16_in1_type(pExpr, p, salt_hex_len, keys_hex_len);
			goto AlreadyCompiled;
		}
		else
			return compile_keys_base16_in1_type(pExpr, p, salt_hex_len, keys_hex_len);
	} else
		MEM_FREE(pExpr);

	// Ok now run the script
	{
		int x, i, j, last_push;
		int salt_len = nSaltLen ? nSaltLen : -32;
		int in_unicode = 0, out_raw = 0, out_64 = 0, out_64c = 0, out_16u = 0, flag_utf16 = 0;
		int append_mode = 0, append_mode2 = 0;
		int len_comp = 0, len_comp2 = 0;
		int inp1_clean = 0, exponent = -1;
		int use_inp1 = 1, use_inp1_again = 0;
		int inp_cnt = 0, ex_cnt = 0, salt_cnt = 0;
		int inp_cnt2 = 0, ex_cnt2 = 0, salt_cnt2 = 0;

		if (bNeedS) {
			if (salt_hex_len)
				salt_len = salt_hex_len;
		} else
			salt_len = 0;
		if (salt_len < 0)
			salt_len *= -1;
		if (!keys_as_input) {
			comp_add_script_line("Func=DynamicFunc__clean_input_kwik\n");
			inp1_clean = 1;
			inp_cnt = ex_cnt = salt_cnt = 0;
			len_comp = 0;
		}
		for (i = 0; i < nCode; ++i) {
			if (pCode[i][0] == 'f' || pCode[i][0] == 'F') {
				char func_last_char = pCode[i][strlen(pCode[i])-1];

				if (!inp1_clean && !keys_as_input) {
					comp_add_script_line("Func=DynamicFunc__clean_input_kwik\n");
					inp1_clean = 1;
					inp_cnt = ex_cnt = salt_cnt = 0;
					len_comp = 0;
				}
				if (!strcasecmp(pCode[i], "futf16be")) {
					if (!in_unicode) {
						in_unicode = 1;
						comp_add_script_line("Func=DynamicFunc__setmode_unicodeBE\n");
					}
					if (!flag_utf16) {
						comp_add_script_line("Flag=MGF_UTF8\n");
						flag_utf16 = 1;
					}
				}
				if (!strcasecmp(pCode[i], "futf16")) {
					if (!in_unicode) {
						in_unicode = 1;
						comp_add_script_line("Func=DynamicFunc__setmode_unicode\n");
					}
					if (!flag_utf16) {
						comp_add_script_line("Flag=MGF_UTF8\n");
						flag_utf16 = 1;
					}
				} else if (func_last_char == 'r') {
					if (!out_raw) {
						out_raw = 1;
						comp_add_script_line("Func=DynamicFunc__LargeHash_OUTMode_raw\n");
					}
				} else if (func_last_char == 'H') {
					if (!out_16u) {
						out_16u = 1;
						comp_add_script_line("Func=DynamicFunc__LargeHash_OUTMode_base16u\n");
					}
				} else if (func_last_char == '6') {
					if (!out_64) {
						out_64 = 1;
						comp_add_script_line("Func=DynamicFunc__LargeHash_OUTMode_base64_nte\n");
					}
				} else  if (func_last_char == 'c') {
					if (!out_64c) {
						out_64c = 1;
						comp_add_script_line("Func=DynamicFunc__LargeHash_OUTMode_base64c\n");
					}
				} else {
					// if final hash, then dont clear the mode to normal
					if ( in_unicode && !(!pCode[i+1] || !pCode[i+1][0]))
						comp_add_script_line("Func=DynamicFunc__setmode_normal\n");
					in_unicode = 0;
					if ( (out_raw||out_64||out_64c||out_16u) && !(!pCode[i+1] || !pCode[i+1][0]))
						comp_add_script_line("Func=DynamicFunc__LargeHash_OUTMode_base16\n");
					out_raw = out_64 = out_64c = out_16u = 0;
				}
				// Found next function.  Now back up and load the data
				for (j = i - 1; j >= 0; --j) {
					if (!strcmp(pCode[j], "push") || (exponent >= 0 && !strcmp(pCode[j], "Xush"))) { // push
						last_push = j;
						use_inp1_again = 0;
						for (x = j+1; x < i; ++x) {
							if (pCode[x][0] == 'X')
								continue;
							if (!strncmp(pCode[x], "app_p", 5)) {
								comp_add_script_line("Func=DynamicFunc__append_keys%s\n", use_inp1?"":"2"); use_inp1 ? ++inp_cnt : ++inp_cnt2; }
							else if (!strcmp(pCode[x], "app_s")) {
								comp_add_script_line("Func=DynamicFunc__append_salt%s\n", use_inp1?"":"2"); use_inp1 ? ++salt_cnt : ++salt_cnt2; }
							else if (!strncmp(pCode[x], "app_u", 5)) {
								comp_add_script_line("Func=DynamicFunc__append_userid%s\n", use_inp1?"":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_s2")) {
								comp_add_script_line("Func=DynamicFunc__append_2nd_salt%s\n", use_inp1?"":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_sh")) {
								comp_add_script_line("Func=DynamicFunc__append_salt%s\n", use_inp1?"":"2"); use_inp1 ? ++salt_cnt : ++salt_cnt2; }
							else if (!strcmp(pCode[x], "app_1")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST1\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_2")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST2\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_3")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST3\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_4")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST4\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_5")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST5\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_6")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST6\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_7")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST7\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strcmp(pCode[x], "app_8")) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_CONST8\n", use_inp1?"1":"2"); use_inp1 ? ++ex_cnt : ++ex_cnt2; }
							else if (!strncmp(pCode[x], "IN2", 3)) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_input2\n", use_inp1?"":"2"); if (use_inp1) { len_comp+=len_comp2; ex_cnt+=ex_cnt2; inp_cnt+=inp_cnt2; salt_cnt+=salt_cnt2;} else { len_comp2<<=1; ex_cnt2<<=1; inp_cnt2<<=1; salt_cnt2<<=1; } }
							else if (!strncmp(pCode[x], "IN1", 3)) {
								comp_add_script_line("Func=DynamicFunc__append_input%s_from_input\n", use_inp1?"":"2"); if (use_inp1) { len_comp<<=1; ex_cnt<<=1; inp_cnt<<=1; salt_cnt<<=1; } else { len_comp2+=len_comp; ex_cnt2+=ex_cnt; inp_cnt2+=inp_cnt; salt_cnt2+=salt_cnt; } }
							else if (!strcmp(pCode[x], "pad16")) {
								comp_add_script_line("Func=DynamicFunc__append_keys_pad16\n"); if (use_inp1) len_comp += 16; else len_comp2 += 16; }
							else if (!strcmp(pCode[x], "pad20")) {
								comp_add_script_line("Func=DynamicFunc__append_keys_pad20\n"); if (use_inp1) len_comp += 20; else len_comp2 += 20; }
							else if (!strcmp(pCode[x], "pad100")) {
								comp_add_script_line("Func=DynamicFunc__set_input_len_100\n"); if (use_inp1) len_comp += 100; else len_comp2 += 100; }

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
						if (use_inp1) {
							len_comp += ex_cnt*24;
							len_comp += inp_cnt*max_inp_len;
							len_comp += salt_cnt*salt_len;
							// add in hash_cnt*whatever_size_hash is.
							if (!strncasecmp(pCode[i], "f512", 4 ) || !strncasecmp(pCode[i], "f384", 4)) {
								// the only 64 bit SIMD hashes we have right now. are sha284 and sha512
								if (len_comp > 239) {
									if (inp_cnt) max_inp_len -= (len_comp-239+(inp_cnt-1))/inp_cnt;
									else max_inp_len = (239-len_comp);
									if (max_inp_len <= 0)
										error_msg("This expression can not be handled by the Dynamic engine.\nThere is a 64 bit SIMD subexpression that is longer than the 239 byte max. Its length is %d bytes long, even with 0 byte PLAINTEXT_LENGTH\n", 239-max_inp_len);
								}
							} else if (!strncasecmp(pCode[i], "f5", 2 ) || !strncasecmp(pCode[i], "f4", 2) ||
									   !strncasecmp(pCode[i], "f1", 2) || !strncasecmp(pCode[i], "f224", 4 ) ||
									   !strncasecmp(pCode[i], "f256", 4)) {
								// the only 32 bit SIMD hashes we have right now. are sha284 and sha512
								if (len_comp > 247) {
									if (inp_cnt) max_inp_len -= (len_comp-247+(inp_cnt-1))/inp_cnt;
									else max_inp_len = (247-len_comp);
									if (max_inp_len <= 0)
										error_msg("This expression can not be handled by the Dynamic engine.\nThere is a 32 bit SIMD subexpression that is longer than the 247 byte max. Its length is %d bytes long, even with 0 byte PLAINTEXT_LENGTH\n", 247-max_inp_len);
								}
							} else {
								// non SIMD code can use full 256 byte buffers.
								if (len_comp > 256) {
									if (inp_cnt) max_inp_len -= (len_comp-256+(inp_cnt-1))/inp_cnt;
									else max_inp_len = (256-len_comp);
									if (max_inp_len <= 0)
										error_msg("This expression can not be handled by the Dynamic engine.\nThere is a subexpression that is longer than the 256 byte max. Its length is %d bytes long, even with 0 byte PLAINTEXT_LENGTH\n", 256-max_inp_len);

								}
							}
							len_comp = 0;
						} else {
							len_comp2 += ex_cnt2*24;
							len_comp2 += inp_cnt2*max_inp_len;
							len_comp2 += salt_cnt2*salt_len;
							// add in hash_cnt*whatever_size_hash is.
							if (!strncasecmp(pCode[i], "f512", 4 ) || !strncasecmp(pCode[i], "f384", 4)) {
								// the only 64 bit SIMD hashes we have right now. are sha284 and sha512
								if (len_comp > 239) {
									if (inp_cnt2) max_inp_len -= (len_comp2-239+(inp_cnt2-1))/inp_cnt2;
									else max_inp_len = (239-len_comp2);
									if (max_inp_len <= 0)
										error_msg("This expression can not be handled by the Dynamic engine.\nThere is a 64 bit SIMD subexpression that is longer than the 239 byte max. Its length is %d bytes long, even with 0 byte PLAINTEXT_LENGTH\n", 239-max_inp_len);
								}
							} else if (!strncasecmp(pCode[i], "f5", 2 ) || !strncasecmp(pCode[i], "f4", 2) ||
									   !strncasecmp(pCode[i], "f1", 2) || !strncasecmp(pCode[i], "f224", 4 ) ||
									   !strncasecmp(pCode[i], "f256", 4)) {
								// the only 32 bit SIMD hashes we have right now. are sha284 and sha512
								if (len_comp2 > 247) {
									if (inp_cnt2) max_inp_len -= (len_comp2-247+(inp_cnt2-1))/inp_cnt2;
									else  max_inp_len = (247-len_comp2);
									if (max_inp_len <= 0)
										error_msg("This expression can not be handled by the Dynamic engine.\nThere is a 32 bit SIMD subexpression that is longer than the 247 byte max. Its length is %d bytes long, even with 0 byte PLAINTEXT_LENGTH\n", 247-max_inp_len);
								}
							} else {
								// non SIMD code can use full 256 byte buffers.
								if (len_comp2 > 256) {
									if (inp_cnt2) max_inp_len -= (len_comp2-256+(inp_cnt2-1))/inp_cnt2;
									else max_inp_len = (256-len_comp2);
									if (max_inp_len <= 0)
										error_msg("This expression can not be handled by the Dynamic engine.\nThere is a subexpression that is longer than the 256 byte max. Its length is %d bytes long, even with 0 byte PLAINTEXT_LENGTH\n", 256-max_inp_len);
								}
							}
							len_comp2 = 0;
						}
						if (!pCode[i+1] || !pCode[i+1][0]) {
							// final hash
							char endch = pCode[i][strlen(pCode[i])-1];
							if (endch == 'c') {
								comp_add_script_line("Flag=MGF_INPBASE64b\n");
							} else if (endch == '6') {
								comp_add_script_line("Flag=MGF_INPBASE64m\n");
							} else if (endch == 'H') {
								comp_add_script_line("Flag=MGF_BASE_16_OUTPUT_UPCASE\n");
							}
							// check for sha512 has to happen before md5, since both start with f5
#undef IF
#undef ELSEIF
#define IF(C,T,L,F) if (!strncasecmp(pCode[i], #T, L)) { \
	comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2"); \
	if (F) { comp_add_script_line("Flag=MGF_INPUT_" #F "_BYTE\n"); outer_hash_len = F; } else outer_hash_len = 16; }
#define ELSEIF(C,T,L,F) else if (!strncasecmp(pCode[i], #T, L)) { \
	comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%s_to_output1_FINAL\n", use_inp1?"1":"2"); \
	if (F) { comp_add_script_line("Flag=MGF_INPUT_" #F "_BYTE\n"); outer_hash_len = F; } else outer_hash_len = 16; }

							IF(SHA512,f512,4,64)
							ELSEIF(MD5,f5,2,0)
							ELSEIF(MD4,f4,2,0)
							ELSEIF(SHA1,f1,2,20)
							ELSEIF(SHA224,f224,4,28) ELSEIF(SHA256,f256,4,32) ELSEIF(SHA384,f384,4,48)
							ELSEIF(GOST,fgost,5,32)
							ELSEIF(Tiger,ftig,4,24)
							ELSEIF(WHIRLPOOL,fwrl,4,64)
							ELSEIF(RIPEMD128,frip128,7,0) ELSEIF(RIPEMD160,frip160,7,20) ELSEIF(RIPEMD256,frip256,7,32) ELSEIF(RIPEMD320,frip320,7,40)
							ELSEIF(HAVAL128_3,fhav128_3,9,0)  ELSEIF(HAVAL128_4,fhav128_4,9,0)  ELSEIF(HAVAL128_5,fhav128_5,9,0)
							ELSEIF(HAVAL160_3,fhav160_3,9,20) ELSEIF(HAVAL160_4,fhav160_4,9,20) ELSEIF(HAVAL160_5,fhav160_5,9,20)
							ELSEIF(HAVAL192_3,fhav192_3,9,24) ELSEIF(HAVAL192_4,fhav192_4,9,24) ELSEIF(HAVAL192_5,fhav192_5,9,24)
							ELSEIF(HAVAL224_3,fhav224_3,9,28) ELSEIF(HAVAL224_4,fhav224_4,9,28) ELSEIF(HAVAL224_5,fhav224_5,9,28)
							ELSEIF(HAVAL256_3,fhav256_3,9,32) ELSEIF(HAVAL256_4,fhav256_4,9,32) ELSEIF(HAVAL256_5,fhav256_5,9,32)
							ELSEIF(MD2,fmd2,4,0) ELSEIF(PANAMA,fpan,4,32)
							ELSEIF(SKEIN224,fskn224,7,28) ELSEIF(SKEIN256,fskn256,7,32)
							ELSEIF(SKEIN384,fskn384,7,48) ELSEIF(SKEIN512,fskn512,7,64)
							ELSEIF(SHA3_224,fsha3_224,9,28) ELSEIF(SHA3_256,fsha3_256,9,32) ELSEIF(SHA3_384,fsha3_384,9,48) ELSEIF(SHA3_512,fsha3_512,9,64)
							ELSEIF(KECCAK_224,fkeccak_224,11,28) ELSEIF(KECCAK_256,fkeccak_256,11,32) ELSEIF(KECCAK_384,fkeccak_384,11,48) ELSEIF(KECCAK_512,fkeccak_512,11,64)
							// LARGE_HASH_EDIT_POINT
						} else {
							if (append_mode2 && pCode[last_push-1][0] != '.') {
#undef IF
#undef ELSEIF
#define IF(C,T,L) if (!strncasecmp(pCode[i], #T, L)) \
	{ \
		char type = pCode[i][strlen(pCode[i])-1]; \
		comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%s_%s_input2\n", use_inp1?"1":"2", use_inp1?"append":"overwrite"); \
		if (type=='r') { len_comp2 += nLenCode[i]; } \
		else if (type=='c'||type=='6') { len_comp2 += b64_len(nLenCode[i]); } \
		else { len_comp2 += nLenCode[i]*2; } \
	}
#define ELSEIF(C,T,L) else if (!strncasecmp(pCode[i], #T, L)) \
	{ \
		char type = pCode[i][strlen(pCode[i])-1]; \
		comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%s_%s_input2\n", use_inp1?"1":"2", use_inp1?"append":"overwrite"); \
		if (type=='r') { len_comp2 += nLenCode[i]; } \
		else if (type=='c'||type=='6') { len_comp2 += b64_len(nLenCode[i]); } \
		else { len_comp2 += nLenCode[i]*2; } \
	}
								IF(SHA512,f512,4)
								ELSEIF(MD5,f5,2)
								ELSEIF(MD4,f4,2)
								ELSEIF(SHA1,f1,2)
								ELSEIF(SHA224,f224,4) ELSEIF(SHA256,f256,4) ELSEIF(SHA384,f384,4)
								ELSEIF(GOST,fgost,5)
								ELSEIF(Tiger,ftig,4)
								ELSEIF(WHIRLPOOL,fwrl,4)
								ELSEIF(RIPEMD128,frip128,7) ELSEIF(RIPEMD160,frip160,7) ELSEIF(RIPEMD256,frip256,7) ELSEIF(RIPEMD320,frip320,7)
								ELSEIF(HAVAL128_3,fhav128_3,9) ELSEIF(HAVAL128_4,fhav128_4,9) ELSEIF(HAVAL128_5,fhav128_5,9)
								ELSEIF(HAVAL160_3,fhav160_3,9) ELSEIF(HAVAL160_4,fhav160_4,9) ELSEIF(HAVAL160_5,fhav160_5,9)
								ELSEIF(HAVAL192_3,fhav192_3,9) ELSEIF(HAVAL192_4,fhav192_4,9) ELSEIF(HAVAL192_5,fhav192_5,9)
								ELSEIF(HAVAL224_3,fhav224_3,9) ELSEIF(HAVAL224_4,fhav224_4,9) ELSEIF(HAVAL224_5,fhav224_5,9)
								ELSEIF(HAVAL256_3,fhav256_3,9) ELSEIF(HAVAL256_4,fhav256_4,9) ELSEIF(HAVAL256_5,fhav256_5,9)
								ELSEIF(MD2,fmd2,4) ELSEIF(PANAMA,fpan,4)
								ELSEIF(SKEIN224,fskn224,7) ELSEIF(SKEIN256,fskn256,7)
								ELSEIF(SKEIN384,fskn384,7) ELSEIF(SKEIN512,fskn512,7)
								ELSEIF(SHA3_224,fsha3_224,9) ELSEIF(SHA3_256,fsha3_256,9) ELSEIF(SHA3_384,fsha3_384,9) ELSEIF(SHA3_512,fsha3_512,9)
								ELSEIF(KECCAK_224,fkeccak_224,11) ELSEIF(KECCAK_256,fkeccak_256,11) ELSEIF(KECCAK_384,fkeccak_384,11) ELSEIF(KECCAK_512,fkeccak_512,11)
								// LARGE_HASH_EDIT_POINT
								else {
									if (use_inp1 && !use_inp1_again)
										use_inp1_again = 1;
								}
						} else { // overwrite mode.
#undef IF
#undef ELSEIF
#define IF(C,T,L) if (!strncasecmp(pCode[i], #T, L)) \
	{ \
		char type = pCode[i][strlen(pCode[i])-1]; \
		comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2"); \
		if (type=='r') { inp_cnt2 = ex_cnt2 = salt_cnt2 = 0; len_comp2 = nLenCode[i]; } \
		else if (type=='c'||type=='6') { inp_cnt2 = ex_cnt2 = salt_cnt2 = 0; len_comp2 += b64_len(nLenCode[i]); } \
		else { inp_cnt2 = ex_cnt2 = salt_cnt2 = 0; len_comp2 = nLenCode[i]*2; } \
		append_mode2 = 1; \
	}
#define ELSEIF(C,T,L) else if (!strncasecmp(pCode[i], #T, L)) \
	{ \
		char type = pCode[i][strlen(pCode[i])-1]; \
		comp_add_script_line("Func=DynamicFunc__" #C "_crypt_input%s_overwrite_input2\n", use_inp1?"1":"2"); \
		if (type=='r') { inp_cnt2 = ex_cnt2 = salt_cnt2 = 0; len_comp2 = nLenCode[i]; } \
		else if (type=='c'||type=='6') { inp_cnt2 = ex_cnt2 = salt_cnt2 = 0; len_comp2 += b64_len(nLenCode[i]); } \
		else { inp_cnt2 = ex_cnt2 = salt_cnt2 =0; len_comp2 = nLenCode[i]*2; } \
		append_mode2 = 1; \
	}
								IF(SHA512,f512,4)
								ELSEIF(MD5,f5,2)
								ELSEIF(MD4,f4,2)
								ELSEIF(SHA1,f1,2)
								ELSEIF(SHA224,f224,4) ELSEIF(SHA256,f256,4) ELSEIF(SHA384,f384,4)
								ELSEIF(GOST,fgost,5)
								ELSEIF(Tiger,ftig,4)
								ELSEIF(WHIRLPOOL,fwrl,4)
								ELSEIF(RIPEMD128,frip128,7) ELSEIF(RIPEMD160,frip160,7) ELSEIF(RIPEMD256,frip256,7) ELSEIF(RIPEMD320,frip320,7)
								ELSEIF(HAVAL128_3,fhav128_3,9) ELSEIF(HAVAL128_4,fhav128_4,9) ELSEIF(HAVAL128_5,fhav128_5,9)
								ELSEIF(HAVAL160_3,fhav160_3,9) ELSEIF(HAVAL160_4,fhav160_4,9) ELSEIF(HAVAL160_5,fhav160_5,9)
								ELSEIF(HAVAL192_3,fhav192_3,9) ELSEIF(HAVAL192_4,fhav192_4,9) ELSEIF(HAVAL192_5,fhav192_5,9)
								ELSEIF(HAVAL224_3,fhav224_3,9) ELSEIF(HAVAL224_4,fhav224_4,9) ELSEIF(HAVAL224_5,fhav224_5,9)
								ELSEIF(HAVAL256_3,fhav256_3,9) ELSEIF(HAVAL256_4,fhav256_4,9) ELSEIF(HAVAL256_5,fhav256_5,9)
								ELSEIF(MD2,fmd2,4) ELSEIF(PANAMA,fpan,4)
								ELSEIF(SKEIN224,fskn224,7) ELSEIF(SKEIN256,fskn256,7)
								ELSEIF(SKEIN384,fskn384,7) ELSEIF(SKEIN512,fskn512,7)
								ELSEIF(SHA3_224,fsha3_224,9) ELSEIF(SHA3_256,fsha3_256,9) ELSEIF(SHA3_384,fsha3_384,9) ELSEIF(SHA3_512,fsha3_512,9)
								ELSEIF(KECCAK_224,fkeccak_224,11) ELSEIF(KECCAK_256,fkeccak_256,11) ELSEIF(KECCAK_384,fkeccak_384,11) ELSEIF(KECCAK_512,fkeccak_512,11)
								// LARGE_HASH_EDIT_POINT
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
				if (i==nCode-1 || pCode[i+1][0] != '^')
					pCode[i][0] = 'X';
				else {
					if (exponent < 1)
						exponent = atoi(&pCode[i+1][1])-2;
					else
						--exponent;
					if (!exponent) {
						int k;
						MEM_FREE(pCode[i+1]);
						for (k = i+1; k < nCode; ++k) {
							pCode[k] = pCode[k+1];
							fpCode[k] = fpCode[k+1];
						}
						--nCode;
					}
					--i;
				}
			}
		}
		comp_add_script_line("MaxInputLenX86=%d\n",max_inp_len);
		comp_add_script_line("MaxInputLen=%d\n",max_inp_len);
	}

	// Build test strings.
	strcpy(gen_pw, "abc");
	build_test_string(p, &p->pLine[0]);
	strcpy(gen_pw, "john");
	build_test_string(p, &p->pLine[1]);
	strcpy(gen_pw, "passweird");
	build_test_string(p, &p->pLine[2]);
	for (i = 0; i < max_inp_len; i++)
		gen_pw[i] = 'A' + (i % 26) + ((i % 52) > 25 ? 0x20 : 0);
	gen_pw[i] = 0;
	build_test_string(p, &p->pLine[3]);
	strcpy(gen_pw, "");
	build_test_string(p, &p->pLine[4]);

	len = i = 0;
	for (i = 0; i < nScriptLines; ++i)
		len += strlen(pScriptLines[i]);
	pScr = mem_alloc_tiny(len+1,1);
	*pScr = 0;
	p->pScript = pScr;
	for (i = 0; i < nScriptLines; ++i) {
		strcpy(pScr, pScriptLines[i]);
		pScr += strlen(pScr);
	}

AlreadyCompiled:;
	if (OLvL>1)
		p->pScript = comp_optimize_script(p->pScript);
	if (OLvL>2)
		 p->pScript = comp_optimize_script_mixed(p->pScript, p->pExtraParams);

	if (compile_debug)
		dump_HANDLE(p);

	return 0;
}
DC_struct INVALID_STRUCT = { ~DC_MAGIC };
static DC_HANDLE do_compile(const char *expr, uint32_t crc32) {
	DC_struct *p;
	char *cp;
	const char *cp2;
	int len;

	if (strncmp(expr, "dynamic=", 8))
		return &INVALID_STRUCT;
	p = mem_calloc_tiny(sizeof(DC_struct), sizeof(void*));
	p->magic = ~DC_MAGIC;
	p->crc32 = crc32;
	p->pFmt = NULL; // not setup yet
	p->pExpr = str_alloc_copy(find_the_expression(expr));
	p->pExtraParams = str_alloc_copy(find_the_extra_params(expr));
	len = strlen(expr)+3;
	// start of hexify code for : convert into \x3a
	cp = strchr(expr, ':');
	if (cp)
		do {
			cp = strchr(&cp[1], ':');
			len += 3;	// \x3a is 3 bytes longer than :
		} while (cp);
	cp = mem_calloc_tiny(len, 1);
	p->pSignature = cp;
	//snprintf(cp, len, "@%s@", expr); /* switch ':' into \x3a in result */
	cp2 = expr;
	*cp++ = '@';
	while (*cp2) {
		if (*cp2 == ':') {
			strcpy(cp, "\\x3a"); // copy the literal string \x3a to the output
			++cp2;
			cp += 4;
		} else if (*cp2 == ',') {
			// Any extra params here, which we should filter OUT of the expression
			// stored in the .pot file.
			if (!strncmp(cp2, ",rdp", 4))
				cp2 += 4;
			else if (!strncmp(cp2, ",nolib", 6))
				cp2 += 6;
			else if (cp2[1] == 'O')
				cp2 += 3;
			else if (!strncmp(cp2, ",debug", 6))
				cp2 += 6;
			else
				*cp++ = *cp2++;
		} else
			*cp++ = *cp2++;
	}
	*cp++ = '@';
	*cp = 0;
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
		if (*expr == ',' && expr[1] != 'c')
			break;
		crc32 = jtr_crc32(crc32,*expr);
		++expr;
	}
	return crc32;
}

static DC_HANDLE find_checksum(uint32_t crc32) {
//	DC_list *p;
	if (!pList)
		pList = mem_calloc_tiny(sizeof(DC_list), sizeof(void*));
	//p = pList->next;
	//while (p) {
	//	if (p->value->crc32 == crc32)
	//		return p->value;
	//	p = p->next;
	//}
	return 0;
}

static void add_checksum_list(DC_HANDLE pHand) {
	DC_list *p;

	p = mem_calloc_tiny(sizeof(DC_list), sizeof(void*));
	p->next = pList->next;
	pList->next = p;
}

static char *convert_old_dyna_to_new(char *fld0, char *in, char *out, int outsize, char *expr) {
	char *cp = strchr(&in[1], '$');

	if (!cp)
		return in;
	++cp;
	snprintf(out, outsize-1, "@dynamic=%s@%s", expr, cp);
	out[outsize-1] = 0;
	if (strstr(expr, "$u") && !strstr(out, "$$U")) {
		strcat (out, "$$U");
		strcat (out, fld0);
	}
	return out;
}

int looks_like_bare_hash(const char *fld1) {
	// look for hex string with 'optional' '$' for salt.
	int len = base64_valid_length(fld1, e_b64_hex, 0, 0);

	if (len == (outer_hash_len<<1)) {
		// check salt flag
		return 1;
	}
	return 0;
}

char *dynamic_compile_prepare(char *fld0, char *fld1) {
	static char Buf[INTERNAL_TMP_BUFSIZE], tmp1[64];
	char *cpExpr=0;

	/* Quick cancel of huge lines (eg. zip archives) */
	if (strnlen(fld1, LINE_BUFFER_SIZE + 1) > LINE_BUFFER_SIZE)
		return fld1;

	if (!strncmp(fld1, "$dynamic_", 9)) {
		int num;
		if (strlen(fld1) > 490)
			return fld1;
		if (strstr(fld1, "$HEX$")) {
			char *cpBuilding=fld1;
			char *cp, *cpo;
			int bGood=1;
			static char ct[INTERNAL_TMP_BUFSIZE];

			strnzcpy(ct, cpBuilding, sizeof(ct));
			cp = strstr(ct, "$HEX$");
			cpo = cp;
			*cpo++ = *cp;
			cp += 5;
			while (*cp && bGood) {
				if (*cp == '0' && cp[1] == '0') {
					bGood = 0;
					break;
				}
				if (atoi16[ARCH_INDEX(*cp)] != 0x7f && atoi16[ARCH_INDEX(cp[1])] != 0x7f) {
					*cpo++ = atoi16[ARCH_INDEX(*cp)]*16 + atoi16[ARCH_INDEX(cp[1])];
					*cpo = 0;
					cp += 2;
				} else if (*cp == '$') {
					while (*cp && strncmp(cp, "$HEX$", 5)) {
						*cpo++ = *cp++;
					}
					*cpo = 0;
					if (!strncmp(cp, "$HEX$", 5)) {
						*cpo++ = *cp;
						cp += 5;
					}
				} else {
					return fld1;
				}
			}
			if (bGood)
				cpBuilding = ct;
			// if we came into $HEX$ removal, then cpBuilding will always be shorter
			fld1 = cpBuilding;
		}
		if (sscanf(fld1, "$dynamic_%d$", &num) == 1) {
			if (num >= 50 && num < 1000) {
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
					case 16: type="haval128_3"; break;
					case 17: type="haval128_4"; break;
					case 18: type="haval128_5"; break;
					case 19: type="haval160_3"; break;
					case 20: type="haval160_4"; break;
					case 21: type="haval160_5"; break;
					case 22: type="haval192_3"; break;
					case 23: type="haval192_4"; break;
					case 24: type="haval192_5"; break;
					case 25: type="haval224_3"; break;
					case 26: type="haval224_4"; break;
					case 27: type="haval224_5"; break;
					case 28: type="haval256_3"; break;
					case 29: type="haval256_4"; break;
					case 30: type="haval256_5"; break;
					case 31: type="md2"; break;
					case 32: type="panama"; break;
					case 33: type="skein224"; break;
					case 34: type="skein256"; break;
					case 35: type="skein384"; break;
					case 36: type="skein512"; break;
					case 37: type="sha3_224"; break;
					case 38: type="sha3_256"; break;
					case 39: type="sha3_384"; break;
					case 40: type="sha3_512"; break;
					case 41: type="keccak_256"; break;
					case 42: type="keccak_512"; break;
					case 43: type="keccak_224"; break;
					case 44: type="keccak_384"; break;
					// LARGE_HASH_EDIT_POINT
				}
				if (type) {
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
				}
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
				case 35: cpExpr = "sha1(uc($u).$c1.$p),c1=\\x3a"; break;
				case 36: cpExpr = "sha1($u.$c1.$p),c1=\\x3a"; break;
				case 37: cpExpr = "sha1(lc($u).$p)"; break;
				case 38: cpExpr = "sha1($s.sha1($s.sha1($p)))"; break;
				case 39: cpExpr = "md5($s.pad16($p)),saltlen=-120"; break;
				case 40: cpExpr = "sha1($s.pad20($p)),saltlen=-120"; break;
				//case 30: cpExpr = ""; break;
				//case 30: cpExpr = ""; break;
				//case 30: cpExpr = ""; break;
			}
			if (cpExpr)
				fld1 = convert_old_dyna_to_new(fld0, fld1, Buf, sizeof(Buf), cpExpr);
		}
	}
	// NOTE, we probably could have used dyna_signature at this point, vs creating this options_format item.
	else if (strstr(options_format, "$u") && fld0 && *fld0 && !strstr(fld1, "$$U")) {
		char buf2[sizeof(Buf)];
		// note that Buf may already be fld1, so do not printf into Buf from here on!!
		if (*fld1 == '@')
			snprintf(buf2, sizeof(buf2), "%s$$U%s", fld1, fld0);
		else
			snprintf(buf2, sizeof(buf2), "@%s@%s$$U%s", options_format, fld1, fld0);
		strcpy(Buf, buf2);
		fld1 = Buf;
	} else if (strncmp(fld1, "@dynamic=", 9) && looks_like_bare_hash(fld1)) {
		char buf2[sizeof(Buf)];
		snprintf(buf2, sizeof(buf2), "%s%s", dyna_signature, fld1);
		strcpy(Buf, buf2);
		fld1 = Buf;
	}
	return dynamic_expr_normalize(fld1);
}
char *dynamic_compile_split(char *ct) {
	extern int ldr_in_pot;

	if (strncmp(ct, "dynamic_", 8)) {
		return dynamic_compile_prepare("", ct);
	} else if (strncmp(ct, "@dynamic=", 9) && strncmp(ct, dyna_signature, dyna_sig_len)) {
		// convert back into dynamic= format
		// Note we should probably ONLY do this on 'raw' hashes!
		static char Buf[512];
		snprintf(Buf, sizeof(Buf), "%s%s", dyna_signature, ct);
		ct = Buf;
	} else {
		if (ldr_in_pot == 1 && !strncmp(ct, "@dynamic=", 9)) {
			static char Buf[512], Buf2[512];
			char *cp = strchr(&ct[1], '@');
			if (cp) {
				strnzcpy(Buf, &cp[1], sizeof(Buf));
				snprintf(Buf2, sizeof(Buf2), "%s%s", dyna_signature, Buf);
				ct = Buf2;
			}
		}
	}
	// ok, now 'normalize' the hash if it is dynamic= hash.
	ct = dynamic_expr_normalize(ct);
	return ct;
}

int dynamic_assign_script_to_format(DC_HANDLE H, struct fmt_main *pFmt) {
	int i;

	/* assume compiler success. */
	dynamic_compiler_failed = 0;

	if (!((DC_struct*)H) || ((DC_struct*)H)->magic != DC_MAGIC)
		return -1;
	dyna_script = ((DC_struct*)H)->pScript;
	dyna_signature = ((DC_struct*)H)->pSignature;
	for (i = 0; i < DC_NUM_VECTORS; i++)
		dyna_line[i] = ((DC_struct*)H)->pLine[i];
	dyna_sig_len = strlen(dyna_signature);
	((DC_struct*)H)->pFmt = pFmt;

	if (1) {
		int failed = force_rdp;
		unsigned char *binary;
		int ret, ret2, j;
		void *slt;
		// perform a quick and quiet 'self' test to make sure generated format is valid.
		// if it is NOT valid, we fall back and use a slow (but safe) oSSL version of the
		// parser format, and emit a warning message to user that this expression is not
		// natively handled by the compiler, BUT that we will run it, using sub-optimal
		// oSSL single step engine
		pFmt->methods.init(pFmt);
		for (j = 0; j < 5 && !failed; ++j) {
			union {
				char c[PLAINTEXT_BUFFER_SIZE];
				int align;
			} plain;

			strnzcpy(plain.c, pFmt->params.tests[j].plaintext, sizeof(plain));
			pFmt->methods.clear_keys();
			pFmt->methods.set_key(plain.c, 0);
			binary = (unsigned char*)pFmt->methods.binary(pFmt->params.tests[j].ciphertext);
			slt = pFmt->methods.salt(pFmt->params.tests[j].ciphertext);
			pFmt->methods.set_salt(slt);
			ret = 1;
			pFmt->methods.crypt_all(&ret, 0);
			ret = pFmt->methods.cmp_one(binary, 0);
			ret2 = pFmt->methods.cmp_all(binary, 1);
			if (ret && ret2) {
				ret = pFmt->methods.cmp_exact(pFmt->params.tests[j].ciphertext, 0);
				if (!ret && !failed) {
					if (options.verbosity > VERB_DEFAULT)
						fprintf(stderr, "%s() the dynamic.cmp_exact() failed. This expression can not use the dynamic format\n", __FUNCTION__);
					failed = 1;
				}
			}
			else if (!failed) {
				if (options.verbosity > VERB_DEFAULT)
					fprintf(stderr, "%s() the dynamic.cmp_all/cmp_one() failed. This expression can not use the dynamic format\n", __FUNCTION__);
				failed = 1;
			}
		}
		if (failed) {
			// Now replay, and make sure it does not fail again.
			dynamic_compiler_failed = 1;
			dynamic_switch_compiled_format_to_RDP(pFmt);
			failed = 0;
			for (j = 0; j < 5 && !failed; ++j) {
				union {
					char c[PLAINTEXT_BUFFER_SIZE];
					int align;
				} plain;

				strnzcpy(plain.c, pFmt->params.tests[j].plaintext, sizeof(plain));
				pFmt->methods.clear_keys();
				pFmt->methods.set_key(plain.c, 0);
				binary = (unsigned char*)pFmt->methods.binary(pFmt->params.tests[j].ciphertext);
				slt = pFmt->methods.salt(pFmt->params.tests[j].ciphertext);
				pFmt->methods.set_salt(slt);
				ret = 1;
				pFmt->methods.crypt_all(&ret, 0);
				ret = pFmt->methods.cmp_one(binary, 0);
				if (ret) {
					ret = pFmt->methods.cmp_exact(pFmt->params.tests[j].ciphertext, 0);
					if (!ret && !failed) {
						fprintf(stderr, "%s() the dynamic.cmp_exact() failed. This expression can not be handled by john!\n", __FUNCTION__);
						failed = 1;
					}
				}
				else if (!failed) {
					fprintf(stderr, "%s() the dynamic.cmp_all/cmp_one() failed. This expression can not be handled by john!\n", __FUNCTION__);
					failed = 1;
				}
			}
			if (!failed) {
				fprintf(stderr, "This expression will use the RDP dynamic compiler format.\n");
			}
			else {
				/* not sure what to do :( */
			}
		}
		//pFmt->methods.done();
		//pFmt->private.initialized = 0;
	}
	return 0;
}

void dynamic_compile_done() {
	init_static_data(); /* this will free all allocated crap */
}
#ifdef WITH_MAIN
int ldr_in_pot = 0;

/*****************************************************************************
 * these functions were missing from dynamic_utils.c, so I simply add dummy
 * functions here.  I needed to access dynamic_Demangle() from that file,
 * but there was other baggage along for the ride. When built with WITH_MAIN
 * we use no other code from dynamic_utils.c, so these stubs are safe.
 ****************************************************************************/
int dynamic_IS_VALID(int i, int single_lookup_only) {return 0;}
char *dynamic_LOAD_PARSER_SIGNATURE(int which) {return 0;}
void cfg_init(char *name, int allow_missing) {}
int cfg_get_bool(char *section, char *subsection, char *param, int def) {return 0;}
char *dynamic_PRELOAD_SIGNATURE(int cnt) {return 0;}
/* END of missing functions from dynamic_utils.c */

int big_gen_one(int Num, char *cpExpr) {
	DC_HANDLE p;
	DC_struct *p2;
	int ret;

	ret = dynamic_compile(cpExpr, &p);
	p2 = (DC_struct *)p;
	if (ret || !p2->pScript) return !!printf("Error, null script variable in type %d\n", Num);
	printf("static struct fmt_tests _Preloads_%d[] = {\n", Num);
	/*
	 * FIXME This should be rewritten, using DC_NUM_VECTORS and not
	 * hard coding stuff:
	 */
	printf("    {\"$dynamic_%d$%s\",\"abc\"},\n",Num, strchr(&(p2->pLine[0][1]), '@')+1);
	printf("    {\"$dynamic_%d$%s\",\"john\"},\n",Num, strchr(&(p2->pLine[1][1]), '@')+1);
	printf("    {\"$dynamic_%d$%s\",\"passweird\"},\n",Num, strchr(&(p2->pLine[2][1]), '@')+1);
	printf("    {NULL}};\n");
	return 0;
}
int big_gen(char *cpType, char *cpNum) {
	int Num = atoi(cpNum)*10, ret;
	char szExpr[128];
	char cpTypeU[64];
	DC_HANDLE p;

	GEN_BIG=1;
	strcpy(cpTypeU, cpType);
	strupr(cpTypeU);

	sprintf(szExpr, "dynamic=%s($p)", cpType); //160
	ret = dynamic_compile(szExpr, &p);
	if (ret) return 1;

	printf("/*** Large hash group for %s dynamic_%d to dynamic_%d ***/\n", cpType, Num, Num+8);
	printf("DYNA_PRE_DEFINE_LARGE_HASH(%s,%s,%d)\n", cpTypeU, cpNum, (int)strlen(gen_conv)); // gen_conv still holds the last hash from the simple hash($p) expression.

	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s($s.$p)", cpType); //161
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s($p.$s)", cpType); //162
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s(%s($p))", cpType, cpType); //163
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s(%s_raw($p))", cpType, cpType); //164
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s(%s($p).$s)", cpType, cpType); //165
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s($s.%s($p))", cpType, cpType); //166
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s(%s($s).%s($p))", cpType, cpType, cpType); //167
	if (big_gen_one(Num++, szExpr)) return 1;
	sprintf(szExpr, "dynamic=%s(%s($p).%s($p))", cpType, cpType, cpType); //168
	if (big_gen_one(Num++, szExpr)) return 1;

	return 0;
}
int main(int argc, char **argv) {
	DC_HANDLE p;
	DC_struct *p2;
	int i, ret;

	CRC32_Init_tab();
	compile_debug = 1;
	if (argc == 4 && !strcmp(argv[1], "BIG_GEN"))
		return big_gen(argv[2], argv[3]);
	printf("processing this expression: %s\n\n", argv[1]);
	ret = dynamic_compile(argv[1], &p);
	p2 = (DC_struct *)p;
	if (ret || !p2->pScript) return !!printf("Error, null script variable\n");

	printf("Script:\n-------------\n%s\n\n", p2->pScript);
	printf("Expression:  %s\n", p2->pExpr);
	printf("ExtraParams: %s\n", p2->pExtraParams);
	printf("Signature:   %s\n", p2->pSignature);
	for (i = 0; i < DC_NUM_VECTORS; i++)
		if (p2->pLine[i])
			printf("Test Line:   %s\n", p2->pLine[i]);
	printf("crc32:       %08x\n", p2->crc32);
	if (nConst) {
		int i;
		for (i = 1; i <= nConst; ++i)
			printf("Const%d:      %s\n", i, Const[i]);
	}
	return 0;
}
#endif

#endif /* DYNAMIC_DISABLED */

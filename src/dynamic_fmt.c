/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009-2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2009-2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic 'scriptable' hash cracker for JtR
 *
 * Renamed and changed from md5_gen* to dynamic*.  We handle MD5 and SHA1
 * at the present time.  More crypt types 'may' be added later.
 * Added SHA2 (SHA224, SHA256, SHA384, SHA512), GOST, Whirlpool crypt types.
 * Whirlpool use oSSSL if OPENSSL_VERSION_NUMBER >= 0x10000000, otherwise use sph_* code.
 *
 * There used to be a todo list, and other commenting here. It has been
 * moved to ./docs/dynamic_history.txt
 *
 * KNOWN issues, and things to do.
 *
 *   1. create a new optimize flag, MGF_PASS_AFTER_FIXEDSALT and
 *      MGF_PASS_BEFORE_FIXEDSALT.  Then create DynamicFunc__appendsalt_after_pass[12]
 *      These would only be valid for a FIXED length salted format. Then
 *      we can write the pass right into the buffer, and get_key() would read
 *      it back from there, either skipping over the salt, or removing the salt
 *      from the end. This would allow crypt($s.$p) and crypt($p.s) to be optimized
 *      in the way of string loading, and many fewer buffer copies.  So dyna_1 could
 *      be optimized to something like:
 // dynamic_1  Joomla md5($p.$s)
static DYNAMIC_primitive_funcp _Funcs_1[] =
{
	//Flags=MGF_PASS_BEFORE_FIXEDSALT | MGF_SALTED
	// saltlen=3 (or whatever).  This fixed size is 'key'
	DynamicFunc__appendsalt_after_pass1,
	DynamicFunc__crypt_md5,
	NULL
};
 *      WELL, the fixed size salt, it 'may' not be key for the MGF_PASS_BEFORE_FIXEDSALT,
 *      I think I can make that 'work' for variable sized salts.  But for the
 *      MGF_PASS_AFTER_FIXEDSALT, i.e. crypt($s.$p) the fixed size salt IS key.  I would
 *      like to store all PW's at salt_len offset in the buffer, and simply overwrite the
 *      first part of each buffer with the salt, never moving the password after the first
 *      time it is written. THEN it is very important this ONLY be allowed when we KNOW
 *      the salt length ahead of time.
 *
 *   2. Change regen-salts to be generic. Add the logic to dynamic_fmt.c proper, and change
 *      the fake-salts.c, and options so that 'generic' regen-salts can be done.
 */

#include <string.h>
#include <time.h>

#if AC_BUILT
#include "autoconfig.h"
#endif

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

#if !FAST_FORMATS_OMP
#ifdef _OPENMP
  #define FORCE_THREAD_MD5_body
#endif
#undef _OPENMP
#endif

#ifndef DYNAMIC_DISABLED

#ifdef SIMD_COEF_32
#include "simd-intrinsics.h"
#endif

#include "misc.h"
#include "common.h"
#include "formats.h"
#include "params.h"
#include "md5.h"
#include "md4.h"
#include "dynamic.h"
#include "dynamic_compiler.h"
#include "options.h"
#include "config.h"
#include "sha.h"
#include "sha2.h"
#include "gost.h"
#include "sph_haval.h"
#include "sph_ripemd.h"
#include "sph_tiger.h"
#include "sph_md2.h"
#include "sph_panama.h"
#include "sph_skein.h"
#include "sph_whirlpool.h"
#include "memory.h"
#include "unicode.h"
#include "johnswap.h"
#include "crc32.h"
#include "aligned.h"
#include "fake_salts.h"
#include "base64_convert.h"

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

#ifdef _OPENMP
#include <omp.h>
static unsigned int m_ompt;
#endif

#include "dynamic_types.h"


#if (defined (_OPENMP)||defined(FORCE_THREAD_MD5_body)) && defined (_MSC_VER)
unsigned DES_bs_max_kpc, DES_bs_min_kpc, DES_bs_all_p;
#undef MD5_body
extern void MD5_body(uint32_t x[15],uint32_t out[4]);
#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

static struct fmt_main fmt_Dynamic;
static struct fmt_main *pFmts;
static int nFmts;
static int nLocalFmts;
static struct fmt_main *pLocalFmts;
static int force_md5_ctx;
static void dynamic_RESET(struct fmt_main *fmt);

#define eLargeOut dyna_eLargeOut
eLargeOut_t *eLargeOut;
#define nLargeOff dyna_nLargeOff
unsigned *nLargeOff;


#if ARCH_LITTLE_ENDIAN
#define MD5_swap(x, y, count)
#define MD5_swap2(a,b,c,d,e)
#else
extern char *MD5_DumpHexStr(void *p);
static void MD5_swap(uint32_t *x, uint32_t *y, int count)
{
	do {
		*y++ = JOHNSWAP(*x++);
	} while (--count);
}
#if MD5_X2
static void MD5_swap2(uint32_t *x, uint32_t *x2, uint32_t *y, uint32_t *y2, int count)
{
	do {
		*y++ = JOHNSWAP(*x++);
		*y2++ = JOHNSWAP(*x2++);
	} while (--count);
}
#endif
#endif

#define FORMAT_LABEL		"dynamic"
#define FORMAT_NAME         "Generic MD5"

#ifdef SIMD_COEF_32
 #define GETPOS(i, index)		( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 + ((i)&3) )
 #define SHAGETPOS(i, index)	( (index&(SIMD_COEF_32-1))*4 + ((i)&(0xffffffff-3) )*SIMD_COEF_32 + (3-((i)&3)) ) //for endianity conversion
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		7
#define CIPHERTEXT_LENGTH		32
#define BINARY_SIZE				16
#define BINARY_SIZE_SHA         20
#define BINARY_ALIGN			MEM_ALIGN_WORD

// Computation for 'salt_size'  The salt (and salt2) is appended to the end of the hash entry.
//    The format of a salted entry is:   $dynamic_#$hash$SALT_VAL[$$2SALT2_VAL]
// salt 64 bytes,
// salt2 64 bytes,
// salt signature $ 1 byte
// salt2 signature $$2 3 bytes
// null termination 1 byte.  This this allows 2 64 byte salt's.
// Note, we now have up to 10 of these.
#define SALT_SIZE			(64*4+1+3+1)
#define SALT_ALIGN			MEM_ALIGN_WORD

// slots to do 24 'tests'. Note, we copy the
// same 3 tests over and over again.  Simply to validate that
// tests use 'multiple' blocks.
static struct fmt_tests dynamic_tests[] = {
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL}
};

#ifdef SIMD_COEF_32
// SSE2 works only with 54 byte keys. Thus, md5(md5($p).md5($s)) can NOT be used
// with the SSE2, since that final md5 will be over a 64 byte block of data.
static union SIMD_inpup {
	uint32_t w[(64*SIMD_COEF_32)/sizeof(uint32_t)];
	unsigned char c[64*SIMD_COEF_32];
} *input_buf, *input_buf2;
static union SIMD_crypt {
	uint32_t w[(BINARY_SIZE*SIMD_COEF_32)/sizeof(uint32_t)];
	unsigned char c[BINARY_SIZE*SIMD_COEF_32];
} *crypt_key, *crypt_key2;
static unsigned int (*total_len)[SIMD_COEF_32];
static unsigned int (*total_len2)[SIMD_COEF_32];

#define MMX_INP_BUF_SZ    (sizeof(input_buf[0]) *BLOCK_LOOPS)
#define MMX_INP_BUF2_SZ   (sizeof(input_buf2[0])*BLOCK_LOOPS)
#define MMX_TOT_LEN_SZ    (sizeof(*total_len) *BLOCK_LOOPS)
#define MMX_TOT_LEN2_SZ   (sizeof(*total_len2)*BLOCK_LOOPS)
#define MMX_INP_BUF_SZ    (sizeof(input_buf[0]) *BLOCK_LOOPS)
#define MMX_CRYPT_KEY_SZ  (sizeof(crypt_key[0]) *BLOCK_LOOPS+sizeof(crypt_key[0]))
#define MMX_CRYPT_KEY2_SZ (sizeof(crypt_key2[0])*BLOCK_LOOPS)
#endif

#define FLAT_INP_BUF_SZ (sizeof(MD5_IN)*(MAX_KEYS_PER_CRYPT_X86>>MD5_X2))
#define FLAT_TOT_LEN_SZ (sizeof(unsigned int)*(MAX_KEYS_PER_CRYPT_X86))

MD5_OUT *crypt_key_X86;
MD5_OUT *crypt_key2_X86;
MD5_IN *input_buf_X86;
MD5_IN *input_buf2_X86;
unsigned int *total_len_X86;
unsigned int *total_len2_X86;
BIG_HASH_OUT dynamic_BHO[4];

static int keys_dirty;
// We store the salt here
static unsigned char *cursalt;
// length of salt (so we don't have to call strlen() all the time.
static int saltlen;
int get_dynamic_fmt_saltlen() { return saltlen; }
// This array is for the 2nd salt in the hash.  I know of no hashes with double salts,
// but test type dynamic_16 (which is 'fake') has 2 salts, and this is the data/code to
// handle double salts.
static unsigned char *cursalt2;
static int saltlen2;

static unsigned char *username;
static int usernamelen;

static unsigned char *flds[10];
static int fld_lens[10];

const char *dynamic_itoa16 = itoa16;

#if !defined (_DEBUG)
#define itoa16_w2 __Dynamic_itoa_w2
#define itoa16_w2_u __Dynamic_itoa_w2_u
#define itoa16_w2_l __Dynamic_itoa_w2_l
#endif
unsigned short itoa16_w2_u[256], itoa16_w2_l[256];
unsigned short *itoa16_w2=itoa16_w2_l;

// array of the keys.  Also lengths of the keys. NOTE if store_keys_in_input, then the
// key array will NOT be used (but the length array still is).
#ifndef MAX_KEYS_PER_CRYPT
#define MAX_KEYS_PER_CRYPT MAX_KEYS_PER_CRYPT_X86
#endif
#ifndef PLAINTEXT_LENGTH
#define PLAINTEXT_LENGTH PLAINTEXT_LENGTH_X86
#endif

#define EFFECTIVE_MKPC (MAX_KEYS_PER_CRYPT > MAX_KEYS_PER_CRYPT_X86 ? MAX_KEYS_PER_CRYPT : MAX_KEYS_PER_CRYPT_X86)
#define EFFECTIVE_MAX_LENGTH (PLAINTEXT_LENGTH > PLAINTEXT_LENGTH_X86 ? PLAINTEXT_LENGTH : PLAINTEXT_LENGTH_X86)

// Used to compute length of each string to clean. This is needed, since we have to clean a little more than
// just the length, IF we are cleaning strings that are in different endianity than native for the CPU.
// This is seen on SHA224 (etc) on Intel, or MD5 of BE systems.  We still try to clean 'only' as much as
// we need to, but that is usually MORE than what the length of the stored string is. 8 gives us 7 byte spill
// over, plus 1 byte for the 0x80
#define COMPUTE_EX_LEN(a) ( (a) > (sizeof(input_buf_X86[0].x1.b)-8) ) ? sizeof(input_buf_X86[0].x1.b) : ((a)+8)

// this new 'ENCODED_EFFECTIVE_MAX_LENGTH' needed, since we grab up to 125 bytes of data WHEN in -encode:utf8 mode for a unicode format.
#define ENCODED_EFFECTIVE_MAX_LENGTH (EFFECTIVE_MAX_LENGTH > 125 ? EFFECTIVE_MAX_LENGTH : 125)
static char saved_key[EFFECTIVE_MKPC][ENCODED_EFFECTIVE_MAX_LENGTH + 1];
static int saved_key_len[EFFECTIVE_MKPC];

// this is the max generic location we should target. This keeps us from having blown MD buffers or overwrite
// when in utf8->utf16 mode, where we are handling data that likely is larger than we should handle.  We have to
// handle this larger data, so that we get as many strings with 1 byte utf8 that would convert to data that would
// blow our buffers.  But we want as many as possible for the 2 and 3 byte utf data.
#define MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE (256-17)

// Used in 'get_key' if we are running in store_keys_in_input mode
static char out[ENCODED_EFFECTIVE_MAX_LENGTH + 1];

// This is the GLOBAL count of keys. ALL of the primitives which deal with a count
// will read from this variable.
#if !defined (_DEBUG)
#define m_count m_Dynamic_Count
#endif
unsigned int m_count;

// If we are run in 'specific' mode (say, -format=dynamic -subformat=dynamic_0, then we
// want to 'allow' bare hashes to be 'valid'. This is how we will do this.  We have a boolean
// that if set to true, we will perform a 1 time check within the valid function. If at
// that time we find out that we are cracking (or showing, etc) that we will accept lines
// that are either format of $dynamic_0$hhhhhh...32 or simply in the format of hhhhhhh..32
int dynamic_allow_rawhash_fixup = 0;

// this one IS in the private_dat, but since it is accessed SO much, we pull it
// out prior to 'internal' processing. The others are accessed right from
// the structure, since there are accessed infrequently enough to not matter.
static int dynamic_use_sse;

// If set to 1, then do unicode conversion is many string setting functions.
static int *md5_unicode_convert;

#if !defined (_DEBUG)
#define curdat Dynamic_curdat
#endif
private_subformat_data curdat;

// Helper function that loads out 256 unsigned short array that does base-16 conversions
// This function is called at the 'validation' call that loads our preloads (i.e. only
// called one time, pre 'run' (but will be called multiple times when benchmarking, but
// will NOT impact benchmark times.)   Loading a word at a time (2 bytes), sped up
// the overall run time of dynamic_2 almost 5%, thus this conversion is MUCH faster than
// the fastest byte by byte I could put together.  I tested several ways to  access this
// array of unsigned shorts, and the best way was a 2 step method into an array of long
// integer pointers (thus, load 1/2 the 32 bit word, then the other 1/2, into a 32 bit word).

/*********************************************************************************
 *********************************************************************************
 * Start of the 'normal' *_fmt code for md5-gen
 *********************************************************************************
 *********************************************************************************/

#define KEEP_UNPRINTABLE 0
#define KEEP_NULLS 1

/*
 * Decode HEX$deadcafe salt strings into bytes. If last parameter is KEEP_UNPRINTABLE and there's
 * unprintable characters in the string, bail without decoding (still copy input to output).
 * If last parameter is KEEP_NULLS, anything except embedded nulls will be decoded.
 * Output buffer must at least as big as input buffer.  If hex is decoded, the resulting
 * output will be shorter.
 */
static char *RemoveHEX(char *output, char *input, int only_null)
{
	char *cpi = input;
	char *cpo = output;
	char *cpH = strstr(input, "$HEX$");

	if (!cpH) {
		// should never get here, we have a check performed before this function is called.
		strcpy(output, input);
		return output;
	}

	while (cpi < cpH)
		*cpo++ = *cpi++;

	*cpo++ = *cpi;
	cpi += 5;
	while (*cpi) {
		if (atoi16[ARCH_INDEX(*cpi)] != 0x7f && atoi16[ARCH_INDEX(cpi[1])] != 0x7f) {
			unsigned char c = atoi16[ARCH_INDEX(*cpi)]*16 + atoi16[ARCH_INDEX(cpi[1])];
			if ((only_null && c == 0) || (!only_null && (c < ' ' || c > 0x7e))) {
				strcpy(output, input);
				return output;
			}
			*cpo++ = c;
			cpi += 2;
		} else if (*cpi == '$') {
			while (*cpi && strncmp(cpi, "$HEX$", 5)) {
				*cpo++ = *cpi++;
			}
			if (!strncmp(cpi, "$HEX$", 5)) {
				*cpo++ = *cpi;
				cpi += 5;
			}
		} else {
			strcpy(output, input);
			return output;
		}
	}
	*cpo = 0;
	return output;
}

/*
 * Add $HEX$ encoding for salts where needed.  For canonicalized pot storage, we encode
 * anything containing unprintables or field separators, but never anything else.
 */
static char *AddHEX(char *ciphertext) {
	char *cp;

	if (strncmp(ciphertext, "$dynamic_", 9) && strncmp(ciphertext, "@dynamic=", 9))
		return ciphertext;  // not a dynamic format, so we can not 'fix' it.

	if (!(cp = strchr(&ciphertext[1], ciphertext[0])) || !(cp = strchr(&cp[1], '$')))
		return ciphertext;  // not a salted format.

	if (!strncmp(cp, "$HEX$", 5))
		return ciphertext;  // already HEX$

	unsigned char *s = (unsigned char*)cp++;
	int need_hex = 0;
	if (*cp && (cp[strlen(cp) - 1] == ' ' || cp[strlen(cp) - 1] == '\t'))
		need_hex = 1;
	else
	while (*++s) {
		if (*s < ' ' || *s > 0x7e || *s == ':' || *s == '$') {
			need_hex = 1;
			break;
		}
	}

	/* New length is length of ciphertext, the HEX$ and 2 bytes per char of salt string plus ending null. */
	if (need_hex) {
		static char *out;
		static size_t out_size;
		size_t size_needed = strlen(ciphertext) + 4 + strlen(cp) + 1;

		if (size_needed > out_size) {
			out_size = (size_needed + 1024) / 1024 * 1024;
			out = mem_realloc(out, out_size);
		}

		char *cpx = out;
		cpx += sprintf(out, "%.*sHEX$", (int)(cp - ciphertext), ciphertext);
		while (*cp)
			cpx += sprintf(cpx, "%02x", (unsigned char)(*cp++));

		return out;
	}

	return ciphertext;
}

/*********************************************************************************
 * Detects a 'valid' md5-gen format. This function is NOT locked to anything. It
 * takes its detection logic from the provided fmt_main pointer. Within there,
 * is a 'private' data pointer.  When john first loads the md5-gen, it calls a
 * function which builds proper 'private' data for EACH type of md5-gen. Then
 * john will call valid on EACH of those formats, asking each one if a string is
 * valid. Each format has a 'private' properly setup data object.
 *********************************************************************************/
static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	unsigned int i, cipherTextLen;
	char *cp, fixed_ciphertext[1024];
	private_subformat_data *pPriv = pFmt->private.data;

	if (!pPriv)
		return 0;

	if (strncmp(ciphertext, pPriv->dynamic_WHICH_TYPE_SIG, strlen(pPriv->dynamic_WHICH_TYPE_SIG)))
		return 0;

	/* Quick cancel of huge lines (eg. zip archives) */
	if (strnlen(ciphertext, LINE_BUFFER_SIZE + 1) > LINE_BUFFER_SIZE)
		return 0;

	// this is now simply REMOVED totally, if we detect it.  Doing this solves MANY other problems
	// of leaving it in there. The ONLY problem we still have is NULL bytes.
	if (strstr(ciphertext, "$HEX$")) {
		if (strnlen(ciphertext, sizeof(fixed_ciphertext) + 1) < sizeof(fixed_ciphertext))
			ciphertext = RemoveHEX(fixed_ciphertext, ciphertext, KEEP_NULLS);
	}

	cp = &ciphertext[strlen(pPriv->dynamic_WHICH_TYPE_SIG)];

	if (pPriv->dynamic_base64_inout == 1 || pPriv->dynamic_base64_inout == 3 || pPriv->dynamic_base64_inout == 5)
	{
		// jgypwqm.JsMssPLiS8YQ00$BaaaaaSX
		unsigned int len;
		len = base64_valid_length(cp, pPriv->dynamic_base64_inout==3?e_b64_mime:e_b64_crypt, flg_Base64_MIME_TRAIL_EQ_CNT, 0);
		if (len < 20 || len > pPriv->dynamic_SALT_OFFSET+4) return 0;
		if (pPriv->dynamic_FIXED_SALT_SIZE == 0)
			return !cp[len];
		if (pPriv->dynamic_FIXED_SALT_SIZE && cp[len] != '$')
			return 0;
		if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && strlen(&cp[len+1]) != pPriv->dynamic_FIXED_SALT_SIZE)
			return 0;
		else if (pPriv->dynamic_FIXED_SALT_SIZE < -1 && strlen(&cp[len+1]) > -(pPriv->dynamic_FIXED_SALT_SIZE))
			return  0;
		return 1;
	}
	if (pPriv->dynamic_base64_inout == 2)
	{
		// h3mJrcH0901pqX/m$alex
		unsigned int i;
		for (i = 0; i < 16; ++i) {
			if (atoi64[ARCH_INDEX(cp[i])] == 0x7F)
				return 0;
		}
		if (pPriv->dynamic_FIXED_SALT_SIZE == 0)
			return !cp[i];
		if (pPriv->dynamic_FIXED_SALT_SIZE && cp[16] != '$')
			return 0;
		if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && strlen(&cp[17]) != pPriv->dynamic_FIXED_SALT_SIZE)
			return 0;
		else if (pPriv->dynamic_FIXED_SALT_SIZE < -1 && strlen(&cp[17]) > -(pPriv->dynamic_FIXED_SALT_SIZE))
			return  0;
		if (strlen(cp) < 16)
			return 0;
		return 1;
	}

	if (strlen(cp) < 32)
		return 0;
	cipherTextLen = CIPHERTEXT_LENGTH;
	if (pPriv->dynamic_40_byte_input) {
		cipherTextLen = 40;
	} else if (pPriv->dynamic_48_byte_input) {
		cipherTextLen = 48;
	} else if (pPriv->dynamic_64_byte_input) {
		cipherTextLen = 64;
	} else if (pPriv->dynamic_56_byte_input) {
		cipherTextLen = 56;
	} else if (pPriv->dynamic_80_byte_input) {
		cipherTextLen = 80;
	} else if (pPriv->dynamic_96_byte_input) {
		cipherTextLen = 96;
	} else if (pPriv->dynamic_128_byte_input) {
		cipherTextLen = 128;
	}
	for (i = 0; i < cipherTextLen; i++) {
		if (atoi16[ARCH_INDEX(cp[i])] == 0x7f)
			return 0;
	}
	if ((pPriv->pSetup->flags&MGF_SALTED) == 0) {
		if (!cp[cipherTextLen])
			return 1;
		return 0;
	}

	if (cp[cipherTextLen] && cp[cipherTextLen] != '$')
		return 0;
// NOTE if looking at this in the future, this was not my fix.
	// dynamic_1552: $s1$$Uuser --> 6+len(s1)+1+len(user) <= SALT_SIZE
	if (strlen(&cp[cipherTextLen]) > SALT_SIZE - 3)
		return 0;
// end NOTE.
	if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && ciphertext[pPriv->dynamic_SALT_OFFSET-1] != '$')
		return 0;
	if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]) != pPriv->dynamic_FIXED_SALT_SIZE) {
		// first check to see if this salt has left the $HEX$ in the string (i.e. embedded nulls).  If so, then
		// validate length with this in mind.
		if (!memcmp(&ciphertext[pPriv->dynamic_SALT_OFFSET], "HEX$", 4)) {
			int len = strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]);
			len = (len-4)>>1;
			if (len != pPriv->dynamic_FIXED_SALT_SIZE)
				return 0;
		} else {
			// check if there is a 'salt-2' or 'username', etc  If that is the case, then this is still valid.
			if (strncmp(&ciphertext[pPriv->dynamic_SALT_OFFSET+pPriv->dynamic_FIXED_SALT_SIZE], "$$", 2))
				return 0;
		}
	}
	else if (!regen_salts_options && pPriv->dynamic_FIXED_SALT_SIZE < -1 && strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]) > -(pPriv->dynamic_FIXED_SALT_SIZE)) {
		char *cpX;
// NOTE if looking at this in the future, that was added by Aleksey for #5032
		if (!pPriv->b2Salts && !pPriv->nUserName && !pPriv->FldMask) {
			/* salt-only, strict mode: salt without $HEX$ or $HEX$hex till the end */
			if (!memcmp(&ciphertext[pPriv->dynamic_SALT_OFFSET], "HEX$", 4)) {
				for (i = pPriv->dynamic_SALT_OFFSET + 4; ciphertext[i]; i++)
					if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7f)
						return 0; // not hex
				if ((i - pPriv->dynamic_SALT_OFFSET - 4) % 2 == 1)
					return 0; // odd length
				if ((i - pPriv->dynamic_SALT_OFFSET - 4) / 2 > -(pPriv->dynamic_FIXED_SALT_SIZE))
					return 0; // salt is too long
			} else {
				if (strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]) > -(pPriv->dynamic_FIXED_SALT_SIZE))
					return 0; // salt is too long
			}
		} else if (pPriv->nUserName && !pPriv->b2Salts && !pPriv->FldMask) {
			/* username and maybe salt: no $HEX$ allowed */
			/* Bad, but code searching for $$U would not work with $HEX$ anyway. */
			if (!memcmp(&ciphertext[pPriv->dynamic_SALT_OFFSET], "HEX$", 4))
				return 0; // no $HEX$ here (for simplicity)
			if (!memcmp(&ciphertext[pPriv->dynamic_SALT_OFFSET], "$U", 2)) {
				/* username only */
				if (strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET + 2]) > -(pPriv->dynamic_FIXED_SALT_SIZE))
					return 0; // username is too long
			} else {
				/* salt and username */
				char *t = strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET], "$$U");
				if (!t)
					return 0; // no username
				/* salt_external_to_internal_convert parses fields from right to left, but it may overwrite found fields */
				if (strstr(t + 3, "$$U"))
					return 0; // second $$U is prohibited (for simplicity)
				if (t - &ciphertext[pPriv->dynamic_SALT_OFFSET] > -(pPriv->dynamic_FIXED_SALT_SIZE))
					return 0; // salt is too long
				if (strlen(t + 3) > -(pPriv->dynamic_FIXED_SALT_SIZE))
					return 0; // username is too long
			}
		}
// end NOTE.
		// first check to see if this salt has left the $HEX$ in the string (i.e. embedded nulls).  If so, then
		// validate length with this in mind.
		if (!memcmp(&ciphertext[pPriv->dynamic_SALT_OFFSET], "HEX$", 4)) {
			int len = strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]);
			len = (len-4)>>1;
			if (len > -(pPriv->dynamic_FIXED_SALT_SIZE))
				return 0;
		} else {
			// check if there is a 'salt-2' or 'username', etc  If that is the case, then this is still 'valid'
			cpX = mem_alloc(-(pPriv->dynamic_FIXED_SALT_SIZE) + 3);
			strnzcpy(cpX, &ciphertext[pPriv->dynamic_SALT_OFFSET], -(pPriv->dynamic_FIXED_SALT_SIZE) + 3);
			if (!strstr(cpX, "$$")) {
				MEM_FREE(cpX);
				return 0;
			}
			MEM_FREE(cpX);
		}
	}
	if (pPriv->b2Salts==1 && !strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], "$$2"))
		return 0;
	if (pPriv->nUserName && !strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], "$$U"))
		return 0;
	if (pPriv->FldMask) {
		for (i = 0; i < 10; ++i) {
			if ((pPriv->FldMask & (MGF_FLDx_BIT<<i)) == (MGF_FLDx_BIT<<i)) {
				char Fld[8];
				sprintf(Fld, "$$F%d", i);
				if (!strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], Fld))
					return 0;
			}
		}
	}
	return 1;
}

static char *FixupIfNeeded(char *ciphertext, private_subformat_data *pPriv);
static struct fmt_main *dynamic_Get_fmt_main(int which);
static char *HandleCase(char *cp, int caseType);

// 'wrapper' functions. These are here, so we can call these functions to work on ALL data (not simply within the
// thead, which ONLY wants to work on a subset of the data.  These functions should NOT be called by threading
// code, EVER.  But this functions KNOW what to do.  Some actually have threads, others do not need them.
#ifdef _OPENMP
#ifndef SIMD_COEF_32
const unsigned int OMP_INC = (MD5_X2+1);
const unsigned int OMP_MD5_INC = (MD5_X2+1);
const unsigned int OMP_MD4_INC = (MD5_X2+1);
const unsigned int OMP_SHA1_INC = (MD5_X2+1);
#else
const unsigned int OMP_INC = (MD5_X2+1);
const unsigned int OMP_MD5_INC = (SIMD_PARA_MD5*SIMD_COEF_32);
const unsigned int OMP_MD4_INC = (SIMD_PARA_MD4*SIMD_COEF_32);
const unsigned int OMP_SHA1_INC = (SIMD_PARA_SHA1*SIMD_COEF_32);
#endif // SIMD_COEF_32
#endif // _OPENMP

inline static void __nonMP_DynamicFunc__SSEtoX86_switch_output2()
{
#ifdef _OPENMP
	DynamicFunc__SSEtoX86_switch_output2(0,m_count,0);
#else
	DynamicFunc__SSEtoX86_switch_output2();
#endif
}

inline static void __nonMP_DynamicFunc__append_from_last_output2_to_input1_as_base16()
{
#ifdef _OPENMP
	DynamicFunc__append_from_last_output2_to_input1_as_base16(0,m_count,0);
#else
	DynamicFunc__append_from_last_output2_to_input1_as_base16();
#endif
}

void __nonMP_eLargeOut(eLargeOut_t what)
{
#ifdef _OPENMP
	unsigned int i;
	for (i = 1; i < m_ompt; ++i)
		eLargeOut[i] = what;
#endif
	eLargeOut[0] = what;
}
void __nonMP_nLargeOff(unsigned val)
{
#ifdef _OPENMP
	unsigned int i;
	for (i = 1; i < m_ompt; ++i)
		nLargeOff[i] = val;
#endif
	nLargeOff[0] = val;
}

inline static void md5_unicode_convert_set(int what, int tid)
{
	md5_unicode_convert[tid] = what;
}

inline static int md5_unicode_convert_get(int tid)
{
	return md5_unicode_convert[tid];
}

void __nonMP_md5_unicode_convert(int what)
{
#ifdef _OPENMP
	unsigned int i;
	for (i = 1; i < m_ompt; ++i)
		md5_unicode_convert[i] = what;
#endif
	md5_unicode_convert[0] = what;
}

#if !defined (_OPENMP)
#define md5_unicode_convert_set(what, tid) md5_unicode_convert_set(what, 0)
#define md5_unicode_convert_get(tid)       md5_unicode_convert_get(0)
#define eLargeOut_set(what, tid)  eLargeOut_set(what, 0)
#define eLargeOut_get(tid)        eLargeOut_get(0)
#define nLargeOff_set(val, tid)   nLargeOff_set(val, 0)
#define nLargeOff_get(tid)        nLargeOff_get(0)
#endif

inline static void __nonMP_DynamicFunc__append_keys2()
{
#ifdef _OPENMP
	DynamicFunc__append_keys2(0,m_count,0);
#else
	DynamicFunc__append_keys2();
#endif
}

static void __possMP_DynamicFunc__crypt2_md5()
{
#ifdef _OPENMP
	int i;
	unsigned int inc = OMP_MD5_INC;
//	if (dynamic_use_sse!=1)
//		inc = OMP_INC;
#pragma omp parallel for
	for (i = 0; i < m_count; i += inc)
		DynamicFunc__crypt2_md5(i,i+inc,omp_get_thread_num());
#else
	DynamicFunc__crypt2_md5();
#endif
}

static void __nonMP_DynamicFunc__clean_input()
{
	unsigned int i=0;
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		memset(input_buf, 0, MMX_INP_BUF_SZ);
		memset(total_len, 0, MMX_TOT_LEN_SZ);
		return;
	}
#endif
	for (; i < MAX_KEYS_PER_CRYPT_X86; ++i) {
		//if (total_len_X86[i]) {
#if MD5_X2
			if (i&1)
				memset(input_buf_X86[i>>MD5_X2].x2.b2, 0, COMPUTE_EX_LEN(total_len_X86[i]));
			else
#endif
			memset(input_buf_X86[i>>MD5_X2].x1.b, 0, COMPUTE_EX_LEN(total_len_X86[i]));
			total_len_X86[i] = 0;
		//}
	}
	return;
}

static void __nonMP_DynamicFunc__clean_input2()
{
	unsigned int i=0;
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		memset(input_buf2, 0, MMX_INP_BUF2_SZ);
		memset(total_len2, 0, MMX_TOT_LEN2_SZ);
		return;
	}
#endif
	if (curdat.using_flat_buffers_sse2_ok) {
		memset(total_len2_X86, 0, sizeof(total_len2_X86[0])*MAX_KEYS_PER_CRYPT_X86);
		return;
	}
	for (; i < MAX_KEYS_PER_CRYPT_X86; ++i) {
		//if (total_len2_X86[i]) {
#if MD5_X2
			if (i&1)
				memset(input_buf2_X86[i>>MD5_X2].x2.b2, 0, COMPUTE_EX_LEN(total_len2_X86[i]));
			else
#endif
			memset(input_buf2_X86[i>>MD5_X2].x1.b, 0, COMPUTE_EX_LEN(total_len2_X86[i]));
			total_len2_X86[i] = 0;
		//}
	}
	return;
}

static void __nonMP_DynamicFunc__clean_input_full()
{
#ifdef SIMD_COEF_32
	memset(input_buf, 0, MMX_INP_BUF_SZ);
	memset(total_len, 0, MMX_TOT_LEN_SZ);
#endif
	memset(input_buf_X86, 0, FLAT_INP_BUF_SZ);
	memset(total_len_X86, 0, FLAT_TOT_LEN_SZ);
}

static void __nonMP_DynamicFunc__clean_input2_full()
{
#ifdef SIMD_COEF_32
	memset(input_buf2, 0, MMX_INP_BUF2_SZ);
	memset(total_len2, 0, MMX_TOT_LEN2_SZ);
#endif
	memset(input_buf2_X86, 0, FLAT_INP_BUF_SZ);
	memset(total_len2_X86, 0, FLAT_TOT_LEN_SZ);
}

static void __nonMP_DynamicFunc__clean_input_kwik()
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		memset(total_len, 0, MMX_TOT_LEN_SZ);
		return;
	}
#endif
	memset(total_len_X86, 0, FLAT_TOT_LEN_SZ);
#if !ARCH_LITTLE_ENDIAN
	memset(input_buf_X86, 0, FLAT_INP_BUF_SZ);
#endif
}

#ifndef _OPENMP
static void __nonMP_DynamicFunc__clean_input2_kwik()
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		memset(total_len2, 0, MMX_TOT_LEN2_SZ);
		return;
	}
#endif
	memset(total_len2_X86, 0, FLAT_TOT_LEN_SZ);
#if !ARCH_LITTLE_ENDIAN
	memset(input_buf2_X86, 0, FLAT_INP_BUF_SZ);
#endif
}
#endif

/*********************************************************************************
 * init() here does nothing. NOTE many formats LINKING into us will have a valid
 * that DOES do something, but ours does nothing.
 *********************************************************************************/
static void init(struct fmt_main *pFmt)
{
	private_subformat_data *pPriv = pFmt->private.data;
	unsigned int i;

	//fprintf(stderr, "init(%s)\n", pPriv->dynamic_WHICH_TYPE_SIG);

	/* first off, SAVE the original format structure (owned by JtR).  We may need this later */
	pPriv->pFmtMain = pFmt;
#ifdef _OPENMP
	m_ompt = omp_get_max_threads();
	if (!md5_unicode_convert) {
		md5_unicode_convert = (int*)mem_calloc(m_ompt, sizeof(int));
		eLargeOut = (eLargeOut_t*)mem_calloc(m_ompt, sizeof(eLargeOut_t));
		nLargeOff = (unsigned*)mem_calloc(m_ompt, sizeof(unsigned));
		for (i = 0; i < m_ompt; ++i) {
			eLargeOut[i] = eBase16;
			nLargeOff[i] = 0;
		}
	}
#else
	if (!md5_unicode_convert) {
		md5_unicode_convert = (int*)mem_calloc(1, sizeof(int));
		eLargeOut = (eLargeOut_t*)mem_calloc(1, sizeof(eLargeOut_t));
		eLargeOut[0] = eBase16;
		nLargeOff = (unsigned*)mem_calloc(1, sizeof(unsigned));
		nLargeOff[0] = 0;
	}
#endif
#ifdef SIMD_COEF_32
	if (!input_buf) {
		input_buf  = mem_calloc_align(1, MMX_INP_BUF_SZ, MEM_ALIGN_SIMD);
		total_len  = mem_calloc_align(1, MMX_TOT_LEN_SZ, MEM_ALIGN_SIMD);
		total_len2 = mem_calloc_align(1, MMX_TOT_LEN2_SZ, MEM_ALIGN_SIMD);
		input_buf2 = mem_calloc_align(1, MMX_INP_BUF2_SZ, MEM_ALIGN_SIMD);
		crypt_key  = mem_calloc_align(1, MMX_CRYPT_KEY_SZ, MEM_ALIGN_SIMD);
		crypt_key2 = mem_calloc_align(1, MMX_CRYPT_KEY2_SZ, MEM_ALIGN_SIMD);
	}
#endif
	if (!crypt_key_X86) {
		crypt_key_X86  = (MD5_OUT *)mem_calloc(((MAX_KEYS_PER_CRYPT_X86>>MD5_X2)+1), sizeof(*crypt_key_X86));
		crypt_key2_X86 = (MD5_OUT *)mem_calloc(((MAX_KEYS_PER_CRYPT_X86>>MD5_X2)+1), sizeof(*crypt_key2_X86));
		input_buf_X86  = (MD5_IN *)mem_calloc(((MAX_KEYS_PER_CRYPT_X86>>MD5_X2)+1), sizeof(*input_buf_X86));
		input_buf2_X86 = (MD5_IN *)mem_calloc(((MAX_KEYS_PER_CRYPT_X86>>MD5_X2)+1), sizeof(*input_buf2_X86));
		total_len_X86  = (unsigned int *)mem_calloc((MAX_KEYS_PER_CRYPT_X86+1), sizeof(*total_len_X86));
		total_len2_X86 = (unsigned int *)mem_calloc((MAX_KEYS_PER_CRYPT_X86+1), sizeof(*total_len2_X86));
	}

	for (i = 0; i < 4; ++i)
		dynamic_BHO[i].dat = mem_calloc_align(BLOCK_LOOPS, sizeof(*(dynamic_BHO[0].dat)), MEM_ALIGN_SIMD);

	gost_init_table();
	if (!pPriv || (pPriv->init == 1 && !strcmp(curdat.dynamic_WHICH_TYPE_SIG, pPriv->dynamic_WHICH_TYPE_SIG)))
		return;

	__nonMP_DynamicFunc__clean_input_full();
	__nonMP_DynamicFunc__clean_input2_full();

	// Some builds (omp vs non omp, etc) do not call these functions, so to avoid 'unused' warnings, we simply
	// call them here.
	__nonMP_DynamicFunc__clean_input_kwik();

	dynamic_RESET(pFmt);
	if (!pPriv)
		return;

	pPriv->init = 1;

	memcpy(&curdat, pPriv, sizeof(private_subformat_data));
	dynamic_use_sse = curdat.dynamic_use_sse;
	force_md5_ctx = curdat.force_md5_ctx;

	fmt_Dynamic.params.max_keys_per_crypt = pFmt->params.max_keys_per_crypt;
	fmt_Dynamic.params.min_keys_per_crypt = pFmt->params.min_keys_per_crypt;
	fmt_Dynamic.params.flags              = pFmt->params.flags;
	fmt_Dynamic.params.format_name        = pFmt->params.format_name;
	fmt_Dynamic.params.algorithm_name     = pFmt->params.algorithm_name;
	fmt_Dynamic.params.benchmark_comment  = pFmt->params.benchmark_comment;
	fmt_Dynamic.params.benchmark_length   = pFmt->params.benchmark_length;
// we allow for 3 bytes of utf8 data to make up the number of plaintext_length unicode chars.
	if ( (pFmt->params.flags&FMT_UNICODE) && options.target_enc == UTF_8 ) {
		//printf("Here pFmt->params.plaintext_length=%d pPriv->pSetup->MaxInputLen=%d\n", pFmt->params.plaintext_length, pPriv->pSetup->MaxInputLen);
		pFmt->params.plaintext_length = MIN(125, pFmt->params.plaintext_length * 3);
	}
	else
		fmt_Dynamic.params.plaintext_length   = pFmt->params.plaintext_length;
	fmt_Dynamic.params.salt_size          = pFmt->params.salt_size;
	fmt_Dynamic.params.flags              = pFmt->params.flags;

	fmt_Dynamic.methods.cmp_all    = pFmt->methods.cmp_all;
	fmt_Dynamic.methods.cmp_one    = pFmt->methods.cmp_one;
	fmt_Dynamic.methods.cmp_exact  = pFmt->methods.cmp_exact;
	fmt_Dynamic.methods.set_salt   = pFmt->methods.set_salt;
	fmt_Dynamic.methods.salt       = pFmt->methods.salt;
	fmt_Dynamic.methods.salt_hash  = pFmt->methods.salt_hash;
	fmt_Dynamic.methods.split      = pFmt->methods.split;
	fmt_Dynamic.methods.set_key    = pFmt->methods.set_key;
	fmt_Dynamic.methods.get_key    = pFmt->methods.get_key;
	fmt_Dynamic.methods.clear_keys = pFmt->methods.clear_keys;
	fmt_Dynamic.methods.crypt_all  = pFmt->methods.crypt_all;
	for (i = 0; i < PASSWORD_HASH_SIZES; ++i)
	{
		fmt_Dynamic.methods.binary_hash[i] = pFmt->methods.binary_hash[i];
		fmt_Dynamic.methods.get_hash[i]    = pFmt->methods.get_hash[i];
	}

#if !MD5_IMM
	{
		extern void MD5_std_init(struct fmt_main *pFmt);
		MD5_std_init(pFmt);
	}
#endif

	if (curdat.input2_set_len32) {
		for (i = 0; i < MAX_KEYS_PER_CRYPT_X86; ++i)
			total_len2_X86[i] = 32;
#ifdef SIMD_COEF_32
		for (i = 0; i < BLOCK_LOOPS; ++i) {
			unsigned int j;
			for (j = 0; j < SIMD_COEF_32; j++) {
				input_buf2[i].c[GETPOS(32, j)] = 0x80;
				input_buf2[i].c[GETPOS(57, j)] = 0x1;
				total_len2[i][j] = 0x20;
			}
		}
#endif
	}
}

static void done(void)
{
	int i;

	MEM_FREE(total_len2_X86);
	MEM_FREE(total_len_X86);
	MEM_FREE(input_buf2_X86);
	MEM_FREE(input_buf_X86);
	MEM_FREE(crypt_key2_X86);
	MEM_FREE(crypt_key_X86);
#ifdef SIMD_COEF_32
	MEM_FREE(crypt_key2);
	MEM_FREE(crypt_key);
	MEM_FREE(input_buf2);
	MEM_FREE(total_len2);
	MEM_FREE(total_len);
	MEM_FREE(input_buf);
#endif
	MEM_FREE(nLargeOff);
	MEM_FREE(eLargeOut);
	MEM_FREE(md5_unicode_convert);
	for (i = 0; i < 4; ++i)
		MEM_FREE(dynamic_BHO[i].dat);
}

/*********************************************************************************
 * This function will add a $dynamic_#$ IF there is not one, and if we have a specific
 * format requested.  Also, it will add things like UserID, Domain, Fld3, Fld4,
 * Fld5, etc.
 *********************************************************************************/
static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	private_subformat_data *pPriv = pFmt->private.data;
	char Tmp[80];
	int i;
	int trim_u=0;

	char *cpBuilding=split_fields[1];

	if (!pPriv)
		return split_fields[1];

	// ANY field[1] longer than 490 will simply be ignored, and returned 'as is'.
	// the rest of this function makes this assumption.
	if (!cpBuilding || strnlen(cpBuilding, 491) > 490)
		return cpBuilding;

	// mime. We want to strip off ALL trailing '=' characters to 'normalize' them
	if (pPriv->dynamic_base64_inout == 3 && !strncmp(cpBuilding, "$dynamic_", 9))
	{
		static char ct[496];
		int len;
		char *cp = strchr(&cpBuilding[9], '$'), *cp2;

		if (!cp) return cpBuilding;
		++cp;
		len = base64_valid_length(cp, e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT, 0);
		if (len && cp[len-1] == '=') {
			strnzcpy(ct, cpBuilding, cp-cpBuilding+len+1);
			cp2 = &ct[strlen(ct)-1];
			while (*cp2 == '=')
				*cp2-- = 0;
			if (cp[len])
				strcat(cp2, &cp[len]);
			cpBuilding = ct;
		}
	}

	if (pFmt->params.salt_size && !strchr(split_fields[1], '$')) {
		if (!pPriv->nUserName && !pPriv->FldMask && options.regen_lost_salts == 0)
			return split_fields[1];
	}

	// handle 'older' md5_gen(x) signature, by simply converting to $dynamic_x$ signature
	// Thus older md5_gen() is a valid input (or from john.pot), but ONLY the newer
	// $dynamic_x$ will be written out (into .pot, output lines, etc).
	if (!strncmp(cpBuilding, "md5_gen(", 8))
	{
		static char ct[496];
		char *cp = &cpBuilding[8], *cpo = &ct[sprintf(ct, "$dynamic_")];
		while (*cp >= '0' && *cp <= '9')
			*cpo++ = *cp++;
		*cpo++ = '$';
		++cp;
		strcpy(cpo, cp);
		cpBuilding = ct;
	}
	// At this point, max length of cpBuilding is 491 (if it was a md5_gen signature)

	// allow a raw hash, if there is a $u but no salt
	if (pPriv->nUserName && split_fields[0][0] && !strchr(cpBuilding, '$') && strcmp(split_fields[0], "?")) {
		static char ct[496];
		strcpy(ct, cpBuilding);
		strcat(ct, "$$U");
		cpBuilding = ct;
		trim_u=1;
	}

	cpBuilding = FixupIfNeeded(cpBuilding, pPriv);
	if (trim_u)
		cpBuilding[strlen(cpBuilding)-3] = 0;

	// at this point max length is still < 512.  491 + strlen($dynamic_xxxxx$) is 506

	// If --regen-lost-salts and salt is missing, add the first possible salt
	if (options.regen_lost_salts && !strchr(cpBuilding + strlen(pFmt->params.label) + 2, '$')) {
		char *cp = load_regen_lost_salt_Prepare(cpBuilding);
		if (cp)
			return cp;
	}

	if (strncmp(cpBuilding, "$dynamic_", 9))
		return split_fields[1];

	if ( (pPriv->pSetup->flags&MGF_SALTED) == 0)
		return cpBuilding;

	/* at this point, we want to convert ANY and all $HEX$hex into values */
	/* the reason we want to do this, is so that things read from john.pot file will be in proper 'native' format */
	/* the ONE exception to this, is if there is a NULL byte in the $HEX$ string, then we MUST leave that $HEX$ string */
	/* alone, and let the later calls in dynamic.c handle them. */
	if (strstr(cpBuilding, "$HEX$")) {
		static char ct[512];

		cpBuilding = RemoveHEX(ct, cpBuilding, KEEP_NULLS);
	}

	// at this point max length is still < 512.  491 + strlen($dynamic_xxxxx$) is 506
	if (pPriv->nUserName && !strstr(cpBuilding, "$$U")) {
		if (split_fields[0] && split_fields[0][0] && strcmp(split_fields[0], "?")) {
			char *userName=split_fields[0], *cp;
			static char ct[1024];
			// assume field[0] is in format: username OR DOMAIN\\username  If we find a \\, then  use the username 'following' it.
			cp = strchr(split_fields[0], '\\');
			if (cp)
				userName = &cp[1];
			userName = HandleCase(userName, pPriv->nUserName);
			snprintf(ct, sizeof(ct), "%s$$U%s", cpBuilding, userName);
			cpBuilding = ct;
		}
	}
	if (pPriv->FldMask) {
		for (i = 0; i < 10; ++i) {
			if (pPriv->FldMask&(MGF_FLDx_BIT<<i)) {
				sprintf(Tmp, "$$F%d", i);
				if (split_fields[i] && split_fields[i][0] && strcmp(split_fields[i], "/") && !strstr(cpBuilding, Tmp)) {
					static char ct[1024];
					char ct2[1024];
					snprintf(ct2, sizeof(ct2), "%s$$F%d%s", cpBuilding, i, split_fields[i]);
					strcpy(ct, ct2);
					cpBuilding = ct;
				}
			}
		}
	}

	return cpBuilding;
}

static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[1024];
	private_subformat_data *pPriv = pFmt->private.data;

	if (strnlen(ciphertext, 951) > 950)
		return ciphertext;

	// mime. We want to strip off ALL trailing '=' characters to 'normalize' them
	if (pPriv->dynamic_base64_inout == 3 &&
	    (!strncmp(ciphertext, "$dynamic_", 9) || !strncmp(ciphertext, "@dynamic=", 9)))
	{
		static char ct[496];
		unsigned int len;
		char search_char = (!strncmp(ciphertext, "@dynamic=", 9)) ? '@' : '$';
		char *cp = strchr(&ciphertext[9], search_char), *cp2;

		if (cp) {
			++cp;
			len = base64_valid_length(cp, e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT, 0);
			if (len && cp[len-1] == '=') {
				strnzcpy(ct, ciphertext, cp-ciphertext+len+1);
				cp2 = &ct[strlen(ct)-1];
				while (*cp2 == '=')
					*cp2-- = 0;
				if (cp[len])
					strcat(cp2, &cp[len]);
				ciphertext = ct;
			}
		}
	}

	if (!strncmp(ciphertext, "$dynamic", 8) ||
	    !strncmp(ciphertext, "@dynamic=", 9)) {
		if (strstr(ciphertext, "$HEX$"))
			return AddHEX(RemoveHEX(out, ciphertext, KEEP_UNPRINTABLE));

		return AddHEX(ciphertext);
	}
	if (!strncmp(ciphertext, "md5_gen(", 8)) {
		ciphertext += 8;
		do ++ciphertext; while (*ciphertext != ')')	;
		++ciphertext;
	}
	if (strstr(ciphertext, "$HEX$")) {
		char *cp = out + sprintf(out, "%s", pPriv->dynamic_WHICH_TYPE_SIG);
		RemoveHEX(cp, ciphertext, KEEP_UNPRINTABLE);
	} else
		snprintf(out, sizeof(out), "%s%s", pPriv->dynamic_WHICH_TYPE_SIG, ciphertext);

	/* Add missing $HEX$ encoding (contains unprintables or field separators). */
	return AddHEX(out);
}

// This split unifies case.
static char *split_UC(char *ciphertext, int index, struct fmt_main *pFmt)
{
	static char out[1024];
	char search_char = '$';
	private_subformat_data *pPriv = pFmt->private.data;

	if (!strncmp(ciphertext, "$dynamic", 8)) {
		if (strstr(ciphertext, "$HEX$"))
			RemoveHEX(out, ciphertext, KEEP_UNPRINTABLE);
		else
			strcpy(out, ciphertext);
	} else if (!strncmp(ciphertext, "@dynamic=", 9)) {
		if (strstr(ciphertext, "$HEX$"))
			RemoveHEX(out, ciphertext, KEEP_UNPRINTABLE);
		else
			strcpy(out, ciphertext);
		search_char = '@';
	} else {
		if (!strncmp(ciphertext, "md5_gen(", 8)) {
			ciphertext += 8;
			do ++ciphertext; while (*ciphertext != ')')	;
			++ciphertext;
		}
		if (strstr(ciphertext, "$HEX$")) {
			char *cp = out + sprintf(out, "%s", pPriv->dynamic_WHICH_TYPE_SIG);
			RemoveHEX(cp, ciphertext, KEEP_UNPRINTABLE);
		} else
			sprintf(out, "%s%s", pPriv->dynamic_WHICH_TYPE_SIG, ciphertext);
	}
	ciphertext = strchr(&out[8], search_char)+1;
	while (*ciphertext && *ciphertext != '$') {
		if (*ciphertext >= 'A' && *ciphertext <= 'Z')
			*ciphertext += 0x20; // ASCII specific, but I really do not care.
		++ciphertext;
	}

	/* Add missing $HEX$ encoding (contains unprintables or field separators). */
	return AddHEX(out);
}

/*********************************************************************************
 * Stores the new salt provided into our 'working' salt
 *********************************************************************************/
static void set_salt(void *salt)
{
	unsigned char *cpsalt;
	unsigned int todo_bits=0, i, bit;
	if (!salt || curdat.dynamic_FIXED_SALT_SIZE == 0) {
		saltlen = 0;
		return;
	}
#if ARCH_ALLOWS_UNALIGNED
        cpsalt = *((unsigned char**)salt);
#else
        memcpy(((void*)&(cpsalt)), ((unsigned char **)salt), sizeof(void*));
#endif
	saltlen = *cpsalt++ - '0';
	saltlen <<= 3;
	saltlen += *cpsalt++ - '0';
#if ARCH_ALLOWS_UNALIGNED
	if (*((uint32_t*)cpsalt) != 0x30303030)
#else
	if (memcmp(cpsalt, "0000", 4))
#endif
	{
		// this is why we used base-8. Takes an extra byte, but there is NO conditional
		// logic, building this number, and no multiplication. We HAVE added one conditional
		// check, to see if we can skip the entire load, if it is 0000.
		todo_bits = *cpsalt++ - '0';
		todo_bits <<= 3;
		todo_bits += *cpsalt++ - '0';
		todo_bits <<= 3;
		todo_bits += *cpsalt++ - '0';
		todo_bits <<= 3;
		todo_bits += *cpsalt++ - '0';
	}
	else
		cpsalt += 4;
	cursalt = cpsalt;
	if (!todo_bits) return;
	cpsalt += saltlen;
	if (todo_bits & 1) {
		todo_bits ^= 1; // clear that bit.
		saltlen2 = *cpsalt++;
		cursalt2 = cpsalt;
		if (todo_bits == 0) return;
		cpsalt += saltlen2;
	}
	if (todo_bits & 2) {
		todo_bits ^= 2; // clear that bit.
		usernamelen = *cpsalt++;
		username = cpsalt;
		if (todo_bits == 0) return;
		cpsalt += usernamelen;
	}
	bit = 4;
	for (i = 0; i < 10; ++i, bit<<=1) {
		if (todo_bits & bit) {
			todo_bits ^= bit; // clear that bit.
			fld_lens[i] = *cpsalt++;
			flds[i] = cpsalt;
			if (todo_bits == 0) return;
			cpsalt += fld_lens[i];
		}
	}
}

/*********************************************************************************
 * Sets this key. It will either be dropped DIRECTLY into the input buffer
 * number 1, or put into an array of keys.  Which one happens depends upon
 * HOW the generic functions were laid out for this type. Not all types can
 * load into the input.  If not they MUST use the key array. Using the input
 * buffer is faster, when it can be safely done.
 *********************************************************************************/
static void set_key(char *key, int index)
{
	unsigned int len;

	//printf("idx=%d key=%s\n", index, key);
#ifdef SIMD_COEF_32
	if (curdat.store_keys_in_input==2)
		dynamic_use_sse = 3;
	else if (curdat.md5_startup_in_x86)
		dynamic_use_sse = 2;
	else if (dynamic_use_sse==2)
		dynamic_use_sse = 1;
#endif

	if (curdat.nPassCase>1)
		key = HandleCase(key, curdat.nPassCase);

	// Ok, if the key is in unicode/utf8, we switch it here one time, and are done with it.

	if (curdat.store_keys_in_input)
	{
#ifdef SIMD_COEF_32
		if (dynamic_use_sse==1) {
			// code derived from rawMD5_fmt_plug.c code from magnum
#if ARCH_ALLOWS_UNALIGNED
			const uint32_t *key32 = (uint32_t*)key;
#else
			char buf_aligned[PLAINTEXT_LENGTH + 1] JTR_ALIGN(sizeof(uint32_t));
			const uint32_t *key32 = is_aligned(key, sizeof(uint32_t)) ?
					(uint32_t*)key : (uint32_t*)strcpy(buf_aligned, key);
#endif
			unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
			uint32_t *keybuffer = &input_buf[idx].w[index&(SIMD_COEF_32-1)];
			uint32_t *keybuf_word = keybuffer;
			unsigned int len;
			uint32_t temp;

			len = 0;
			while((temp = *key32++) & 0xff) {
				if (!(temp & 0xff00))
				{
					*keybuf_word = (temp & 0xff) | (0x80 << 8);
					++len;
					goto key_cleaning;
				}
				if (!(temp & 0xff0000))
				{
					*keybuf_word = (temp & 0xffff) | (0x80 << 16);
					len+=2;
					goto key_cleaning;
				}
				if (!(temp & 0xff000000))
				{
					*keybuf_word = temp | (0x80U << 24);
					len+=3;
					goto key_cleaning;
				}
				*keybuf_word = temp;
				len += 4;
				keybuf_word += SIMD_COEF_32;
			}
			*keybuf_word = 0x80;

key_cleaning:
			keybuf_word += SIMD_COEF_32;
			while(*keybuf_word) {
				*keybuf_word = 0;
				keybuf_word += SIMD_COEF_32;
			}
			keybuffer[14*SIMD_COEF_32] = len << 3;
			return;
		}
#endif
		len = strlen(key);
		if (len > 110) // we never do UTF-8 -> UTF-16 in this mode
			len = 110;

//		if (index==0) {
			// we 'have' to use full clean here. NOTE 100% sure why, but 10 formats fail if we do not.
//			__nonMP_DynamicFunc__clean_input_full();
//		}
#if MD5_X2
		if (index & 1)
			memcpy(input_buf_X86[index>>MD5_X2].x2.b2, key, len);
		else
#endif
			memcpy(input_buf_X86[index>>MD5_X2].x1.b, key, len);
		saved_key_len[index] = total_len_X86[index] = len;
	}
	else
	{
		len = strlen(key);
		if (len > 110 && !(fmt_Dynamic.params.flags & FMT_UNICODE))
			len = 110;
//		if (index==0) {
//			__nonMP_DynamicFunc__clean_input_full();
//		}
		keys_dirty = 1;
		memcpy(((char*)(saved_key[index])), key, len);
		saved_key_len[index] = len;
	}
}

static void clear_keys(void)
{
#ifdef SIMD_COEF_32
	if (curdat.pSetup->flags & MGF_FULL_CLEAN_REQUIRED) {
		__nonMP_DynamicFunc__clean_input_full();
		return;
	}
	if (curdat.store_keys_in_input==1 || curdat.store_keys_in_input==3)
		return;
	if (curdat.md5_startup_in_x86)
		__nonMP_DynamicFunc__clean_input_full();

// This clean was causing failures (dirty buffers left) for dyna_51, 61 and formspring.
// once commented out, dyna fully passes.  I see no reason to keep this here at all.
//	else
//		__nonMP_DynamicFunc__clean_input_kwik();
#else
	__nonMP_DynamicFunc__clean_input_full();
#endif
}

/*********************************************************************************
 * Returns the key.  NOTE how it gets it depends upon if we are storing
 * into the array of keys (there we simply return it), or if we are
 * loading into input buffer #1. If in input buffer, we have to re-create
 * the key, prior to returning it.
 *********************************************************************************/
static char *get_key(int index)
{
	if (curdat.store_keys_in_input)
	{
		unsigned int i;
		unsigned char *cp;
#ifdef SIMD_COEF_32
		//if (dynamic_use_sse==1) {
		// Note, if we are not in
		if (dynamic_use_sse && !curdat.md5_startup_in_x86) {
			unsigned int s;
			unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
//if (curdat.store_keys_in_input && dynamic_use_sse==1)

//			s = saved_key_len[index];  // NOTE, we now have to get the length from the buffer, we do NOT store it into a saved_key_len buffer.
			uint32_t *keybuffer = &input_buf[idx].w[index&(SIMD_COEF_32-1)];
			s = keybuffer[14*SIMD_COEF_32] >> 3;
			for (i=0;i<s;i++)
				out[i] = input_buf[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
			out[i] = 0;
			return (char*)out;
		}
#endif
#if MD5_X2
		if (index & 1)
			cp = input_buf_X86[index>>MD5_X2].x2.B2;
		else
#endif
			cp = input_buf_X86[index>>MD5_X2].x1.B;

		for (i=0;i<saved_key_len[index];++i)
			out[i] = cp[i];
		out[i] = 0;
		return (char*)out;
	}
	else
	{
		saved_key[index][saved_key_len[index]] = '\0';
		return saved_key[index];
	}
}

/*********************************************************************************
 * Looks for ANY key that was cracked.
 *********************************************************************************/
static int cmp_all(void *binary, int count)
{
	unsigned int i;
#ifdef SIMD_COEF_32
	unsigned int j;
	if (dynamic_use_sse&1) {
		unsigned int cnt = ( ((unsigned int)count+SIMD_COEF_32-1)/SIMD_COEF_32);
		for (i = 0; i < cnt; ++i)
		{
			for (j = 0; j < SIMD_COEF_32; ++j)
				if ( *((uint32_t *)binary) == crypt_key[i].w[j])
					return 1;
		}
		return 0;
	}
#endif
	for (i = 0; i < count; i++) {
#if MD5_X2
		if (i&1) {
			if (!(((uint32_t *)binary)[0] - crypt_key_X86[i>>MD5_X2].x2.w2[0]))
				return 1;
		}
		else
#endif
		if (!(((uint32_t *)binary)[0] - crypt_key_X86[i>>MD5_X2].x1.w[0]))
			return 1;
	}
	return 0;
}

#if ARCH_LITTLE_ENDIAN
#define MASK_4x6 0x00ffffff
#else
#define MASK_4x6 0xffffff00
#endif
static int cmp_all_64_4x6(void *binary, int count)
{
	unsigned int i;
#ifdef SIMD_COEF_32
	unsigned int j;
	if (dynamic_use_sse==1) {
		unsigned int cnt = ( ((unsigned int)count+SIMD_COEF_32-1)/SIMD_COEF_32);
		for (i = 0; i < cnt; ++i)
		{
			for (j = 0; j < SIMD_COEF_32; ++j)
				if ( *((uint32_t *)binary) == (crypt_key[i].w[j] & MASK_4x6))
					return 1;
		}
		return 0;
	}
#endif
	for (i = 0; i < count; i++) {
#if MD5_X2
		if (i&1) {
			if (!(((uint32_t *)binary)[0] - (crypt_key_X86[i>>MD5_X2].x2.w2[0]&MASK_4x6)))
				return 1;
		}
		else
#endif
		if (!(((uint32_t *)binary)[0] - (crypt_key_X86[i>>MD5_X2].x1.w[0]&MASK_4x6)))
			return 1;
	}
	return 0;
}

/*********************************************************************************
 * In this code, we always do exact compare, so if this function is called, it
 * simply returns true.
 *********************************************************************************/
static int cmp_exact(char *binary, int index)
{
	return 1;
}

/*********************************************************************************
 * There was 'something' that was possibly hit. Now john will ask us to check
 * each one of the data items, for an 'exact' match.
 *********************************************************************************/
static int cmp_one(void *binary, int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		if ( (((uint32_t *)binary)[0] == ((uint32_t *)&(crypt_key[idx].c))[0*SIMD_COEF_32+(index&(SIMD_COEF_32-1))]) &&
			(((uint32_t *)binary)[1] == ((uint32_t *)&(crypt_key[idx].c))[1*SIMD_COEF_32+(index&(SIMD_COEF_32-1))]) &&
			(((uint32_t *)binary)[2] == ((uint32_t *)&(crypt_key[idx].c))[2*SIMD_COEF_32+(index&(SIMD_COEF_32-1))]) &&
			(((uint32_t *)binary)[3] == ((uint32_t *)&(crypt_key[idx].c))[3*SIMD_COEF_32+(index&(SIMD_COEF_32-1))]))
			return 1;
		return 0;
	}
#endif

#if MD5_X2
	if (index & 1) {
		if ( (((uint32_t *)binary)[0] == crypt_key_X86[index>>MD5_X2].x2.w2[0] ) &&
             (((uint32_t *)binary)[1] == crypt_key_X86[index>>MD5_X2].x2.w2[1] ) &&
             (((uint32_t *)binary)[2] == crypt_key_X86[index>>MD5_X2].x2.w2[2] ) &&
             (((uint32_t *)binary)[3] == crypt_key_X86[index>>MD5_X2].x2.w2[3] ) )
			 return 1;
		return 0;
	}
#endif
	if ( (((uint32_t *)binary)[0] == crypt_key_X86[index>>MD5_X2].x1.w[0] ) &&
		 (((uint32_t *)binary)[1] == crypt_key_X86[index>>MD5_X2].x1.w[1] ) &&
		 (((uint32_t *)binary)[2] == crypt_key_X86[index>>MD5_X2].x1.w[2] ) &&
		 (((uint32_t *)binary)[3] == crypt_key_X86[index>>MD5_X2].x1.w[3] ) )
		 return 1;
	return 0;
}

static int cmp_one_64_4x6(void *binary, int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		if ( (((uint32_t *)binary)[0] == (((uint32_t *)&(crypt_key[idx].c))[0*SIMD_COEF_32+(index&(SIMD_COEF_32-1))] & MASK_4x6)) &&
			(((uint32_t *)binary)[1] == (((uint32_t *)&(crypt_key[idx].c))[1*SIMD_COEF_32+(index&(SIMD_COEF_32-1))] & MASK_4x6)) &&
			(((uint32_t *)binary)[2] == (((uint32_t *)&(crypt_key[idx].c))[2*SIMD_COEF_32+(index&(SIMD_COEF_32-1))] & MASK_4x6)) &&
			(((uint32_t *)binary)[3] == (((uint32_t *)&(crypt_key[idx].c))[3*SIMD_COEF_32+(index&(SIMD_COEF_32-1))] & MASK_4x6)))
			return 1;
		return 0;
	}
#endif
#if MD5_X2
	if (index & 1) {
		if ( (((uint32_t*)binary)[0] == (crypt_key_X86[index>>MD5_X2].x2.w2[0] & MASK_4x6)) &&
			 (((uint32_t*)binary)[1] == (crypt_key_X86[index>>MD5_X2].x2.w2[1] & MASK_4x6)) &&
			 (((uint32_t*)binary)[2] == (crypt_key_X86[index>>MD5_X2].x2.w2[2] & MASK_4x6)) &&
			 (((uint32_t*)binary)[3] == (crypt_key_X86[index>>MD5_X2].x2.w2[3] & MASK_4x6)) )
			return 1;
		return 0;
	}
#endif
	if ( (((uint32_t*)binary)[0] == (crypt_key_X86[index>>MD5_X2].x1.w[0] & MASK_4x6)) &&
		 (((uint32_t*)binary)[1] == (crypt_key_X86[index>>MD5_X2].x1.w[1] & MASK_4x6)) &&
		 (((uint32_t*)binary)[2] == (crypt_key_X86[index>>MD5_X2].x1.w[2] & MASK_4x6)) &&
		 (((uint32_t*)binary)[3] == (crypt_key_X86[index>>MD5_X2].x1.w[3] & MASK_4x6)) )
		return 1;
	return 0;
}

/*********************************************************************************
 *********************************************************************************
 *  This is the real 'engine'.  It simply calls functions one
 *  at a time from the array of functions.
 *********************************************************************************
 *********************************************************************************/
static int crypt_all(int *pcount, struct db_salt *salt)
{
	// set m_count.  This is our GLOBAL value, used by ALL of the script functions to know how
	// many keys are loaded, and how much work we do.
	m_count = *pcount;
	__nonMP_eLargeOut(eBase16);
	__nonMP_nLargeOff(0);

#ifdef SIMD_COEF_32
	// If this format is MMX built, but is supposed to start in X86 (but be switchable), then we
	// set that value here.
	if (curdat.store_keys_in_input==2)
		dynamic_use_sse = 3;
	else if (curdat.md5_startup_in_x86)
		dynamic_use_sse = 2;
	else if (dynamic_use_sse==2)
		dynamic_use_sse = 1;
#endif

	__nonMP_md5_unicode_convert(0);

	if (curdat.dynamic_base16_upcase) {
		dynamic_itoa16 = itoa16u;
		itoa16_w2 = itoa16_w2_u;
	}
	else {
		dynamic_itoa16 = itoa16;
		itoa16_w2 = itoa16_w2_l;
	}

	// There may have to be some 'prelim' work done with the keys.  This is so that if we 'know' that keys were
	// loaded into the keys[] array, but that we should do something like md5 and base-16 put them into an
	// input slot, then we do that FIRST, prior to calling the script functions.  Thus for a format such as
	// md5(md5($p).$s)  we could md5 the pass, and base-16 put it into a input buffer.  Then when john sets salt
	// and calls crypt all, the crypt script would simply set the input len to 32, append the salt and call a
	// single crypt.  That eliminates almost 1/2 of the calls to md5_crypt() for the format show in this example.
	if (keys_dirty)
	{
		int did_key_clean = 0;
		// NOTE, once we KNOW the proper MIN_KEYS_PER_CRYPT for each format, then we can change this to:
		//    if (m_count % curdat.min_keys_per_crypt)
		// That will only clean if they 'last' crypt block is not fully filled in. But for now, any
		// short block (that is NOT the global MIN_KEYS_PER_CRYPT), will be fully cleaned, even if it
		// does not need to be.
		if (m_count < MAX_KEYS_PER_CRYPT && m_count != MIN_KEYS_PER_CRYPT) {
			did_key_clean = 1;
			__nonMP_DynamicFunc__clean_input2_full();
			__nonMP_DynamicFunc__clean_input_full();
		}
		if (curdat.store_keys_normal_but_precompute_hash_to_output2)
		{
			keys_dirty = 0;
			if (!did_key_clean) {
				if (curdat.pSetup->flags & MGF_FULL_CLEAN_REQUIRED2)
					__nonMP_DynamicFunc__clean_input2_full();
				else
					__nonMP_DynamicFunc__clean_input2();
			}
			if (curdat.store_keys_in_input_unicode_convert)
				__nonMP_md5_unicode_convert(1);
			__nonMP_DynamicFunc__append_keys2();
			__nonMP_md5_unicode_convert(0);

			//if (curdat.using_flat_buffers_sse2_ok) {
			if (curdat.dynamic_use_sse == 0) {
				if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1) {
#ifdef _OPENMP
#define CASE(H) case MGF__##H: DynamicFunc__##H##_crypt_input2_overwrite_input1(0,m_count,0); break
#else
#define CASE(H) case MGF__##H: DynamicFunc__##H##_crypt_input2_overwrite_input1(); break
#endif
					switch(curdat.store_keys_normal_but_precompute_hash_to_output2_base16_type)
					{
						CASE(MD5);
						CASE(MD4);
						CASE(SHA1);
						CASE(SHA224);
						CASE(SHA256);
						CASE(SHA384);
						CASE(SHA512);
						CASE(GOST);
						CASE(WHIRLPOOL);
						CASE(Tiger);
						CASE(RIPEMD128);
						CASE(RIPEMD160);
						CASE(RIPEMD256);
						CASE(RIPEMD320);
						CASE(HAVAL128_3);
						CASE(HAVAL128_4);
						CASE(HAVAL128_5);
						CASE(HAVAL160_3);
						CASE(HAVAL160_4);
						CASE(HAVAL160_5);
						CASE(HAVAL192_3);
						CASE(HAVAL192_4);
						CASE(HAVAL192_5);
						CASE(HAVAL224_3);
						CASE(HAVAL224_4);
						CASE(HAVAL224_5);
						CASE(HAVAL256_3);
						CASE(HAVAL256_4);
						CASE(HAVAL256_5);
						CASE(MD2);
						CASE(PANAMA);
						CASE(SKEIN224);
						CASE(SKEIN256);
						CASE(SKEIN384);
						CASE(SKEIN512);
						CASE(SHA3_224);
						CASE(SHA3_256);
						CASE(SHA3_384);
						CASE(SHA3_512);
						CASE(KECCAK_224);
						CASE(KECCAK_256);
						CASE(KECCAK_384);
						CASE(KECCAK_512);
						// LARGE_HASH_EDIT_POINT
					}
				} else if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX) {
					unsigned int i;
					for (i = 0; i < m_count; ++i)
						total_len_X86[i] = curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX;
#undef CASE
#ifdef _OPENMP
#define CASE(H) case MGF__##H: DynamicFunc__##H##_crypt_input2_append_input1(0,m_count,0); break
#else
#define CASE(H) case MGF__##H: DynamicFunc__##H##_crypt_input2_append_input1(); break
#endif

					switch(curdat.store_keys_normal_but_precompute_hash_to_output2_base16_type) {
						CASE(MD5);
						CASE(MD4);
						CASE(SHA1);
						CASE(SHA224);
						CASE(SHA256);
						CASE(SHA384);
						CASE(SHA512);
						CASE(GOST);
						CASE(WHIRLPOOL);
						CASE(Tiger);
						CASE(RIPEMD128);
						CASE(RIPEMD160);
						CASE(RIPEMD256);
						CASE(RIPEMD320);
						CASE(HAVAL128_3);
						CASE(HAVAL128_4);
						CASE(HAVAL128_5);
						CASE(HAVAL160_3);
						CASE(HAVAL160_4);
						CASE(HAVAL160_5);
						CASE(HAVAL192_3);
						CASE(HAVAL192_4);
						CASE(HAVAL192_5);
						CASE(HAVAL224_3);
						CASE(HAVAL224_4);
						CASE(HAVAL224_5);
						CASE(HAVAL256_3);
						CASE(HAVAL256_4);
						CASE(HAVAL256_5);
						CASE(MD2);
						CASE(PANAMA);
						CASE(SKEIN224);
						CASE(SKEIN256);
						CASE(SKEIN384);
						CASE(SKEIN512);
						CASE(SHA3_224);
						CASE(SHA3_256);
						CASE(SHA3_384);
						CASE(SHA3_512);
						CASE(KECCAK_224);
						CASE(KECCAK_256);
						CASE(KECCAK_384);
						CASE(KECCAK_512);
						// LARGE_HASH_EDIT_POINT
					}
				} else {
					// calls 'old' code (ossl, sorry :(   We should FIND and remove any format
					// written this way, if it is
					__possMP_DynamicFunc__crypt2_md5();
				}
			} else {
				__possMP_DynamicFunc__crypt2_md5();
				if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1)
				{
					if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1==2)
						__nonMP_DynamicFunc__SSEtoX86_switch_output2();
					__nonMP_DynamicFunc__clean_input();
					__nonMP_DynamicFunc__append_from_last_output2_to_input1_as_base16();
				}
			}
		}
	}

	// Ok, now we 'run' the script. We simply call 1 function right after the other.
	// ALL functions are void f(void).  They use the globals:
	//   input_buf1[] input_buf2[] (requires thread safety)
	//   total_len1[] total_len2[]   (requires thread safety)
	//   crypt1[] crypt2[]           (requires thread safety)
	//   md5_unicode_convert         (requires thread safety, had to change to array)
	//   saved_key[]                 (const?)
	//   saved_key_len[]             (const)
	//   cursalt, cursalt2           (const)
	//   saltlen, saltlen2           (const)
	//   m_count                     (const)
	//   nConsts                     (const)
	//   Consts[], ConstsLen[]       (const)

	// Since this array is in a structure, we assign a simple pointer to it
	// before walking.  Trivial improvement, but every cycle counts :)

	if (dynamic_compiler_failed) {
		unsigned int i;
		DC_ProcData dc;
		dc.iSlt = cursalt;
		dc.nSlt = saltlen;
		dc.iSlt2 = cursalt2;
		dc.nSlt2 = saltlen2;
		dc.iUsr = username;
		dc.nUsr = usernamelen;
		dynamic_use_sse = 0;
		for (i = 0; i < m_count; ++i) {
			if (curdat.store_keys_in_input) {
#if MD5_X2
				if (i & 1)
					dc.iPw = input_buf_X86[i >> MD5_X2].x2.b2;
				else
#endif
					dc.iPw = input_buf_X86[i >> MD5_X2].x1.b;
			} else
				dc.iPw = saved_key[i];
			dc.nPw = saved_key_len[i];
#if MD5_X2
			if (i & 1) {
				dc.oBin = crypt_key_X86[i >> MD5_X2].x2.B2;
			}
			else
#endif
			dc.oBin = crypt_key_X86[i >> MD5_X2].x1.B;
			run_one_RDP_test(&dc);
		}
		return m_count;
	}
	{
#ifdef _OPENMP
	if ((curdat.pFmtMain->params.flags & FMT_OMP) == FMT_OMP) {
		int j;
		unsigned int inc = (m_count+m_ompt-1) / m_ompt;
		//printf("maxkeys=%d m_count=%d inc1=%d granularity=%d inc2=%d\n", curdat.pFmtMain->params.max_keys_per_crypt, m_count, inc, curdat.omp_granularity, ((inc + curdat.omp_granularity-1)/curdat.omp_granularity)*curdat.omp_granularity);
		inc = ((inc + curdat.omp_granularity-1)/curdat.omp_granularity)*curdat.omp_granularity;
#pragma omp parallel for shared(curdat, inc, m_count)
		for (j = 0; j < m_count; j += inc) {
			unsigned int i;
			unsigned int top=j+inc;
			/* The last block may 'appear' to have more keys than we have in the
			   entire buffer space.  This is due to the granularity.  If so,
			   reduce that last one to stop at end of our buffers.  NOT doing
			   this is causes a huge buffer overflow.  */
			if (top > curdat.pFmtMain->params.max_keys_per_crypt)
				top = curdat.pFmtMain->params.max_keys_per_crypt;

			// we now run a full script in this thread, using only a subset of
			// the data, from [j,top)  The next thread will run from [top,top+inc)
			// each thread will take the next inc values, until we get to m_count
			for (i = 0; curdat.dynamic_FUNCTIONS[i]; ++i)
				(*(curdat.dynamic_FUNCTIONS[i]))(j,top,omp_get_thread_num());
		}
	} else {
		unsigned int i;
		// same code (almost), but without the threads.
		for (i = 0; curdat.dynamic_FUNCTIONS[i]; ++i)
			(*(curdat.dynamic_FUNCTIONS[i]))(0,m_count,0);
	}
#else
	unsigned int i;
	for (i = 0; curdat.dynamic_FUNCTIONS[i]; ++i) {
		(*(curdat.dynamic_FUNCTIONS[i]))();
#if 0
		// Dump state (for debugging help)
		if (i==0) printf("\npassword=%.*s\n", saved_key_len[0], saved_key[0]);
		printf("\nState after function: %s\n", dynamic_Find_Function_Name(curdat.dynamic_FUNCTIONS[i]));
		// dump input 1
#ifdef SIMD_COEF_32
		dump_stuff_mmx_msg("input_buf[0]", input_buf[0].c, 64, 0);
		dump_stuff_mmx_msg("input_buf[1]", input_buf[0].c, 64, 1);
		dump_stuff_mmx_msg("input_buf[2]", input_buf[0].c, 64, 2);
		dump_stuff_mmx_msg("input_buf[3]", input_buf[0].c, 64, 3);
#endif
		printf("input_buf86[0] : %*.*s\n", total_len_X86[0],total_len_X86[0],input_buf_X86[0].x1.b);
		printf("input_buf86[1] : %*.*s\n", total_len_X86[1],total_len_X86[1],input_buf_X86[1].x1.b);
		printf("input_buf86[2] : %*.*s\n", total_len_X86[2],total_len_X86[2],input_buf_X86[2].x1.b);
		printf("input_buf86[3] : %*.*s\n", total_len_X86[3],total_len_X86[3],input_buf_X86[3].x1.b);
		// dump crypt 1
#ifdef SIMD_COEF_32
		dump_stuff_mmx_msg("crypt_key[0]", crypt_key[0].c, 16, 0);
		dump_stuff_mmx_msg("crypt_key[1]", crypt_key[0].c, 16, 1);
		dump_stuff_mmx_msg("crypt_key[2]", crypt_key[0].c, 16, 2);
		dump_stuff_mmx_msg("crypt_key[3]", crypt_key[0].c, 16, 3);
#endif
		dump_stuff_be_msg("crypt_key_X86[0]", crypt_key_X86[0].x1.b, 16);
		dump_stuff_be_msg("crypt_key_X86[1]", crypt_key_X86[1].x1.b, 16);
		dump_stuff_be_msg("crypt_key_X86[2]", crypt_key_X86[2].x1.b, 16);
		dump_stuff_be_msg("crypt_key_X86[3]", crypt_key_X86[3].x1.b, 16);
		// dump input 2
#ifdef SIMD_COEF_32
		dump_stuff_mmx_msg("input_buf2[0]", input_buf2[0].c, 64, 0);
		dump_stuff_mmx_msg("input_buf2[1]", input_buf2[0].c, 64, 1);
		dump_stuff_mmx_msg("input_buf2[2]", input_buf2[0].c, 64, 2);
		dump_stuff_mmx_msg("input_buf2[3]", input_buf2[0].c, 64, 3);
#endif
		printf("input2_buf86[0] : %*.*s\n", total_len2_X86[0],total_len2_X86[0],input_buf2_X86[0].x1.b);
		printf("input2_buf86[1] : %*.*s\n", total_len2_X86[1],total_len2_X86[1],input_buf2_X86[1].x1.b);
		printf("input2_buf86[2] : %*.*s\n", total_len2_X86[2],total_len2_X86[2],input_buf2_X86[2].x1.b);
		printf("input2_buf86[3] : %*.*s\n", total_len2_X86[3],total_len2_X86[3],input_buf2_X86[3].x1.b);
		// dump crypt 2
#ifdef SIMD_COEF_32
		dump_stuff_mmx_msg("crypt_key2[0]", crypt_key2[0].c, 16, 0);
		dump_stuff_mmx_msg("crypt_key2[1]", crypt_key2[0].c, 16, 1);
		dump_stuff_mmx_msg("crypt_key2[2]", crypt_key2[0].c, 16, 2);
		dump_stuff_mmx_msg("crypt_key2[3]", crypt_key2[0].c, 16, 3);
#endif
		dump_stuff_be_msg("crypt_key2_X86[0]", crypt_key2_X86[0].x1.b, 16);
		dump_stuff_be_msg("crypt_key2_X86[1]", crypt_key2_X86[1].x1.b, 16);
		dump_stuff_be_msg("crypt_key2_X86[2]", crypt_key2_X86[2].x1.b, 16);
		dump_stuff_be_msg("crypt_key2_X86[3]", crypt_key2_X86[3].x1.b, 16);
#endif
	}
#endif
	}

	return m_count;
}

/*********************************************************************************
 * 'normal' hashing functions
 *********************************************************************************/
extern char *MD5_DumpHexStr(void *p);

#if !ARCH_LITTLE_ENDIAN
// the lower 8 bits is zero on the binary (but filled in on the hash).  We need to dump the low 8
static int binary_hash_0_64x4(void * binary) { return (((uint32_t *)binary)[0]>>8) & PH_MASK_0; }
static int binary_hash_1_64x4(void * binary) { return (((uint32_t *)binary)[0]>>8) & PH_MASK_1; }
static int binary_hash_2_64x4(void * binary) { return (((uint32_t *)binary)[0]>>8) & PH_MASK_2; }
static int binary_hash_3_64x4(void * binary) { return (((uint32_t *)binary)[0]>>8) & PH_MASK_3; }
static int binary_hash_4_64x4(void * binary) { return (((uint32_t *)binary)[0]>>8) & PH_MASK_4; }
static int binary_hash_5_64x4(void * binary) { return (((uint32_t *)binary)[0]>>8) & PH_MASK_5; }
static int get_hash_0_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & PH_MASK_0;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & PH_MASK_0;}
static int get_hash_1_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & PH_MASK_1;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & PH_MASK_1;}
static int get_hash_2_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & PH_MASK_2;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & PH_MASK_2;}
static int get_hash_3_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & PH_MASK_3;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & PH_MASK_3;}
static int get_hash_4_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & PH_MASK_4;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & PH_MASK_4;}
static int get_hash_5_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & PH_MASK_5;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & PH_MASK_5;}


#endif

static int get_hash_0(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_0;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_0;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_0;
}

static int get_hash_1(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_1;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_1;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_1;
}

static int get_hash_2(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_2;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_2;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_2;
}

static int get_hash_3(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_3;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_3;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_3;
}

static int get_hash_4(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_4;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_4;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_4;
}

static int get_hash_5(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_5;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_5;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_5;
}

static int get_hash_6(int index)
{
#ifdef SIMD_COEF_32
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned int)index)/SIMD_COEF_32);
		return ((uint32_t *)&(crypt_key[idx].c))[index&(SIMD_COEF_32-1)] & PH_MASK_6;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & PH_MASK_6;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & PH_MASK_6;
}


/************************************************************************
 * We now fully handle all hashing of salts, here in the format. We
 * return a pointer to an allocated salt record. Thus, we search all
 * of the salt records, looking for the same salt.  If we find it, we
 * want to return THAT pointer, and not allocate a new pointer.
 * This works great, but forces us to do salt comparision here.
 ***********************************************************************/
#define DYNA_SALT_HASH_BITS SALT_HASH_LOG
#define DYNA_SALT_HASH_SIZE (1<<DYNA_SALT_HASH_BITS)
#define DYNA_SALT_HASH_MOD  (DYNA_SALT_HASH_SIZE-1)

typedef struct dyna_salt_list_entry {
	struct dyna_salt_list_entry *next;
	unsigned len;
	unsigned char *salt;
} dyna_salt_list_entry;
typedef struct {
	dyna_salt_list_entry *head, *tail;
	int count;
} dyna_salt_list_main;

typedef struct {
	dyna_salt_list_main List;
} SaltHashTab_t;
static SaltHashTab_t        *SaltHashTab=NULL;
static dyna_salt_list_entry *pSaltHashData=NULL, *pSaltHashDataNext=NULL;
static int                   dyna_salt_list_count=0;
static unsigned char        *pSaltDataBuf=NULL, *pNextSaltDataBuf=NULL;
static int                   nSaltDataBuf=0;

static unsigned char *AddSaltHash(unsigned char *salt, unsigned int len, unsigned int idx)
{
	unsigned char *pRet;
	if (dyna_salt_list_count == 0) {
		pSaltHashDataNext = pSaltHashData = mem_calloc_tiny(sizeof(dyna_salt_list_entry) * 25000, MEM_ALIGN_WORD);
		dyna_salt_list_count = 25000;
	}
	if (nSaltDataBuf < len) {
		pSaltDataBuf = pNextSaltDataBuf = mem_alloc_tiny(0x60000, MEM_ALIGN_NONE);
		nSaltDataBuf = 0x60000;
	}
	pRet = pNextSaltDataBuf;
	pSaltHashDataNext->salt = pNextSaltDataBuf;
	memcpy(pSaltHashDataNext->salt, salt, len);
	pSaltHashDataNext->len = len;
	pNextSaltDataBuf += len;
	nSaltDataBuf -= len;

	if (SaltHashTab[idx].List.count == 0)
		SaltHashTab[idx].List.tail = SaltHashTab[idx].List.head = pSaltHashDataNext;
	else {
		SaltHashTab[idx].List.tail->next = pSaltHashDataNext;
		SaltHashTab[idx].List.tail = pSaltHashDataNext;
	}
	++SaltHashTab[idx].List.count;
	++pSaltHashDataNext;
	--dyna_salt_list_count;
	return pRet;
}

static unsigned char *FindSaltHash(unsigned char *salt, unsigned int len, CRC32_t crc)
{
	unsigned int idx = crc & DYNA_SALT_HASH_MOD;
	dyna_salt_list_entry *p;
	if (!SaltHashTab)
		SaltHashTab = mem_calloc_tiny(sizeof(SaltHashTab_t) * DYNA_SALT_HASH_SIZE, MEM_ALIGN_WORD);

	if (!SaltHashTab[idx].List.count) {
		return AddSaltHash(salt, len, idx);
	}
	// Ok, we have some salts in this hash list.  Now walk the list, searching for an EQUAL salt.
	p = SaltHashTab[idx].List.head;
	while (p) {
		if (len == p->len && !memcmp((char*)salt, (char*)p->salt, len)) {
			return p->salt;  // found it!  return this one, so we do not allocate another.
		}
		p = p->next;
	}
	return AddSaltHash(salt, len, idx);
}

static unsigned char *HashSalt(unsigned char *salt, unsigned int len)
{
	CRC32_t crc = 0xffffffff, i;
	unsigned char *ret_hash;

	// compute the hash.
	for (i = 0; i < len; ++i)
		crc = jtr_crc32(crc,salt[i]);
	crc = ~crc;

	ret_hash = FindSaltHash(salt, len, crc);
	return ret_hash;
}

static int ConvertFromHex(unsigned char *p, int len)
{
	unsigned char *cp;
	unsigned int i, x;
	if (!p || memcmp(p, "HEX$", 4))
		return len;
	// Ok, do a convert, and return 'new' len.
	len -= 4;
	len >>= 1;
	cp = p;
	x = len;
	for (i=4; x; --x, i+= 2) {
		*cp++ = atoi16[ARCH_INDEX(p[i])]*16 + atoi16[ARCH_INDEX(p[i+1])];
    }
	*cp = 0;
	return len;
}

static unsigned int salt_external_to_internal_convert(unsigned char *extern_salt, unsigned char *Buffer)
{
	// Ok, we get this:   extern_salt = salt_data$$2salt2$$Uuser ...  where anything can be missing or in any order
	// the any order has 1 exception of salt_data MUST be first.  So if we get $$2salt2, then we know there is no salt-1 value.
	unsigned char *salt2=0, *userid=0, *Flds[10];
	int i, nsalt2=0, nuserid=0, nFlds[10]={0,0,0,0,0,0,0,0,0,0};
	unsigned int len = strlen((char*)extern_salt), bit;
	unsigned int bit_array=0;
	unsigned int the_real_len = 6;  // 2 bytes base-8 length, and 4 bytes base-8 bitmap.

	// work from back of string to front, looking for the $$X signatures.
	for (i = len-3; i >= 0; --i) {
		if (extern_salt[i] == '$' && extern_salt[i+1] == '$') {
			// a 'likely' extra salt value.
			switch(extern_salt[i+2]) {
				case '2':
					if (curdat.b2Salts) {
						salt2 = &extern_salt[i+3];
						nsalt2 = strlen((char*)salt2);
						nsalt2 = ConvertFromHex(salt2, nsalt2);
						extern_salt[i] = 0;
						bit_array |= 1;
						the_real_len += (nsalt2+1);
					}
					break;
				case 'U':
					if (curdat.nUserName) {
						userid = &extern_salt[i+3];
						nuserid = strlen((char*)userid);
						nuserid = ConvertFromHex(userid, nuserid);
						extern_salt[i] = 0;
						bit_array |= 2;
						the_real_len += (nuserid+1);
					}
					break;
				case 'F': {
					if (extern_salt[i+3] >= '0' && extern_salt[i+3] <= '9') {
						if (curdat.FldMask && (curdat.FldMask & (MGF_FLDx_BIT<<(extern_salt[i+3]-'0'))) == (MGF_FLDx_BIT<<(extern_salt[i+3]-'0'))) {
							Flds[extern_salt[i+3]-'0'] = &extern_salt[i+4];
							nFlds[extern_salt[i+3]-'0'] = strlen((char*)(Flds[extern_salt[i+3]-'0']));
							nFlds[extern_salt[i+3]-'0'] = ConvertFromHex(Flds[extern_salt[i+3]-'0'], nFlds[extern_salt[i+3]-'0']);
							extern_salt[i] = 0;
							bit_array |= (1<<(2+extern_salt[i+3]-'0'));
							the_real_len += (nFlds[extern_salt[i+3]-'0']+1);
						}
						break;
					}
				}
			}
		}
	}
	// We have now ripped the data apart.  Now put it into Buffer, in proper ORDER

	// Length of salt (salt1)  These 2 are stored as base-8 numbers.
	len = strlen((char*)extern_salt);
	len = ConvertFromHex(extern_salt, len);
	the_real_len += len;

	*Buffer++ = (len>>3) + '0';
	*Buffer++ = (len&7) + '0';

	// bit array
	*Buffer++ = (bit_array>>9) + '0';
	*Buffer++ = ((bit_array>>6)&7) + '0';
	*Buffer++ = ((bit_array>>3)&7) + '0';
	*Buffer++ = (bit_array&7) + '0';

	memcpy((char*)Buffer, (char*)extern_salt, len);
	Buffer += len;

	if (!bit_array)
		return the_real_len;

	if (nsalt2) {
		*Buffer++ = nsalt2;
		memcpy((char*)Buffer, (char*)salt2, nsalt2);
		Buffer += nsalt2;
		bit_array &= ~1;
		if (!bit_array)
			return the_real_len;
	}
	if (nuserid) {
		*Buffer++ = nuserid;
		memcpy((char*)Buffer, (char*)userid, nuserid);
		if (curdat.nUserName==2) {
			Buffer[nuserid] = 0;
			strupr((char*)Buffer);
		} else if (curdat.nUserName==2) {
			Buffer[nuserid] = 0;
			strlwr((char*)Buffer);
		}
		Buffer += nuserid;
		bit_array &= ~2;
		if (!bit_array)
			return the_real_len;
	}
	bit = 4;
	for (i = 0; i < 10; ++i, bit<<=1) {
		if (nFlds[i]) {
			*Buffer++ = nFlds[i];
			memcpy((char*)Buffer, (char*)(Flds[i]), nFlds[i]);
			Buffer += nFlds[i];
			bit_array &= ~bit;
			if (!bit_array)
				return the_real_len;
		}

	}
	return the_real_len;
}

/*********************************************************************************
 * This salt function has been TOTALLY re-written.  Now, we do these things:
 *  1. convert from external format ($salt$$Uuser$$2HEX$salt2_in_hex, etc, into
 *     our internal format.  Our internal format is 2 base-8 numbers (2 digit and 4
 *     digit), followed by the 'raw' salt bytes, followed by pascal strings of any
 *     other special salt values (salt2, user, flields 0 to 9).  The first 2 digit
 *     base 8 number is the length of the binary bytes of the 'real' salt.  The
 *     2nd base-8 4 digit number, is a bit mask of what 'extra' salt types are
 *     contained.
 *  2. We allocate and 'own' the salt buffers here, so that:
 *  3. We detect duplicate salts. NOTE, we have normalized the salts, so 2 salts that
 *     appear different (external format), appear exactly the same on internal format.
 *     Thus, we dupe remove them here.
 *  4. We allocation storage for the salts. The ONLY thing we return to john, is
 *     a 4 (or 8 byte in 64 bit builds) pointer to the salt.  Thus, when we find
 *     a dupe, we do not have to allocate ANY memory, and simply return the pointer
 *     to the original salt (which is the same as the one we are working on now).
 *
 *  this is much more complex, however, it allows us to use much less memory, to
 *  have the set_salt function operate VERY quickly (all processing is done here).
 *  It also allows john load time to happen FASTER (yes faster), that it was happening
 *  due to smaller memory footprint, and john's external salt collision to have
 *  less work to do.  The memory footprint was also reduced, because now we store
 *  JUST the require memory, and a pointer.  Before, often we stored a LOT of memory
 *  for many format types.  For a few types, we do use more memory with this method
 *  than before, but for more the memory usage is way down.
 *********************************************************************************/
static void *get_salt(char *ciphertext)
{
	char Salt[SALT_SIZE + 1], saltIntBuf[SALT_SIZE + 1], unhex_salt[1024];
	int off, possible_neg_one=0;
	unsigned char *saltp;
	unsigned int the_real_len;
	static union x {
		unsigned char salt_p[sizeof(unsigned char*)];
		ARCH_WORD p[1];
	} union_x;

	// We may have kept unprintables (except NULLs) so far, now remove them
	if (strstr(ciphertext, "$HEX$"))
		ciphertext = RemoveHEX(unhex_salt, ciphertext, KEEP_NULLS);

	if ( (curdat.pSetup->flags&MGF_SALTED) == 0) {
		memset(union_x.salt_p, 0, sizeof(union_x.salt_p));
		return union_x.salt_p;
	}

	memset(Salt, 0, SALT_SIZE+1);

	// Ok, see if the wrong dynamic type is loaded (such as the 'last' dynamic type).
	if (!strncmp(ciphertext, "$dynamic_", 9)) {
		char *cp1 = &ciphertext[9];
		char *cp2 = &curdat.dynamic_WHICH_TYPE_SIG[9];
		while (*cp2 && *cp2 == *cp1) {
			++cp1; ++cp2;
		}
		if (*cp2) {
			char subformat[17];
			struct fmt_main *pFmtLocal;
			int nFmtNum;
			memcpy(subformat, ciphertext, 16);
			subformat[16] = 0;
			cp2 = &subformat[9];
			while (*cp2 && *cp2 != '$')
				++cp2;
			*cp2 = 0;
			nFmtNum = -1;
			sscanf(subformat, "$dynamic_%d", &nFmtNum);
			if (nFmtNum==-1)
				return union_x.salt_p;
			pFmtLocal = dynamic_Get_fmt_main(nFmtNum);
			memcpy(&curdat, pFmtLocal->private.data, sizeof(private_subformat_data));
		}
	}

	if (curdat.dynamic_FIXED_SALT_SIZE==0 && !curdat.nUserName && !curdat.FldMask)
		return union_x.salt_p;
	if (!strncmp(ciphertext, "$dynamic_", 9))
		off=curdat.dynamic_SALT_OFFSET;
	else
		off=curdat.dynamic_SALT_OFFSET-strlen(curdat.dynamic_WHICH_TYPE_SIG);

	if (ciphertext[off] == '$') {
		if (ciphertext[off+1]=='U' && curdat.nUserName)
			possible_neg_one = -1;
		else if (ciphertext[off+1]=='2' && curdat.b2Salts)
			possible_neg_one = -1;
		else if (ciphertext[off+1]=='F' && ciphertext[off+2]>='0' && ciphertext[off+2]<='9' && curdat.FldMask) {
			if ((curdat.FldMask & (MGF_FLDx_BIT<<(ciphertext[off+2]-'0'))) == (MGF_FLDx_BIT<<(ciphertext[off+2]-'0')))
			possible_neg_one = -1;
		}
	}
	strnzcpy(Salt, &ciphertext[off + possible_neg_one], SALT_SIZE);

	if (curdat.dynamic_salt_as_hex)
	{
		unsigned char Buf[128];
		unsigned int slen=strlen(Salt);
		switch (curdat.dynamic_salt_as_hex_format_type) {
			//  TODO:  Come up with some way to put these into a CASE(HASH) #define

#define SPH_CASE(H,F,S)  case MGF__##H: {sph_##F##_context c;sph_##F##_init(&c);sph_##F(&c,(const unsigned char*)Salt,slen);sph_##F##_close(&c,Buf); \
				memset(Salt,0,SALT_SIZE+1);base64_convert(Buf,e_b64_raw,S,Salt,e_b64_hex,SALT_SIZE, 0, 0);break; }
#define OSSL_CASE(H,C,S)  case MGF__##H: {C##_CTX c;H##_Init(&c);H##_Update(&c,Salt,slen);H##_Final(Buf,&c); \
				memset(Salt,0,SALT_SIZE+1);base64_convert(Buf,e_b64_raw,S,Salt,e_b64_hex,SALT_SIZE, 0, 0);break; }
#define KECCAK_CASE(H,S)  case MGF__##H: {KECCAK_CTX c;H##_Init(&c);KECCAK_Update(&c,(BitSequence*)Salt,slen);KECCAK_Final(Buf,&c); \
				memset(Salt,0,SALT_SIZE+1);base64_convert(Buf,e_b64_raw,S,Salt,e_b64_hex,SALT_SIZE, 0, 0);break; }

			case MGF__MD5:
			{
				// Do not 'worry' about SSE/MMX,  Only do 'generic' md5.  This is ONLY done
				// at the start of the run.  We will NEVER see this run, once john starts.
				MD5_CTX ctx;
				int i;
				char *cpo;
				MD5_Init(&ctx);
				if (curdat.dynamic_salt_as_hex & 0x100)
				{
					char *s2 = mem_alloc(slen*2+1);
					for (i = 0; i < slen; ++i)
					{
						s2[i<<1] = Salt[i];
						s2[(i<<1)+1] = 0;
					}
					MD5_Update(&ctx, s2, slen*2);
					MEM_FREE(s2);
				}
				else
					MD5_Update(&ctx, Salt, slen);
				MD5_Final(Buf, &ctx);
				if ( (curdat.dynamic_salt_as_hex&3) == 2) {
					strcat(Salt, "$$2");
					cpo = &Salt[slen+3];
				}
				else {
					cpo = Salt;
					memset(Salt, 0, SALT_SIZE+1);
				}
				base64_convert(Buf, e_b64_raw, 16, cpo, e_b64_hex, SALT_SIZE, 0, 0);
				break;
			}
			OSSL_CASE(MD4,MD4,16)
			OSSL_CASE(SHA1,SHA,20)
			OSSL_CASE(SHA224,SHA256,28)
			OSSL_CASE(SHA256,SHA256,32)
			OSSL_CASE(SHA384,SHA512,48)
			OSSL_CASE(SHA512,SHA512,64)
			OSSL_CASE(WHIRLPOOL,WHIRLPOOL,64)
			case MGF__GOST:
			{
				gost_ctx ctx;
				john_gost_init(&ctx);
				john_gost_update(&ctx, (const unsigned char*)Salt, slen);
				john_gost_final(&ctx, (unsigned char*)Buf);
				memset(Salt, 0, SALT_SIZE+1);
				base64_convert(Buf, e_b64_raw, 32, Salt, e_b64_hex, SALT_SIZE, 0, 0);
				break;
			}
			SPH_CASE(Tiger,tiger,24)
			SPH_CASE(RIPEMD128,ripemd128,16)
			SPH_CASE(RIPEMD160,ripemd160,20)
			SPH_CASE(RIPEMD256,ripemd256,32)
			SPH_CASE(RIPEMD320,ripemd320,40)
			SPH_CASE(HAVAL128_3,haval128_3,16)
			SPH_CASE(HAVAL128_4,haval128_4,16)
			SPH_CASE(HAVAL128_5,haval128_5,16)
			SPH_CASE(HAVAL160_3,haval160_3,20)
			SPH_CASE(HAVAL160_4,haval160_4,20)
			SPH_CASE(HAVAL160_5,haval160_5,20)
			SPH_CASE(HAVAL192_3,haval192_3,24)
			SPH_CASE(HAVAL192_4,haval192_4,24)
			SPH_CASE(HAVAL192_5,haval192_5,24)
			SPH_CASE(HAVAL224_3,haval224_3,28)
			SPH_CASE(HAVAL224_4,haval224_4,28)
			SPH_CASE(HAVAL224_5,haval224_5,28)
			SPH_CASE(HAVAL256_3,haval256_3,32)
			SPH_CASE(HAVAL256_4,haval256_4,32)
			SPH_CASE(HAVAL256_5,haval256_5,32)
			SPH_CASE(MD2,md2,16)
			SPH_CASE(PANAMA,panama,32)
			SPH_CASE(SKEIN224,skein224,28)
			SPH_CASE(SKEIN256,skein256,32)
			SPH_CASE(SKEIN384,skein384,48)
			SPH_CASE(SKEIN512,skein512,64)
			KECCAK_CASE(SHA3_224,28)
			KECCAK_CASE(SHA3_256,32)
			KECCAK_CASE(SHA3_384,48)
			KECCAK_CASE(SHA3_512,64)
			KECCAK_CASE(KECCAK_224,28)
			KECCAK_CASE(KECCAK_256,32)
			KECCAK_CASE(KECCAK_384,48)
			KECCAK_CASE(KECCAK_512,64)
			// LARGE_HASH_EDIT_POINT

			default:
			{
				error_msg("Invalid dynamic flags seen.  Data type not yet defined\n");
			}
		}
	}

	the_real_len = salt_external_to_internal_convert((unsigned char*)Salt, (unsigned char*)saltIntBuf);

	// Now convert this into a stored salt, or find the 'already' stored same salt.
	saltp = HashSalt((unsigned char*)saltIntBuf, the_real_len);
	memcpy(union_x.salt_p, &saltp, sizeof(saltp));
	return union_x.salt_p;
}

/*********************************************************************************
 * Now our salt is returned only as a pointer.  We
 *********************************************************************************/
static int salt_hash(void *salt)
{
	uintptr_t H;

	if (!salt) return 0;
	if ( (curdat.pSetup->flags&MGF_SALTED) == 0)
		return 0;

	// salt is now a pointer, but WORD aligned.  We remove that word alingment, and simply use the next bits
#if ARCH_ALLOWS_UNALIGNED
	H = *((uintptr_t*)salt);
#else
	memcpy(&H, salt, sizeof(H));
#endif

	// Mix up the pointer value (H^(H>>9)) so that if we have a fixed sized allocation
	// that things do get 'stirred' up better.
	return ( (H^(H>>9)) & (SALT_HASH_SIZE-1) );
}

static unsigned dynamic_this_salt_length(const void *v) {
	const unsigned char *s = (unsigned char*)v;
	unsigned l = *s++ - '0';
	unsigned bits;
	l <<= 3;
	l += *s++ - '0';
#if ARCH_ALLOWS_UNALIGNED
	if (*((uint32_t*)s) == 0x30303030)
#else
	if (!memcmp(s, "0000", 4))
#endif
		return l;
	bits = *s++ - '0';
	bits <<= 3;
	bits += *s++ - '0';
	bits <<= 3;
	bits += *s++ - '0';
	bits <<= 3;
	bits += *s++ - '0';
	s += l;
	while(bits) {
		if (bits & 1) {
			l += *s;
			s += *s;
			++s;
		}
		bits >>= 1;
	}
	return l;
}

/*
 * dyna compare is required, to get all the shortest
 * salt strings first, then the next longer, then the
 * next, and finally the longest.  Without this change
 * there are many dyna formats which will miss finding
 * hashes, because old dirty salt information gets left
 * over, blowing the next runs.  There are many formats
 * which try to not clear buffers if they do not need
 * to, BUT this only works if salts are taken shortest
 * to longest.  This sort builds the list of salts that way
 */
static int salt_compare(const void *x, const void *y)
{
	/* this is all that is needed in dyna salt_compare().
	   Dyna is a pointer to a string, NOT the actual string.
	   The first 2 bytes of string are length (base 8 ascii) */
	const char *X = *((const char**)x);
	const char *Y = *((const char**)y);
	int l1, l2, l;
	if (*X<*Y) return -1;
	if (*X>*Y) return 1;
	if (X[1]<Y[1]) return -1;
	if (X[1]>Y[1]) return 1;

	// we had to make the salt order 100% deterministic, so that intersalt-restore
	l = l1 = dynamic_this_salt_length(X);
	l2 = dynamic_this_salt_length(Y);
	if (l2 < l) l = l2;
	l = memcmp(&X[6], &Y[6], l);
	if (l) return l;
	if (l1==l2) return 0;
	if (l1 > l2) return 1;
	return -1;
}

void dynamic_salt_md5(struct db_salt *s) {
	MD5_CTX ctx;
	int len;
	const char *S = *((const char**)s->salt);

	MD5_Init(&ctx);
	len = dynamic_this_salt_length(S);
	MD5_Update(&ctx, S + 6, len);
	MD5_Final((unsigned char*)(s->salt_md5), &ctx);
}

/*********************************************************************************
 * Gets the binary value from a base-16 hash.
 *********************************************************************************/
static void *get_binary(char *_ciphertext)
{
	static char *realcipher;
	unsigned int i;
	char *ciphertext = _ciphertext;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE_SHA, MEM_ALIGN_WORD);

	if (!strncmp(_ciphertext, "$dynamic_", 9)) {
		ciphertext += 9;
		while (*ciphertext++ != '$')
			;
	}

	for (i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] =
			atoi16[ARCH_INDEX(ciphertext[i*2])]*16 +
			atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

// NOTE NOTE NOTE, we have currently ONLY implemented a non-salted function!!!
static char *source(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 16; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_20_hex(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 20; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_28_hex(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 28; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_32_hex(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 32; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_40_hex(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 40; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_48_hex(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 48; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_64_hex(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	unsigned int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 64; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

/*********************************************************************************
 * Gets the binary value from a base-64 hash
 *********************************************************************************/

static void * binary_b64m(char *ciphertext)
{
	unsigned int i;
	static unsigned char *b;
	char *pos;

	if (!b) b = mem_alloc_tiny(64+3, MEM_ALIGN_WORD);
	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
	i = base64_valid_length(pos, e_b64_mime, 0, 0);
	base64_convert(pos, e_b64_mime, i, b, e_b64_raw, 64+3, 0, 0);
	//printf("\nciphertext=%s\n", ciphertext);
	//dump_stuff_msg("binary", b, 16);
	return b;
}

static void * binary_b64(char *ciphertext)
{
	unsigned int i;
	static unsigned char *b;
	char *pos;

	if (!b) b = mem_alloc_tiny(64+3, MEM_ALIGN_WORD);
	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
	i = base64_valid_length(pos, e_b64_crypt, 0, 0);
	base64_convert(pos, e_b64_cryptBS, i, b, e_b64_raw, 64+3, 0, 0);
	//printf("\nciphertext=%s\n", ciphertext);
	//dump_stuff_msg("binary", b, 16);
	return b;
}

static void * binary_b64b(char *ciphertext)
{
	unsigned int i;
	static unsigned char *b;
	char *pos;

	if (!b) b = mem_alloc_tiny(64+3, MEM_ALIGN_WORD);
	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
	i = base64_valid_length(pos, e_b64_crypt, 0, 0);
	base64_convert(pos, e_b64_crypt, i, b, e_b64_raw, 64+3, 0, 0);
	//printf("\nciphertext=%s\n", ciphertext);
	//dump_stuff_msg("binary", b, 16);
	return b;
}

#define TO_BINARY(b1, b2, b3) \
	value = \
		(uint32_t)atoi64[ARCH_INDEX(pos[0])] | \
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((uint32_t)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	b[b1] = value >> 16; \
	b[b2] = value >> 8; \
	b[b3] = value;
static void * binary_b64a(char *ciphertext)
{
	static unsigned char *b;
	char *pos;
	uint32_t value;

	if (!b) b = mem_alloc_tiny(16, MEM_ALIGN_WORD);
	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
	TO_BINARY(0, 6, 12);
	TO_BINARY(1, 7, 13);
	TO_BINARY(2, 8, 14);
	TO_BINARY(3, 9, 15);
	TO_BINARY(4, 10, 5);
	b[11] =
		(uint32_t)atoi64[ARCH_INDEX(pos[0])] |
		((uint32_t)atoi64[ARCH_INDEX(pos[1])] << 6);

	MD5_swap((uint32_t*)b,(uint32_t*)b, 4);
	return b;
}

/*********************************************************************************
 * Gets the binary value from a base-64 hash (such as cisco PIX)
 *********************************************************************************/
static void * binary_b64_4x6(char *ciphertext)
{
	static uint32_t *b;
	unsigned int i;
	char *pos;

	if (!b) b = mem_alloc_tiny(16, MEM_ALIGN_WORD);
	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
	for (i = 0; i < 4; i++) {
		b[i] =
			atoi64[ARCH_INDEX(pos[i*4 + 0])] +
			(atoi64[ARCH_INDEX(pos[i*4 + 1])] << 6) +
			(atoi64[ARCH_INDEX(pos[i*4 + 2])] << 12) +
			(atoi64[ARCH_INDEX(pos[i*4 + 3])] << 18);
	}
	MD5_swap(b,b, 4);
	return (void *)b;
}

/*********************************************************************************
 * Here is the main mdg_generic fmt_main. NOTE in its default settings, it is
 * ready to handle base-16 hashes.
 *********************************************************************************/
static struct fmt_main fmt_Dynamic =
{
	{
		FORMAT_LABEL,
		FORMAT_NAME,
#ifdef SIMD_COEF_32
		ALGORITHM_NAME,
#else
		ALGORITHM_NAME_X86,
#endif
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
		0,
#ifdef SIMD_COEF_32
		PLAINTEXT_LENGTH,
#else
		PLAINTEXT_LENGTH_X86,
#endif
		BINARY_SIZE,
		BINARY_ALIGN,
		SALT_SIZE,
		SALT_ALIGN,
#ifdef SIMD_COEF_32
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#else
		MIN_KEYS_PER_CRYPT_X86,
		MAX_KEYS_PER_CRYPT_X86,
#endif
#ifdef _OPENMP
		FMT_OMP | FMT_OMP_BAD |
#endif
		FMT_CASE | FMT_8_BIT,
		{ NULL },
		{ NULL },
		dynamic_tests
	}, {
		init,
		done,
		fmt_default_reset,
		prepare,
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
		salt_compare,
		set_salt,
		set_key,
		get_key,
		clear_keys,
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

/**************************************************************
 **************************************************************
 **************************************************************
 **************************************************************
 *  These are the md5 'primitive' functions that are used by
 *  the build-in expressions, and by the expression generator
 *  They load passwords, salts, user ids, do crypts, convert
 *  crypts into base-16, etc.  They are pretty encompassing,
 *  and have been found to be able to do most anything with
 *  a standard 'base-16' md5 hash, salted or unsalted that
 *  fits a 'simple' php style expression.
 **************************************************************
 **************************************************************
 **************************************************************
 *************************************************************/

void Dynamic_Load_itoa16_w2()
{
	char buf[3];
	unsigned int i;
	for (i = 0; i < 256; ++i)
	{
		sprintf(buf, "%X%X", i>>4, i&0xF);
		memcpy(&(itoa16_w2_u[i]), buf, 2);
		sprintf(buf, "%x%x", i>>4, i&0xF);
		memcpy(&(itoa16_w2_l[i]), buf, 2);
	}
}

#ifdef SIMD_COEF_32


/**************************************************************
 **************************************************************
 *  Here are some 'helpers' to our helpers, when it comes to
 *  loading data into the mmx/sse buffers.  We have several
 *  of these common helper functions, and use them in 'most'
 *  of the helper primitives, instead of having the same
 *  code being inlined in each of them.
 **************************************************************
 *************************************************************/

static void __SSE_append_output_base16_to_input(uint32_t *IPBdw, unsigned char *CRY, unsigned int idx_mod)
{
	// #3
    // 5955K  (core2, $dynamic_2$)
    // 1565K  (core2, $dynamic_1006$)
	// 3381K  (ath64, $dynamic_2$)
	// 824.7k (ath64, $dynamic_1006$)
#undef inc
#define inc ((SIMD_COEF_32-1) * 2)
	unsigned short *IPBw = (unsigned short*)IPBdw;
	IPBw += (idx_mod<<1);
	CRY += (idx_mod<<2);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;

	*IPBw = 0x80;
#undef inc
}

static void __SSE_overwrite_output_base16_to_input(uint32_t *IPBdw, unsigned char *CRY, unsigned int idx_mod)
{
	// #3
    // 5955K  (core2, $dynamic_2$)
    // 1565K  (core2, $dynamic_1006$)
	// 3381K  (ath64, $dynamic_2$)
	// 824.7k (ath64, $dynamic_1006$)
#undef inc
#define inc ((SIMD_COEF_32-1) * 2)
	unsigned short *IPBw = (unsigned short *)IPBdw;
	IPBw += (idx_mod<<1);
	CRY += (idx_mod<<2);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
#undef inc
}

static void __SSE_append_output_base16_to_input_semi_aligned_2(unsigned int ip, uint32_t *IPBdw, unsigned char *CRY, unsigned int idx_mod)
{
	// #1
    // 9586k/4740k  (core2, $dynamic_9$)
    // 5113k/4382k  (core2,$dynamic_10$)
	//  (ath64, $dynamic_9$)
	//  (ath64, $dynamic_10$)
 #define inc SIMD_COEF_32
 #define incCRY ((SIMD_COEF_32 - 1) * 4)
	// Ok, here we are 1/2 off. We are starting in the 'middle' of a DWORD (and end
	// in the middle of the last one).

	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	IPBdw += (ip>>2)*SIMD_COEF_32;

	CRY += (idx_mod<<2);

	// first byte handled here.
	*IPBdw &= 0xFFFF;
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	CRY += incCRY;
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	CRY += incCRY;
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	CRY += incCRY;
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((uint32_t)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);

	// Add the 0x80 at the proper location (offset 0x21)
	*IPBdw |= 0x800000;

#undef inc
#undef incCRY
}

static void __SSE_append_output_base16_to_input_semi_aligned_0(unsigned int ip, uint32_t *IPBdw, unsigned char *CRY, unsigned int idx_mod)
{
// NOTE if looking at this in the future, that was added by Aleksey for #5032
	if (ip + 32 > 55)
		return;
// end NOTE.
	// #2
    // 6083k  (core2, $dynamic_2$)
    // 1590K  (core2, $dynamic_1006$)
	// 3537K  (ath64, $dynamic_2$)
	// 890.3K (ath64, $dynamic_1006$)
#undef inc
#define inc SIMD_COEF_32
#define incCRY (4*SIMD_COEF_32-2)

	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	IPBdw += (ip>>2)*SIMD_COEF_32;
	CRY += (idx_mod<<2);

	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
//	CRY += (inc*3)+2;
	CRY += incCRY;

	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
//	CRY += (inc*3)+2;
	CRY += incCRY;

	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
//	CRY += (inc*3)+2;
	CRY += incCRY;

	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((uint32_t)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);

	// Add the 0x80 at the proper location (offset 0x21)
	IPBdw += inc;
	*IPBdw = 0x80;
#undef inc
#undef incCRY
}

static void __SSE_append_string_to_input_unicode(unsigned char *IPB, unsigned int idx_mod, unsigned char *cp, unsigned int len, unsigned int bf_ptr, unsigned int bUpdate0x80)
{
	unsigned char *cpO;
#if ARCH_LITTLE_ENDIAN
	// if big-endian, we gain nothing from this function (since we would have to byte swap)
    if (len>1&&!(bf_ptr&1))
    {
        unsigned int w32_cnt;
		if (bf_ptr&2) {
			cpO = &IPB[GETPOS(bf_ptr, idx_mod)];
			bf_ptr += 2;
			*cpO = *cp++;
			cpO[1] = 0;
			--len;
		}
		w32_cnt = len>>1;
        if (w32_cnt)
        {
            uint32_t *wpO;
            wpO = (uint32_t*)&IPB[GETPOS(bf_ptr, idx_mod)];
            len -= (w32_cnt<<1);
            bf_ptr += (w32_cnt<<2);
            do
            {
				uint32_t x = 0;
                x = cp[1];
				x <<= 16;
				x += cp[0];
				*wpO = x;
                cp += 2;
                wpO += SIMD_COEF_32;
            }
            while (--w32_cnt);
        }
    }
#endif
	cpO = &IPB[GETPOS(bf_ptr, idx_mod)];
	while (len--)
	{
		*cpO++ = *cp++;
		if ( ((++bf_ptr)&3) == 0)
			cpO += ((SIMD_COEF_32-1)*4);
		*cpO++ = 0;
		if ( ((++bf_ptr)&3) == 0)
			cpO += ((SIMD_COEF_32-1)*4);
	}
	if (bUpdate0x80)
		*cpO = 0x80;

}

static void __SSE_append_string_to_input(unsigned char *IPB, unsigned int idx_mod, unsigned char *cp, unsigned int len, unsigned int bf_ptr, unsigned int bUpdate0x80)
{
	unsigned char *cpO;
// NOTE if looking at this in the future, that was added by Aleksey for #5032
	if (len + bf_ptr > 55)
		return;
// end NOTE.
	// if our insertion point is on an 'even' DWORD, then we use DWORD * copying, as long as we can
	// This provides quite a nice speedup.
#if ARCH_LITTLE_ENDIAN && ARCH_ALLOWS_UNALIGNED
	// if big-endian, we gain nothing from this function (since we would have to byte swap)
	if (len>3&&(bf_ptr&3)) {
		cpO = &IPB[GETPOS(bf_ptr, idx_mod)];
		while (len--)
		{
			*cpO++ = *cp++;
			if ( ((++bf_ptr)&3) == 0) {
				if (!len) {
					if (bUpdate0x80)
						*cpO = 0x80;
					return;
				}
				break;
			}
		}
	}
    if (len>3&&!(bf_ptr&3))
    {
        unsigned int w32_cnt = len>>2;
        if (w32_cnt)
        {
            uint32_t *wpO;
            wpO = (uint32_t*)&IPB[GETPOS(bf_ptr, idx_mod)];
            len -= (w32_cnt<<2);
            bf_ptr += (w32_cnt<<2);
            do
            {
                *wpO = *((uint32_t*)cp);
                cp += 4;
                wpO += SIMD_COEF_32;
            }
            while (--w32_cnt);
        }
		if (!len) {
			if (bUpdate0x80)
				IPB[GETPOS(bf_ptr, idx_mod)] = 0x80;
			return;
		}
    }
#endif
	cpO = &IPB[GETPOS(bf_ptr, idx_mod)];
	while (len--)
	{
		*cpO++ = *cp++;
		if ( ((++bf_ptr)&3) == 0)
			cpO += ((SIMD_COEF_32-1)*4);
	}
	if (bUpdate0x80)
		*cpO = 0x80;
}


#endif  // #ifdef SIMD_COEF_32 from way above.


inline static void __append_string(DYNA_OMP_PARAMSm unsigned char *Str, unsigned int len)
{
	unsigned int j;
	unsigned int til;
	int utf16 = md5_unicode_convert_get(tid);
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		if (!utf16) {
			for (; j < til; ++j) {
				unsigned int idx = j/SIMD_COEF_32;
				unsigned int idx_mod = j&(SIMD_COEF_32-1);
				unsigned int bf_ptr = total_len[idx][idx_mod];
				total_len[idx][idx_mod] += len;
				__SSE_append_string_to_input(input_buf[idx].c,idx_mod,Str,len,bf_ptr,1);
			}
		} else {
			if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;

				if (utf16 == 1)
					outlen = enc_to_utf16(utf16Str, 27, Str, len) * sizeof(UTF16);
				else
					outlen = enc_to_utf16_be(utf16Str, 27, Str, len) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (; j < til; ++j) {
					unsigned int idx = j/SIMD_COEF_32;
					unsigned int idx_mod = j&(SIMD_COEF_32-1);
					unsigned int bf_ptr = total_len[idx][idx_mod];
					total_len[idx][idx_mod] += outlen;
					// note we use the 'non' unicode variant, since we have already computed the unicode, and length properly
					__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				}
			} else {
				for (; j < til; ++j) {
					unsigned int idx = j/SIMD_COEF_32;
					unsigned int idx_mod = j&(SIMD_COEF_32-1);
					unsigned int bf_ptr = total_len[idx][idx_mod];
					total_len[idx][idx_mod] += len << 1;
					__SSE_append_string_to_input_unicode(input_buf[idx].c,idx_mod,Str,len,bf_ptr,1);
				}
			}
		}
		return;
	}
#endif
	if (utf16) {
		if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
			UTF16 utf16Str[ENCODED_EFFECTIVE_MAX_LENGTH + 1];
			int outlen;
			if (utf16 == 1)
				outlen = enc_to_utf16(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, Str, len) * sizeof(UTF16);
			else
				outlen = enc_to_utf16_be(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, Str, len) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp;
				unsigned char *cpi = (unsigned char*)utf16Str;

				if (total_len_X86[j] + outlen <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]);
					else
#endif
					cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);
					for (z = 0; z < outlen; ++z) {
						*cp++ = *cpi++;
					}
					total_len_X86[j] += outlen;
				}
			}
		} else {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp;
				unsigned char *cpi = Str;

				if (total_len_X86[j] + (len<<1) <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]);
					else
#endif
					cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);
					for (z = 0; z < len; ++z) {
						*cp++ = *cpi++;
						*cp++ = 0;
					}
					total_len_X86[j] += (len<<1);
				}
			}
		}
	} else {
		for (; j < til; ++j) {
#if MD5_X2
			if (j&1)
				memcpy(&(input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]]), Str, len);
			else
#endif
			memcpy(&(input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]]), Str, len);
			total_len_X86[j] += len;
		}
	}
}

inline static void __append2_string(DYNA_OMP_PARAMSm unsigned char *Str, unsigned int len)
{
	unsigned int j;
	unsigned int til;
	int utf16 = md5_unicode_convert_get(tid);
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		if (!utf16) {
			for (; j < til; ++j) {
				unsigned int idx = j/SIMD_COEF_32;
				unsigned int idx_mod = j&(SIMD_COEF_32-1);
				unsigned int bf_ptr = total_len2[idx][idx_mod];
				total_len2[idx][idx_mod] += len;
				__SSE_append_string_to_input(input_buf2[idx].c,idx_mod,Str,len,bf_ptr,1);
			}
		} else {
			if (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;

				if (utf16 == 1)
					outlen = enc_to_utf16(utf16Str, 27, Str, len) * sizeof(UTF16);
				else
					outlen = enc_to_utf16_be(utf16Str, 27, Str, len) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (; j < til; ++j) {
					unsigned int idx = j/SIMD_COEF_32;
					unsigned int idx_mod = j&(SIMD_COEF_32-1);
					unsigned int bf_ptr = total_len2[idx][idx_mod];
					total_len2[idx][idx_mod] += outlen;
					// note we use the 'non' unicode variant of __SSE_append_string_to_input(), since it's already unicode, and length properly
					__SSE_append_string_to_input(input_buf2[idx].c,idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				}
			} else {
				for (; j < til; ++j) {
					unsigned int idx = j/SIMD_COEF_32;
					unsigned int idx_mod = j&(SIMD_COEF_32-1);
					unsigned int bf_ptr = total_len2[idx][idx_mod];
					total_len2[idx][idx_mod] += len << 1;
					__SSE_append_string_to_input_unicode(input_buf2[idx].c,idx_mod,Str,len,bf_ptr,1);
				}
			}
		}
		return;
	}
#endif
	if (utf16) {
		if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
			UTF16 utf16Str[ENCODED_EFFECTIVE_MAX_LENGTH + 1];
			int outlen;
			if (utf16 == 1)
				outlen = enc_to_utf16(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, Str, len) * sizeof(UTF16);
			else
				outlen = enc_to_utf16_be(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, Str, len) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp;
				unsigned char *cpi = (unsigned char*)utf16Str;

				if (total_len2_X86[j] + outlen <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf2_X86[j>>MD5_X2].x2.B2[total_len2_X86[j]]);
					else
#endif
					cp = &(input_buf2_X86[j>>MD5_X2].x1.B[total_len2_X86[j]]);
					for (z = 0; z < outlen; ++z) {
						*cp++ = *cpi++;
					}
					total_len2_X86[j] += outlen;
				}
			}
		} else {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp;
				unsigned char *cpi = Str;

				if (total_len2_X86[j] + (len<<1) <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf2_X86[j>>MD5_X2].x2.B2[total_len2_X86[j]]);
					else
#endif
					cp = &(input_buf2_X86[j>>MD5_X2].x1.B[total_len2_X86[j]]);
					for (z = 0; z < len; ++z) {
						*cp++ = *cpi++;
						*cp++ = 0;
					}
					total_len2_X86[j] += (len<<1);
				}
			}
		}
	} else {
		for (; j < til; ++j) {
#if MD5_X2
			if (j&1)
				memcpy(&(input_buf2_X86[j>>MD5_X2].x2.b2[total_len2_X86[j]]), Str, len);
			else
#endif
			memcpy(&(input_buf2_X86[j>>MD5_X2].x1.b[total_len2_X86[j]]), Str, len);
			total_len2_X86[j] += len;
		}
	}
}

void DynamicFunc__setmode_unicodeBE(DYNA_OMP_PARAMS) // DYNA_OMP_PARAMS not used. We use omp_thread_num() instead.
{
	md5_unicode_convert_set(2,tid);
}

void DynamicFunc__setmode_unicode(DYNA_OMP_PARAMS) // DYNA_OMP_PARAMS not used. We use omp_thread_num() instead.
{
	md5_unicode_convert_set(1,tid);
}

void DynamicFunc__setmode_normal (DYNA_OMP_PARAMS) // DYNA_OMP_PARAMS not used. We use omp_thread_num() instead.
{
	md5_unicode_convert_set(0,tid);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Clears the input variable, and input 'lengths'
 *************************************************************/
void DynamicFunc__clean_input(DYNA_OMP_PARAMS)
{
#ifndef _OPENMP
	__nonMP_DynamicFunc__clean_input();
#else
	unsigned int i=0;
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int x = first / SIMD_COEF_32;
		unsigned int y = (last+SIMD_COEF_32-1) / SIMD_COEF_32;
		while (x < y) {
			memset(input_buf[x].c, 0, sizeof(input_buf[0]));
			memset(total_len[x], 0, SIMD_COEF_32 * sizeof(total_len[0][0]));
			++x;
		}
		return;
	}
#endif
	for (i = first; i < last; ++i) {
#if MD5_X2
			if (i&1)
				memset(input_buf_X86[i>>MD5_X2].x2.b2, 0, COMPUTE_EX_LEN(total_len_X86[i]));
			else
#endif
			memset(input_buf_X86[i>>MD5_X2].x1.b, 0, COMPUTE_EX_LEN(total_len_X86[i]));
			total_len_X86[i] = 0;
	}
#endif
}

void DynamicFunc__clean_input2(DYNA_OMP_PARAMS)
{
#ifndef _OPENMP
	__nonMP_DynamicFunc__clean_input2();
#else
	unsigned int i=0;
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int x = first / SIMD_COEF_32;
		unsigned int y = (last+SIMD_COEF_32-1) / SIMD_COEF_32;
		while (x < y) {
			memset(input_buf2[x].c, 0, sizeof(input_buf2[0]));
			memset(total_len2[x], 0, SIMD_COEF_32 * sizeof(total_len2[0][0]));
			++x;
		}
		return;
	}
#endif
	for (i = first; i < last; ++i) {
#if MD5_X2
			if (i&1)
				memset(input_buf2_X86[i>>MD5_X2].x2.b2, 0, COMPUTE_EX_LEN(total_len2_X86[i]));
			else
#endif
			memset(input_buf2_X86[i>>MD5_X2].x1.b, 0, COMPUTE_EX_LEN(total_len2_X86[i]));
			total_len2_X86[i] = 0;
	}
#endif
}

void DynamicFunc__clean_input_full(DYNA_OMP_PARAMS)
{
#ifndef _OPENMP
	__nonMP_DynamicFunc__clean_input_full();
#else
	unsigned int i;
#ifdef SIMD_COEF_32
	unsigned int x = first / SIMD_COEF_32;
	unsigned int y = (last+SIMD_COEF_32-1) / SIMD_COEF_32;
	while (x < y) {
		memset(input_buf[x].c, 0, sizeof(input_buf[0]));
		memset(total_len[x], 0, SIMD_COEF_32 * sizeof(total_len[0][0]));
		++x;
	}
#endif
	for (i = first; i < last; ++i) {
#if MD5_X2
			if (i&1)
				memset(input_buf_X86[i>>MD5_X2].x2.b2, 0, COMPUTE_EX_LEN(total_len_X86[i]));
			else
#endif
			memset(input_buf_X86[i>>MD5_X2].x1.b, 0, COMPUTE_EX_LEN(total_len_X86[i]));
			total_len_X86[i] = 0;
	}
#endif
}

void DynamicFunc__clean_input2_full(DYNA_OMP_PARAMS)
{
#ifndef _OPENMP
	__nonMP_DynamicFunc__clean_input2_full();
#else
	unsigned int i;
#ifdef SIMD_COEF_32
	unsigned int x = first / SIMD_COEF_32;
	unsigned int y = (last+SIMD_COEF_32-1) / SIMD_COEF_32;
	while (x < y) {
		memset(input_buf2[x].c, 0, sizeof(input_buf2[0]));
		memset(total_len2[x], 0, SIMD_COEF_32 * sizeof(total_len2[0][0]));
		++x;
	}
#endif
	for (i = first; i < last; ++i) {
#if MD5_X2
			if (i&1)
				memset(input_buf2_X86[i>>MD5_X2].x2.b2, 0, COMPUTE_EX_LEN(total_len2_X86[i]));
			else
#endif
			memset(input_buf2_X86[i>>MD5_X2].x1.b, 0, COMPUTE_EX_LEN(total_len2_X86[i]));
			total_len2_X86[i] = 0;
	}
#endif
}

void DynamicFunc__clean_input_kwik(DYNA_OMP_PARAMS)
{
#ifndef _OPENMP
	__nonMP_DynamicFunc__clean_input_kwik();
#else
#ifdef SIMD_COEF_32
	unsigned int i;
	if (dynamic_use_sse==1) {
		unsigned int x = first / SIMD_COEF_32;
		unsigned int y = (last+SIMD_COEF_32-1) / SIMD_COEF_32;
		while (x < y)
			memset(total_len[x++], 0, SIMD_COEF_32 * sizeof(total_len[0][0]));
		return;
	}
#else
	unsigned int i;
#endif
	for (i = first; i < last; ++i) {
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
			if (i&1)
				memset(input_buf_X86[i>>MD5_X2].x2.b2, 0, total_len_X86[i]+5);
			else
#endif
			memset(input_buf_X86[i>>MD5_X2].x1.b, 0, total_len_X86[i]+5);
#endif
			total_len_X86[i] = 0;
	}
#endif
}

void DynamicFunc__clean_input2_kwik(DYNA_OMP_PARAMS)
{
#ifndef _OPENMP
	__nonMP_DynamicFunc__clean_input2_kwik();
#else
#ifdef SIMD_COEF_32
	unsigned int i;
	if (dynamic_use_sse==1) {
		unsigned int x = first / SIMD_COEF_32;
		unsigned int y = (last+SIMD_COEF_32-1) / SIMD_COEF_32;
		while (x < y)
			memset(total_len2[x++], 0, SIMD_COEF_32 * sizeof(total_len2[0][0]));
		return;
	}
#else
	unsigned int i;
#endif
	for (i = first; i < last; ++i) {
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
			if (i&1)
				memset(input_buf2_X86[i>>MD5_X2].x2.b2, 0, total_len2_X86[i]+5);
			else
#endif
			memset(input_buf2_X86[i>>MD5_X2].x1.b, 0, total_len2_X86[i]+5);
#endif
			total_len2_X86[i] = 0;
	}
#endif
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends all keys to the end of the input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_keys(DYNA_OMP_PARAMS)
{
	unsigned int j;
	unsigned int til;
	int utf16 = md5_unicode_convert_get(tid);
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		for (; j < til; ++j) {
			unsigned int idx = j/SIMD_COEF_32;
			unsigned int idx_mod = j&(SIMD_COEF_32-1);
			unsigned int bf_ptr = total_len[idx][idx_mod];
			if (utf16) {
				if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
					UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
					int outlen;
					int maxlen=27;
					if (curdat.pSetup->MaxInputLen < maxlen)
						maxlen = curdat.pSetup->MaxInputLen;
					if (utf16 == 1)
						outlen = enc_to_utf16(utf16Str, maxlen, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
					else
						outlen = enc_to_utf16_be(utf16Str, maxlen, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
					if (outlen <= 0) {
						saved_key_len[j] = -outlen / sizeof(UTF16);
						if (outlen < 0)
							outlen = strlen16(utf16Str) * sizeof(UTF16);
					}
					total_len[idx][idx_mod] += outlen;
					__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				} else {
					total_len[idx][idx_mod] += (saved_key_len[j] << 1);
					__SSE_append_string_to_input_unicode(input_buf[idx].c,idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
				}
			} else {
				total_len[idx][idx_mod] += saved_key_len[j];
				__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
			}
		}
		return;
	}
#endif
	if (utf16) {
		if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi;
				UTF16 utf16Str[ENCODED_EFFECTIVE_MAX_LENGTH + 1];
				int outlen;
				if (utf16 == 1)
					outlen = enc_to_utf16(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
				else
					outlen = enc_to_utf16_be(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
				if (outlen <= 0) {
					saved_key_len[j] = -outlen / sizeof(UTF16);
					if (outlen < 0)
						outlen = strlen16(utf16Str) * sizeof(UTF16);
				}

				// only copy data if it will NOT trash the buffer
				if (total_len_X86[j] + outlen <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE)
				{
#if MD5_X2
					if (j&1)
						cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]);
					else
#endif
					cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);
					for (cpi = (unsigned char*)utf16Str, z = 0; z < outlen; ++z)
						*cp++ = *cpi++;
					total_len_X86[j] += outlen;
				}
			}
		} else {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi = (unsigned char*)saved_key[j];

				if (total_len_X86[j] + (saved_key_len[j]<<1) <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]);
					else
#endif
					cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);
					for (z = 0; z < saved_key_len[j]; ++z) {
						*cp++ = *cpi++;
						*cp++ = 0;
					}
					total_len_X86[j] += (saved_key_len[j]<<1);
				}
			}
		}
	} else {
		for (; j < til; ++j) {
#if MD5_X2
			if (j&1)
				memcpy(&(input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]]), saved_key[j], saved_key_len[j]);
			else
#endif
			memcpy(&(input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]]), saved_key[j], saved_key_len[j]);
			total_len_X86[j] += saved_key_len[j];
		}
	}
}

//  DynamicFunc__append_keys_pad16
//    append the array of keys to the array input1[], padding with nulls to 16 bytes, if input shorter.
//    Needed for net-md5 and net-sha1 formats.
void DynamicFunc__append_keys_pad16(DYNA_OMP_PARAMS)
{
	unsigned int j;
	unsigned int til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		for (; j < til; ++j) {
			unsigned int idx = j/SIMD_COEF_32;
			unsigned int idx_mod = j&(SIMD_COEF_32-1);
			unsigned int bf_ptr = total_len[idx][idx_mod];
			saved_key[j][saved_key_len[j]] = 0; // so strncpy 'works'
			if (saved_key_len[j] < 16) {
				char buf[24];
				strncpy(buf, saved_key[j], 18);
				total_len[idx][idx_mod] += 16;
				__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)buf,16,bf_ptr,1);
			} else {
				total_len[idx][idx_mod] += saved_key_len[j];
				__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
			}
		}
		return;
	}
#endif
	for (; j < til; ++j) {
		saved_key[j][saved_key_len[j]] = 0;  // so strncpy 'works'
#if MD5_X2
		if (j&1)
			strncpy(&(input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]]), saved_key[j], 17);
		else
#endif
		strncpy(&(input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]]), saved_key[j], 17);
		total_len_X86[j] += 16;
	}
}

void DynamicFunc__append_keys_pad20(DYNA_OMP_PARAMS)
{
	unsigned int j;
	unsigned int til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		for (; j < til; ++j) {
			unsigned int idx = j/SIMD_COEF_32;
			unsigned int idx_mod = j&(SIMD_COEF_32-1);
			unsigned int bf_ptr = total_len[idx][idx_mod];
			saved_key[j][saved_key_len[j]] = 0; // so strncpy 'works'
			if (saved_key_len[j] < 20) {
				char buf[28];
				strncpy(buf, saved_key[j], 22);
				total_len[idx][idx_mod] += 20;
				__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)buf,20,bf_ptr,1);
			} else {
				total_len[idx][idx_mod] += saved_key_len[j];
				__SSE_append_string_to_input(input_buf[idx].c,idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
			}
		}
		return;
	}
#endif
	for (; j < til; ++j) {
		saved_key[j][saved_key_len[j]] = 0;  // so strncpy 'works'
#if MD5_X2
		if (j&1)
			strncpy(&(input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]]), saved_key[j], 21);
		else
#endif
		strncpy(&(input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]]), saved_key[j], 21);
		total_len_X86[j] += 20;
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends all keys to the end of the 2nd input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_keys2(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
	int utf16 = md5_unicode_convert_get(tid);
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		for (; j < til; ++j) {
			unsigned int idx = j/SIMD_COEF_32;
			unsigned int idx_mod = j&(SIMD_COEF_32-1);
			unsigned int bf_ptr = total_len2[idx][idx_mod];
			if (utf16) {
				if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
					UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
					int outlen;
					int maxlen=27;
					if (curdat.pSetup->MaxInputLen < maxlen)
						maxlen = curdat.pSetup->MaxInputLen;
					if (utf16 == 1)
						outlen = enc_to_utf16(utf16Str, maxlen, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
					else
						outlen = enc_to_utf16_be(utf16Str, maxlen, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
					if (outlen <= 0) {
						saved_key_len[j] = -outlen / sizeof(UTF16);
						if (outlen < 0)
							outlen = strlen16(utf16Str) * sizeof(UTF16);
					}
					total_len2[idx][idx_mod] += outlen;
					__SSE_append_string_to_input(input_buf2[idx].c,idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				} else {
					total_len2[idx][idx_mod] += (saved_key_len[j] << 1);
					__SSE_append_string_to_input_unicode(input_buf2[idx].c,idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
				}
			} else {
				total_len2[idx][idx_mod] += saved_key_len[j];
				__SSE_append_string_to_input(input_buf2[idx].c,idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
			}
		}
		return;
	}
#endif
	if (utf16) {
		if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi;
				UTF16 utf16Str[ENCODED_EFFECTIVE_MAX_LENGTH + 1];
				int outlen;
				if (utf16 == 1)
					outlen = enc_to_utf16(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
				else
					outlen = enc_to_utf16_be(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
				if (outlen <= 0) {
					saved_key_len[j] = -outlen / sizeof(UTF16);
					if (outlen < 0)
						outlen = strlen16(utf16Str) * sizeof(UTF16);
				}

				// only copy data if it will NOT trash the buffer
				if (total_len_X86[j] + outlen <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf2_X86[j>>MD5_X2].x2.B2[total_len2_X86[j]]);
					else
#endif
					cp = &(input_buf2_X86[j>>MD5_X2].x1.B[total_len2_X86[j]]);
					for (cpi = (unsigned char*)utf16Str, z = 0; z < outlen; ++z)
						*cp++ = *cpi++;
					total_len2_X86[j] += outlen;
				}
			}
		} else {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi = (unsigned char*)saved_key[j];

				if (total_len2_X86[j] + (saved_key_len[j]<<1) <= MAX_BUFFER_OFFSET_AVOIDING_OVERWRITE) {
#if MD5_X2
					if (j&1)
						cp = &(input_buf2_X86[j>>MD5_X2].x2.B2[total_len2_X86[j]]);
					else
#endif
					cp = &(input_buf2_X86[j>>MD5_X2].x1.B[total_len2_X86[j]]);
					for (z = 0; z < saved_key_len[j]; ++z) {
						*cp++ = *cpi++;
						*cp++ = 0;
					}
					total_len2_X86[j] += (saved_key_len[j]<<1);
				}
			}
		}
	} else {
		for (; j < til; ++j) {
#if MD5_X2
			if (j&1)
				memcpy(&(input_buf2_X86[j>>MD5_X2].x2.b2[total_len2_X86[j]]), saved_key[j], saved_key_len[j]);
			else
#endif
			memcpy(&(input_buf2_X86[j>>MD5_X2].x1.b[total_len2_X86[j]]), saved_key[j], saved_key_len[j]);
			total_len2_X86[j] += saved_key_len[j];
		}
	}
}

void DynamicFunc__set_input_len_16(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int k;
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			// If length is < 16, then remove existing end of buffer marker, and then set
			// one at offset 16
			for (k = 0; k < SIMD_COEF_32; ++k) {
				unsigned int this_item_len = total_len[j][k];

				if (this_item_len < 16)
					input_buf[j].c[GETPOS(this_item_len, k&(SIMD_COEF_32-1))] = 0x00;
				input_buf[j].c[GETPOS(16, k&(SIMD_COEF_32-1))] = 0x80;

				total_len[j][k] = 16;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		// TODO: this code MAY need buffer cleaned up if we are using md5_go code!!!
#if MD5_X2
		if (j&1) {
			while (total_len_X86[j] < 16)
				input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]++] = 0;
		}
		else
#endif
		{while (total_len_X86[j] < 16)
			input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]++] = 0;}
		total_len_X86[j] = 16;
	}
}

void DynamicFunc__set_input2_len_16(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int k;
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			// If length is < 16, then remove existing end of buffer marker, and then set
			// one at offset 16
			for (k = 0; k < SIMD_COEF_32; ++k) {
				unsigned int this_item_len = total_len2[j][k];
				if (this_item_len < 16)
					input_buf2[j].c[GETPOS(this_item_len, k&(SIMD_COEF_32-1))] = 0x00;
				input_buf2[j].c[GETPOS(16, k&(SIMD_COEF_32-1))] = 0x80;
				total_len2[j][k] = 16;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		// TODO: this code MAY need buffer cleaned up if we are using md5_go code!!!
#if MD5_X2
		if (j&1) {
			while (total_len2_X86[j] < 16)
				input_buf2_X86[j>>MD5_X2].x2.b2[total_len2_X86[j]++] = 0;
		}
		else
#endif
		{while (total_len2_X86[j] < 16)
			input_buf2_X86[j>>MD5_X2].x1.b[total_len2_X86[j]++] = 0;}
		total_len2_X86[j] = 16;
	}
}

void DynamicFunc__set_input_len_20(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int k;
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			// If length is < 20, then remove existing end of buffer marker, and then set
			// one at offset 20
			for (k = 0; k < SIMD_COEF_32; ++k) {
				unsigned int this_item_len = total_len[j][k];
				if (this_item_len < 20)
					input_buf[j].c[GETPOS(this_item_len, k&(SIMD_COEF_32-1))] = 0x00;
				input_buf[j].c[GETPOS(20, k&(SIMD_COEF_32-1))] = 0x80;
				total_len[j][k] = 20;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
#if MD5_X2
		if (j&1) {
			while (total_len_X86[j] < 20)
				input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]++] = 0;
		}
		else
#endif
		{while (total_len_X86[j] < 20)
			input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]++] = 0;}
		total_len_X86[j] = 20;
	}
}

void DynamicFunc__set_input2_len_20(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int k;
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			// If length is < 20, then remove existing end of buffer marker, and then set
			// one at offset 20
			for (k = 0; k < SIMD_COEF_32; ++k) {
				unsigned int this_item_len = total_len2[j][k];
				if (this_item_len < 20)
					input_buf2[j].c[GETPOS(this_item_len, k&(SIMD_COEF_32-1))] = 0x00;
				input_buf2[j].c[GETPOS(20, k&(SIMD_COEF_32-1))] = 0x80;
				total_len2[j][k] = 20;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
#if MD5_X2
		if (j&1) {
			while (total_len2_X86[j] < 20)
				input_buf2_X86[j>>MD5_X2].x2.b2[total_len2_X86[j]++] = 0;
		}
		else
#endif
		{while (total_len2_X86[j] < 20)
			input_buf2_X86[j>>MD5_X2].x1.b[total_len2_X86[j]++] = 0;}
		total_len2_X86[j] = 20;
	}
}

void DynamicFunc__set_input_len_32(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 32;
}

void DynamicFunc__set_input_len_32_cleartop(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			unsigned int k;
			for (k = 0; k < SIMD_COEF_32; ++k) {
				input_buf[j].c[GETPOS(32, k&(SIMD_COEF_32-1))] = 0x80;
				total_len[j][k] = 32;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j) {
		total_len_X86[j] = 32;
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
		if (j&1) {
			//MD5_swap(input_buf_X86[j>>MD5_X2].x2.w2, input_buf2_X86[j>>MD5_X2].x2.w2, 8);
			memset(&(input_buf_X86[j>>MD5_X2].x2.B2[32]), 0, 24);
		}
		else
#endif
		{
			//MD5_swap(input_buf_X86[j>>MD5_X2].x1.w, input_buf2_X86[j>>MD5_X2].x1.w, 8);
			memset(&(input_buf_X86[j>>MD5_X2].x1.B[32]), 0, 24);
		}
#endif
	}
}

void DynamicFunc__set_input2_len_32(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 32;
}
void DynamicFunc__set_input2_len_32_cleartop(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			unsigned int k;
			for (k = 0; k < SIMD_COEF_32; ++k) {
				input_buf2[j].c[GETPOS(32, k&(SIMD_COEF_32-1))] = 0x80;
				total_len2[j][k] = 32;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		total_len2_X86[j] = 32;
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
		if (j&1) {
			//MD5_swap(input_buf2_X86[j>>MD5_X2].x2.w2, input_buf2_X86[j>>MD5_X2].x2.w2, 8);
			memset(&(input_buf2_X86[j>>MD5_X2].x2.B2[32]), 0, 24);
		}
		else
#endif
		{
			//MD5_swap(input_buf2_X86[j>>MD5_X2].x1.w, input_buf2_X86[j>>MD5_X2].x1.w, 8);
			memset(&(input_buf2_X86[j>>MD5_X2].x1.B[32]), 0, 24);
		}
#endif
	}
}

void DynamicFunc__set_input_len_40(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 40;
}

void DynamicFunc__set_input2_len_40(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 40;
}

void DynamicFunc__set_input2_len_40_cleartop(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		j /= SIMD_COEF_32;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		for (; j < til; ++j)
		{
			unsigned int k;
			for (k = 0; k < SIMD_COEF_32; ++k) {
				input_buf2[j].c[GETPOS(40, k&(SIMD_COEF_32-1))] = 0x80;
				total_len2[j][k] = 40;
			}
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		total_len2_X86[j] = 40;
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
		if (j&1) {
			memset(&(input_buf2_X86[j>>MD5_X2].x2.B2[40]), 0, 16);
		}
		else
#endif
		{
			memset(&(input_buf2_X86[j>>MD5_X2].x1.B[40]), 0, 16);
		}
#endif
	}
}

void DynamicFunc__set_input_len_64(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_64 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 64;
}

void DynamicFunc__set_input2_len_64(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_64 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 64;
}

void DynamicFunc__set_input_len_100(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_100 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j) {
		unsigned char *cp;
#if MD5_X2
		if (j&1)
			cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]);
		else
#endif
			cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);
		while (*cp)
			*cp++ = 0;
		total_len_X86[j] = 100;
	}
}


void DynamicFunc__set_input_len_24(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_24 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 24;
}

void DynamicFunc__set_input_len_28(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_28 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 28;
}

void DynamicFunc__set_input_len_48(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_48 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 48;
}

void DynamicFunc__set_input_len_56(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_56 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 56;
}

void DynamicFunc__set_input_len_80(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_80 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 80;
}

void DynamicFunc__set_input_len_96(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_96 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 96;
}

void DynamicFunc__set_input_len_112(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_112 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 112;
}

void DynamicFunc__set_input_len_128(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_128 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 128;
}

void DynamicFunc__set_input_len_160(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_160 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 160;
}

void DynamicFunc__set_input_len_192(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_192 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 192;
}

void DynamicFunc__set_input_len_256(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_256 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len_X86[j] = 256;
}

void DynamicFunc__set_input2_len_24(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_24 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 24;
}

void DynamicFunc__set_input2_len_28(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_28 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 28;
}

void DynamicFunc__set_input2_len_48(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_48 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 48;
}

void DynamicFunc__set_input2_len_56(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_56 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 56;
}

void DynamicFunc__set_input2_len_80(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_80 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 80;
}

void DynamicFunc__set_input2_len_96(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_96 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 96;
}

void DynamicFunc__set_input2_len_112(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_112 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 112;
}

void DynamicFunc__set_input2_len_128(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_128 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 128;
}

void DynamicFunc__set_input2_len_160(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_160 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 160;
}

void DynamicFunc__set_input2_len_192(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_192 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 192;
}

void DynamicFunc__set_input2_len_256(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	til = last;
	j = first;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse == 1)
		error_msg("Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_256 in SSE2/MMX mode\n");
#endif
	for (; j < til; ++j)
		total_len2_X86[j] = 256;
}


/**************************************************************
 * DYNAMIC primitive helper function
 * Appends the salt to the end of the input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_salt(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm cursalt, saltlen);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends the salt to the end of the 2nd input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_salt2(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm cursalt, saltlen);
}

void DynamicFunc__append_input_from_input2(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int j, k;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; ++i)
		{
			for (j = 0; j < SIMD_COEF_32; ++j)
			{
				unsigned int start_len = total_len[i][j];
				unsigned int len1 = total_len2[i][j];
				for (k = 0; k < len1; ++k)
					input_buf[i].c[GETPOS((k+start_len), j)] = input_buf2[i].c[GETPOS(k,j)];
				input_buf[i].c[GETPOS((len1+start_len), j)] = 0x80;
				total_len[i][j] += len1;
			}
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
#if MD5_X2
		if (i&1)
			memcpy(&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]), input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
		memcpy(&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]), input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		total_len_X86[i] += total_len2_X86[i];
	}
}

void DynamicFunc__append_input2_from_input(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int j, k;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; ++i)
		{
			for (j = 0; j < SIMD_COEF_32; ++j)
			{
				unsigned int start_len = total_len2[i][j];
				unsigned int len1 = total_len[i][j];
				for (k = 0; k < len1; ++k)
					input_buf2[i].c[GETPOS((k+start_len), j)] = input_buf[i].c[GETPOS(k,j)];
				input_buf2[i].c[GETPOS((len1+start_len), j)] = 0x80;
				total_len2[i][j] += len1;
			}
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
#if MD5_X2
		if (i&1)
			memcpy(&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]), input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
		memcpy(&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]), input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		total_len2_X86[i] += total_len_X86[i];
	}
}

void DynamicFunc__append_input_from_input(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int j, k;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; ++i)
		{
			for (j = 0; j < SIMD_COEF_32; ++j)
			{
				unsigned int start_len = total_len[i][j];
				for (k = 0; k < start_len; ++k)
					input_buf[i].c[GETPOS((k+start_len), j)] = input_buf[i].c[GETPOS(k,j)];
				input_buf[i].c[GETPOS((start_len+start_len), j)] = 0x80;
				total_len[i][j] += start_len;
			}
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
#if MD5_X2
		if (i&1)
			memcpy(&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]), input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
		memcpy(&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]), input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		total_len_X86[i] <<= 1;
	}
}

void DynamicFunc__append_input2_from_input2(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int j, k;
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; ++i)
		{
			for (j = 0; j < SIMD_COEF_32; ++j)
			{
				unsigned int start_len = total_len2[i][j];
				for (k = 0; k < start_len; ++k)
					input_buf2[i].c[GETPOS((k+start_len), j)] = input_buf2[i].c[GETPOS(k,j)];
				input_buf2[i].c[GETPOS((start_len+start_len), j)] = 0x80;
				total_len2[i][j] += start_len;
			}
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
#if MD5_X2
		if (i&1)
			memcpy(&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]), input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
		memcpy(&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]), input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		total_len2_X86[i] <<= 1;
	}
}

#ifdef SIMD_PARA_MD5
static void SSE_Intrinsics_LoadLens_md5(int side, int i)
{
	uint32_t *p;
	unsigned int j, k;
	if (side == 0)
	{
		for (j = 0; j < SIMD_PARA_MD5; j++)
		{
			p = input_buf[i+j].w;
			for (k = 0; k < SIMD_COEF_32; k++)
				p[14*SIMD_COEF_32+k] = total_len[i+j][k] << 3;
		}
	}
	else
	{
		for (j = 0; j < SIMD_PARA_MD5; j++)
		{
			p = input_buf2[i+j].w;
			for (k = 0; k < SIMD_COEF_32; k++)
				p[14*SIMD_COEF_32+k] = total_len2[i+j][k] << 3;
		}
	}
}
#endif
#ifdef SIMD_PARA_MD4
static void SSE_Intrinsics_LoadLens_md4(int side, int i)
{
	uint32_t *p;
	unsigned int j, k;
	if (side == 0)
	{
		for (j = 0; j < SIMD_PARA_MD4; j++)
		{
			p = input_buf[i+j].w;
			for (k = 0; k < SIMD_COEF_32; k++)
				p[14*SIMD_COEF_32+k] = total_len[i+j][k] << 3;
		}
	}
	else
	{
		for (j = 0; j < SIMD_PARA_MD4; j++)
		{
			p = input_buf2[i+j].w;
			for (k = 0; k < SIMD_COEF_32; k++)
				p[14*SIMD_COEF_32+k] = total_len2[i+j][k] << 3;
		}
	}
}
#endif
/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the first input field. The data is
 * still in the binary encrypted format, in the crypt_key.
 * we do not yet convert to base-16.  This is so we can output
 * as base-16, or later, if we add base-64, we can output to
 * that format instead.
 *************************************************************/
void DynamicFunc__crypt_md5(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		if (curdat.store_keys_in_input) {
			for (; i < til; i += SIMD_PARA_MD5) {
				SIMDmd5body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			}
		} else {
			for (; i < til; i += SIMD_PARA_MD5) {
				SSE_Intrinsics_LoadLens_md5(0, i);
				SIMDmd5body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			}
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md4(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		if (curdat.store_keys_in_input) {
			for (; i < til; i += SIMD_PARA_MD4) {
				SIMDmd4body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			}
		} else {
			for (; i < til; i += SIMD_PARA_MD4) {
				SSE_Intrinsics_LoadLens_md4(0, i);
				SIMDmd4body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			}
		}
		return;
	}
#endif
	for (; i < til; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		DoMD4(input_buf_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__POCrypt(DYNA_OMP_PARAMS)
{
	unsigned int i, j;
	unsigned int til, len;
	unsigned char *pBuf;
#if MD5_X2
	unsigned char *pBuf2;
	unsigned int lens[2];
#endif
#ifdef _OPENMP
	til = last;
	i = first;
#else
	i = 0;
	til = m_count;
#endif
	//DynamicFunc__clean_input_kwik();
	//DynamicFunc__append_salt,
	//DynamicFunc__append_input1_from_CONST1,
	//DynamicFunc__append_keys,
	//DynamicFunc__append_input1_from_CONST2,
	//DynamicFunc__append_salt,
	//DynamicFunc__crypt_md5,
	pBuf = input_buf_X86[i>>MD5_X2].x1.B;
#if MD5_X2
	pBuf2 = input_buf_X86[i>>MD5_X2].x2.B2;
	memset(pBuf2, 0, sizeof(input_buf_X86[i>>MD5_X2].x2.B2));
	memcpy(pBuf2, cursalt, 32);
	pBuf2[32] = 'Y';
#endif
	memset(pBuf, 0, sizeof(input_buf_X86[i>>MD5_X2].x1.b));
	memcpy(pBuf, cursalt, 32);
	pBuf[32] = 'Y';
	for (j = i; j < til; ++j) {
		len = saved_key_len[j];
		memcpy(&pBuf[33], saved_key[j], len);
		pBuf[33+len] = 0xf7;
		memcpy(&pBuf[34+len], cursalt, 32);

#if MD5_X2
		lens[0] = len+66;  // len from the 'first'
		++j;
		if (j < m_count) {
			len = saved_key_len[j];
			memcpy(&pBuf2[33], saved_key[j], len);
			pBuf2[33+len] = 0xf7;
			memcpy(&pBuf2[34+len], cursalt, 32);
			lens[1] = len+66;
		} else {
			lens[1] = 0;
		}
		DoMD5(input_buf_X86[i>>MD5_X2], lens, crypt_key_X86[j>>MD5_X2]);
#else
		DoMD5(input_buf_X86[i>>MD5_X2], (len+66), crypt_key_X86[j]);
#endif
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the 2nd input field into crypt_keys2.
 *************************************************************/
void DynamicFunc__crypt2_md5(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD5) {
			SSE_Intrinsics_LoadLens_md5(1, i);
			SIMDmd5body(input_buf2[i].c, crypt_key2[i].w, NULL, SSEi_MIXED_IN);
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len2_X86[i++];
		if (i < m_count)
			len[1] = total_len2_X86[i];
		else
			len[1] = 0;
#else
		unsigned int len = total_len2_X86[i];
#endif
		DoMD5(input_buf2_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt2_md4(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD4) {
			SSE_Intrinsics_LoadLens_md4(1, i);
			SIMDmd4body(input_buf2[i].c, crypt_key2[i].w, NULL, SSEi_MIXED_IN);
		}
		return;
	}
#endif
	for (; i < til; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len2_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len2_X86[i];
#else
		unsigned int len = total_len2_X86[i];
#endif
		DoMD4(input_buf2_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the 1st input field      crypt_keys2.
 *************************************************************/
void DynamicFunc__crypt_md5_in1_to_out2(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		if (curdat.store_keys_in_input) {
			for (; i < til; i += SIMD_PARA_MD5) {
				SIMDmd5body(input_buf[i].c, crypt_key2[i].w, NULL, SSEi_MIXED_IN);
			}
		} else {
			for (; i < til; i += SIMD_PARA_MD5) {
				SSE_Intrinsics_LoadLens_md5(0, i);
				SIMDmd5body(input_buf[i].c, crypt_key2[i].w, NULL, SSEi_MIXED_IN);
			}
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md4_in1_to_out2(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		if (curdat.store_keys_in_input) {
			for (; i < til; i += SIMD_PARA_MD4) {
				SIMDmd4body(input_buf[i].c, crypt_key2[i].w, NULL, SSEi_MIXED_IN);
			}
		} else {
			for (; i < til; i += SIMD_PARA_MD4) {
				SSE_Intrinsics_LoadLens_md4(0, i);
				SIMDmd4body(input_buf[i].c, crypt_key2[i].w, NULL, SSEi_MIXED_IN);
			}
		}
		return;
	}
#endif
	for (; i < til; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		DoMD4(input_buf_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the 2nd input field into crypt_keys.
 *************************************************************/
void DynamicFunc__crypt_md5_in2_to_out1(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD5)
		{
			SSE_Intrinsics_LoadLens_md5(1, i);
			SIMDmd5body(input_buf2[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			//dump_stuff_mmx_msg("DynamicFunc__crypt_md5_in2_to_out1", input_buf2[i].c,64,m_count-1);
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len2_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len2_X86[i];
#else
		unsigned int len = total_len2_X86[i];
#endif
		DoMD5(input_buf2_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md4_in2_to_out1(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD4)
		{
			SSE_Intrinsics_LoadLens_md4(1, i);
			SIMDmd4body(input_buf2[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
		}
		return;
	}
#endif
	for (; i < til; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len2_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len2_X86[i];
#else
		unsigned int len = total_len2_X86[i];
#endif
		DoMD4(input_buf2_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md5_to_input_raw(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD5)
		{
			unsigned int j, k;
			SSE_Intrinsics_LoadLens_md5(0, i);
			// NOTE, since crypt_key array is 16 bytes each, and input_buf is 64 bytes
			// each, and we are doing 3 at a time, we can NOT directly write to the
			// input buff, but have to use the crypt_key buffer, and then memcpy when done.
			SIMDmd5body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			for (j = 0; j < SIMD_PARA_MD5; ++j)
			{
				memset(input_buf[i+j].c, 0, sizeof(input_buf[0]));
				memcpy(input_buf[i+j].c, crypt_key[i+j].c, 16*SIMD_COEF_32);
				for (k = 0; k < SIMD_COEF_32; k++)
					total_len[i+j][k] = 16;
			}
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i];
		total_len_X86[i++] = 0x10;
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, input_buf_X86[i>>MD5_X2]);
		total_len_X86[i] = 0x10;
	}
}

void DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD5)
		{
			unsigned int j;
			SSE_Intrinsics_LoadLens_md5(0, i);
			// NOTE, since crypt_key array is 16 bytes each, and input_buf is 64 bytes
			// each, and we are doing 3 at a time, we can NOT directly write to the
			// input buff, but have to use the crypt_key buffer, and then memcpy when done.
			SIMDmd5body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			for (j = 0; j < SIMD_PARA_MD5; ++j)
				memcpy(input_buf[i+j].c, crypt_key[i+j].c, 16*SIMD_COEF_32);
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, input_buf_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		til = (til+SIMD_COEF_32-1)/SIMD_COEF_32;
		i /= SIMD_COEF_32;
		for (; i < til; i += SIMD_PARA_MD5)
		{
			unsigned int j;
			// NOTE, since crypt_key array is 16 bytes each, and input_buf is 64 bytes
			// each, and we are doing 3 at a time, we can NOT directly write to the
			// input buff, but have to use the crypt_key buffer, and then memcpy when done.
			SIMDmd5body(input_buf[i].c, crypt_key[i].w, NULL, SSEi_MIXED_IN);
			for (j = 0; j < SIMD_PARA_MD5; ++j)
				memcpy(input_buf[i+j].c, crypt_key[i+j].c, 16*SIMD_COEF_32);
		}
		return;
	}
#endif
	for (; i < til; ++i) {
#if MD5_X2
		unsigned int len[2];
		len[0] = total_len_X86[i++];
		if (i == m_count)
			len[1] = 0;
		else
			len[1] = total_len_X86[i];
#else
		unsigned int len = total_len_X86[i];
#endif
		// we call DoMD5o so as to 'not' change then length (it was already set)
		DoMD5o(input_buf_X86[i>>MD5_X2], len, input_buf_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__overwrite_salt_to_input1_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
	int utf16 = md5_unicode_convert_get(tid);
#ifdef _OPENMP
	j = first;
	til = last;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		if (utf16) {
			if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;
				if (utf16 == 1)
					outlen = enc_to_utf16(utf16Str, 27, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
				else
					outlen = enc_to_utf16_be(utf16Str, 27, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (; j < til; ++j) {
					__SSE_append_string_to_input(input_buf[j/SIMD_COEF_32].c,j&(SIMD_COEF_32-1),(unsigned char*)utf16Str,outlen,0,0);
				}
			} else {
				for (; j < til; ++j)
					__SSE_append_string_to_input_unicode(input_buf[j/SIMD_COEF_32].c,j&(SIMD_COEF_32-1),(unsigned char*)cursalt,saltlen,0,0);
			}
			return;
		}
		for (; j < til; ++j)
			__SSE_append_string_to_input(input_buf[j/SIMD_COEF_32].c,j&(SIMD_COEF_32-1),cursalt,saltlen,0,0);
		return;
	}
#endif
	if (utf16) {
		if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
			UTF16 utf16Str[ENCODED_EFFECTIVE_MAX_LENGTH + 1];
			int outlen;
			if (utf16 == 1)
				outlen = enc_to_utf16(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
			else
				outlen = enc_to_utf16_be(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);

			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi = (unsigned char*)utf16Str;
#if MD5_X2
				if (j&1)
					cp = input_buf_X86[j>>MD5_X2].x2.B2;
				else
#endif
				cp = input_buf_X86[j>>MD5_X2].x1.B;
				for (z = 0; z < outlen; ++z)
					*cp++ = *cpi++;
			}
		} else {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi = (unsigned char*)cursalt;
#if MD5_X2
				if (j&1)
					cp = input_buf_X86[j>>MD5_X2].x2.B2;
				else
#endif
				cp = input_buf_X86[j>>MD5_X2].x1.B;
				for (z = 0; z < saltlen; ++z) {
					*cp++ = *cpi++;
					*cp++ = 0;
				}
			}
		}
		return;
	}
	for (; j < til; ++j) {
#if MD5_X2
		if (j&1)
			memcpy(input_buf_X86[j>>MD5_X2].x2.b2, cursalt, saltlen);
		else
#endif
		memcpy(input_buf_X86[j>>MD5_X2].x1.b, cursalt, saltlen);
	}
}

void DynamicFunc__overwrite_salt_to_input2_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
	int utf16 = md5_unicode_convert_get(tid);
#ifdef _OPENMP
	j = first;
	til = last;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		if (utf16) {
			if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;
				if (utf16 == 1)
					outlen = enc_to_utf16(utf16Str, 27, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
				else
					outlen = enc_to_utf16_be(utf16Str, 27, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (; j < til; ++j) {
					__SSE_append_string_to_input(input_buf2[j/SIMD_COEF_32].c,j&(SIMD_COEF_32-1),(unsigned char*)utf16Str,outlen,0,0);
				}
			} else {
				for (; j < til; ++j)
					__SSE_append_string_to_input_unicode(input_buf2[j/SIMD_COEF_32].c,j&(SIMD_COEF_32-1),(unsigned char*)cursalt,saltlen,0,0);
			}
			return;
		}
		for (; j < til; ++j)
			__SSE_append_string_to_input(input_buf2[j/SIMD_COEF_32].c,j&(SIMD_COEF_32-1),cursalt,saltlen,0,0);
		return;
	}
#endif
	if (utf16) {
		if (utf16 == 2 || (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)) {
			UTF16 utf16Str[ENCODED_EFFECTIVE_MAX_LENGTH + 1];
			int outlen;
			if (utf16 == 1)
				outlen = enc_to_utf16(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
			else
				outlen = enc_to_utf16_be(utf16Str, ENCODED_EFFECTIVE_MAX_LENGTH, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);

			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi = (unsigned char*)utf16Str;
#if MD5_X2
				if (j&1)
					cp = input_buf2_X86[j>>MD5_X2].x2.B2;
				else
#endif
				cp = input_buf2_X86[j>>MD5_X2].x1.B;
				for (z = 0; z < outlen; ++z)
					*cp++ = *cpi++;
			}
		} else {
			for (; j < til; ++j) {
				unsigned int z;
				unsigned char *cp, *cpi = (unsigned char*)cursalt;
#if MD5_X2
				if (j&1)
					cp = input_buf2_X86[j>>MD5_X2].x2.B2;
				else
#endif
				cp = input_buf2_X86[j>>MD5_X2].x1.B;

				for (z = 0; z < saltlen; ++z) {
					*cp++ = *cpi++;
					*cp++ = 0;
				}
			}
		}
		return;
	}
	for (; j < til; ++j) {
#if MD5_X2
		if (j&1)
			memcpy(input_buf2_X86[j>>MD5_X2].x2.b2, cursalt, saltlen);
		else
#endif
		memcpy(input_buf2_X86[j>>MD5_X2].x1.b, cursalt, saltlen);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * overwrites start of input1 from the output2 data using base-16
 *************************************************************/
void DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	j = first;
	til = last;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; j < til; ++j)
		{
			idx = ( ((unsigned int)j)/SIMD_COEF_32);
			__SSE_overwrite_output_base16_to_input(input_buf[idx].w, crypt_key2[idx].c, j&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		unsigned char *cpo, *cpi;
		unsigned int i;
		/* uint32_t *w; */
#if MD5_X2
		if (j&1)
			{cpo = input_buf_X86[j>>MD5_X2].x2.B2; cpi = crypt_key2_X86[j>>MD5_X2].x2.B2; /* w=input_buf_X86[j>>MD5_X2].x2.w2; */}
		else
#endif
			{cpo = input_buf_X86[j>>MD5_X2].x1.B; cpi = crypt_key2_X86[j>>MD5_X2].x1.B; /* w=input_buf_X86[j>>MD5_X2].x1.w; */ }
		for (i = 0; i < 16; ++i, ++cpi)
		{
			*cpo++ = dynamic_itoa16[*cpi>>4];
			*cpo++ = dynamic_itoa16[*cpi&0xF];
		}
		//MD5_swap(w,w,4);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * overwrites start of input1 from the output1 data using base-16
 *************************************************************/
void DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	j = first;
	til = last;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; j < til; ++j)
		{
			idx = ( ((unsigned int)j)/SIMD_COEF_32);
			__SSE_overwrite_output_base16_to_input(input_buf[idx].w, crypt_key[idx].c, j&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		unsigned char *cpo, *cpi;
		unsigned int i;
		/* uint32_t *w; */
#if MD5_X2
		if (j&1)
			{cpo = input_buf_X86[j>>MD5_X2].x2.B2; cpi = crypt_key_X86[j>>MD5_X2].x2.B2; /* w=input_buf_X86[j>>MD5_X2].x2.w2; */}
		else
#endif
			{cpo = input_buf_X86[j>>MD5_X2].x1.B; cpi = crypt_key_X86[j>>MD5_X2].x1.B; /* w=input_buf_X86[j>>MD5_X2].x1.w; */ }
		for (i = 0; i < 16; ++i, ++cpi)
		{
			*cpo++ = dynamic_itoa16[*cpi>>4];
			*cpo++ = dynamic_itoa16[*cpi&0xF];
		}
		//MD5_swap(w,w,4);
	}
}


/**************************************************************
 * DYNAMIC primitive helper function
 * This will take the data stored in the crypt_keys (the encrypted
 * 'first' key variable), and use a base-16 text formatting, and
 * append this to the first input buffer (adjusting the lengths)
 *************************************************************/
void DynamicFunc__append_from_last_output_as_base16(DYNA_OMP_PARAMS)
{
	unsigned int j, til;
#ifdef _OPENMP
	j = first;
	til = last;
#else
	j = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; j < til; ++j)
		{
			unsigned int ip;
			idx = ( ((unsigned int)j)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len[idx][j & (SIMD_COEF_32 - 1)];
			total_len[idx][j & (SIMD_COEF_32 - 1)] += 32;
			if (!ip)
				__SSE_append_output_base16_to_input(input_buf[idx].w, crypt_key[idx].c, j&(SIMD_COEF_32-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				unsigned int k;
				for (k = 0; k < 16; ++k)
				{
					unsigned char v = crypt_key[idx].c[GETPOS(k, j&(SIMD_COEF_32-1))];
					input_buf[idx].c[GETPOS(ip+(k<<1), j&(SIMD_COEF_32-1))] = dynamic_itoa16[v>>4];
					input_buf[idx].c[GETPOS(ip+(k<<1)+1, j&(SIMD_COEF_32-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf[idx].c[GETPOS(ip+32, j&(SIMD_COEF_32-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, input_buf[idx].w, crypt_key[idx].c, j&(SIMD_COEF_32-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, input_buf[idx].w, crypt_key[idx].c, j&(SIMD_COEF_32-1));

		}
		return;
	}
#endif
	for (; j < til; ++j)
	{
		unsigned char *cp, *cpi;
		unsigned int i;
#if MD5_X2
		if (j&1)
		{cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]); cpi =  crypt_key_X86[j>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);  cpi = crypt_key_X86[j>>MD5_X2].x1.B; }
		for (i = 0; i < 16; ++i)
		{
#if ARCH_ALLOWS_UNALIGNED
			*((unsigned short*)cp) = itoa16_w2[*cpi++];
			cp += 2;
#else
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
#endif
		}
		*cp = 0;
		total_len_X86[j] += 32;
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * This will take the data stored in the crypt_keys2 (the encrypted
 * 'second' key variable), and base-16 appends to the 2nd input
 *************************************************************/
void DynamicFunc__append_from_last_output2_as_base16(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; i < til; ++i)
		{
			unsigned int ip, j;
			idx = ( ((unsigned int)i)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len2[idx][i&(SIMD_COEF_32-1)];
			total_len2[idx][i&(SIMD_COEF_32-1)] += 32;
			if (!ip)
				__SSE_append_output_base16_to_input(input_buf2[idx].w, crypt_key2[idx].c, i&(SIMD_COEF_32-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (j = 0; j < 16; ++j)
				{
					unsigned char v = crypt_key2[idx].c[GETPOS(j, i&(SIMD_COEF_32-1))];
					input_buf2[idx].c[GETPOS(ip+(j<<1), i&(SIMD_COEF_32-1))] = dynamic_itoa16[v>>4];
					input_buf2[idx].c[GETPOS(ip+(j<<1)+1, i&(SIMD_COEF_32-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf2[idx].c[GETPOS(ip+32, i&(SIMD_COEF_32-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, input_buf2[idx].w, crypt_key2[idx].c, i&(SIMD_COEF_32-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, input_buf2[idx].w, crypt_key2[idx].c, i&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;
#if MD5_X2
		if (i&1)
		{cp = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x1.B; }
		for (j = 0; j < 16; ++j)
		{
#if ARCH_ALLOWS_UNALIGNED
			*((unsigned short*)cp) = itoa16_w2[*cpi++];
			cp += 2;
#else
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
#endif
		}
		*cp = 0;
		total_len2_X86[i] += 32;
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * overwrites start of input2 from the output1 data using base-16
 * an optimization, if the same thing is done over and over
 * again, such as md5(md5(md5(md5($p))))  There, we would only
 * call the copy and set length once, then simply call copy.
 *************************************************************/
void DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int i, til,j;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; i < til; ++i)
		{
			idx = ( ((unsigned int)i)/SIMD_COEF_32);
			__SSE_overwrite_output_base16_to_input(input_buf2[idx].w, crypt_key[idx].c, i&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	j = i;
	for (; j < til; ++j)
	{
		unsigned char *cpo, *cpi;
		/* uint32_t *w; */
#if MD5_X2
		if (j&1)
			{cpo = input_buf2_X86[j>>MD5_X2].x2.B2; cpi = crypt_key_X86[j>>MD5_X2].x2.B2; /* w=input_buf_X86[j>>MD5_X2].x2.w2; */}
		else
#endif
			{cpo = input_buf2_X86[j>>MD5_X2].x1.B; cpi = crypt_key_X86[j>>MD5_X2].x1.B; /* w=input_buf_X86[j>>MD5_X2].x1.w; */ }
		for (i = 0; i < 16; ++i, ++cpi)
		{
			*cpo++ = dynamic_itoa16[*cpi>>4];
			*cpo++ = dynamic_itoa16[*cpi&0xF];
		}
		//MD5_swap(w,w,4);
	}
}

void DynamicFunc__overwrite_from_last_output2_to_input2_as_base16_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int i, til,j;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; i < til; ++i)
		{
			idx = ( ((unsigned int)i)/SIMD_COEF_32);
			__SSE_overwrite_output_base16_to_input(input_buf2[idx].w, crypt_key2[idx].c, i&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	j = i;
	for (; j < til; ++j)
	{
		unsigned char *cpo, *cpi;
		/* uint32_t *w; */
#if MD5_X2
		if (j&1)
			{cpo = input_buf2_X86[j>>MD5_X2].x2.B2; cpi = crypt_key2_X86[j>>MD5_X2].x2.B2; /* w=input_buf2_X86[j>>MD5_X2].x2.w2; */}
		else
#endif
			{cpo = input_buf2_X86[j>>MD5_X2].x1.B; cpi = crypt_key2_X86[j>>MD5_X2].x1.B; /* w=input_buf2_X86[j>>MD5_X2].x1.w; */ }
		for (i = 0; i < 16; ++i, ++cpi)
		{
			*cpo++ = dynamic_itoa16[*cpi>>4];
			*cpo++ = dynamic_itoa16[*cpi&0xF];
		}
		//MD5_swap(w,w,4);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * overwrites start of input2 from the output2 data using base-16
 *************************************************************/
void DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix(DYNA_OMP_PARAMS)
{
	unsigned int i, til,j;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int idx;
		for (; i < til; ++i)
		{
			idx = ( ((unsigned int)i)/SIMD_COEF_32);
			__SSE_overwrite_output_base16_to_input(input_buf2[idx].w, crypt_key2[idx].c, i&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	j=i;
	for (; j < til; ++j)
	{
		unsigned char *cpo, *cpi;
		/* uint32_t *w; */
#if MD5_X2
		if (j&1)
			{cpo = input_buf2_X86[j>>MD5_X2].x2.B2; cpi = crypt_key2_X86[j>>MD5_X2].x2.B2; /* w=input_buf_X86[j>>MD5_X2].x2.w2; */}
		else
#endif
			{cpo = input_buf2_X86[j>>MD5_X2].x1.B; cpi = crypt_key2_X86[j>>MD5_X2].x1.B; /* w=input_buf_X86[j>>MD5_X2].x1.w; */ }
		for (i = 0; i < 16; ++i, ++cpi)
		{
			*cpo++ = dynamic_itoa16[*cpi>>4];
			*cpo++ = dynamic_itoa16[*cpi&0xF];
		}
		//MD5_swap(w,w,4);
	}
}


/**************************************************************
 * DYNAMIC primitive helper function
 * This will take the data stored in the crypt_keys1 (the encrypted
 * 'first' key variable), and base-16 appends to the 2nd input
 *************************************************************/
void DynamicFunc__append_from_last_output_to_input2_as_base16(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int index=i, idx;
		for (; index < til; ++index)
		{
			unsigned int ip;
			idx = ( ((unsigned int)index)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len2[idx][index&(SIMD_COEF_32-1)];
			total_len2[idx][index&(SIMD_COEF_32-1)] += 32;
			if (!ip)
				__SSE_append_output_base16_to_input(input_buf2[idx].w, crypt_key[idx].c, index&(SIMD_COEF_32-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (i = 0; i < 16; ++i)
				{
					unsigned char v = crypt_key[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
					input_buf2[idx].c[GETPOS(ip+(i<<1), index&(SIMD_COEF_32-1))] = dynamic_itoa16[v>>4];
					input_buf2[idx].c[GETPOS(ip+(i<<1)+1, index&(SIMD_COEF_32-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf2[idx].c[GETPOS(ip+32, index&(SIMD_COEF_32-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, input_buf2[idx].w, crypt_key[idx].c, index&(SIMD_COEF_32-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, input_buf2[idx].w, crypt_key[idx].c, index&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;
#if MD5_X2
		if (i&1)
		{cpi = crypt_key_X86[i>>MD5_X2].x2.B2; cp = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]); }
		else
#endif
		{cpi = crypt_key_X86[i>>MD5_X2].x1.B; cp = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);}
		for (j = 0; j < 16; ++j)
		{
#if ARCH_ALLOWS_UNALIGNED
			*((unsigned short*)cp) = itoa16_w2[*cpi++];
			cp += 2;
#else
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
#endif
		}
		*cp = 0;
		total_len2_X86[i] += 32;
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * This will take the data stored in the crypt_keys2 (the encrypted
 * 'second' key variable), and base-16 appends to the 1st input
 *************************************************************/
void DynamicFunc__append_from_last_output2_to_input1_as_base16(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int index=i, idx;
		for (; index < til; ++index)
		{
			unsigned int ip;
			idx = ( ((unsigned int)index)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len[idx][index&(SIMD_COEF_32-1)];
			total_len[idx][index&(SIMD_COEF_32-1)] += 32;
			if (!ip)
				__SSE_append_output_base16_to_input(input_buf[idx].w, crypt_key2[idx].c, index&(SIMD_COEF_32-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (i = 0; i < 16; ++i)
				{
					unsigned char v = crypt_key2[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
					input_buf[idx].c[GETPOS(ip+(i<<1), index&(SIMD_COEF_32-1))] = dynamic_itoa16[v>>4];
					input_buf[idx].c[GETPOS(ip+(i<<1)+1, index&(SIMD_COEF_32-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf[idx].c[GETPOS(ip+32, index&(SIMD_COEF_32-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, input_buf[idx].w, crypt_key2[idx].c, index&(SIMD_COEF_32-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, input_buf[idx].w, crypt_key2[idx].c, index&(SIMD_COEF_32-1));
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;
#if MD5_X2
		if (i&1)
		{cp = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x1.B; }
		for (j = 0; j < 16; ++j)
		{
#if ARCH_ALLOWS_UNALIGNED
			*((unsigned short*)cp) = itoa16_w2[*cpi++];
			cp += 2;
#else
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
#endif
		}
		*cp = 0;
		total_len_X86[i] += 32;
	}
}

void DynamicFunc__append_from_last_output2_as_raw(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int index=i, idx;
		for (; index < til; ++index)
		{
			unsigned int ip;
			idx = ( ((unsigned int)index)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len[idx][index&(SIMD_COEF_32-1)];
			if (!ip)
			{
				uint32_t *po = input_buf[idx].w;
				uint32_t *pi = crypt_key2[idx].w;
				po += (index&(SIMD_COEF_32-1));
				pi += (index&(SIMD_COEF_32-1));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += SIMD_COEF_32;
					pi += SIMD_COEF_32;
				}
				input_buf[idx].c[GETPOS(16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf[idx].c[GETPOS(ip+i, index&(SIMD_COEF_32-1))] = crypt_key2[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
				input_buf[idx].c[GETPOS(ip+16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			total_len[idx][index&(SIMD_COEF_32-1)] += 16;
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;

#if MD5_X2
		if (i&1)
		{cp = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x1.B; }

		for (j = 0; j < 16; ++j)
			*cp++ = *cpi++;
		*cp = 0;
		total_len_X86[i] += 16;
	}
}

void DynamicFunc__append2_from_last_output2_as_raw(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int index=i, idx;
		for (; index < til; ++index)
		{
			unsigned int ip;
			idx = ( ((unsigned int)index)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len2[idx][index&(SIMD_COEF_32-1)];
			if (!ip)
			{
				uint32_t *po = input_buf2[idx].w;
				uint32_t *pi = crypt_key2[idx].w;
				po += (index&(SIMD_COEF_32-1));
				pi += (index&(SIMD_COEF_32-1));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += SIMD_COEF_32;
					pi += SIMD_COEF_32;
				}
				input_buf2[idx].c[GETPOS(16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf2[idx].c[GETPOS(ip+i, index&(SIMD_COEF_32-1))] = crypt_key2[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
				input_buf2[idx].c[GETPOS(ip+16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			total_len2[idx][index&(SIMD_COEF_32-1)] += 16;
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;

#if MD5_X2
		if (i&1)
		{cp = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x1.B; }

		for (j = 0; j < 16; ++j)
			*cp++ = *cpi++;
		*cp = 0;
		total_len2_X86[i] += 16;
	}
}

void DynamicFunc__append_from_last_output1_as_raw(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int index, idx;
		for (index = i; index < til; ++index)
		{
			unsigned int ip;
			idx = ( ((unsigned int)index)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len[idx][index&(SIMD_COEF_32-1)];
			if (!ip)
			{
				uint32_t *po = input_buf[idx].w;
				uint32_t *pi = crypt_key[idx].w;
				po += (index&(SIMD_COEF_32-1));
				pi += (index&(SIMD_COEF_32-1));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += SIMD_COEF_32;
					pi += SIMD_COEF_32;
				}
				input_buf[idx].c[GETPOS(16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf[idx].c[GETPOS(ip+i, index&(SIMD_COEF_32-1))] = crypt_key[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
				input_buf[idx].c[GETPOS(ip+16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			total_len[idx][index&(SIMD_COEF_32-1)] += 16;
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;

#if MD5_X2
		if (i&1)
		{cp = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]); cpi = crypt_key_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]); cpi = crypt_key_X86[i>>MD5_X2].x1.B; }

		for (j = 0; j < 16; ++j)
			*cp++ = *cpi++;
		*cp = 0;
		total_len_X86[i] += 16;
	}
}

void DynamicFunc__append2_from_last_output1_as_raw(DYNA_OMP_PARAMS)
{
	unsigned int i, til;
#ifdef _OPENMP
	i = first;
	til = last;
#else
	i = 0;
	til = m_count;
#endif
#ifdef SIMD_COEF_32
	if (dynamic_use_sse==1) {
		unsigned int index, idx;
		for (index = i; index < til; ++index)
		{
			unsigned int ip;
			idx = ( ((unsigned int)index)/SIMD_COEF_32);
			// This is the 'actual' work.
			ip = total_len2[idx][index&(SIMD_COEF_32-1)];
			if (!ip)
			{
				uint32_t *po = input_buf2[idx].w;
				uint32_t *pi = crypt_key[idx].w;
				po += (index&(SIMD_COEF_32-1));
				pi += (index&(SIMD_COEF_32-1));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += SIMD_COEF_32;
					pi += SIMD_COEF_32;
				}
				input_buf2[idx].c[GETPOS(16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf2[idx].c[GETPOS(ip+i, index&(SIMD_COEF_32-1))] = crypt_key[idx].c[GETPOS(i, index&(SIMD_COEF_32-1))];
				input_buf2[idx].c[GETPOS(ip+16, index&(SIMD_COEF_32-1))] = 0x80;
			}
			total_len2[idx][index&(SIMD_COEF_32-1)] += 16;
		}
		return;
	}
#endif
	for (; i < til; ++i)
	{
		unsigned int j;
		unsigned char *cp, *cpi;

#if MD5_X2
		if (i&1)
		{cp = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]); cpi = crypt_key_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]); cpi = crypt_key_X86[i>>MD5_X2].x1.B; }

		for (j = 0; j < 16; ++j)
			*cp++ = *cpi++;
		*cp = 0;
		total_len2_X86[i] += 16;
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Append salt #2 into input 1
 *************************************************************/
void DynamicFunc__append_2nd_salt(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm cursalt2, saltlen2);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Append salt #2 into input 2
 *************************************************************/
void DynamicFunc__append_2nd_salt2(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm cursalt2, saltlen2);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Append UserID into input 1
 *************************************************************/
void DynamicFunc__append_userid(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm username, usernamelen);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Append UserID into input 2
 *************************************************************/
void DynamicFunc__append_userid2(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm username, usernamelen);
}

void DynamicFunc__append_input1_from_CONST1(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[0], curdat.ConstsLen[0]);
}

void DynamicFunc__append_input1_from_CONST2(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[1], curdat.ConstsLen[1]);
}

void DynamicFunc__append_input1_from_CONST3(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[2], curdat.ConstsLen[2]);
}

void DynamicFunc__append_input1_from_CONST4(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[3], curdat.ConstsLen[3]);
}

void DynamicFunc__append_input1_from_CONST5(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[4], curdat.ConstsLen[4]);
}

void DynamicFunc__append_input1_from_CONST6(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[5], curdat.ConstsLen[5]);
}

void DynamicFunc__append_input1_from_CONST7(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[6], curdat.ConstsLen[6]);
}

void DynamicFunc__append_input1_from_CONST8(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm curdat.Consts[7], curdat.ConstsLen[7]);
}

void DynamicFunc__append_input2_from_CONST1(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[0], curdat.ConstsLen[0]);
}

void DynamicFunc__append_input2_from_CONST2(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[1], curdat.ConstsLen[1]);
}

void DynamicFunc__append_input2_from_CONST3(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[2], curdat.ConstsLen[2]);
}

void DynamicFunc__append_input2_from_CONST4(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[3], curdat.ConstsLen[3]);
}

void DynamicFunc__append_input2_from_CONST5(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[4], curdat.ConstsLen[4]);
}

void DynamicFunc__append_input2_from_CONST6(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[5], curdat.ConstsLen[5]);
}

void DynamicFunc__append_input2_from_CONST7(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[6], curdat.ConstsLen[6]);
}

void DynamicFunc__append_input2_from_CONST8(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm curdat.Consts[7], curdat.ConstsLen[7]);
}

void DynamicFunc__append_fld0(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[0], fld_lens[0]);
}

void DynamicFunc__append_fld1(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[1], fld_lens[1]);
}

void DynamicFunc__append_fld2(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[2], fld_lens[2]);
}

void DynamicFunc__append_fld3(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[3], fld_lens[3]);
}

void DynamicFunc__append_fld4(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[4], fld_lens[4]);
}

void DynamicFunc__append_fld5(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[5], fld_lens[5]);
}

void DynamicFunc__append_fld6(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[6], fld_lens[6]);
}

void DynamicFunc__append_fld7(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[7], fld_lens[7]);
}

void DynamicFunc__append_fld8(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[8], fld_lens[8]);
}

void DynamicFunc__append_fld9(DYNA_OMP_PARAMS)
{
	__append_string(DYNA_OMP_PARAMSdm flds[9], fld_lens[9]);
}

void DynamicFunc__append2_fld0(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[0], fld_lens[0]);
}

void DynamicFunc__append2_fld1(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[1], fld_lens[1]);
}

void DynamicFunc__append2_fld2(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[2], fld_lens[2]);
}

void DynamicFunc__append2_fld3(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[3], fld_lens[3]);
}

void DynamicFunc__append2_fld4(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[4], fld_lens[4]);
}

void DynamicFunc__append2_fld5(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[5], fld_lens[5]);
}

void DynamicFunc__append2_fld6(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[6], fld_lens[6]);
}

void DynamicFunc__append2_fld7(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[7], fld_lens[7]);
}

void DynamicFunc__append2_fld8(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[8], fld_lens[8]);
}

void DynamicFunc__append2_fld9(DYNA_OMP_PARAMS)
{
	__append2_string(DYNA_OMP_PARAMSdm flds[9], fld_lens[9]);
}

void DynamicFunc__SSEtoX86_switch_input1(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int i, j, k, idx, max;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += SIMD_COEF_32)
	{
		uint32_t *cpi;
		uint32_t *cpo[SIMD_COEF_32];
#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			cpo[i  ] = input_buf_X86[(j>>1)+(i>>1)].x1.w;
			cpo[i+1] = input_buf_X86[(j>>1)+(i>>1)].x2.w2;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			cpo[i] = input_buf_X86[j+i].x1.w;
#endif

		idx = j / SIMD_COEF_32;
		cpi = input_buf[idx].w;

		max = total_len_X86[j] = (total_len[idx][0]);
		for (i = 1; i < SIMD_COEF_32; i++)
			if (max < (total_len_X86[j+i] = total_len[idx][j]))
				max = total_len_X86[j+i];

		max = (max+3)>>2;
		for (k = 0; k < max; ++k) {
			for (i = 0; i < SIMD_COEF_32; i++)
				*cpo[i]++ = *cpi++;
		}

#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			input_buf_X86[(j>>1)+(i>>1)].x1.b[total_len_X86[j+i]] = 0;
			input_buf_X86[(j>>1)+(i>>1)].x2.b2[total_len_X86[j+i+1]] = 0;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			input_buf_X86[j+i].x1.b[total_len_X86[j+i]] = 0;
#endif
	}
#endif
}

void DynamicFunc__SSEtoX86_switch_input2(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int i, j, k, idx, max;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += SIMD_COEF_32)
	{
		uint32_t *cpi;
		uint32_t *cpo[SIMD_COEF_32];
#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			cpo[i  ] = input_buf2_X86[(j>>1)+(i>>1)].x1.w;
			cpo[i+1] = input_buf2_X86[(j>>1)+(i>>1)].x2.w2;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			cpo[i] = input_buf2_X86[j+i].x1.w;
#endif

		idx = j / SIMD_COEF_32;
		cpi = input_buf2[idx].w;

		max = total_len2_X86[j] = (total_len2[idx][0]);
		for (i = 1; i < SIMD_COEF_32; i++)
			if (max < (total_len2_X86[j+i] = total_len2[idx][i]))
				max = total_len2_X86[j+i];

		max = (max+3)>>2;
		for (k = 0; k < max; ++k) {
			for (i = 0; i < SIMD_COEF_32; i++)
				*cpo[i]++ = *cpi++;
		}

		// get rid of the 0x80
#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			input_buf2_X86[(j>>1)+(i>>1)].x1.b[total_len_X86[j+i]] = 0;
			input_buf2_X86[(j>>1)+(i>>1)].x2.b2[total_len_X86[j+i+1]] = 0;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			input_buf2_X86[j+i].x1.b[total_len2_X86[j+i]] = 0;
#endif
	}
#endif
}

void DynamicFunc__SSEtoX86_switch_output1(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int i, j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += SIMD_COEF_32)
	{
		uint32_t *cpi;
		uint32_t *cpo[SIMD_COEF_32];
#if MD5_X2
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			cpo[i  ] = crypt_key_X86[(j>>1)+(i>>1)].x1.w;
			cpo[i+1] = crypt_key_X86[(j>>1)+(i>>1)].x2.w2;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			cpo[i] = crypt_key_X86[j+i].x1.w;
#endif

		idx = j/SIMD_COEF_32;
		cpi = (void*)crypt_key[idx].c;
		for (k = 0; k < 4; ++k) {
			for (i = 0; i < SIMD_COEF_32; i++)
				*cpo[i]++ = *cpi++;
		}
	}
#endif
}

void DynamicFunc__SSEtoX86_switch_output2(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int i, j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += SIMD_COEF_32)
	{
		uint32_t *cpi;
		uint32_t *cpo[SIMD_COEF_32];
#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			cpo[i  ] = crypt_key2_X86[(j>>1)+(i>>1)].x1.w;
			cpo[i+1] = crypt_key2_X86[(j>>1)+(i>>1)].x2.w2;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			cpo[i] = crypt_key2_X86[j+i].x1.w;
#endif

		idx = j / SIMD_COEF_32;
		cpi = crypt_key2[idx].w;
		for (k = 0; k < 4; ++k) {
			for (i = 0; i < SIMD_COEF_32; i++)
				*cpo[i]++ = *cpi++;
		}
	}
#endif
}

void DynamicFunc__X86toSSE_switch_input1(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int j, idx, idx_mod;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;
	__nonMP_DynamicFunc__clean_input();
	for (j = 0; j < m_count; ++j) {
		idx = j/SIMD_COEF_32;
		idx_mod = j&(SIMD_COEF_32-1);
		total_len[idx][idx_mod] += total_len_X86[j];
#if (MD5_X2)
		if (j & 1)
			__SSE_append_string_to_input(input_buf[idx].c,idx_mod,input_buf_X86[j>>1].x2.B2,total_len_X86[j],0,1);
		else
#endif
		__SSE_append_string_to_input(input_buf[idx].c,idx_mod,input_buf_X86[j>>MD5_X2].x1.B,total_len_X86[j],0,1);
	}
#endif
}

void DynamicFunc__X86toSSE_switch_input2(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int j, idx, idx_mod;
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;
	__nonMP_DynamicFunc__clean_input2();
	for (j = 0; j < m_count; ++j) {
		idx = j/SIMD_COEF_32;
		idx_mod = j&(SIMD_COEF_32-1);
		total_len2[idx][idx_mod] += total_len2_X86[j];
#if (MD5_X2)
		if (j & 1)
			__SSE_append_string_to_input(input_buf2[idx].c,idx_mod,input_buf2_X86[j>>1].x2.B2,total_len2_X86[j],0,1);
		else
#endif
		__SSE_append_string_to_input(input_buf2[idx].c,idx_mod,input_buf2_X86[j>>MD5_X2].x1.B,total_len2_X86[j],0,1);
	}
#endif
}

void DynamicFunc__X86toSSE_switch_output1(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int i, j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;

	for (j = 0; j < m_count; j += SIMD_COEF_32)
	{
		uint32_t *cpi;
		uint32_t *cpo[SIMD_COEF_32];
#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			cpo[i  ] = crypt_key_X86[(j>>1)+(i>>1)].x1.w;
			cpo[i+1] = crypt_key_X86[(j>>1)+(i>>1)].x2.w2;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			cpo[i] = crypt_key_X86[j+i].x1.w;
#endif

		idx = j / SIMD_COEF_32;
		cpi = (void*)crypt_key[idx].c;
		for (k = 0; k < 4; ++k) {
			for (i = 0; i < SIMD_COEF_32; i++)
				*cpi++ = *cpo[i]++;
		}
	}
#endif
}

void DynamicFunc__X86toSSE_switch_output2(DYNA_OMP_PARAMS)
{
#ifdef SIMD_COEF_32
	unsigned int i, j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;

	for (j = 0; j < m_count; j += SIMD_COEF_32)
	{
		uint32_t *cpi;
		uint32_t *cpo[SIMD_COEF_32];
#if (MD5_X2)
		for (i = 0; i < SIMD_COEF_32; i += 2) {
			cpo[i  ] = crypt_key2_X86[(j>>1)+(i>>1)].x1.w;
			cpo[i+1] = crypt_key2_X86[(j>>1)+(i>>1)].x2.w2;
		}
#else
		for (i = 0; i < SIMD_COEF_32; i++)
			cpo[i] = crypt_key2_X86[j+i].x1.w;
#endif

		idx = j / SIMD_COEF_32;
		cpi = crypt_key2[idx].w;
		for (k = 0; k < 4; ++k) {
			for (i = 0; i < SIMD_COEF_32; i++)
				*cpi++ = *cpo[i]++;
		}
	}
#endif
}

// This function, simply 'switches' back to SSE  It does NOT copy any data from X86 to SSE
void DynamicFunc__ToSSE(DYNA_OMP_PARAMS)
{
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;
}

// This function, simply 'switches' to X86  It does NOT copy any data from SSE to X86
void DynamicFunc__ToX86(DYNA_OMP_PARAMS)
{
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;
}

void DynamicFunc__base16_convert_locase(DYNA_OMP_PARAMS)
{
	dynamic_itoa16 = itoa16;
	itoa16_w2=itoa16_w2_l;
}

void DynamicFunc__base16_convert_upcase(DYNA_OMP_PARAMS)
{
	dynamic_itoa16 = itoa16u;
	itoa16_w2=itoa16_w2_u;
}

/**************************************************************
 * DEPRICATED functions. These are the older pseudo functions
 * which we now have flags for.  We keep them, so that we can
 * add the proper flags, even if the user is running an older
 * script.
 *************************************************************/
void DynamicFunc__InitialLoadKeysToInput(DYNA_OMP_PARAMS) {}
void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2(DYNA_OMP_PARAMS) {}
void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1(DYNA_OMP_PARAMS) {}
void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32(DYNA_OMP_PARAMS) {}


/**************************************************************
 **************************************************************
 **************************************************************
 **************************************************************
 * DYNAMIC primitive helper function
 * This is the END of the primitives.
 **************************************************************
 **************************************************************
 **************************************************************
 *************************************************************/

static DYNAMIC_primitive_funcp *ConvertFuncs(DYNAMIC_primitive_funcp p, unsigned int *count)
{
	static DYNAMIC_primitive_funcp fncs[20];
	*count = 0;
	if (p==DynamicFunc__InitialLoadKeysToInput ||
		p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2 ||
		p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1 ||
		p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32)
		return fncs; // ignore these

#ifndef SIMD_COEF_32
	if (p==DynamicFunc__SSEtoX86_switch_input1  || p==DynamicFunc__SSEtoX86_switch_input2 ||
		p==DynamicFunc__SSEtoX86_switch_output1 || p==DynamicFunc__SSEtoX86_switch_output2 ||
		p==DynamicFunc__X86toSSE_switch_input1  || p==DynamicFunc__X86toSSE_switch_input2 ||
		p==DynamicFunc__X86toSSE_switch_output1 || p==DynamicFunc__X86toSSE_switch_output2 ||
		p==DynamicFunc__ToSSE                   || p==DynamicFunc__ToX86)
		return fncs; // we ignore these functions 100% in x86 mode.
#endif
//	if (p==DynamicFunc__append_input2_from_CONST1) {
//		fncs[0] = DynamicFunc__set_input2;
//		fncs[1] = DynamicFunc__set_CONST1;
//		fncs[2] = DynamicFunc__append_CONST;
//		*count = 3;
//	}

	/*  LOOK INTO THIS!!!!! This may not be valid, now that SHA1 is handled 100% outside of the SSE2 code.
	    But I am not sure just WTF this is supposed to do anyway, since not LE should be using CTX only??? */
#if !ARCH_LITTLE_ENDIAN
	if (/*p==DynamicFunc__SHA1_crypt_input1_append_input2_base16    ||*/ p==DynamicFunc__SHA1_crypt_input1_append_input2    ||
		/*p==DynamicFunc__SHA1_crypt_input2_append_input1_base16    ||*/ p==DynamicFunc__SHA1_crypt_input2_append_input1    ||
		/*p==DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16 ||*/ p==DynamicFunc__SHA1_crypt_input1_overwrite_input1 ||
		/*p==DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16 ||*/ p==DynamicFunc__SHA1_crypt_input2_overwrite_input2 ||
		/*p==DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16 ||*/ p==DynamicFunc__SHA1_crypt_input1_overwrite_input2 ||
		/*p==DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16 ||*/ p==DynamicFunc__SHA1_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA1_crypt_input1_to_output1_FINAL        ||
		p==DynamicFunc__SHA1_crypt_input2_to_output1_FINAL)
		curdat.force_md5_ctx = 0;
#endif

	*count = 1;
	fncs[0] = p;
	return fncs;
}

#ifdef _OPENMP
static int isBadOMPFunc(DYNAMIC_primitive_funcp p)
{
	// If ANY of these functions are seen, we can NOT use OMP for this single format.
#if SIMD_COEF_32
	if (p==DynamicFunc__SSEtoX86_switch_input1   || p==DynamicFunc__SSEtoX86_switch_input2   ||
		p==DynamicFunc__SSEtoX86_switch_output1  || p==DynamicFunc__SSEtoX86_switch_output2  ||
		p==DynamicFunc__X86toSSE_switch_input1   || p==DynamicFunc__X86toSSE_switch_input2   ||
		p==DynamicFunc__X86toSSE_switch_output1  || p==DynamicFunc__X86toSSE_switch_output2  ||
		p==DynamicFunc__ToSSE                    || p==DynamicFunc__ToX86)
		return 1;
#endif
	if (p==DynamicFunc__base16_convert_locase    || p==DynamicFunc__base16_convert_upcase)
		return 1;
	return 0;
}
#endif

#define RETURN_TRUE_IF_BIG_FUNC(H) if (p==DynamicFunc__##H##_crypt_input1_append_input2 || \
		p==DynamicFunc__##H##_crypt_input2_append_input1    || \
		p==DynamicFunc__##H##_crypt_input1_overwrite_input1 || \
		p==DynamicFunc__##H##_crypt_input2_overwrite_input2 || \
		p==DynamicFunc__##H##_crypt_input1_overwrite_input2 || \
		p==DynamicFunc__##H##_crypt_input2_overwrite_input1 || \
		p==DynamicFunc__##H##_crypt_input1_to_output1_FINAL || \
		p==DynamicFunc__##H##_crypt_input2_to_output1_FINAL) \
		return 1

static int isMD4Func(DYNAMIC_primitive_funcp p)
{
	// handle flats
	RETURN_TRUE_IF_BIG_FUNC(MD4);
	// handle older mmx_coef variants
	if (p==DynamicFunc__crypt_md4    || p==DynamicFunc__crypt_md4_in1_to_out2    ||
		p==DynamicFunc__crypt2_md4   || p==DynamicFunc__crypt_md4_in2_to_out1)
		return 1;
	return 0;
}

#ifdef _OPENMP
// Only used in OMP code, to compute LCM granularity. So we #ifdef it out to avoid compiler warnings.
#ifdef SIMD_COEF_32
// otherwise unused
static int isMD5Func(DYNAMIC_primitive_funcp p)
{
	// handle flats
	RETURN_TRUE_IF_BIG_FUNC(MD5);
	// handle older mmx_coef variants
	if (p==DynamicFunc__crypt_md5                || p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1      ||
		p==DynamicFunc__crypt_md5_in1_to_out2    || p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2                       ||
		p==DynamicFunc__crypt_md5_to_input_raw   || p==DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen                   ||
		p==DynamicFunc__crypt_md5_in2_to_out1    || p==DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE ||
		p==DynamicFunc__crypt2_md5               || p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32)
		return 1;
	return 0;
}
#endif
#endif

static int isSHA1Func(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(SHA1);
	return 0;
}
static int isSHA2_256Func(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(SHA224); RETURN_TRUE_IF_BIG_FUNC(SHA256);
	return 0;
}
static int isSHA2_512Func(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(SHA384); RETURN_TRUE_IF_BIG_FUNC(SHA512);
	return 0;
}
static int isGOSTFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(GOST);
	return 0;
}
static int isTigerFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(Tiger);
	return 0;
}
static int isWHIRLFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(WHIRLPOOL);
	return 0;
}
static int isRIPEMDFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(RIPEMD128); RETURN_TRUE_IF_BIG_FUNC(RIPEMD160);
	RETURN_TRUE_IF_BIG_FUNC(RIPEMD256); RETURN_TRUE_IF_BIG_FUNC(RIPEMD320);
	return 0;
}
static int isHAVALFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(HAVAL128_3); RETURN_TRUE_IF_BIG_FUNC(HAVAL128_4); RETURN_TRUE_IF_BIG_FUNC(HAVAL128_5);
	RETURN_TRUE_IF_BIG_FUNC(HAVAL160_3); RETURN_TRUE_IF_BIG_FUNC(HAVAL160_4); RETURN_TRUE_IF_BIG_FUNC(HAVAL160_5);
	RETURN_TRUE_IF_BIG_FUNC(HAVAL192_3); RETURN_TRUE_IF_BIG_FUNC(HAVAL192_4); RETURN_TRUE_IF_BIG_FUNC(HAVAL192_5);
	RETURN_TRUE_IF_BIG_FUNC(HAVAL224_3); RETURN_TRUE_IF_BIG_FUNC(HAVAL224_4); RETURN_TRUE_IF_BIG_FUNC(HAVAL224_5);
	RETURN_TRUE_IF_BIG_FUNC(HAVAL256_3); RETURN_TRUE_IF_BIG_FUNC(HAVAL256_4); RETURN_TRUE_IF_BIG_FUNC(HAVAL256_5);
	return 0;
}
static int isMD2Func(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(MD2);
	return 0;
}
static int isPANAMAFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(PANAMA);
	return 0;
}
static int isSKEINFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(SKEIN224); RETURN_TRUE_IF_BIG_FUNC(SKEIN256);
	RETURN_TRUE_IF_BIG_FUNC(SKEIN384); RETURN_TRUE_IF_BIG_FUNC(SKEIN512);
	return 0;
}
static int isKECCAKFunc(DYNAMIC_primitive_funcp p) {
	RETURN_TRUE_IF_BIG_FUNC(SHA3_224); RETURN_TRUE_IF_BIG_FUNC(SHA3_256); RETURN_TRUE_IF_BIG_FUNC(SHA3_384);
	RETURN_TRUE_IF_BIG_FUNC(SHA3_512);
	RETURN_TRUE_IF_BIG_FUNC(KECCAK_224); RETURN_TRUE_IF_BIG_FUNC(KECCAK_256); RETURN_TRUE_IF_BIG_FUNC(KECCAK_384);
	RETURN_TRUE_IF_BIG_FUNC(KECCAK_512);
	return 0;
}
// LARGE_HASH_EDIT_POINT  (Add a new IsXXXFunc() type function)

static int isLargeHashFinalFunc(DYNAMIC_primitive_funcp p)
{
#undef IF
#define IF(H) p==DynamicFunc__##H##_crypt_input1_to_output1_FINAL||p==DynamicFunc__##H##_crypt_input2_to_output1_FINAL

	if (IF(SHA1)||IF(SHA224)||IF(SHA256)||IF(SHA384)||IF(SHA512)||IF(GOST)||IF(WHIRLPOOL)||IF(Tiger)||IF(RIPEMD128)||
		IF(RIPEMD160)||IF(RIPEMD256)||IF(RIPEMD320)||
		IF(HAVAL128_3)||IF(HAVAL128_4)||IF(HAVAL128_5)||IF(HAVAL160_3)||IF(HAVAL160_4)||IF(HAVAL160_5)||
		IF(HAVAL192_3)||IF(HAVAL192_4)||IF(HAVAL192_5)||IF(HAVAL224_3)||IF(HAVAL224_4)||IF(HAVAL224_5)||
		IF(HAVAL256_3)||IF(HAVAL256_4)||IF(HAVAL256_5)||IF(MD2)||IF(PANAMA)||IF(SKEIN224)||IF(SKEIN256)||
		IF(SKEIN384)||IF(SKEIN512)||IF(SHA3_224)||IF(SHA3_256)||IF(SHA3_384)||IF(SHA3_512)||
		IF(KECCAK_224)||IF(KECCAK_256)||IF(KECCAK_384)||IF(KECCAK_512))
		// LARGE_HASH_EDIT_POINT
		return 1;
	return 0;
}

#ifdef _OPENMP
#ifdef SIMD_COEF_32
// Simple euclid algorithm for GCD
static int GCD (int a, int b)
{
	while (b) {
		int t = b;
		b = a % b;
		a = t;
	}
	return a;
}

// simple algorithm for LCM is (a*b)/GCD(a,b)
static int LCM(int a, int b)
{
	a/=GCD(a,b);
	return a*b;
}
#endif

static void dyna_setupOMP(DYNAMIC_Setup *Setup, struct fmt_main *pFmt)
{
	unsigned int i;

#ifndef SIMD_COEF_32
	curdat.omp_granularity=OMP_INC;
#else
	if ((curdat.pSetup->flags& MGF_NOTSSE2Safe) == MGF_NOTSSE2Safe)
		curdat.omp_granularity=OMP_INC;
	else {
		curdat.omp_granularity = 1;
		for (i=0; Setup->pFuncs[i]; ++i) {
			if (isMD5Func(Setup->pFuncs[i]))
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_PARA_MD5*SIMD_COEF_32);
			else if (isMD4Func(Setup->pFuncs[i]))
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_PARA_MD4*SIMD_COEF_32);
			else if (isSHA1Func(Setup->pFuncs[i]))
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_PARA_SHA1*SIMD_COEF_32);
			else if (isSHA2_256Func(Setup->pFuncs[i]))
#if SIMD_COEF_32
	#if SIMD_PARA_SHA256
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_PARA_SHA256*SIMD_COEF_32);
	#else
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_COEF_32);
	#endif
#else
				curdat.omp_granularity=LCM(curdat.omp_granularity, OMP_INC);
#endif
			else if (isSHA2_512Func(Setup->pFuncs[i]))
#if SIMD_COEF_64
	#if SIMD_PARA_SHA512
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_PARA_SHA512*SIMD_COEF_64);
	#else
				curdat.omp_granularity = LCM(curdat.omp_granularity, SIMD_COEF_64);
	#endif
#else
				curdat.omp_granularity=LCM(curdat.omp_granularity, OMP_INC);
#endif
		}
	}
#endif
	for (i=0; Setup->pFuncs[i]; ++i) {
		if (isBadOMPFunc(Setup->pFuncs[i]))
			pFmt->params.flags &= (~(FMT_OMP|FMT_OMP_BAD));
	}
	if ((pFmt->params.flags&FMT_OMP)==FMT_OMP && (curdat.pSetup->startFlags&MGF_POOR_OMP)==MGF_POOR_OMP)
		pFmt->params.flags |= FMT_OMP_BAD;
}
#endif

int dynamic_SETUP(DYNAMIC_Setup *Setup, struct fmt_main *pFmt)
{
	unsigned int i, j, cnt, cnt2, x;
	DYNAMIC_primitive_funcp *pFuncs;

	if (Setup->flags & MGF_ColonNOTValid)
	{
		extern struct options_main options;
		if (options.loader.field_sep_char == ':')
		{
			return 0;
		}
	}

	// Deal with depricated 1st functions.  Convert them to proper 'flags'
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeysToInput)
		Setup->startFlags |= MGF_KEYS_INPUT;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2)
		Setup->startFlags |= MGF_KEYS_CRYPT_IN2;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1)
		Setup->startFlags |= MGF_KEYS_BASE16_IN1;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32)
		Setup->startFlags |= MGF_KEYS_BASE16_IN1_Offset32;

	curdat.dynamic_40_byte_input = ((Setup->startFlags&MGF_INPUT_20_BYTE)==MGF_INPUT_20_BYTE) ? 1 : 0;
	curdat.dynamic_48_byte_input = ((Setup->startFlags&MGF_INPUT_24_BYTE)==MGF_INPUT_24_BYTE) ? 1 : 0;
	curdat.dynamic_64_byte_input = ((Setup->startFlags&MGF_INPUT_32_BYTE)==MGF_INPUT_32_BYTE) ? 1 : 0;
	curdat.dynamic_56_byte_input = ((Setup->startFlags&MGF_INPUT_28_BYTE)==MGF_INPUT_28_BYTE) ? 1 : 0;
	curdat.dynamic_80_byte_input = ((Setup->startFlags&MGF_INPUT_40_BYTE)==MGF_INPUT_40_BYTE) ? 1 : 0;
	curdat.dynamic_96_byte_input = ((Setup->startFlags&MGF_INPUT_48_BYTE)==MGF_INPUT_48_BYTE) ? 1 : 0;
	curdat.dynamic_128_byte_input= ((Setup->startFlags&MGF_INPUT_64_BYTE)==MGF_INPUT_64_BYTE) ? 1 : 0;

	curdat.FldMask = 0;
	curdat.b2Salts               = ((Setup->flags&MGF_SALTED2)==MGF_SALTED2) ? 1 : 0;
	curdat.dynamic_base16_upcase = ((Setup->flags&MGF_BASE_16_OUTPUT_UPCASE)==MGF_BASE_16_OUTPUT_UPCASE) ? 1 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD0)==MGF_FLD0) ? MGF_FLD0 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD1)==MGF_FLD1) ? MGF_FLD1 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD2)==MGF_FLD2) ? MGF_FLD2 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD3)==MGF_FLD3) ? MGF_FLD3 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD4)==MGF_FLD4) ? MGF_FLD4 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD5)==MGF_FLD5) ? MGF_FLD5 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD6)==MGF_FLD6) ? MGF_FLD6 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD7)==MGF_FLD7) ? MGF_FLD7 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD8)==MGF_FLD8) ? MGF_FLD8 : 0;
	curdat.FldMask              |= ((Setup->flags&MGF_FLD9)==MGF_FLD9) ? MGF_FLD9 : 0;

	curdat.dynamic_base64_inout = 0;
	curdat.dynamic_salt_as_hex = 0;
	curdat.dynamic_salt_as_hex_format_type = 0;
	curdat.force_md5_ctx = 0;
	curdat.nUserName = 0;
	curdat.nPassCase = 1;
	curdat.md5_startup_in_x86 = curdat.dynamic_use_sse = 0;  // if 0, then never use SSE2
	curdat.init = 0;
	curdat.pSetup = Setup;
	pFmt->methods.binary = get_binary;
	pFmt->methods.cmp_all=cmp_all;
	pFmt->methods.cmp_one=cmp_one;
	pFmt->methods.source=fmt_default_source;
	pFmt->methods.salt = get_salt;
	pFmt->methods.done = done;
	pFmt->methods.set_salt = set_salt;
	pFmt->methods.salt_hash = salt_hash;
	//pFmt->params.format_name = str_alloc_copy(Setup->szFORMAT_NAME);
	pFmt->params.format_name = "";
	pFmt->params.benchmark_length = BENCHMARK_LENGTH;	// If unsalted, we or with 0x100 later
	pFmt->params.salt_size = 0;
	curdat.using_flat_buffers_sse2_ok = 0;	// used to distingish MGF_NOTSSE2Safe from MGF_FLAT_BUFFERS
	if ((Setup->flags & MGF_FLAT_BUFFERS) == MGF_FLAT_BUFFERS)
		curdat.using_flat_buffers_sse2_ok = 1;
#ifdef SIMD_COEF_32
	curdat.dynamic_use_sse = 1;  // if 1, then we are in SSE2 mode (but can switch out)
	if ((Setup->flags & MGF_NOTSSE2Safe) == MGF_NOTSSE2Safe) {
		curdat.dynamic_use_sse = 0;  // Do not use SSE code at all.
	} else if ((Setup->flags & MGF_FLAT_BUFFERS) == MGF_FLAT_BUFFERS) {
		curdat.dynamic_use_sse = 0; // uses flat buffers but will use SSE code (large formats use the flat buffers, and the SSE2 code 'mixes' them).
		curdat.using_flat_buffers_sse2_ok = 1;
	} else if ((Setup->flags & MGF_StartInX86Mode) == MGF_StartInX86Mode) {
		curdat.dynamic_use_sse = 2;  // if 2, then we are in SSE2 mode, but currently using X86 (and can switch back to SSE2).
		curdat.md5_startup_in_x86 = 1;
	}
	if (curdat.dynamic_use_sse || curdat.using_flat_buffers_sse2_ok) {
		pFmt->params.max_keys_per_crypt = MAX_KEYS_PER_CRYPT;
		pFmt->params.algorithm_name = ALGORITHM_NAME;
	} else {
		pFmt->params.max_keys_per_crypt = MAX_KEYS_PER_CRYPT_X86;
		pFmt->params.algorithm_name = ALGORITHM_NAME_X86;
	}
#else
	pFmt->params.max_keys_per_crypt = MAX_KEYS_PER_CRYPT_X86;
	pFmt->params.algorithm_name = ALGORITHM_NAME_X86;
#endif
	dynamic_use_sse = curdat.dynamic_use_sse;

	// Ok, set the new 'constants' data
	memset(curdat.Consts, 0, sizeof(curdat.Consts));
	memset(curdat.ConstsLen, 0, sizeof(curdat.ConstsLen));
	for (curdat.nConsts = 0; curdat.nConsts < 8; ++curdat.nConsts)
	{
		if (Setup->pConstants[curdat.nConsts].Const == NULL)
			break;
		//curdat.Consts[curdat.nConsts] = (unsigned char*)str_alloc_copy(Setup->pConstants[curdat.nConsts].Const);
		//curdat.ConstsLen[curdat.nConsts] = strlen(Setup->pConstants[curdat.nConsts].Const);
		// we really do not 'have' to null terminate, but do just to be on the 'safe' side.
		curdat.Consts[curdat.nConsts] = mem_alloc_tiny(Setup->pConstants[curdat.nConsts].len+1, MEM_ALIGN_NONE);
		memcpy(curdat.Consts[curdat.nConsts], Setup->pConstants[curdat.nConsts].Const, Setup->pConstants[curdat.nConsts].len);
		curdat.Consts[curdat.nConsts][Setup->pConstants[curdat.nConsts].len] = 0;
		curdat.ConstsLen[curdat.nConsts] = Setup->pConstants[curdat.nConsts].len;
	}

	if ( (Setup->flags & MGF_INPBASE64) == MGF_INPBASE64)
	{
		curdat.dynamic_base64_inout = 1;
		pFmt->methods.binary = binary_b64;
	}
	if ( (Setup->flags & MGF_INPBASE64m) == MGF_INPBASE64m)
	{
		curdat.dynamic_base64_inout = 3;
		pFmt->methods.binary = binary_b64m;
	}
	if ( (Setup->flags & MGF_INPBASE64b) == MGF_INPBASE64b)
	{
		curdat.dynamic_base64_inout = 5;
		pFmt->methods.binary = binary_b64b;
	}
	if ( (Setup->flags & MGF_INPBASE64_4x6) == MGF_INPBASE64_4x6)
	{
		curdat.dynamic_base64_inout = 2;
		pFmt->methods.binary = binary_b64_4x6;
		pFmt->methods.cmp_all = cmp_all_64_4x6;
		pFmt->methods.cmp_one = cmp_one_64_4x6;

#if !ARCH_LITTLE_ENDIAN
		pFmt->methods.binary_hash[0] = binary_hash_0_64x4;
		pFmt->methods.binary_hash[1] = binary_hash_1_64x4;
		pFmt->methods.binary_hash[2] = binary_hash_2_64x4;
		pFmt->methods.binary_hash[3] = binary_hash_3_64x4;
		pFmt->methods.binary_hash[4] = binary_hash_4_64x4;
		pFmt->methods.binary_hash[5] = binary_hash_5_64x4;
		pFmt->methods.get_hash[0] = get_hash_0_64x4;
		pFmt->methods.get_hash[1] = get_hash_1_64x4;
		pFmt->methods.get_hash[2] = get_hash_2_64x4;
		pFmt->methods.get_hash[3] = get_hash_3_64x4;
		pFmt->methods.get_hash[4] = get_hash_4_64x4;
		pFmt->methods.get_hash[5] = get_hash_5_64x4;
#endif
		// Not enough bits in a single WORD
		if (PASSWORD_HASH_SIZE_6 >= 0x1000000) {
			pFmt->methods.binary_hash[6] = NULL;
			pFmt->methods.get_hash[6] = NULL;
		}
		if (PASSWORD_HASH_SIZE_5 >= 0x1000000) {
			pFmt->methods.binary_hash[5] = NULL;
			pFmt->methods.get_hash[5] = NULL;
		}
		if (PASSWORD_HASH_SIZE_4 >= 0x1000000) {
			pFmt->methods.binary_hash[4] = NULL;
			pFmt->methods.get_hash[4] = NULL;
		}
		if (PASSWORD_HASH_SIZE_3 >= 0x1000000) {
			pFmt->methods.binary_hash[3] = NULL;
			pFmt->methods.get_hash[3] = NULL;
		}

	}
//	printf("%.13s",Setup->szFORMAT_NAME);
	if ( (Setup->flags & (MGF_INPBASE64|MGF_INPBASE64_4x6|MGF_INPBASE64a|MGF_INPBASE64m|MGF_INPBASE64b)) == 0)  {
		pFmt->params.flags |= FMT_SPLIT_UNIFIES_CASE;
//		printf("  Setting FMT_SPLIT_UNIFIES_CASE");
		if (pFmt->methods.split == split) {
			pFmt->methods.split = split_UC;
//			printf("  split set to split_UC()\n");
		}
	}
//	else printf("  split set to split()\n");
	if (Setup->flags & MGF_UTF8)
		pFmt->params.flags |= FMT_ENC;
	if (Setup->flags & MGF_INPBASE64a) {
		curdat.dynamic_base64_inout = 1;
		pFmt->methods.binary = binary_b64a;
	}

	if ( (Setup->flags & MGF_USERNAME) == MGF_USERNAME)
		curdat.nUserName = 1;
	if ( (Setup->flags & MGF_USERNAME_UPCASE) == MGF_USERNAME_UPCASE)
		curdat.nUserName = 2;
	if ( (Setup->flags & MGF_USERNAME_LOCASE) == MGF_USERNAME_LOCASE)
		curdat.nUserName = 3;

	// Ok, what 'flag' in the format struct, do we clear???
	if ( (Setup->flags & MGF_PASSWORD_UPCASE) == MGF_PASSWORD_UPCASE) {
		curdat.nPassCase = 2;
		pFmt->params.flags &= (~FMT_CASE);
	}
	if ( (Setup->flags & MGF_PASSWORD_LOCASE) == MGF_PASSWORD_LOCASE) {
		curdat.nPassCase = 3;
		pFmt->params.flags &= (~FMT_CASE);
	}

	if ( (Setup->flags & MGF_SALT_AS_HEX) == MGF_SALT_AS_HEX) {
		curdat.dynamic_salt_as_hex = 1;
		curdat.dynamic_salt_as_hex_format_type = Setup->flags >> 56;
	}
	if ( (Setup->flags & MGF_SALT_AS_HEX_TO_SALT2) == MGF_SALT_AS_HEX_TO_SALT2) {
		curdat.dynamic_salt_as_hex = 2;
		if (curdat.b2Salts)
			return !fprintf(stderr, "Error invalid format %s: MGF_SALT_AS_HEX_TO_SALT2 and MGF_SALTED2 are not valid to use in same format\n", Setup->szFORMAT_NAME);
		curdat.b2Salts = 2;
	}
	if ( (Setup->flags & MGF_SALT_UNICODE_B4_CRYPT) == MGF_SALT_UNICODE_B4_CRYPT && curdat.dynamic_salt_as_hex)
		curdat.dynamic_salt_as_hex |= 0x100;

	if ( (Setup->flags & MGF_SALTED) == 0)
	{
		curdat.dynamic_FIXED_SALT_SIZE = 0;
		pFmt->params.benchmark_length |= 0x100;
		pFmt->params.salt_size = 0;
	}
	else
	{
		pFmt->params.salt_size = sizeof(void *);
		if (Setup->SaltLen > 0)
			curdat.dynamic_FIXED_SALT_SIZE = Setup->SaltLen;
		else
		{
			// says we have a salt, but NOT a fixed sized one that we 'know' about.
			// if the SaltLen is -1, then there is NO constraints. If the SaltLen
			// is -12 (or any other neg number other than -1), then there is no
			// fixed salt length, but the 'max' salt size is -SaltLen.  So, -12
			// means any salt from 1 to 12 is 'valid'.
			if (Setup->SaltLen > -2)
				curdat.dynamic_FIXED_SALT_SIZE = -1;
			else {
				curdat.dynamic_FIXED_SALT_SIZE = Setup->SaltLen;
#if !defined (SIMD_COEF_32)
				// for non-sse, we limit ourselves to 110 bytes, not 55.  So, we can add 55 to this value
				curdat.dynamic_FIXED_SALT_SIZE -= 55;
#endif
			}
		}
	}

	if (Setup->MaxInputLen)
		pFmt->params.plaintext_length = Setup->MaxInputLen;
	else {
		if ( ((Setup->flags&MGF_FLAT_BUFFERS)==MGF_FLAT_BUFFERS) || ((Setup->flags&MGF_NOTSSE2Safe)==MGF_NOTSSE2Safe)) {
			pFmt->params.plaintext_length = 110 - abs(Setup->SaltLen);
			if (pFmt->params.plaintext_length < 32)
				pFmt->params.plaintext_length = 32;
		} else {
			pFmt->params.plaintext_length = 55 - abs(Setup->SaltLen);
			if (pFmt->params.plaintext_length < 1) {
				pFmt->params.plaintext_length = 1;
				fprintf(stderr, "\nError, for format %s, MMX build, is not valid due to TOO long of a SaltLength\n", Setup->szFORMAT_NAME);
			}
		}
	}
#ifndef SIMD_COEF_32
	if (Setup->MaxInputLenX86) {
		pFmt->params.plaintext_length = Setup->MaxInputLenX86;
	} else {
		if (Setup->SaltLenX86)
			pFmt->params.plaintext_length = 110 - abs(Setup->SaltLenX86);
		else
			pFmt->params.plaintext_length = 110 - abs(Setup->SaltLen);
		if (pFmt->params.plaintext_length < 32)
			pFmt->params.plaintext_length = 32;
	}
#endif

	curdat.store_keys_in_input = !!(Setup->startFlags&MGF_KEYS_INPUT );
	curdat.input2_set_len32 = !!(Setup->startFlags&MGF_SET_INP2LEN32);

	if (Setup->startFlags&MGF_SOURCE) {
		if      (Setup->startFlags&MGF_INPUT_20_BYTE) pFmt->methods.source = source_20_hex;
		else if (Setup->startFlags&MGF_INPUT_28_BYTE) pFmt->methods.source = source_28_hex;
		else if (Setup->startFlags&MGF_INPUT_32_BYTE) pFmt->methods.source = source_32_hex;
		else if (Setup->startFlags&MGF_INPUT_40_BYTE) pFmt->methods.source = source_40_hex;
		else if (Setup->startFlags&MGF_INPUT_48_BYTE) pFmt->methods.source = source_48_hex;
		else if (Setup->startFlags&MGF_INPUT_64_BYTE) pFmt->methods.source = source_64_hex;
		else                                          pFmt->methods.source = source;
	}

	if (!curdat.store_keys_in_input && Setup->startFlags&MGF_KEYS_INPUT_BE_SAFE)
		curdat.store_keys_in_input = 3;

	curdat.store_keys_in_input_unicode_convert = !!(Setup->startFlags&MGF_KEYS_UNICODE_B4_CRYPT);
	if (curdat.store_keys_in_input_unicode_convert && curdat.store_keys_in_input)
		return !fprintf(stderr, "Error invalid format %s: Using MGF_KEYS_INPUT and MGF_KEYS_UNICODE_B4_CRYPT in same format is NOT valid\n", Setup->szFORMAT_NAME);

	curdat.store_keys_normal_but_precompute_hash_to_output2 = !!(Setup->startFlags&MGF_KEYS_CRYPT_IN2);

	curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1 = !!(Setup->startFlags&MGF_KEYS_BASE16_IN1);

	if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1)
		curdat.store_keys_normal_but_precompute_hash_to_output2 = 1;

#define IF_CDOFF32(F,L) if (!curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX) \
	curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX = \
		(!!((Setup->startFlags&MGF_KEYS_BASE16_IN1_Offset_TYPE)==MGF_KEYS_BASE16_IN1_Offset_ ## F))*L

	curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX = 0;
	IF_CDOFF32(MD5,32); IF_CDOFF32(MD4,32); IF_CDOFF32(SHA1,40); IF_CDOFF32(SHA224,56);
	IF_CDOFF32(SHA256,64); IF_CDOFF32(SHA384,96); IF_CDOFF32(SHA512,128); IF_CDOFF32(GOST,64);
	IF_CDOFF32(WHIRLPOOL,128); IF_CDOFF32(Tiger,48); IF_CDOFF32(RIPEMD128,32); IF_CDOFF32(RIPEMD160,40);
	IF_CDOFF32(RIPEMD256,64); IF_CDOFF32(RIPEMD320,80); IF_CDOFF32(MD2,32); IF_CDOFF32(PANAMA,64);
	IF_CDOFF32(HAVAL128_3,32); IF_CDOFF32(HAVAL160_3,40); IF_CDOFF32(HAVAL192_3,48); IF_CDOFF32(HAVAL224_3,56); IF_CDOFF32(HAVAL256_3,64);
	IF_CDOFF32(HAVAL128_4,32); IF_CDOFF32(HAVAL160_4,40); IF_CDOFF32(HAVAL192_4,48); IF_CDOFF32(HAVAL224_4,56); IF_CDOFF32(HAVAL256_4,64);
	IF_CDOFF32(HAVAL128_5,32); IF_CDOFF32(HAVAL160_5,40); IF_CDOFF32(HAVAL192_5,48); IF_CDOFF32(HAVAL224_5,56); IF_CDOFF32(HAVAL256_5,64);
	IF_CDOFF32(SKEIN224,56); IF_CDOFF32(SKEIN256,64); IF_CDOFF32(SKEIN384,96); IF_CDOFF32(SKEIN512,128);
	IF_CDOFF32(SHA3_224,56); IF_CDOFF32(SHA3_256,64); IF_CDOFF32(SHA3_384,96); IF_CDOFF32(SHA3_512,128);
	IF_CDOFF32(KECCAK_224,56); IF_CDOFF32(KECCAK_256,64); IF_CDOFF32(KECCAK_384,96); IF_CDOFF32(KECCAK_512,128);
	// LARGE_HASH_EDIT_POINT

	if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX)
	{
		curdat.store_keys_normal_but_precompute_hash_to_output2 = 1;
	}
	curdat.store_keys_normal_but_precompute_hash_to_output2_base16_type = Setup->startFlags>>56;

	if ((Setup->startFlags) == 0)
	{
		// Ok, if we do not have some 'special' loader function, we MUST first clean some
		// input.  If that is not done, there is NO WAY this is a valid format.  This is
		// NOT an intelligent check, but more like the dummy lights on newer automobiles.
		// You know it will not work, but do not know 'why', nor should you care.
		if (Setup->pFuncs[0] != DynamicFunc__clean_input &&
			Setup->pFuncs[0] != DynamicFunc__clean_input2 &&
			Setup->pFuncs[0] != DynamicFunc__clean_input_kwik &&
			Setup->pFuncs[0] != DynamicFunc__clean_input2_kwik &&
			Setup->pFuncs[0] != DynamicFunc__clean_input_full)
			return !fprintf(stderr, "Error invalid format %s: The first command MUST be a clean of input 1 or input 2 OR a special key 2 input loader function\n", Setup->szFORMAT_NAME);
	}
	if ( (Setup->flags&MGF_SALTED2)==MGF_SALTED2 && (Setup->flags&MGF_SALT_AS_HEX) == MGF_SALT_AS_HEX)
	{
		// if the user wants salt_as_hex, then here can NOT be 2 salts.
		return !fprintf(stderr, "Error invalid format %s: If using MGF_SALT_AS_HEX flag, then you can NOT have a 2nd salt.\n", Setup->szFORMAT_NAME);
	}

	if (Setup->pFuncs && Setup->pFuncs[0])
	{
		unsigned int z;
		for (z = 0; Setup->pFuncs[z]; ++z)
			;
		z += 50;
		curdat.dynamic_FUNCTIONS = mem_alloc_tiny(z*sizeof(DYNAMIC_primitive_funcp), MEM_ALIGN_WORD);

		j = 0;
#if !ARCH_LITTLE_ENDIAN
		// for bigendian, we do NOT store into keys, since we byte swap them.

		if (curdat.store_keys_in_input==1) {
			// this is only a minor speed hit, so simply fix by doing this.  There is an
			// extra memcpy, that is it.
			curdat.store_keys_in_input = 0;
			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__clean_input;
			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__append_keys;
		}

		// NOTE NOTE NOTE, FIXME.  These are 'hacks' which slow stuff way down.  We should look at
		// building preloads that CAN do this. Store key input to input 1, but then do not use
		// input 1.  Put a copy to input 2, then append, etc.   In that way, we cut the number of
		// MD5's down by at least 1.
		//
		// But for now, just get it working.  Get it working faster later.

		// NOTE, these are commented out now. I am not sure why they were there
		// I think the thought was for SIMD, BUT SIMD is not used on Sparc
		// I am leaving this code for now, BUT I think it should NOT be here.
		// I was getting failures on the 16 byte sph formats, for any
		// hash(hash($p).$s)  such as md2(md2($p).$s)  However, the modifications
		// where curdat.store_keys_in_input==1 is absolutely needed, or we have
		// get_key() failures all over the place.

		// note, with Setup->pFuncs[0]==DynamicFunc__set_input_len_32, we only will handle type 6 and 7
		// for now we have this 'turned' off.  It is fixed for type 6, 7 and 14.  It is left on for the
		// john.ini stuff.  Thus, if someone builds the intel version type 6, it will work (but slower).
//		if (curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1==1 && Setup->pFuncs[0]==DynamicFunc__set_input_len_32) {
//			curdat.store_keys_normal_but_precompute_hash_to_output2_base16_to_input1 = 0;
//			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__clean_input;
//			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__append_keys;
//			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__crypt_md5;
//			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__clean_input;
//			Setup->pFuncs[0] = DynamicFunc__append_from_last_output_as_base16;
//		}
#endif
		for (i=0; Setup->pFuncs[i]; ++i)
		{
			if (j > z-10)
			{
				unsigned int k;
				z += 100;
				curdat.dynamic_FUNCTIONS = mem_alloc_tiny(z*sizeof(DYNAMIC_primitive_funcp), MEM_ALIGN_WORD);
				for (k = 0; k <= j; ++k)
					curdat.dynamic_FUNCTIONS[k] = curdat.dynamic_FUNCTIONS[k];
			}
			if (curdat.store_keys_in_input)
			{
				if (Setup->pFuncs[i] == DynamicFunc__append_keys)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but append_keys called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__append_keys2)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but append_keys2 called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__clean_input)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but clean_input called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__append_salt)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but append_salt called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__append_from_last_output2_to_input1_as_base16)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but append_from_last_output2_to_input1_as_base16 called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but overwrite_from_last_output2_to_input1_as_base16_no_size_fix called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__append_from_last_output_as_base16)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but append_from_last_output_as_base16s called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but overwrite_from_last_output_as_base16_no_size_fix called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__append_2nd_salt)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but append_2nd_salt called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__set_input_len_32)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but DynamicFunc__set_input_len_32 called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__set_input_len_64)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but DynamicFunc__set_input_len_32 called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__overwrite_salt_to_input1_no_size_fix)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but DynamicFunc__set_input_len_32 called and that is invalid\n", Setup->szFORMAT_NAME);
				if (Setup->pFuncs[i] == DynamicFunc__append_input_from_input2)
					return !fprintf(stderr, "Error invalid format %s: MGF_KEYS_INPUT used, but DynamicFunc__set_input_len_32 called and that is invalid\n", Setup->szFORMAT_NAME);
			}
			// Ok if copy constants are set, make SURE we have that many constants.
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST1 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST1) && curdat.nConsts == 0)
				return !fprintf(stderr, "Error invalid format %s: Append Constant function called, but NO constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST2 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST2) && curdat.nConsts < 2)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #2 function called, but NO constants, or less than 2 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST3 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST3) && curdat.nConsts < 3)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #3 function called, but NO constants, or less than 3 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST4 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST4) && curdat.nConsts < 4)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #4 function called, but NO constants, or less than 4 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST5 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST5) && curdat.nConsts < 5)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #5 function called, but NO constants, or less than 5 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST6 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST6) && curdat.nConsts < 6)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #6 function called, but NO constants, or less than 6 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST7 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST7) && curdat.nConsts < 7)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #7 function called, but NO constants, or less than 7 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_input1_from_CONST8 || Setup->pFuncs[i] == DynamicFunc__append_input2_from_CONST8) && curdat.nConsts < 8)
				return !fprintf(stderr, "Error invalid format %s: Append Constant #8 function called, but NO constants, or less than 8 constants in the format\n", Setup->szFORMAT_NAME);
			if ( (Setup->pFuncs[i] == DynamicFunc__append_2nd_salt || Setup->pFuncs[i] == DynamicFunc__append_2nd_salt2) && curdat.b2Salts == 0)
				return !fprintf(stderr, "Error invalid format %s: A call to one of the 'salt-2' functions, but this format does not have MFG_SALT2 flag set\n", Setup->szFORMAT_NAME);

			// Ok, if we have made it here, the function is 'currently' still valid.  Load this pointer into our array of pointers.
			pFuncs = ConvertFuncs(Setup->pFuncs[i], &cnt2);

#define IS_FUNC_NAME(H,N) if (is##H##Func(pFuncs[x])){ if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME)) pFmt->params.algorithm_name = ALGORITHM_NAME_##N; \
			else if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME_X86)) 	pFmt->params.algorithm_name = ALGORITHM_NAME_X86_##N; }

			for (x = 0; x < cnt2; ++x) {
				curdat.dynamic_FUNCTIONS[j++] = pFuncs[x];
				if (pFuncs[x] == DynamicFunc__setmode_unicode || pFuncs[x] == DynamicFunc__setmode_unicodeBE)
					pFmt->params.flags |= FMT_UNICODE;
				IS_FUNC_NAME(SHA1,S)
				if (isSHA2_256Func(pFuncs[x])) {
#ifdef SIMD_COEF_32
					if (curdat.using_flat_buffers_sse2_ok)
						pFmt->params.algorithm_name = ALGORITHM_NAME_S2_256;
					else
#endif
						pFmt->params.algorithm_name = ALGORITHM_NAME_X86_S2_256;
				}
				if (isSHA2_512Func(pFuncs[x])) {
#ifdef SIMD_COEF_64
					if (curdat.using_flat_buffers_sse2_ok)
						pFmt->params.algorithm_name = ALGORITHM_NAME_S2_512;
					else
#endif
						pFmt->params.algorithm_name = ALGORITHM_NAME_X86_S2_512;
				}
				IS_FUNC_NAME(MD4,4)
				IS_FUNC_NAME(WHIRL,WP2)
				IS_FUNC_NAME(GOST,GST2)
				IS_FUNC_NAME(Tiger,TGR)
				IS_FUNC_NAME(RIPEMD,RIPEMD)
				IS_FUNC_NAME(HAVAL,HAVAL)
				IS_FUNC_NAME(MD2,MD2)
				IS_FUNC_NAME(PANAMA,PANAMA)
				IS_FUNC_NAME(SKEIN,SKEIN)

				// Note, until we add SIMD keccak, one algoithm is all we 'need'
				IS_FUNC_NAME(KECCAK,KECCAK)
//				IS_FUNC_NAME(KECCAK,SHA3_256)
//				IS_FUNC_NAME(KECCAK,SHA3_384)
//				IS_FUNC_NAME(KECCAK,SHA3_512)
//				IS_FUNC_NAME(KECCAK,KECCAK_256)
//				IS_FUNC_NAME(KECCAK,KECCAK_512)

				// LARGE_HASH_EDIT_POINT  (MUST match the just added a new IsXXXFunc() type function)
			}
			if (isLargeHashFinalFunc(curdat.dynamic_FUNCTIONS[j-1]))
			{
				if (Setup->pFuncs[i+1])
					return !fprintf(stderr, "Error invalid format %s: DynamicFunc__LARGE_HASH_crypt_inputX_to_output1_FINAL, can ONLY be used as the last function in a script\n", Setup->szFORMAT_NAME);
			}
		}
		curdat.dynamic_FUNCTIONS[j] = NULL;
	}
	if (!Setup->pPreloads || Setup->pPreloads[0].ciphertext == NULL)
	{
		return !fprintf(stderr, "Error invalid format %s: Error, no validation hash(s) for this format\n", Setup->szFORMAT_NAME);
	}
	cnt = 0;

#ifdef _OPENMP
	dyna_setupOMP(Setup, pFmt);
#endif

	{
		struct fmt_tests *pfx = mem_alloc_tiny(ARRAY_COUNT(dynamic_tests) * sizeof (struct fmt_tests), MEM_ALIGN_WORD);
		memset(pfx, 0, ARRAY_COUNT(dynamic_tests) * sizeof (struct fmt_tests));

		for (i = 0; cnt < ARRAY_COUNT(dynamic_tests) -1; ++i)
		{
			if (Setup->pPreloads[i].ciphertext == NULL) {
				i = 0;
			}
			if (Setup->pPreloads[i].ciphertext[0] == 'A' && Setup->pPreloads[i].ciphertext[1] == '=') {
				if (options.target_enc != ENC_RAW && options.target_enc != ISO_8859_1)
					continue;
				pfx[cnt].ciphertext = str_alloc_copy(&Setup->pPreloads[i].ciphertext[2]);
			}
			else if (Setup->pPreloads[i].ciphertext[0] == 'U' && Setup->pPreloads[i].ciphertext[1] == '=') {
				if (options.target_enc != UTF_8)
					continue;
				pfx[cnt].ciphertext = str_alloc_copy(&Setup->pPreloads[i].ciphertext[2]);
			}
			else
				pfx[cnt].ciphertext = str_alloc_copy(Setup->pPreloads[i].ciphertext);
			pfx[cnt].plaintext = str_alloc_copy(Setup->pPreloads[i].plaintext);
			pfx[cnt].fields[0] = Setup->pPreloads[i].fields[0]  ? str_alloc_copy(Setup->pPreloads[i].fields[0]) : "";
			pfx[cnt].fields[1] = pfx[cnt].ciphertext;
			for (j = 2; j < 10; ++j)
				pfx[cnt].fields[j] = Setup->pPreloads[i].fields[j]  ? str_alloc_copy(Setup->pPreloads[i].fields[j]) : "";
			++cnt;
		}
		pfx[cnt].ciphertext = NULL;
		pfx[cnt].plaintext = NULL;

		pFmt->params.tests = pfx;
	}

	if (curdat.dynamic_base16_upcase)
		dynamic_itoa16 = itoa16u;
	else
		dynamic_itoa16 = itoa16;

	{
		char s[512], *cp;
		cp = Setup->szFORMAT_NAME;
		cp = strchr(Setup->szFORMAT_NAME, ' ');
		++cp;
		sprintf(s, "%s %s", cp, pFmt->params.algorithm_name);
		pFmt->params.algorithm_name = str_alloc_copy(s);
	}

	if ((Setup->flags & MGF_SALTED) && !Setup->SaltLen)
		return !fprintf(stderr, "Error invalid format %s\n\tIt is required to add SaltLen= to the script, for this format\n", Setup->szFORMAT_NAME);
	return 1;
}

static int LoadOneFormat(int idx, struct fmt_main *pFmt)
{
	char label[16] = { 0 }, label_id[16] = { 0 }, *cp = NULL;
	memcpy(pFmt, &fmt_Dynamic, sizeof(struct fmt_main));

	// TODO:
	// NOTE, this was commented out, because the late binding @dynamic=expr@
	// hashes were killing out possibly pre-setup input buffers.  NOTE, that
	// things worked fine after this, all self tests do pass, and I am 99%
	// sure that all of this 'required' cleaning happens in init(). but I am
	// putting this comment in here, so that if at a later time, there are
	// problems and are tracked down to this, we will know why.
//	dynamic_RESET(pFmt);

	// Ok we need to list this as a dynamic format (even for the 'thin' formats)
	pFmt->params.flags |= FMT_DYNAMIC;

	if (idx < 1000) {
		if (dynamic_RESERVED_PRELOAD_SETUP(idx, pFmt) != 1)
			return 0;
	}
	else {
		if (dynamic_LOAD_PARSER_FUNCTIONS(idx, pFmt) != 1)
			return 0;
	}

	/* we 'have' to take the sig from the test array.  If we do not have */
	/* our preload array 'solid', then the idx will not be the proper */
	/* number.  So we simply grab the label from the test cyphertext string */
	strncpy(label, pFmt->params.tests[0].ciphertext, 15);
	cp = strchr(&label[1], '$');
	if (NULL != cp) cp[1] = 0;
	strcpy(label_id, &label[1]);
	cp = strchr(label_id, '$');
	if (NULL != cp) *cp = 0;

	pFmt->params.label = str_alloc_copy(label_id);

	strcpy(curdat.dynamic_WHICH_TYPE_SIG, label);

	curdat.dynamic_HASH_OFFSET = strlen(label);

	if (curdat.dynamic_base64_inout == 1 || curdat.dynamic_base64_inout == 3) {
		// we have to compute 'proper' offset
		const char *cp = pFmt->params.tests[0].ciphertext;
		size_t len = base64_valid_length(&cp[curdat.dynamic_HASH_OFFSET], curdat.dynamic_base64_inout == 1 ? e_b64_crypt : e_b64_mime, flg_Base64_MIME_TRAIL_EQ_CNT, 0);
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + len + 1;
	}
	else if (curdat.dynamic_base64_inout == 2)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 16 + 1;
	else if (curdat.dynamic_40_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 40 + 1;
	else if (curdat.dynamic_48_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 48 + 1;
	else if (curdat.dynamic_64_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 64 + 1;
	else if (curdat.dynamic_56_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 56 + 1;
	else if (curdat.dynamic_80_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 80 + 1;
	else if (curdat.dynamic_96_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 96 + 1;
	else if (curdat.dynamic_128_byte_input)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 128 + 1;
	else
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 32 + 1;

	pFmt->private.data = mem_alloc_tiny(sizeof(private_subformat_data), MEM_ALIGN_WORD);
	memcpy(pFmt->private.data, &curdat, sizeof(private_subformat_data));

	if (strncmp(curdat.dynamic_WHICH_TYPE_SIG, pFmt->params.tests[0].ciphertext, strlen(curdat.dynamic_WHICH_TYPE_SIG)))
	{
		fprintf(stderr, "ERROR, when loading dynamic formats, the wrong curdat item was linked to this type:\nTYPE_SIG=%s\nTest_Dat=%s\n",
				curdat.dynamic_WHICH_TYPE_SIG, pFmt->params.tests[0].ciphertext);
		return 0;
	}
	return 1;
}

struct fmt_main *dynamic_Register_local_format(int *type) {
	int num=nLocalFmts++;
	private_subformat_data keep;
	if (!pLocalFmts)
		pLocalFmts = mem_calloc_tiny(1000*sizeof(struct fmt_main), 16);

	/* since these are loaded LATE in the process, init() has been called
	 * and we HAVE to preserve the already loaded setup. This will happen
	 * if we run a crack, but do not specify a specific dyna format
	 */
	memcpy(&keep, &curdat, sizeof(private_subformat_data));
	LoadOneFormat(num+6000, &(pLocalFmts[num]));
	memcpy(&curdat, &keep, sizeof(private_subformat_data));
	dynamic_use_sse = curdat.dynamic_use_sse;
	force_md5_ctx = curdat.force_md5_ctx;

	*type = num+6000;
	return &(pLocalFmts[num]);
}

int dynamic_Register_formats(struct fmt_main **ptr)
{
	int count, i, idx, single=-1, wildcard = 0, pop[5000];
	extern struct options_main options;

	if (options.format && strstr(options.format, "*"))
		wildcard = 1;

	Dynamic_Load_itoa16_w2();
	if (!wildcard && options.format &&
	    !strncmp(options.format, "dynamic_", 8))
		sscanf(options.format, "dynamic_%d", &single);
	if (options.format && options.subformat  && !strcmp(options.format, "dynamic") && !strncmp(options.subformat, "dynamic_", 8))
		sscanf(options.subformat, "dynamic_%d", &single);
	if (options.dynamic_bare_hashes_always_valid == 'Y')
		dynamic_allow_rawhash_fixup = 1;
	else if (options.dynamic_bare_hashes_always_valid != 'N'  && cfg_get_bool(SECTION_OPTIONS, NULL, "DynamicAlwaysUseBareHashes", 1))
		dynamic_allow_rawhash_fixup = 1;

	if (single != -1) {
		// user wanted only a 'specific' format.  Simply load that one.
		dynamic_allow_rawhash_fixup = 1;
		if (dynamic_IS_VALID(single, 1) == 0)
			return 0;
		pFmts = mem_alloc_tiny(sizeof(pFmts[0]), MEM_ALIGN_WORD);
		if (!LoadOneFormat(single, pFmts))
			return 0;
		*ptr = pFmts;
		return (nFmts = 1);
	}

	for (count = i = 0; i < 5000; ++i) {
		if ((pop[i] = (dynamic_IS_VALID(i, 0) == 1)))
			++count;
	}

	// Ok, now we know how many formats we have.  Load them
	pFmts = mem_alloc_tiny(sizeof(pFmts[0])*count, MEM_ALIGN_WORD);
	for (idx = i = 0; i < 5000; ++i) {
		if (pop[i]) {
			if (LoadOneFormat(i, &pFmts[idx]) == 0)
				--count;
			else
				++idx;
		}
	}
	*ptr = pFmts;
	return (nFmts = count);
}

/*
 * finds the 'proper' sub format from the allocated formats, IFF that format 'exists'
 */
static struct fmt_main *dynamic_Get_fmt_main(int which)
{
	char label[40];
	int i;

	sprintf(label, "$dynamic_%d$", which);
	for (i = 0; i < nFmts; ++i) {
		private_subformat_data *pPriv = pFmts[i].private.data;
		if (!strcmp(pPriv->dynamic_WHICH_TYPE_SIG, label))
			return &pFmts[i];
	}
	for (i = 0; i < nLocalFmts; ++i) {
		private_subformat_data *pPriv = pLocalFmts[i].private.data;
		if (!strcmp(pPriv->dynamic_WHICH_TYPE_SIG, label))
			return &pLocalFmts[i];
	}
	return NULL;
}

/*
 * This function will 'forget' which md5-gen subtype we are working with. It will allow
 * a different type to be used.  Very useful for things like -test (benchmarking).
 */
static void dynamic_RESET(struct fmt_main *fmt)
{
	memset(&curdat, 0, sizeof(curdat));
	m_count = 0;
	keys_dirty = 0;
	cursalt=cursalt2=username=0;
	saltlen=saltlen2=usernamelen=0;
	// make 'sure' we startout with blank inputs.
	m_count = 0;
#ifdef SIMD_COEF_32
	if (input_buf) {
#else
	if (input_buf_X86) {
#endif
		__nonMP_DynamicFunc__clean_input_full();
		__nonMP_DynamicFunc__clean_input2_full();
	}
}

/*
 * This will LINK our functions into some other fmt_main struction. That way
 * that struction can use our code.  The other *_fmt.c file will need to
 * 'override' the valid, the binary and the salt functions, and make changes
 * to the hash, BEFORE calling into the dynamic valid/binary/salt functions.
 * Other than those functions (and calling into this linkage function at init time)
 * that is about all that needs to be in that 'other' *_fmt.c file, as long as the
 * format is part of the md5-generic 'class' of functions.
 */

struct fmt_main *dynamic_THIN_FORMAT_LINK(struct fmt_main *pFmt, char *ciphertext, char *orig_sig, int bInitAlso)
{
	int i, valid, nFmtNum;
	struct fmt_main *pFmtLocal;
	static char subformat[17], *cp;

	dynamic_allow_rawhash_fixup = 0;
	strncpy(subformat, ciphertext, 16);
	subformat[16] = 0;
	cp = strchr(&subformat[9], '$');
	if (cp)
		cp[1] = 0;

	nFmtNum = -1;
	sscanf(subformat, "$dynamic_%d", &nFmtNum);
	if (nFmtNum == -1)
		error_msg("Error, Invalid signature line trying to link to dynamic format.\nOriginal format=%s\nSignature line=%s\n", orig_sig, ciphertext);
	pFmtLocal = dynamic_Get_fmt_main(nFmtNum);
	if (pFmtLocal == NULL)
		error_msg("Error, Invalid signature line trying to link to dynamic format.\nOriginal format=%s\nSignature line=%s\n", orig_sig, ciphertext);
	valid = pFmtLocal->methods.valid(ciphertext, pFmtLocal);
	if (!valid)
		error_msg("Error, trying to link to %s using ciphertext=%s FAILED\n", subformat, ciphertext);
	pFmt->params.algorithm_name = pFmtLocal->params.algorithm_name;
	if (pFmt->params.plaintext_length == 0 ||
		pFmt->params.plaintext_length > pFmtLocal->params.plaintext_length) {
		pFmt->params.plaintext_length = pFmtLocal->params.plaintext_length;
		pFmt->params.plaintext_min_length = pFmtLocal->params.plaintext_min_length;
	}
	pFmt->params.max_keys_per_crypt = pFmtLocal->params.max_keys_per_crypt;
	pFmt->params.min_keys_per_crypt = pFmtLocal->params.min_keys_per_crypt;
	pFmt->params.flags = pFmtLocal->params.flags;
	if (pFmtLocal->params.salt_size)
		pFmt->params.salt_size = sizeof(void*);
	else
		pFmt->params.salt_size = 0;
	pFmt->methods.cmp_all    = pFmtLocal->methods.cmp_all;
	pFmt->methods.cmp_one    = pFmtLocal->methods.cmp_one;
	pFmt->methods.cmp_exact  = pFmtLocal->methods.cmp_exact;
	for (i = 0; i < FMT_TUNABLE_COSTS; ++i) {
		pFmt->methods.tunable_cost_value[i] = pFmtLocal->methods.tunable_cost_value[i];
		pFmt->params.tunable_cost_name[i] = pFmtLocal->params.tunable_cost_name[i];
	}
	pFmt->methods.source     = pFmtLocal->methods.source;
	pFmt->methods.set_salt   = pFmtLocal->methods.set_salt;
	pFmt->methods.salt       = pFmtLocal->methods.salt;
	pFmt->methods.done       = pFmtLocal->methods.done;
	pFmt->methods.salt_hash  = pFmtLocal->methods.salt_hash;
	pFmt->methods.split      = pFmtLocal->methods.split;
	pFmt->methods.set_key    = pFmtLocal->methods.set_key;
	pFmt->methods.get_key    = pFmtLocal->methods.get_key;
	pFmt->methods.clear_keys = pFmtLocal->methods.clear_keys;
	pFmt->methods.crypt_all  = pFmtLocal->methods.crypt_all;
	pFmt->methods.prepare    = pFmtLocal->methods.prepare;
	pFmt->methods.salt_compare    = pFmtLocal->methods.salt_compare;
	for (i = 0; i < PASSWORD_HASH_SIZES; ++i)
	{
		pFmt->methods.binary_hash[i] = pFmtLocal->methods.binary_hash[i];
		pFmt->methods.get_hash[i]    = pFmtLocal->methods.get_hash[i];
	}

	if (bInitAlso)
	{
		//fprintf(stderr, "dynamic_THIN_FORMAT_LINK() calling init(%s)\n", subformat);
		init(pFmtLocal);
	}

	pFmt->private.data = mem_alloc_tiny(sizeof(private_subformat_data), MEM_ALIGN_WORD);
	memcpy(pFmt->private.data, pFmtLocal->private.data, sizeof(private_subformat_data));

	return pFmtLocal;
}

// We ONLY deal with hex hashes at this time.  Is we later have to deal with
// base-64, this will become harder.  Before this function we had bugs where
// many things were loaded as 'being' valid, even if not.
static int looks_like_raw_hash(char *ciphertext, private_subformat_data *pPriv)
{
	int i, cipherTextLen = CIPHERTEXT_LENGTH;
	if (pPriv->dynamic_40_byte_input) {
		cipherTextLen = 40;
	} else if (pPriv->dynamic_48_byte_input) {
		cipherTextLen = 48;
	} else if (pPriv->dynamic_64_byte_input) {
		cipherTextLen = 64;
	} else if (pPriv->dynamic_56_byte_input) {
		cipherTextLen = 56;
	} else if (pPriv->dynamic_80_byte_input) {
		cipherTextLen = 80;
	} else if (pPriv->dynamic_96_byte_input) {
		cipherTextLen = 96;
	} else if (pPriv->dynamic_128_byte_input) {
		cipherTextLen = 128;
	}
	for (i = 0; i < cipherTextLen; i++) {
		if (atoi16[ARCH_INDEX(ciphertext[i])] == 0x7f)
			return 0;
	}
	if ((pPriv->pSetup->flags&MGF_SALTED) == 0) {
		if (!ciphertext[cipherTextLen])
			return 1;
		return 0;
	}
	return ciphertext[cipherTextLen] == '$';
}

static char *FixupIfNeeded(char *ciphertext, private_subformat_data *pPriv)
{
	if (!ciphertext || *ciphertext == 0 || *ciphertext == '*')
		return ciphertext;
	if (dynamic_allow_rawhash_fixup && strncmp(ciphertext, "$dynamic_", 9) && looks_like_raw_hash(ciphertext, pPriv))
	{
		static char __ciphertext[512+24];
		if (pPriv->pSetup->flags & MGF_SALTED) {
			if (!strchr(ciphertext, '$'))
				return ciphertext;
		}
		if ( (pPriv->pSetup->flags & MGF_SALTED2) == MGF_SALTED2) {
			if (!strstr(ciphertext, "$$2"))
				return ciphertext;
		}
		if ( (pPriv->pSetup->flags & MGF_USERNAME) == MGF_USERNAME) {
			if (!strstr(ciphertext, "$$U"))
				return ciphertext;
		}
		if (pPriv->FldMask) {
			int i;
			for (i = 0; i < 10; ++i) {
				if ((pPriv->FldMask & (MGF_FLDx_BIT<<i)) == (MGF_FLDx_BIT<<i)) {
					char Fld[8];
#if __GNUC__ == 8
/* suppress false positive GCC 8 warning */
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wformat-overflow="
#endif
					sprintf(Fld, "$$F%d", i);
#if __GNUC__ == 8
#pragma GCC diagnostic pop
#endif
					if (!strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], Fld))
						return ciphertext;
				}
			}
		}
		strcpy(__ciphertext, pPriv->dynamic_WHICH_TYPE_SIG);
		strnzcpy(&__ciphertext[strlen(__ciphertext)], ciphertext, 512);
		return __ciphertext;
	}
	return ciphertext;
}

int text_in_dynamic_format_already(struct fmt_main *pFmt, char *ciphertext)
{
	private_subformat_data *pPriv;

	if (!pFmt) return 0;
	/* NOTE, it 'is' possible to get called here, without the private stuff being setup
	  properly (in valid, etc).  So, we simply grab the static private stuff each time */
	pPriv = pFmt->private.data;
	if (!ciphertext || !pPriv) return 0;
	return !strncmp(ciphertext, pPriv->dynamic_WHICH_TYPE_SIG, strlen(pPriv->dynamic_WHICH_TYPE_SIG));
}

// if caseType == 1, return cp
// if caseType == 2, return upcase(cp)
// if caseType == 3, return locase(cp)
// if caseType == 4, return upcaseFirstChar(locase(cp))
static char *HandleCase(char *cp, int caseType)
{
	static UTF8 dest[512];

	switch(caseType) {
		case 1:
			return cp;
		case 2:
			/* -1 is a temporary workaround for #5029 */
			enc_uc(dest, sizeof(dest) - 1, (unsigned char*)cp, strlen(cp));
			if (!strcmp((char*)dest, cp))
				return cp;
			break;
		case 3:
		case 4:
			/* -1 is a temporary workaround for #5029 */
			enc_lc(dest, sizeof(dest) - 1, (unsigned char*)cp, strlen(cp));
			if (caseType == 4)
				dest[0] = low2up_ansi(dest[0]);
			if (!strcmp((char*)dest, cp))
				return cp;
			break;
		default:
			return cp;
	}
	return (char*)dest;
}

int dynamic_real_salt_length(struct fmt_main *pFmt)
{
	if (pFmt->params.flags & FMT_DYNAMIC) {
		private_subformat_data *pPriv = pFmt->private.data;
		if (pPriv == NULL || pPriv->pSetup == NULL)
			return -1;  // not a dynamic format, or called before we have loaded them!!
		return abs(pPriv->pSetup->SaltLen);
	}
	// NOT a dynamic format
	return -1;
}

void dynamic_switch_compiled_format_to_RDP(struct fmt_main *pFmt)
{
	if (pFmt->params.flags & FMT_DYNAMIC) {
		private_subformat_data *pPriv = pFmt->private.data;

		// in case there was any
		__nonMP_DynamicFunc__clean_input_full();
		__nonMP_DynamicFunc__clean_input2_full();

		if (pPriv == NULL || pPriv->pSetup == NULL)
			return;
		pPriv->dynamic_use_sse = 0;
		dynamic_use_sse = 0;
		curdat.dynamic_use_sse = 0;
		pFmt->params.algorithm_name = "Dynamic RDP";
	}
}
#else
#warning Notice: Dynamic format disabled from build.
#endif /* DYNAMIC_DISABLED */

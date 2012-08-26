/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2009-2012. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2009-2012 Jim Fougeron
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
 * Whirlpool only if OPENSSL_VERSION_NUMBER >= 0x10000000
 *
 * There used to be a todo list, and other commenting here. It has been
 * moved to ./docs/dynamic_history.txt
 *
 * KNOWN issues, and things to do.
 *
 *   1. MD5 and MD4 MUST both be using same SSE_PARA values, and built the
 *      same (I think).  If not, then MD4 should fall back to X86 mode.
 *   2. Add more crypt types, using the SHA1 'model'.  Currently, all
 *      sha2 crypts have been added (sha224, sha256, sha384, sha512).
 *      others could be any from oSSL, or any that we can get hash files
 *      for (such as GOST, IDA, IDEA, AES, CAST, Whirlpool, etc, etc)
 *   3. create a new optimize flag, MGF_PASS_AFTER_FIXEDSALT and
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

WELL, the fixed size salt, it 'may' not be key for the MGF_PASS_BEFORE_FIXEDSALT, I think I can
make that 'work' for variable sized salts.  But for the MGF_PASS_AFTER_FIXEDSALT, i.e. crypt($s.$p)
the fixed size salt IS key.  I would like to store all PW's at salt_len offset in the buffer, and
simply overwrite the first part of each buffer with the salt, never moving the password after the
first time it is written. THEN it is very important this ONLY be allowed when we KNOW the salt length
ahead of time.

 */

#include <string.h>
#include <time.h>

#include "arch.h"
#include "misc.h"
#include "common.h"
#include "formats.h"
#include "md5.h"
#include "md4.h"
#include "dynamic.h"
#include "options.h"
#include "config.h"
#include "sha.h"
#include "sha2.h"
#include "gost.h"
#include "memory.h"
#include "unicode.h"
#include "johnswap.h"
#include "pkzip.h"

#if OPENSSL_VERSION_NUMBER >= 0x10000000
#include "openssl/whrlpool.h"
#endif

#define STRINGIZE2(s) #s
#define STRINGIZE(s) STRINGIZE2(s)

extern struct fmt_main fmt_Dynamic;
static struct fmt_main *pFmts;
static int nFmts;
static int force_md5_ctx;

/* these are 'low level' inner loop data maniplation functions. Some work */
/* faster on certain CPU, and some on other CPU's.  At this time, simply  */
/* use #defines to select the 'fastest' one.   When benching, the 'raw'   */
/* timings are shown, and the fastest one can then be selected            */
/*  On my core2, __SSE_append_output_base16_to_input_2 is fastest         */
/*  On my Ath64, __SSE_append_output_base16_to_input_3 is fastest (32 bit mode */
#define LOW_BASE16_INPUT_TYPE 3
#define LOW_BASE16_INPUT_SEMI0_TYPE 2
#define LOW_BASE16_INPUT_SEMI2_TYPE 1

#define __SSE_append_output_base16_to_input __SSE_append_output_base16_to_input_3
#define __SSE_append_output_base16_to_input_semi_aligned_0 __SSE_append_output_base16_to_input_semi_aligned0_2
#define __SSE_append_output_base16_to_input_semi_aligned_2 __SSE_append_output_base16_to_input_semi_aligned2_1
//NOTE, for the 'DEEP_TIME_TEST' to be used, you MUST have timer.c and timer.h
//#define DEEP_TIME_TEST

typedef enum { eUNK=0, eBase16=1, eBase16u=2, eBase64=3, eBase64_nte=4, eBaseRaw=5} eLargeOut_t;
static	eLargeOut_t eLargeOut = eBase16;

typedef ARCH_WORD_32 MD5_word;

typedef struct {
	union {
		double dummy;
		MD5_word w[4];
		char b[16];
		unsigned char B[16];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		MD5_word w2[4];
		char b2[16];
		unsigned char B2[16];
	}x2;
#endif
} MD5_OUT;
typedef union {
	double dummy;
	MD5_word w[5];
	char b[20];
	unsigned char B[16];
} SHA1_OUT;

#if ARCH_LITTLE_ENDIAN
// MD5_go is SUPER slow on big endian. In the case of bigendian, we simply
// fall back, and use OpenSSL MD5 calls, which are usually MUCH faster.
#define USE_MD5_Go
#define MD5_swap(x, y, count)
#define MD5_swap2(a,b,c,d,e)
#ifdef SHA1_SSE_PARA
#define shammx(a,b,c)
static void SHA1_swap(MD5_word *x, MD5_word *y, int count)
{
	do {
		*y++ = JOHNSWAP(*x++);
	} while (--count);
}
#endif
#else
extern char *MD5_DumpHexStr(void *p);
static void MD5_swap(MD5_word *x, MD5_word *y, int count)
{
	do {
		*y++ = JOHNSWAP(*x++);
	} while (--count);
}
#if MD5_X2
static void MD5_swap2(MD5_word *x, MD5_word *x2, MD5_word *y, MD5_word *y2, int count)
{
	do {
		*y++ = JOHNSWAP(*x++);
		*y2++ = JOHNSWAP(*x2++);
	} while (--count);
}
#endif
#define SHA1_swap(x,y,z)
#endif

#ifdef DEEP_TIME_TEST
static int __SSE_gen_bBenchThisTime;
static void __SSE_gen_BenchLowLevelFunctions();
#endif

#define FORMAT_LABEL		"dynamic"
#define FORMAT_NAME         "Generic MD5"

#ifdef MMX_COEF
# include "sse-intrinsics.h"
# define GETPOS(i, index)		( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF + ((i)&3) )
# define SHAGETPOS(i, index)	( (index&(MMX_COEF-1))*4 + ((i)&(0xffffffff-3) )*MMX_COEF + (3-((i)&3)) ) //for endianity conversion
# define MIN_KEYS_PER_CRYPT	1
# if (MMX_COEF == 2)
#  define BLOCK_LOOPS			64
#  define ALGORITHM_NAME		"64/64 " MD5_SSE_type  " 64x2"
#  define ALGORITHM_NAME_S		"64/64 " SHA1_SSE_type " 64x2"
#  define ALGORITHM_NAME_4		"64/64 " MD4_SSE_type  " 64x2"
#  define MAX_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#  define BSD_BLKS 1
# elif MMX_COEF == 4
#  define BLOCK_LOOPS			32
#  if !defined MD5_SSE_PARA || MD5_SSE_PARA==1
#   define BY_X			32
#  elif MD5_SSE_PARA==2
#   define BY_X			16
#  elif MD5_SSE_PARA==3
#   define BY_X			10
#  elif MD5_SSE_PARA==4
#   define BY_X			8
#  elif MD5_SSE_PARA==5
#   define BY_X			6
#  elif MD5_SSE_PARA==6
#   define BY_X			5
#  endif
#define LOOP_STR
#  ifdef MD5_SSE_PARA
#   define ALGORITHM_NAME		"128/128 " MD5_SSE_type  " " STRINGIZE(BY_X) "x4x" STRINGIZE(MD5_SSE_PARA)
#   define BSD_BLKS (MD5_SSE_PARA)
#  else
#   define ALGORITHM_NAME		"128/128 " MD5_SSE_type  " " STRINGIZE(BY_X) "x4"
#   define BSD_BLKS 1
#  endif
#  ifdef SHA1_SSE_PARA
#   define ALGORITHM_NAME_S		"128/128 " SHA1_SSE_type " " STRINGIZE(BY_X) "x4x" STRINGIZE(SHA1_SSE_PARA)
#  else
#   define ALGORITHM_NAME_S		"128/128 " SHA1_SSE_type " " STRINGIZE(BY_X) "x4"
#  endif
#  ifdef MD4_SSE_PARA
#   define ALGORITHM_NAME_4		"128/128 " MD4_SSE_type  " " STRINGIZE(BY_X) "x4x" STRINGIZE(MD4_SSE_PARA)
#  else
#   define ALGORITHM_NAME_4		"128/128 " MD4_SSE_type  " " STRINGIZE(BY_X) "x4"
#  endif
#  define PLAINTEXT_LENGTH	(27*3+1) // for worst-case UTF-8
#  ifdef MD5_SSE_PARA
// gives us 16 'loops' for para=2 and 10 loops for para==3 (or max of 128 for 2 and 120 for 3)
#   define MAX_KEYS_PER_CRYPT	(((MMX_COEF*BLOCK_LOOPS)/(MD5_SSE_PARA*4))*(MD5_SSE_PARA*4))
#  else
#   define MAX_KEYS_PER_CRYPT	MMX_COEF*BLOCK_LOOPS
#  endif
# else
#  error "Invalid MMX_COEF  Only valid is 2 or 4"
# endif
#else // !MMX_COEF
# define BLOCK_LOOPS			128
# define ALGORITHM_NAME			"32/" ARCH_BITS_STR " 128x1"
# define ALGORITHM_NAME_S		"32/" ARCH_BITS_STR " 128x1"
# define ALGORITHM_NAME_4		"32/" ARCH_BITS_STR " 128x1"
#endif

#define ALGORITHM_NAME_X86_S	"32/" ARCH_BITS_STR " 128x1"
#define ALGORITHM_NAME_X86_4	"32/" ARCH_BITS_STR " 128x1"

// No SSE2 'yet' for sha2.  Waiting patiently for a kind super hacker to do these formats ;)
#if defined (COMMON_DIGEST_FOR_OPENSSL)
#define ALGORITHM_NAME_S2		"32/" ARCH_BITS_STR " 128x1 CommonCrypto"
#define ALGORITHM_NAME_X86_S2	"32/" ARCH_BITS_STR " 128x1 CommonCrypto"
#elif defined (GENERIC_SHA2)
#define ALGORITHM_NAME_S2		"32/" ARCH_BITS_STR " 128x1 sha2-generic"
#define ALGORITHM_NAME_X86_S2	"32/" ARCH_BITS_STR " 128x1 sha2-generic"
#else
#define ALGORITHM_NAME_S2		"32/" ARCH_BITS_STR " 128x1 sha2-OpenSSL"
#define ALGORITHM_NAME_X86_S2	"32/" ARCH_BITS_STR " 128x1 sha2-OpenSSL"
#endif

// NOTE, we will HAVE to increase this at some time.  sha512 has 128 byte hash all in itself. So you try
// to do sha512($s.sha512($p)), or even sha512(sha512($p)) we are blowing past our buffers, BAD

// Would LOVE to go to 128 bytes (would allow md5(md5($p).md5($p).md5($p).md5($p)) but
// due to other parts of john, we can only go to 128-3 as max sized plaintext.
#define PLAINTEXT_LENGTH_X86		124

#ifdef USE_MD5_Go
#define MIN_KEYS_PER_CRYPT_X86	1
#define MAX_KEYS_PER_CRYPT_X86	128
extern void MD5_Go2 (unsigned char *data, unsigned int len, unsigned char *result);
#if MD5_X2 && (!MD5_ASM)
#if defined(_OPENMP)
#define MD5_body(x0, x1, out0, out1) \
	MD5_body_for_thread(0, x0, x1, out0, out1)
extern void MD5_body_for_thread(int t, MD5_word x[15], MD5_word x2[15], MD5_word out[4], MD5_word out2[4]);
#else
extern void MD5_body(MD5_word x[15], MD5_word x2[15], MD5_word out[4], MD5_word out2[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " 64x2 (MD5_Body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L[0])<55&&(L[1])<55) {A.x1.b[L[0]]=0x80;A.x2.b2[L[1]]=0x80;A.x1.w[14]=(L[0]<<3);A.x2.w2[14]=(L[1]<<3);MD5_swap(A.x1.w,A.x1.w,(L[0]+4)>>2);MD5_swap(A.x2.w2,A.x2.w2,(L[1]+4)>>2);MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);MD5_swap2(C.x1.w,C.x2.w2,C.x1.w,C.x2.w2,4);} else {MD5_Go2(A.x1.B,L[0],C.x1.B); MD5_Go2(A.x2.B2,L[1],C.x2.B2);} }while(0)
#define DoMD5o(A,L,C) do{if((L[0])<55&&(L[1])<55) {MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);} else {MD5_Go2(A.x1.B,L[0],C.x1.B); MD5_Go2(A.x2.B2,L[1],C.x2.B2);} }while(0)
#if ARCH_LITTLE_ENDIAN
#define DoMD5a(A,L,C) MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2)
#define DoMD5a2(A,L,C,D) MD5_body(A->x1.w,A->x2.w2, (ARCH_WORD_32*)D[0], (ARCH_WORD_32*)D[1])
#else
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2);MD5_swap2(C->x1.w,C->x2.w2,C->x1.w,C->x2.w2,4);}while(0)
#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,A->x2.w2,tmpOut.x1.w,tmpOut.x2.w2);MD5_swap2(tmpOut.x1.w,tmpOut.x2.w2,tmpOut.x1.w,tmpOut.x2.w2,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);memcpy(&(C->x2.b2[D[1]]),tmpOut.x2.b2,16);}while(0)
#endif
#else
#if defined(_OPENMP) && !MD5_ASM
#define MD5_body(x, out) \
	MD5_body_for_thread(0, x, out)
extern void MD5_body_for_thread(int t, ARCH_WORD_32 x[15], ARCH_WORD_32 out[4]);
#else
extern void MD5_body(ARCH_WORD_32 x[15], ARCH_WORD_32 out[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " 128x1 (MD5_Body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L)<55) {A.x1.b[L]=0x80;A.x1.w[14]=(L<<3);MD5_swap(A.x1.w,A.x1.w,((L+4)>>2));MD5_body(A.x1.w,C.x1.w);MD5_swap(C.x1.w,C.x1.w,4);} else MD5_Go2(A.x1.B,L,C.x1.B); }while(0)
#define DoMD5o(A,L,C) do{if((L)<55) {MD5_body(A.x1.w,C.x1.w);} else MD5_Go2(A.x1.B,L,C.x1.B); }while(0)
#if ARCH_LITTLE_ENDIAN
#define DoMD5a(A,L,C) MD5_body(A->x1.w,C->x1.w)
#define DoMD5a2(A,L,C,D) MD5_body(A->x1.w,(ARCH_WORD_32*)D)
#else
static MD5_OUT tmpOut;
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,C->x1.w);MD5_swap(C->x1.w,C->x1.w,4);}while(0)
#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,tmpOut.x1.w);MD5_swap(tmpOut.x1.w,tmpOut.x1.w,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);}while(0)
#endif
#endif
#else // !USE_MD5_Go
static MD5_OUT tmpOut;
#define MIN_KEYS_PER_CRYPT_X86	1
#define MAX_KEYS_PER_CRYPT_X86	128
#if MD5_X2 && (!MD5_ASM)
#if defined(_OPENMP)
#define MD5_body(x0, x1, out0, out1) \
	MD5_body_for_thread(0, x0, x1, out0, out1)
extern void MD5_body_for_thread(int t, ARCH_WORD_32 x1[15], ARCH_WORD_32 x2[15], ARCH_WORD_32 out1[4], ARCH_WORD_32 out2[4]);
#else
extern void MD5_body(ARCH_WORD_32 x1[15], ARCH_WORD_32 x2[15], ARCH_WORD_32 out1[4], ARCH_WORD_32 out2[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " 64x2 (MD5_body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L[0])<55&&(L[1])<55) {A.x1.b[L[0]]=0x80;A.x2.b2[L[1]]=0x80;A.x1.w[14]=(L[0]<<3);A.x2.w2[14]=(L[1]<<3);MD5_swap(A.x1.w,A.x1.w,(L[0]+4)>>2);MD5_swap(A.x2.w2,A.x2.w2,(L[1]+4)>>2);MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);MD5_swap2(C.x1.w,C.x2.w2,C.x1.w,C.x2.w2,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5o(A,L,C) do{if((L[0])<55&&(L[1])<55) {MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2);}while(0)
#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,A->x2.w2,tmpOut.x1.w,tmpOut.x2.w2);MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);MD5_swap(C->x2.w2,C->x2.w2,(D[1]+21)>>2);MD5_swap(tmpOut.x1.w,tmpOut.x1.w,4);MD5_swap(tmpOut.x2.w2,tmpOut.x2.w2,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);memcpy(&(C->x2.b2[D[1]]),tmpOut.x2.b2,16);MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);MD5_swap(C->x2.w2,C->x2.w2,(D[1]+21)>>2);}while(0)
#else
#if defined(_OPENMP) && !MD5_ASM
#define MD5_body(x, out) \
	MD5_body_for_thread(0, x, out)
extern void MD5_body_for_thread(int t, MD5_word x[15],MD5_word out[4]);
#else
extern void MD5_body(MD5_word x[15],MD5_word out[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " 128x1 (MD5_body)"
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L)<55) {A.x1.b[L]=0x80;A.x1.w[14]=(L<<3);MD5_swap(A.x1.w,A.x1.w,((L+4)>>2));MD5_body(A.x1.w,C.x1.w);MD5_swap(C.x1.w,C.x1.w,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L); MD5_Final((unsigned char *)(C.x1.b),&ctx); } }while(0)
#define DoMD5o(A,L,C) do{if((L)<55) {MD5_body(A.x1.w,C.x1.w);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L); MD5_Final((unsigned char *)(C.x1.b),&ctx); } }while(0)
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,C->x1.w);}while(0)
#define DoMD5a2(A,L,C,D)  do{MD5_body(A->x1.w,tmpOut.x1.w); MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16); MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);}while(0)
#endif
#endif
SHA_CTX sha_ctx;

// simple macro for now.  We can and will improve upon this later.
#if MD5_X2
#define DoMD4(A,L,C) do{ MD4_CTX ctx; MD4_Init(&ctx); MD4_Update(&ctx,A.x1.b,L[0]); MD4_Final(C.x1.B,&ctx); MD4_Init(&ctx); MD4_Update(&ctx,A.x2.b2,L[1]); MD4_Final(C.x2.B2,&ctx);}while(0)
#else
#define DoMD4(A,L,C) do{ MD4_CTX ctx; MD4_Init(&ctx); MD4_Update(&ctx,A.x1.b,L); MD4_Final(C.x1.B,&ctx);}while(0)
#endif

#define BENCHMARK_COMMENT		""
#define BENCHMARK_LENGTH		-1
#define CIPHERTEXT_LENGTH		32
#define BINARY_SIZE				16
#define BINARY_SIZE_SHA         20

// Computation for 'salt_size'  The salt (and salt2) is appended to the end of the hash entry.
//    The format of a salted entry is:   $dynamic_#$hash$SALT_VAL[$$2SALT2_VAL]
// salt 64 bytes,
// salt2 64 bytes,
// salt signature $ 1 byte
// salt2 signature $$2 3 bytes
// null termination 1 byte.  This this allows 2 64 byte salt's.
// Note, we now have up to 10 of these.
#define SALT_SIZE				(64*4+1+3+1)

// slots to do 24 'tests'. Note, we copy the
// same 3 tests over and over again.  Simply to validate that
// tests use 'multiple' blocks.
static struct fmt_tests dynamic_tests[] = {
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},
	{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL},{NULL}
};

#ifdef MMX_COEF
// SSE2 works only with 54 byte keys. Thus, md5(md5($p).md5($s)) can NOT be used
// with the SSE2, since that final md5 will be over a 64 byte block of data.
#ifndef _DEBUG
#define input_buf  genMD5_input_buf
#define input_buf2 genMD5_input_buf2
#define crypt_key  genMD5_crypt_key
#define crypt_key2 genMD5_crypt_key2
#define sinput_buf  genMD5_sinput_buf
#define scrypt_key  genMD5_scrypt_key
#endif
#ifdef SHA1_SSE_PARA
#define SHA_BLOCKS SHA1_SSE_PARA
#else
#define SHA_BLOCKS 1
#endif
#ifdef _MSC_VER
__declspec(align(16)) unsigned char input_buf[BLOCK_LOOPS][64*MMX_COEF];
__declspec(align(16)) unsigned char input_buf2[BLOCK_LOOPS][64*MMX_COEF];
__declspec(align(16)) unsigned char crypt_key[BLOCK_LOOPS+1][BINARY_SIZE*MMX_COEF]; // the +1 is so we can directly dump sha1 crypts here. We need an extra buffer on the end, to hold the last buffer overwrite
__declspec(align(16)) unsigned char crypt_key2[BLOCK_LOOPS][BINARY_SIZE*MMX_COEF];
// SHA keyspace
__declspec(align(16)) unsigned char sinput_buf[SHA_BLOCKS][SHA_BUF_SIZ*4*MMX_COEF];
__declspec(align(16)) unsigned char scrypt_key[SHA_BLOCKS][BINARY_SIZE_SHA*MMX_COEF];
#else
unsigned char input_buf[BLOCK_LOOPS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char input_buf2[BLOCK_LOOPS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char crypt_key[BLOCK_LOOPS+1][BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));  // the +1 is so we can directly dump sha1 crypts here. We need an extra buffer on the end, to hold the last buffer overwrite
unsigned char crypt_key2[BLOCK_LOOPS][BINARY_SIZE*MMX_COEF] __attribute__ ((aligned(16)));
// SHA keyspace
unsigned char sinput_buf[SHA_BLOCKS][SHA_BUF_SIZ*4*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char scrypt_key[SHA_BLOCKS][BINARY_SIZE_SHA*MMX_COEF] __attribute__ ((aligned(16)));
#endif
static unsigned int total_len[BLOCK_LOOPS];
static unsigned int total_len2[BLOCK_LOOPS];
#endif
// Allows us to work with up to 96 byte keys in the non-sse2 code

typedef struct {
	union {
		double dummy;
		MD5_word w[(PLAINTEXT_LENGTH_X86+96)/4];
		char b[PLAINTEXT_LENGTH_X86+96];
		unsigned char B[PLAINTEXT_LENGTH_X86+96];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		MD5_word w2[(PLAINTEXT_LENGTH_X86+96)/4];
		char b2[PLAINTEXT_LENGTH_X86+96];
		unsigned char B2[PLAINTEXT_LENGTH_X86+96];
	}x2;
#endif
} MD5_IN;

static MD5_OUT crypt_key_X86[MAX_KEYS_PER_CRYPT_X86>>MD5_X2];
static MD5_OUT crypt_key2_X86[MAX_KEYS_PER_CRYPT_X86>>MD5_X2];

static MD5_IN input_buf_X86[MAX_KEYS_PER_CRYPT_X86>>MD5_X2];
static MD5_IN input_buf2_X86[MAX_KEYS_PER_CRYPT_X86>>MD5_X2];

static unsigned int total_len_X86[MAX_KEYS_PER_CRYPT_X86];
static unsigned int total_len2_X86[MAX_KEYS_PER_CRYPT_X86];

static int keys_dirty;
// We store the salt here
static unsigned char *cursalt;
// length of salt (so we don't have to call strlen() all the time.
static int saltlen;
// This array is for the 2nd salt in the hash.  I know of no hashes with double salts,
// but test type dynamic_16 (which is 'fake') has 2 salts, and this is the data/code to
// handle double salts.
static unsigned char *cursalt2;
static int saltlen2;

static unsigned char *username;
static int usernamelen;

static unsigned char *flds[10];
static int fld_lens[10];

static char *dynamic_itoa16 = itoa16;
static unsigned short itoa16_w2_u[256], itoa16_w2_l[256], *itoa16_w2=itoa16_w2_l;

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

static char saved_key[EFFECTIVE_MKPC][EFFECTIVE_MAX_LENGTH + 1];
static int saved_key_len[EFFECTIVE_MKPC];

// Used in 'get_key' if we are running in store_keys_in_input mode
static char out[EFFECTIVE_MAX_LENGTH + 1];

// This is the GLOBAL count of keys. ALL of the primitives which deal with a count
// will read from this variable.
static int m_count;

// If we are run in 'specific' mode (say, -format=dynamic -subformat=dynamic_0, then we
// want to 'allow' raw hashes to be 'valid'. This is how we will do this.  We have a boolean
// that if set to true, we will perform a 1 time check within the valid function. If at
// that time we find out that we are cracking (or showing, etc) that we will accept lines
// that are either format of $dynamic_0$hhhhhh...32 or simply in the format of hhhhhhh..32
static int m_allow_rawhash_fixup = 0;

// this one IS in the private_dat, but since it is accessed SO much, we pull it
// out prior to 'internal' processing. The others are accessed right from
// the structure, since there are accessed infrequently enough to not matter.
static int dynamic_use_sse;

// If set to 1, then do unicode conversion is many string setting functions.
static int md5_unicode_convert;

typedef struct private_subformat_data
{
	// If compiled in SSE, AND the format allows SSE, then this will be set to 1.
	int dynamic_use_sse;
	int md5_startup_in_x86;

	// if the format is non-base16 (i.e. base-64), then this flag is set, and
	// a the hash loading function uses it.
	int dynamic_base64_inout;
	// if we want 'upper-case' in our base-16 conversions.
	int dynamic_base16_upcase;
	// if set, then we load keys directly into input1 and NOT into the saved_key buffers
	int store_keys_in_input;
	int input2_set_len32;
	int store_keys_in_input_unicode_convert;
	int store_keys_normal_but_precompute_md5_to_output2;
	int store_keys_normal_but_precompute_md5_to_output2_base16_to_input1;
	int store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32;
	int dynamic_salt_as_hex;
	int force_md5_ctx;

	// This array is for the 2nd salt in the hash.  I know of no hashes with double salts,
	// but test type dynamic_16 (which is 'fake') has 2 salts, and this is the data/code to
	// handle double salts.
	int b2Salts;
	int nUserName;
	int nPassCase;
	unsigned FldMask;
	// Special HDAA salt function
	int dynamic_hdaa_salt;
	// if the external hash is sha1()  (such as sha1(md5($p)) then we want 40 byte input hashes.
	// We only 'use' 32 bytes of it to compare, but we should only run against 40byte hashes.
	int dynamic_40_byte_sha1;
	// set to 1 if sha224 or sha256 'input' hashes are used
	int dynamic_56_byte_sha224;
	int dynamic_64_byte_sha256;
	int dynamic_96_byte_sha384;
	int dynamic_128_byte_sha512;
	int dynamic_64_byte_gost;
	int dynamic_128_byte_whirlpool;

	// Some formats have 'constants'.  A good example is the MD5 Post Office format dynamic_18
	// There can be 8 constants which can be put into the strings being built.  Most formats do
	// not have constants.
	unsigned char *Consts[8];
	int ConstsLen[8];
	int nConsts;

	char dynamic_WHICH_TYPE_SIG[40];
	// this 'will' be replaced, and will 'replace' FORMAT_NAME
	int init;
	int dynamic_FIXED_SALT_SIZE;
	int dynamic_SALT_OFFSET;
	int dynamic_HASH_OFFSET;
	DYNAMIC_primitive_funcp *dynamic_FUNCTIONS;
	DYNAMIC_Setup *pSetup;

} private_subformat_data;

static private_subformat_data curdat;

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

char *RemoveHEX(char *output, char *input) {
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
		if (*cpi == '0' && cpi[1] == '0') {
			strcpy(output, input);
			return output;
		}
		if (atoi16[ARCH_INDEX(*cpi)] != 0x7f && atoi16[ARCH_INDEX(cpi[1])] != 0x7f) {
			*cpo++ = atoi16[ARCH_INDEX(*cpi)]*16 + atoi16[ARCH_INDEX(cpi[1])];
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

/*********************************************************************************
 * Detects a 'valid' md5-gen format. This function is NOT locked to anything. It
 * takes it's detection logic from the provided fmt_main pointer. Within there,
 * is a 'private' data pointer.  When john first loads the md5-gen, it calls a
 * function which builds proper 'private' data for EACH type of md5-gen. Then
 * john will call valid on EACH of those formats, asking each one if a string is
 * valid. Each format has a 'private' properly setup data object.
 *********************************************************************************/
static int valid(char *ciphertext, struct fmt_main *pFmt)
{
	int i, cipherTextLen;
	char *cp, *fixed_ciphertext;
	private_subformat_data *pPriv = pFmt->private.data;

	if (!pPriv)
		return 0;

	if (strncmp(ciphertext, pPriv->dynamic_WHICH_TYPE_SIG, strlen(pPriv->dynamic_WHICH_TYPE_SIG)))
		return 0;
	cp = &ciphertext[strlen(pPriv->dynamic_WHICH_TYPE_SIG)];

	// this is now simply REMOVED totally, if we detect it.  Doing this solves MANY other problems
	// of leaving it in there. The ONLY problem we still have is NULL bytes.
	if (strstr(ciphertext, "$HEX$")) {
		fixed_ciphertext = alloca(strlen(ciphertext)+1);
		ciphertext = RemoveHEX(fixed_ciphertext, ciphertext);
	}

	if (pPriv->dynamic_base64_inout == 1)
	{
		// jgypwqm.JsMssPLiS8YQ00$BaaaaaSX
		int i;
		for (i = 0; i < 22; ++i) {
			if (atoi64[ARCH_INDEX(cp[i])] == 0x7F)
				return 0;
		}
		if (pPriv->dynamic_FIXED_SALT_SIZE == 0)
			return 1;
		if (pPriv->dynamic_FIXED_SALT_SIZE && cp[22] != '$')
			return 0;
		if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && strlen(&cp[23]) != pPriv->dynamic_FIXED_SALT_SIZE)
			return 0;
		else if (pPriv->dynamic_FIXED_SALT_SIZE < -1 && strlen(&cp[23]) > -(pPriv->dynamic_FIXED_SALT_SIZE))
			return  0;
		return 1;
	}
	if (pPriv->dynamic_base64_inout == 2)
	{
		// h3mJrcH0901pqX/m$alex
		int i;
		for (i = 0; i < 16; ++i) {
			if (atoi64[ARCH_INDEX(cp[i])] == 0x7F)
				return 0;
		}
		if (pPriv->dynamic_FIXED_SALT_SIZE == 0)
			return 1;
		if (pPriv->dynamic_FIXED_SALT_SIZE && cp[16] != '$')
			return 0;
		if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && strlen(&cp[17]) != pPriv->dynamic_FIXED_SALT_SIZE)
			return 0;
		else if (pPriv->dynamic_FIXED_SALT_SIZE < -1 && strlen(&cp[17]) > -(pPriv->dynamic_FIXED_SALT_SIZE))
			return  0;
		return 1;
	}

	if (pPriv->dynamic_base64_inout == 1)
	{
		if (strlen(cp) < 22)
			return 0;
	}
	else if (pPriv->dynamic_base64_inout == 2)
	{
		if (strlen(cp) < 16)
			return 0;
	}
	else
	{
		if (strlen(cp) < 32)
			return 0;
	}
	cipherTextLen = CIPHERTEXT_LENGTH;
	if (pPriv->dynamic_40_byte_sha1) {
		cipherTextLen = 40;
	} else if (pPriv->dynamic_64_byte_sha256 || pPriv->dynamic_64_byte_gost) {
		cipherTextLen = 64;
	} else if (pPriv->dynamic_56_byte_sha224) {
		cipherTextLen = 56;
	} else if (pPriv->dynamic_96_byte_sha384) {
		cipherTextLen = 96;
	} else if (pPriv->dynamic_128_byte_sha512 || pPriv->dynamic_128_byte_whirlpool) {
		cipherTextLen = 128;
	}
	for (i = 0; i < cipherTextLen; i++) {
		if (atoi16[ARCH_INDEX(cp[i])] == 0x7f)
			return 0;
	}
	if ( (pPriv->pSetup->flags&MGF_SALTED) == 0)
		return 1;

	if (cp[cipherTextLen] && cp[cipherTextLen] != '$')
		return 0;
	if (pPriv->dynamic_FIXED_SALT_SIZE && ciphertext[pPriv->dynamic_SALT_OFFSET-1] != '$')
		return 0;
	if (pPriv->dynamic_FIXED_SALT_SIZE > 0 && strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]) != pPriv->dynamic_FIXED_SALT_SIZE) {
		// check if there is a 'salt-2' or 'username', etc  If that is the case, then this is still valid.
		if (strncmp(&ciphertext[pPriv->dynamic_SALT_OFFSET+pPriv->dynamic_FIXED_SALT_SIZE], "$$", 2))
			return 0;
	}
	else if (pPriv->dynamic_FIXED_SALT_SIZE < -1 && strlen(&ciphertext[pPriv->dynamic_SALT_OFFSET]) > -(pPriv->dynamic_FIXED_SALT_SIZE)) {
		// check if there is a 'salt-2' or 'username', etc  If that is the case, then this is still 'valid'
		char *cpX = mem_alloc(-(pPriv->dynamic_FIXED_SALT_SIZE) + 3);
		strnzcpy(cpX, &ciphertext[pPriv->dynamic_SALT_OFFSET], -(pPriv->dynamic_FIXED_SALT_SIZE) + 3);
		if (!strstr(cpX, "$$")) {
			MEM_FREE(cpX);
			return 0;
		}
		MEM_FREE(cpX);
	}
	if (pPriv->b2Salts==1 && !strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], "$$2"))
		return 0;
	if (pPriv->nUserName && !strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], "$$U"))
		return 0;
	for (i = 0; i < 10; ++i) {
		char Fld[5];
		sprintf(Fld, "$$F%d", i);
		if ( (pPriv->FldMask & (MGF_FLDx_BIT<<i)) == (MGF_FLDx_BIT<<i) && !strstr(&ciphertext[pPriv->dynamic_SALT_OFFSET-1], Fld))
			return 0;
	}

	return 1;
}

static char *FixupIfNeeded(char *ciphertext, private_subformat_data *pPriv);
static struct fmt_main *dynamic_Get_fmt_main(int which);
static char *HandleCase(char *cp, int caseType);

/*********************************************************************************
 * init() here does nothing. NOTE many formats LINKING into us will have a valid
 * that DOES do something, but ours does nothing.
 *********************************************************************************/
static void init(struct fmt_main *pFmt)
{
	private_subformat_data *pPriv = pFmt->private.data;
	int i;

	gost_init_table();
	if (!pPriv || (pPriv->init == 1 && !strcmp(curdat.dynamic_WHICH_TYPE_SIG, pPriv->dynamic_WHICH_TYPE_SIG)))
		return;

	DynamicFunc__clean_input_full();
	DynamicFunc__clean_input2_full();

	dynamic_RESET(pFmt);
	if (!pPriv)
		return;

	pPriv->init = 1;

	memcpy(&curdat, pPriv, sizeof(private_subformat_data));
	dynamic_use_sse = curdat.dynamic_use_sse;
	force_md5_ctx = curdat.force_md5_ctx;

	fmt_Dynamic.params.max_keys_per_crypt = pFmt->params.max_keys_per_crypt;
	fmt_Dynamic.params.min_keys_per_crypt = pFmt->params.min_keys_per_crypt;
	fmt_Dynamic.params.format_name        = pFmt->params.format_name;
	fmt_Dynamic.params.algorithm_name     = pFmt->params.algorithm_name;
	fmt_Dynamic.params.benchmark_comment  = pFmt->params.benchmark_comment;
	fmt_Dynamic.params.benchmark_length   = pFmt->params.benchmark_length;
	if ( (pFmt->params.flags&FMT_UNICODE) && options.utf8 )
		pFmt->params.plaintext_length = pPriv->pSetup->MaxInputLen * 3; // we allow for 3 bytes of utf8 data to make up the number of plaintext_length unicode chars.
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
#ifdef MMX_COEF
		for (i = 0; i < BLOCK_LOOPS; ++i) {
			input_buf2[i][GETPOS(32,0)] = 0x80;
			input_buf2[i][GETPOS(57,0)] = 0x1;
			input_buf2[i][GETPOS(32,1)] = 0x80;
			input_buf2[i][GETPOS(57,1)] = 0x1;
			total_len2[i*MMX_COEF] = 32;
			total_len2[i*MMX_COEF+1] = 32;
#if (MMX_COEF==4)
			input_buf2[i][GETPOS(32,2)] = 0x80;
			input_buf2[i][GETPOS(57,2)] = 0x1;
			input_buf2[i][GETPOS(32,3)] = 0x80;
			input_buf2[i][GETPOS(57,3)] = 0x1;
			total_len2[i*MMX_COEF+2] = 32;
			total_len2[i*MMX_COEF+3] = 32;
#endif
		}
#endif
	}
}

/*********************************************************************************
 * This function will add a $dynamic_#$ IF there is not one, and if we have a specific
 * format requested.  Also, it will add things like UserID, Domain, Fld3, Fld4,
 * Fld5, etc.
 *********************************************************************************/
static char *prepare(char *split_fields[10], struct fmt_main *pFmt)
{
	static char ct[512];
	private_subformat_data *pPriv = pFmt->private.data;
	char Tmp[80];
	int i;

	char *cpBuilding=split_fields[1];

	if (!pPriv)
		return split_fields[1];

	if (pFmt->params.salt_size && !strchr(split_fields[1], '$')) {
		if (!pPriv->nUserName && !pPriv->FldMask)
			return split_fields[1];
	}

	// handle 'older' md5_gen(x) signature, by simply converting to $dynamic_x$ signature
	// Thus older md5_gen() is a valid input (or from john.pot), but ONLY the newer
	// $dynamic_x$ will be written out (into .pot, output lines, etc).
	if (!strncmp(cpBuilding, "md5_gen(", 8))
	{
		char *cp = &cpBuilding[8], *cpo = &ct[sprintf(ct, "$dynamic_")];
		while (*cp >= '0' && *cp <= '9')
			*cpo++ = *cp++;
		*cpo++ = '$';
		++cp;
		strnzcpy(cpo, cp, 512);
		cpBuilding = ct;
	}

	cpBuilding = FixupIfNeeded(cpBuilding, pPriv);
	if (strncmp(cpBuilding, "$dynamic_", 9))
		return split_fields[1];

	if ( (pPriv->pSetup->flags&MGF_SALTED) == 0)
		return cpBuilding;

	/* at this point, we want to convert ANY and all $HEX$hex into values */
	/* the reason we want to do this, is so that things read from john.pot file will be in proper 'native' format */
	/* the ONE exception to this, is if there is a NULL byte in the $HEX$ string, then we MUST leave that $HEX$ string */
	/* alone, and let the later calls in dynamic.c handle them. */
	if (strstr(cpBuilding, "$HEX$")) {
		char *cp, *cpo;
		int bGood=1;

		strcpy(ct, cpBuilding);
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
				return split_fields[1];
			}
		}
		if (bGood)
			cpBuilding = ct;
	}

	if (pPriv->nUserName && !strstr(cpBuilding, "$$U")) {
		char *userName=split_fields[0], *cp;
		// assume field[0] is in format: username OR DOMAIN\\username  If we find a \\, then  use the username 'following' it.
		cp = strchr(split_fields[0], '\\');
		if (cp)
			userName = &cp[1];
		userName = HandleCase(userName, pPriv->nUserName);
		sprintf (ct, "%s$$U%s", cpBuilding, userName);
		cpBuilding = ct;
	}
	for (i = 0; i <= 8; ++i) {
		sprintf(Tmp, "$$F%d", i);
		if ( split_fields[i] &&  (pPriv->FldMask&(MGF_FLDx_BIT<<i)) && !strstr(cpBuilding, Tmp)) {
			sprintf (ct, "%s$$F%d%s", cpBuilding, i, split_fields[i]);
			cpBuilding = ct;
		}
	}
	return cpBuilding;
}

#if FMT_MAIN_VERSION > 9
static char *split(char *ciphertext, int index, struct fmt_main *pFmt)
#else
static char *split(char *ciphertext, int index)
#endif
{
	static char out[1024];
#if FMT_MAIN_VERSION > 9
	private_subformat_data *pPriv = pFmt->private.data;
#else
	private_subformat_data *pPriv = &curdat;
#endif

	if (!strncmp(ciphertext, "$dynamic", 8)) {
		if (strstr(ciphertext, "$HEX$"))
			return RemoveHEX(out, ciphertext);
		return ciphertext;
	}
	if (!strncmp(ciphertext, "md5_gen(", 8)) {
		ciphertext += 8;
		do ++ciphertext; while (*ciphertext != ')')	;
		++ciphertext;
	}
	if (strstr(ciphertext, "$HEX$")) {
		char *cp = out + sprintf(out, "%s", pPriv->dynamic_WHICH_TYPE_SIG);
		RemoveHEX(cp, ciphertext);
	} else
		sprintf(out, "%s%s", pPriv->dynamic_WHICH_TYPE_SIG, ciphertext);

	return out;
}

// This split unifies case.
#if FMT_MAIN_VERSION > 9
static char *split_UC(char *ciphertext, int index, struct fmt_main *pFmt)
#else
static char *split_UC(char *ciphertext, int index)
#endif
{
	static char out[1024];
#if FMT_MAIN_VERSION > 9
	private_subformat_data *pPriv = pFmt->private.data;
#else
	private_subformat_data *pPriv = &curdat;
#endif

	if (!strncmp(ciphertext, "$dynamic", 8)) {
		if (strstr(ciphertext, "$HEX$"))
			RemoveHEX(out, ciphertext);
		else
			strcpy(out, ciphertext);
	} else {
		if (!strncmp(ciphertext, "md5_gen(", 8)) {
			ciphertext += 8;
			do ++ciphertext; while (*ciphertext != ')')	;
			++ciphertext;
		}
		if (strstr(ciphertext, "$HEX$")) {
			char *cp = out + sprintf(out, "%s", pPriv->dynamic_WHICH_TYPE_SIG);
			RemoveHEX(cp, ciphertext);
		} else
			sprintf(out, "%s%s", pPriv->dynamic_WHICH_TYPE_SIG, ciphertext);
	}
	ciphertext = strchr(&out[8], '$')+1;
	while (*ciphertext && *ciphertext != '$') {
		if (*ciphertext >= 'A' && *ciphertext <= 'Z')
			*ciphertext += 0x20; // ASCII specific, but I really do not care.
		++ciphertext;
	}
	return out;
}

/*********************************************************************************
 * Stores the new salt provided into our 'working' salt
 *********************************************************************************/
static void set_salt(void *salt)
{
	unsigned char *cpsalt;
	unsigned todo_bits=0, i, bit;
	if (!salt || curdat.dynamic_FIXED_SALT_SIZE == 0) {
		saltlen = 0;
		return;
	}
	cpsalt = *((unsigned char**)salt);
	saltlen = *cpsalt++ - '0';
	saltlen <<= 3;
	saltlen += *cpsalt++ - '0';
#if ARCH_ALLOWS_UNALIGNED
	if (*((ARCH_WORD_32*)cpsalt) != 0x30303030)
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

#ifdef MMX_COEF
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
#ifdef MMX_COEF
		if (dynamic_use_sse==1) {
			// code derived from rawMD5_fmt_plug.c code from magnum
			const ARCH_WORD_32 *key32 = (ARCH_WORD_32*)key;
			unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)(&(input_buf[idx])))[index&(MMX_COEF-1)];
			ARCH_WORD_32 *keybuf_word = keybuffer;
			unsigned int len;
			ARCH_WORD_32 temp;

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
					*keybuf_word = temp | (0x80 << 24);
					len+=3;
					goto key_cleaning;
				}
				*keybuf_word = temp;
				len += 4;
				keybuf_word += MMX_COEF;
			}
			*keybuf_word = 0x80;

key_cleaning:
			keybuf_word += MMX_COEF;
			while(*keybuf_word) {
				*keybuf_word = 0;
				keybuf_word += MMX_COEF;
			}
			keybuffer[14*MMX_COEF] = len << 3;
			return;
		}
		if (dynamic_use_sse==3) {
			// code derived from nsldap_fmt_plug.c code from magnum
			const ARCH_WORD_32 *key32 = (ARCH_WORD_32*)key;
			unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)(&(sinput_buf[idx])))[index&(MMX_COEF-1)];
			ARCH_WORD_32 *keybuf_word = keybuffer;
			unsigned int len;
			ARCH_WORD_32 temp;

#ifndef SHA1_SSE_PARA
			if (!index)
				memset(total_len, 0, sizeof(total_len));
#endif

			len = 0;
			while((temp = JOHNSWAP(*key32++)) & 0xff000000) {
				if (!(temp & 0xff0000))
				{
					*keybuf_word = (temp & 0xff000000) | 0x800000;
					++len;
					goto key_cleaning2;
				}
				if (!(temp & 0xff00))
				{
					*keybuf_word = (temp & 0xffff0000) | 0x8000;
					len+=2;
					goto key_cleaning2;
				}
				if (!(temp & 0xff))
				{
					*keybuf_word = temp | 0x80;
					len+=3;
					goto key_cleaning2;
				}
				*keybuf_word = temp;
				len += 4;
				keybuf_word += MMX_COEF;
			}
			*keybuf_word = 0x80000000;

key_cleaning2:
			keybuf_word += MMX_COEF;
			while(*keybuf_word) {
				*keybuf_word = 0;
				keybuf_word += MMX_COEF;
			}
#ifndef SHA1_SSE_PARA
			total_len[idx] += ( len << ( ( (32/MMX_COEF) * index ) ));
			saved_key_len[index] = len;
#else
			keybuffer[15*MMX_COEF] = len << 3;
#endif
			return;
		}
#endif
		len = strlen(key);
		if (len > 55) // we never do UTF-8 -> UTF-16 in this mode
			len = 55;

//		if(index==0) {
			// we 'have' to use full clean here. NOTE 100% sure why, but 10 formats fail if we do not.
//			DynamicFunc__clean_input_full();
//		}
#if MD5_X2
		if (index & 1)
			strnzcpy(input_buf_X86[index>>MD5_X2].x2.b2, key, len+1);
		else
#endif
			strnzcpy(input_buf_X86[index>>MD5_X2].x1.b, key, len+1);
		saved_key_len[index] = total_len_X86[index] = len;
	}
	else
	{
		len = strlen(key);
		if (len > 55 && !(fmt_Dynamic.params.flags & FMT_UNICODE))
			len = 55;
//		if(index==0) {
//			DynamicFunc__clean_input();
//		}
		keys_dirty = 1;
		strnzcpy(((char*)(saved_key[index])), key, len+1);
		saved_key_len[index] = len;
	}
}

static void clear_keys(void) {
#ifdef MMX_COEF
	if (curdat.pSetup->flags & MGF_FULL_CLEAN_REQUIRED) {
		DynamicFunc__clean_input_full();
		return;
	}
	if (curdat.store_keys_in_input==1 || curdat.store_keys_in_input==3)
		return;
	if (curdat.md5_startup_in_x86)
		DynamicFunc__clean_input_full();
	else
		DynamicFunc__clean_input_kwik();
#else
	DynamicFunc__clean_input_full();
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
#ifdef MMX_COEF
		//if (dynamic_use_sse==1) {
		// Note, if we are not in
		if (dynamic_use_sse && !curdat.md5_startup_in_x86) {
			unsigned int s;
			unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
//if (curdat.store_keys_in_input && dynamic_use_sse==1)

//			s = saved_key_len[index];  // NOTE, we now have to get the length from the buffer, we do NOT store it into a saved_key_len buffer.
			if (dynamic_use_sse==3) {
#ifndef SHA1_SSE_PARA
				s = saved_key_len[index];
#else
				ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)(&(sinput_buf[idx])))[index&(MMX_COEF-1)];
				s = keybuffer[15*MMX_COEF] >> 3;
#endif
				for(i=0;i<s;i++)
					out[i] = sinput_buf[idx][ SHAGETPOS(i, index&(MMX_COEF-1)) ];
			} else {
				ARCH_WORD_32 *keybuffer = &((ARCH_WORD_32 *)(&(input_buf[idx])))[index&(MMX_COEF-1)];
				s = keybuffer[14*MMX_COEF] >> 3;
				for(i=0;i<s;i++)
					out[i] = input_buf[idx][ GETPOS(i, index&(MMX_COEF-1)) ];
			}
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

		for(i=0;i<saved_key_len[index];++i)
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
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int cnt = ( ((unsigned)count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
			if(( *((ARCH_WORD_32 *)binary) == ((ARCH_WORD_32 *)&(crypt_key[i]))[0])
			|| ( *((ARCH_WORD_32 *)binary) == ((ARCH_WORD_32 *)&(crypt_key[i]))[1])
#if (MMX_COEF > 3)
			|| ( *((ARCH_WORD_32 *)binary) == ((ARCH_WORD_32 *)&(crypt_key[i]))[2])
			|| ( *((ARCH_WORD_32 *)binary) == ((ARCH_WORD_32 *)&(crypt_key[i]))[3])
#endif
			)
				return 1;
		}
		return 0;
	}
#endif
	for (i = 0; i < count; i++) {
#if MD5_X2
		if (i&1) {
			if (!(((ARCH_WORD_32 *)binary)[0] - crypt_key_X86[i>>MD5_X2].x2.w2[0]))
				return 1;
		}
		else
#endif
		if (!(((ARCH_WORD_32 *)binary)[0] - crypt_key_X86[i>>MD5_X2].x1.w[0]))
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
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned int cnt = ( ((unsigned)count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
			if(( *((ARCH_WORD_32 *)binary) == (((ARCH_WORD_32 *)&(crypt_key[i]))[0] & MASK_4x6))
			|| ( *((ARCH_WORD_32 *)binary) == (((ARCH_WORD_32 *)&(crypt_key[i]))[1] & MASK_4x6))
#if (MMX_COEF > 3)
			|| ( *((ARCH_WORD_32 *)binary) == (((ARCH_WORD_32 *)&(crypt_key[i]))[2] & MASK_4x6))
			|| ( *((ARCH_WORD_32 *)binary) == (((ARCH_WORD_32 *)&(crypt_key[i]))[3] & MASK_4x6))
#endif
			)
				return 1;
		}
		return 0;
	}
#endif
	for (i = 0; i < count; i++) {
#if MD5_X2
		if (i&1) {
			if (!(((ARCH_WORD_32 *)binary)[0] - (crypt_key_X86[i>>MD5_X2].x2.w2[0]&MASK_4x6)))
				return 1;
		}
		else
#endif
		if (!(((ARCH_WORD_32 *)binary)[0] - (crypt_key_X86[i>>MD5_X2].x1.w[0]&MASK_4x6)))
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
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		if( (((ARCH_WORD_32 *)binary)[0] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[0*MMX_COEF+(index&(MMX_COEF-1))]) &&
			(((ARCH_WORD_32 *)binary)[1] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[1*MMX_COEF+(index&(MMX_COEF-1))]) &&
			(((ARCH_WORD_32 *)binary)[2] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[2*MMX_COEF+(index&(MMX_COEF-1))]) &&
			(((ARCH_WORD_32 *)binary)[3] == ((ARCH_WORD_32 *)&(crypt_key[idx]))[3*MMX_COEF+(index&(MMX_COEF-1))]))
			return 1;
		return 0;
	}
#endif

#if MD5_X2
	if (index & 1) {
		if ( (((ARCH_WORD_32 *)binary)[0] == crypt_key_X86[index>>MD5_X2].x2.w2[0] ) &&
             (((ARCH_WORD_32 *)binary)[1] == crypt_key_X86[index>>MD5_X2].x2.w2[1] ) &&
             (((ARCH_WORD_32 *)binary)[2] == crypt_key_X86[index>>MD5_X2].x2.w2[2] ) &&
             (((ARCH_WORD_32 *)binary)[3] == crypt_key_X86[index>>MD5_X2].x2.w2[3] ) )
			 return 1;
		return 0;
	}
#endif
	if ( (((ARCH_WORD_32 *)binary)[0] == crypt_key_X86[index>>MD5_X2].x1.w[0] ) &&
		 (((ARCH_WORD_32 *)binary)[1] == crypt_key_X86[index>>MD5_X2].x1.w[1] ) &&
		 (((ARCH_WORD_32 *)binary)[2] == crypt_key_X86[index>>MD5_X2].x1.w[2] ) &&
		 (((ARCH_WORD_32 *)binary)[3] == crypt_key_X86[index>>MD5_X2].x1.w[3] ) )
		 return 1;
	return 0;
}
static int cmp_one_64_4x6(void *binary, int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		if( (((ARCH_WORD_32 *)binary)[0] == (((ARCH_WORD_32 *)&(crypt_key[idx]))[0*MMX_COEF+(index&(MMX_COEF-1))] & MASK_4x6)) &&
			(((ARCH_WORD_32 *)binary)[1] == (((ARCH_WORD_32 *)&(crypt_key[idx]))[1*MMX_COEF+(index&(MMX_COEF-1))] & MASK_4x6)) &&
			(((ARCH_WORD_32 *)binary)[2] == (((ARCH_WORD_32 *)&(crypt_key[idx]))[2*MMX_COEF+(index&(MMX_COEF-1))] & MASK_4x6)) &&
			(((ARCH_WORD_32 *)binary)[3] == (((ARCH_WORD_32 *)&(crypt_key[idx]))[3*MMX_COEF+(index&(MMX_COEF-1))] & MASK_4x6)))
			return 1;
		return 0;
	}
#endif
#if MD5_X2
	if (index & 1) {
		if ( (((ARCH_WORD_32*)binary)[0] == (crypt_key_X86[index>>MD5_X2].x2.w2[0] & MASK_4x6)) &&
			 (((ARCH_WORD_32*)binary)[1] == (crypt_key_X86[index>>MD5_X2].x2.w2[1] & MASK_4x6)) &&
			 (((ARCH_WORD_32*)binary)[2] == (crypt_key_X86[index>>MD5_X2].x2.w2[2] & MASK_4x6)) &&
			 (((ARCH_WORD_32*)binary)[3] == (crypt_key_X86[index>>MD5_X2].x2.w2[3] & MASK_4x6)) )
			return 1;
		return 0;
	}
#endif
	if ( (((ARCH_WORD_32*)binary)[0] == (crypt_key_X86[index>>MD5_X2].x1.w[0] & MASK_4x6)) &&
		 (((ARCH_WORD_32*)binary)[1] == (crypt_key_X86[index>>MD5_X2].x1.w[1] & MASK_4x6)) &&
		 (((ARCH_WORD_32*)binary)[2] == (crypt_key_X86[index>>MD5_X2].x1.w[2] & MASK_4x6)) &&
		 (((ARCH_WORD_32*)binary)[3] == (crypt_key_X86[index>>MD5_X2].x1.w[3] & MASK_4x6)) )
		return 1;
	return 0;
}

/*********************************************************************************
 *********************************************************************************
 *  This is the real 'engine'.  It simply calls functions one
 *  at a time from the array of functions.
 *********************************************************************************
 *********************************************************************************/
static void crypt_all(int count)
{
	int i;
	DYNAMIC_primitive_funcp *pFuncs;

	// set m_count.  This is our GLOBAL value, used by ALL of the script functions to know how
	// many keys are loaded, and how much work we do.
	m_count = count;
	eLargeOut = eBase16;

#ifdef MMX_COEF
	// If this format is MMX built, but is supposed to start in X86 (but be switchable), then we
	// set that value here.
	if (curdat.store_keys_in_input==2)
		dynamic_use_sse = 3;
	else if (curdat.md5_startup_in_x86)
		dynamic_use_sse = 2;
	else if (dynamic_use_sse==2)
		dynamic_use_sse = 1;
#endif

	md5_unicode_convert = 0;

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
		if (curdat.store_keys_normal_but_precompute_md5_to_output2)
		{
			keys_dirty = 0;
			DynamicFunc__clean_input2();
			if (curdat.store_keys_in_input_unicode_convert)
				md5_unicode_convert = 1;
			DynamicFunc__append_keys2();
			md5_unicode_convert = 0;
			DynamicFunc__crypt2_md5();

			if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1)
			{
				if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1==2)
					DynamicFunc__SSEtoX86_switch_output2();
				DynamicFunc__clean_input();
				DynamicFunc__append_from_last_output2_to_input1_as_base16();
			}
			if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32)
			{
#ifndef MMX_COEF
				if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32==2)
#endif
					DynamicFunc__SSEtoX86_switch_output2();
				DynamicFunc__clean_input();
				DynamicFunc__set_input_len_32();
				DynamicFunc__append_from_last_output2_to_input1_as_base16();
			}
		}
	}

	// Ok, now we 'run' the script. We simply call 1 function right after the other.
	// ALL functions are void f(void).  They use the globals:
	//   input_buf1[] input_buf2[]
	//   total_len1[] total_len2[]
	//   crypt1[] crypt2[]
	//   saved_key[]
	//   saved_key_len[]
	//   cursalt, cursalt2
	//   saltlen, saltlen2
	//   m_count
	//   nConsts
	//   Consts[], ConstsLen[]

	// Since this array is in a structure, we assign a simple pointer to it
	// before walking.  Trivial improvement, but every cycle counts :)
	pFuncs = curdat.dynamic_FUNCTIONS;
	for (i = 0; pFuncs[i]; ++i)
		(*(pFuncs[i]))();
}

/*********************************************************************************
 * 'normal' hashing functions
 *********************************************************************************/
extern char *MD5_DumpHexStr(void *p);
static int binary_hash_0(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xf; }
static int binary_hash_1(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xff; }
static int binary_hash_2(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfff; }
static int binary_hash_3(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffff; }
static int binary_hash_4(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xfffff; }
static int binary_hash_5(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0xffffff; }
static int binary_hash_6(void * binary) { return ((ARCH_WORD_32 *)binary)[0] & 0x7ffffff; }

#if !ARCH_LITTLE_ENDIAN
// the lower 8 bits is zero on the binary (but filled in on the hash).  We need to dump the low 8
static int binary_hash_0_64x4(void * binary) { return (((ARCH_WORD_32 *)binary)[0]>>8) & 0xf; }
static int binary_hash_1_64x4(void * binary) { return (((ARCH_WORD_32 *)binary)[0]>>8) & 0xff; }
static int binary_hash_2_64x4(void * binary) { return (((ARCH_WORD_32 *)binary)[0]>>8) & 0xfff; }
static int binary_hash_3_64x4(void * binary) { return (((ARCH_WORD_32 *)binary)[0]>>8) & 0xffff; }
static int binary_hash_4_64x4(void * binary) { return (((ARCH_WORD_32 *)binary)[0]>>8) & 0xfffff; }
static int binary_hash_5_64x4(void * binary) { return (((ARCH_WORD_32 *)binary)[0]>>8) & 0xffffff; }
int get_hash_0_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & 0xf;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & 0xf;}
int get_hash_1_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & 0xff;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & 0xff;}
int get_hash_2_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & 0xfff;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & 0xfff;}
int get_hash_3_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & 0xffff;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & 0xffff;}
int get_hash_4_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & 0xfffff;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & 0xfffff;}
int get_hash_5_64x4(int index) {
#if MD5_X2
	if (index & 1) return (crypt_key_X86[index>>MD5_X2].x2.w2[0]>>8) & 0xffffff;
#endif
	return (crypt_key_X86[index>>MD5_X2].x1.w[0]>>8) & 0xffffff;}


#endif

int get_hash_0(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xf;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0xf;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0xf;
}

int get_hash_1(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xff;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0xff;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0xff;
}

int get_hash_2(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xfff;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0xfff;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0xfff;
}

int get_hash_3(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xffff;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0xffff;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0xffff;
}
int get_hash_4(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xfffff;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0xfffff;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0xfffff;
}
int get_hash_5(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0xffffff;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0xffffff;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0xffffff;
}
int get_hash_6(int index)
{
#ifdef MMX_COEF
	if (dynamic_use_sse&1) {
		unsigned int idx = ( ((unsigned)index)>>(MMX_COEF>>1));
		return ((ARCH_WORD_32 *)&(crypt_key[idx]))[index&(MMX_COEF-1)] & 0x7ffffff;
	}
#endif
#if MD5_X2
	if (index & 1)
		return crypt_key_X86[index>>MD5_X2].x2.w2[0] & 0x7ffffff;
#endif
	return crypt_key_X86[index>>MD5_X2].x1.w[0] & 0x7ffffff;
}


/************************************************************************
 * We now fully handle all hashing of salts, here in the format. We
 * return a pointer ot an allocated salt record. Thus, we search all
 * of the salt records, looking for the same salt.  If we find it, we
 * want to return THAT pointer, and not allocate a new pointer.
 * This works great, but forces us to do salt comparision here.
 ***********************************************************************/
#define DYNA_SALT_HASH_BITS 15
#define DYNA_SALT_HASH_SIZE (1<<DYNA_SALT_HASH_BITS)
#define DYNA_SALT_HASH_MOD  (DYNA_SALT_HASH_SIZE-1)

typedef struct dyna_salt_list_entry {
	struct dyna_salt_list_entry *next;
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

static unsigned char *AddSaltHash(unsigned char *salt, unsigned len, unsigned int idx) {
	unsigned char *pRet;
	if (dyna_salt_list_count == 0) {
		pSaltHashDataNext = pSaltHashData = mem_calloc_tiny(sizeof(dyna_salt_list_entry) * 25000, MEM_ALIGN_WORD);
		dyna_salt_list_count = 25000;
	}
	if (nSaltDataBuf < len) {
		pSaltDataBuf = pNextSaltDataBuf = mem_alloc_tiny(MEM_ALLOC_SIZE*6, MEM_ALIGN_NONE);
		nSaltDataBuf = MEM_ALLOC_SIZE*6;
	}
	pRet = pNextSaltDataBuf;
	pSaltHashDataNext->salt = pNextSaltDataBuf;
	memcpy(pSaltHashDataNext->salt, salt, len);
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
static unsigned char *FindSaltHash(unsigned char *salt, unsigned len, u32 crc) {
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
		if (!memcmp((char*)salt, (char*)p->salt, len)) {
			return p->salt;  // found it!  return this one, so we do not allocate another.
		}
		p = p->next;
	}
	return AddSaltHash(salt, len, idx);
}
static unsigned char *HashSalt(unsigned char *salt, unsigned len) {
	u32 crc = 0xffffffff, i;
	unsigned char *ret_hash;

	// compute the hash.
	for (i = 0; i < len; ++i)
		crc = pkzip_crc32(crc,salt[i]);
	crc = ~crc;

	ret_hash = FindSaltHash(salt, len, crc);
	return ret_hash;
}
static int ConvertFromHex(unsigned char *p, int len) {
	unsigned char *cp;
	int i, x;
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
static unsigned salt_external_to_internal_convert(unsigned char *extern_salt, unsigned char *Buffer) {
	// Ok, we get this:   extern_salt = salt_data$$2salt2$$Uuser ...  where anything can be missing or in any order
	// the any order has 1 exception of salt_data MUST be first.  So if we get $$2salt2, then we know there is no salt-1 value.
	unsigned char *salt2=0, *userid=0, *Flds[10];
	int i, nsalt2=0, nuserid=0, nFlds[10]={0,0,0,0,0,0,0,0,0,0};
	unsigned char len = strlen((char*)extern_salt), bit;
	unsigned bit_array=0;
	unsigned the_real_len = 6;  // 2 bytes base-8 length, and 4 bytes base-8 bitmap.

	// work from back of string to front, looking for the $$X signatures.
	for (i = len-3; i >= 0; --i) {
		if (extern_salt[i] == '$' && extern_salt[i+1] == '$') {
			// a 'likely' extra salt value.
			switch(extern_salt[i+2]) {
				case '2':
					salt2 = &extern_salt[i+3];
					nsalt2 = strlen((char*)salt2);
					nsalt2 = ConvertFromHex(salt2, nsalt2);
					extern_salt[i] = 0;
					bit_array |= 1;
					the_real_len += (nsalt2+1);
					break;
				case 'U':
					userid = &extern_salt[i+3];
					nuserid = strlen((char*)userid);
					nuserid = ConvertFromHex(userid, nuserid);
					extern_salt[i] = 0;
					bit_array |= 2;
					the_real_len += (nuserid+1);
					break;
				case 'F': {
					if (extern_salt[i+3] >= '0' && extern_salt[i+3] <= '9') {
						Flds[extern_salt[i+3]-'0'] = &extern_salt[i+4];
						nFlds[extern_salt[i+3]-'0'] = strlen((char*)(Flds[extern_salt[i+3]-'0']));
						nFlds[extern_salt[i+3]-'0'] = ConvertFromHex(Flds[extern_salt[i+3]-'0'], nFlds[extern_salt[i+3]-'0']);
						extern_salt[i] = 0;
						bit_array |= (1<<(2+extern_salt[i+3]-'0'));
						the_real_len += (nFlds[extern_salt[i+3]-'0']+1);
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
static void *salt(char *ciphertext)
{
	char Salt[SALT_SIZE+1], saltIntBuf[SALT_SIZE+1];
	int off, possible_neg_one=0;
	unsigned char *saltp;
	unsigned the_real_len;
	static union x {
		unsigned char salt_p[sizeof(unsigned char*)];
		unsigned long p[1];
	} union_x;

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

	if (ciphertext[off] == '$' && (ciphertext[off+1]=='U' ||
		                          (ciphertext[off+1]=='F' && ciphertext[off+2]>='0' && ciphertext[off+2]<='9') ||
								   ciphertext[off+1]=='2') )
		possible_neg_one = -1;
	strnzcpy(Salt, &ciphertext[off + possible_neg_one], SALT_SIZE);

	if (curdat.dynamic_salt_as_hex)
	{
		// Do not 'worry' about SSE/MMX,  Only do 'generic' md5.  This is ONLY done
		// at the start of the run.  We will NEVER see this run, once john starts.
		MD5_CTX ctx;
		unsigned char Buf[16];
		unsigned char *cpo, *cpi, i;
		unsigned slen=strlen(Salt);
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
			cpo = (unsigned char *)&Salt[slen+3];
		}
		else {
			cpo = (unsigned char*)Salt;
			memset(Salt, 0, SALT_SIZE+1);
		}
		cpi = Buf;
		for (i = 0; i < 16; ++i)
		{
			*cpo++ = dynamic_itoa16[(*cpi)>>4];
			*cpo++ = dynamic_itoa16[(*cpi)&0xF];
			++cpi;
		}
		*cpo = 0;
	}
	if (curdat.dynamic_hdaa_salt) {
		//=$dynamic_1060$679066476e67b5c7c4e88f04be567f8b$8c12bd8f728afe56d45a0ce846b70e5a$$Uuser$$F2myrealm$$F3GET$/$$F400000001$4b61913cec32e2c9$auth:nocode
		//digest authentication scheme :
		//H1 = md5(user:realm:password)
		//H2 = md5(method:digestURI)
		//response = H3 = md5(h1:nonce:nonceCount:ClientNonce:qop:h2)

		// salt is:
		//8c12bd8f728afe56d45a0ce846b70e5a$$Uuser$$F2myrealm$$F3GET$/$$F400000001$4b61913cec32e2c9$auth
		//change this to:  (abcd is base-64 number)
		//abcd                            :8c12bd8f728afe56d45a0ce846b70e5a:00000001:4b61913cec32e2c9:auth:H1$$Uuser$$F2myrealm

		unsigned char *cp2, *cp3, *cp4, *cpTmp = mem_alloc(strlen(Salt) + 200);  // larger than needed, 100% assured.
		unsigned char *cpU2 = mem_alloc(strlen(Salt));
		static unsigned cnt = 1;
		unsigned i, j;
		MD5_CTX ctx;
		unsigned char Buf[16], h1_input[64];

		memset(cpTmp, ' ', 33);

		j = cnt++;
		cp2 = cpTmp;
		for (i = 0; i < 4; ++i) {
			*cp2++ = itoa64[j%64];
			j /= 64;
		}
		cp3 = (unsigned char*)strstr(Salt, "$$U");
		*cp3++ = 0;
		cp2 = cpU2;
		*cp2++ = '$';
		while (strncmp((char*)cp3, "$$F3", 4))
			*cp2++ = *cp3++;
		*cp2 = 0;
		cp2 = &cpTmp[32];
		*cp2++ = ':';
		strcpy((char*)cp2, Salt);
		cp2 += strlen((char*)cp2);
		*cp2++ = ':';
		cp4 = h1_input;
		cp3 += 4;
		while (strncmp((char*)cp3, "$$F4", 4)) {
			if (*cp3 == '$') { *cp4++ = ':'; ++cp3; continue; }
			*cp4++ = *cp3++;
		}
		*cp4 = 0;
		MD5_Init(&ctx);
		MD5_Update(&ctx, h1_input, strlen((char*)h1_input));
		MD5_Final(Buf, &ctx);

		cp3 += 4;
		while (*cp3) {
			if (*cp3 == '$') { *cp2++ = ':'; ++cp3; continue; }
			*cp2++ = *cp3++;
		}
		*cp2++ = ':';
		cp3 = Buf;
		for (i = 0; i < 16; ++i)
		{
			*cp2++ = dynamic_itoa16[(*cp3)>>4];
			*cp2++ = dynamic_itoa16[(*cp3)&0xF];
			++cp3;
		}
		*cp2 = 0;
		strcat((char*)cpTmp, (char*)cpU2);
		strcpy(Salt, (char*)cpTmp);
		MEM_FREE(cpU2);
		MEM_FREE(cpTmp);
	}

	the_real_len = salt_external_to_internal_convert((unsigned char*)Salt, (unsigned char*)saltIntBuf);

	// Now convert this into a stored salt, or find the 'already' stored same salt.
	saltp = HashSalt((unsigned char*)saltIntBuf, the_real_len);
	memcpy(union_x.salt_p, &saltp, sizeof(saltp));
	return union_x.salt_p;
}
/*********************************************************************************
 * 'special' get salt function for phpass. We return the 8 bytes salt, followed by
 * the 1 byte loop count.  'normally' in phpass format, that order is reversed.
 * we do it this way, since our 'primitive' functions would not know to treat the
 * salt any differently for phpass.  Thus the primitives are told about the first
 * 8 bytes (and not the full 9).  But the phpass crypt function uses that 9th byte.
 *********************************************************************************/
static void *salt_phpass(char *ciphertext)
{
	unsigned char salt[20], *saltp;
	static union x {
		unsigned char salt_p[sizeof(unsigned char*)];
		unsigned long p[1];
	} union_x;

	if (!strncmp(ciphertext, "$dynamic_", 9)) {
		ciphertext += 9;
		while (*ciphertext != '$')
			++ciphertext;
	}
	sprintf((char*)salt, "100000%8.8s%c", &ciphertext[25], ciphertext[24]);

	// Now convert this into a stored salt, or find the 'already' stored same salt.
	saltp = HashSalt(salt, 15);
	memcpy(union_x.salt_p, &saltp, sizeof(saltp));
	return union_x.salt_p;
}

/*********************************************************************************
 * Now our salt is returned only as a pointer.  We
 *********************************************************************************/
static int salt_hash(void *salt)
{
	unsigned long H;
	if (!salt) return 0;
	if ( (curdat.pSetup->flags&MGF_SALTED) == 0)
		return 0;

	// salt is now a pointer, but WORD aligned.  We remove that word alingment, and simply use the next bits
	H = *((unsigned long*)salt);

	// Mix up the pointer value (H^(H>>9)) so that if we have a fixed sized allocation
	// that things do get 'stirred' up better.
	return ( (H^(H>>9)) & (SALT_HASH_SIZE-1) );
}

/*********************************************************************************
 * Gets the binary value from a base-16 hash.
 *********************************************************************************/
static void *binary(char *_ciphertext)
{
	static char *realcipher;
	int i;
	char *ciphertext = _ciphertext;

	if (!realcipher) realcipher = mem_alloc_tiny(BINARY_SIZE_SHA, MEM_ALIGN_WORD);

	if (!strncmp(_ciphertext, "$dynamic_", 9)) {
		ciphertext += 9;
		while (*ciphertext++ != '$')
			;
	}

	for(i=0;i<BINARY_SIZE;i++)
	{
		realcipher[i] =
			atoi16[ARCH_INDEX(ciphertext[i*2])]*16 +
			atoi16[ARCH_INDEX(ciphertext[i*2+1])];
	}
	return (void *)realcipher;
}

#if FMT_MAIN_VERSION > 9
// NOTE NOTE NOTE, we have currently ONLY implemented a non-salted function!!!
static char *source(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 16; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}

static char *source_sha(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 20; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
static char *source_sha224(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 28; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
static char *source_sha256(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 32; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
static char *source_sha384(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 48; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
static char *source_sha512(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 64; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
static char *source_gost(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 32; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
static char *source_whirlpool(char *source, void *binary)
{
	static char Buf[256];
	unsigned char *cpi= (unsigned char*)(binary);
	char *cpo = Buf;
	int i;

	cpo += sprintf(Buf, "%s", curdat.dynamic_WHICH_TYPE_SIG);
	for (i = 0; i < 64; ++i) {
		*cpo++ = itoa16[(*cpi)>>4];
		*cpo++ = itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return Buf;
}
#endif

/*********************************************************************************
 * Gets the binary value from a base-64 hash (such as phpass)
 *********************************************************************************/
static void * binary_b64(char *ciphertext)
{
	int i;
	unsigned sixbits;
	static unsigned char b[16];
	int bidx=0;
	char *pos;

	// ugly code, but only called one time (at program load,
	// once for each candidate pass hash).

	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
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

#define TO_BINARY(b1, b2, b3) \
	value = \
		(MD5_word)atoi64[ARCH_INDEX(pos[0])] | \
		((MD5_word)atoi64[ARCH_INDEX(pos[1])] << 6) | \
		((MD5_word)atoi64[ARCH_INDEX(pos[2])] << 12) | \
		((MD5_word)atoi64[ARCH_INDEX(pos[3])] << 18); \
	pos += 4; \
	b[b1] = value >> 16; \
	b[b2] = value >> 8; \
	b[b3] = value;
static void * binary_b64a(char *ciphertext)
{
	static unsigned char b[16];
	char *pos;
	MD5_word value;

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
		(MD5_word)atoi64[ARCH_INDEX(pos[0])] |
		((MD5_word)atoi64[ARCH_INDEX(pos[1])] << 6);

	MD5_swap((MD5_word*)b,(MD5_word*)b, 4);
	return b;
}

/*********************************************************************************
 * Gets the binary value from a base-64 hash (such as cisco PIX)
 *********************************************************************************/
static void * binary_b64_4x6(char *ciphertext)
{
	static ARCH_WORD_32 b[4];
	int i;
	char *pos;

	pos = ciphertext;
	if (!strncmp(pos, "$dynamic_", 9)) {
		pos += 9;
		while (*pos++ != '$')
			;
	}
	for(i = 0; i < 4; i++) {
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
 * Here is the main mdg_generic fmt_main. NOTE in it's default settings, it is
 * ready to handle base-16 hashes.  The phpass stuff will be linked in later, IF
 * needed.
 *********************************************************************************/
struct fmt_main fmt_Dynamic =
{
	{
		FORMAT_LABEL,
		FORMAT_NAME,
#ifdef MMX_COEF
		ALGORITHM_NAME,
#else
		ALGORITHM_NAME_X86,
#endif
		BENCHMARK_COMMENT,
		BENCHMARK_LENGTH,
#ifdef MMX_COEF
		PLAINTEXT_LENGTH,
#else
		PLAINTEXT_LENGTH_X86,
#endif
		BINARY_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
		SALT_SIZE,
#if FMT_MAIN_VERSION > 9
		DEFAULT_ALIGN,
#endif
#ifdef MMX_COEF
		MIN_KEYS_PER_CRYPT,
		MAX_KEYS_PER_CRYPT,
#else
		MIN_KEYS_PER_CRYPT_X86,
		MAX_KEYS_PER_CRYPT_X86,
#endif
		FMT_CASE | FMT_8_BIT,
		dynamic_tests
	}, {
		init,
		prepare,
		valid,
		split,
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

#ifdef MMX_COEF


/**************************************************************
 **************************************************************
 *  Here are some 'helpers' to our helpers, when it comes to
 *  loading data into the mmx/sse buffers.  We have several
 *  of these common helper functions, and use them in 'most'
 *  of the helper primatives, instead of having the same
 *  code being inlined in each of them.
 **************************************************************
 *************************************************************/

static void __SSE_Load_itoa16_w2()
{
	char buf[3];
	int i;
	for (i = 0; i < 256; ++i)
	{
		sprintf(buf, "%X%X", i>>4, i&0xF);
		memcpy(&(itoa16_w2_u[i]), buf, 2);
		sprintf(buf, "%x%x", i>>4, i&0xF);
		memcpy(&(itoa16_w2_l[i]), buf, 2);
	}
}

//**************************************************************************************
// output -> base16 -> input.
//
//  IPB points to input buffer (&input1[idx] or &input2[idx]).  idx is count/MMX_COEF.
//      Caller computes right buffer
//  CRY is pointer to the crypt buffer (&crypt1[idx] or crypt2[idx])
//  idx_mod is count%MMX_COEF
//**************************************************************************************
#if (LOW_BASE16_INPUT_TYPE==1) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_1(ARCH_WORD_32 *IPBdw, unsigned char *CRY, unsigned idx_mod)
{
	// #1
    // 6040K  (core2, $dynamic_2$)
    // 1576K  (core2, $dynamic_1006$)
	// 3392K  (ath64, $dynamic_2$)
	// 827.3K (ath64, $dynamic_1006$)
#if (MMX_COEF==4)
#  define inc 4
#  define incCRY 12
#else
#  define inc 2
#  define incCRY 4
#endif
	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	CRY += (idx_mod<<2);

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);

	// Add the 0x80 at the proper location (offset 0x21)
	IPBdw += inc;
	*IPBdw = 0x80;
#undef inc
#undef incCRY
}
#endif

#if (LOW_BASE16_INPUT_TYPE==2) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_2(ARCH_WORD_32 *IPBdw, unsigned char *CRY, unsigned idx_mod)
{
	// #2
    // 6083k  (core2, $dynamic_2$)
    // 1590K  (core2, $dynamic_1006$)
	// 3537K  (ath64, $dynamic_2$)
	// 890.3K (ath64, $dynamic_1006$)
#undef inc
#if (MMX_COEF==4)
#define inc 4
#  define incCRY 14
#else
#define inc 2
#  define incCRY 6
#endif

	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	CRY += (idx_mod<<2);

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);

	// Add the 0x80 at the proper location (offset 0x21)
	IPBdw += inc;
	*IPBdw = 0x80;
#undef inc
#undef incCRY
}
#endif

#if (LOW_BASE16_INPUT_TYPE==3) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_3(unsigned short *IPBw, unsigned char *CRY, unsigned idx_mod)
{
	// #3
    // 5955K  (core2, $dynamic_2$)
    // 1565K  (core2, $dynamic_1006$)
	// 3381K  (ath64, $dynamic_2$)
	// 824.7k (ath64, $dynamic_1006$)
#undef inc
#if (MMX_COEF==4)
#define inc 6
#else
#define inc 2
#endif
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
#endif

static void __SSE_overwrite_output_base16_to_input(unsigned short *IPBw, unsigned char *CRY, unsigned idx_mod)
{
	// #3
    // 5955K  (core2, $dynamic_2$)
    // 1565K  (core2, $dynamic_1006$)
	// 3381K  (ath64, $dynamic_2$)
	// 824.7k (ath64, $dynamic_1006$)
#undef inc
#if (MMX_COEF==4)
#define inc 6
#else
#define inc 2
#endif
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

#if (LOW_BASE16_INPUT_SEMI0_TYPE==1) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_semi_aligned0_1(unsigned ip, ARCH_WORD_32* IPBdw, unsigned char *CRY, unsigned idx_mod)
{
	// #1
    // 6083k  (core2, $dynamic_9$)
    // 1590K  (core2, $dynamic_10$)
	// 3537K  (ath64, $dynamic_9$)
	// 890.3K (ath64, $dynamic_10$)
#if (MMX_COEF==4)
# define inc 4
# define incCRY 12
#else
# define inc 2
# define incCRY 4
#endif
	IPBdw += idx_mod;
	IPBdw += (ip>>2)*MMX_COEF;

	CRY += (idx_mod<<2);

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	CRY += incCRY;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);

	// Add the 0x80 at the proper location (offset 0x21)
	IPBdw += inc;
	*IPBdw = 0x80;
#undef inc
#undef incCRY
}
#endif

#if (LOW_BASE16_INPUT_SEMI2_TYPE==1) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_semi_aligned2_1(unsigned ip, ARCH_WORD_32 *IPBdw, unsigned char *CRY, unsigned idx_mod)
{
	// #1
    // 9586k/4740k  (core2, $dynamic_9$)
    // 5113k/4382k  (core2,$dynamic_10$)
	//  (ath64, $dynamic_9$)
	//  (ath64, $dynamic_10$)
#if (MMX_COEF==4)
# define inc 4
# define incCRY 12
#else
# define inc 2
# define incCRY 4
#endif
	// Ok, here we are 1/2 off. We are starting in the 'middle' of a DWORD (and end
	// in the middle of the last one).

	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	IPBdw += (ip>>2)*MMX_COEF;

	CRY += (idx_mod<<2);

	// first byte handled here.
	*IPBdw &= 0xFFFF;
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	CRY += incCRY;
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	CRY += incCRY;
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);
	CRY += incCRY;
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;

	*IPBdw = (itoa16_w2[*CRY++]);
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY++]))<<16);
	IPBdw += inc;
	*IPBdw = (itoa16_w2[*CRY++]);

	// Add the 0x80 at the proper location (offset 0x21)
	*IPBdw |= 0x800000;

#undef inc
#undef incCRY
}
#endif

#if (LOW_BASE16_INPUT_SEMI0_TYPE==2) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_semi_aligned0_2(unsigned ip, ARCH_WORD_32 *IPBdw, unsigned char *CRY, unsigned idx_mod)
{
	// #2
    // 6083k  (core2, $dynamic_2$)
    // 1590K  (core2, $dynamic_1006$)
	// 3537K  (ath64, $dynamic_2$)
	// 890.3K (ath64, $dynamic_1006$)
#undef inc
#if (MMX_COEF==4)
#define inc 4
//# define incCRY 12
# define incCRY 14
#else
#define inc 2
# define incCRY 6
#endif


	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	IPBdw += (ip>>2)*MMX_COEF;
	CRY += (idx_mod<<2);

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
//	CRY += (inc*3)+2;
	CRY += incCRY;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
//	CRY += (inc*3)+2;
	CRY += incCRY;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
//	CRY += (inc*3)+2;
	CRY += incCRY;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);
	IPBdw += inc;
	CRY += 2;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+1)]))<<16)|(itoa16_w2[*CRY]);

	// Add the 0x80 at the proper location (offset 0x21)
	IPBdw += inc;
	*IPBdw = 0x80;
#undef inc
#undef incCRY
}
#endif

#if (LOW_BASE16_INPUT_SEMI2_TYPE==2) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_semi_aligned2_2(unsigned ip, ARCH_WORD_32 *IPBdw, unsigned char *CRY, unsigned idx_mod)
{
	// #2
    // 10375k/4902k (core2, $dynamic_9$)
    // 5263k/4502k  (core2, $dynamic_10$)
	//  (ath64, $dynamic_9$)
	//  (ath64, $dynamic_10$)
#undef inc
#if (MMX_COEF==4)
#define inc 4
#define incCRY 16
#else
#define inc 2
#define incCRY 8
#endif
	// Ok, here we are 1/2 off. We are starting in the 'middle' of a DWORD (and end
	// in the middle of the last one).

	// start our pointers out at the right 32 bit offset into the first MMX/SSE buffer
	IPBdw += idx_mod;
	IPBdw += (ip>>2)*MMX_COEF;

	CRY += (idx_mod<<2);

	// first byte handled here.
	*IPBdw &= 0xFFFF;
	*IPBdw |= (((ARCH_WORD_32)(itoa16_w2[*CRY]))<<16);
	IPBdw += inc;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+2)]))<<16)|(itoa16_w2[*(CRY+1)]);
	IPBdw += inc;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+incCRY)]))<<16)|(itoa16_w2[*(CRY+3)]);
	CRY += incCRY;
	IPBdw += inc;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+2)]))<<16)|(itoa16_w2[*(CRY+1)]);
	IPBdw += inc;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+incCRY)]))<<16)|(itoa16_w2[*(CRY+3)]);
	CRY += incCRY;
	IPBdw += inc;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+2)]))<<16)|(itoa16_w2[*(CRY+1)]);
	IPBdw += inc;
	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+incCRY)]))<<16)|(itoa16_w2[*(CRY+3)]);
	CRY += incCRY;
	IPBdw += inc;

	*IPBdw = (((ARCH_WORD_32)(itoa16_w2[*(CRY+2)]))<<16)|(itoa16_w2[*(CRY+1)]);
	IPBdw += inc;
	*IPBdw = (0x80<<16)|(itoa16_w2[*(CRY+3)]);

#undef inc
#undef incCRY
}
#endif

#if (LOW_BASE16_INPUT_SEMI0_TYPE==3) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_semi_aligned0_3(unsigned ip, unsigned short *IPBw, unsigned char *CRY, unsigned idx_mod)
{
	// #3
    // 5955K  (core2, $dynamic_2$)
    // 1565K  (core2, $dynamic_1006$)
	// 3381K  (ath64, $dynamic_2$)
	// 824.7k (ath64, $dynamic_1006$)
#undef inc
#if (MMX_COEF==4)
#define inc 6
#else
#define inc 2
#endif
	IPBw += (idx_mod<<1);
	IPBw += (ip>>1)*MMX_COEF;
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
#endif

#if (LOW_BASE16_INPUT_SEMI2_TYPE==3) || defined (DEEP_TIME_TEST)
static void __SSE_append_output_base16_to_input_semi_aligned2_3(unsigned ip, unsigned short *IPBw, unsigned char *CRY, unsigned idx_mod)
{
	// #3
    // 9398k/4588k  (core2, $dynamic_2$)
    // 4825k/4186k  (core2, $dynamic_1006$)
	//  (ath64, $dynamic_2$)
	//  (ath64, $dynamic_1006$)
#undef inc
#if (MMX_COEF==4)
#define inc 6
#else
#define inc 2
#endif
	IPBw += (idx_mod<<1);
	IPBw += ((ip>>2)*MMX_COEF)<<1;
	CRY += (idx_mod<<2);

	++IPBw;

	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	CRY += (inc<<1);

	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];
	*IPBw++ = itoa16_w2[*CRY++];
	IPBw += inc;
	*IPBw++ = itoa16_w2[*CRY++];

	*IPBw = 0x80;
#undef inc
}
#endif

static void __SSE_append_string_to_input_unicode(unsigned char *IPB, unsigned idx_mod, unsigned char *cp, unsigned len, unsigned bf_ptr, unsigned bUpdate0x80)
{
	unsigned char *cpO;
#if ARCH_LITTLE_ENDIAN
	// if big-endian, we gain nothing from this function (since we would have to byte swap)
    if (len>1&&!(bf_ptr&1))
    {
        unsigned w32_cnt;
		if(bf_ptr&2) {
			cpO = &IPB[GETPOS(bf_ptr, idx_mod)];
			bf_ptr += 2;
			*cpO = *cp++;
			cpO[1] = 0;
			--len;
		}
		w32_cnt = len>>1;
        if (w32_cnt)
        {
            ARCH_WORD_32 *wpO;
            wpO = (ARCH_WORD_32*)&IPB[GETPOS(bf_ptr, idx_mod)];
            len -= (w32_cnt<<1);
            bf_ptr += (w32_cnt<<2);
            do
            {
				ARCH_WORD_32 x = 0;
                x = cp[1];
				x <<= 16;
				x += cp[0];
				*wpO = x;
                cp += 2;
                wpO += MMX_COEF;
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
			cpO += ((MMX_COEF-1)*4);
		*cpO++ = 0;
		if ( ((++bf_ptr)&3) == 0)
			cpO += ((MMX_COEF-1)*4);
	}
	if (bUpdate0x80)
		*cpO = 0x80;

}

static void __SSE_append_string_to_input(unsigned char *IPB, unsigned idx_mod, unsigned char *cp, unsigned len, unsigned bf_ptr, unsigned bUpdate0x80)
{
	unsigned char *cpO;
	// if our insertion point is on an 'even' DWORD, then we use DWORD * copying, as long as we can
	// This provides quite a nice speedup.
#if ARCH_LITTLE_ENDIAN
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
        unsigned w32_cnt = len>>2;
        if (w32_cnt)
        {
            ARCH_WORD_32 *wpO;
            wpO = (ARCH_WORD_32*)&IPB[GETPOS(bf_ptr, idx_mod)];
            len -= (w32_cnt<<2);
            bf_ptr += (w32_cnt<<2);
            do
            {
                *wpO = *((ARCH_WORD_32*)cp);
                cp += 4;
                wpO += MMX_COEF;
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
			cpO += ((MMX_COEF-1)*4);
	}
	if (bUpdate0x80)
		*cpO = 0x80;
}

#ifdef DEEP_TIME_TEST
#include "timer.h"

static int __SSE_gen_BenchLowLevMD5(unsigned secs, unsigned which)
{
#ifndef CLK_TCK
	return 0;
#else
	int i;
	unsigned cnt=0;
	clock_t til;
	sTimer Timer;
	double d;

	til = clock();
	til += secs*CLK_TCK;
	m_count = 100;

	store_keys_in_input = 1;

	for (i = 0; i < BLOCK_LOOPS-2; ++i)
	{
		char Pass[40];
		sprintf(Pass, "Sample Password %d - %d", cnt, i);
		fmt_Dynamic.methods.set_key(Pass, i);
	}
	DynamicFunc__clean_input();
	DynamicFunc__clean_input2();
	DynamicFunc__append_keys();
	DynamicFunc__crypt_md5();
	DynamicFunc__append_keys2();
	DynamicFunc__crypt2_md5();

	sTimer_sTimer(&Timer);
	sTimer_Start(&Timer, 1);

	while (clock() < til)
	{
		++cnt;
		switch(which)
		{
			case 1:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_1((void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_1((void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 2:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_2((void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_2((void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 3:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_3((void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_3((void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 4:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_semi_aligned0_1(8, (void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_semi_aligned0_1(8, (void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 5:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_semi_aligned0_2(8, (void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_semi_aligned0_2(8, (void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 6:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_semi_aligned0_3(8, (void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_semi_aligned0_3(8, (void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 7:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_semi_aligned2_1(10, (void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_semi_aligned2_1(10, (void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 8:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_semi_aligned2_2(10, (void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_semi_aligned2_2(10, (void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
			case 9:
				for (i = 0; i<100; i++)
				{
					__SSE_append_output_base16_to_input_semi_aligned2_3(10, (void*)(&input_buf[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
					__SSE_append_output_base16_to_input_semi_aligned2_3(10, (void*)(&input_buf2[i>>(MMX_COEF>>1)]), (unsigned char*)(&crypt_key2[i>>(MMX_COEF>>1)]), i&(MMX_COEF-1));
				}
				break;
		}
	}
	d = cnt;
	d *= 100;
	d /= sTimer_GetSecs(&Timer);


	DynamicFunc__clean_input();
	DynamicFunc__clean_input2();
	fmt_Dynamic.methods.set_key("", 0);

	return (int)d;
#endif
}

static void __SSE_gen_BenchLowLevelFunctions()
{
#ifdef CLK_TCK
	unsigned cnt;
	extern unsigned int benchmark_time;

	printf ("\n\nBenchmarking Low Level generic-md5 conversion functions (smaller is faster)\n");
	if (benchmark_time > 3600)
		benchmark_time = 3600;
	// I am simply going to use the 'emu' time, using clock() function.  If
	// a compiler does not have CLK_TCK defined (they define CLK_TCK CLOCKS_PER_SEC)
	// then this function will never be run.  Sorry, it works for me.

	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 1);
	printf ("%u runs of __SSE_append_output_base16_to_input_1\n", cnt);
	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 2);
	printf ("%u runs of __SSE_append_output_base16_to_input_2\n", cnt);
	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 3);
	printf ("%u runs of __SSE_append_output_base16_to_input_3\n\n", cnt);

	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 4);
	printf ("%u runs of __SSE_append_output_base16_to_input_semi_aligned0_1\n", cnt);
	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 5);
	printf ("%u runs of __SSE_append_output_base16_to_input_semi_aligned0_2\n", cnt);
	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 6);
	printf ("%u runs of __SSE_append_output_base16_to_input_semi_aligned0_3\n\n", cnt);

	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 7);
	printf ("%u runs of __SSE_append_output_base16_to_input_semi_aligned2_1\n", cnt);
	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 8);
	printf ("%u runs of __SSE_append_output_base16_to_input_semi_aligned2_2\n", cnt);
	cnt = __SSE_gen_BenchLowLevMD5(benchmark_time, 9);
	printf ("%u runs of __SSE_append_output_base16_to_input_semi_aligned2_3\n\n", cnt);

#endif
}
#endif

#endif  // #ifdef MMX_COEF from way above.


static inline void __append_string(unsigned char *Str, unsigned len)
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		if (!md5_unicode_convert) {
			for (j = 0; j < m_count; ++j) {
				unsigned idx = (j>>(MMX_COEF>>1));
				unsigned idx_mod = j&(MMX_COEF-1);
				unsigned bf_ptr = (total_len[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
				total_len[idx] += (len << ((32/MMX_COEF)*idx_mod));
				__SSE_append_string_to_input((unsigned char*)(&input_buf[idx]),idx_mod,Str,len,bf_ptr,1);
			}
		} else {
			if (!options.ascii && !options.iso8859_1) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;

				outlen = enc_to_utf16(utf16Str, 27, Str, len) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (j = 0; j < m_count; ++j) {
					unsigned idx = (j>>(MMX_COEF>>1));
					unsigned idx_mod = j&(MMX_COEF-1);
					unsigned bf_ptr = (total_len[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
					total_len[idx] += ( outlen << ((32/MMX_COEF)*idx_mod));
					// note we use the 'non' unicode variant, since we have already computed the unicode, and length properly
					__SSE_append_string_to_input((unsigned char*)(&input_buf[idx]),idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				}
			} else {
				for (j = 0; j < m_count; ++j) {
					unsigned idx = (j>>(MMX_COEF>>1));
					unsigned idx_mod = j&(MMX_COEF-1);
					unsigned bf_ptr = (total_len[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
					total_len[idx] += ( (len<<1) << ((32/MMX_COEF)*idx_mod));
					__SSE_append_string_to_input_unicode((unsigned char*)(&input_buf[idx]),idx_mod,Str,len,bf_ptr,1);
				}
			}
		}
		return;
	}
#endif
	if (md5_unicode_convert) {
		if (!options.ascii && !options.iso8859_1) {
			UTF16 utf16Str[EFFECTIVE_MAX_LENGTH / 3 + 1];
			int outlen;
			outlen = enc_to_utf16(utf16Str, EFFECTIVE_MAX_LENGTH / 3, Str, len) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp;
				unsigned char *cpi = (unsigned char*)utf16Str;
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
		} else {
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp;
				unsigned char *cpi = Str;
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
	} else {
		for (j = 0; j < m_count; ++j) {
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

static inline void __append2_string(unsigned char *Str, unsigned len)
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		if (!md5_unicode_convert) {
			for (j = 0; j < m_count; ++j) {
				unsigned idx = (j>>(MMX_COEF>>1));
				unsigned idx_mod = j&(MMX_COEF-1);
				unsigned bf_ptr = (total_len2[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
				total_len2[idx] += ( len << ((32/MMX_COEF)*idx_mod));
				__SSE_append_string_to_input((unsigned char*)(&input_buf2[idx]),idx_mod,Str,len,bf_ptr,1);
			}
		} else {
			if (!options.ascii && !options.iso8859_1) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;

				outlen = enc_to_utf16(utf16Str, 27, Str, len) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (j = 0; j < m_count; ++j) {
					unsigned idx = (j>>(MMX_COEF>>1));
					unsigned idx_mod = j&(MMX_COEF-1);
					unsigned bf_ptr = (total_len2[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
					total_len2[idx] += ( outlen << ((32/MMX_COEF)*idx_mod));
					// note we use the 'non' unicode variant of __SSE_append_string_to_input(), since it's already unicode, and length properly
					__SSE_append_string_to_input((unsigned char*)(&input_buf2[idx]),idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				}
			} else {
				for (j = 0; j < m_count; ++j) {
					unsigned idx = (j>>(MMX_COEF>>1));
					unsigned idx_mod = j&(MMX_COEF-1);
					unsigned bf_ptr = (total_len2[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
					total_len2[idx] += ( (len<<1) << ((32/MMX_COEF)*idx_mod));
					__SSE_append_string_to_input_unicode((unsigned char*)(&input_buf2[idx]),idx_mod,Str,len,bf_ptr,1);
				}
			}
		}
		return;
	}
#endif
	if (md5_unicode_convert) {
		if (!options.ascii && !options.iso8859_1) {
			UTF16 utf16Str[EFFECTIVE_MAX_LENGTH / 3 + 1];
			int outlen;
			outlen = enc_to_utf16(utf16Str, EFFECTIVE_MAX_LENGTH / 3, Str, len) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp;
				unsigned char *cpi = (unsigned char*)utf16Str;
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
		} else {
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp;
				unsigned char *cpi = Str;
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
	} else {
		for (j = 0; j < m_count; ++j) {
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

void DynamicFunc__setmode_unicode()
{
	md5_unicode_convert = 1;
}
void DynamicFunc__setmode_normal ()
{
	md5_unicode_convert = 0;
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Clears the input variable, and input 'lengths'
 *************************************************************/
void DynamicFunc__clean_input()
{
	unsigned i=0;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		memset(input_buf, 0, sizeof(input_buf));
		memset(total_len, 0, sizeof(total_len));
		return;
	}
#endif
	for (; i < MAX_KEYS_PER_CRYPT_X86; ++i) {
		//if (total_len_X86[i]) {
#if MD5_X2
			if (i&1)
				memset(input_buf_X86[i>>MD5_X2].x2.b2, 0, total_len_X86[i]+5);
			else
#endif
			memset(input_buf_X86[i>>MD5_X2].x1.b, 0, total_len_X86[i]+5);
			total_len_X86[i] = 0;
		//}
	}
	return;
}
void DynamicFunc__clean_input2()
{
	unsigned i=0;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		memset(input_buf2, 0, sizeof(input_buf2));
		memset(total_len2, 0, sizeof(total_len2));
		return;
	}
#endif
	for (; i < MAX_KEYS_PER_CRYPT_X86; ++i) {
		//if (total_len2_X86[i]) {
#if MD5_X2
			if (i&1)
				memset(input_buf2_X86[i>>MD5_X2].x2.b2, 0, total_len2_X86[i]+5);
			else
#endif
			memset(input_buf2_X86[i>>MD5_X2].x1.b, 0, total_len2_X86[i]+5);
			total_len2_X86[i] = 0;
		//}
	}
	return;
}
void DynamicFunc__clean_input_full()
{
#ifdef MMX_COEF
	memset(input_buf, 0, sizeof(input_buf));
	memset(total_len, 0, sizeof(total_len));
#endif
	memset(input_buf_X86, 0, sizeof(input_buf_X86));
	memset(total_len_X86, 0, sizeof(total_len_X86));
}
void DynamicFunc__clean_input2_full()
{
#ifdef MMX_COEF
	memset(input_buf2, 0, sizeof(input_buf));
	memset(total_len2, 0, sizeof(total_len));
#endif
	memset(input_buf2_X86, 0, sizeof(input_buf2_X86));
	memset(total_len2_X86, 0, sizeof(total_len2_X86));
}
void DynamicFunc__clean_input_kwik()
{
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		memset(total_len, 0, sizeof(total_len));
		return;
	}
#endif
	memset(total_len_X86, 0, sizeof(total_len_X86));
#if !ARCH_LITTLE_ENDIAN
	memset(input_buf_X86, 0, sizeof(input_buf_X86));
#endif
}
void DynamicFunc__clean_input2_kwik()
{
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		memset(total_len2, 0, sizeof(total_len2));
		return;
	}
#endif
	memset(total_len2_X86, 0, sizeof(total_len2_X86));
#if !ARCH_LITTLE_ENDIAN
	memset(input_buf2_X86, 0, sizeof(input_buf2_X86));
#endif
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends all keys to the end of the input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_keys()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		for (j = 0; j < m_count; ++j) {
			unsigned idx = (j>>(MMX_COEF>>1));
			unsigned idx_mod = j&(MMX_COEF-1);
			unsigned bf_ptr = (total_len[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
			if (md5_unicode_convert) {
				if (!options.ascii && !options.iso8859_1) {
					UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
					int outlen;
					int maxlen=27;
					if (curdat.pSetup->MaxInputLen < maxlen)
						maxlen = curdat.pSetup->MaxInputLen;
					outlen = enc_to_utf16(utf16Str, maxlen, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
					if (outlen <= 0) {
						saved_key_len[j] = -outlen / sizeof(UTF16);
						if (outlen < 0)
							outlen = strlen16(utf16Str) * sizeof(UTF16);
					}
					total_len[idx] += ( outlen << ((32/MMX_COEF)*idx_mod));
					__SSE_append_string_to_input((unsigned char*)(&input_buf[idx]),idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				} else {
					total_len[idx] += ( ((saved_key_len[j])<<1) << ((32/MMX_COEF)*idx_mod));
					__SSE_append_string_to_input_unicode((unsigned char*)(&input_buf[idx]),idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
				}
			} else {
				total_len[idx] += (saved_key_len[j] << ((32/MMX_COEF)*idx_mod));
				__SSE_append_string_to_input((unsigned char*)(&input_buf[idx]),idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
			}
		}
		return;
	}
#endif
	if (md5_unicode_convert) {
		if (!options.ascii && !options.iso8859_1) {
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp, *cpi;
				UTF16 utf16Str[EFFECTIVE_MAX_LENGTH / 3 + 1];
				int outlen;
				outlen = enc_to_utf16(utf16Str, EFFECTIVE_MAX_LENGTH / 3, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
				if (outlen <= 0) {
					saved_key_len[j] = -outlen / sizeof(UTF16);
					if (outlen < 0)
						outlen = strlen16(utf16Str) * sizeof(UTF16);
				}
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
		} else {
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp, *cpi = (unsigned char*)saved_key[j];
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
	} else {
		for (j = 0; j < m_count; ++j) {
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

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends all keys to the end of the 2nd input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_keys2()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		for (j = 0; j < m_count; ++j) {
			unsigned idx = (j>>(MMX_COEF>>1));
			unsigned idx_mod = j&(MMX_COEF-1);
			unsigned bf_ptr = (total_len2[idx] >> ((32/MMX_COEF)*idx_mod)) & 0xFF;
			if (md5_unicode_convert) {
				if (!options.ascii && !options.iso8859_1) {
					UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
					int outlen;
					int maxlen=27;
					if (curdat.pSetup->MaxInputLen < maxlen)
						maxlen = curdat.pSetup->MaxInputLen;
					outlen = enc_to_utf16(utf16Str, maxlen, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
					if (outlen <= 0) {
						saved_key_len[j] = -outlen / sizeof(UTF16);
						if (outlen < 0)
							outlen = strlen16(utf16Str) * sizeof(UTF16);
					}
					total_len2[idx] += ( outlen << ((32/MMX_COEF)*idx_mod));
					__SSE_append_string_to_input((unsigned char*)(&input_buf2[idx]),idx_mod,(unsigned char*)utf16Str,outlen,bf_ptr,1);
				} else {
					total_len2[idx] += ( (saved_key_len[j]<<1) << ((32/MMX_COEF)*idx_mod));
					__SSE_append_string_to_input_unicode((unsigned char*)(&input_buf2[idx]),idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
				}
			} else {
				total_len2[idx] += (saved_key_len[j] << ((32/MMX_COEF)*idx_mod));
				__SSE_append_string_to_input((unsigned char*)(&input_buf2[idx]),idx_mod,(unsigned char*)saved_key[j],saved_key_len[j],bf_ptr,1);
			}
		}
		return;
	}
#endif
	if (md5_unicode_convert) {
		if (!options.ascii && !options.iso8859_1) {
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp, *cpi;
				UTF16 utf16Str[EFFECTIVE_MAX_LENGTH / 3 + 1];
				int outlen;
				outlen = enc_to_utf16(utf16Str, EFFECTIVE_MAX_LENGTH / 3, (unsigned char*)saved_key[j], saved_key_len[j]) * sizeof(UTF16);
				if (outlen <= 0) {
					saved_key_len[j] = -outlen / sizeof(UTF16);
					if (outlen < 0)
						outlen = strlen16(utf16Str) * sizeof(UTF16);
				}
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
		} else {
			for (j = 0; j < m_count; ++j) {
				int z;
				unsigned char *cp, *cpi = (unsigned char*)saved_key[j];
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
	} else {
		for (j = 0; j < m_count; ++j) {
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

void DynamicFunc__set_input_len_16()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned cnt, k;
		cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (j = 0; j < cnt; ++j)
		{
			// If length is < 16, then remove existing end of buffer marker, and then set
			// one at offset 16
			unsigned cur_block_len = total_len[j];
			for (k = 0; k < MMX_COEF; ++k) {
				unsigned this_item_len = cur_block_len & 0xFF;
#if (MMX_COEF==4)
				cur_block_len >>= 8;
#else
				cur_block_len >>= 16;
#endif
				if (this_item_len < 16)
					input_buf[j][GETPOS(this_item_len, k&(MMX_COEF-1))] = 0x00;
				input_buf[j][GETPOS(16, k&(MMX_COEF-1))] = 0x80;
			}
#if (MMX_COEF==4)
			total_len[j] = 0x10101010;
#else
			total_len[j] = 0x100010;
#endif
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
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

void DynamicFunc__set_input2_len_16()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned cnt, k;
		cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (j = 0; j < cnt; ++j)
		{
			// If length is < 16, then remove existing end of buffer marker, and then set
			// one at offset 16
			unsigned cur_block_len = total_len2[j];
			for (k = 0; k < MMX_COEF; ++k) {
				unsigned this_item_len = cur_block_len & 0xFF;
#if (MMX_COEF==4)
				cur_block_len >>= 8;
#else
				cur_block_len >>= 16;
#endif
				if (this_item_len < 16)
					input_buf2[j][GETPOS(this_item_len, k&(MMX_COEF-1))] = 0x00;
				input_buf2[j][GETPOS(16, k&(MMX_COEF-1))] = 0x80;
			}
#if (MMX_COEF==4)
			total_len2[j] = 0x10101010;
#else
			total_len2[j] = 0x100010;
#endif
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
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

void DynamicFunc__set_input_len_32()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned cnt;
		cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
#if (MMX_COEF==4)
			total_len[i] = 0x20202020;
#else
			total_len[i] = 0x200020;
#endif
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		total_len_X86[i] = 32;
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
		if (i&1) {
			//MD5_swap(input_buf_X86[i>>MD5_X2].x2.w2, input_buf_X86[i>>MD5_X2].x2.w2, 8);
			memset(&(input_buf_X86[i>>MD5_X2].x2.B2[32]), 0, 24);
		}
		else
#endif
		{
			//MD5_swap(input_buf_X86[i>>MD5_X2].x1.w, input_buf_X86[i>>MD5_X2].x1.w, 8);
			memset(&(input_buf_X86[i>>MD5_X2].x1.B[32]), 0, 24);
		}
#endif
	}
}

void DynamicFunc__set_input2_len_32()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned cnt;
		cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
#if (MMX_COEF==4)
			total_len2[i] = 0x20202020;
#else
			total_len2[i] = 0x200020;
#endif
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		total_len2_X86[i] = 32;
#if !ARCH_LITTLE_ENDIAN
#if MD5_X2
		if (i&1) {
			//MD5_swap(input_buf2_X86[i>>MD5_X2].x2.w2, input_buf2_X86[i>>MD5_X2].x2.w2, 8);
			memset(&(input_buf2_X86[i>>MD5_X2].x2.B2[32]), 0, 24);
		}
		else
#endif
		{
			//MD5_swap(input_buf2_X86[i>>MD5_X2].x1.w, input_buf2_X86[i>>MD5_X2].x1.w, 8);
			memset(&(input_buf2_X86[i>>MD5_X2].x1.B[32]), 0, 24);
		}
#endif
	}
}

void DynamicFunc__set_input_len_64()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		exit(!!fprintf(stderr, "Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_64 in SSE2/MMX mode\n"));
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		total_len_X86[j] = 64;
	}
}
void DynamicFunc__set_input_len_100()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		exit(!!fprintf(stderr, "Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input_len_100 in SSE2/MMX mode\n"));
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		unsigned char *cp;
#if MD5_X2
		if (j&1)
			cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]+1]);
		else
#endif
			cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]+1]);
		while (*cp)
			*cp++ = 0;
		total_len_X86[j] = 100;
	}
}
void DynamicFunc__set_input2_len_64()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		exit(!!fprintf(stderr, "Error, in your DYNAMIC script.\nIt is NOT valid to call DynamicFunc__set_input2_len_64 in SSE2/MMX mode\n"));
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		total_len2_X86[j] = 64;
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends the salt to the end of the input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_salt()
{
	__append_string(cursalt, saltlen);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Appends the salt to the end of the 2nd input variables, and
 * updates lengths
 *************************************************************/
void DynamicFunc__append_salt2()
{
	__append2_string(cursalt, saltlen);
}

void DynamicFunc__append_input_from_input2()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned i, k, cnt;
		cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
			for (j = 0; j < MMX_COEF; ++j)
			{
				unsigned start_len = (total_len[i] >> ((32/MMX_COEF)*j)) & 0xFF;
				unsigned len1 = (total_len2[i] >> ((32/MMX_COEF)*j)) & 0xFF;
				for (k = 0; k < len1; ++k)
					input_buf[i][GETPOS((k+start_len), j)] = input_buf2[i][GETPOS(k,j)];
				input_buf[i][GETPOS((len1+start_len), j)] = 0x80;
				total_len[i] += ( len1 << ( ( (32/MMX_COEF) * j ) ));
			}
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
#if MD5_X2
		if (j&1)
			memcpy(&(input_buf_X86[j>>MD5_X2].x2.b2[total_len_X86[j]]), input_buf2_X86[j>>MD5_X2].x2.b2, total_len2_X86[j]);
		else
#endif
		memcpy(&(input_buf_X86[j>>MD5_X2].x1.b[total_len_X86[j]]), input_buf2_X86[j>>MD5_X2].x1.b, total_len2_X86[j]);
		total_len_X86[j] += total_len2_X86[j];
	}
}

void DynamicFunc__append_input2_from_input()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned i, k, cnt;
		cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
			for (j = 0; j < MMX_COEF; ++j)
			{
				unsigned start_len = (total_len2[i] >> ((32/MMX_COEF)*j)) & 0xFF;
				unsigned len1 = (total_len[i] >> ((32/MMX_COEF)*j)) & 0xFF;
				for (k = 0; k < len1; ++k)
					input_buf2[i][GETPOS((k+start_len), j)] = input_buf[i][GETPOS(k,j)];
				input_buf2[i][GETPOS((len1+start_len), j)] = 0x80;
				total_len2[i] += ( len1 << ( ( (32/MMX_COEF) * j ) ));
			}
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
#if MD5_X2
		if (j&1)
			memcpy(&(input_buf2_X86[j>>MD5_X2].x2.b2[total_len2_X86[j]]), input_buf_X86[j>>MD5_X2].x2.b2, total_len_X86[j]);
		else
#endif
		memcpy(&(input_buf2_X86[j>>MD5_X2].x1.b[total_len2_X86[j]]), input_buf_X86[j>>MD5_X2].x1.b, total_len_X86[j]);
		total_len2_X86[j] += total_len_X86[j];
	}
}

#ifdef MD5_SSE_PARA
void SSE_Intrinsics_LoadLens(int side, int i)
{
	ARCH_WORD_32 *p;
	ARCH_WORD_32 TL;
	int j;
	if (side == 0)
	{
		for (j = 0; j < MD5_SSE_PARA; j++)
		{
			p = (ARCH_WORD_32 *)(&input_buf[i+j]);
			TL = (ARCH_WORD_32)total_len[i+j];
			p[14*MMX_COEF+0] = ((TL>>0)&0xFF)<<3;
			p[14*MMX_COEF+1] = ((TL>>8)&0xFF)<<3;
			p[14*MMX_COEF+2] = ((TL>>16)&0xFF)<<3;
			p[14*MMX_COEF+3] = ((TL>>24)&0xFF)<<3;
		}
	}
	else
	{
		for (j = 0; j < MD5_SSE_PARA; j++)
		{
			p = (ARCH_WORD_32 *)(&input_buf2[i+j]);
			TL = (ARCH_WORD_32)total_len2[i+j];
			p[14*MMX_COEF+0] = ((TL>>0)&0xFF)<<3;
			p[14*MMX_COEF+1] = ((TL>>8)&0xFF)<<3;
			p[14*MMX_COEF+2] = ((TL>>16)&0xFF)<<3;
			p[14*MMX_COEF+3] = ((TL>>24)&0xFF)<<3;
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
 * that format instead.  Some functions do NOT change from
 * the binary format (such as phpass). Thus if we are doing
 * something like phpass, we would NOT want the conversion
 * to happen at all
 *************************************************************/
void DynamicFunc__crypt_md5()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; i += MD5_SSE_PARA) {
				SSEmd5body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			}
		} else {
			for (i = 0; i < cnt; i += MD5_SSE_PARA) {
				SSE_Intrinsics_LoadLens(0, i);
				SSEmd5body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			}
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; ++i)
				mdfivemmx_nosizeupdate((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf[i]), 1);
		} else {
			for (i = 0; i < cnt; ++i)
				mdfivemmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
		}
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i++];
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}
void DynamicFunc__crypt_md4()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD4_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; i += MD4_SSE_PARA) {
				SSEmd4body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			}
		} else {
			for (i = 0; i < cnt; i += MD4_SSE_PARA) {
				SSE_Intrinsics_LoadLens(0, i);
				SSEmd4body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			}
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; ++i)
				mdfourmmx_nosizeupdate((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf[i]), 1);
		} else {
			for (i = 0; i < cnt; ++i)
				mdfourmmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
		}
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i++];
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		DoMD4(input_buf_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}

#ifndef MMX_COEF
typedef struct {
	union {
		double dummy;
		MD5_word w[64/4];
		char b[64];
		unsigned char B[64];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		MD5_word w2[64/4];
		char b2[64];
		unsigned char B2[64];
	}x2;
#endif
} MD5_A;

static MD5_A md5_cspp, md5_pspc, md5_cpp, md5_ppc, md5_csp, md5_psc, md5_cp, md5_pc;
//static unsigned md5_lens[2][8];
struct md5_item {
	MD5_A *in1, *in2, *out2;
#if ARCH_LITTLE_ENDIAN
#if MD5_X2
	unsigned char *off[2];
#else
	unsigned char *off;
#endif
#else
	unsigned off[2];
#endif
	unsigned len1, len2;
};
static struct md5_item md5_items[21] = {
  {&md5_cp,   &md5_pspc, &md5_cspp },
  {&md5_cspp, &md5_ppc,  &md5_cspp },
  {&md5_cspp, &md5_pspc, &md5_cpp },
  {&md5_cpp,  &md5_psc,  &md5_cspp },
  {&md5_cspp, &md5_ppc,  &md5_cspp },
  {&md5_cspp, &md5_pspc, &md5_cpp },
  {&md5_cpp,  &md5_pspc, &md5_csp },
  {&md5_csp,  &md5_ppc,  &md5_cspp },
  {&md5_cspp, &md5_pspc, &md5_cpp },
  {&md5_cpp,  &md5_pspc, &md5_cspp },
  {&md5_cspp, &md5_pc,   &md5_cspp },
  {&md5_cspp, &md5_pspc, &md5_cpp },
  {&md5_cpp,  &md5_pspc, &md5_cspp },
  {&md5_cspp, &md5_ppc,  &md5_csp },
  {&md5_csp,  &md5_pspc, &md5_cpp },
  {&md5_cpp,  &md5_pspc, &md5_cspp },
  {&md5_cspp, &md5_ppc,  &md5_cspp },
  {&md5_cspp, &md5_psc,  &md5_cpp },
  {&md5_cpp,  &md5_pspc, &md5_cspp },
  {&md5_cspp, &md5_ppc,  &md5_cspp },
  {&md5_cspp, &md5_pspc, &md5_cp }
};

/*
	if (len<md5_lens[i][b]) memset(&cp[len],0,(md5_lens[i][b]-len)+5); \
	md5_lens[i][b] = len; \
*/
#define SETLEN_MD5_INPUT(a,b,c) do{\
	len=cp-a+c; \
	a[len]=0x80; ((MD5_word *)a)[14]=(len<<3); \
}while(0)

static void FreeBSDMD5Crypt_setup_nonMMX() {
	unsigned char *cp, *cp1;
	//MD5_word *w;
	unsigned len, i;
	char *pass;
	unsigned plen;

	memset(&md5_cspp,0,sizeof(md5_cspp));
	memset(&md5_pspc,0,sizeof(md5_pspc));
	memset(&md5_cpp,0,sizeof(md5_cpp));
	memset(&md5_ppc,0,sizeof(md5_ppc));
	memset(&md5_csp,0,sizeof(md5_csp));
	memset(&md5_psc,0,sizeof(md5_psc));
	memset(&md5_cp,0,sizeof(md5_cp));
	memset(&md5_pc,0,sizeof(md5_pc));

	i = 0;
#if MD5_X2
	for (; i < 2; ++i)  {
#endif
		pass = saved_key[i];
		plen = saved_key_len[i];

		cp1 = md5_cspp.x1.B; /* w=md5_cspp.x1.w*/ ;
#if MD5_X2
		if (i == 1) { cp1 = md5_cspp.x2.B2; /* w=md5_cspp.x2.w2; */ }
#endif
	cp = &cp1[16];
	memcpy(cp, cursalt, saltlen); cp += saltlen; memcpy(cp, pass, plen); cp += plen; memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 0, 0);
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[1].len1 = md5_items[2].len1 = md5_items[4].len1 = md5_items[5].len1 =
	md5_items[8].len1 = md5_items[10].len1 = md5_items[11].len1 = md5_items[13].len1 =
	md5_items[16].len1 = md5_items[17].len1 = md5_items[19].len1 = md5_items[20].len1 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_pspc.x1.B; /* w=md5_pspc.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_pspc.x2.B2; /* w=md5_pspc.x2.w2 */; }
#endif
	cp = cp1;
	memcpy(cp, pass, plen); cp += plen; memcpy(cp, cursalt, saltlen); cp += saltlen; memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 1, 16);
#if ARCH_LITTLE_ENDIAN
#if MD5_X2
	md5_items[0].off[i] = md5_items[2].off[i] = md5_items[5].off[i] = md5_items[6].off[i] =
	md5_items[8].off[i] = md5_items[9].off[i] = md5_items[11].off[i] = md5_items[12].off[i] =
	md5_items[14].off[i] = md5_items[15].off[i] = md5_items[18].off[i] = md5_items[20].off[i] = &cp1[cp-cp1];
#else
	md5_items[0].off = md5_items[2].off = md5_items[5].off = md5_items[6].off =
	md5_items[8].off = md5_items[9].off = md5_items[11].off = md5_items[12].off =
	md5_items[14].off = md5_items[15].off = md5_items[18].off = md5_items[20].off = &cp1[cp-cp1];
#endif
#else
	md5_items[0].off[i] = md5_items[2].off[i] = md5_items[5].off[i] = md5_items[6].off[i] =
	md5_items[8].off[i] = md5_items[9].off[i] = md5_items[11].off[i] = md5_items[12].off[i] =
	md5_items[14].off[i] = md5_items[15].off[i] = md5_items[18].off[i] = md5_items[20].off[i] = cp-cp1;
#endif
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[0].len2 = md5_items[2].len2 = md5_items[5].len2 = md5_items[6].len2 =
	md5_items[8].len2 = md5_items[9].len2 = md5_items[11].len2 = md5_items[12].len2 =
	md5_items[14].len2 = md5_items[15].len2 = md5_items[18].len2 = md5_items[20].len2 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_cpp.x1.B; /* w=md5_cpp.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_cpp.x2.B2; /* w=md5_cpp.x2.w2 */; }
#endif
	cp = &cp1[16];
	memcpy(cp, pass, plen); cp += plen; memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 2, 0);
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[3].len1 = md5_items[6].len1 = md5_items[9].len1 = md5_items[12].len1 =
	md5_items[15].len1 = md5_items[18].len1 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_ppc.x1.B; /* w=md5_ppc.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_ppc.x2.B2; /* w=md5_ppc.x2.w2 */; }
#endif
	cp = cp1;
	memcpy(cp, pass, plen); cp += plen; memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 3, 16);
#if ARCH_LITTLE_ENDIAN
#if MD5_X2
	md5_items[1].off[i] = md5_items[4].off[i] = md5_items[7].off[i] = md5_items[13].off[i] =
	md5_items[16].off[i] = md5_items[19].off[i] = &cp1[cp-cp1];
#else
	md5_items[1].off = md5_items[4].off = md5_items[7].off = md5_items[13].off =
	md5_items[16].off = md5_items[19].off = &cp1[cp-cp1];
#endif
#else
	md5_items[1].off[i] = md5_items[4].off[i] = md5_items[7].off[i] = md5_items[13].off[i] =
	md5_items[16].off[i] = md5_items[19].off[i] = cp-cp1;
#endif
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[1].len2 = md5_items[4].len2 = md5_items[7].len2 = md5_items[13].len2 =
	md5_items[16].len2 = md5_items[19].len2 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_csp.x1.B; /* w=md5_csp.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_csp.x2.B2; /* w=md5_csp.x2.w2 */; }
#endif
	cp = &cp1[16];
	memcpy(cp, cursalt, saltlen); cp += saltlen; memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 4, 0);
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[7].len1 = md5_items[14].len1 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_psc.x1.B; /* w=md5_psc.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_psc.x2.B2; /* w=md5_psc.x2.w2 */; }
#endif
	cp = cp1;
	memcpy(cp, pass, plen); cp += plen; memcpy(cp, cursalt, saltlen); cp += saltlen;
	SETLEN_MD5_INPUT(cp1, 5, 16);
#if ARCH_LITTLE_ENDIAN
#if MD5_X2
	md5_items[3].off[i] = md5_items[17].off[i] = &cp1[cp-cp1];
#else
	md5_items[3].off = md5_items[17].off = &cp1[cp-cp1];
#endif
#else
	md5_items[3].off[i] = md5_items[17].off[i] = cp-cp1;
#endif
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[3].len2 = md5_items[17].len2 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_cp.x1.B; /* w=md5_cp.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_cp.x2.B2; /* w=md5_cp.x2.w2 */; }
#endif
	cp = &cp1[16];
	memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 6, 0);
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[0].len1 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

	cp1 = md5_pc.x1.B; /* w=md5_pc.x1.w */;
#if MD5_X2
	if (i == 1) { cp1 = md5_pc.x2.B2; /* w=md5_pc.x2.w2 */; }
#endif
	cp = cp1;
	memcpy(cp, pass, plen); cp += plen;
	SETLEN_MD5_INPUT(cp1, 7, 16);
#if ARCH_LITTLE_ENDIAN
#if MD5_X2
	md5_items[10].off[i] = &cp1[cp-cp1];
#else
	md5_items[10].off = &cp1[cp-cp1];
#endif
#else
	md5_items[10].off[i] = cp-cp1;
#endif
#if !defined (USE_MD5_Go) || (MD5_ASM != 1)
	md5_items[10].len2 = len;
#endif
	//MD5_swap(w,w,(len+5)>>2);

#if MD5_X2
	}
#endif
}

static void DynamicFunc__FreeBSDMD5Crypt_ANY()
{
	unsigned char *cp, *cp1;
	int i, I, len[2];
	unsigned jj;
	char *pass = saved_key[0];
	unsigned plen = saved_key_len[0];

#if MD5_X2
	char *pass2 = saved_key[1];
	unsigned plen2 = saved_key_len[1];
#endif

	FreeBSDMD5Crypt_setup_nonMMX(); //	dumpMD5(1, 0);

	memset(&input_buf_X86[0], 0, sizeof(input_buf_X86[0]));

	// Build B
	memcpy(input_buf_X86[0].x1.b, pass, plen);
	memcpy(&input_buf_X86[0].x1.b[plen], cursalt, saltlen);
	memcpy(&input_buf_X86[0].x1.b[plen+saltlen], pass, plen);
#if MD5_X2
	memcpy(input_buf_X86[0].x2.b2, pass2, plen2);
	memcpy(&input_buf_X86[0].x2.b2[plen2], cursalt, saltlen);
	memcpy(&input_buf_X86[0].x2.b2[plen2+saltlen], pass2, plen2);
	len[0] = (plen<<1)+saltlen;
	len[1] = (plen2<<1)+saltlen;
	DoMD5(input_buf_X86[0], len, crypt_key_X86[0]);
#else
	DoMD5(input_buf_X86[0],((plen<<1)+saltlen),crypt_key_X86[0]);
#endif

	i = 0;
#if MD5_X2
	for (; i < 2; ++i) {
#endif
		// Build A
		pass = saved_key[i];
		plen = saved_key_len[i];
		cp1 = input_buf_X86[0].x1.B;
#if MD5_X2
		if (i == 1)
			cp1 = input_buf_X86[0].x2.B2;
#endif

		cp = cp1;
		memcpy(cp, pass, plen);
		cp += plen;
		memcpy(cp, curdat.Consts[0], curdat.ConstsLen[0]);
		cp += curdat.ConstsLen[0];

		memcpy(cp, cursalt, saltlen);
		cp += saltlen;
		// since pass len ls limted to 15 bytes (so all will fit in one MD5 block),
		// we can ignore the loop, and just use plen
		//for (i = plen; i > 0; i -= 16) {
		//	memcpy(cp, b, i>16?16:i);
		//	cp += i>16?16:i;
		//}
		if (!i)
			memcpy(cp, crypt_key_X86[0].x1.b, plen);
#if MD5_X2
		else
			memcpy(cp, crypt_key_X86[0].x2.b2, plen);
#endif
		cp += plen;

		for (I = plen; I ; I >>= 1)
			if (I & 1)
				*cp++ = 0;
			else
				*cp++ = pass[0];
		len[i] = cp-cp1;
#if MD5_X2
	}
#endif

#if MD5_X2
	DoMD5(input_buf_X86[0], len, md5_cp);
	MD5_swap2(md5_cp.x1.w, md5_cp.x2.w2, md5_cp.x1.w, md5_cp.x2.w2, 4);
#else
	DoMD5(input_buf_X86[0], len[0], md5_cp);
	MD5_swap(md5_cp.x1.w, md5_cp.x1.w, 4);
#endif

	for (jj = 0; jj < 500; ++jj) {
//		int j = jj%21;
//		DoMD5a2(md5_items[j].in1, md5_items[j].len1, md5_items[j].in2, md5_items[j].off);
//		DoMD5a(md5_items[j].in2, md5_items[j].len2, md5_items[j].out2);

		DoMD5a2(md5_items[0].in1, md5_items[0].len1, md5_items[0].in2, md5_items[0].off);

		DoMD5a(md5_items[0].in2, md5_items[0].len2, md5_items[0].out2);
		DoMD5a2(md5_items[1].in1, md5_items[1].len1, md5_items[1].in2, md5_items[1].off);
		DoMD5a(md5_items[1].in2, md5_items[1].len2, md5_items[1].out2);
		DoMD5a2(md5_items[2].in1, md5_items[2].len1, md5_items[2].in2, md5_items[2].off);
		DoMD5a(md5_items[2].in2, md5_items[2].len2, md5_items[2].out2);
		DoMD5a2(md5_items[3].in1, md5_items[3].len1, md5_items[3].in2, md5_items[3].off);
		DoMD5a(md5_items[3].in2, md5_items[3].len2, md5_items[3].out2);
		DoMD5a2(md5_items[4].in1, md5_items[4].len1, md5_items[4].in2, md5_items[4].off);
		DoMD5a(md5_items[4].in2, md5_items[4].len2, md5_items[4].out2);
		DoMD5a2(md5_items[5].in1, md5_items[5].len1, md5_items[5].in2, md5_items[5].off);
		DoMD5a(md5_items[5].in2, md5_items[5].len2, md5_items[5].out2);
		DoMD5a2(md5_items[6].in1, md5_items[6].len1, md5_items[6].in2, md5_items[6].off);
		DoMD5a(md5_items[6].in2, md5_items[6].len2, md5_items[6].out2);
		DoMD5a2(md5_items[7].in1, md5_items[7].len1, md5_items[7].in2, md5_items[7].off);
		DoMD5a(md5_items[7].in2, md5_items[7].len2, md5_items[7].out2);
		DoMD5a2(md5_items[8].in1, md5_items[8].len1, md5_items[8].in2, md5_items[8].off);
		DoMD5a(md5_items[8].in2, md5_items[8].len2, md5_items[8].out2);
		DoMD5a2(md5_items[9].in1, md5_items[9].len1, md5_items[9].in2, md5_items[9].off);
		DoMD5a(md5_items[9].in2, md5_items[9].len2, md5_items[9].out2);
		DoMD5a2(md5_items[10].in1, md5_items[10].len1, md5_items[10].in2, md5_items[10].off);
		DoMD5a(md5_items[10].in2, md5_items[10].len2, md5_items[10].out2);
		DoMD5a2(md5_items[11].in1, md5_items[11].len1, md5_items[11].in2, md5_items[11].off);
		DoMD5a(md5_items[11].in2, md5_items[11].len2, md5_items[11].out2);
		DoMD5a2(md5_items[12].in1, md5_items[12].len1, md5_items[12].in2, md5_items[12].off);
		DoMD5a(md5_items[12].in2, md5_items[12].len2, md5_items[12].out2);
		DoMD5a2(md5_items[13].in1, md5_items[13].len1, md5_items[13].in2, md5_items[13].off);
		DoMD5a(md5_items[13].in2, md5_items[13].len2, md5_items[13].out2);
		DoMD5a2(md5_items[14].in1, md5_items[14].len1, md5_items[14].in2, md5_items[14].off);
		DoMD5a(md5_items[14].in2, md5_items[14].len2, md5_items[14].out2);
		DoMD5a2(md5_items[15].in1, md5_items[15].len1, md5_items[15].in2, md5_items[15].off);
		DoMD5a(md5_items[15].in2, md5_items[15].len2, md5_items[15].out2);
		DoMD5a2(md5_items[16].in1, md5_items[16].len1, md5_items[16].in2, md5_items[16].off);
		DoMD5a(md5_items[16].in2, md5_items[16].len2, md5_items[16].out2);
		if (jj > 480) break;
		DoMD5a2(md5_items[17].in1, md5_items[17].len1, md5_items[17].in2, md5_items[17].off);
		DoMD5a(md5_items[17].in2, md5_items[17].len2, md5_items[17].out2);
		DoMD5a2(md5_items[18].in1, md5_items[18].len1, md5_items[18].in2, md5_items[18].off);
		DoMD5a(md5_items[18].in2, md5_items[18].len2, md5_items[18].out2);
		DoMD5a2(md5_items[19].in1, md5_items[19].len1, md5_items[19].in2, md5_items[19].off);
		DoMD5a(md5_items[19].in2, md5_items[19].len2, md5_items[19].out2);
		DoMD5a2(md5_items[20].in1, md5_items[20].len1, md5_items[20].in2, md5_items[20].off);
		DoMD5a(md5_items[20].in2, md5_items[20].len2, md5_items[20].out2);
		jj += 20;
	}
	//memcpy(crypt_key_X86[0], md5_items[j].out2, 16);
	memcpy(crypt_key_X86[0].x1.b, md5_cspp.x1.b, 16);  // [j]out2 is [16].out2 which is md5_cspp
#if MD5_X2
	memcpy(crypt_key_X86[0].x2.b2, md5_cspp.x2.b2, 16);
#endif
}
#else  // if !defined MMX_COEF

#ifdef _MSC_VER
__declspec(align(16)) unsigned char md5_cspp[BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_pspc[BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_cpp [BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_ppc [BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_csp [BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_psc [BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_cp  [BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_pc  [BSD_BLKS][64*MMX_COEF];
__declspec(align(16)) unsigned char md5_tmp_out [BSD_BLKS][16*MMX_COEF];
__declspec(align(16)) unsigned char md5_tmp_in [BSD_BLKS][64*MMX_COEF];
#else
unsigned char md5_cspp[BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_pspc[BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_cpp [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_ppc [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_csp [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_psc [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_cp  [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_pc  [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_tmp_out [BSD_BLKS][16*MMX_COEF] __attribute__ ((aligned(16)));
unsigned char md5_tmp_in [BSD_BLKS][64*MMX_COEF] __attribute__ ((aligned(16)));
#endif

struct md5_item {
	void *in1, *in2, *out2;	// what we used to call out1 is actually in2, so we simply 'ignore' the extra variable.
	unsigned lens[BSD_BLKS][MMX_COEF];
};
static struct md5_item md5_items[21] =  {
  {md5_cp,   md5_pspc, md5_cspp },
  {md5_cspp, md5_ppc,  md5_cspp },
  {md5_cspp, md5_pspc, md5_cpp },
  {md5_cpp,  md5_psc,  md5_cspp },
  {md5_cspp, md5_ppc,  md5_cspp },
  {md5_cspp, md5_pspc, md5_cpp },
  {md5_cpp,  md5_pspc, md5_csp },
  {md5_csp,  md5_ppc,  md5_cspp },
  {md5_cspp, md5_pspc, md5_cpp },
  {md5_cpp,  md5_pspc, md5_cspp },
  {md5_cspp, md5_pc,   md5_cspp },
  {md5_cspp, md5_pspc, md5_cpp },
  {md5_cpp,  md5_pspc, md5_cspp },
  {md5_cspp, md5_ppc,  md5_csp },
  {md5_csp,  md5_pspc, md5_cpp },
  {md5_cpp,  md5_pspc, md5_cspp },
  {md5_cspp, md5_ppc,  md5_cspp },
  {md5_cspp, md5_psc,  md5_cpp },
  {md5_cpp,  md5_pspc, md5_cspp },
  {md5_cspp, md5_ppc,  md5_cspp },
  {md5_cspp, md5_pspc, md5_cp }
};

#define SETLEN_MD5_INPUT(a,b,c) do{\
	len=cp-a+b; \
	a[len]=0x80; a[64-8]=len<<3; a[64-7]=len>>5; \
	__SSE_append_string_to_input(c[idx],idx_mod,(unsigned char*)a,64,0,0); \
}while(0)


static void FreeBSDMD5Crypt_setup_MMX() {
	unsigned char *cp;
	unsigned len=0, plen, i, idx_mod, idx;
	char *pass;
	unsigned char Tmp[64];

	memset(Tmp, 0, sizeof(Tmp));

	// Not needed, things get properly cleaned up in SETLEN_MD5_INPUT,
	// by copying the WHOLE 64 byte line.  Thus these memsets are not needed.

	//memset(md5_cspp,0,sizeof(md5_cspp));
	//memset(md5_pspc,0,sizeof(md5_pspc));
	//memset(md5_cpp,0,sizeof(md5_cpp));
	//memset(md5_ppc,0,sizeof(md5_ppc));
	//memset(md5_csp,0,sizeof(md5_csp));
	//memset(md5_psc,0,sizeof(md5_psc));
	//memset(md5_cp,0,sizeof(md5_cp));
	//memset(md5_pc,0,sizeof(md5_pc));
	//for (i = 0; i < 21; ++i)
	//	memset(md5_items[i].lens, 0, sizeof(md5_items[i].lens));

	idx = 0;
#ifdef MD5_SSE_PARA
	for (; idx < MD5_SSE_PARA; ++idx)
#endif
	{
		for (i = 0; i < MMX_COEF; ++i) {
			idx_mod = i%MMX_COEF;

			pass = saved_key[idx*MMX_COEF+i];
			plen = saved_key_len[idx*MMX_COEF+i];
			cp = &Tmp[16];
			memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 0, md5_cp);

			cp = Tmp;
			memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 16, md5_pc);
			md5_items[10].lens[idx][i] = cp-Tmp;

			cp = &Tmp[16];
			memcpy(cp, cursalt, saltlen); cp += saltlen; memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 0, md5_csp);

			cp = Tmp;
			memcpy(cp, pass, plen); cp += plen; memcpy(cp, cursalt, saltlen); cp += saltlen;
			SETLEN_MD5_INPUT(Tmp, 16, md5_psc);
			md5_items[3].lens[idx][i] = md5_items[17].lens[idx][i] = cp-Tmp;

			cp = &Tmp[16]; memset(Tmp, 0, len+1);
			memcpy(cp, pass, plen); cp += plen; memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 0, md5_cpp);

			cp = Tmp;
			memcpy(cp, pass, plen); cp += plen; memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 16, md5_ppc);
			md5_items[1].lens[idx][i] = md5_items[4].lens[idx][i] = md5_items[7].lens[idx][i] = md5_items[13].lens[idx][i] =
			md5_items[16].lens[idx][i] = md5_items[19].lens[idx][i] = cp-Tmp;

			cp = &Tmp[16];
			memcpy(cp, cursalt, saltlen); cp += saltlen; memcpy(cp, pass, plen); cp += plen; memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 0, md5_cspp);

			cp = Tmp;
			memcpy(cp, pass, plen); cp += plen; memcpy(cp, cursalt, saltlen); cp += saltlen; memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(Tmp, 16, md5_pspc);
			md5_items[0].lens[idx][i] = md5_items[2].lens[idx][i] = md5_items[5].lens[idx][i] = md5_items[6].lens[idx][i] =
			md5_items[8].lens[idx][i] = md5_items[9].lens[idx][i] = md5_items[11].lens[idx][i] = md5_items[12].lens[idx][i] =
			md5_items[14].lens[idx][i] = md5_items[15].lens[idx][i] = md5_items[18].lens[idx][i] = md5_items[20].lens[idx][i] = cp-Tmp;

			memset(Tmp, 0, len+1);
		}
	}
}

static void CopyCryptToOut1Location(unsigned char *o, int j, int k) {
	int x, idx=0;
	unsigned char *out;
	ARCH_WORD_32 Buf[4];

	out = md5_items[j].in2;

#ifdef MD5_SSE_PARA
	for (; idx < MD5_SSE_PARA; ++idx)
#endif
	{
		for (x = 0; x < MMX_COEF; ++x) {
			unsigned idx_mod = x%MMX_COEF;
			ARCH_WORD_32 *pi = (ARCH_WORD_32*)o;
			pi += idx_mod;
			Buf[0] = *pi; pi += MMX_COEF;
			Buf[1] = *pi; pi += MMX_COEF;
			Buf[2] = *pi; pi += MMX_COEF;
			Buf[3] = *pi;
			__SSE_append_string_to_input(out,idx_mod,(unsigned char*)Buf,16,md5_items[j].lens[idx][x],0);
		}
#ifdef MD5_SSE_PARA
		out += 64*MMX_COEF;
		o += 16*MMX_COEF;
#endif
	}
}

void CopyCryptToFlat(unsigned char *cp, int plen, int idx, int idx_mod) {
	// this function is ONLY called during key setup (once), so trying to optimize
	// to do full DWORD copying (vs byte/byte copying), will not gain us anything.
	unsigned char *in = md5_tmp_out[idx];
	int n = 0;
	in += 4*idx_mod;
	while (plen--) {
		*cp++ = *in++;
		if (!((++n)&3))
			// we have processed one DWORD.  Now we need to skip ahead
			// MMX_COEF-1 dwords (to get to the next DWORD for 'this' crypt)
			in += 4*(MMX_COEF-1);
	}
}

void DynamicFunc__FreeBSDMD5Crypt_MMX()
{
	unsigned char tmp[64], *cp;
	int i, x, len;
	unsigned j, jj, plen, idx, idx_mod;
	char *pass;

	FreeBSDMD5Crypt_setup_MMX();

	memset(md5_tmp_in, 0, sizeof(md5_tmp_in));
	// Build B
	memset(tmp, 0, sizeof(tmp));
	idx = 0;
#ifdef MD5_SSE_PARA
	for ( ; idx < MD5_SSE_PARA; ++ idx)
#endif
	{
		for (x = 0; x < MMX_COEF; ++x) {
			idx_mod = x%MMX_COEF;
			pass = saved_key[idx*MMX_COEF+x];
			plen = saved_key_len[idx*MMX_COEF+x];

			cp = tmp;
			memcpy(cp, pass, plen); cp += plen;
			memcpy(cp, cursalt, saltlen); cp += saltlen;
			memcpy(cp, pass, plen); cp += plen;
			SETLEN_MD5_INPUT(tmp, 0, md5_tmp_in);
			memset(tmp, 0, cp-tmp+1);
		}
	}

#ifdef MD5_SSE_PARA
	SSEmd5body(md5_tmp_in, (unsigned int *)md5_tmp_out, 1);
#else
	mdfivemmx_nosizeupdate(md5_tmp_out[0], md5_tmp_in[0], 1);
#endif

	// Build A  A should ALWAYS be larger then B, so no memset needed.
	//memset(md5_tmp_in, 0, sizeof(md5_tmp_in));
	idx = 0;
#ifdef MD5_SSE_PARA
	for ( ; idx < MD5_SSE_PARA; ++ idx)
#endif
	{
		for (x = 0; x < MMX_COEF; ++x) {
			idx_mod = x%MMX_COEF;
			pass = saved_key[idx*MMX_COEF+x];
			plen = saved_key_len[idx*MMX_COEF+x];

			cp = tmp;
			memcpy(cp, pass, plen);
			cp += plen;
			memcpy(cp, curdat.Consts[0], curdat.ConstsLen[0]);
			cp += curdat.ConstsLen[0];

			memcpy(cp, cursalt, saltlen);
			cp += saltlen;

			// since pass len ls limted to 15 bytes (so all will fit in one MD5 block),
			// we can ignore the loop, and just use plen
			//for (i = plen; i > 0; i -= 16) {
			//	CopyCryptToFlat(md5_tmp_out, cp, idx, idx_out);
			//	memcpy(cp, b, i>16?16:i);
			//	cp += i>16?16:i;
			//}
			CopyCryptToFlat(cp, plen, idx, idx_mod);
			cp += plen;

			i = plen;
			for (i = plen; i ; i >>= 1)
				if (i & 1)
					*cp++ = 0;
				else
					*cp++ = pass[0];
			SETLEN_MD5_INPUT(tmp, 0, md5_tmp_in);
			memset(tmp, 0, cp-tmp+1);
		}
	}

	// Ok, now place this 16 bytes into the 'proper' location.
	// This is A but we simply shove it to the start of md5_cp which is where we start from.

#ifdef MD5_SSE_PARA
	SSEmd5body(md5_tmp_in, (unsigned int *)md5_tmp_out, 1);
	for (j = 0; j < MD5_SSE_PARA; ++j)
		memcpy(md5_cp[j], md5_tmp_out[j], 16*MMX_COEF);
#else
	mdfivemmx_nosizeupdate(md5_cp[0], md5_tmp_in[0], 1);
#endif

	for (jj = j = 0; jj < 500; ++jj) {
		j=jj%21;
#ifdef MD5_SSE_PARA
		SSEmd5body(md5_items[j].in1, (unsigned int *)md5_tmp_out, 1);
		CopyCryptToOut1Location(md5_tmp_out[0], j, 0);
		SSEmd5body(md5_items[j].in2, (unsigned int *)md5_tmp_out, 1);
		cp = md5_items[j].out2;
		for (i = 0; i < MD5_SSE_PARA; ++i) {
			memcpy(cp, md5_tmp_out[i], 16*MMX_COEF);
			cp += 64*MMX_COEF;
		}
#else
		mdfivemmx_nosizeupdate(md5_tmp_out[0], md5_items[j].in1, 64);
		CopyCryptToOut1Location(md5_tmp_out[0], j, 0);
		mdfivemmx_nosizeupdate(md5_items[j].out2, md5_items[j].in2, 64);
#endif
		// unrolling seems to be slower.
	}
#ifdef MD5_SSE_PARA
	cp = md5_items[j].out2;
	for (i = 0; i < MD5_SSE_PARA; ++i) {
		memcpy(crypt_key[i], cp, BINARY_SIZE*MMX_COEF);
		cp += 64*MMX_COEF;
	}
#else
	memcpy(crypt_key[0], md5_items[j].out2, BINARY_SIZE*MMX_COEF);
#endif


	dynamic_use_sse = 1;
}

#endif
void DynamicFunc__FreeBSDMD5Crypt()
{
#ifdef MMX_COEF
	DynamicFunc__FreeBSDMD5Crypt_MMX();
#else
	DynamicFunc__FreeBSDMD5Crypt_ANY();
#endif
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Special crypt to handle the 'looping' needed for phpass
 *************************************************************/
void DynamicFunc__PHPassCrypt()
{
	unsigned Lcount;

	Lcount = atoi64[ARCH_INDEX(cursalt[8])];
	if (Lcount < 7 || Lcount > 31)
		exit(!!fprintf(stderr, "Error, invalid loop byte in a php salt %s\n",cursalt));
	Lcount = (1<<Lcount);

	DynamicFunc__clean_input();

	// First 'round' is md5 of ($s.$p)
	DynamicFunc__append_salt();
	DynamicFunc__append_keys();

	// The later rounds (variable number, based upon the salt's first byte)
	//   are ALL done as 16 byte md5 result of prior hash, with the password appeneded

	// crypt, and put the 'raw' 16 byte raw crypt data , into the
	// input buffer.  We will then append the keys to that, and never
	// have to append the keys again (we just make sure we do NOT adjust
	// the amount of bytes to md5 from this point no
	DynamicFunc__crypt_md5_to_input_raw();

	// Now append the pass
	DynamicFunc__append_keys();

	// NOTE last we do 1 less than the required number of crypts in our loop
	DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE();

#if !ARCH_LITTLE_ENDIAN
	// from this point on, we want to have the binary blobs in 'native' big endian
	// format. Thus, we need to 'unswap' them.  Then the call to the
	// DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen will leave the 16 bytes
	// output, in big endian (thus needing no swapping).
	// we only have to 'fix up' the final crypt results.
#if MD5_X2
		MD5_swap(input_buf_X86[0].x2.w2, input_buf_X86[0].x2.w2, 4);
#endif
		MD5_swap(input_buf_X86[0].x1.w, input_buf_X86[0].x1.w, 4);
#endif

	--Lcount;
	while(--Lcount)
		DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen();

	// final crypt is to the normal 'output' buffer, since john uses that to find 'hits'.
#if !ARCH_LITTLE_ENDIAN
	// we have to use this funtion, since we do not want to 'fixup' the
	// end of the buffer again (it has been put into BE format already.
	// Thus, simply use the raw_overwrite again, then swap the output that
	// is found in the input buf to the output buf.
	DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen();
#if MD5_X2
	MD5_swap(input_buf_X86[0].x2.w2, crypt_key_X86[0].x2.w2, 4);
#endif
	MD5_swap(input_buf_X86[0].x1.w, crypt_key_X86[0].x1.w, 4);
#else
	// little endian can use 'original' crypt function.
	DynamicFunc__crypt_md5();
#endif
}
void DynamicFunc__POCrypt()
{
	//DynamicFunc__clean_input_kwik();
	//DynamicFunc__append_salt,
	//DynamicFunc__append_input1_from_CONST1,
	//DynamicFunc__append_keys,
	//DynamicFunc__append_input1_from_CONST2,
	//DynamicFunc__append_salt,
	//DynamicFunc__crypt_md5,

	unsigned i, len;
	unsigned char *pBuf = input_buf_X86[0].x1.B;
#if MD5_X2
	unsigned lens[2];
	unsigned char *pBuf2 = input_buf_X86[0].x2.B2;
	memset(pBuf2, 0, sizeof(input_buf_X86[0].x2.B2));
	memcpy(pBuf2, cursalt, 32);
	pBuf2[32] = 'Y';
#endif
	memset(pBuf, 0, sizeof(input_buf_X86[0].x1.b));
	memcpy(pBuf, cursalt, 32);
	pBuf[32] = 'Y';
	for (i = 0; i < m_count; ++i) {
		len = saved_key_len[i];
		memcpy(&pBuf[33], saved_key[i], len);
		pBuf[33+len] = 0xf7;
		memcpy(&pBuf[34+len], cursalt, 32);

#if MD5_X2
		lens[0] = len+66;  // len from the 'first'
		++i;
		len = saved_key_len[i];
		memcpy(&pBuf2[33], saved_key[i], len);
		pBuf2[33+len] = 0xf7;
		memcpy(&pBuf2[34+len], cursalt, 32);
		lens[1] = len+66;
		DoMD5(input_buf_X86[0], lens, crypt_key_X86[i>>MD5_X2]);
#else
		DoMD5(input_buf_X86[0], (len+66), crypt_key_X86[i]);
#endif
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the 2nd input field into crypt_keys2.
 *************************************************************/
void DynamicFunc__crypt2_md5()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; i += MD5_SSE_PARA) {
			SSE_Intrinsics_LoadLens(1, i);
			SSEmd5body((unsigned char*)(&input_buf2[i]), (unsigned int*)(&crypt_key2[i]), 1);
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
			mdfivemmx((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf2[i]), total_len2[i]);
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len2_X86[i++];
		len[1] = total_len2_X86[i];
#else
		unsigned len = total_len2_X86[i];
#endif
		DoMD5(input_buf2_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}
void DynamicFunc__crypt2_md4()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD4_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; i += MD4_SSE_PARA) {
			SSE_Intrinsics_LoadLens(1, i);
			SSEmd4body((unsigned char*)(&input_buf2[i]), (unsigned int*)(&crypt_key2[i]), 1);
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
			mdfourmmx((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf2[i]), total_len2[i]);
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned len[2];
		len[0] = total_len2_X86[i++];
		len[1] = total_len2_X86[i];
#else
		unsigned len = total_len2_X86[i];
#endif
		DoMD4(input_buf2_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the 1st input field      crypt_keys2.
 *************************************************************/
void DynamicFunc__crypt_md5_in1_to_out2()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; i += MD5_SSE_PARA) {
				SSEmd5body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key2[i]), 1);
			}
		} else {
			for (i = 0; i < cnt; i += MD5_SSE_PARA) {
				SSE_Intrinsics_LoadLens(0, i);
				SSEmd5body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key2[i]), 1);
			}
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; ++i)
				mdfivemmx_nosizeupdate((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf[i]), 1);
		} else {
			for (i = 0; i < cnt; ++i)
				mdfivemmx((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
		}
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i++];
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}
void DynamicFunc__crypt_md4_in1_to_out2()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD4_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; i += MD4_SSE_PARA) {
				SSEmd4body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key2[i]), 1);
			}
		} else {
			for (i = 0; i < cnt; i += MD4_SSE_PARA) {
				SSE_Intrinsics_LoadLens(0, i);
				SSEmd4body((unsigned char*)(&input_buf[i]), (unsigned int*)(&crypt_key2[i]), 1);
			}
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		if (curdat.store_keys_in_input) {
			for (i = 0; i < cnt; ++i)
				mdfourmmx_nosizeupdate((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf[i]), 1);
		} else {
			for (i = 0; i < cnt; ++i)
				mdfourmmx((unsigned char*)&(crypt_key2[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
		}
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i++];
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		DoMD4(input_buf_X86[i>>MD5_X2], len, crypt_key2_X86[i>>MD5_X2]);
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Encrypts the data in the 2nd input field into crypt_keys.
 *************************************************************/
void DynamicFunc__crypt_md5_in2_to_out1()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));;
		for (i = 0; i < cnt; i += MD5_SSE_PARA)
		{
			SSE_Intrinsics_LoadLens(1, i);
			SSEmd5body((unsigned char*)(&input_buf2[i]), (unsigned int*)(&crypt_key[i]), 1);
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));;
		for (i = 0; i < cnt; ++i)
			mdfivemmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf2[i]), total_len2[i]);
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len2_X86[i++];
		len[1] = total_len2_X86[i];
#else
		unsigned len = total_len2_X86[i];
#endif
		DoMD5(input_buf2_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}
void DynamicFunc__crypt_md4_in2_to_out1()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD4_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));;
		for (i = 0; i < cnt; i += MD4_SSE_PARA)
		{
			SSE_Intrinsics_LoadLens(1, i);
			SSEmd4body((unsigned char*)(&input_buf2[i]), (unsigned int*)(&crypt_key[i]), 1);
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));;
		for (i = 0; i < cnt; ++i)
			mdfourmmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf2[i]), total_len2[i]);
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
		// MD5_X2 sets our input buffers and crypt keys up in 'double' format. Thus, we HAVE
		// to treat them just like we do in MD5.  The macro hides the details.
#if MD5_X2
		unsigned len[2];
		len[0] = total_len2_X86[i++];
		len[1] = total_len2_X86[i];
#else
		unsigned len = total_len2_X86[i];
#endif
		DoMD4(input_buf2_X86[i>>MD5_X2], len, crypt_key_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md5_to_input_raw()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; i += MD5_SSE_PARA)
		{
			unsigned j;
			SSE_Intrinsics_LoadLens(0, i);
			// NOTE, since crypt_key array is 16 bytes each, and input_buf is 64 bytes
			// each, and we are doing 3 at a time, we can NOT directly write to the
			// input buff, but have to use the crypt_key buffer, and then memcpy when done.
			SSEmd5body((char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			for (j = 0; j < MD5_SSE_PARA; ++j)
			{
				memset((&input_buf[i+j]), 0, sizeof(input_buf[0]));
				memcpy((char*)(&input_buf[i+j]), (char*)(&crypt_key[i+j]), 16*4);
				total_len[i+j] = 0x10101010;
			}
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
		{
			mdfivemmx((unsigned char*)&(crypt_key[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
			memset((&input_buf[i]), 0, sizeof(input_buf[0]));
			memcpy((char*)(&input_buf[i]), (char*)(&crypt_key[i]), sizeof(crypt_key[0]));
#if (MMX_COEF==4)
			total_len[i] = 0x10101010;
#else
			total_len[i] = 0x100010;
#endif
		}
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i];
		total_len_X86[i++] = 0x10;
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, input_buf_X86[i>>MD5_X2]);
		total_len_X86[i] = 0x10;
	}
}
void DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen_but_setlen_in_SSE()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; i += MD5_SSE_PARA)
		{
			unsigned j;
			SSE_Intrinsics_LoadLens(0, i);
			// NOTE, since crypt_key array is 16 bytes each, and input_buf is 64 bytes
			// each, and we are doing 3 at a time, we can NOT directly write to the
			// input buff, but have to use the crypt_key buffer, and then memcpy when done.
			SSEmd5body((char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			for (j = 0; j < MD5_SSE_PARA; ++j)
				memcpy((char*)(&input_buf[i+j]), (char*)(&crypt_key[i+j]), 16*4);
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
			mdfivemmx((unsigned char*)&(input_buf[i]), (unsigned char*)&(input_buf[i]), total_len[i]);
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i++];
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		DoMD5(input_buf_X86[i>>MD5_X2], len, input_buf_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__crypt_md5_to_input_raw_Overwrite_NoLen()
{
	unsigned i;
#ifdef MMX_COEF
#ifdef MD5_SSE_PARA
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; i += MD5_SSE_PARA)
		{
			unsigned j;
			// NOTE, since crypt_key array is 16 bytes each, and input_buf is 64 bytes
			// each, and we are doing 3 at a time, we can NOT directly write to the
			// input buff, but have to use the crypt_key buffer, and then memcpy when done.
			SSEmd5body((char*)(&input_buf[i]), (unsigned int*)(&crypt_key[i]), 1);
			for (j = 0; j < MD5_SSE_PARA; ++j)
				memcpy((char*)(&input_buf[i+j]), (char*)(&crypt_key[i+j]), 16*4);
		}
		return;
	}
#else
	if (dynamic_use_sse==1) {
		unsigned cnt = ( ((unsigned)m_count+MMX_COEF-1)>>(MMX_COEF>>1));
		for (i = 0; i < cnt; ++i)
			mdfivemmx_nosizeupdate((unsigned char*)&(input_buf[i]), (unsigned char*)&(input_buf[i]), 0);
		return;
	}
#endif
#endif
	for (i = 0; i < m_count; ++i) {
#if MD5_X2
		unsigned len[2];
		len[0] = total_len_X86[i++];
		len[1] = total_len_X86[i];
#else
		unsigned len = total_len_X86[i];
#endif
		// we call DoMD5o so as to 'not' change then length (it was already set)
		DoMD5o(input_buf_X86[i>>MD5_X2], len, input_buf_X86[i>>MD5_X2]);
	}
}

void DynamicFunc__overwrite_salt_to_input1_no_size_fix()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		if (md5_unicode_convert) {
			if (!options.ascii && !options.iso8859_1) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;
				outlen = enc_to_utf16(utf16Str, 27, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (j = 0; j < m_count; ++j) {
					__SSE_append_string_to_input((unsigned char*)(&input_buf[j>>(MMX_COEF>>1)]),j&(MMX_COEF-1),(unsigned char*)utf16Str,outlen,0,0);
				}
			} else {
				for (j = 0; j < m_count; ++j)
					__SSE_append_string_to_input_unicode((unsigned char*)(&input_buf[j>>(MMX_COEF>>1)]),j&(MMX_COEF-1),(unsigned char*)cursalt,saltlen,0,0);
			}
			return;
		}
		for (j = 0; j < m_count; ++j)
			__SSE_append_string_to_input((unsigned char*)(&input_buf[j>>(MMX_COEF>>1)]),j&(MMX_COEF-1),cursalt,saltlen,0,0);
		return;
	}
#endif
	if (md5_unicode_convert) {
		if (!options.ascii && !options.iso8859_1) {
			UTF16 utf16Str[EFFECTIVE_MAX_LENGTH / 3 + 1];
			int outlen;
			outlen = enc_to_utf16(utf16Str, EFFECTIVE_MAX_LENGTH / 3, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);

			for (j = 0; j < m_count; ++j) {
				int z;
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
			for (j = 0; j < m_count; ++j) {
				int z;
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
	for (j = 0; j < m_count; ++j) {
#if MD5_X2
		if (j&1)
			memcpy(input_buf_X86[j>>MD5_X2].x2.b2, cursalt, saltlen);
		else
#endif
		memcpy(input_buf_X86[j>>MD5_X2].x1.b, cursalt, saltlen);
	}
}
void DynamicFunc__overwrite_salt_to_input2_no_size_fix()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		if (md5_unicode_convert) {
			if (!options.ascii && !options.iso8859_1) {
				UTF16 utf16Str[27+1]; // 27 chars is 'max' that fits in SSE without overflow, so that is where we limit it at now
				int outlen;
				outlen = enc_to_utf16(utf16Str, 27, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
				if (outlen < 0)
					outlen = strlen16(utf16Str) * sizeof(UTF16);
				for (j = 0; j < m_count; ++j) {
					__SSE_append_string_to_input((unsigned char*)(&input_buf2[j>>(MMX_COEF>>1)]),j&(MMX_COEF-1),(unsigned char*)utf16Str,outlen,0,0);
				}
			} else {
				for (j = 0; j < m_count; ++j)
					__SSE_append_string_to_input_unicode((unsigned char*)(&input_buf2[j>>(MMX_COEF>>1)]),j&(MMX_COEF-1),(unsigned char*)cursalt,saltlen,0,0);
			}
			return;
		}
		for (j = 0; j < m_count; ++j)
			__SSE_append_string_to_input((unsigned char*)(&input_buf2[j>>(MMX_COEF>>1)]),j&(MMX_COEF-1),cursalt,saltlen,0,0);
		return;
	}
#endif
	if (md5_unicode_convert) {
		if (!options.ascii && !options.iso8859_1) {
			UTF16 utf16Str[EFFECTIVE_MAX_LENGTH / 3 + 1];
			int outlen;
			outlen = enc_to_utf16(utf16Str, EFFECTIVE_MAX_LENGTH / 3, (unsigned char*)cursalt, saltlen) * sizeof(UTF16);
			if (outlen < 0)
				outlen = strlen16(utf16Str) * sizeof(UTF16);

			for (j = 0; j < m_count; ++j) {
				int z;
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
			for (j = 0; j < m_count; ++j) {
				int z;
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
	for (j = 0; j < m_count; ++j) {
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
void DynamicFunc__overwrite_from_last_output2_to_input1_as_base16_no_size_fix()
{
	unsigned i, j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned idx;
		for (i = 0; i < m_count; ++i)
		{
			idx = ( ((unsigned)i)>>(MMX_COEF>>1));
			__SSE_overwrite_output_base16_to_input((void*)(&input_buf[idx]), (unsigned char*)(&crypt_key2[idx]), i&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		unsigned char *cpo, *cpi;
		/* MD5_word *w; */
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
		// if swapped, then HDAA fails on big endian systems.
	}
}

/**************************************************************
 * DYNAMIC primitive helper function
 * overwrites start of input1 from the output1 data using base-16
 *************************************************************/
void DynamicFunc__overwrite_from_last_output_as_base16_no_size_fix()
{
	unsigned i, j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned idx;
		for (i = 0; i < m_count; ++i)
		{
			idx = ( ((unsigned)i)>>(MMX_COEF>>1));
			__SSE_overwrite_output_base16_to_input((void*)(&input_buf[idx]), (unsigned char*)(&crypt_key[idx]), i&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		unsigned char *cpo, *cpi;
		/* MD5_word *w; */
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
		// if swapped, then HDAA fails on big endian systems.
	}
}


/**************************************************************
 * DYNAMIC primitive helper function
 * This will take the data stored in the crypt_keys (the encrypted
 * 'first' key variable), and use a base-16 text formatting, and
 * append this to the first input buffer (adjusting the lengths)
 *************************************************************/
void DynamicFunc__append_from_last_output_as_base16()
{
	unsigned j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			total_len[idx] += (32<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
			if (!ip)
				__SSE_append_output_base16_to_input((void*)(&input_buf[idx]), (unsigned char*)(&crypt_key[idx]), index&(MMX_COEF-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (j = 0; j < 16; ++j)
				{
					unsigned char v = crypt_key[idx][GETPOS(j, index&(MMX_COEF-1))];
					input_buf[idx][GETPOS(ip+(j<<1), index&(MMX_COEF-1))] = dynamic_itoa16[v>>4];
					input_buf[idx][GETPOS(ip+(j<<1)+1, index&(MMX_COEF-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, (void*)(&input_buf[idx]), (unsigned char*)(&crypt_key[idx]), index&(MMX_COEF-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, (void*)(&input_buf[idx]), (unsigned char*)(&crypt_key[idx]), index&(MMX_COEF-1));

		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		unsigned char *cp, *cpi;
		unsigned i;
#if MD5_X2
		if (j&1)
		{cp = &(input_buf_X86[j>>MD5_X2].x2.B2[total_len_X86[j]]); cpi =  crypt_key_X86[j>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf_X86[j>>MD5_X2].x1.B[total_len_X86[j]]);  cpi = crypt_key_X86[j>>MD5_X2].x1.B; }
		for (i = 0; i < 16; ++i)
		{
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
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
void DynamicFunc__append_from_last_output2_as_base16()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			total_len2[idx] += (32<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
			if (!ip)
				__SSE_append_output_base16_to_input((void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key2[idx]), index&(MMX_COEF-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (i = 0; i < 16; ++i)
				{
					unsigned char v = crypt_key2[idx][GETPOS(i, index&(MMX_COEF-1))];
					input_buf2[idx][GETPOS(ip+(i<<1), index&(MMX_COEF-1))] = dynamic_itoa16[v>>4];
					input_buf2[idx][GETPOS(ip+(i<<1)+1, index&(MMX_COEF-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf2[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, (void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key2[idx]), index&(MMX_COEF-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, (void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key2[idx]), index&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
		unsigned char *cp, *cpi;
#if MD5_X2
		if (i&1)
		{cp = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x1.B; }
		for (j = 0; j < 16; ++j)
		{
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
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
void DynamicFunc__overwrite_from_last_output_to_input2_as_base16_no_size_fix()
{
	unsigned i, j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned idx;
		for (i = 0; i < m_count; ++i)
		{
			idx = ( ((unsigned)i)>>(MMX_COEF>>1));
			__SSE_overwrite_output_base16_to_input((void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key[idx]), i&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		unsigned char *cpo, *cpi;
		/* MD5_word *w; */
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
		// if swapped, then HDAA fails on big endian systems.
	}
}
/**************************************************************
 * DYNAMIC primitive helper function
 * overwrites start of input2 from the output2 data using base-16
 *************************************************************/
void DynamicFunc__overwrite_from_last_output2_as_base16_no_size_fix()
{
	unsigned i, j;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned idx;
		for (i = 0; i < m_count; ++i)
		{
			idx = ( ((unsigned)i)>>(MMX_COEF>>1));
			__SSE_overwrite_output_base16_to_input((void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key2[idx]), i&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (j = 0; j < m_count; ++j)
	{
		unsigned char *cpo, *cpi;
		/* MD5_word *w; */
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
		// if swapped, then HDAA fails on big endian systems.
	}
}


/**************************************************************
 * DYNAMIC primitive helper function
 * This will take the data stored in the crypt_keys1 (the encrypted
 * 'first' key variable), and base-16 appends to the 2nd input
 *************************************************************/
void DynamicFunc__append_from_last_output_to_input2_as_base16()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			total_len2[idx] += (32<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
			if (!ip)
				__SSE_append_output_base16_to_input((void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key[idx]), index&(MMX_COEF-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (i = 0; i < 16; ++i)
				{
					unsigned char v = crypt_key[idx][GETPOS(i, index&(MMX_COEF-1))];
					input_buf2[idx][GETPOS(ip+(i<<1), index&(MMX_COEF-1))] = dynamic_itoa16[v>>4];
					input_buf2[idx][GETPOS(ip+(i<<1)+1, index&(MMX_COEF-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf2[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, (void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key[idx]), index&(MMX_COEF-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, (void*)(&input_buf2[idx]), (unsigned char*)(&crypt_key[idx]), index&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
		unsigned char *cp, *cpi;
#if MD5_X2
		if (i&1)
		{cpi = crypt_key_X86[i>>MD5_X2].x2.B2; cp = &(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]); }
		else
#endif
		{cpi = crypt_key_X86[i>>MD5_X2].x1.B; cp = &(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);}
		for (j = 0; j < 16; ++j)
		{
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
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
void DynamicFunc__append_from_last_output2_to_input1_as_base16()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			total_len[idx] += (32<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
			if (!ip)
				__SSE_append_output_base16_to_input((void*)(&input_buf[idx]), (unsigned char*)(&crypt_key2[idx]), index&(MMX_COEF-1));
			else if (ip&1)
			{
				// Note we are 100% unaligned, and it seems fastest to handle byte/byte (at this time).
				for (i = 0; i < 16; ++i)
				{
					unsigned char v = crypt_key2[idx][GETPOS(i, index&(MMX_COEF-1))];
					input_buf[idx][GETPOS(ip+(i<<1), index&(MMX_COEF-1))] = dynamic_itoa16[v>>4];
					input_buf[idx][GETPOS(ip+(i<<1)+1, index&(MMX_COEF-1))] = dynamic_itoa16[v&0xF];
				}
				input_buf[idx][GETPOS(ip+32, index&(MMX_COEF-1))] = 0x80;
			}
			else if ((ip&3)==0)
				__SSE_append_output_base16_to_input_semi_aligned_0(ip, (void*)(&input_buf[idx]), (unsigned char*)(&crypt_key2[idx]), index&(MMX_COEF-1));
			else
				__SSE_append_output_base16_to_input_semi_aligned_2(ip, (void*)(&input_buf[idx]), (unsigned char*)(&crypt_key2[idx]), index&(MMX_COEF-1));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
		unsigned char *cp, *cpi;
#if MD5_X2
		if (i&1)
		{cp = &(input_buf_X86[i>>MD5_X2].x2.B2[total_len_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x2.B2; }
		else
#endif
		{cp = &(input_buf_X86[i>>MD5_X2].x1.B[total_len_X86[i]]); cpi = crypt_key2_X86[i>>MD5_X2].x1.B; }
		for (j = 0; j < 16; ++j)
		{
			unsigned char b = *cpi++;
			*cp++ = dynamic_itoa16[b>>4];
			*cp++ = dynamic_itoa16[b&0xF];
		}
		*cp = 0;
		total_len_X86[i] += 32;
	}
}

void DynamicFunc__append_from_last_output2_as_raw()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			if (!ip)
			{
				ARCH_WORD_32 *po = (ARCH_WORD_32*)(&(input_buf[idx]));
				ARCH_WORD_32 *pi = (ARCH_WORD_32*)(&(crypt_key2[idx]));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += MMX_COEF;
					pi += MMX_COEF;
				}
				input_buf[idx][GETPOS(16, index&(MMX_COEF-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf[idx][GETPOS(ip+i, index&(MMX_COEF-1))] = crypt_key2[idx][GETPOS(i, index&(MMX_COEF-1))];
				input_buf[idx][GETPOS(ip+16, index&(MMX_COEF-1))] = 0x80;
			}
			total_len[idx] += (16<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
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

void DynamicFunc__append2_from_last_output2_as_raw()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			if (!ip)
			{
				ARCH_WORD_32 *po = (ARCH_WORD_32*)(&(input_buf2[idx]));
				ARCH_WORD_32 *pi = (ARCH_WORD_32*)(&(crypt_key2[idx]));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += MMX_COEF;
					pi += MMX_COEF;
				}
				input_buf2[idx][GETPOS(16, index&(MMX_COEF-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf2[idx][GETPOS(ip+i, index&(MMX_COEF-1))] = crypt_key2[idx][GETPOS(i, index&(MMX_COEF-1))];
				input_buf2[idx][GETPOS(ip+16, index&(MMX_COEF-1))] = 0x80;
			}
			total_len2[idx] += (16<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
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
void DynamicFunc__append_from_last_output1_as_raw()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			if (!ip)
			{
				ARCH_WORD_32 *po = (ARCH_WORD_32*)(&(input_buf[idx]));
				ARCH_WORD_32 *pi = (ARCH_WORD_32*)(&(crypt_key[idx]));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += MMX_COEF;
					pi += MMX_COEF;
				}
				input_buf[idx][GETPOS(16, index&(MMX_COEF-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf[idx][GETPOS(ip+i, index&(MMX_COEF-1))] = crypt_key[idx][GETPOS(i, index&(MMX_COEF-1))];
				input_buf[idx][GETPOS(ip+16, index&(MMX_COEF-1))] = 0x80;
			}
			total_len[idx] += (16<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
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
void DynamicFunc__append2_from_last_output1_as_raw()
{
	unsigned i;
#ifdef MMX_COEF
	if (dynamic_use_sse==1) {
		unsigned index, idx;
		for (index = 0; index < m_count; ++index)
		{
			unsigned ip;
			idx = ( ((unsigned)index)>>(MMX_COEF>>1));
			// This is the 'actual' work.
			ip = (total_len2[idx] >> ((32/MMX_COEF)*(index&(MMX_COEF-1)))) & 0xFF;
			if (!ip)
			{
				ARCH_WORD_32 *po = (ARCH_WORD_32*)(&(input_buf2[idx]));
				ARCH_WORD_32 *pi = (ARCH_WORD_32*)(&(crypt_key[idx]));
				for (i = 0; i < 4; i++)
				{
					*po = *pi;
					po += MMX_COEF;
					pi += MMX_COEF;
				}
				input_buf2[idx][GETPOS(16, index&(MMX_COEF-1))] = 0x80;
			}
			else
			{
				for (i = 0; i < 16; ++i)
					input_buf2[idx][GETPOS(ip+i, index&(MMX_COEF-1))] = crypt_key[idx][GETPOS(i, index&(MMX_COEF-1))];
				input_buf2[idx][GETPOS(ip+16, index&(MMX_COEF-1))] = 0x80;
			}
			total_len2[idx] += (16<<((32/MMX_COEF)*(index&(MMX_COEF-1))));
		}
		return;
	}
#endif
	for (i = 0; i < m_count; ++i)
	{
		unsigned j;
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
void DynamicFunc__append_2nd_salt()
{
	__append_string(cursalt2, saltlen2);
}
/**************************************************************
 * DYNAMIC primitive helper function
 * Append salt #2 into input 2
 *************************************************************/
void DynamicFunc__append_2nd_salt2()
{
	__append2_string(cursalt2, saltlen2);
}

/**************************************************************
 * DYNAMIC primitive helper function
 * Append UserID into input 1
 *************************************************************/
void DynamicFunc__append_userid()
{
	__append_string(username, usernamelen);
}
/**************************************************************
 * DYNAMIC primitive helper function
 * Append UserID into input 2
 *************************************************************/
void DynamicFunc__append_userid2()
{
	__append2_string(username, usernamelen);
}

void DynamicFunc__append_input1_from_CONST1()
{
	__append_string(curdat.Consts[0], curdat.ConstsLen[0]);
}
void DynamicFunc__append_input1_from_CONST2()
{
	__append_string(curdat.Consts[1], curdat.ConstsLen[1]);
}
void DynamicFunc__append_input1_from_CONST3()
{
	__append_string(curdat.Consts[2], curdat.ConstsLen[2]);
}
void DynamicFunc__append_input1_from_CONST4()
{
	__append_string(curdat.Consts[3], curdat.ConstsLen[3]);
}
void DynamicFunc__append_input1_from_CONST5()
{
	__append_string(curdat.Consts[4], curdat.ConstsLen[4]);
}
void DynamicFunc__append_input1_from_CONST6()
{
	__append_string(curdat.Consts[5], curdat.ConstsLen[5]);
}
void DynamicFunc__append_input1_from_CONST7()
{
	__append_string(curdat.Consts[6], curdat.ConstsLen[6]);
}
void DynamicFunc__append_input1_from_CONST8()
{
	__append_string(curdat.Consts[7], curdat.ConstsLen[7]);
}

void DynamicFunc__append_input2_from_CONST1()
{
	__append2_string(curdat.Consts[0], curdat.ConstsLen[0]);
}
void DynamicFunc__append_input2_from_CONST2()
{
	__append2_string(curdat.Consts[1], curdat.ConstsLen[1]);
}
void DynamicFunc__append_input2_from_CONST3()
{
	__append2_string(curdat.Consts[2], curdat.ConstsLen[2]);
}
void DynamicFunc__append_input2_from_CONST4()
{
	__append2_string(curdat.Consts[3], curdat.ConstsLen[3]);
}
void DynamicFunc__append_input2_from_CONST5()
{
	__append2_string(curdat.Consts[4], curdat.ConstsLen[4]);
}
void DynamicFunc__append_input2_from_CONST6()
{
	__append2_string(curdat.Consts[5], curdat.ConstsLen[5]);
}
void DynamicFunc__append_input2_from_CONST7()
{
	__append2_string(curdat.Consts[6], curdat.ConstsLen[6]);
}
void DynamicFunc__append_input2_from_CONST8()
{
	__append2_string(curdat.Consts[7], curdat.ConstsLen[7]);
}

void DynamicFunc__append_fld0()
{
	__append_string(flds[0], fld_lens[0]);
}
void DynamicFunc__append_fld1()
{
	__append_string(flds[1], fld_lens[1]);
}
void DynamicFunc__append_fld2()
{
	__append_string(flds[2], fld_lens[2]);
}
void DynamicFunc__append_fld3()
{
	__append_string(flds[3], fld_lens[3]);
}
void DynamicFunc__append_fld4()
{
	__append_string(flds[4], fld_lens[4]);
}
void DynamicFunc__append_fld5()
{
	__append_string(flds[5], fld_lens[5]);
}
void DynamicFunc__append_fld6()
{
	__append_string(flds[6], fld_lens[6]);
}
void DynamicFunc__append_fld7()
{
	__append_string(flds[7], fld_lens[7]);
}
void DynamicFunc__append_fld8()
{
	__append_string(flds[8], fld_lens[8]);
}
void DynamicFunc__append_fld9()
{
	__append_string(flds[9], fld_lens[9]);
}

void DynamicFunc__append2_fld0()
{
	__append2_string(flds[0], fld_lens[0]);
}
void DynamicFunc__append2_fld1()
{
	__append2_string(flds[1], fld_lens[1]);
}
void DynamicFunc__append2_fld2()
{
	__append2_string(flds[2], fld_lens[2]);
}
void DynamicFunc__append2_fld3()
{
	__append2_string(flds[3], fld_lens[3]);
}
void DynamicFunc__append2_fld4()
{
	__append2_string(flds[4], fld_lens[4]);
}
void DynamicFunc__append2_fld5()
{
	__append2_string(flds[5], fld_lens[5]);
}
void DynamicFunc__append2_fld6()
{
	__append2_string(flds[6], fld_lens[6]);
}
void DynamicFunc__append2_fld7()
{
	__append2_string(flds[7], fld_lens[7]);
}
void DynamicFunc__append2_fld8()
{
	__append2_string(flds[8], fld_lens[8]);
}
void DynamicFunc__append2_fld9()
{
	__append2_string(flds[9], fld_lens[9]);
}


void DynamicFunc__SSEtoX86_switch_input1() {
#ifdef MMX_COEF
	int j, k, idx, max;
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += MMX_COEF)
	{
		ARCH_WORD_32 *cpi;
#if (MD5_X2)
		ARCH_WORD_32 *cpo  = input_buf_X86[j>>1].x1.w;
		ARCH_WORD_32 *cpo2 = input_buf_X86[j>>1].x2.w2;
		ARCH_WORD_32 *cpo3 = input_buf_X86[(j>>1)+1].x1.w;
		ARCH_WORD_32 *cpo4 = input_buf_X86[(j>>1)+1].x2.w2;
#else
		ARCH_WORD_32 *cpo = input_buf_X86[j].x1.w;
		ARCH_WORD_32 *cpo2 = input_buf_X86[j+1].x1.w;
#if (MMX_COEF==4)
		ARCH_WORD_32 *cpo3 = input_buf_X86[j+2].x1.w;
		ARCH_WORD_32 *cpo4 = input_buf_X86[j+3].x1.w;
#endif
#endif
		idx = ( ((unsigned)j)>>(MMX_COEF>>1));
		cpi = (void*)(&input_buf[idx]);

		max = total_len_X86[j] = (total_len[idx]&0xFF);
#if (MMX_COEF==2)
		if (max < (total_len_X86[j+1]=((total_len[idx]>> 16)&0xFF)))
			max = total_len_X86[j+1];
#else
		if (max < (total_len_X86[j+1]=((total_len[idx]>> 8)&0xFF)))
			max = total_len_X86[j+1];
		if (max < (total_len_X86[j+2]=((total_len[idx]>>16)&0xFF)))
			max = total_len_X86[j+2];
		if (max < (total_len_X86[j+3]=((total_len[idx]>>24)&0xFF)))
			max = total_len_X86[j+3];
#endif
		max = (max+3)>>2;
		for (k = 0; k < max; ++k) {
			*cpo++ = *cpi++;
			*cpo2++ = *cpi++;
#if (MMX_COEF==4)
			*cpo3++ = *cpi++;
			*cpo4++ = *cpi++;
#endif
		}
#if (MD5_X2)
		input_buf_X86[j>>1].x1.b[total_len_X86[j]] = 0;
		input_buf_X86[j>>1].x2.b2[total_len_X86[j+1]] = 0;
		input_buf_X86[(j>>1)+1].x1.b[total_len_X86[j+2]] = 0;
		input_buf_X86[(j>>1)+1].x2.b2[total_len_X86[j+3]] = 0;
#else
		input_buf_X86[j].x1.b[total_len_X86[j]] = 0;
		input_buf_X86[j+1].x1.b[total_len_X86[j+1]] = 0;
#if (MMX_COEF==4)
		input_buf_X86[j+2].x1.b[total_len_X86[j+2]] = 0;
		input_buf_X86[j+3].x1.b[total_len_X86[j+3]] = 0;
#endif
#endif
	}
#endif
}
void DynamicFunc__SSEtoX86_switch_input2() {
#ifdef MMX_COEF
	int j, k, idx, max;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += MMX_COEF)
	{
		ARCH_WORD_32 *cpi;
#if (MD5_X2)
		ARCH_WORD_32 *cpo  = input_buf2_X86[j>>1].x1.w;
		ARCH_WORD_32 *cpo2 = input_buf2_X86[j>>1].x2.w2;
		ARCH_WORD_32 *cpo3 = input_buf2_X86[(j>>1)+1].x1.w;
		ARCH_WORD_32 *cpo4 = input_buf2_X86[(j>>1)+1].x2.w2;
#else
		ARCH_WORD_32 *cpo = input_buf2_X86[j].x1.w;
		ARCH_WORD_32 *cpo2 = input_buf2_X86[j+1].x1.w;
#if (MMX_COEF==4)
		ARCH_WORD_32 *cpo3 = input_buf2_X86[j+2].x1.w;
		ARCH_WORD_32 *cpo4 = input_buf2_X86[j+3].x1.w;
#endif
#endif
		idx = ( ((unsigned)j)>>(MMX_COEF>>1));
		cpi = (void*)(&input_buf2[idx]);

		max = total_len2_X86[j] = (total_len2[idx]&0xFF);
#if (MMX_COEF==2)
		if (max < (total_len2_X86[j+1]=((total_len2[idx]>>16)&0xFF)))
			max = total_len2_X86[j+1];
#else
		if (max < (total_len2_X86[j+1]=((total_len2[idx]>> 8)&0xFF)))
			max = total_len2_X86[j+1];
		if (max < (total_len2_X86[j+2]=((total_len2[idx]>>16)&0xFF)))
			max = total_len2_X86[j+2];
		if (max < (total_len2_X86[j+3]=((total_len2[idx]>>24)&0xFF)))
			max = total_len2_X86[j+3];
#endif
		max = (max+3)>>2;
		for (k = 0; k < max; ++k) {
			*cpo++ = *cpi++;
			*cpo2++ = *cpi++;
#if (MMX_COEF==4)
			*cpo3++ = *cpi++;
			*cpo4++ = *cpi++;
#endif
		}
		// get rid of the 0x80
#if (MD5_X2)
		input_buf2_X86[j>>1].x1.b[total_len2_X86[j]] = 0;
		input_buf2_X86[j>>1].x2.b2[total_len2_X86[j+1]] = 0;
		input_buf2_X86[(j>>1)+1].x1.b[total_len2_X86[j+2]] = 0;
		input_buf2_X86[(j>>1)+1].x2.b2[total_len2_X86[j+3]] = 0;
#else
		input_buf2_X86[j].x1.b[total_len2_X86[j]] = 0;
		input_buf2_X86[j+1].x1.b[total_len2_X86[j+1]] = 0;
#if (MMX_COEF==4)
		input_buf2_X86[j+2].x1.b[total_len2_X86[j+2]] = 0;
		input_buf2_X86[j+3].x1.b[total_len2_X86[j+3]] = 0;
#endif
#endif
	}
#endif
}
void DynamicFunc__SSEtoX86_switch_output1() {
#ifdef MMX_COEF
	int j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += MMX_COEF)
	{
		ARCH_WORD_32 *cpi;
#if (MD5_X2)
		ARCH_WORD_32 *cpo = crypt_key_X86[j>>1].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key_X86[j>>1].x2.w2;
		ARCH_WORD_32 *cpo3 = crypt_key_X86[(j>>1)+1].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key_X86[(j>>1)+1].x2.w2;
#else
		ARCH_WORD_32 *cpo = crypt_key_X86[j].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key_X86[j+1].x1.w;
#if (MMX_COEF==4)
		ARCH_WORD_32 *cpo3 = crypt_key_X86[j+2].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key_X86[j+3].x1.w;
#endif
#endif
		idx = ( ((unsigned)j)>>(MMX_COEF>>1));
		cpi = (void*)(&crypt_key[idx]);
		for (k = 0; k < 4; ++k) {
			*cpo++ = *cpi++;
			*cpo2++ = *cpi++;
#if (MMX_COEF==4)
			*cpo3++ = *cpi++;
			*cpo4++ = *cpi++;
#endif
		}
	}
#endif
}
void DynamicFunc__SSEtoX86_switch_output2() {
#ifdef MMX_COEF
	int j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;

	for (j = 0; j < m_count; j += MMX_COEF)
	{
		ARCH_WORD_32 *cpi;
#if (MD5_X2)
		ARCH_WORD_32 *cpo = crypt_key2_X86[j>>1].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key2_X86[j>>1].x2.w2;
		ARCH_WORD_32 *cpo3 = crypt_key2_X86[(j>>1)+1].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key2_X86[(j>>1)+1].x2.w2;
#else
		ARCH_WORD_32 *cpo = crypt_key2_X86[j].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key2_X86[j+1].x1.w;
#if (MMX_COEF==4)
		ARCH_WORD_32 *cpo3 = crypt_key2_X86[j+2].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key2_X86[j+3].x1.w;
#endif
#endif
		idx = ( ((unsigned)j)>>(MMX_COEF>>1));
		cpi = (void*)(&crypt_key2[idx]);
		for (k = 0; k < 4; ++k) {
			*cpo++ = *cpi++;
			*cpo2++ = *cpi++;
#if (MMX_COEF==4)
			*cpo3++ = *cpi++;
			*cpo4++ = *cpi++;
#endif
		}
	}
#endif
}
void DynamicFunc__X86toSSE_switch_input1() {
#ifdef MMX_COEF
	unsigned j, idx, idx_mod;
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;
	DynamicFunc__clean_input();
	for (j = 0; j < m_count; ++j) {
		idx = (j>>(MMX_COEF>>1));
		idx_mod = j&(MMX_COEF-1);
		total_len[idx] += (total_len_X86[j] << ((32/MMX_COEF)*idx_mod));
#if (MD5_X2)
		if (j & 1)
			__SSE_append_string_to_input((unsigned char*)(&input_buf[idx]),idx_mod,input_buf_X86[j>>1].x2.B2,total_len_X86[j],0,1);
		else
#endif
		__SSE_append_string_to_input((unsigned char*)(&input_buf[idx]),idx_mod,input_buf_X86[j>>MD5_X2].x1.B,total_len_X86[j],0,1);
	}
#endif
}
void DynamicFunc__X86toSSE_switch_input2() {
#ifdef MMX_COEF
	unsigned j, idx, idx_mod;
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;
	DynamicFunc__clean_input2();
	for (j = 0; j < m_count; ++j) {
		idx = (j>>(MMX_COEF>>1));
		idx_mod = j&(MMX_COEF-1);
		total_len2[idx] += (total_len2_X86[j] << ((32/MMX_COEF)*idx_mod));
#if (MD5_X2)
		if (j & 1)
			__SSE_append_string_to_input((unsigned char*)(&input_buf2[idx]),idx_mod,input_buf2_X86[j>>1].x2.B2,total_len2_X86[j],0,1);
		else
#endif
		__SSE_append_string_to_input((unsigned char*)(&input_buf2[idx]),idx_mod,input_buf2_X86[j>>MD5_X2].x1.B,total_len2_X86[j],0,1);
	}
#endif
}
void DynamicFunc__X86toSSE_switch_output1() {
#ifdef MMX_COEF
	int j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;

	for (j = 0; j < m_count; j += MMX_COEF)
	{
		ARCH_WORD_32 *cpi;
#if (MD5_X2)
		ARCH_WORD_32 *cpo = crypt_key_X86[j>>1].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key_X86[j>>1].x2.w2;
		ARCH_WORD_32 *cpo3 = crypt_key_X86[(j>>1)+1].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key_X86[(j>>1)+1].x2.w2;
#else
		ARCH_WORD_32 *cpo = crypt_key_X86[j].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key_X86[j+1].x1.w;
#if (MMX_COEF==4)
		ARCH_WORD_32 *cpo3 = crypt_key_X86[j+2].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key_X86[j+3].x1.w;
#endif
#endif
		idx = ( ((unsigned)j)>>(MMX_COEF>>1));
		cpi = (void*)(&crypt_key[idx]);
		for (k = 0; k < 4; ++k) {
			*cpi++ = *cpo++;
			*cpi++ = *cpo2++;
#if (MMX_COEF==4)
			*cpi++ = *cpo3++;
			*cpi++ = *cpo4++;
#endif
		}
	}
#endif
}
void DynamicFunc__X86toSSE_switch_output2() {
#ifdef MMX_COEF
	int j, k, idx;

	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;

	for (j = 0; j < m_count; j += MMX_COEF)
	{
		ARCH_WORD_32 *cpi;
#if (MD5_X2)
		ARCH_WORD_32 *cpo = crypt_key2_X86[j>>1].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key2_X86[j>>1].x2.w2;
		ARCH_WORD_32 *cpo3 = crypt_key2_X86[(j>>1)+1].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key2_X86[(j>>1)+1].x2.w2;
#else
		ARCH_WORD_32 *cpo = crypt_key2_X86[j].x1.w;
		ARCH_WORD_32 *cpo2 = crypt_key2_X86[j+1].x1.w;
#if (MMX_COEF==4)
		ARCH_WORD_32 *cpo3 = crypt_key2_X86[j+2].x1.w;
		ARCH_WORD_32 *cpo4 = crypt_key2_X86[j+3].x1.w;
#endif
#endif
		idx = ( ((unsigned)j)>>(MMX_COEF>>1));
		cpi = (void*)(&crypt_key2[idx]);
		for (k = 0; k < 4; ++k) {
			*cpi++ = *cpo++;
			*cpi++ = *cpo2++;
#if (MMX_COEF==4)
			*cpi++ = *cpo3++;
			*cpi++ = *cpo4++;
#endif
		}
	}
#endif
}
// This function, simply 'switches' back to SSE  It does NOT copy any data from X86 to SSE
void DynamicFunc__ToSSE() {
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 1;
}
// This function, simply 'switches' to X86  It does NOT copy any data from SSE to X86
void DynamicFunc__ToX86() {
	if (dynamic_use_sse == 0)
		return;
	dynamic_use_sse = 2;
}

void DynamicFunc__base16_convert_locase() {
	dynamic_itoa16 = itoa16;
	itoa16_w2=itoa16_w2_l;
}
void DynamicFunc__base16_convert_upcase() {
	dynamic_itoa16 = itoa16u;
	itoa16_w2=itoa16_w2_u;
}

/* These are the 'older' singular functions. These SHOULD be viewed as depricated.  They still work, but should not be used */
/* NOTE, any new larger hash crypts, will NOT have this *_base16() functions.                                               */
void DynamicFunc__SHA1_crypt_input1_append_input2_base16()		{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA1_crypt_input1_append_input2(); }
void DynamicFunc__SHA1_crypt_input2_append_input1_base16()		{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA1_crypt_input2_append_input1(); }
void DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA1_crypt_input1_overwrite_input1(); }
void DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA1_crypt_input2_overwrite_input2(); }
void DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA1_crypt_input1_overwrite_input2(); }
void DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA1_crypt_input2_overwrite_input1(); }
void DynamicFunc__SHA224_crypt_input1_append_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA224_crypt_input1_append_input2(); }
void DynamicFunc__SHA224_crypt_input2_append_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA224_crypt_input2_append_input1(); }
void DynamicFunc__SHA224_crypt_input1_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA224_crypt_input1_overwrite_input1(); }
void DynamicFunc__SHA224_crypt_input2_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA224_crypt_input2_overwrite_input2(); }
void DynamicFunc__SHA224_crypt_input1_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA224_crypt_input1_overwrite_input2(); }
void DynamicFunc__SHA224_crypt_input2_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA224_crypt_input2_overwrite_input1(); }
void DynamicFunc__SHA256_crypt_input1_append_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA256_crypt_input1_append_input2(); }
void DynamicFunc__SHA256_crypt_input2_append_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA256_crypt_input2_append_input1(); }
void DynamicFunc__SHA256_crypt_input1_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA256_crypt_input1_overwrite_input1(); }
void DynamicFunc__SHA256_crypt_input2_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA256_crypt_input2_overwrite_input2(); }
void DynamicFunc__SHA256_crypt_input1_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA256_crypt_input1_overwrite_input2(); }
void DynamicFunc__SHA256_crypt_input2_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA256_crypt_input2_overwrite_input1(); }
void DynamicFunc__SHA384_crypt_input1_append_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA384_crypt_input1_append_input2(); }
void DynamicFunc__SHA384_crypt_input2_append_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA384_crypt_input2_append_input1(); }
void DynamicFunc__SHA384_crypt_input1_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA384_crypt_input1_overwrite_input1(); }
void DynamicFunc__SHA384_crypt_input2_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA384_crypt_input2_overwrite_input2(); }
void DynamicFunc__SHA384_crypt_input1_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA384_crypt_input1_overwrite_input2(); }
void DynamicFunc__SHA384_crypt_input2_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA384_crypt_input2_overwrite_input1(); }
void DynamicFunc__SHA512_crypt_input1_append_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA512_crypt_input1_append_input2(); }
void DynamicFunc__SHA512_crypt_input2_append_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA512_crypt_input2_append_input1(); }
void DynamicFunc__SHA512_crypt_input1_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA512_crypt_input1_overwrite_input1(); }
void DynamicFunc__SHA512_crypt_input2_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA512_crypt_input2_overwrite_input2(); }
void DynamicFunc__SHA512_crypt_input1_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA512_crypt_input1_overwrite_input2(); }
void DynamicFunc__SHA512_crypt_input2_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__SHA512_crypt_input2_overwrite_input1(); }
void DynamicFunc__GOST_crypt_input1_append_input2_base16()		{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__GOST_crypt_input1_append_input2(); }
void DynamicFunc__GOST_crypt_input2_append_input1_base16()		{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__GOST_crypt_input2_append_input1(); }
void DynamicFunc__GOST_crypt_input1_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__GOST_crypt_input1_overwrite_input1(); }
void DynamicFunc__GOST_crypt_input2_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__GOST_crypt_input2_overwrite_input2(); }
void DynamicFunc__GOST_crypt_input1_overwrite_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__GOST_crypt_input1_overwrite_input2(); }
void DynamicFunc__GOST_crypt_input2_overwrite_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__GOST_crypt_input2_overwrite_input1(); }
#if OPENSSL_VERSION_NUMBER >= 0x10000000
void DynamicFunc__WHIRLPOOL_crypt_input1_append_input2_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__WHIRLPOOL_crypt_input1_append_input2(); }
void DynamicFunc__WHIRLPOOL_crypt_input2_append_input1_base16()	{ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__WHIRLPOOL_crypt_input2_append_input1(); }
void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1_base16(){ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1(); }
void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2_base16(){ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2(); }
void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2_base16(){ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2(); }
void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1_base16(){ DynamicFunc__LargeHash_OUTMode_base16(); DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1(); }
#endif

/* These SIMPLE setter functions, change how the large hash output format is performed   */
/* Once set, it stays that way, until set a different way.  By DEFAULT (i.e. it is reset */
/* this way each time), when crypt_all is called, the large output is in eBase16 mode    */
void DynamicFunc__LargeHash_OUTMode_base16() {
	eLargeOut = eBase16;
}
void DynamicFunc__LargeHash_OUTMode_base16u() {
	eLargeOut = eBase16u;
}
void DynamicFunc__LargeHash_OUTMode_base64() {
	eLargeOut = eBase64;
}
void DynamicFunc__LargeHash_OUTMode_base64_nte() {
	eLargeOut = eBase64_nte;
}
void DynamicFunc__LargeHash_OUTMode_raw() {
	eLargeOut = eBaseRaw;
}


/******************************************************************************
 *****  These helper functions are used by all of the 'LARGE' hash functions. 
 *****  These are used to convert an 'out' into the proper format, and writing
 *****  it to the buffer.  Currently we handle base-16, base-16u, base-64 and
 *****  raw buffer writting. These functions do not return any count of bytes
 *****  nor deal with things like overwrite/appending.  That has to be done in
 *****  the calling function.  The caller will get the pointers setup, then call
 *****  these helpers.  Then the caller will update any length values if needed
 *****  based upon what the output pointer was, and what was returned by these
 *****  helpers.  Doing things like this will reduce the size of the large hash
 *****  primative functions.
 ******************************************************************************/
// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *hex_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		*cpo++ = dynamic_itoa16[*cpi>>4];
		*cpo++ = dynamic_itoa16[*cpi&0xF];
		++cpi;
	}
	*cpo = 0;
	return cpo; // returns pointer TO the null byte, not past it.
}
// NOTE, cpo must be at least in_byte_cnt*2 bytes of buffer
static inline unsigned char *hex_out_buf_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		*cpo++ = dynamic_itoa16[*cpi>>4];
		*cpo++ = dynamic_itoa16[*cpi&0xF];
		++cpi;
	}
	return cpo;
}
// NOTE, cpo must be at least in_byte_cnt*2 bytes of buffer
static inline unsigned char *hexu_out_buf_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		//*cpo++ = dynamic_itoa16[*cpi>>4];
		//*cpo++ = dynamic_itoa16[*cpi&0xF];
		*cpo++ = itoa16u[*cpi>>4];
		*cpo++ = itoa16u[*cpi&0xF];
		++cpi;
	}
	return cpo;
}
// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *hexu_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	cpo = hexu_out_buf_no_null(cpi, cpo, in_byte_cnt);
	*cpo = 0;
	return cpo; // returns pointer TO the null byte, not past it.
}

// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *raw_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	int j;
	for (j = 0; j < in_byte_cnt; ++j) {
		*cpo++ = *cpi++;
	}
	return cpo;
}

// compatible 'standard' MIME base-64 encoding.
static inline unsigned char *base64_out_buf_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int add_eq) {
	static char *_itoa64 = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

	while (in_byte_cnt > 2) {
		*cpo++ = _itoa64[(cpi[0] & 0xfc) >> 2];
		*cpo++ = _itoa64[((cpi[0] & 0x03) << 4) + ((cpi[1] & 0xf0) >> 4)];
		*cpo++ = _itoa64[((cpi[1] & 0x0f) << 2) + ((cpi[2] & 0xc0) >> 6)];
		*cpo++ = _itoa64[cpi[2] & 0x3f];
		cpi += 3;
		in_byte_cnt -= 3;
	}
	// easiest way is to simply have 2 'special' cases to handle these lengths
	if (in_byte_cnt==2)
	{
		*cpo++ = _itoa64[(cpi[0] & 0xfc) >> 2];
		*cpo++ = _itoa64[((cpi[0] & 0x03) << 4) + ((cpi[1] & 0xf0) >> 4)];
		*cpo++ = _itoa64[((cpi[1] & 0x0f) << 2)];
		if (add_eq) *cpo++ = '=';
	}
	if (in_byte_cnt==1)
	{
		*cpo++ = _itoa64[(cpi[0] & 0xfc) >> 2];
		*cpo++ = _itoa64[((cpi[0] & 0x03) << 4)];
		if (add_eq) { *cpo++ = '='; *cpo++ = '='; }
	}
	return cpo;
}

// NOTE, cpo must be at least in_byte_cnt*2+1 bytes of buffer
static inline unsigned char *base64_out_buf(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int add_eq) {
	cpo = base64_out_buf_no_null(cpi, cpo, in_byte_cnt, add_eq);
	*cpo = 0;
	return cpo; // returns pointer TO the null byte, not past it.
}
#if 0
void TEST_MIME_crap() {
	SHA_CTX ctx1;
	MD5_CTX ctx;
	SHA256_CTX ctx256;
	SHA512_CTX ctx512;
	unsigned char Data[64], Res[128];
	char *pw="password";

	printf ("pw = %s\n", pw);

	SHA384_Init(&ctx512); 	SHA384_Update(&ctx512, pw, strlen(pw)); 	SHA384_Final(Data, &ctx512);
	hex_out_buf(Data, Res, 48);
	printf ("\nSHA384 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 48);
	printf ("b64=%s\n", Res);

	SHA224_Init(&ctx256); 	SHA224_Update(&ctx256, pw, strlen(pw)); 	SHA224_Final(Data, &ctx256);
	hex_out_buf(Data, Res, 28);
	printf ("\nSHA224 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 28);
	printf ("b64=%s\n", Res);

	SHA1_Init(&ctx1); 	SHA1_Update(&ctx1, pw, strlen(pw)); 	SHA1_Final(Data, &ctx1);
	hex_out_buf(Data, Res, 20);
	printf ("\nSHA1 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 20);
	printf ("b64=%s\n", Res);

	MD5_Init(&ctx); 	MD5_Update(&ctx, pw, strlen(pw)); 	MD5_Final(Data, &ctx);
	hex_out_buf(Data, Res, 16);
	printf ("\nMD5 data:\nb16=%s\n", Res);
	base64_out_buf(Data, Res, 16);
	printf ("b64=%s\n", Res);

	base64_out_buf(Data, Res, 15);
	printf ("\n15 byte MD5 base-16 (should be no trailing ==\nb64=%s\n", Res);

	exit(0);

}
#endif

static inline int large_hash_output(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	unsigned char *cpo2=cpo;
	switch(eLargeOut) {
		case eBase16:
			cpo2 = hex_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eBase16u:
			hexu_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eBase64:
			base64_out_buf(cpi, cpo, in_byte_cnt, 1);
			break;
		case eBase64_nte:
			base64_out_buf(cpi, cpo, in_byte_cnt, 0);
			break;
		case eBaseRaw:
			raw_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eUNK:
		default:
			exit(fprintf(stderr, "Error, a unknown 'output' state found in large_hash_output function, in %s\n", curdat.dynamic_WHICH_TYPE_SIG));
	}
	return cpo2-cpo;
}
static inline int large_hash_output_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt) {
	unsigned char *cpo2=cpo;
	switch(eLargeOut) {
		case eBase16:
			cpo2 = hex_out_buf_no_null(cpi, cpo, in_byte_cnt);
			break;
		case eBase16u:
			hexu_out_buf_no_null(cpi, cpo, in_byte_cnt);
			break;
		case eBase64:
			base64_out_buf_no_null(cpi, cpo, in_byte_cnt, 1);
			break;
		case eBase64_nte:
			base64_out_buf_no_null(cpi, cpo, in_byte_cnt, 0);
			break;
		case eBaseRaw:
			raw_out_buf(cpi, cpo, in_byte_cnt);
			break;
		case eUNK:
		default:
			exit(fprintf(stderr, "Error, a unknown 'output' state found in large_hash_output function, in %s\n", curdat.dynamic_WHICH_TYPE_SIG));
	}
	return cpo2-cpo;
}

/**************************************************************
 **************************************************************
  SHA1 functions. Intermix.   not as 'powerful' due to limitations
  But this allows building in 'some' interplay bewteen the formats.
 **************************************************************
 **************************************************************/

#ifdef MMX_COEF
void SHA1_SSE_Crypt(MD5_IN input[MAX_KEYS_PER_CRYPT_X86], unsigned int ilen[MAX_KEYS_PER_CRYPT_X86],
					MD5_IN out[MAX_KEYS_PER_CRYPT_X86]  , unsigned int olen[MAX_KEYS_PER_CRYPT_X86], int append)
{
	unsigned i, j, tot=0, tot2=0, z, k;

	for (k = 0; k*MMX_COEF*SHA_BLOCKS < m_count; ++k)
	{
		z=0;
#ifdef SHA1_SSE_PARA
		for (; z < SHA1_SSE_PARA; ++z)
#endif
		{
			memset(sinput_buf[z], 0, 56*MMX_COEF); // we only have to blank out the 'first' part of the buffer.
			for (j = 0; j < MMX_COEF && tot < m_count; ++j, ++tot)
			{
				unsigned char *si; // = input[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j].x1.B;
				unsigned int li;
#if (MD5_X2)
				if (j & 1)
					si = input[(k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j) >> 1].x2.B2;
				else
#endif
				si = input[(k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j) >> MD5_X2].x1.B;
				li = ilen[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j];
				for (i = 0; i < li; ++i)
					sinput_buf[z][SHAGETPOS(i, j)] = si[i];
				sinput_buf[z][SHAGETPOS(i, j)] = 0x80;
				((unsigned int *)sinput_buf[z])[15*MMX_COEF+j] = li<<3;
			}
		}
#ifdef SHA1_SSE_PARA
		SSESHA1body(sinput_buf, (unsigned int*)scrypt_key, NULL, 0);
#else
		shammx_nosizeupdate_nofinalbyteswap(((unsigned char*)(scrypt_key[0])), sinput_buf[0], 1);
#endif
		// Ok, convert to base-16
		z = 0;
#ifdef SHA1_SSE_PARA
		for (; z < SHA1_SSE_PARA; ++z)
#endif
		{
			for (j = 0; j < MMX_COEF && tot2 < m_count; ++j, ++tot2)
			{
				unsigned char *oo; // = out[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j].x1.B;
				unsigned short *wo;
#if (MD5_X2)
				if (j & 1)
					oo = out[(k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j) >> 1].x2.B2;
				else
#endif
				oo = out[(k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j) >> MD5_X2].x1.B;
				if (!append)
					olen[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j] = 0;
				oo += olen[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j];
				wo = (unsigned short*)oo;
				olen[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j] += 40;

				for (i = 0; i < 20; i+=4) {
					*wo++ = itoa16_w2[scrypt_key[z][GETPOS(i+3, j)]];
					*wo++ = itoa16_w2[scrypt_key[z][GETPOS(i+2, j)]];
					*wo++ = itoa16_w2[scrypt_key[z][GETPOS(i+1, j)]];
					*wo++ = itoa16_w2[scrypt_key[z][GETPOS(i+0, j)]];
				}
				oo[40] = 0;
			}
		}
	}
}

void SHA1_SSE_Crypt_final(MD5_IN input[MAX_KEYS_PER_CRYPT_X86], unsigned int ilen[MAX_KEYS_PER_CRYPT_X86])
{
#if !SHA1_SSE_PARA
	if (dynamic_use_sse==3)
	{
		shammx(crypt_key[0], sinput_buf[0], total_len[0]);
	}
	else
#endif
	{
		unsigned i, j, tot=0, /*tot2=0,*/ z, k;

		for (k = 0; k*MMX_COEF*SHA_BLOCKS < m_count; ++k)
		{
			if ((curdat.pSetup->startFlags&MGF_RAW_SHA1_INPUT) == 0)
			{
				z=0;
#ifdef SHA1_SSE_PARA
				for (; z < SHA1_SSE_PARA; ++z)
#endif
				{
					memset(sinput_buf[z], 0, 56*MMX_COEF); // we only have to blank out the 'first' part of the buffer.
					for (j = 0; j < MMX_COEF && tot < m_count; ++j, ++tot)
					{
						unsigned char *si; // = input[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j].x1.B;
						unsigned int li = ilen[k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j];
#if (MD5_X2)
						if (j & 1)
							si = input[(k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j) >> 1].x2.B2;
						else
#endif
						si = input[(k*MMX_COEF*SHA_BLOCKS+z*MMX_COEF+j) >> MD5_X2].x1.B;
						for (i = 0; i < li; ++i)
							sinput_buf[z][SHAGETPOS(i, j)] = si[i];
						sinput_buf[z][SHAGETPOS(i, j)] = 0x80;
						((unsigned int *)sinput_buf[z])[15*MMX_COEF+j] = li<<3;
					}
				}
			}
#ifdef SHA1_SSE_PARA
			SSESHA1body(sinput_buf, (unsigned int*)scrypt_key, NULL, 0);
			SHA1_swap(((MD5_word*)scrypt_key), ((MD5_word*)scrypt_key), 5*MMX_COEF*SHA1_SSE_PARA);
			for (z = 0; z < SHA1_SSE_PARA; ++z)
				memcpy(crypt_key[k*SHA1_SSE_PARA+z], scrypt_key[z], BINARY_SIZE*MMX_COEF);
#else
			shammx_nosizeupdate(((unsigned char*)(crypt_key[k])), sinput_buf[0], 1);
#endif
		}
	}
}
#endif

void DynamicFunc__SHA1_crypt_input1_append_input2()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int switchback=dynamic_use_sse;
	int i;

	if (dynamic_use_sse == 1) {
		DynamicFunc__SSEtoX86_switch_input1();
		DynamicFunc__SSEtoX86_switch_input2();
	}
#ifdef MMX_COEF
	if (switchback)
		SHA1_SSE_Crypt(input_buf_X86, total_len_X86, input_buf2_X86, total_len2_X86, 1);
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA1_Final(crypt_out, &sha_ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 20);
	}
	if (switchback==1) {
		DynamicFunc__X86toSSE_switch_input2();
	}
}
void DynamicFunc__SHA1_crypt_input2_append_input1()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int switchback=dynamic_use_sse;
	int i;

	if (dynamic_use_sse == 1) {
		DynamicFunc__SSEtoX86_switch_input1();
		DynamicFunc__SSEtoX86_switch_input2();
	}
#ifdef MMX_COEF
	if (switchback)
		SHA1_SSE_Crypt(input_buf2_X86, total_len2_X86, input_buf_X86, total_len_X86, 1);
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA1_Final(crypt_out, &sha_ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 20);
	}
	if (switchback==1) {
		DynamicFunc__X86toSSE_switch_input1();
	}
}
void DynamicFunc__SHA1_crypt_input1_overwrite_input1()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int switchback=dynamic_use_sse;
	int i;

	if (dynamic_use_sse == 1) {
		DynamicFunc__SSEtoX86_switch_input1();
	}
#ifdef MMX_COEF
	if (switchback)
		SHA1_SSE_Crypt(input_buf_X86, total_len_X86, input_buf_X86, total_len_X86, 0);
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA1_Final(crypt_out, &sha_ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 20);
	}
	if (switchback==1) {
		DynamicFunc__X86toSSE_switch_input1();
	}
}
void DynamicFunc__SHA1_crypt_input1_overwrite_input2()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int switchback=dynamic_use_sse;
	int i;

	if (dynamic_use_sse == 1) {
		DynamicFunc__SSEtoX86_switch_input1();
	}
#ifdef MMX_COEF
	if (switchback)
		SHA1_SSE_Crypt(input_buf_X86, total_len_X86, input_buf2_X86, total_len2_X86, 0);
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA1_Final(crypt_out, &sha_ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 20);
	}
	if (switchback==1) {
		DynamicFunc__X86toSSE_switch_input2();
	}
}
void DynamicFunc__SHA1_crypt_input2_overwrite_input1()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int switchback=dynamic_use_sse;
	int i;

	if (dynamic_use_sse == 1) {
		DynamicFunc__SSEtoX86_switch_input2();
	}
#ifdef MMX_COEF
	if (switchback)
		SHA1_SSE_Crypt(input_buf2_X86, total_len2_X86, input_buf_X86, total_len_X86, 0);
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA1_Final(crypt_out, &sha_ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 20);
	}
	if (switchback==1) {
		DynamicFunc__X86toSSE_switch_input1();
	}
}
void DynamicFunc__SHA1_crypt_input2_overwrite_input2()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int switchback=dynamic_use_sse;
	int i;

	if (dynamic_use_sse == 1) {
		DynamicFunc__SSEtoX86_switch_input2();
	}
#ifdef MMX_COEF
	if (switchback)
		SHA1_SSE_Crypt(input_buf2_X86, total_len2_X86, input_buf2_X86, total_len2_X86, 0);
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA1_Final(crypt_out, &sha_ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 20);
	}
	if (switchback==1) {
		DynamicFunc__X86toSSE_switch_input2();
	}
}
void DynamicFunc__SHA1_crypt_input1_to_output1_FINAL()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int switchback=dynamic_use_sse;
	int i;

	if (switchback == 1) {
		DynamicFunc__SSEtoX86_switch_input1();
	}
#ifdef MMX_COEF
	if (switchback) {
		SHA1_SSE_Crypt_final(input_buf_X86, total_len_X86);
		dynamic_use_sse=switchback;
		if (dynamic_use_sse==2)
			dynamic_use_sse=1;
	}
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1)
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA1_Update(&sha_ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA1_Final(crypt_out, &sha_ctx);

		// Only copies the first 16 out of 20 bytes.  Thus we do not have
		// the entire SHA1. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA1 hash (vs the whole 160 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 20).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA1_crypt_input2_to_output1_FINAL()
{
	union xx { unsigned char u[20]; ARCH_WORD a[20/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int switchback=dynamic_use_sse;
	int i;

	if (switchback == 1) {
		DynamicFunc__SSEtoX86_switch_input2();
	}
#ifdef MMX_COEF
	if (switchback) {
		SHA1_SSE_Crypt_final(input_buf2_X86, total_len2_X86);
		dynamic_use_sse = switchback;
		if (dynamic_use_sse==2)
			dynamic_use_sse=1;
	}
	else
#endif
	for (i = 0; i < m_count; ++i) {
		SHA1_Init(&sha_ctx);
#if (MD5_X2)
		if (i & 1)
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA1_Update(&sha_ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA1_Final(crypt_out, &sha_ctx);

		// Only copies the first 16 out of 20 bytes.  Thus we do not have
		// the entire SHA1. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA1 hash (vs the whole 160 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 20).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}

/********************************************************************
 ****  Here are the SHA224 and SHA256 functions!!!
 *******************************************************************/
void DynamicFunc__SHA224_crypt_input1_append_input2() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA224_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 28);
	}
}
void DynamicFunc__SHA256_crypt_input1_append_input2() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA256_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 32);
	}
}
void DynamicFunc__SHA224_crypt_input2_append_input1() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA224_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 28);
	}
}
void DynamicFunc__SHA256_crypt_input2_append_input1() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA256_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 32);
	}
}
void DynamicFunc__SHA224_crypt_input1_overwrite_input1(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 28);
	}
}
void DynamicFunc__SHA256_crypt_input1_overwrite_input1(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__SHA224_crypt_input1_overwrite_input2(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 28);
	}
}
void DynamicFunc__SHA256_crypt_input1_overwrite_input2(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__SHA224_crypt_input2_overwrite_input1(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 28);
	}
}
void DynamicFunc__SHA256_crypt_input2_overwrite_input1(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__SHA224_crypt_input2_overwrite_input2(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA224_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 28);
	}
}
void DynamicFunc__SHA256_crypt_input2_overwrite_input2(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA256_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__SHA224_crypt_input1_to_output1_FINAL(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA224_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA224_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA224. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA224 hash (vs the whole 224 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 28).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA256_crypt_input1_to_output1_FINAL(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA256_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA256_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA256. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA256 hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA224_crypt_input2_to_output1_FINAL(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA224_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA224_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA224_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA224. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA224 hash (vs the whole 224 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 28).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA256_crypt_input2_to_output1_FINAL(){
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA256_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA256_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA256_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA256_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA256. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA256 hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}

/********************************************************************
 ****  Here are the SHA384 and SHA512 functions!!!
 *******************************************************************/
void DynamicFunc__SHA384_crypt_input1_append_input2() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 48);
	}
}
void DynamicFunc__SHA512_crypt_input1_append_input2() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.b2[total_len2_X86[i]]);
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.b[total_len2_X86[i]]);
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 64);
	}
}
void DynamicFunc__SHA384_crypt_input2_append_input1() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 48);
	}
}
void DynamicFunc__SHA512_crypt_input2_append_input1() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 64);
	}
}
void DynamicFunc__SHA384_crypt_input1_overwrite_input1(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 48);
	}
}
void DynamicFunc__SHA512_crypt_input1_overwrite_input1(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__SHA384_crypt_input1_overwrite_input2(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 48);
	}
}
void DynamicFunc__SHA512_crypt_input1_overwrite_input2(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__SHA384_crypt_input2_overwrite_input1(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 48);
	}
}
void DynamicFunc__SHA512_crypt_input2_overwrite_input1(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__SHA384_crypt_input2_overwrite_input2(){
	union xx { unsigned char u[56]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA384_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 48);
	}
}
void DynamicFunc__SHA512_crypt_input2_overwrite_input2(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		SHA512_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__SHA384_crypt_input1_to_output1_FINAL(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA384_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA384_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA384. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA384 hash (vs the whole 384 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 28).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA512_crypt_input1_to_output1_FINAL(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.b2, total_len_X86[i]);
		else
#endif
			SHA512_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.b, total_len_X86[i]);
		SHA512_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA512. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA512 hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA384_crypt_input2_to_output1_FINAL(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA384_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA384_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA384_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 28 bytes.  Thus we do not have
		// the entire SHA384. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA384 hash (vs the whole 384 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 28).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}
void DynamicFunc__SHA512_crypt_input2_to_output1_FINAL(){
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	SHA512_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		SHA512_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.b2, total_len2_X86[i]);
		else
#endif
			SHA512_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.b, total_len2_X86[i]);
		SHA512_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire SHA512. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of SHA512 hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.b2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.b, crypt_out, 16);
	}
}

/**************************************************************
 ** GOST functions for dynamic
 *************************************************************/

void DynamicFunc__GOST_crypt_input1_append_input2() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 32);
	}
}
void DynamicFunc__GOST_crypt_input2_append_input1() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 32);
	}
}
void DynamicFunc__GOST_crypt_input1_overwrite_input1() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__GOST_crypt_input2_overwrite_input2() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__GOST_crypt_input1_overwrite_input2() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__GOST_crypt_input2_overwrite_input1() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		john_gost_final(&ctx, crypt_out);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 32);
	}
}
void DynamicFunc__GOST_crypt_input1_to_output1_FINAL() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			john_gost_update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		john_gost_final(&ctx, crypt_out);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire GOST. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of GOST hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__GOST_crypt_input2_to_output1_FINAL() {
	union xx { unsigned char u[32]; ARCH_WORD a[32/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	gost_ctx ctx;

	for (i = 0; i < m_count; ++i) {
		john_gost_init(&ctx);
#if (MD5_X2)
		if (i & 1)
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			john_gost_update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		john_gost_final(&ctx, crypt_out);

		// Only copies the first 16 out of 32 bytes.  Thus we do not have
		// the entire GOST. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of GOST hash (vs the whole 256 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 32).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}

/**************************************************************
 ** WHIRLPOOL functions for dynamic
 *************************************************************/
#if OPENSSL_VERSION_NUMBER >= 0x10000000
void DynamicFunc__WHIRLPOOL_crypt_input1_append_input2() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x2.B2[total_len2_X86[i]]);
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)&(input_buf2_X86[i>>MD5_X2].x1.B[total_len2_X86[i]]);
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output(crypt_out, cpo, 64);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_append_input1() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x2.b2[total_len_X86[i]]);
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)&(input_buf_X86[i>>MD5_X2].x1.b[total_len_X86[i]]);
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output(crypt_out, cpo, 64);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
			cpo = (unsigned char *)input_buf2_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len2_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u, *cpo;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1) {
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x2.b2;
		}
		else
#endif
		{
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
			cpo = (unsigned char *)input_buf_X86[i>>MD5_X2].x1.b;
		}
		WHIRLPOOL_Final(crypt_out, &ctx);
		total_len_X86[i] += large_hash_output_no_null(crypt_out, cpo, 64);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x2.B2, total_len_X86[i]);
		else
#endif
			WHIRLPOOL_Update(&ctx, input_buf_X86[i>>MD5_X2].x1.B, total_len_X86[i]);
		WHIRLPOOL_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 64 bytes.  Thus we do not have
		// the entire WHIRLPOOL. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of WHIRLPOOL hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 64).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
void DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL() {
	union xx { unsigned char u[64]; ARCH_WORD a[64/sizeof(ARCH_WORD)]; } u;
	unsigned char *crypt_out=u.u;
	int i;
	WHIRLPOOL_CTX ctx;

	for (i = 0; i < m_count; ++i) {
		WHIRLPOOL_Init(&ctx);
#if (MD5_X2)
		if (i & 1)
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x2.B2, total_len2_X86[i]);
		else
#endif
			WHIRLPOOL_Update(&ctx, input_buf2_X86[i>>MD5_X2].x1.B, total_len2_X86[i]);
		WHIRLPOOL_Final(crypt_out, &ctx);

		// Only copies the first 16 out of 64 bytes.  Thus we do not have
		// the entire WHIRLPOOL. It would NOT be valid to continue from here. However
		// it is valid (and 128 bit safe), to simply check the first 128 bits
		// of WHIRLPOOL hash (vs the whole 512 bits), with cmp_all/cmp_one, and if it
		// matches, then we can 'assume' we have a hit.
		// That is why the name of the function is *_FINAL()  it is meant to be
		// something like sha1(md5($p))  and then we simply compare 16 bytes
		// of hash (instead of the full 64).
#if (MD5_X2)
		if (i & 1)
			memcpy(crypt_key_X86[i>>MD5_X2].x2.B2, crypt_out, 16);
		else
#endif
			memcpy(crypt_key_X86[i>>MD5_X2].x1.B, crypt_out, 16);
	}
}
#endif

/**************************************************************
 * DEPRICATED functions. These are the older pseudo functions
 * which we now have flags for.  We keep them, so that we can
 * add the proper flags, even if the user is running an older
 * script.
 *************************************************************/
void DynamicFunc__PHPassSetup() {}
void DynamicFunc__InitialLoadKeysToInput() {}
void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2() {}
void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1() {}
void DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32() {}


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

static DYNAMIC_primitive_funcp *ConvertFuncs(DYNAMIC_primitive_funcp p, int *count)
{
	static DYNAMIC_primitive_funcp fncs[20];
	*count = 0;
	if (p==DynamicFunc__PHPassSetup  ||
		p==DynamicFunc__InitialLoadKeysToInput ||
		p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2 ||
		p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1 ||
		p==DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32)
		return fncs; // ignore these

#ifndef MMX_COEF
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

#if !ARCH_LITTLE_ENDIAN
	if (p==DynamicFunc__SHA1_crypt_input1_append_input2_base16    || p==DynamicFunc__SHA1_crypt_input1_append_input2    ||
		p==DynamicFunc__SHA1_crypt_input2_append_input1_base16    || p==DynamicFunc__SHA1_crypt_input2_append_input1    ||
		p==DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__SHA1_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA1_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__SHA1_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__SHA1_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA1_crypt_input1_to_output1_FINAL        ||
		p==DynamicFunc__SHA1_crypt_input2_to_output1_FINAL)
		curdat.force_md5_ctx = 0;
#endif

	*count = 1;
	fncs[0] = p;
	return fncs;
}

static int isSHA1Func(DYNAMIC_primitive_funcp p) {
	if (p==DynamicFunc__SHA1_crypt_input1_append_input2_base16    || p==DynamicFunc__SHA1_crypt_input1_append_input2    ||
		p==DynamicFunc__SHA1_crypt_input2_append_input1_base16    || p==DynamicFunc__SHA1_crypt_input2_append_input1    ||
		p==DynamicFunc__SHA1_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__SHA1_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__SHA1_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA1_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__SHA1_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__SHA1_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__SHA1_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__SHA1_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA1_crypt_input1_to_output1_FINAL        ||
		p==DynamicFunc__SHA1_crypt_input2_to_output1_FINAL)
		return 1;
	return 0;
}
static int isSHA2Func(DYNAMIC_primitive_funcp p) {
	if (p==DynamicFunc__SHA224_crypt_input1_append_input2_base16    || p==DynamicFunc__SHA224_crypt_input1_append_input2    ||
		p==DynamicFunc__SHA224_crypt_input2_append_input1_base16    || p==DynamicFunc__SHA224_crypt_input2_append_input1    ||
		p==DynamicFunc__SHA224_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__SHA224_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__SHA224_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA224_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__SHA224_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA224_crypt_input2_overwrite_input2 ||
 		p==DynamicFunc__SHA224_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__SHA224_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA224_crypt_input1_to_output1_FINAL ||
		p==DynamicFunc__SHA224_crypt_input2_to_output1_FINAL ||
		p==DynamicFunc__SHA256_crypt_input1_append_input2_base16    || p==DynamicFunc__SHA256_crypt_input1_append_input2    ||
		p==DynamicFunc__SHA256_crypt_input2_append_input1_base16    || p==DynamicFunc__SHA256_crypt_input2_append_input1    ||
		p==DynamicFunc__SHA256_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__SHA256_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__SHA256_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA256_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__SHA256_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__SHA256_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__SHA256_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__SHA256_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA256_crypt_input1_to_output1_FINAL ||
		p==DynamicFunc__SHA256_crypt_input2_to_output1_FINAL ||
		p==DynamicFunc__SHA384_crypt_input1_append_input2_base16    || p==DynamicFunc__SHA384_crypt_input1_append_input2    ||
		p==DynamicFunc__SHA384_crypt_input2_append_input1_base16    || p==DynamicFunc__SHA384_crypt_input2_append_input1    ||
		p==DynamicFunc__SHA384_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__SHA384_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__SHA384_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA384_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__SHA384_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__SHA384_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__SHA384_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__SHA384_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA384_crypt_input1_to_output1_FINAL ||
		p==DynamicFunc__SHA384_crypt_input2_to_output1_FINAL ||
		p==DynamicFunc__SHA512_crypt_input1_append_input2_base16    || p==DynamicFunc__SHA512_crypt_input1_append_input2    ||
		p==DynamicFunc__SHA512_crypt_input2_append_input1_base16    || p==DynamicFunc__SHA512_crypt_input2_append_input1    ||
		p==DynamicFunc__SHA512_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__SHA512_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__SHA512_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__SHA512_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__SHA512_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__SHA512_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__SHA512_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__SHA512_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__SHA512_crypt_input1_to_output1_FINAL ||
		p==DynamicFunc__SHA512_crypt_input2_to_output1_FINAL)
		return 1;
	return 0;
}

static int isMD4Func(DYNAMIC_primitive_funcp p) {
	if (p==DynamicFunc__crypt_md4 ||
		p==DynamicFunc__crypt2_md4 ||
		p==DynamicFunc__crypt_md4_in1_to_out2 ||
		p==DynamicFunc__crypt_md4_in2_to_out1)
		return 1;
	return 0;
}

static int isGOSTFunc(DYNAMIC_primitive_funcp p) {
	if (p==DynamicFunc__GOST_crypt_input1_append_input2_base16    || p==DynamicFunc__GOST_crypt_input1_append_input2    ||
		p==DynamicFunc__GOST_crypt_input2_append_input1_base16    || p==DynamicFunc__GOST_crypt_input2_append_input1    ||
		p==DynamicFunc__GOST_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__GOST_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__GOST_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__GOST_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__GOST_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__GOST_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__GOST_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__GOST_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__GOST_crypt_input1_to_output1_FINAL ||
		p==DynamicFunc__GOST_crypt_input2_to_output1_FINAL)
		return 1;
	return 0;
}

static int isWHIRLFunc(DYNAMIC_primitive_funcp p) {
#if OPENSSL_VERSION_NUMBER >= 0x10000000
	if (p==DynamicFunc__WHIRLPOOL_crypt_input1_append_input2_base16    || p==DynamicFunc__WHIRLPOOL_crypt_input1_append_input2    ||
		p==DynamicFunc__WHIRLPOOL_crypt_input2_append_input1_base16    || p==DynamicFunc__WHIRLPOOL_crypt_input2_append_input1    ||
		p==DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1_base16 || p==DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input1 ||
		p==DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2_base16 || p==DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input2 ||
		p==DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2_base16 || p==DynamicFunc__WHIRLPOOL_crypt_input1_overwrite_input2 ||
		p==DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1_base16 || p==DynamicFunc__WHIRLPOOL_crypt_input2_overwrite_input1 ||
		p==DynamicFunc__WHIRLPOOL_crypt_input1_to_output1_FINAL ||
		p==DynamicFunc__WHIRLPOOL_crypt_input2_to_output1_FINAL)
		return 1;
#endif
	return 0;
}

int dynamic_SETUP(DYNAMIC_Setup *Setup, struct fmt_main *pFmt)
{
	int i, j, cnt, cnt2, x;
	DYNAMIC_primitive_funcp *pFuncs;

	if (Setup->flags & MGF_ColonNOTValid)
	{
		extern struct options_main options;
		if (options.field_sep_char == ':')
		{
			return 0;
		}
	}

	// Deal with depricated 1st functions.  Convert them to proper 'flags'
	if (Setup->pFuncs[0] == DynamicFunc__PHPassSetup)
		Setup->startFlags |= MGF_PHPassSetup;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeysToInput)
		Setup->startFlags |= MGF_KEYS_INPUT;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2)
		Setup->startFlags |= MGF_KEYS_CRYPT_IN2;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1)
		Setup->startFlags |= MGF_KEYS_BASE16_IN1;
	if (Setup->pFuncs[0] == DynamicFunc__InitialLoadKeys_md5crypt_ToOutput2_Base16_to_Input1_offset32)
		Setup->startFlags |= MGF_KEYS_BASE16_IN1_Offset32;

	curdat.dynamic_hdaa_salt      = ((Setup->flags     &MGF_HDAA_SALT)==MGF_HDAA_SALT) ? 1 : 0;
	curdat.dynamic_40_byte_sha1   = ((Setup->startFlags&MGF_SHA1_40_BYTE_FINISH)==MGF_SHA1_40_BYTE_FINISH) ? 1 : 0;
	curdat.dynamic_64_byte_sha256 = ((Setup->startFlags&MGF_SHA256_64_BYTE_FINISH)==MGF_SHA256_64_BYTE_FINISH) ? 1 : 0;
	curdat.dynamic_56_byte_sha224 = ((Setup->startFlags&MGF_SHA224_56_BYTE_FINISH)==MGF_SHA224_56_BYTE_FINISH) ? 1 : 0;
	curdat.dynamic_96_byte_sha384 = ((Setup->startFlags&MGF_SHA384_96_BYTE_FINISH)==MGF_SHA384_96_BYTE_FINISH) ? 1 : 0;
	curdat.dynamic_128_byte_sha512= ((Setup->startFlags&MGF_SHA512_128_BYTE_FINISH)==MGF_SHA512_128_BYTE_FINISH) ? 1 : 0;
	curdat.dynamic_64_byte_gost   = ((Setup->startFlags&MGF_GOST_64_BYTE_FINISH)==MGF_GOST_64_BYTE_FINISH) ? 1 : 0;
	curdat.dynamic_128_byte_whirlpool = ((Setup->startFlags&MGF_WHIRLPOOL_128_BYTE_FINISH)==MGF_WHIRLPOOL_128_BYTE_FINISH) ? 1 : 0;

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
	curdat.force_md5_ctx = 0;
	curdat.nUserName = 0;
	curdat.nPassCase = 1;
	curdat.md5_startup_in_x86 = curdat.dynamic_use_sse = 0;  // if 0, then never use SSE2
	curdat.init = 0;
	curdat.pSetup = Setup;
	pFmt->methods.binary = binary;
	pFmt->methods.cmp_all=cmp_all;
	pFmt->methods.cmp_one=cmp_one;
#if FMT_MAIN_VERSION > 9
	pFmt->methods.source=fmt_default_source;
#endif
	pFmt->methods.salt = salt;
	pFmt->methods.set_salt = set_salt;
	pFmt->methods.salt_hash = salt_hash;
	pFmt->params.format_name = str_alloc_copy(Setup->szFORMAT_NAME);
	pFmt->params.benchmark_length = 0;		// NOTE 0 'assumes' salted. If unsalted, we set back to -1
	pFmt->params.salt_size = 0;
	pFmt->params.min_keys_per_crypt = 1;
#ifdef MMX_COEF
	curdat.dynamic_use_sse = 1;  // if 1, then we are in SSE2 mode (but can switch out)
	if ((Setup->flags & MGF_NOTSSE2Safe) == MGF_NOTSSE2Safe)
		curdat.dynamic_use_sse = 0;  // Do not use SSE code at all.
	else if ((Setup->flags & MGF_StartInX86Mode) == MGF_StartInX86Mode) {
		curdat.dynamic_use_sse = 2;  // if 2, then we are in SSE2 mode, but currently using X86 (and can switch back to SSE2).
		curdat.md5_startup_in_x86 = 1;
	}
	if (curdat.dynamic_use_sse) {
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
		curdat.Consts[curdat.nConsts][Setup->pConstants[curdat.nConsts].len+1] = 0;
		curdat.ConstsLen[curdat.nConsts] = Setup->pConstants[curdat.nConsts].len;
	}

	if (Setup->flags & MGF_INPBASE64)
	{
		curdat.dynamic_base64_inout = 1;
		pFmt->methods.binary = binary_b64;
	}
	if (Setup->flags & MGF_INPBASE64_4x6)
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
		// Not enough bits in a single WORD to do the 7th one.
		pFmt->methods.binary_hash[6] = NULL;
		pFmt->methods.get_hash[6] = NULL;

	}
	if ( (Setup->flags & (MGF_INPBASE64|MGF_INPBASE64_4x6|MGF_INPBASE64a)) == 0)  {
		pFmt->params.flags |= FMT_SPLIT_UNIFIES_CASE;
		if (pFmt->methods.split == split)
			pFmt->methods.split = split_UC;
	}
	if (Setup->flags & MGF_UTF8)
		pFmt->params.flags |= FMT_UTF8;
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
		pFmt->params.flags |= (~FMT_CASE);
	}
	if ( (Setup->flags & MGF_PASSWORD_LOCASE) == MGF_PASSWORD_LOCASE) {
		curdat.nPassCase = 3;
		pFmt->params.flags |= (~FMT_CASE);
	}

	if ( (Setup->flags & MGF_SALT_AS_HEX) == MGF_SALT_AS_HEX)
		curdat.dynamic_salt_as_hex = 1;
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
		pFmt->params.benchmark_length = -1;
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
			else
				curdat.dynamic_FIXED_SALT_SIZE = Setup->SaltLen;
		}
	}

	if (Setup->MaxInputLen)
		pFmt->params.plaintext_length = Setup->MaxInputLen;
	else
		pFmt->params.plaintext_length = 55 - abs(Setup->SaltLen);
#ifndef MMX_COEF
	if (Setup->MaxInputLenX86) {
		pFmt->params.plaintext_length = Setup->MaxInputLenX86;
	} else {
		if (Setup->SaltLenX86)
			pFmt->params.plaintext_length = 80 - abs(Setup->SaltLenX86);
		else
			pFmt->params.plaintext_length = 80 - abs(Setup->SaltLen);
	}
#endif

	curdat.store_keys_in_input = !!(Setup->startFlags&MGF_KEYS_INPUT );
	curdat.input2_set_len32 = !!(Setup->startFlags&MGF_SET_INP2LEN32);

#if FMT_MAIN_VERSION > 9
	if (Setup->startFlags&MGF_SOURCE)        pFmt->methods.source = source;
	if (Setup->startFlags&MGF_SOURCE_SHA)    pFmt->methods.source = source_sha;
	if (Setup->startFlags&MGF_SOURCE_SHA224) pFmt->methods.source = source_sha224;
	if (Setup->startFlags&MGF_SOURCE_SHA256) pFmt->methods.source = source_sha256;
	if (Setup->startFlags&MGF_SOURCE_SHA384) pFmt->methods.source = source_sha384;
	if (Setup->startFlags&MGF_SOURCE_SHA512) pFmt->methods.source = source_sha512;
	if (Setup->startFlags&MGF_SOURCE_GOST)   pFmt->methods.source = source_gost;
	if (Setup->startFlags&MGF_SOURCE_WHIRLPOOL)   pFmt->methods.source = source_whirlpool;
#endif

	if (!curdat.store_keys_in_input && Setup->startFlags&MGF_KEYS_INPUT_BE_SAFE)
		curdat.store_keys_in_input = 3;

	curdat.store_keys_in_input_unicode_convert = !!(Setup->startFlags&MGF_KEYS_UNICODE_B4_CRYPT);
	if (curdat.store_keys_in_input_unicode_convert && curdat.store_keys_in_input)
		return !fprintf(stderr, "Error invalid format %s: Using MGF_KEYS_INPUT and MGF_KEYS_UNICODE_B4_CRYPT in same format is NOT valid\n", Setup->szFORMAT_NAME);

	curdat.store_keys_normal_but_precompute_md5_to_output2 = !!(Setup->startFlags&MGF_KEYS_CRYPT_IN2);

	curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1 = !!(Setup->startFlags&MGF_KEYS_BASE16_IN1);
	if (!!(Setup->startFlags&MGF_KEYS_BASE16_X86_IN1)) {
		curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1=2;
	}
	if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1)
		curdat.store_keys_normal_but_precompute_md5_to_output2 = 1;

	curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32 = !!(Setup->startFlags&MGF_KEYS_BASE16_IN1_Offset32);
	if (!!(Setup->startFlags&MGF_KEYS_BASE16_X86_IN1_Offset32))
		curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32=2;
	if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1_offset32)
	{
		curdat.store_keys_normal_but_precompute_md5_to_output2 = 1;
	}

	if (Setup->startFlags&MGF_RAW_SHA1_INPUT)
	{
		curdat.store_keys_in_input = 2;
#ifdef MMX_COEF
		pFmt->params.max_keys_per_crypt = MMX_COEF*SHA_BLOCKS;
#if (MMX_COEF==2)
		pFmt->params.algorithm_name = "64/64 " SHA1_SSE_type " 2x" STRINGIZE(SHA_BLOCKS);
#else
		pFmt->params.algorithm_name = "128/128 " SHA1_SSE_type " 4x" STRINGIZE(SHA_BLOCKS);
#endif
#endif
	}

	if (Setup->startFlags&MGF_FreeBSDMD5Setup)
	{
#ifdef MMX_COEF
#if (MMX_COEF==2)
		pFmt->params.algorithm_name = "64/64 " SHA1_SSE_type " 2x1";
		pFmt->params.max_keys_per_crypt = 2;
#elif defined (MD5_SSE_PARA)
		pFmt->params.algorithm_name = "128/128 " SHA1_SSE_type " 4x" STRINGIZE(MD5_SSE_PARA);
		pFmt->params.max_keys_per_crypt = 4*MD5_SSE_PARA;
#else
		pFmt->params.algorithm_name = "128/128 " SHA1_SSE_type " 4x1";
		pFmt->params.max_keys_per_crypt = 4;
#endif
#else
		// In non-sse mode, 1 test runs as fast as 128. But validity checking is MUCH faster if
		// we leave it at only 1.
		pFmt->params.max_keys_per_crypt = 1;
#if MD5_X2
		pFmt->params.max_keys_per_crypt = 2;
		pFmt->params.algorithm_name = "32/" ARCH_BITS_STR " X2 (MD5_body)";
#else
		pFmt->params.algorithm_name = "32/" ARCH_BITS_STR " (MD5_body)";
#endif
#endif
		pFmt->params.min_keys_per_crypt = 1;
		saltlen = 8;
		// no reason to run double tests. The 1 salt vs MANY salts is the
		// same speed, so why double the benchmark time for no reason.
		pFmt->params.benchmark_length = -1;
	}
	if (Setup->startFlags&MGF_PHPassSetup)
	{
		pFmt->methods.salt = salt_phpass;
#ifdef MMX_COEF
		// no reason to do 128 crypts, causes slow validity checking.  But we do get some gains
		// by doing more than simple 1 set of MMX_COEF
#if (MMX_COEF==2)
		pFmt->params.algorithm_name = "64/64 " SHA1_SSE_type " 8x2";
		pFmt->params.max_keys_per_crypt = 16;
#elif defined (MD5_SSE_PARA)
		pFmt->params.algorithm_name = "128/128 " SHA1_SSE_type " 4x4x" STRINGIZE(MD5_SSE_PARA);
		pFmt->params.max_keys_per_crypt = 16*MD5_SSE_PARA;
#else
		pFmt->params.algorithm_name = "128/128 " SHA1_SSE_type " 4x4";
		pFmt->params.max_keys_per_crypt = 16;
#endif
#else
		// In non-sse mode, 1 test runs as fast as 128. But validity checking is MUCH faster if
		// we leave it at only 1.
		pFmt->params.max_keys_per_crypt = 1;
#if MD5_X2
		pFmt->params.max_keys_per_crypt = 2;
		pFmt->params.algorithm_name = "32/" ARCH_BITS_STR " X2  (MD5_body)";
#else
		pFmt->params.algorithm_name = "32/" ARCH_BITS_STR " (MD5_body)";
#endif
#endif
		pFmt->params.min_keys_per_crypt = 1;
		saltlen = 8;
		// no reason to run double tests. The 1 salt vs MANY salts is the
		// same speed, so why double the benchmark time for no reason.
		pFmt->params.benchmark_length = -1;
	}

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
		int z;
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

		// note, with Setup->pFuncs[0]==DynamicFunc__set_input_len_32, we only will handle type 6 and 7
		// for now we have this 'turned' off.  It is fixed for type 6, 7 and 14.  It is left on for the
		// john.ini stuff.  Thus, if someone builds the intel version type 6, it will work (but slower).
		if (curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1==1 && Setup->pFuncs[0]==DynamicFunc__set_input_len_32) {
			curdat.store_keys_normal_but_precompute_md5_to_output2_base16_to_input1 = 0;
			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__clean_input;
			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__append_keys;
			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__crypt_md5;
			curdat.dynamic_FUNCTIONS[j++] = DynamicFunc__clean_input;
			Setup->pFuncs[0] = DynamicFunc__append_from_last_output_as_base16;
		}
#endif
		for (i=0; Setup->pFuncs[i]; ++i)
		{
			if (j > z-10)
			{
				int k;
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
			for (x = 0; x < cnt2; ++x) {
				curdat.dynamic_FUNCTIONS[j++] = pFuncs[x];
				if (pFuncs[x] == DynamicFunc__setmode_unicode)
					pFmt->params.flags |= FMT_UNICODE;
				if (isSHA1Func(pFuncs[x])) {
					if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME))
						pFmt->params.algorithm_name = ALGORITHM_NAME_S;
					else if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME_X86))
						pFmt->params.algorithm_name = ALGORITHM_NAME_X86_S;
				}
				if (isSHA2Func(pFuncs[x])) {
					if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME))
						pFmt->params.algorithm_name = ALGORITHM_NAME_S2;
					else if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME_X86))
						pFmt->params.algorithm_name = ALGORITHM_NAME_X86_S2;
				}
				if (isMD4Func(pFuncs[x])) {
					if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME))
						pFmt->params.algorithm_name = ALGORITHM_NAME_4;
					else if(!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME_X86))
						pFmt->params.algorithm_name = ALGORITHM_NAME_X86_4;
				}
				if (isWHIRLFunc(pFuncs[x])) {
					// STILL TODO
					//if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME))
					//	pFmt->params.algorithm_name = ALGORITHM_NAME_S2;
					//else if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME_X86))
					//	pFmt->params.algorithm_name = ALGORITHM_NAME_X86_S2;
				}
				if (isGOSTFunc(pFuncs[x])) {
					// STILL TODO
					//if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME))
					//	pFmt->params.algorithm_name = ALGORITHM_NAME_S2;
					//else if (!strcmp(pFmt->params.algorithm_name, ALGORITHM_NAME_X86))
					//	pFmt->params.algorithm_name = ALGORITHM_NAME_X86_S2;
				}
			}

			if (curdat.dynamic_FUNCTIONS[j-1] == DynamicFunc__SHA1_crypt_input1_to_output1_FINAL ||
				curdat.dynamic_FUNCTIONS[j-1] == DynamicFunc__SHA1_crypt_input2_to_output1_FINAL)
			{
				if (Setup->pFuncs[i+1])
					return !fprintf(stderr, "Error invalid format %s: DynamicFunc__SHA1_crypt_inputX_to_output1_FINAL, can ONLY be used as the last function in a script\n", Setup->szFORMAT_NAME);
			}
		}
		curdat.dynamic_FUNCTIONS[j] = NULL;
	}
	if (!Setup->pPreloads || Setup->pPreloads[0].ciphertext == NULL)
	{
		return !fprintf(stderr, "Error invalid format %s: Error, no validation hash(s) for this format\n", Setup->szFORMAT_NAME);
	}
	cnt = 0;

	{
		struct fmt_tests *pfx = mem_alloc_tiny(ARRAY_COUNT(dynamic_tests) * sizeof (struct fmt_tests), MEM_ALIGN_WORD);
		memset(pfx, 0, ARRAY_COUNT(dynamic_tests) * sizeof (struct fmt_tests));

		for (i = 0; cnt < ARRAY_COUNT(dynamic_tests) -1; ++i, ++cnt)
		{
			if (Setup->pPreloads[i].ciphertext == NULL) {
				if (Setup->startFlags&MGF_PHPassSetup || Setup->startFlags&MGF_FreeBSDMD5Setup)
					// for phpass, do not load ANY more than the 9 that are in the preload.
					// loading more will simply slow down the validation code loop at startup.
					break;
				i = 0;
			}
			if (Setup->pPreloads[i].ciphertext[0] == 'A' && Setup->pPreloads[i].ciphertext[1] == '=') {
				if (!options.ascii && !options.iso8859_1)
					continue;
				pfx[cnt].ciphertext = str_alloc_copy(&Setup->pPreloads[i].ciphertext[2]);
			}
			else if (Setup->pPreloads[i].ciphertext[0] == 'U' && Setup->pPreloads[i].ciphertext[1] == '=') {
				if (!options.utf8)
					continue;
				pfx[cnt].ciphertext = str_alloc_copy(&Setup->pPreloads[i].ciphertext[2]);
			}
			else
				pfx[cnt].ciphertext = str_alloc_copy(Setup->pPreloads[i].ciphertext);
			pfx[cnt].plaintext = str_alloc_copy(Setup->pPreloads[i].plaintext);
#if FMT_MAIN_VERSION > 9
			pfx[cnt].fields[0] = Setup->pPreloads[i].fields[0]  ? str_alloc_copy(Setup->pPreloads[i].fields[0]) : "";
			pfx[cnt].fields[1] = pfx[cnt].ciphertext;
			for (j = 2; j < 10; ++j)
				pfx[cnt].fields[j] = Setup->pPreloads[i].fields[j]  ? str_alloc_copy(Setup->pPreloads[i].fields[j]) : "";
#else
			pfx[cnt].flds[0] = Setup->pPreloads[i].flds[0]  ? str_alloc_copy(Setup->pPreloads[i].flds[0]) : "";
			pfx[cnt].flds[1] = pfx[cnt].ciphertext;
			for (j = 2; j < 10; ++j)
				pfx[cnt].flds[j] = Setup->pPreloads[i].flds[j]  ? str_alloc_copy(Setup->pPreloads[i].flds[j]) : "";
#endif
		}
		pfx[cnt].ciphertext = NULL;
		pfx[cnt].plaintext = NULL;

		pFmt->params.tests = pfx;
	}

	if (curdat.dynamic_base16_upcase)
		dynamic_itoa16 = itoa16u;
	else
		dynamic_itoa16 = itoa16;

	return 1;
}

static int LoadOneFormat(int idx, struct fmt_main *pFmt)
{
	extern struct options_main options;
	char label[16], label_id[16], *cp;
	memcpy(pFmt, &fmt_Dynamic, sizeof(struct fmt_main));
	dynamic_RESET(pFmt);

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
	cp[1] = 0;
	strcpy(label_id, &label[1]);
	cp = strchr(label_id, '$');
	*cp = 0;

//	if (!options.format || strncmp(options.format, "dynamic_", 8))
//		pFmt->params.label = str_alloc_copy("dynamic");
//	else
		pFmt->params.label = str_alloc_copy(label_id);

	strcpy(curdat.dynamic_WHICH_TYPE_SIG, label);

	curdat.dynamic_HASH_OFFSET = strlen(label);

	if (curdat.dynamic_base64_inout == 1)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 22 + 1;
	else if (curdat.dynamic_base64_inout == 2)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 16 + 1;
	else if (curdat.dynamic_40_byte_sha1)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 40 + 1;
	else if (curdat.dynamic_64_byte_sha256 || curdat.dynamic_64_byte_gost)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 64 + 1;
	else if (curdat.dynamic_56_byte_sha224)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 56 + 1;
	else if (curdat.dynamic_96_byte_sha384)
		curdat.dynamic_SALT_OFFSET = curdat.dynamic_HASH_OFFSET + 96 + 1;
	else if (curdat.dynamic_128_byte_sha512 || curdat.dynamic_128_byte_whirlpool)
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

int dynamic_Register_formats(struct fmt_main **ptr)
{
	int count, i, idx, single=-1;
	extern struct options_main options;

#ifdef MMX_COEF
		__SSE_Load_itoa16_w2();
#endif
	if (options.format && !strncmp(options.format, "dynamic_", 8))
		sscanf(options.format, "dynamic_%d", &single);
	if (options.format && options.subformat  && !strcmp(options.format, "dynamic") && !strncmp(options.subformat, "dynamic_", 8))
		sscanf(options.subformat, "dynamic_%d", &single);
	if (options.dynamic_raw_hashes_always_valid == 'Y')
		m_allow_rawhash_fixup = 1;
	else if (options.dynamic_raw_hashes_always_valid != 'N'  && cfg_get_bool(SECTION_OPTIONS, NULL, "DynamicAlwaysUseRawHashes", 1))
		m_allow_rawhash_fixup = 1;

	if (single != -1) {
		// user wanted only a 'specific' format.  Simply load that one.
		m_allow_rawhash_fixup = 1;
		if (dynamic_IS_VALID(single) == 0)
			return 0;
		pFmts = mem_alloc_tiny(sizeof(pFmts[0]), MEM_ALIGN_WORD);
		if (!LoadOneFormat(single, pFmts))
			return 0;
		*ptr = pFmts;
		return (nFmts = 1);
	}

	for (count = i = 0; i < 5000; ++i) {
		if (dynamic_IS_VALID(i) == 1)
			++count;
	}
	// Ok, now we know how many formats we have.  Load them
	pFmts = mem_alloc_tiny(sizeof(pFmts[0])*count, MEM_ALIGN_WORD);
	for (idx = i = 0; i < 5000; ++i) {
		if (dynamic_IS_VALID(i) == 1) {
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
	return NULL;
}

/*
 * This function will 'forget' which md5-gen subtype we are working with. It will allow
 * a different type to be used.  Very useful for things like -test (benchmarking).
 */
void dynamic_RESET(struct fmt_main *fmt)
{
	memset(&curdat, 0, sizeof(curdat));
	m_count = 0;
	keys_dirty = 0;
	cursalt=cursalt2=username=0;
	saltlen=saltlen2=usernamelen=0;
	// make 'sure' we startout with blank inputs.
	m_count = 0;
	DynamicFunc__clean_input_full();
	DynamicFunc__clean_input2_full();
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
	strncpy(subformat, ciphertext, 16);
	subformat[16] = 0;
	cp = strchr(&subformat[9], '$');
	if (cp)
		cp[1] = 0;

	nFmtNum = -1;
	sscanf(subformat, "$dynamic_%d", &nFmtNum);
	if (nFmtNum==-1)
		exit(fprintf(stderr, "Error, Invalid signature line trying to link to dynamic format.\nOriginal format=%s\nSignature line=%s\n", orig_sig, ciphertext));

	pFmtLocal = dynamic_Get_fmt_main(nFmtNum);
	if (pFmtLocal == NULL) {
		exit(fprintf(stderr, "Error, Invalid signature line trying to link to dynamic format.\nOriginal format=%s\nSignature line=%s\n", orig_sig, ciphertext));
	}

	valid = pFmtLocal->methods.valid(ciphertext, pFmtLocal);
	if (!valid)
		exit(fprintf(stderr, "Error, trying to link to %s using ciphertext=%s FAILED\n", subformat, ciphertext));

	pFmt->params.max_keys_per_crypt = pFmtLocal->params.max_keys_per_crypt;
	pFmt->params.min_keys_per_crypt = pFmtLocal->params.min_keys_per_crypt;
	if (pFmtLocal->params.salt_size)
		pFmt->params.salt_size = sizeof(void*);
	else
		pFmt->params.salt_size = 0;
	pFmt->methods.cmp_all    = pFmtLocal->methods.cmp_all;
	pFmt->methods.cmp_one    = pFmtLocal->methods.cmp_one;
	pFmt->methods.cmp_exact  = pFmtLocal->methods.cmp_exact;
#if FMT_MAIN_VERSION > 9
	pFmt->methods.source     = pFmtLocal->methods.source;
#endif
	pFmt->methods.set_salt   = pFmtLocal->methods.set_salt;
	pFmt->methods.salt       = pFmtLocal->methods.salt;
	pFmt->methods.salt_hash  = pFmtLocal->methods.salt_hash;
	pFmt->methods.split      = pFmtLocal->methods.split;
	pFmt->methods.set_key    = pFmtLocal->methods.set_key;
	pFmt->methods.get_key    = pFmtLocal->methods.get_key;
	pFmt->methods.clear_keys = pFmtLocal->methods.clear_keys;
	pFmt->methods.crypt_all  = pFmtLocal->methods.crypt_all;
	pFmt->methods.prepare    = pFmtLocal->methods.prepare;
	for (i = 0; i < 5; ++i)
	{
		pFmt->methods.binary_hash[i] = pFmtLocal->methods.binary_hash[i];
		pFmt->methods.get_hash[i]    = pFmtLocal->methods.get_hash[i];
	}

	if (bInitAlso)
		init(pFmtLocal);

	pFmt->private.data = mem_alloc_tiny(sizeof(private_subformat_data), MEM_ALIGN_WORD);
	memcpy(pFmt->private.data, pFmtLocal->private.data, sizeof(private_subformat_data));

	return pFmtLocal;
}

static char *FixupIfNeeded(char *ciphertext, private_subformat_data *pPriv)
{
	if (!ciphertext || *ciphertext == 0 || *ciphertext == '*')
		return ciphertext;
	if (m_allow_rawhash_fixup && strncmp(ciphertext, "$dynamic_", 9))
	{
		static char __ciphertext[512+24];
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
	if (!ciphertext || !pPriv || !pPriv->dynamic_WHICH_TYPE_SIG) return 0;
	return !strncmp(ciphertext, pPriv->dynamic_WHICH_TYPE_SIG, strlen(pPriv->dynamic_WHICH_TYPE_SIG));
}

// if caseType == 1, return cp
// if caseType == 2, return upcase(cp)
// if caseType == 3, return locase(cp)
// if caseType == 4, return upcaseFirstChar(locase(cp))
static char *HandleCase(char *cp, int caseType)
{
	static UTF8 dest[256];

	switch(caseType) {
		case 1:
			return cp;
		case 2:
			enc_uc(dest, sizeof(dest), (unsigned char*)cp, strlen(cp));
			if (!strcmp((char*)dest, cp))
				return cp;
			break;
		case 3:
		case 4:
			enc_lc(dest, sizeof(dest), (unsigned char*)cp, strlen(cp));
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

int dynamic_real_salt_length(struct fmt_main *pFmt) {
	if (pFmt->params.flags & FMT_DYNAMIC) {
		private_subformat_data *pPriv = pFmt->private.data;
		if (pPriv == NULL || pPriv->pSetup == NULL)
			return -1;  // not a dynamic format, or called before we have loaded them!!
		return abs(pPriv->pSetup->SaltLen);
	}
	// NOT a dynamic format
	return -1;
}

#if !defined (__Dynamic_Types__H__)
#define __Dynamic_Types__H__

//#if AC_BUILT
//#include "autoconfig.h"
//#endif

#ifndef DYNAMIC_DISABLED
/*
 * This software was written by Jim Fougeron jfoug AT cox dot net
 * in 2013. No copyright is claimed, and the software is hereby
 * placed in the public domain. In case this attempt to disclaim
 * copyright and place the software in the public domain is deemed
 * null and void, then the software is Copyright (c) 2013 Jim Fougeron
 * and it is hereby released to the general public under the following
 * terms:
 *
 * This software may be modified, redistributed, and used for any
 * purpose, in source and binary forms, with or without modification.
 *
 * Generic 'scriptable' hash cracker for JtR
 *
 * This is a 'private' include for dynamic. It is internal data structures
 * and defines.  It has been placed into a separate file, due to the huge
 * size of dynamic_fmt.c.  I am trying to split it up a bit, so that it
 * is not SOOOOO huge.
 */

// NOTE, we will HAVE to increase this at some time.  sha512 has 128 byte hash all in itself. So you try
// to do sha512($s.sha512($p)), or even sha512(sha512($p)) we are blowing past our buffers, BAD

// Would LOVE to go to 128 bytes (would allow md5(md5($p).md5($p).md5($p).md5($p)) but
// due to other parts of john, we can only go to 128-3 as max sized plaintext.
#define PLAINTEXT_LENGTH_X86		124

// Allows us to work with up to 96 byte keys in the non-sse2 code

// this allows 2x sized buffers. 1x for pw and 1x for salt.  Was shown 'needed' by type 1014.
// NOTE, this was flushed out by the max password sized stuff in format self test code, but
// this IS the size needed to avoid overflows.  126 'would' be large enough. We go a bit over
// this.  NOTE, if we are using md5_go any more, we would need to expand this even more.
// Right now, we have type dynamic_107: WHIRLPOOL(WHIRLPOOL($s).WHIRLPOOL($p)) and
// dynamic_87: sha512(sha512($s).sha512($p)) which both require a 257 byte buffer.  We
// have only a 260 byte buffer, so it is barely large enough for those. This would be
// nowhere near large enough to use for md5_go code any more.
//
// reduced to exactly 256 bytes, and will be KEPT at that length. This will allow non-mmx to work up to
// dynamic_87/dynamic_107 length. Also, the original 'flat' buffers can be used for direct work, within
// the SHA2 SSE code (4x buffer size for sha256 and 2x buffer size for SHA512).
#define EX_BUF_LEN 132


typedef struct {
	union {
		double dummy;
		uint32_t w[16/sizeof(uint32_t)];
		char b[16];
		unsigned char B[16];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		uint32_t w2[16/sizeof(uint32_t)];
		char b2[16];
		unsigned char B2[16];
	}x2;
#endif
} MD5_OUT;

typedef struct {
	union {
		uint32_t w32[128/4];
		uint64_t w64[128/8];
		uint8_t b[128];
		char c[128];
	} *dat;
	uint32_t width; // number of bytes that are 'valid' in the dat[] element.
	uint32_t bits;
	uint32_t BE;
	uint32_t mixed_SIMD;
} BIG_HASH_OUT;

typedef struct {
	union {
		double dummy;
		uint32_t w[(PLAINTEXT_LENGTH_X86+EX_BUF_LEN)/sizeof(uint32_t)];
		char b[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
		unsigned char B[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
	}x1;
#if MD5_X2
	union {
		double dummy2;
		uint32_t w2[(PLAINTEXT_LENGTH_X86+EX_BUF_LEN)/sizeof(uint32_t)];
		char b2[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
		unsigned char B2[PLAINTEXT_LENGTH_X86+EX_BUF_LEN];
	}x2;
#endif
} MD5_IN;

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
	int store_keys_normal_but_precompute_hash_to_output2;
	int store_keys_normal_but_precompute_hash_to_output2_base16_to_input1;
	int store_keys_normal_but_precompute_hash_to_output2_base16_to_input1_offsetX;
	int store_keys_normal_but_precompute_hash_to_output2_base16_type;
	int using_flat_buffers_sse2_ok;
	int dynamic_salt_as_hex;
	int dynamic_salt_as_hex_format_type;  // 00 is md5, 01 is md4, 02 is sha1, etc. See the flags in dynamic_types.h
	int force_md5_ctx;

	// This array is for the 2nd salt in the hash.  I know of no hashes with double salts,
	// but test type dynamic_16 (which is 'fake') has 2 salts, and this is the data/code to
	// handle double salts.
	int b2Salts;
	int nUserName;
	int nPassCase;
	unsigned FldMask;
	// if the external hash is sha1()  (such as sha1(md5($p)) then we want 40 byte input hashes.
	// We only 'use' 32 bytes of it to compare, but we should only run against 40byte hashes.
	int dynamic_40_byte_input;
	int dynamic_48_byte_input;
	int dynamic_56_byte_input;
	int dynamic_64_byte_input;
	int dynamic_80_byte_input;
	int dynamic_96_byte_input;
	int dynamic_128_byte_input;

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
	struct fmt_main *pFmtMain;
#ifdef _OPENMP
	int omp_granularity;
#endif
} private_subformat_data;

#ifndef OMP_SCALE
#define OMP_SCALE 2
#endif


// This value still gets us all para from 1 to 7
#ifdef SIMD_COEF_32
#define NON_OMP_MAX   (SIMD_COEF_32*3*4*5*7)
#else
#define NON_OMP_MAX   (1<<MD5_X2)
#endif
#define OMP_MAX       (NON_OMP_MAX*OMP_SCALE)

#ifdef SIMD_COEF_32
 #define MIN_KEYS_PER_CRYPT	(SIMD_COEF_32*SIMD_PARA_MD5*SIMD_PARA_SHA1*(MD5_X2+1))
 #ifdef _OPENMP
  #if SIMD_COEF_32 >= 4
   #define BLOCK_LOOPS		((OMP_MAX/SIMD_COEF_32)*OMP_SCALE)
  #endif
 #else
  #if SIMD_COEF_32 >= 4
   #define BLOCK_LOOPS		(NON_OMP_MAX/SIMD_COEF_32)
  #endif
 #endif
 #define LOOP_STR
 #if SIMD_COEF_32 >= 4
  #if SIMD_COEF_32 == 16
   #define BITS				"512/512"
  #elif SIMD_COEF_32 == 8
   #define BITS				"256/256"
  #elif SIMD_COEF_32 == 4
   #define BITS				"128/128"
  #elif SIMD_COEF_32 == 2
   #define BITS				"64/64"
 #endif
  #ifdef SIMD_PARA_MD5
   #define ALGORITHM_NAME		BITS " " SIMD_TYPE  " " STRINGIZE(SIMD_COEF_32) "x" STRINGIZE(SIMD_PARA_MD5)
   #define BSD_BLKS (SIMD_PARA_MD5)
  #else
   #define ALGORITHM_NAME		BITS " " SIMD_TYPE  " " STRINGIZE(SIMD_COEF_32)
   #define BSD_BLKS 1
  #endif
  #ifdef SIMD_PARA_SHA1
   #define ALGORITHM_NAME_S		BITS " " SIMD_TYPE " " STRINGIZE(SIMD_COEF_32) "x" STRINGIZE(SIMD_PARA_SHA1)
  #else
   #define ALGORITHM_NAME_S		BITS " " SIMD_TYPE " " STRINGIZE(SIMD_COEF_32)
  #endif
  #ifdef SIMD_PARA_MD4
   #define ALGORITHM_NAME_4		BITS " " SIMD_TYPE  " " STRINGIZE(SIMD_COEF_32) "x" STRINGIZE(SIMD_PARA_MD4)
  #else
   #define ALGORITHM_NAME_4		BITS " " SIMD_TYPE  " " STRINGIZE(SIMD_COEF_32)
  #endif
  #define PLAINTEXT_LENGTH	(27*3+1) // for worst-case UTF-8
  #ifdef SIMD_PARA_MD5
// gives us 16 'loops' for para=2 and 10 loops for para==3 (or max of 128 for 2 and 120 for 3)
   #define MAX_KEYS_PER_CRYPT	(((SIMD_COEF_32*BLOCK_LOOPS)/(SIMD_PARA_MD5*4))*(SIMD_PARA_MD5*4))
  #else
   #define MAX_KEYS_PER_CRYPT	SIMD_COEF_32*BLOCK_LOOPS
  #endif
 #endif
#else // !SIMD_COEF_32
 #ifdef _OPENMP
  #define BLOCK_LOOPS			(OMP_MAX*OMP_SCALE)
 #else
  #define BLOCK_LOOPS			NON_OMP_MAX
 #endif
 #define ALGORITHM_NAME			"32/" ARCH_BITS_STR
 #define ALGORITHM_NAME_S		"32/" ARCH_BITS_STR
 #define ALGORITHM_NAME_4		"32/" ARCH_BITS_STR
 #define MIN_KEYS_PER_CRYPT		(MD5_X2+1)
#endif

#ifdef _OPENMP
 #define X86_BLOCK_LOOPS			(OMP_MAX*OMP_SCALE)
 #define X86_BLOCK_LOOPSx2			((OMP_MAX/2)*OMP_SCALE)
#else
 #define X86_BLOCK_LOOPS			NON_OMP_MAX
 #define X86_BLOCK_LOOPSx2			(NON_OMP_MAX/2)
#endif

#define ALGORITHM_NAME_X86_S	"32/"ARCH_BITS_STR
#define ALGORITHM_NAME_X86_4	"32/"ARCH_BITS_STR

#define ALGORITHM_NAME_S2_256		BITS " " SIMD_TYPE " " SHA256_N_STR
#define ALGORITHM_NAME_S2_512		BITS " " SIMD_TYPE " " SHA512_N_STR

#if defined (GENERIC_SHA2)
#define ALGORITHM_NAME_X86_S2_256	"32/"ARCH_BITS_STR
#define ALGORITHM_NAME_X86_S2_512	ARCH_BITS_STR"/64"
#else
#define ALGORITHM_NAME_X86_S2_256	"32/"ARCH_BITS_STR
#define ALGORITHM_NAME_X86_S2_512	ARCH_BITS_STR"/64"
#endif

#if OPENSSL_VERSION_NUMBER >= 0x10000000
#define ALGORITHM_NAME_WP2      "32/"ARCH_BITS_STR " OpenSSL"
#define ALGORITHM_NAME_X86_WP2  "32/"ARCH_BITS_STR " OpenSSL"
#else
#define ALGORITHM_NAME_WP2      "32/"ARCH_BITS_STR " SPH_WP"
#define ALGORITHM_NAME_X86_WP2  "32/"ARCH_BITS_STR " SPH_WP"
#endif

#if !defined(USE_GCC_ASM_IA32) && defined(USE_GCC_ASM_X64)
#define ALGORITHM_NAME_GST2     "64/64"
#define ALGORITHM_NAME_X86_GST2 "64/64"
#else
#define ALGORITHM_NAME_GST2     "32/"ARCH_BITS_STR
#define ALGORITHM_NAME_X86_GST2 "32/"ARCH_BITS_STR
#endif

#define ALGORITHM_NAME_TGR     "32/"ARCH_BITS_STR " sph_tiger"
#define ALGORITHM_NAME_X86_TGR "32/"ARCH_BITS_STR " sph_tiger"

#define ALGORITHM_NAME_RIPEMD     "32/"ARCH_BITS_STR " sph_ripemd"
#define ALGORITHM_NAME_X86_RIPEMD "32/"ARCH_BITS_STR " sph_ripemd"

#define ALGORITHM_NAME_HAVAL     "32/"ARCH_BITS_STR " sph_haval"
#define ALGORITHM_NAME_X86_HAVAL "32/"ARCH_BITS_STR " sph_haval"

#define ALGORITHM_NAME_MD2       "32/"ARCH_BITS_STR " sph_md2"
#define ALGORITHM_NAME_X86_MD2   "32/"ARCH_BITS_STR " sph_md2"

#define ALGORITHM_NAME_PANAMA     "32/"ARCH_BITS_STR " sph_panama"
#define ALGORITHM_NAME_X86_PANAMA "32/"ARCH_BITS_STR " sph_panama"

#define ALGORITHM_NAME_SKEIN     "32/"ARCH_BITS_STR " sph_skein"
#define ALGORITHM_NAME_X86_SKEIN "32/"ARCH_BITS_STR " sph_skein"

#define ALGORITHM_NAME_KECCAK     "64/"ARCH_BITS_STR " keccak"
#define ALGORITHM_NAME_X86_KECCAK "64/"ARCH_BITS_STR " keccak"
// LARGE_HASH_EDIT_POINT

#ifndef SIMD_COEF_32
//static MD5_OUT tmpOut;
#endif
#define MIN_KEYS_PER_CRYPT_X86	(MD5_X2+1)
#define MAX_KEYS_PER_CRYPT_X86	X86_BLOCK_LOOPS
#if MD5_X2 && (!MD5_ASM)
#if defined(_OPENMP) || defined (FORCE_THREAD_MD5_body)
#define MD5_body(x0,x1,out0,out1) MD5_body_for_thread(0, x0, x1, out0, out1)
extern void MD5_body_for_thread(int t, uint32_t x1[15], uint32_t x2[15], uint32_t out1[4], uint32_t out2[4]);
#else
extern void MD5_body(uint32_t x1[15], uint32_t x2[15], uint32_t out1[4], uint32_t out2[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR " x2"
#if defined(_OPENMP) || defined (FORCE_THREAD_MD5_body)
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L[0])<55&&(L[1])<55) {A.x1.b[L[0]]=0x80;A.x2.b2[L[1]]=0x80;A.x1.w[14]=(L[0]<<3);A.x2.w2[14]=(L[1]<<3);MD5_swap(A.x1.w,A.x1.w,(L[0]+4)>>2);MD5_swap(A.x2.w2,A.x2.w2,(L[1]+4)>>2);MD5_body_for_thread(0,A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);MD5_swap2(C.x1.w,C.x2.w2,C.x1.w,C.x2.w2,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5o(A,L,C) do{if((L[0])<55&&(L[1])<55) {MD5_body_for_thread(0,A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5a(A,L,C) do{MD5_body_for_thread(0,A->x1.w,A->x2.w2,C->x1.w,C->x2.w2);}while(0)
#else
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L[0])<55&&(L[1])<55) {A.x1.b[L[0]]=0x80;A.x2.b2[L[1]]=0x80;A.x1.w[14]=(L[0]<<3);A.x2.w2[14]=(L[1]<<3);MD5_swap(A.x1.w,A.x1.w,(L[0]+4)>>2);MD5_swap(A.x2.w2,A.x2.w2,(L[1]+4)>>2);MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);MD5_swap2(C.x1.w,C.x2.w2,C.x1.w,C.x2.w2,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5o(A,L,C) do{if((L[0])<55&&(L[1])<55) {MD5_body(A.x1.w,A.x2.w2,C.x1.w,C.x2.w2);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L[0]); MD5_Final((unsigned char *)(C.x1.b),&ctx); MD5_Init(&ctx); MD5_Update(&ctx,A.x2.b2,L[1]); MD5_Final((unsigned char *)(C.x2.b2),&ctx);} }while(0)
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,A->x2.w2,C->x1.w,C->x2.w2);}while(0)
//#define DoMD5a2(A,L,C,D) do{MD5_body(A->x1.w,A->x2.w2,tmpOut.x1.w,tmpOut.x2.w2);MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);MD5_swap(C->x2.w2,C->x2.w2,(D[1]+21)>>2);MD5_swap(tmpOut.x1.w,tmpOut.x1.w,4);MD5_swap(tmpOut.x2.w2,tmpOut.x2.w2,4);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16);memcpy(&(C->x2.b2[D[1]]),tmpOut.x2.b2,16);MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);MD5_swap(C->x2.w2,C->x2.w2,(D[1]+21)>>2);}while(0)
#endif
#else
#if (defined(_OPENMP) || defined (FORCE_THREAD_MD5_body)) && !MD5_ASM
#define MD5_body(x, out) MD5_body_for_thread(0, x, out)
extern void MD5_body_for_thread(int t, uint32_t x[15],uint32_t out[4]);
#else
extern void MD5_body(uint32_t x[15],uint32_t out[4]);
#endif
#define ALGORITHM_NAME_X86		"32/" ARCH_BITS_STR
#define DoMD5(A,L,C) do{if(!force_md5_ctx&&(L)<55) {A.x1.b[L]=0x80;A.x1.w[14]=(L<<3);MD5_swap(A.x1.w,A.x1.w,((L+4)>>2));MD5_body(A.x1.w,C.x1.w);MD5_swap(C.x1.w,C.x1.w,4);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L); MD5_Final((unsigned char *)(C.x1.b),&ctx); } }while(0)
#define DoMD5o(A,L,C) do{if((L)<55) {MD5_body(A.x1.w,C.x1.w);} else {MD5_CTX ctx; MD5_Init(&ctx); MD5_Update(&ctx,A.x1.b,L); MD5_Final((unsigned char *)(C.x1.b),&ctx); } }while(0)
#define DoMD5a(A,L,C) do{MD5_body(A->x1.w,C->x1.w);}while(0)
//#define DoMD5a2(A,L,C,D)  do{MD5_body(A->x1.w,tmpOut.x1.w); MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);memcpy(&(C->x1.b[D[0]]),tmpOut.x1.b,16); MD5_swap(C->x1.w,C->x1.w,(D[0]+21)>>2);}while(0)
#endif

// simple macro for now.  We can and will improve upon this later.
#if MD5_X2
#define DoMD4(A,L,C) do{ MD4_CTX ctx; MD4_Init(&ctx); MD4_Update(&ctx,A.x1.b,L[0]); MD4_Final(C.x1.B,&ctx); MD4_Init(&ctx); MD4_Update(&ctx,A.x2.b2,L[1]); MD4_Final(C.x2.B2,&ctx);}while(0)
#else
#define DoMD4(A,L,C) do{ MD4_CTX ctx; MD4_Init(&ctx); MD4_Update(&ctx,A.x1.b,L); MD4_Final(C.x1.B,&ctx);}while(0)
#endif


extern int large_hash_output(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int tid);
int large_hash_output_no_null(unsigned char *cpi, unsigned char *cpo, int in_byte_cnt, int tid);

typedef enum { eUNK=0, eBase16=1, eBase16u=2, eBase64=3, eBase64_nte=4, eBaseRaw=5, eBase64c=6, } eLargeOut_t;

#endif /* DYNAMIC_DISABLED */

#endif  // __Dynamic_Types__H__
